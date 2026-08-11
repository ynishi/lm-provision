//! Content identity: the crate's single SHA-256 implementation.
//!
//! Three places in this workspace answer the question "do these two
//! byte streams have the same content": the canonical profile hash
//! ([`crate::canonical::hash`]), the `FileDigest` predicate of the
//! Assert model ([`crate::exec::assert`]), and the driver's
//! `ensure-binary` idempotency check (`lm-provision-driver`). They used
//! to answer it three different ways — a `{:02x}` loop here, a
//! `format!("{:x}")` there, a raw `Vec<u8>` equality in the third — so
//! this module exists to hold the one implementation they all reach
//! for.
//!
//! Public because the driver crate is a separate compilation unit and
//! has to reach it (08-push-driver-protocol.md §Session steps
//! "ensure-binary" is specified in terms of a sha256 comparison, so the
//! driver is a legitimate consumer of the same rendering, not a
//! reimplementer of it).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Bytes read per hashing iteration by [`of_file`].
///
/// A model weight file is measured in gigabytes, so the content is
/// never held in memory at once. 64 KiB is the chunk the predecessor
/// implementation streams downloads with, kept the same here so a
/// download that hashes as it writes and a later verification read use
/// the same block size.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// SHA-256 of `bytes` rendered as hex.
///
/// Contract: **lowercase, zero-padded, exactly 64 chars, no prefix.**
/// Every byte contributes two characters, so a digest byte below `0x10`
/// keeps its leading zero.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    render(hasher)
}

/// The content digest of the file at `path`, or `None` when there is no
/// file there.
///
/// **`Ok(None)` and `Err` are different answers and are kept apart.**
/// "Nothing is there" is a fact about the target; "the read failed" is
/// a fact about the attempt, and collapsing the second into the first
/// is exactly what made the driver's `ensure_binary` unable to tell a
/// permission failure from a content mismatch (design §4.1). Only
/// [`io::ErrorKind::NotFound`] becomes `Ok(None)`; every other error
/// stays an error for the caller to classify.
///
/// The content is streamed in [`READ_CHUNK_BYTES`] blocks, never read
/// into memory whole — the intended subjects are multi-gigabyte model
/// weights.
pub fn of_file(path: &Path) -> io::Result<Option<String>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(render(hasher)))
}

/// Render a finished hasher under the [`hex_sha256`] contract.
fn render(hasher: Sha256) -> String {
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        // `format!("{byte:02x}")` guarantees two lowercase hex chars.
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published rendering contract, on the one input whose digest
    /// is quotable from the standard test vectors.
    #[test]
    fn hex_sha256_renders_64_lowercase_hex_chars() {
        let empty = hex_sha256(b"");
        assert_eq!(
            empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of the empty input is a published test vector",
        );
        assert_eq!(empty.len(), 64);
        assert!(empty
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')));
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-digest-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// A streamed file digest equals the in-memory one, across a
    /// content longer than one read chunk — the loop's boundary is the
    /// only thing that could make them differ.
    #[test]
    fn of_file_agrees_with_the_in_memory_digest_across_chunk_boundaries() {
        let dir = scratch_dir("chunks");
        let path = dir.join("payload.bin");
        let content: Vec<u8> = (0..(READ_CHUNK_BYTES * 2 + 7))
            .map(|i| u8::try_from(i % 251).expect("modulo 251 fits in a byte"))
            .collect();
        std::fs::write(&path, &content).expect("write payload");

        assert_eq!(
            of_file(&path).expect("the file is readable"),
            Some(hex_sha256(&content)),
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An absent file is an answer (`Ok(None)`), not an error.
    #[test]
    fn of_file_reports_an_absent_file_as_an_answer() {
        let dir = scratch_dir("absent");
        assert_eq!(
            of_file(&dir.join("nothing-here")).expect("absence is not a failure"),
            None,
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A path that exists but cannot be read as a byte stream stays an
    /// error rather than being folded into "absent". A directory is the
    /// portable way to produce that: `open` succeeds, `read` does not.
    #[test]
    fn of_file_keeps_an_unreadable_path_distinct_from_an_absent_one() {
        let dir = scratch_dir("unreadable");
        assert!(
            of_file(&dir).is_err(),
            "a directory is not an absent file, and must not answer as one",
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
