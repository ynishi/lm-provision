//! `fetch` — retrieve a shared profile over HTTP(S) and keep it only if
//! its canonical hash matches the one the caller already holds
//! (07-cli.md §Invocation `fetch`).
//!
//! # The hash is the trust root, not the host
//!
//! The profile hash is computed over the canonical AST encoding
//! (chapter 01 §Spec fields), so it is frontend-independent and stable
//! across whitespace, key order and transport. That makes distribution
//! content-addressed: a profile named by its hash can be served from
//! any static host — a raw repository URL, a pages site, a mirror —
//! and the fetch is trustworthy exactly when the hash checks out. This
//! is the same judgement Nix and OCI make for their artifacts; the
//! index that names the hash (e.g. `docs/profiles/index.json`) is the
//! only thing that has to come from somewhere the operator believes.
//!
//! It is also why this route **follows redirects** while the crate's
//! `net.http_get` effect deliberately does not: a shared-profile host
//! legitimately answers with a hop to a CDN, and integrity comes from
//! the hash, not from which host finally served the bytes.
//!
//! `--expect-hash` is therefore **required**. A fetch that skips
//! verification is `curl`, which already exists; the one thing this
//! subcommand adds over it is the refusal.
//!
//! # Nothing unverified is produced
//!
//! The body lands in a staging file next to the destination —
//! created exclusively under a per-process name, so no parallel run,
//! pre-planted symlink or pre-existing file is ever written through —
//! and is renamed over the destination only after the hash matches.
//! On any failure the staging file is removed and the destination is
//! not touched. A file that was already at the destination before the
//! run (an earlier `curl`, an older fetch) survives a refusal
//! untouched: this subcommand vouches only for what it wrote itself.
//! The staging file shares the destination's extension because the
//! frontend selects its parser by extension alone (07-cli.md §Profile
//! input format) — which also means the destination's extension must
//! match the body's format (`.json` for the published JSON profiles).

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Whole-request deadline. A profile is KB-scale; a source that cannot
/// deliver one in this window is down, not slow.
///
/// `pub(crate)` because [`crate::resolve`] shares this deadline for its
/// fragment fetches — the two routes have the same shape (KB-scale
/// documents over static HTTPS), and spec 07-cli.md §Invocation `pin`
/// names the shared budget literally ("under the same 4 MB cap and
/// 30 s deadline `fetch` uses"). One constant, one place to change.
pub(crate) const TIMEOUT_SEC: u64 = 30;

/// Body cap, checked chunk-by-chunk before buffering
/// ([`crate::exec::effects::read_capped`]). Refuses an index typo that
/// points the URL at a model weight before it can fill memory.
///
/// `pub(crate)` for the same reason [`TIMEOUT_SEC`] is: [`crate::resolve`]
/// and [`crate::pin`] cap fragment / index bodies at the same 4 MB
/// (spec 07-cli.md §Invocation `pin`).
pub(crate) const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;

/// What a successful fetch admitted.
#[derive(Debug)]
pub struct Fetched {
    /// The profile name off the `Spec` root.
    pub name: String,
    /// The verified canonical hash (64-char lowercase hex).
    pub hash: String,
    /// Where the profile now is.
    pub path: PathBuf,
}

/// Why a fetch refused. Rendered as the single stderr failure line
/// (07-cli.md §Error surface), so each variant carries what that line
/// needs and nothing else.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The transport failed before a body arrived, or the body blew
    /// its cap mid-read.
    #[error("GET {url} failed: {message}")]
    Transport {
        /// What was asked for.
        url: String,
        /// The transport's rendered source chain
        /// ([`crate::exec::effects::render`] — `reqwest`'s `Display`
        /// alone is only a category).
        message: String,
    },

    /// The server answered with a non-success status.
    #[error("GET {url} returned {status}")]
    Status {
        /// What was asked for.
        url: String,
        /// The status line, e.g. `404 Not Found`.
        status: String,
    },

    /// The body could not be staged or the verified file could not be
    /// moved into place.
    #[error("could not write {}: {message}", path.display())]
    Io {
        /// The file being written or renamed.
        path: PathBuf,
        /// The OS error's own words.
        message: String,
    },

    /// The body loaded but its fragment imports could not be resolved
    /// (spec 11 §Resolution). The profile hash is the *expanded*
    /// canonical hash, so an unresolvable body has no hash to verify
    /// against `--expect-hash`.
    #[error("the fetched profile's imports could not be resolved: {message}")]
    Unresolvable {
        /// The resolve error, verbatim.
        message: String,
    },

    /// The body is not a loadable profile — or the destination's
    /// extension routed it to the wrong parser (§module doc).
    #[error(
        "the fetched body is not a profile (or the -o extension selects the wrong \
         parser for it): {message}"
    )]
    NotAProfile {
        /// The frontend's load error, verbatim.
        message: String,
    },

    /// The body loaded, but its root is not a `Spec` — not a profile
    /// an `apply` downstream could run.
    #[error("the fetched body is not a profile: its root is not a Spec")]
    NotASpec,

    /// The profile loaded, but it is not the one the caller named.
    #[error(
        "hash mismatch: expected {expected}, got {got} — refusing to keep the file \
         (the source does not serve the profile the index describes)"
    )]
    HashMismatch {
        /// The hash the caller pinned.
        expected: String,
        /// The hash the body actually has.
        got: String,
    },
}

/// GET `url`, verify against `expect_hash`, land at `out`.
///
/// Async because the one HTTP client in this crate is async
/// (workspace `reqwest`, rustls-only for the musl build); the CLI
/// wraps this in the same per-subcommand runtime `apply` uses.
pub async fn fetch(url: &str, expect_hash: &str, out: &Path) -> Result<Fetched, FetchError> {
    let client = crate::exec::effects::client("fetch", |builder| {
        builder.timeout(std::time::Duration::from_secs(TIMEOUT_SEC))
    })
    .map_err(|err| FetchError::Transport {
        url: url.to_string(),
        message: err.to_string(),
    })?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| FetchError::Transport {
            url: url.to_string(),
            message: crate::exec::effects::render(&err),
        })?;
    if !response.status().is_success() {
        return Err(FetchError::Status {
            url: url.to_string(),
            status: response.status().to_string(),
        });
    }
    let body = crate::exec::effects::read_capped(response, MAX_PROFILE_BYTES)
        .await
        .map_err(|message| FetchError::Transport {
            url: url.to_string(),
            message,
        })?;
    admit(&body, expect_hash, out)
}

/// Stage `body`, hash it, and rename it to `out` only on a match.
///
/// Split from [`fetch`] so the admit-or-refuse half — the half with
/// the invariants — is testable without a server.
pub(crate) fn admit(body: &[u8], expect_hash: &str, out: &Path) -> Result<Fetched, FetchError> {
    let staging = staging_path(out);
    // Exclusive create: refuses to write through a pre-planted symlink
    // or over anything already there. A leftover from a killed earlier
    // run surfaces here as `AlreadyExists` with the path named, so the
    // operator can remove it rather than this run silently reusing it.
    if let Err(err) = std::fs::File::create_new(&staging).and_then(|mut file| file.write_all(body))
    {
        return Err(FetchError::Io {
            path: staging,
            message: err.to_string(),
        });
    }

    // From here every early return must remove the staging file:
    // this run leaves nothing behind but an admitted profile.
    let node = match crate::frontend::load_profile(&staging) {
        Ok(node) => node,
        Err(err) => {
            std::fs::remove_file(&staging).ok();
            return Err(FetchError::NotAProfile {
                message: err.to_string(),
            });
        }
    };
    // Resolve before hashing: the profile hash is the expanded
    // canonical hash (spec 11 §Resolution), and `lm-provision hash`
    // resolves first — `fetch` must judge the same identity or the two
    // disagree about the same document. A body with no imports resolves
    // to itself (the whole pre-spec-11 behaviour, byte-for-byte).
    let node = match crate::resolve::resolve(node, &staging) {
        Ok(node) => node,
        Err(err) => {
            std::fs::remove_file(&staging).ok();
            return Err(FetchError::Unresolvable {
                message: err.to_string(),
            });
        }
    };
    let crate::profile_ast::ProfileNode::Spec { name, .. } = &node else {
        std::fs::remove_file(&staging).ok();
        return Err(FetchError::NotASpec);
    };
    let name = name.clone();
    let got = crate::canonical::hash(&node);
    let expected = expect_hash.to_ascii_lowercase();
    if got != expected {
        std::fs::remove_file(&staging).ok();
        return Err(FetchError::HashMismatch { expected, got });
    }

    if let Err(err) = std::fs::rename(&staging, out) {
        std::fs::remove_file(&staging).ok();
        return Err(FetchError::Io {
            path: out.to_path_buf(),
            message: err.to_string(),
        });
    }
    Ok(Fetched {
        name,
        hash: got,
        path: out.to_path_buf(),
    })
}

/// The staging file: `profile.json` → `profile.part-<pid>.json`. The
/// destination's extension is preserved because the frontend picks its
/// parser by extension alone (`profile.json.part` would be parsed as
/// canonical text and every JSON fetch would refuse); the pid keeps
/// two concurrent fetches to the same destination from staging into
/// each other's file.
fn staging_path(out: &Path) -> PathBuf {
    let pid = std::process::id();
    match out.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => out.with_extension(format!("part-{pid}.{ext}")),
        None => out.with_extension(format!("part-{pid}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"{
      "type": "Spec",
      "name": "fetch-test",
      "version": "0.1.0",
      "capabilities": [],
      "paths": [],
      "phases": [{ "type": "ShExec", "argv": ["echo", "ok"] }]
    }"#;

    fn hash_of(body: &str, dir: &Path) -> String {
        let path = dir.join("hash-probe.json");
        std::fs::write(&path, body).unwrap();
        let node = crate::frontend::load_profile(&path).unwrap();
        std::fs::remove_file(&path).ok();
        crate::canonical::hash(&node)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lm-provision-fetch-{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The staging file keeps the destination's extension — that is
    /// what routes it to the same parser the destination would get —
    /// and carries the pid so concurrent runs never share one.
    #[test]
    fn staging_preserves_the_extension() {
        let pid = std::process::id();
        assert_eq!(
            staging_path(Path::new("/x/profile.json")),
            PathBuf::from(format!("/x/profile.part-{pid}.json"))
        );
        assert_eq!(
            staging_path(Path::new("/x/profile")),
            PathBuf::from(format!("/x/profile.part-{pid}"))
        );
    }

    /// The whole point of the subcommand: a matching hash lands the
    /// file, and the staging file is gone afterwards.
    #[test]
    fn a_matching_hash_admits_the_file() {
        let dir = temp_dir("admit");
        let out = dir.join("profile.json");
        let expected = hash_of(PROFILE, &dir);

        let fetched = admit(PROFILE.as_bytes(), &expected, &out).unwrap();

        assert_eq!(fetched.name, "fetch-test");
        assert_eq!(fetched.hash, expected);
        assert!(out.exists());
        assert!(
            !staging_path(&out).exists(),
            "staging file must be renamed away"
        );
        std::fs::remove_file(&out).ok();
    }

    /// An uppercase pin still matches: the operator copies hashes from
    /// wherever they are displayed, and case is not content.
    #[test]
    fn the_expected_hash_is_case_insensitive() {
        let dir = temp_dir("case");
        let out = dir.join("profile.json");
        let expected = hash_of(PROFILE, &dir).to_ascii_uppercase();

        assert!(admit(PROFILE.as_bytes(), &expected, &out).is_ok());
        std::fs::remove_file(&out).ok();
    }

    /// **What a refusal leaves behind: nothing new.** On mismatch the
    /// destination is not created and the staging file is removed.
    #[test]
    fn a_mismatch_leaves_no_file() {
        let dir = temp_dir("mismatch");
        let out = dir.join("profile.json");

        let err = admit(PROFILE.as_bytes(), &"0".repeat(64), &out).unwrap_err();

        assert!(matches!(err, FetchError::HashMismatch { .. }), "{err}");
        assert!(!out.exists(), "the destination must not appear on mismatch");
        assert!(
            !staging_path(&out).exists(),
            "the staging file must be cleaned up"
        );
    }

    /// A refusal does not eat what was already there: a pre-existing
    /// destination file survives byte-for-byte.
    #[test]
    fn a_mismatch_leaves_a_pre_existing_destination_untouched() {
        let dir = temp_dir("pre-existing");
        let out = dir.join("profile.json");
        std::fs::write(&out, b"already here").unwrap();

        assert!(admit(PROFILE.as_bytes(), &"0".repeat(64), &out).is_err());

        assert_eq!(std::fs::read(&out).unwrap(), b"already here");
        std::fs::remove_file(&out).ok();
    }

    /// A body that is not a profile refuses before hashing, and cleans
    /// up the same way.
    #[test]
    fn a_non_profile_body_is_refused_and_cleaned_up() {
        let dir = temp_dir("not-a-profile");
        let out = dir.join("profile.json");

        let err = admit(b"{ not json", &"0".repeat(64), &out).unwrap_err();

        assert!(matches!(err, FetchError::NotAProfile { .. }), "{err}");
        assert!(!out.exists());
        assert!(!staging_path(&out).exists());
    }

    /// A loadable body whose root is not a `Spec` is refused: it would
    /// only fail one layer later, at `apply`, where the refusal no
    /// longer names the source.
    #[test]
    fn a_non_spec_root_is_refused() {
        let dir = temp_dir("non-spec");
        let out = dir.join("profile.json");
        let body = r#"{ "type": "ShExec", "argv": ["echo", "ok"] }"#;
        let expected = hash_of(body, &dir);

        let err = admit(body.as_bytes(), &expected, &out).unwrap_err();

        assert!(matches!(err, FetchError::NotASpec), "{err}");
        assert!(!out.exists());
        assert!(!staging_path(&out).exists());
    }

    /// The staging file is created exclusively: a file already at the
    /// staging path (a symlink someone planted, a leftover) refuses
    /// the run instead of being written through.
    #[test]
    fn an_occupied_staging_path_refuses_instead_of_overwriting() {
        let dir = temp_dir("occupied");
        let out = dir.join("profile.json");
        let staging = staging_path(&out);
        std::fs::write(&staging, b"planted").unwrap();

        let err = admit(PROFILE.as_bytes(), &"0".repeat(64), &out).unwrap_err();

        assert!(matches!(err, FetchError::Io { .. }), "{err}");
        assert_eq!(
            std::fs::read(&staging).unwrap(),
            b"planted",
            "the occupant must not be overwritten"
        );
        std::fs::remove_file(&staging).ok();
    }
}
