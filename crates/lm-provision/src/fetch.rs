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
use std::sync::atomic::{AtomicU64, Ordering};

use url::Url;

/// Per-process counter in a staging file's name. The pid alone is not
/// enough: one MCP server process runs concurrent `lm_apply` sessions,
/// and two fetches to the same destination inside it would share a pid
/// — and therefore a staging path, where the first `create_new` wins
/// and the second refuses a file that is not a leftover but its own
/// sibling's work in flight. Same shape as the three sibling sites
/// ([`crate::resolve`]'s cache-temp counter, [`crate::pin`]'s
/// verify-temp counter, and the driver session's expanded-payload
/// counter).
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

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
    // The URL that actually served the bytes — after redirects, which
    // this route follows (§The hash is the trust root, not the host).
    // That is the anchor the body's own relative imports are written
    // against, so it is the one [`admit`] resolves at, not the request
    // URL and not the file the bytes are staged in.
    let origin = response.url().clone();
    let body = crate::exec::effects::read_capped(response, MAX_PROFILE_BYTES)
        .await
        .map_err(|message| FetchError::Transport {
            url: url.to_string(),
            message,
        })?;
    admit(&body, expect_hash, out, &origin)
}

/// Stage `body`, hash it, and rename it to `out` only on a match.
///
/// `origin` is the URL that served `body`. It is not decoration: the
/// hash this function verifies is the *expanded* canonical hash, so the
/// body's imports get resolved on the way — and an import's meaning
/// depends on where its document is (spec 11 §Resolution step 2). See
/// [`admit_into`] for what anchoring it at the staging file instead did.
///
/// Split from [`fetch`] so the admit-or-refuse half — the half with
/// the invariants — is testable without a server.
pub(crate) fn admit(
    body: &[u8],
    expect_hash: &str,
    out: &Path,
    origin: &Url,
) -> Result<Fetched, FetchError> {
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    admit_into(body, expect_hash, out, &staging_path(out, seq), origin)
}

/// [`admit`] with the staging path chosen by the caller.
///
/// The split exists for the exclusive-create test: once the staging
/// name carries a per-call counter, no caller outside this function can
/// predict which path a given [`admit`] will use, and a test that wants
/// to plant something in the way has to be the one that names it.
fn admit_into(
    body: &[u8],
    expect_hash: &str,
    out: &Path,
    staging: &Path,
    origin: &Url,
) -> Result<Fetched, FetchError> {
    let staging = staging.to_path_buf();
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
    //
    // Resolved **at the origin URL, not at the staging file.** The
    // staging path is where the bytes happen to sit for the length of
    // this call; the document was written against the URL it came from.
    // Anchoring it locally gave its relative imports the temp directory
    // — where a legitimate `./frag.json` is simply missing, and where a
    // resolved one would be an operator-host file the document never
    // named. It also stood the referential sanity check down: a
    // document reached over https may only import https sources (spec
    // 11 §Adopted conventions), and a `File` location has no remote to
    // be same-origin with.
    let node = match crate::resolve::resolve_remote(node, origin) {
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

/// The staging file: `profile.json` → `profile.part-<pid>-<seq>.json`.
///
/// The destination's extension is preserved because the frontend picks
/// its parser by extension alone (`profile.json.part` would be parsed
/// as canonical text and every JSON fetch would refuse). The `pid` keeps
/// two processes fetching the same destination out of each other's
/// file, and `seq` ([`STAGING_SEQ`]) does the same for two fetches
/// inside one process — which is not hypothetical: an MCP server holds
/// concurrent sessions in a single pid.
fn staging_path(out: &Path, seq: u64) -> PathBuf {
    let pid = std::process::id();
    match out.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => out.with_extension(format!("part-{pid}-{seq}.{ext}")),
        None => out.with_extension(format!("part-{pid}-{seq}")),
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

    /// The URL these tests pretend served the body. Every `admit` call
    /// carries one because every real one does — the origin is what the
    /// body's imports are resolved against.
    fn origin() -> Url {
        Url::parse("https://example.com/profiles/fetch-test-0.1.0.json").expect("a valid URL")
    }

    /// Every `.part-` file this module could have left in `dir`. The
    /// staging name carries a counter now, so a test cannot name the
    /// path a given `admit` used — but it can still say "nothing was
    /// left behind", which is the invariant the assertions want.
    fn staging_leftovers(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".part-"))
            })
            .collect()
    }

    /// The staging file keeps the destination's extension — that is
    /// what routes it to the same parser the destination would get —
    /// and carries the pid *and* a per-call counter, so neither two
    /// processes nor two concurrent fetches inside one process ever
    /// share a staging path.
    #[test]
    fn staging_preserves_the_extension_and_is_unique_per_call() {
        let pid = std::process::id();
        assert_eq!(
            staging_path(Path::new("/x/profile.json"), 7),
            PathBuf::from(format!("/x/profile.part-{pid}-7.json"))
        );
        assert_eq!(
            staging_path(Path::new("/x/profile"), 7),
            PathBuf::from(format!("/x/profile.part-{pid}-7"))
        );
        assert_ne!(
            staging_path(Path::new("/x/profile.json"), 7),
            staging_path(Path::new("/x/profile.json"), 8),
            "two fetches in one process must not stage into one file"
        );
    }

    /// The whole point of the subcommand: a matching hash lands the
    /// file, and the staging file is gone afterwards.
    #[test]
    fn a_matching_hash_admits_the_file() {
        let dir = temp_dir("admit");
        let out = dir.join("profile.json");
        let expected = hash_of(PROFILE, &dir);

        let fetched = admit(PROFILE.as_bytes(), &expected, &out, &origin()).unwrap();

        assert_eq!(fetched.name, "fetch-test");
        assert_eq!(fetched.hash, expected);
        assert!(out.exists());
        assert!(
            staging_leftovers(&dir).is_empty(),
            "staging file must be renamed away: {:?}",
            staging_leftovers(&dir)
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

        assert!(admit(PROFILE.as_bytes(), &expected, &out, &origin()).is_ok());
        std::fs::remove_file(&out).ok();
    }

    /// **What a refusal leaves behind: nothing new.** On mismatch the
    /// destination is not created and the staging file is removed.
    #[test]
    fn a_mismatch_leaves_no_file() {
        let dir = temp_dir("mismatch");
        let out = dir.join("profile.json");

        let err = admit(PROFILE.as_bytes(), &"0".repeat(64), &out, &origin()).unwrap_err();

        assert!(matches!(err, FetchError::HashMismatch { .. }), "{err}");
        assert!(!out.exists(), "the destination must not appear on mismatch");
        assert!(
            staging_leftovers(&dir).is_empty(),
            "the staging file must be cleaned up: {:?}",
            staging_leftovers(&dir)
        );
    }

    /// A refusal does not eat what was already there: a pre-existing
    /// destination file survives byte-for-byte.
    #[test]
    fn a_mismatch_leaves_a_pre_existing_destination_untouched() {
        let dir = temp_dir("pre-existing");
        let out = dir.join("profile.json");
        std::fs::write(&out, b"already here").unwrap();

        assert!(admit(PROFILE.as_bytes(), &"0".repeat(64), &out, &origin()).is_err());

        assert_eq!(std::fs::read(&out).unwrap(), b"already here");
        std::fs::remove_file(&out).ok();
    }

    /// A body that is not a profile refuses before hashing, and cleans
    /// up the same way.
    #[test]
    fn a_non_profile_body_is_refused_and_cleaned_up() {
        let dir = temp_dir("not-a-profile");
        let out = dir.join("profile.json");

        let err = admit(b"{ not json", &"0".repeat(64), &out, &origin()).unwrap_err();

        assert!(matches!(err, FetchError::NotAProfile { .. }), "{err}");
        assert!(!out.exists());
        assert!(staging_leftovers(&dir).is_empty());
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

        let err = admit(body.as_bytes(), &expected, &out, &origin()).unwrap_err();

        assert!(matches!(err, FetchError::NotASpec), "{err}");
        assert!(!out.exists());
        assert!(staging_leftovers(&dir).is_empty());
    }

    /// **A fetched body's imports belong to the URL it came from, not
    /// to the temp file it is sitting in.** This body carries a
    /// relative import with no pin. Resolved at the origin it is a
    /// remote import — remote imports must be pinned (spec 11 §The
    /// `Import` node), and that is the refusal. Resolved at the staging
    /// file, as it was before, the same `./frag.json` read as an
    /// operator-host path: no pin required, and a fragment picked up
    /// from whatever happened to be next to the temp file.
    #[test]
    fn a_fetched_bodys_relative_import_resolves_against_the_origin_url() {
        let dir = temp_dir("remote-origin");
        let out = dir.join("profile.json");
        let body = serde_json::json!({
            "type": "Spec",
            "name": "imports-a-sibling",
            "phases": [{ "type": "Import", "src": "./frag.json" }]
        })
        .to_string();

        let err = admit(body.as_bytes(), &"0".repeat(64), &out, &origin()).unwrap_err();

        let FetchError::Unresolvable { message } = &err else {
            panic!("expected an unresolvable body, got: {err}");
        };
        assert!(
            message.contains("carries no hash pin"),
            "the import must be judged as remote: {message}"
        );
        assert!(
            message.contains("https://example.com/profiles/"),
            "the chain must name the origin, not the staging file: {message}"
        );
        assert!(!out.exists());
        assert!(staging_leftovers(&dir).is_empty());
    }

    /// The staging file is created exclusively: a file already at the
    /// staging path (a symlink someone planted, a leftover) refuses
    /// the run instead of being written through.
    ///
    /// Drives [`admit_into`] because the path is the subject here — a
    /// counter-bearing name is unpredictable by design, so the test
    /// names the staging file and hands the same one to the code.
    #[test]
    fn an_occupied_staging_path_refuses_instead_of_overwriting() {
        let dir = temp_dir("occupied");
        let out = dir.join("profile.json");
        let staging = staging_path(&out, 0);
        std::fs::write(&staging, b"planted").unwrap();

        let err = admit_into(
            PROFILE.as_bytes(),
            &"0".repeat(64),
            &out,
            &staging,
            &origin(),
        )
        .unwrap_err();

        assert!(matches!(err, FetchError::Io { .. }), "{err}");
        assert_eq!(
            std::fs::read(&staging).unwrap(),
            b"planted",
            "the occupant must not be overwritten"
        );
        std::fs::remove_file(&staging).ok();
    }
}
