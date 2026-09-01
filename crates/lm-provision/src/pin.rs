//! The `pin` subcommand (spec 11 §The resolver layer): rewrite every
//! `Import` in a JSON profile whose `src` is the `name@version`
//! shorthand into the explicit pinned `src` + `hash` form, using an
//! `index.json` — local file or HTTPS URL — as the resolver.
//!
//! # Why it lives *outside* the DSL
//!
//! The DSL only speaks the explicit form (spec 11 §The `Import` node —
//! `src` is the *literal* location and `hash` the pin). `name@version`
//! is authoring convenience: the wire format is always what the file
//! says, and what the file says is what `lm-provision hash` covers.
//! This subcommand is the one thing that converts the convenient shape
//! into the wire shape, at authoring time, and writes the result back.
//!
//! # Verify-before-write
//!
//! After rewriting the document in memory the subcommand materializes
//! it to a temp file in the same directory as the target, then runs
//! [`crate::resolve::resolve`] on it — which fetches every rewritten
//! fragment and re-verifies every pin against its expanded canonical
//! hash. Only after that succeeds does the temp file rename over the
//! original; on any failure the temp file is removed and the original
//! is left untouched. This is what keeps `pin` from ever writing a
//! document that does not itself resolve.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value};
use url::Url;

use crate::resolve::{ReqwestFragmentSource, ResolveCtx};

/// Per-process counter appended to a pin verify-temp file's name so
/// two `pin` runs in one process do not race on the same temp path.
/// Same shape as [`crate::resolve`]'s cache-temp counter.
static PIN_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A `pin`-stage rejection. Rendered as the single stderr failure line
/// (07-cli.md §Error surface), so each variant carries what that line
/// needs and nothing else.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// The target profile could not be read from disk.
    #[error("could not read profile {}: {message}", path.display())]
    Io {
        /// The path that failed to open.
        path: PathBuf,
        /// The OS error's own words.
        message: String,
    },

    /// The target profile is not JSON. MVP is JSON-only: the canonical
    /// text form does not have an object-preserving pass we can rewrite
    /// through without re-serializing every canonical byte the author
    /// carefully spelled out. Named as an implementation limit rather
    /// than a rejection of text profiles at large (deferred).
    #[error(
        "pin only supports JSON profiles (`{}`); the canonical text form is not \
         rewritable without losing whitespace and comments — deferred",
        path.display()
    )]
    NotJson {
        /// The path with the non-`.json` extension.
        path: PathBuf,
    },

    /// The target profile is malformed JSON — not this subcommand's
    /// business to fix.
    #[error("could not parse profile {} as JSON: {message}", path.display())]
    Parse {
        /// The path that failed to parse.
        path: PathBuf,
        /// The `serde_json` error message.
        message: String,
    },

    /// The `--index` argument could not be read as JSON (I/O failure,
    /// HTTP failure, or malformed body).
    #[error("could not load index {index}: {message}")]
    IndexUnavailable {
        /// The `--index` argument as written.
        index: String,
        /// What failed.
        message: String,
    },

    /// The index parsed but its shape is not the `{"profiles": [...]}`
    /// this subcommand consumes.
    #[error("index {index} has an unexpected shape: {message}")]
    IndexShape {
        /// The `--index` argument as written.
        index: String,
        /// What shape rule failed.
        message: String,
    },

    /// A `name@version` in the profile has no matching entry in the
    /// index.
    #[error("no entry named {name}@{version} in index {index}")]
    NoIndexEntry {
        /// The unmatched name.
        name: String,
        /// The unmatched version.
        version: String,
        /// The `--index` argument as written.
        index: String,
    },

    /// The rewritten profile did not itself resolve — a rewritten pin
    /// is off, a fragment named in the index cannot be fetched, or one
    /// of the fragment's own imports has a problem. `pin` never writes
    /// a document that does not resolve, so this reaches the stderr
    /// line with the original file intact.
    #[error("rewritten profile does not resolve: {message}")]
    VerifyFailed {
        /// The resolve error, verbatim.
        message: String,
    },

    /// The rewritten profile could not be renamed over the original.
    #[error("could not write {}: {message}", path.display())]
    Write {
        /// The destination that failed.
        path: PathBuf,
        /// The OS error's own words.
        message: String,
    },
}

/// One `name@version` import that `pin` rewrote — echoed on the stdout
/// artifact so the caller sees exactly what changed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Pinned {
    /// Name half of `name@version`, as written.
    pub name: String,
    /// Version half, as written.
    pub version: String,
    /// The new `src` (index location parent joined with the entry's
    /// `path`, HTTPS or local).
    pub src: String,
    /// The new `hash` — the entry's `profile_hash`.
    pub hash: String,
}

/// Result of a successful [`pin`] run.
#[derive(Debug)]
pub struct PinOutcome {
    /// The rewrites `pin` applied. Empty when the profile has no
    /// `name@version` imports — the run is a no-op and the file is not
    /// touched.
    pub pinned: Vec<Pinned>,
}

/// Run the `pin` subcommand.
///
/// See the module doc for what the flow does and the invariants it
/// maintains.
pub fn pin(profile: &Path, index: &str) -> Result<PinOutcome, PinError> {
    let source = ReqwestFragmentSource;
    let ctx = ResolveCtx {
        source: &source,
        cache_root: crate::resolve::default_cache_root(),
    };
    pin_with_ctx(profile, index, &ctx)
}

/// [`pin`] with a caller-supplied [`ResolveCtx`]. `pub(crate)` for the
/// same reason [`crate::resolve::resolve_with_ctx`] is: tests inject a
/// fake source and a scratch cache directory rather than touching the
/// operator's real XDG root.
pub(crate) fn pin_with_ctx(
    profile: &Path,
    index: &str,
    ctx: &ResolveCtx<'_>,
) -> Result<PinOutcome, PinError> {
    // JSON-only for MVP: name the limitation loudly rather than falling
    // through to a rewrite path that doesn't exist.
    let is_json = profile
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    if !is_json {
        return Err(PinError::NotJson {
            path: profile.to_path_buf(),
        });
    }

    let text = std::fs::read_to_string(profile).map_err(|err| PinError::Io {
        path: profile.to_path_buf(),
        message: err.to_string(),
    })?;
    let mut value: Value = serde_json::from_str(&text).map_err(|err| PinError::Parse {
        path: profile.to_path_buf(),
        message: err.to_string(),
    })?;

    // Load the index in whichever form was requested.
    let (index_body, index_kind) = load_index(index, ctx)?;
    let entries: IndexEntries =
        serde_json::from_slice(&index_body).map_err(|err| PinError::IndexShape {
            index: index.to_string(),
            message: err.to_string(),
        })?;

    // Walk the Value tree, rewriting every `name@version` Import in
    // place and recording what changed.
    let mut pinned = Vec::new();
    rewrite_imports(&mut value, index, &entries, &index_kind, &mut pinned)?;

    // No rewrites → idempotent no-op: succeed with the empty log and
    // do not touch the file (`pin` on an already-pinned profile is
    // safe to loop).
    if pinned.is_empty() {
        return Ok(PinOutcome { pinned });
    }

    // Verify-before-write: materialize to a temp file next to the
    // target, resolve it (which fetches every rewritten pin's fragment
    // and re-hashes it), then rename over the original on success. On
    // any failure the temp file is removed and the original is left
    // untouched.
    //
    // The temp file's name preserves the `.json` extension so
    // `frontend::load_profile` routes it to the JSON serde bridge —
    // the frontend picks its parser by extension alone.
    //
    // Written exclusively via `File::create_new`: same judgement as
    // [`crate::fetch::admit`]'s staging file — a pre-planted temp
    // (leftover from a killed run, a planted symlink) refuses to be
    // written through, so this run vouches only for what it wrote
    // itself. A unique per-call name (pid + a monotonically increasing
    // counter) avoids legitimate collisions between concurrent pin
    // runs in the same process.
    let parent = profile.parent().unwrap_or(Path::new("."));
    let stem = profile
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("profile");
    let seq = PIN_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".{stem}.pin-{}-{seq}.json", std::process::id()));
    let rendered = serde_json::to_vec_pretty(&value).expect("Value serialization is infallible");
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create_new(&temp).map_err(|err| PinError::Write {
            path: temp.clone(),
            message: err.to_string(),
        })?;
        file.write_all(&rendered).map_err(|err| PinError::Write {
            path: temp.clone(),
            message: err.to_string(),
        })?;
    }

    let verify_result = (|| -> Result<(), PinError> {
        let node = crate::frontend::load_profile(&temp).map_err(|err| PinError::VerifyFailed {
            message: err.to_string(),
        })?;
        crate::resolve::resolve_with_ctx(node, &temp, ctx).map_err(|err| {
            PinError::VerifyFailed {
                message: err.to_string(),
            }
        })?;
        Ok(())
    })();

    match verify_result {
        Ok(()) => {
            std::fs::rename(&temp, profile).map_err(|err| {
                // Clean up the temp file if the rename didn't consume it.
                let _ = std::fs::remove_file(&temp);
                PinError::Write {
                    path: profile.to_path_buf(),
                    message: err.to_string(),
                }
            })?;
            Ok(PinOutcome { pinned })
        }
        Err(err) => {
            let _ = std::fs::remove_file(&temp);
            Err(err)
        }
    }
}

/// The shape [`pin`] consumes from `index.json`. Extra fields on each
/// entry (`summary`, whatever) are ignored — this consumer names only
/// what it uses.
#[derive(Debug, serde::Deserialize)]
struct IndexEntries {
    profiles: Vec<IndexEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct IndexEntry {
    name: String,
    version: String,
    path: String,
    profile_hash: String,
}

/// Where the index lives: needed for joining a relative entry `path`.
enum IndexKind {
    /// A URL index — entries join via `Url::join`, producing a URL
    /// again (spec 11 §Adopted conventions: URL is a location hint,
    /// but the pin makes the identity content-addressed).
    Url(Url),
    /// A local file index — entries join via filesystem
    /// path-concatenation.
    Path(PathBuf),
}

/// Load `index` — HTTPS URL or local path — into raw bytes.
///
/// Scheme detection uses [`crate::resolve::has_scheme`] (case-
/// insensitive per RFC 3986 §3.1) so `HTTPS://…` is treated as a URL,
/// not fallen through to `std::fs::read` as a local path.
fn load_index(index: &str, ctx: &ResolveCtx<'_>) -> Result<(Vec<u8>, IndexKind), PinError> {
    if crate::resolve::has_scheme(index, "https://") {
        let url = Url::parse(index).map_err(|err| PinError::IndexUnavailable {
            index: index.to_string(),
            message: format!("malformed URL: {err}"),
        })?;
        let bytes = ctx
            .source
            .fetch(&url)
            .map_err(|err| PinError::IndexUnavailable {
                index: index.to_string(),
                message: err,
            })?;
        Ok((bytes, IndexKind::Url(url)))
    } else if crate::resolve::has_scheme(index, "http://") {
        // Match the resolver's own "https only" rule for symmetry.
        Err(PinError::IndexUnavailable {
            index: index.to_string(),
            message: "http:// indexes are refused; use https or a local path".to_string(),
        })
    } else {
        let path = PathBuf::from(index);
        let bytes = std::fs::read(&path).map_err(|err| PinError::IndexUnavailable {
            index: index.to_string(),
            message: err.to_string(),
        })?;
        Ok((bytes, IndexKind::Path(path)))
    }
}

/// Walk the JSON `value` tree in place, rewriting every object with
/// `"type": "Import"` whose `src` matches the `name@version` shape.
fn rewrite_imports(
    value: &mut Value,
    index: &str,
    entries: &IndexEntries,
    index_kind: &IndexKind,
    pinned: &mut Vec<Pinned>,
) -> Result<(), PinError> {
    match value {
        Value::Object(obj) => {
            if is_import_object(obj) {
                if let Some(Value::String(src)) = obj.get("src") {
                    if crate::resolve::looks_like_name_at_version(src) {
                        // Both halves already validated by
                        // looks_like_name_at_version — split cannot
                        // fail.
                        let (name, version) = src
                            .split_once('@')
                            .expect("name@version shape guarantees a split");
                        let entry = entries
                            .profiles
                            .iter()
                            .find(|e| e.name == name && e.version == version)
                            .ok_or_else(|| PinError::NoIndexEntry {
                                name: name.to_string(),
                                version: version.to_string(),
                                index: index.to_string(),
                            })?;
                        let new_src = join_entry(index_kind, &entry.path)?;
                        let record = Pinned {
                            name: name.to_string(),
                            version: version.to_string(),
                            src: new_src.clone(),
                            hash: entry.profile_hash.clone(),
                        };
                        pinned.push(record);
                        obj.insert("src".into(), Value::String(new_src));
                        obj.insert("hash".into(), Value::String(entry.profile_hash.clone()));
                    }
                }
                // Do not recurse into the import object's children —
                // `src` / `hash` are scalars and no other field of the
                // Import variant carries a nested Import.
                return Ok(());
            }
            for (_, child) in obj.iter_mut() {
                rewrite_imports(child, index, entries, index_kind, pinned)?;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                rewrite_imports(item, index, entries, index_kind, pinned)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_import_object(obj: &Map<String, Value>) -> bool {
    matches!(obj.get("type"), Some(Value::String(t)) if t == "Import")
}

/// Join an index-relative entry `path` against the index's own location.
/// A URL index produces another URL (`Url::join` — the parent of the
/// index URL is what "relative to" means here); a local index produces
/// an **absolute** local path so the written `src` is location-
/// independent.
///
/// A CWD-relative or profile-relative spelling would break resolve:
/// `pin`'s `--index` argument is resolved relative to the caller's
/// CWD, but the resolver later anchors relative `src` values against
/// the *importing profile's own directory* (spec 11 §Resolution
/// step 2). Canonicalizing the index's parent here writes an absolute
/// src that the resolver interprets the same way no matter which
/// directory the profile is opened from.
fn join_entry(index_kind: &IndexKind, entry_path: &str) -> Result<String, PinError> {
    match index_kind {
        IndexKind::Url(url) => {
            let joined = url.join(entry_path).map_err(|err| PinError::IndexShape {
                index: url.as_str().to_string(),
                message: format!(
                    "could not join entry path {entry_path:?} against index URL: {err}"
                ),
            })?;
            Ok(joined.to_string())
        }
        IndexKind::Path(path) => {
            let raw_parent = path.parent().unwrap_or(Path::new("."));
            // `canonicalize` requires the directory to exist — it does
            // (we just read the index out of it). If it somehow does
            // not by the time we get here, name the failure as an
            // IndexUnavailable rather than write a src that the
            // resolver would silently misanchor.
            let parent =
                std::fs::canonicalize(raw_parent).map_err(|err| PinError::IndexUnavailable {
                    index: path.display().to_string(),
                    message: format!(
                        "could not canonicalize index parent directory {}: {err}",
                        raw_parent.display()
                    ),
                })?;
            let joined = parent.join(entry_path);
            Ok(joined.display().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;
    use crate::frontend;
    use crate::resolve::{FragmentSource, ResolveCtx};
    use dsl_kit::IdGen;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lm-provision-pin-{}-{test}", std::process::id(),));
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        dir
    }

    fn write(dir: &Path, name: &str, value: &Value) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    #[derive(Default)]
    struct FakeSource {
        entries: std::collections::HashMap<String, Vec<u8>>,
        calls: AtomicUsize,
    }

    impl FakeSource {
        fn new(entries: &[(&str, &[u8])]) -> Self {
            let mut map = std::collections::HashMap::new();
            for (url, bytes) in entries {
                map.insert((*url).to_string(), bytes.to_vec());
            }
            Self {
                entries: map,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl FragmentSource for FakeSource {
        fn fetch(&self, url: &Url) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.entries.get(url.as_str()) {
                Some(bytes) => Ok(bytes.clone()),
                None => Err(format!("no entry for {}", url.as_str())),
            }
        }
    }

    fn frag_bytes() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "Fragment",
            "name": "frag",
            "capabilities": ["sh.exec"],
            "paths": ["/workspace"],
            "phases": [{ "type": "ShExec", "argv": ["echo", "ok"] }]
        }))
        .unwrap()
    }

    fn pin_of(bytes: &[u8]) -> String {
        let ast = frontend::load_profile_bytes(bytes, true, &IdGen::new()).unwrap();
        canonical::hash(&ast)
    }

    fn ctx_with<'a>(src: &'a dyn FragmentSource, dir: &Path) -> ResolveCtx<'a> {
        ResolveCtx {
            source: src,
            cache_root: dir.join("cache"),
        }
    }

    /// Local index + local fragments: `pin` rewrites the profile and
    /// the verify-then-rename lands the new bytes.
    #[test]
    fn pin_rewrites_name_at_version_against_a_local_index() {
        let dir = temp_dir("local-happy");
        let frag = frag_bytes();
        let frag_path = write(
            &dir,
            "my-frag-0.1.0.json",
            &serde_json::from_slice(&frag).unwrap(),
        );
        let frag_pin = pin_of(&frag);
        let index = json!({
            "profiles": [
                {
                    "name": "my-frag",
                    "version": "0.1.0",
                    "path": "my-frag-0.1.0.json",
                    "profile_hash": frag_pin,
                }
            ]
        });
        let index_path = write(&dir, "index.json", &index);
        let profile = write(
            &dir,
            "profile.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "capabilities": ["sh.exec"],
                "paths": ["/workspace"],
                "phases": [
                    { "type": "SystemApt", "packages": ["git"] },
                    { "type": "Import", "src": "my-frag@0.1.0" }
                ]
            }),
        );

        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        let outcome =
            pin_with_ctx(&profile, index_path.to_str().unwrap(), &ctx).expect("pin must succeed");

        assert_eq!(outcome.pinned.len(), 1);
        assert_eq!(outcome.pinned[0].name, "my-frag");
        assert_eq!(outcome.pinned[0].hash, frag_pin);
        assert!(outcome.pinned[0].src.ends_with("my-frag-0.1.0.json"));

        // Read back and confirm the profile now carries the pinned form.
        let rewritten: Value = serde_json::from_slice(&std::fs::read(&profile).unwrap()).unwrap();
        let phases = rewritten["phases"].as_array().unwrap();
        let import = &phases[1];
        assert_eq!(import["type"], "Import");
        assert_eq!(import["hash"], frag_pin);
        assert!(import["src"]
            .as_str()
            .unwrap()
            .ends_with("my-frag-0.1.0.json"));

        // And the resulting profile is resolvable — the whole point of
        // the verify step.
        let node = frontend::load_profile(&profile).unwrap();
        crate::resolve::resolve_with_ctx(node, &profile, &ctx)
            .expect("rewritten profile must resolve");

        // Consumed fragment: never fetched through source (local).
        // Silence unused var.
        let _ = frag_path;
    }

    /// Idempotent: a profile with no `name@version` imports is a no-op
    /// — pinned is empty and the file is unchanged.
    #[test]
    fn pin_is_idempotent_when_no_shortcuts_exist() {
        let dir = temp_dir("noop");
        let index_path = write(&dir, "index.json", &json!({ "profiles": [] }));
        let profile_value = json!({
            "type": "Spec",
            "name": "already-pinned",
            "capabilities": ["sh.exec"],
            "phases": [
                { "type": "ShExec", "argv": ["echo", "ok"] }
            ]
        });
        let profile = write(&dir, "profile.json", &profile_value);
        let before = std::fs::read(&profile).unwrap();

        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        let outcome = pin_with_ctx(&profile, index_path.to_str().unwrap(), &ctx)
            .expect("noop pin must succeed");

        assert!(outcome.pinned.is_empty());
        assert_eq!(
            std::fs::read(&profile).unwrap(),
            before,
            "file must be byte-identical"
        );
    }

    /// A `name@version` with no matching entry is
    /// [`PinError::NoIndexEntry`]; the file is not rewritten.
    #[test]
    fn pin_names_the_missing_index_entry() {
        let dir = temp_dir("missing-entry");
        let index_path = write(&dir, "index.json", &json!({ "profiles": [] }));
        let profile = write(
            &dir,
            "profile.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "phases": [{ "type": "Import", "src": "not-there@1.0.0" }]
            }),
        );
        let before = std::fs::read(&profile).unwrap();

        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        match pin_with_ctx(&profile, index_path.to_str().unwrap(), &ctx) {
            Err(PinError::NoIndexEntry { name, version, .. }) => {
                assert_eq!(name, "not-there");
                assert_eq!(version, "1.0.0");
            }
            other => panic!("expected NoIndexEntry, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&profile).unwrap(),
            before,
            "file must be untouched on failure"
        );
    }

    /// If the verify step fails (e.g. the index pointed at a hash the
    /// fragment does not carry), the original profile is left intact
    /// and the temp file is cleaned up.
    #[test]
    fn pin_leaves_the_file_untouched_when_verify_fails() {
        let dir = temp_dir("verify-fail");
        let frag = frag_bytes();
        let _frag_path = write(
            &dir,
            "my-frag-0.1.0.json",
            &serde_json::from_slice(&frag).unwrap(),
        );
        // Index lies about the hash: verify must catch it.
        let index = json!({
            "profiles": [
                {
                    "name": "my-frag",
                    "version": "0.1.0",
                    "path": "my-frag-0.1.0.json",
                    "profile_hash": "0".repeat(64),
                }
            ]
        });
        let index_path = write(&dir, "index.json", &index);
        let profile_value = json!({
            "type": "Spec",
            "name": "consumer",
            "phases": [{ "type": "Import", "src": "my-frag@0.1.0" }]
        });
        let profile = write(&dir, "profile.json", &profile_value);
        let before = std::fs::read(&profile).unwrap();

        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        match pin_with_ctx(&profile, index_path.to_str().unwrap(), &ctx) {
            Err(PinError::VerifyFailed { .. }) => {}
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&profile).unwrap(),
            before,
            "file must be byte-identical after a verify failure"
        );
    }

    /// The written `src` is anchored to the *index file's* directory,
    /// not to the caller's CWD — so a profile in one subdir and an
    /// index + fragment in a sibling dir resolves correctly against
    /// what `pin` wrote. Regression against the CWD-relative bug: the
    /// resolver later anchors relative srcs against the importing
    /// profile's own directory (spec 11 §Resolution step 2), so a
    /// CWD-relative rewrite would fail pin's own verify pass when the
    /// two paths differ. Tests never `chdir` — cwd is process-wide.
    #[test]
    fn pin_writes_an_absolute_src_when_the_index_lives_in_a_sibling_dir() {
        let dir = temp_dir("layout-siblings");
        let profiles_dir = dir.join("profiles");
        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::create_dir_all(&registry_dir).unwrap();

        let frag = frag_bytes();
        let frag_path = registry_dir.join("my-frag-0.1.0.json");
        std::fs::write(&frag_path, &frag).unwrap();
        let frag_pin = pin_of(&frag);

        let index = json!({
            "profiles": [
                {
                    "name": "my-frag",
                    "version": "0.1.0",
                    "path": "my-frag-0.1.0.json",
                    "profile_hash": frag_pin,
                }
            ]
        });
        let index_path = registry_dir.join("index.json");
        std::fs::write(&index_path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();

        let profile_path = profiles_dir.join("consumer.json");
        std::fs::write(
            &profile_path,
            serde_json::to_vec_pretty(&json!({
                "type": "Spec",
                "name": "consumer",
                "capabilities": ["sh.exec"],
                "paths": ["/workspace"],
                "phases": [
                    { "type": "Import", "src": "my-frag@0.1.0" }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        let outcome = pin_with_ctx(&profile_path, index_path.to_str().unwrap(), &ctx)
            .expect("pin must succeed when profile and index live in sibling dirs");

        assert_eq!(outcome.pinned.len(), 1);
        // The written `src` is absolute — location-independent — so
        // the resolver anchors it correctly regardless of the profile
        // file's own parent directory.
        assert!(
            Path::new(&outcome.pinned[0].src).is_absolute(),
            "written src must be absolute, got {:?}",
            outcome.pinned[0].src
        );
        // And it points at the actual fragment file (canonicalized).
        let canonical_frag = std::fs::canonicalize(&frag_path).unwrap();
        assert_eq!(
            Path::new(&outcome.pinned[0].src),
            canonical_frag,
            "written src must be the canonical fragment path"
        );

        // Verify: re-resolve the on-disk rewritten profile and confirm
        // that resolves too (belt and braces — pin's own verify pass
        // has already run, but this asserts the *persisted* file is
        // resolvable).
        let node = frontend::load_profile(&profile_path).unwrap();
        crate::resolve::resolve_with_ctx(node, &profile_path, &ctx)
            .expect("the rewritten profile must resolve after write");
    }

    /// A non-`.json` target is refused up front (MVP limitation).
    #[test]
    fn pin_refuses_non_json_profiles() {
        let dir = temp_dir("not-json");
        let profile = dir.join("profile.txt");
        std::fs::write(&profile, b"Spec()").unwrap();
        let source = FakeSource::new(&[]);
        let ctx = ctx_with(&source, &dir);
        match pin_with_ctx(&profile, "irrelevant", &ctx) {
            Err(PinError::NotJson { .. }) => {}
            other => panic!("expected NotJson, got {other:?}"),
        }
    }
}
