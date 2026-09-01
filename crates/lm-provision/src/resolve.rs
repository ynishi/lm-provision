//! Fragment-import resolution: the pipeline stage between load and
//! validate (spec `11-fragment-import.md` §Resolution).
//!
//! ```text
//! load → resolve → validate → canonical / hash → plan → …
//! ```
//!
//! Everything downstream of resolve sees a plain expanded
//! [`ProfileNode::Spec`]: each [`ProfileNode::Import`] is replaced in
//! place by the imported fragment's expanded phase list, and the
//! fragment's declarations merge into the consumer's (§Resolution
//! rule 5 — set union for the set-shaped lists, disjoint-key merge for
//! `env` / `assumes`). A profile with no `Import` node expands to
//! itself, so every existing profile keeps the hash its ledger rows
//! already carry (spec 11 §Stability guarantee 1).
//!
//! **Identity**: [`crate::canonical::hash`] of the expanded AST is
//! *the* profile hash. A pin, when written, is verified against the
//! fragment's own **expanded canonical hash** (chapter 03 rules applied
//! to the expanded [`ProfileNode::Fragment`] node — §Resolution
//! rule 3), so a fragment's internal refactoring never invalidates
//! consumers (spec 11 §Stability guarantee 2).
//!
//! ## Scope of this revision (spec 11 §MVP scope increment 1)
//!
//! Local imports only: relative paths (resolved against the importing
//! document's own location — fragment-relative, never
//! consumer-relative) and absolute operator-host paths. A remote
//! `https://` import is recognized, has its pin requirement enforced
//! (an unpinned remote is [`ResolveError::ImportHashRequired`], not
//! fetched-then-warned), and then fails as
//! [`ResolveError::ImportUnresolved`] naming the unimplemented fetch —
//! increment 2 adds the fetch, the referential sanity check, and the
//! XDG cache behind the same node shape.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dsl_kit::IdGen;

use crate::canonical;
use crate::frontend;
use crate::profile_ast::ProfileNode;

/// A resolve-stage rejection (spec 11 §Error surface). Every message
/// names the import chain (`consumer → … → fragment`) that produced
/// it.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Fetch / read of an `Import.src` failed.
    #[error("import of {src:?} could not be resolved: {detail} (import chain: {chain})")]
    ImportUnresolved {
        /// The `src` as written.
        src: String,
        /// What failed (I/O, parse, or the unimplemented remote fetch).
        detail: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// A remote `src` with no `hash` pin. Rejected at resolve, never
    /// fetched-then-warned (spec 11 §The `Import` node).
    #[error(
        "remote import of {src:?} carries no hash pin; a pin is \
         mandatory for remote sources (import chain: {chain})"
    )]
    ImportHashRequired {
        /// The `src` as written.
        src: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// The fragment's expanded canonical hash does not match the pin.
    /// Nothing was kept and nothing merged.
    #[error(
        "import of {src:?} failed hash verification: expected {expected}, \
         got {actual}; nothing was merged (import chain: {chain})"
    )]
    ImportHashMismatch {
        /// The `src` as written.
        src: String,
        /// The pin as written (case-normalized).
        expected: String,
        /// The fragment's actual expanded canonical hash.
        actual: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// A written pin is not a 64-character hex SHA-256. Rejected before
    /// any comparison so a malformed pin reads as the authoring mistake
    /// it is, not as a content mismatch. (Not in the spec 11 error
    /// table; recorded here as an implementation-stage refinement of
    /// `ImportHashMismatch`.)
    #[error(
        "import of {src:?} carries a malformed hash pin {hash:?}; \
         the pin is a 64-character lowercase hex SHA-256 \
         (import chain: {chain})"
    )]
    ImportPinShape {
        /// The `src` as written.
        src: String,
        /// The malformed pin as written.
        hash: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// A fragment is reachable from itself.
    #[error("import cycle detected at {src:?} (import chain: {chain})")]
    ImportCycle {
        /// The `src` whose resolution closed the cycle.
        src: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// A `src` outside the three source forms: non-https remote,
    /// `file://`, `~/` home path (spec 11 §Source forms).
    #[error("import of {src:?} denied: {reason} (import chain: {chain})")]
    ImportSchemeDenied {
        /// The `src` as written.
        src: String,
        /// Which source-form rule rejected it.
        reason: &'static str,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// An `env` / `assumes` key declared by both sides with different
    /// values. An error, **not an override** (spec 11 §Resolution
    /// rule 5); identical entries deduplicate silently.
    #[error(
        "import of {src:?} collides on {slot}[{key:?}]: both sides declare \
         it with different values; overrides are not a merge rule \
         (import chain: {chain})"
    )]
    ImportMergeCollision {
        /// The `src` whose merge collided.
        src: String,
        /// `"env"` or `"assumes"`.
        slot: &'static str,
        /// The colliding key.
        key: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },

    /// The imported document's root is not a [`ProfileNode::Fragment`].
    /// A fragment is a top-level `Fragment` node (spec 11 §Fragment
    /// documents); importing a full `Spec` profile is not defined. (Not
    /// in the spec 11 error table; recorded here as an
    /// implementation-stage gap the spec should absorb.)
    #[error(
        "import of {src:?} is not a fragment document: its root must be \
         a Fragment node (import chain: {chain})"
    )]
    ImportNotAFragment {
        /// The `src` as written.
        src: String,
        /// The `consumer → … → fragment` chain.
        chain: String,
    },
}

/// Resolve every [`ProfileNode::Import`] in `root`, which was loaded
/// from `doc_path`. Returns the expanded document — the same root
/// variant, with no `Import` remaining anywhere beneath it.
///
/// A root with no `Import` node expands to itself; a non-`Spec` /
/// non-`Fragment` root is returned unchanged (validate owns rejecting
/// it, as it always has).
///
/// Takes `root` by value: the no-import path (every existing profile)
/// moves the tree straight through, and spliced fragments move rather
/// than clone.
pub fn resolve(root: ProfileNode, doc_path: &Path) -> Result<ProfileNode, ResolveError> {
    // Every fragment parse mints from this one generator, seeded above
    // every id the consumer's own parse allocated — the same injectivity
    // rule `normalize`'s inserted phases follow, for the same measured
    // reason (normalize.rs `IdMinter`: a NodeId collision made the
    // engine run one phase in place of the whole profile). Each
    // `frontend::load_profile` call starts a fresh `IdGen` at zero, so
    // splicing fragment nodes with their original ids is guaranteed to
    // collide with the consumer's.
    let ids = IdGen::new();
    for _ in 0..=crate::normalize::max_node_id(&root) {
        ids.node();
    }
    let mut chain = vec![doc_path.display().to_string()];
    let mut stack = vec![stable_key(doc_path)];
    expand_document(root, doc_path, &ids, &mut stack, &mut chain)
}

/// A path key for cycle detection: canonicalized when the file exists
/// (so `./a.json` and `a.json` collide as they should), the lexical
/// path otherwise (a missing file fails at read, not here).
fn stable_key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Expand one document in place: `Spec` and `Fragment` roots get their
/// phase lists expanded and their declaration slots merged; any other
/// root passes through untouched.
fn expand_document(
    root: ProfileNode,
    doc_path: &Path,
    ids: &IdGen,
    stack: &mut Vec<PathBuf>,
    chain: &mut Vec<String>,
) -> Result<ProfileNode, ResolveError> {
    match root {
        ProfileNode::Spec {
            id,
            name,
            version,
            description,
            capabilities,
            env,
            env_secrets,
            paths,
            http_allowlist,
            assumes,
            requires_ports,
            requires_gpu,
            requires_disk,
            provider,
            artifacts,
            phases,
        } => {
            let mut slots = Slots {
                capabilities,
                env,
                env_secrets,
                paths,
                http_allowlist,
                assumes,
            };
            let phases = expand_phases(phases, doc_path, ids, &mut slots, stack, chain)?;
            Ok(ProfileNode::Spec {
                id,
                name,
                version,
                description,
                capabilities: slots.capabilities,
                env: slots.env,
                env_secrets: slots.env_secrets,
                paths: slots.paths,
                http_allowlist: slots.http_allowlist,
                assumes: slots.assumes,
                requires_ports,
                requires_gpu,
                requires_disk,
                provider,
                artifacts,
                phases,
            })
        }
        ProfileNode::Fragment {
            id,
            name,
            version,
            description,
            capabilities,
            env,
            env_secrets,
            paths,
            http_allowlist,
            assumes,
            phases,
        } => {
            let mut slots = Slots {
                capabilities,
                env,
                env_secrets,
                paths,
                http_allowlist,
                assumes,
            };
            let phases = expand_phases(phases, doc_path, ids, &mut slots, stack, chain)?;
            Ok(ProfileNode::Fragment {
                id,
                name,
                version,
                description,
                capabilities: slots.capabilities,
                env: slots.env,
                env_secrets: slots.env_secrets,
                paths: slots.paths,
                http_allowlist: slots.http_allowlist,
                assumes: slots.assumes,
                phases,
            })
        }
        other => Ok(other),
    }
}

/// The declaration slots a fragment merges into — shared between the
/// `Spec` and `Fragment` halves of [`expand_document`], because a
/// nested fragment merges into its *importing fragment* by exactly the
/// rule a top-level fragment merges into the profile (§Resolution
/// rule 5, applied at each level).
struct Slots {
    capabilities: Vec<String>,
    env: BTreeMap<String, ProfileNode>,
    env_secrets: Vec<String>,
    paths: Vec<String>,
    http_allowlist: Vec<String>,
    assumes: BTreeMap<String, String>,
}

/// Expand a phase list: every [`ProfileNode::Import`] is replaced by
/// its fragment's expanded phase list (order preserved on both sides —
/// §Resolution rule 4), and the fragment's declarations merge into
/// `slots` (§Resolution rule 5). Every other phase passes through.
fn expand_phases(
    phases: Vec<ProfileNode>,
    doc_path: &Path,
    ids: &IdGen,
    slots: &mut Slots,
    stack: &mut Vec<PathBuf>,
    chain: &mut Vec<String>,
) -> Result<Vec<ProfileNode>, ResolveError> {
    let mut out = Vec::with_capacity(phases.len());
    for phase in phases {
        match phase {
            ProfileNode::Import { id: _, src, hash } => {
                let (fragment, fragment_chain) =
                    expand_import(&src, hash.as_deref(), doc_path, ids, stack, chain)?;
                let ProfileNode::Fragment {
                    capabilities,
                    env,
                    env_secrets,
                    paths,
                    http_allowlist,
                    assumes,
                    phases: fragment_phases,
                    ..
                } = fragment
                else {
                    // expand_import guarantees a Fragment; if a refactor
                    // ever breaks that, dropping the import's whole
                    // contribution silently is the worst failure
                    // available — fail loudly instead.
                    return Err(ResolveError::ImportNotAFragment {
                        src,
                        chain: fragment_chain,
                    });
                };
                merge_union(&mut slots.capabilities, capabilities);
                merge_union(&mut slots.env_secrets, env_secrets);
                merge_union(&mut slots.paths, paths);
                merge_union(&mut slots.http_allowlist, http_allowlist);
                merge_env(&mut slots.env, env, &src, &fragment_chain)?;
                merge_assumes(&mut slots.assumes, assumes, &src, &fragment_chain)?;
                out.extend(fragment_phases);
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Resolve one `Import`: fetch or read `src`, recurse into the
/// fragment's own imports, verify the pin — §Resolution steps 1-3.
/// Returns the **expanded** [`ProfileNode::Fragment`] together with the
/// rendered `consumer → … → fragment` chain (the fragment element
/// included, so post-return errors — the merge collisions — name the
/// document that contributed the key); the caller splices and merges
/// (steps 4-5).
fn expand_import(
    src: &str,
    pin: Option<&str>,
    doc_path: &Path,
    ids: &IdGen,
    stack: &mut Vec<PathBuf>,
    chain: &mut Vec<String>,
) -> Result<(ProfileNode, String), ResolveError> {
    // §Source forms: classify before touching the filesystem. Scheme
    // matching is case-insensitive (RFC 3986 §3.1) so `HTTPS://…` is a
    // remote import, not an unsupported scheme.
    if let Some(reason) = denied_scheme(src) {
        return Err(ResolveError::ImportSchemeDenied {
            src: src.to_string(),
            reason,
            chain: chain.join(" → "),
        });
    }
    if has_scheme(src, "https://") {
        // Pin first: an unpinned remote is rejected as such even while
        // the fetch itself is unimplemented, so the error an author
        // fixes first is the one that survives increment 2.
        if pin.is_none() {
            return Err(ResolveError::ImportHashRequired {
                src: src.to_string(),
                chain: chain.join(" → "),
            });
        }
        return Err(ResolveError::ImportUnresolved {
            src: src.to_string(),
            detail: "remote imports are not implemented yet (spec 11 §MVP scope increment 2)"
                .to_string(),
            chain: chain.join(" → "),
        });
    }

    // Local path: relative resolves against the importing document's
    // own location (fragment-relative, never consumer-relative —
    // §Adopted conventions), absolute is an operator-host path.
    let target = if Path::new(src).is_absolute() {
        PathBuf::from(src)
    } else {
        doc_path.parent().unwrap_or(Path::new(".")).join(src)
    };

    // The chain the errors below name: the fragment element included
    // (spec 11 §Error surface — "All resolve errors name the import
    // chain (consumer → … → fragment)").
    let fragment_chain = |chain: &[String]| {
        let mut rendered = chain.join(" → ");
        rendered.push_str(" → ");
        rendered.push_str(&target.display().to_string());
        rendered
    };

    let key = stable_key(&target);
    if stack.contains(&key) {
        return Err(ResolveError::ImportCycle {
            src: src.to_string(),
            chain: fragment_chain(chain),
        });
    }

    // §Resolution step 1: read, minting node ids from the resolve
    // pass's shared generator (see [`resolve`] — a per-document
    // generator would collide with the consumer's ids). Parser
    // selection follows the extension rule the fetch surface already
    // applies (`.json` → serde bridge, otherwise canonical text) —
    // [`frontend::load_profile_with`] *is* that rule.
    let document = frontend::load_profile_with(&target, ids).map_err(|err| {
        ResolveError::ImportUnresolved {
            src: src.to_string(),
            detail: err.to_string(),
            chain: fragment_chain(chain),
        }
    })?;
    if !matches!(document, ProfileNode::Fragment { .. }) {
        return Err(ResolveError::ImportNotAFragment {
            src: src.to_string(),
            chain: fragment_chain(chain),
        });
    }

    // §Resolution step 2: recurse into the fragment's own imports, its
    // relative `src` values resolving against *its* location.
    stack.push(key);
    chain.push(target.display().to_string());
    let expanded = expand_document(document, &target, ids, stack, chain);
    let rendered_chain = chain.join(" → ");
    chain.pop();
    stack.pop();
    let expanded = expanded?;

    // §Resolution step 3: verify the pin — the fragment's expanded
    // canonical hash, compared case-insensitively the way
    // `fetch --expect-hash` already does ([`crate::fetch`]). On
    // mismatch nothing is kept and nothing merges (the caller never
    // sees the node).
    if let Some(pin) = pin {
        let expected = pin.to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ResolveError::ImportPinShape {
                src: src.to_string(),
                hash: pin.to_string(),
                chain: rendered_chain,
            });
        }
        let actual = canonical::hash(&expanded);
        if actual != expected {
            return Err(ResolveError::ImportHashMismatch {
                src: src.to_string(),
                expected,
                actual,
                chain: rendered_chain,
            });
        }
    }

    Ok((expanded, rendered_chain))
}

/// True when `src` begins with `scheme` compared case-insensitively —
/// URI schemes are case-insensitive (RFC 3986 §3.1).
fn has_scheme(src: &str, scheme: &str) -> bool {
    src.len() >= scheme.len() && src[..scheme.len()].eq_ignore_ascii_case(scheme)
}

/// Which §Source forms rule rejects `src`, if any. `https://` is legal
/// (handled by the caller); everything else that looks like a scheme or
/// a home path is denied.
fn denied_scheme(src: &str) -> Option<&'static str> {
    if has_scheme(src, "http://") {
        return Some("remote imports are https only");
    }
    if has_scheme(src, "file://") {
        return Some("file:// is not a source form; write the bare path");
    }
    if src == "~" || src.starts_with("~/") {
        return Some("home paths are not a source form; a profile that resolves differently per operator host is not the same profile");
    }
    // Any other `scheme://` spelling (s3://, ftp://, …) is no local
    // path and no supported remote. `https://` is exempt — it is the
    // one legal remote form and the caller owns its pin / fetch rules.
    if !has_scheme(src, "https://") {
        if let Some(pos) = src.find("://") {
            if src[..pos]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
            {
                return Some("unsupported URL scheme; remote imports are https only");
            }
        }
    }
    None
}

/// Set union: append the fragment entries the consumer does not already
/// carry. These lists are order-independent sets (chapter 03 sorts them
/// before hashing), so union is the whole rule (§Resolution rule 5).
fn merge_union(consumer: &mut Vec<String>, fragment: Vec<String>) {
    for entry in fragment {
        if !consumer.contains(&entry) {
            consumer.push(entry);
        }
    }
}

/// Disjoint-key merge for `env`. Value equality is judged on canonical
/// bytes ([`canonical::encode`]) rather than `PartialEq`, because two
/// parses of the same value node differ in `NodeId` and nothing else —
/// exactly the field canonical excludes.
fn merge_env(
    consumer: &mut BTreeMap<String, ProfileNode>,
    fragment: BTreeMap<String, ProfileNode>,
    src: &str,
    chain: &str,
) -> Result<(), ResolveError> {
    for (key, value) in fragment {
        match consumer.get(&key) {
            None => {
                consumer.insert(key, value);
            }
            Some(existing) if canonical::encode(existing) == canonical::encode(&value) => {}
            Some(_) => {
                return Err(ResolveError::ImportMergeCollision {
                    src: src.to_string(),
                    slot: "env",
                    key,
                    chain: chain.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Disjoint-key merge for `assumes` (plain string values).
fn merge_assumes(
    consumer: &mut BTreeMap<String, String>,
    fragment: BTreeMap<String, String>,
    src: &str,
    chain: &str,
) -> Result<(), ResolveError> {
    for (key, value) in fragment {
        match consumer.get(&key) {
            None => {
                consumer.insert(key, value);
            }
            Some(existing) if *existing == value => {}
            Some(_) => {
                return Err(ResolveError::ImportMergeCollision {
                    src: src.to_string(),
                    slot: "assumes",
                    key,
                    chain: chain.to_string(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    /// One temp dir per test, so relative-path fixtures live beside
    /// each other the way real documents do.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-resolve-{}-{test}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        dir
    }

    fn write(dir: &Path, name: &str, value: &serde_json::Value) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, value.to_string()).expect("fixture must be writable");
        path
    }

    fn load(path: &Path) -> ProfileNode {
        frontend::load_profile(path).expect("fixture must parse")
    }

    fn resolve_file(path: &Path) -> Result<ProfileNode, ResolveError> {
        resolve(load(path), path)
    }

    fn shexec_fragment() -> serde_json::Value {
        json!({
            "type": "Fragment",
            "name": "frag",
            "capabilities": ["sh.exec"],
            "paths": ["/workspace"],
            "phases": [
                { "type": "ShExec", "argv": ["echo", "from-fragment"] }
            ]
        })
    }

    fn importing_profile(src: &str, pin: Option<&str>) -> serde_json::Value {
        let mut import = json!({ "type": "Import", "src": src });
        if let Some(pin) = pin {
            import["hash"] = json!(pin);
        }
        json!({
            "type": "Spec",
            "name": "consumer",
            "capabilities": ["net.transfer"],
            "http_allowlist": ["https://example.com"],
            "phases": [
                { "type": "SystemApt", "packages": ["git"] },
                import,
                { "type": "ShExec", "argv": ["echo", "after"] }
            ]
        })
    }

    /// Spec 11 §Stability guarantee 1: a profile with no `Import` node
    /// expands to itself, byte-for-byte.
    #[test]
    fn a_profile_without_imports_keeps_its_canonical_bytes() {
        let dir = temp_dir("no-imports");
        let path = write(
            &dir,
            "plain.json",
            &json!({
                "type": "Spec",
                "name": "plain",
                "capabilities": ["sh.exec"],
                "phases": [{ "type": "ShExec", "argv": ["true"] }]
            }),
        );
        let loaded = load(&path);
        let expanded = resolve(loaded.clone(), &path).expect("no imports must resolve");
        assert_eq!(canonical::encode(&loaded), canonical::encode(&expanded));
        assert_eq!(canonical::hash(&loaded), canonical::hash(&expanded));
    }

    /// §Resolution rules 4-5: the fragment's phases replace the
    /// `Import` in place (order preserved on both sides), and its
    /// declarations merge by set union.
    #[test]
    fn a_local_import_splices_phases_and_merges_declarations() {
        let dir = temp_dir("splice");
        write(&dir, "frag.json", &shexec_fragment());
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", None),
        );

        let ProfileNode::Spec {
            capabilities,
            paths,
            http_allowlist,
            phases,
            ..
        } = resolve_file(&path).expect("local import must resolve")
        else {
            panic!("expanded root must stay a Spec");
        };

        // Splice in place: apt, fragment's sh.exec, trailing sh.exec.
        assert_eq!(phases.len(), 3);
        assert!(matches!(&phases[0], ProfileNode::SystemApt { .. }));
        match &phases[1] {
            ProfileNode::ShExec { argv, .. } => assert_eq!(argv[1], "from-fragment"),
            other => panic!("expected the fragment's phase in place, got {other:?}"),
        }
        match &phases[2] {
            ProfileNode::ShExec { argv, .. } => assert_eq!(argv[1], "after"),
            other => panic!("expected the trailing phase preserved, got {other:?}"),
        }

        // Union merge: consumer's entries kept, fragment's added.
        assert!(capabilities.contains(&"net.transfer".to_string()));
        assert!(capabilities.contains(&"sh.exec".to_string()));
        assert_eq!(paths, vec!["/workspace".to_string()]);
        assert_eq!(http_allowlist, vec!["https://example.com".to_string()]);
    }

    /// Expanded-hash identity: a profile importing a fragment hashes
    /// exactly as the same profile written inline (§Purpose — "the
    /// profile's identity stays what it always was").
    #[test]
    fn an_importing_profile_hashes_as_its_inline_equivalent() {
        let dir = temp_dir("identity");
        write(&dir, "frag.json", &shexec_fragment());
        let importing = write(
            &dir,
            "importing.json",
            &importing_profile("./frag.json", None),
        );
        let inline = write(
            &dir,
            "inline.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "capabilities": ["net.transfer", "sh.exec"],
                "paths": ["/workspace"],
                "http_allowlist": ["https://example.com"],
                "phases": [
                    { "type": "SystemApt", "packages": ["git"] },
                    { "type": "ShExec", "argv": ["echo", "from-fragment"] },
                    { "type": "ShExec", "argv": ["echo", "after"] }
                ]
            }),
        );
        let expanded = resolve_file(&importing).expect("import must resolve");
        let inline = load(&inline);
        assert_eq!(canonical::hash(&expanded), canonical::hash(&inline));
        // And the expanded profile passes validate with the fragment's
        // contributions counted (spec 11 §Resolution — "every existing
        // check sees fragment contributions exactly as if they had been
        // written inline").
        crate::validate::validate(&expanded).expect("expanded profile must validate");
    }

    /// §Adopted conventions: a fragment's relative imports resolve
    /// against the fragment's own location, never the consumer's.
    #[test]
    fn a_nested_import_resolves_fragment_relative() {
        let dir = temp_dir("nested");
        let sub = dir.join("shared");
        std::fs::create_dir_all(&sub).expect("subdir must be creatable");
        // shared/inner.json — only reachable relative to shared/.
        write(
            &sub,
            "inner.json",
            &json!({
                "type": "Fragment",
                "name": "inner",
                "capabilities": ["net.http_get"],
                "phases": [
                    { "type": "NetHttpGet", "url": "https://example.com/ping" }
                ]
            }),
        );
        // shared/outer.json imports ./inner.json — fragment-relative.
        write(
            &sub,
            "outer.json",
            &json!({
                "type": "Fragment",
                "name": "outer",
                "capabilities": ["sh.exec"],
                "phases": [
                    { "type": "Import", "src": "./inner.json" },
                    { "type": "ShExec", "argv": ["true"] }
                ]
            }),
        );
        let path = write(
            &dir,
            "profile.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "phases": [{ "type": "Import", "src": "./shared/outer.json" }]
            }),
        );

        let ProfileNode::Spec {
            capabilities,
            phases,
            ..
        } = resolve_file(&path).expect("nested import must resolve")
        else {
            panic!("expanded root must stay a Spec");
        };
        assert_eq!(phases.len(), 2);
        assert!(matches!(&phases[0], ProfileNode::NetHttpGet { .. }));
        assert!(matches!(&phases[1], ProfileNode::ShExec { .. }));
        // Declarations propagate transitively through the outer
        // fragment's own merge.
        assert!(capabilities.contains(&"net.http_get".to_string()));
        assert!(capabilities.contains(&"sh.exec".to_string()));
    }

    /// §Resolution rule 5: identical `env` entries deduplicate
    /// silently; differing ones are an error, not an override.
    #[test]
    fn env_merge_is_disjoint_with_silent_dedupe() {
        let dir = temp_dir("env-merge");
        write(
            &dir,
            "frag.json",
            &json!({
                "type": "Fragment",
                "name": "frag",
                "env": {
                    "SHARED": { "type": "EnvLiteral", "value": "same" },
                    "FRAGMENT_ONLY": { "type": "EnvLiteral", "value": "x" }
                },
                "phases": []
            }),
        );
        let ok = write(
            &dir,
            "ok.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "env": { "SHARED": { "type": "EnvLiteral", "value": "same" } },
                "phases": [{ "type": "Import", "src": "./frag.json" }]
            }),
        );
        let ProfileNode::Spec { env, .. } = resolve_file(&ok).expect("identical entries dedupe")
        else {
            panic!("expanded root must stay a Spec");
        };
        assert_eq!(env.len(), 2);
        assert!(env.contains_key("FRAGMENT_ONLY"));

        let collide = write(
            &dir,
            "collide.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "env": { "SHARED": { "type": "EnvLiteral", "value": "different" } },
                "phases": [{ "type": "Import", "src": "./frag.json" }]
            }),
        );
        match resolve_file(&collide) {
            Err(ResolveError::ImportMergeCollision {
                slot: "env", key, ..
            }) => {
                assert_eq!(key, "SHARED");
            }
            other => panic!("expected an env merge collision, got {other:?}"),
        }
    }

    /// Same rule for `assumes`.
    #[test]
    fn assumes_merge_collision_is_an_error() {
        let dir = temp_dir("assumes-merge");
        write(
            &dir,
            "frag.json",
            &json!({
                "type": "Fragment",
                "name": "frag",
                "assumes": { "comfyui_root": "/workspace/ComfyUI" },
                "phases": []
            }),
        );
        let path = write(
            &dir,
            "profile.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "assumes": { "comfyui_root": "/opt/ComfyUI" },
                "phases": [{ "type": "Import", "src": "./frag.json" }]
            }),
        );
        assert!(matches!(
            resolve_file(&path),
            Err(ResolveError::ImportMergeCollision {
                slot: "assumes",
                ..
            })
        ));
    }

    /// §Resolution rule 2: a cycle is an error.
    #[test]
    fn an_import_cycle_is_detected() {
        let dir = temp_dir("cycle");
        write(
            &dir,
            "a.json",
            &json!({
                "type": "Fragment",
                "name": "a",
                "phases": [{ "type": "Import", "src": "./b.json" }]
            }),
        );
        write(
            &dir,
            "b.json",
            &json!({
                "type": "Fragment",
                "name": "b",
                "phases": [{ "type": "Import", "src": "./a.json" }]
            }),
        );
        let path = write(
            &dir,
            "profile.json",
            &json!({
                "type": "Spec",
                "name": "consumer",
                "phases": [{ "type": "Import", "src": "./a.json" }]
            }),
        );
        match resolve_file(&path) {
            Err(ResolveError::ImportCycle { chain, .. }) => {
                // The chain names consumer → a → b, the path that
                // closed the loop.
                assert!(
                    chain.contains("a.json") && chain.contains("b.json"),
                    "{chain}"
                );
            }
            other => panic!("expected a cycle error, got {other:?}"),
        }
    }

    /// §Resolution rule 3: a written local pin is verified exactly like
    /// a remote one — against the fragment's *expanded* canonical hash.
    #[test]
    fn a_local_pin_verifies_against_the_expanded_hash() {
        let dir = temp_dir("pin");
        let frag_path = write(&dir, "frag.json", &shexec_fragment());
        let expanded_fragment = resolve_file(&frag_path).expect("fragment alone must resolve");
        let pin = canonical::hash(&expanded_fragment);

        let good = write(
            &dir,
            "good.json",
            &importing_profile("./frag.json", Some(&pin)),
        );
        resolve_file(&good).expect("a correct pin must verify");

        let bad_pin = "0".repeat(64);
        let bad = write(
            &dir,
            "bad.json",
            &importing_profile("./frag.json", Some(&bad_pin)),
        );
        match resolve_file(&bad) {
            Err(ResolveError::ImportHashMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, bad_pin);
                assert_eq!(actual, pin);
            }
            other => panic!("expected a hash mismatch, got {other:?}"),
        }
    }

    /// A malformed pin is an authoring error, reported before any
    /// content comparison.
    #[test]
    fn a_malformed_pin_is_rejected_as_such() {
        let dir = temp_dir("pin-shape");
        write(&dir, "frag.json", &shexec_fragment());
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", Some("not-a-hash")),
        );
        assert!(matches!(
            resolve_file(&path),
            Err(ResolveError::ImportPinShape { .. })
        ));
    }

    /// §The `Import` node: an unpinned remote import is rejected at
    /// resolve, not fetched-then-warned — and a pinned one names the
    /// unimplemented fetch honestly (§MVP scope: increment 1 is local
    /// only).
    #[test]
    fn remote_imports_enforce_the_pin_then_name_the_missing_fetch() {
        let dir = temp_dir("remote");
        let unpinned = write(
            &dir,
            "unpinned.json",
            &importing_profile("https://example.com/frag.json", None),
        );
        assert!(matches!(
            resolve_file(&unpinned),
            Err(ResolveError::ImportHashRequired { .. })
        ));

        let pinned = write(
            &dir,
            "pinned.json",
            &importing_profile("https://example.com/frag.json", Some(&"a".repeat(64))),
        );
        match resolve_file(&pinned) {
            Err(ResolveError::ImportUnresolved { detail, .. }) => {
                assert!(detail.contains("not implemented"), "{detail}");
            }
            other => panic!("expected the unimplemented-fetch error, got {other:?}"),
        }
    }

    /// §Source forms: http, file:// and home paths are not source
    /// forms.
    #[test]
    fn denied_source_forms_are_rejected() {
        let dir = temp_dir("schemes");
        for src in [
            "http://example.com/f.json",
            "file:///opt/f.json",
            "~/f.json",
        ] {
            let path = write(&dir, "profile.json", &importing_profile(src, None));
            assert!(
                matches!(
                    resolve_file(&path),
                    Err(ResolveError::ImportSchemeDenied { .. })
                ),
                "{src} must be denied"
            );
        }
    }

    /// An import target whose root is a full `Spec` profile is not a
    /// fragment document.
    #[test]
    fn importing_a_spec_document_is_rejected() {
        let dir = temp_dir("not-a-fragment");
        write(
            &dir,
            "profile-as-frag.json",
            &json!({ "type": "Spec", "name": "not-a-fragment", "phases": [] }),
        );
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./profile-as-frag.json", None),
        );
        assert!(matches!(
            resolve_file(&path),
            Err(ResolveError::ImportNotAFragment { .. })
        ));
    }

    /// A missing fragment file fails at read with the chain named.
    #[test]
    fn a_missing_fragment_is_import_unresolved() {
        let dir = temp_dir("missing");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./nowhere.json", None),
        );
        match resolve_file(&path) {
            Err(ResolveError::ImportUnresolved { chain, .. }) => {
                assert!(chain.contains("profile.json"), "{chain}");
            }
            other => panic!("expected ImportUnresolved, got {other:?}"),
        }
    }

    /// The defensive validate check: an unresolved `Import` reaching
    /// validate is rejected rather than silently dropped downstream.
    #[test]
    fn validate_rejects_an_unresolved_import() {
        let dir = temp_dir("validate-defense");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", None),
        );
        let unresolved = load(&path);
        assert!(matches!(
            crate::validate::validate(&unresolved),
            Err(crate::validate::ValidateError::UnresolvedImport { kind: "Import", .. })
        ));
    }

    /// The CLI pipeline is wired: `hash` on an importing document
    /// resolves first and hashes the expansion (spec 11 §Resolution
    /// "Identity").
    #[test]
    fn ast_hash_resolves_before_hashing() {
        let dir = temp_dir("cli-hash");
        write(&dir, "frag.json", &shexec_fragment());
        let importing = write(
            &dir,
            "importing.json",
            &importing_profile("./frag.json", None),
        );
        let via_cli = crate::cli::ast_hash(&importing).expect("hash must resolve imports");
        let expanded = resolve_file(&importing).expect("import must resolve");
        assert_eq!(via_cli, canonical::hash(&expanded));
    }

    /// Every [`dsl_kit::NodeId`] in `node`'s subtree, in walk order.
    fn collect_ids(node: &ProfileNode, out: &mut Vec<u64>) {
        use dsl_kit::DslNode as _;
        out.push(node.node_id().0);
        if let ProfileNode::Spec { env, phases, .. } | ProfileNode::Fragment { env, phases, .. } =
            node
        {
            for child in env.values().chain(phases.iter()) {
                collect_ids(child, out);
            }
        }
    }

    /// Spliced fragment nodes must not reuse the consumer's `NodeId`s:
    /// the exec context keys its program on them (`normalize`'s
    /// `IdMinter` documents the measured wrong-step incident a
    /// collision causes). Each `load_profile` call numbers from zero,
    /// so without the shared resolve-pass generator every fragment
    /// with ≥ 1 phase collides.
    #[test]
    fn spliced_fragment_ids_stay_disjoint_from_the_consumers() {
        let dir = temp_dir("id-injectivity");
        write(&dir, "frag.json", &shexec_fragment());
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", None),
        );
        let expanded = resolve_file(&path).expect("import must resolve");
        let mut ids = Vec::new();
        collect_ids(&expanded, &mut ids);
        let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "expanded tree carries a NodeId collision: {ids:?}"
        );
    }

    /// End-to-end over the engine: an importing profile, resolved and
    /// normalized, executes every phase — the consumer's and the
    /// fragment's — exactly once (the failure mode of a NodeId
    /// collision is the engine running the colliding phase in place of
    /// others while reporting ok).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_resolved_importing_profile_executes_every_phase_once() {
        use dsl_kit::Stepper as _;
        use std::sync::{Arc, Mutex};

        let dir = temp_dir("dry-run");
        write(&dir, "frag.json", &shexec_fragment());
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", None),
        );
        let normalized =
            crate::normalize::normalize(&resolve_file(&path).expect("import must resolve"));

        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = crate::profile_ast::create_profile_engine(
            &normalized,
            crate::exec::ExecMode::DryRun,
            Arc::clone(&log),
        )
        .expect("engine construction must succeed");
        let mut steps = 0;
        loop {
            let outcome = engine.step().expect("step execution failed");
            steps += 1;
            if matches!(outcome, dsl_kit::StepOutcome::Done(_)) {
                break;
            }
            assert!(steps <= 100, "execution exceeded expected step limit");
        }

        // system.apt + the fragment's sh.exec + the trailing sh.exec:
        // three phases, three op log lines, in canonical order.
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 3, "{log:?}");
        assert!(log[0].starts_with("system_apt"), "{log:?}");
        assert!(log[1].starts_with("sh_exec"), "{log:?}");
        assert!(log[2].starts_with("sh_exec"), "{log:?}");
    }
}
