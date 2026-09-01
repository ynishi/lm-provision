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
//! ## Increments 1 + 2 (spec 11 §MVP scope)
//!
//! Local imports (increment 1) and remote imports over `https://` with
//! the XDG cache (increment 2) both land through this module. The
//! caller-facing entry is [`resolve`]; every other item is either
//! testing seam ([`FragmentSource`], [`ResolveCtx`]) or module-private
//! plumbing.
//!
//! ## Sync/async seam
//!
//! [`resolve`] is synchronous — it is called from
//! [`crate::cli::ast_validate`] / `ast_hash` / `ast_plan` off a plain
//! thread — but it is *also* called from inside a `tokio` runtime by
//! [`crate::fetch::admit`], which runs under
//! [`crate::cli::run_fetch`]'s `runtime.block_on`. Neither
//! `Handle::block_on` nor building a runtime on the current thread is
//! safe in both contexts. The production HTTP fetch therefore runs on a
//! dedicated `std::thread` that builds its own current-thread `tokio`
//! runtime; see [`ReqwestFragmentSource::fetch`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dsl_kit::IdGen;
use url::Url;

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
        /// What failed (I/O, parse, or HTTP).
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
    /// any comparison or network call so a malformed pin reads as the
    /// authoring mistake it is, not as a content mismatch. (Not in the
    /// spec 11 error table; recorded here as an implementation-stage
    /// refinement of `ImportHashMismatch`.)
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

    /// A remote fragment imports a local path. The **referential
    /// sanity** rule (spec 11 §Adopted conventions, §Resolution step 2)
    /// keeps a document reachable only over HTTPS from resolving on the
    /// operator host's filesystem, where its `src` would mean whatever
    /// each operator happens to have.
    #[error(
        "remote fragment cannot import a local path {src:?}; \
         a fragment reached via https may only import https sources \
         (import chain: {chain})"
    )]
    ImportReferentialSanity {
        /// The offending `src` written inside the remote fragment.
        src: String,
        /// The `consumer → … → fragment` chain up to the offending
        /// fragment.
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

// ---------------------------------------------------------------------
// Location + cycle-detection key
// ---------------------------------------------------------------------

/// Where an import resolved to. Splits the recursion cleanly between the
/// two source families so a fragment fetched over https can resolve its
/// own relative imports against its URL (`Url::join` — same-origin, stays
/// remote per spec 11 §Resolution step 2), and so the referential
/// sanity check has one place to fire.
#[derive(Debug, Clone)]
enum Location {
    File(PathBuf),
    Https(Url),
}

impl Location {
    /// A display string for the import chain that resolve errors name.
    fn display(&self) -> String {
        match self {
            Location::File(path) => path.display().to_string(),
            Location::Https(url) => url.as_str().to_string(),
        }
    }

    /// Stable identity for cycle detection. Files are canonicalized when
    /// they exist (so `./a.json` and `a.json` collide as they should);
    /// URLs are compared by their normalized string form (`Url` already
    /// normalizes scheme, host and path percent-encoding).
    fn stable_key(&self) -> StableKey {
        match self {
            Location::File(path) => {
                StableKey::File(std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
            }
            Location::Https(url) => StableKey::Url(url.as_str().to_string()),
        }
    }

    /// Whether the extension of the last path segment routes this
    /// document through the JSON serde bridge (`.json`) or the canonical
    /// text grammar (anything else) — spec 11 §Source forms: "Parser
    /// selection follows the extension rule the fetch surface already
    /// applies."
    fn is_json(&self) -> bool {
        match self {
            Location::File(path) => path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("json")),
            Location::Https(url) => url
                .path_segments()
                .and_then(|mut segs| segs.next_back())
                .and_then(|last| {
                    std::path::Path::new(last)
                        .extension()
                        .and_then(|e| e.to_str())
                })
                .is_some_and(|e| e.eq_ignore_ascii_case("json")),
        }
    }
}

/// Cycle-detection key covering both source families.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StableKey {
    File(PathBuf),
    Url(String),
}

// ---------------------------------------------------------------------
// FragmentSource + production impl
// ---------------------------------------------------------------------

/// The HTTPS fetch behind [`ResolveCtx`]. A trait so tests can inject a
/// fake source serving canned bytes keyed by URL — that keeps the
/// https-only rule intact in tests (a real 127.0.0.1 http server would
/// be denied by [`denied_scheme`] before it was ever reached).
pub trait FragmentSource: Send + Sync {
    /// GET `url`, returning the raw body bytes on success or a rendered
    /// message on failure. Every failure is the same class from the
    /// resolver's point of view — it becomes
    /// [`ResolveError::ImportUnresolved`].
    fn fetch(&self, url: &Url) -> Result<Vec<u8>, String>;
}

/// The production [`FragmentSource`]. See the module doc for why the
/// HTTP runs on a dedicated `std::thread` rather than directly on the
/// caller's runtime.
pub struct ReqwestFragmentSource;

impl FragmentSource for ReqwestFragmentSource {
    fn fetch(&self, url: &Url) -> Result<Vec<u8>, String> {
        let url_owned = url.clone();
        // The two contexts this function must survive:
        //   1. `cli::ast_hash` / `ast_validate` / `ast_plan` — no
        //      tokio runtime on the calling thread.
        //   2. `cli::run_fetch` / `driver session preflight` —
        //      `runtime.block_on` on a multi-threaded runtime is already
        //      active on the calling thread.
        // A fresh current-thread runtime on a dedicated `std::thread`
        // works for both: it never touches the caller's runtime (if any),
        // and joining the thread is what the caller waits on.
        let handle = std::thread::spawn(move || -> Result<Vec<u8>, String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| format!("failed building the fetch runtime: {err}"))?;
            runtime.block_on(async move {
                // Fragment fetching shares the profile-fetch budget from
                // [`crate::fetch`] — spec 07-cli.md §Invocation `pin`
                // names the shared limits literally ("under the same
                // 4 MB cap and 30 s deadline `fetch` uses"). One
                // constant per limit, one place to change.
                let client = crate::exec::effects::client("fragment_fetch", |builder| {
                    builder.timeout(std::time::Duration::from_secs(crate::fetch::TIMEOUT_SEC))
                })
                .map_err(|err| err.to_string())?;
                let response = client
                    .get(url_owned.as_str())
                    .send()
                    .await
                    .map_err(|err| crate::exec::effects::render(&err))?;
                if !response.status().is_success() {
                    return Err(format!(
                        "GET {} returned {}",
                        url_owned.as_str(),
                        response.status()
                    ));
                }
                crate::exec::effects::read_capped(response, crate::fetch::MAX_PROFILE_BYTES).await
            })
        });
        match handle.join() {
            Ok(result) => result,
            Err(_) => Err("fragment-fetch thread panicked".to_string()),
        }
    }
}

// ---------------------------------------------------------------------
// ResolveCtx
// ---------------------------------------------------------------------

/// The dependencies the resolver needs: the HTTPS source and the cache
/// root. The public [`resolve`] builds a production instance; tests
/// build their own with a fake source and a `tempdir` root.
///
/// **Do not mutate `XDG_CACHE_HOME` from tests to steer the cache** —
/// tests run in parallel. Inject `cache_root` explicitly instead.
pub struct ResolveCtx<'a> {
    /// The fetch implementation.
    pub source: &'a dyn FragmentSource,
    /// The XDG-style cache root (spec 11 §Cache: `<cache_root>/<hash>`).
    /// The resolver reads / writes files inside this directory; it does
    /// not create the directory itself unless a write is about to
    /// happen, so a caller passing a nonexistent root pays no cost.
    pub cache_root: PathBuf,
}

/// Resolve every [`ProfileNode::Import`] in `root`, which was loaded
/// from `doc_path`. Returns the expanded document — the same root
/// variant, with no `Import` remaining anywhere beneath it.
///
/// A root with no `Import` node expands to itself; a non-`Spec` /
/// non-`Fragment` root is returned unchanged (validate owns rejecting
/// it, as it always has).
///
/// Uses the production [`ReqwestFragmentSource`] and the XDG cache root
/// (`${XDG_CACHE_HOME:-~/.cache}/lm-provision/fragments`). Tests reach
/// [`resolve_with_ctx`] directly so they can inject a fake source and
/// a scratch cache directory.
pub fn resolve(root: ProfileNode, doc_path: &Path) -> Result<ProfileNode, ResolveError> {
    let source = ReqwestFragmentSource;
    let ctx = ResolveCtx {
        source: &source,
        cache_root: default_cache_root(),
    };
    resolve_with_ctx(root, doc_path, &ctx)
}

/// [`resolve`] with a caller-supplied [`ResolveCtx`]. Kept `pub(crate)`:
/// external callers should go through [`resolve`], which reads the
/// production XDG root just once. In-crate consumers (currently the
/// tests below) use this variant to keep from touching the operator's
/// real cache directory.
pub(crate) fn resolve_with_ctx(
    root: ProfileNode,
    doc_path: &Path,
    ctx: &ResolveCtx,
) -> Result<ProfileNode, ResolveError> {
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
    let root_loc = Location::File(doc_path.to_path_buf());
    let mut chain = vec![root_loc.display()];
    let mut stack = vec![root_loc.stable_key()];
    expand_document(root, &root_loc, ctx, &ids, &mut stack, &mut chain)
}

/// The production XDG cache root: `${XDG_CACHE_HOME:-$HOME/.cache}/lm-provision/fragments`
/// (spec 11 §Cache). Absent both env vars, falls back to `/tmp/lm-provision/fragments`
/// — a cold cache is always safe, so a resolve run without a home
/// directory works but never persists.
///
/// `pub(crate)` so [`crate::pin`] shares this rule — the pin subcommand
/// builds its own [`ResolveCtx`] for the verify pass and must use the
/// same root the resolver uses when it runs standalone.
pub(crate) fn default_cache_root() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("lm-provision").join("fragments")
}

/// Expand one document in place: `Spec` and `Fragment` roots get their
/// phase lists expanded and their declaration slots merged; any other
/// root passes through untouched.
fn expand_document(
    root: ProfileNode,
    doc_loc: &Location,
    ctx: &ResolveCtx,
    ids: &IdGen,
    stack: &mut Vec<StableKey>,
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
            sh_egress,
            assumes,
            requires_ports,
            requires_gpu,
            requires_disk,
            provider,
            artifacts,
            phases,
        } => {
            let (slots, phases) = expand_into_slots(
                capabilities,
                env,
                env_secrets,
                paths,
                http_allowlist,
                sh_egress,
                assumes,
                phases,
                doc_loc,
                ctx,
                ids,
                stack,
                chain,
            )?;
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
                sh_egress: slots.sh_egress,
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
            sh_egress,
            assumes,
            phases,
        } => {
            let (slots, phases) = expand_into_slots(
                capabilities,
                env,
                env_secrets,
                paths,
                http_allowlist,
                sh_egress,
                assumes,
                phases,
                doc_loc,
                ctx,
                ids,
                stack,
                chain,
            )?;
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
                sh_egress: slots.sh_egress,
                assumes: slots.assumes,
                phases,
            })
        }
        other => Ok(other),
    }
}

/// Build a [`Slots`] from a `Spec` or `Fragment`'s seven merge-shaped
/// declaration fields and expand its phase list through it —
/// [`expand_phases`] mutates the slots as each nested import merges in.
///
/// The two callers destructure their variant **exhaustively (no `..`)**
/// so a new declaration field is a compile error at the destructure
/// site; this helper takes the seven fields as named arguments, so the
/// same field addition is also a compile error here, in exactly one
/// place. Extracted so the 9-line Slots-build + expand-phases +
/// unpack block does not live twice.
#[allow(clippy::too_many_arguments)]
fn expand_into_slots(
    capabilities: Vec<String>,
    env: BTreeMap<String, ProfileNode>,
    env_secrets: Vec<String>,
    paths: Vec<String>,
    http_allowlist: Vec<String>,
    sh_egress: Vec<String>,
    assumes: BTreeMap<String, String>,
    phases: Vec<ProfileNode>,
    doc_loc: &Location,
    ctx: &ResolveCtx,
    ids: &IdGen,
    stack: &mut Vec<StableKey>,
    chain: &mut Vec<String>,
) -> Result<(Slots, Vec<ProfileNode>), ResolveError> {
    let mut slots = Slots {
        capabilities,
        env,
        env_secrets,
        paths,
        http_allowlist,
        sh_egress,
        assumes,
    };
    let phases = expand_phases(phases, doc_loc, ctx, ids, &mut slots, stack, chain)?;
    Ok((slots, phases))
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
    sh_egress: Vec<String>,
    assumes: BTreeMap<String, String>,
}

/// Expand a phase list: every [`ProfileNode::Import`] is replaced by
/// its fragment's expanded phase list (order preserved on both sides —
/// §Resolution rule 4), and the fragment's declarations merge into
/// `slots` (§Resolution rule 5). Every other phase passes through.
fn expand_phases(
    phases: Vec<ProfileNode>,
    doc_loc: &Location,
    ctx: &ResolveCtx,
    ids: &IdGen,
    slots: &mut Slots,
    stack: &mut Vec<StableKey>,
    chain: &mut Vec<String>,
) -> Result<Vec<ProfileNode>, ResolveError> {
    let mut out = Vec::with_capacity(phases.len());
    for phase in phases {
        match phase {
            ProfileNode::Import { id: _, src, hash } => {
                let (fragment, fragment_chain) =
                    expand_import(&src, hash.as_deref(), doc_loc, ctx, ids, stack, chain)?;
                let ProfileNode::Fragment {
                    capabilities,
                    env,
                    env_secrets,
                    paths,
                    http_allowlist,
                    sh_egress,
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
                merge_union(&mut slots.sh_egress, sh_egress);
                merge_env(&mut slots.env, env, &src, &fragment_chain)?;
                merge_assumes(&mut slots.assumes, assumes, &src, &fragment_chain)?;
                out.extend(fragment_phases);
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Resolve one `Import`: classify the source, fetch or read it, recurse
/// into the fragment's own imports, verify the pin — §Resolution steps
/// 1-3. Returns the **expanded** [`ProfileNode::Fragment`] together
/// with the rendered `consumer → … → fragment` chain (the fragment
/// element included, so post-return errors — the merge collisions —
/// name the document that contributed the key); the caller splices and
/// merges (steps 4-5).
fn expand_import(
    src: &str,
    pin: Option<&str>,
    doc_loc: &Location,
    ctx: &ResolveCtx,
    ids: &IdGen,
    stack: &mut Vec<StableKey>,
    chain: &mut Vec<String>,
) -> Result<(ProfileNode, String), ResolveError> {
    // §Source forms: classify before touching the filesystem or the
    // network. Scheme matching is case-insensitive (RFC 3986 §3.1) so
    // `HTTPS://…` is a remote import, not an unsupported scheme.
    if let Some(reason) = denied_scheme(src) {
        return Err(ResolveError::ImportSchemeDenied {
            src: src.to_string(),
            reason,
            chain: chain.join(" → "),
        });
    }

    // §Resolution step 2's referential sanity: a fragment reached via
    // https may only import https sources (§Adopted conventions). A
    // *relative* src (`./inner.json`, `../shared.json`, bare `inner`)
    // resolves via `Url::join` and stays same-origin (spec 11:
    // "a remote fragment's relative import stays same-origin and
    // therefore remote"). An *absolute-path* src (starting with `/`)
    // is a filesystem-path spelling — a category error under an HTTPS
    // location where there is no operator host in scope — and is
    // rejected here, before any fetch or cache work.
    if let Location::Https(_) = doc_loc {
        if !has_scheme(src, "https://") && src.starts_with('/') {
            return Err(ResolveError::ImportReferentialSanity {
                src: src.to_string(),
                chain: chain.join(" → "),
            });
        }
    }

    // Resolve `src` to a concrete [`Location`]. Relative paths inside a
    // remote fragment stay same-origin via `Url::join`; relative paths
    // inside a local document resolve against the document's own dir.
    let target = resolve_location(src, doc_loc, chain)?;

    // The chain the errors below name: the fragment element included
    // (spec 11 §Error surface — "All resolve errors name the import
    // chain (consumer → … → fragment)").
    let fragment_chain = |chain: &[String]| {
        let mut rendered = chain.join(" → ");
        rendered.push_str(" → ");
        rendered.push_str(&target.display());
        rendered
    };

    // Remote imports: enforce the pin's presence and shape *before* any
    // fetch or cache work. A malformed pin is authoring, not content —
    // and it costs us zero network calls to say so.
    let expected_pin: Option<String> = match (matches!(target, Location::Https(_)), pin) {
        (true, None) => {
            return Err(ResolveError::ImportHashRequired {
                src: src.to_string(),
                chain: fragment_chain(chain),
            });
        }
        (_, Some(pin)) => {
            // Shape check goes through the shared
            // [`canonical::is_sha256_hex`] so this and
            // [`crate::validate`]'s `models.sha256` check answer to
            // one rule (case not policed). Lowercase after the shape
            // pass because [`canonical::hash`] renders in lowercase
            // (spec 11 §Hash spelling), and the comparison later is
            // byte-for-byte.
            if !canonical::is_sha256_hex(pin) {
                return Err(ResolveError::ImportPinShape {
                    src: src.to_string(),
                    hash: pin.to_string(),
                    chain: fragment_chain(chain),
                });
            }
            Some(pin.to_ascii_lowercase())
        }
        (false, None) => None,
    };

    let key = target.stable_key();
    if stack.contains(&key) {
        return Err(ResolveError::ImportCycle {
            src: src.to_string(),
            chain: fragment_chain(chain),
        });
    }

    // Remote-only cache lookup (§Cache): the lookup precedes the
    // network. On hit the entry is already the expanded fragment —
    // parse it, recompute the expanded canonical hash, compare against
    // the pin. Any failure (parse, wrong root, wrong hash) is a miss;
    // never an error, and never runs the recursive expander (the entry
    // is already expanded, spec 11 §Cache).
    if let (Location::Https(_), Some(expected)) = (&target, expected_pin.as_deref()) {
        if let Some(cached) = try_cache(&ctx.cache_root, expected, ids) {
            let mut rendered = chain.join(" → ");
            rendered.push_str(" → ");
            rendered.push_str(&target.display());
            return Ok((cached, rendered));
        }
    }

    // §Resolution step 1: read (local) or fetch (remote), then parse
    // through the extension-selected frontend. Parser selection follows
    // [`Location::is_json`] so a URL path ending `.json` routes the same
    // way a local `.json` file does.
    let document = load_at(&target, ctx, ids).map_err(|detail| {
        // A common authoring mistake: writing `name@version` as an
        // Import.src as if it were the resolver-layer shorthand. The
        // resolver layer (`lm-provision pin`, spec 11 §The resolver
        // layer) rewrites that at authoring time; the resolve stage
        // itself only sees the resulting explicit src+hash pair, so
        // this reaches us as a plain unresolvable local path. Name it
        // so the author gets pointed at `pin`.
        let detail = if matches!(target, Location::File(_)) && looks_like_name_at_version(src) {
            format!(
                "{detail} (looks like a name@version spelling — run \
                 `lm-provision pin <profile> --index <url-or-path>` to \
                 rewrite it into the pinned src+hash form)"
            )
        } else {
            detail
        };
        ResolveError::ImportUnresolved {
            src: src.to_string(),
            detail,
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
    chain.push(target.display());
    let expanded = expand_document(document, &target, ctx, ids, stack, chain);
    let rendered_chain = chain.join(" → ");
    chain.pop();
    stack.pop();
    let expanded = expanded?;

    // §Resolution step 3: verify the pin (§Cache: parse-then-rehash is
    // the only integrity check — the byte format is trusted for none).
    // Compared case-insensitively the way `fetch --expect-hash` does
    // ([`crate::fetch`]).
    if let Some(expected) = expected_pin.as_deref() {
        let actual = canonical::hash(&expanded);
        if actual != expected {
            return Err(ResolveError::ImportHashMismatch {
                src: src.to_string(),
                expected: expected.to_string(),
                actual,
                chain: rendered_chain,
            });
        }

        // Persist the freshly-verified expanded fragment to the cache
        // under its pin. This is opportunistic: a write failure (no
        // disk space, unwritable path, race with another resolver) does
        // *not* fail the resolve — the fragment is already in hand and
        // the caller expects a merge.
        if matches!(target, Location::Https(_)) {
            let _ = write_cache(&ctx.cache_root, expected, &expanded);
        }
    }

    Ok((expanded, rendered_chain))
}

/// Resolve a written `src` to a concrete [`Location`], anchored against
/// `doc_loc` (spec 11 §Resolution step 2 — fragment-relative, never
/// consumer-relative).
fn resolve_location(
    src: &str,
    doc_loc: &Location,
    chain: &[String],
) -> Result<Location, ResolveError> {
    if has_scheme(src, "https://") {
        return Url::parse(src).map(Location::Https).map_err(|err| {
            ResolveError::ImportUnresolved {
                src: src.to_string(),
                detail: format!("malformed URL: {err}"),
                chain: chain.join(" → "),
            }
        });
    }
    match doc_loc {
        Location::File(doc_path) => {
            let path = if Path::new(src).is_absolute() {
                PathBuf::from(src)
            } else {
                doc_path.parent().unwrap_or(Path::new(".")).join(src)
            };
            Ok(Location::File(path))
        }
        Location::Https(base) => {
            // §Adopted conventions — `Url::join` implements
            // relative-URL resolution per RFC 3986 §5, which is what
            // "same-origin" collapses to for `./foo.json`. The
            // referential-sanity check above already rejected any
            // shape that would land off HTTPS.
            let joined = base
                .join(src)
                .map_err(|err| ResolveError::ImportUnresolved {
                    src: src.to_string(),
                    detail: format!("could not join {src:?} against {}: {err}", base.as_str()),
                    chain: chain.join(" → "),
                })?;
            if joined.scheme() != "https" {
                return Err(ResolveError::ImportReferentialSanity {
                    src: src.to_string(),
                    chain: chain.join(" → "),
                });
            }
            Ok(Location::Https(joined))
        }
    }
}

/// Load a document at `target`, returning a rendered error string on
/// any failure (the caller wraps it in [`ResolveError::ImportUnresolved`]).
fn load_at(target: &Location, ctx: &ResolveCtx, ids: &IdGen) -> Result<ProfileNode, String> {
    match target {
        Location::File(path) => {
            frontend::load_profile_with(path, ids).map_err(|err| err.to_string())
        }
        Location::Https(url) => {
            let bytes = ctx.source.fetch(url)?;
            frontend::load_profile_bytes(&bytes, target.is_json(), ids)
                .map_err(|err| err.to_string())
        }
    }
}

/// Cache lookup (§Cache): read `<cache_root>/<pin>`, parse as bridge
/// JSON, verify that the root is a `Fragment` and that its recomputed
/// expanded canonical hash equals the pin. Any failure is a miss; the
/// caller refetches.
fn try_cache(cache_root: &Path, pin_hex: &str, ids: &IdGen) -> Option<ProfileNode> {
    let entry = cache_root.join(pin_hex);
    let bytes = std::fs::read(&entry).ok()?;
    // The cache always stores bridge JSON (see [`write_cache`]), never
    // canonical text, so `is_json = true` is unconditional here.
    let node = frontend::load_profile_bytes(&bytes, true, ids).ok()?;
    if !matches!(node, ProfileNode::Fragment { .. }) {
        return None;
    }
    if canonical::hash(&node) != pin_hex {
        return None;
    }
    Some(node)
}

/// Per-process counter appended to a cache temp file's name so two
/// resolvers racing on the same pin do not share a temp path. `pid`
/// alone is not enough — two threads in one process would collide, one
/// could unlink the other's in-flight file, and `rename` could land a
/// partial entry.
static CACHE_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Persist `expanded` to `<cache_root>/<pin>` (§Cache). Writes the
/// bridge-JSON form to a temp file in the same directory, then renames
/// it — a rename is atomic on the same filesystem, so a reader never
/// sees a partial entry. All I/O errors are silent: a cache write
/// failure does not fail the resolve.
fn write_cache(
    cache_root: &Path,
    pin_hex: &str,
    expanded: &ProfileNode,
) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(cache_root)?;
    let entry = cache_root.join(pin_hex);
    // Per-call unique temp name: pid + monotonically increasing counter.
    // Two threads in the same process resolving the same fragment now
    // get disjoint temp names, so neither can unlink the other's
    // in-flight file (the sh_egress-fixup-2026 report's finding).
    let seq = CACHE_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = cache_root.join(format!("{pin_hex}.tmp-{}-{seq}", std::process::id()));
    let value = crate::to_bridge_json::to_bridge_json(expanded);
    let bytes = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
    // `create_new` refuses to write through a pre-planted file. With
    // the unique-per-call name above there is no legitimate collision;
    // if `create_new` still fails (foreign leftover, planted symlink),
    // give up rather than unlink someone else's work — the cache write
    // is opportunistic, and the caller already holds the fragment.
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create_new(&tmp)?;
        file.write_all(&bytes)?;
    }
    if let Err(err) = std::fs::rename(&tmp, &entry) {
        // Best-effort cleanup of the temp file; the caller only needs
        // the rename to have succeeded.
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// True when `src` begins with `scheme` compared case-insensitively —
/// URI schemes are case-insensitive (RFC 3986 §3.1).
///
/// `pub(crate)` so [`crate::pin`]'s `--index` scheme detection reuses
/// the same case-insensitive predicate the resolver applies to
/// `Import.src` — a caller writing `HTTPS://…` for the index must be
/// treated as a URL, not fall through to `std::fs::read`.
pub(crate) fn has_scheme(src: &str, scheme: &str) -> bool {
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

// ---------------------------------------------------------------------
// The `pin` subcommand's shape-detection helper (spec 11 §The resolver
// layer). Written here rather than in [`crate::cli`] so it can be
// shared with the DX addition below — the `ImportUnresolved` detail for
// a local-path import whose src *looks* like `name@version` names
// `lm-provision pin`.
// ---------------------------------------------------------------------

/// True when `src` matches the `name@version` shape the resolver layer
/// consumes — no scheme, no `/`, exactly one `@`, both halves non-empty
/// and drawn from `[A-Za-z0-9._-]` (the character class already carried
/// by the sample `index.json` and the [profiles README](docs/profiles/README.md)).
///
/// `pub(crate)` because the resolver (this module) and the pin
/// subcommand ([`crate::cli`]) both use it: the same rule that decides
/// what `lm-provision pin` rewrites decides what the resolver's
/// `ImportUnresolved` message names as "looks like a name@version".
pub(crate) fn looks_like_name_at_version(src: &str) -> bool {
    if src.contains("://") || src.contains('/') {
        return false;
    }
    let (name, version) = match src.split_once('@') {
        Some(halves) => halves,
        None => return false,
    };
    if name.is_empty() || version.is_empty() {
        return false;
    }
    if version.contains('@') {
        return false;
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-';
    name.chars().all(allowed) && version.chars().all(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

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

    /// A resolve helper that uses a fresh empty cache directory so tests
    /// never touch the operator's real XDG cache. The source is a
    /// silent [`FakeSource`] that fails every call; tests that need
    /// serving inject their own [`FakeSource`] map.
    fn resolve_with_cache(path: &Path, ctx: &ResolveCtx) -> Result<ProfileNode, ResolveError> {
        resolve_with_ctx(load(path), path, ctx)
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

    // -----------------------------------------------------------------
    // Fake source used by the remote-import tests.
    // -----------------------------------------------------------------

    /// A [`FragmentSource`] that serves canned bytes keyed by URL and
    /// counts the calls it received. Every URL absent from `entries` is
    /// answered with an error, so tests can assert on "was fetched at
    /// all" without stubbing a real server.
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

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl FragmentSource for FakeSource {
        fn fetch(&self, url: &Url) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.entries.get(url.as_str()) {
                Some(bytes) => Ok(bytes.clone()),
                None => Err(format!("fake source has no entry for {}", url.as_str())),
            }
        }
    }

    /// A [`FragmentSource`] that always returns Err. Used by the warm-
    /// cache test: a hit must not consult the network.
    struct DeadSource(Mutex<Vec<String>>);

    impl DeadSource {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }
    }

    impl FragmentSource for DeadSource {
        fn fetch(&self, url: &Url) -> Result<Vec<u8>, String> {
            self.0.lock().unwrap().push(url.as_str().to_string());
            Err("dead source: this test should never reach the network".to_string())
        }
    }

    /// Build a resolve context whose source is `src` and whose cache
    /// root is a fresh subdirectory of `dir`. Each call gets a unique
    /// subdirectory so intra-test cache scenarios stay disjoint.
    fn ctx_for<'a>(src: &'a dyn FragmentSource, dir: &Path, tag: &str) -> ResolveCtx<'a> {
        let cache_root = dir.join(format!("cache-{tag}"));
        ResolveCtx {
            source: src,
            cache_root,
        }
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
    /// resolve, not fetched-then-warned.
    #[test]
    fn an_unpinned_remote_import_is_hash_required() {
        let dir = temp_dir("unpinned-remote");
        let unpinned = write(
            &dir,
            "unpinned.json",
            &importing_profile("https://example.com/frag.json", None),
        );
        // Real production path is fine here: `ImportHashRequired` fires
        // before we ever touch the network or the cache.
        assert!(matches!(
            resolve_file(&unpinned),
            Err(ResolveError::ImportHashRequired { .. })
        ));
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

    // -----------------------------------------------------------------
    // Increment 2: remote fetch + cache.
    // -----------------------------------------------------------------

    /// Compute the pin for a fragment authored inline. The pin is the
    /// fragment's *expanded* canonical hash (spec 11 §Cache), but a
    /// fragment with no imports expands to itself, so hashing the
    /// as-written AST is enough for these fixtures.
    fn pin_of(fragment_bytes: &[u8]) -> String {
        let ast = frontend::load_profile_bytes(fragment_bytes, true, &IdGen::new())
            .expect("fixture fragment must parse");
        canonical::hash(&ast)
    }

    /// The happy remote path: fetch, expand, verify, splice + merge —
    /// and the cache entry appears at `<cache_root>/<pin>`, keyed by
    /// the pin, containing parseable bridge JSON.
    #[test]
    fn a_remote_import_fetches_verifies_and_populates_the_cache() {
        let dir = temp_dir("remote-happy");
        let frag_bytes = serde_json::to_vec(&shexec_fragment()).unwrap();
        let pin = pin_of(&frag_bytes);
        let url = "https://example.com/frag.json";
        let source = FakeSource::new(&[(url, &frag_bytes)]);
        let ctx = ctx_for(&source, &dir, "happy");
        let path = write(&dir, "profile.json", &importing_profile(url, Some(&pin)));

        let expanded = resolve_with_cache(&path, &ctx).expect("remote import must resolve");
        assert_eq!(
            source.calls(),
            1,
            "the fetch must have been called exactly once"
        );
        let ProfileNode::Spec { phases, .. } = &expanded else {
            panic!("expanded root must stay a Spec");
        };
        // apt, fragment's sh.exec, trailing sh.exec.
        assert_eq!(phases.len(), 3);

        let entry = ctx.cache_root.join(&pin);
        assert!(entry.exists(), "cache entry must be created");
        let cached_bytes = std::fs::read(&entry).unwrap();
        let cached_node = frontend::load_profile_bytes(&cached_bytes, true, &IdGen::new())
            .expect("cache entry must be parseable bridge JSON");
        assert!(matches!(cached_node, ProfileNode::Fragment { .. }));
        assert_eq!(canonical::hash(&cached_node), pin);
    }

    /// A warm cache serves without any network call — the entire point
    /// of the cache. Uses a [`DeadSource`] whose every call is an error
    /// so a fetch would fail loudly.
    #[test]
    fn a_second_resolve_serves_purely_from_the_warm_cache() {
        let dir = temp_dir("remote-warm");
        let frag_bytes = serde_json::to_vec(&shexec_fragment()).unwrap();
        let pin = pin_of(&frag_bytes);
        let url = "https://example.com/frag.json";

        // First run: warm the cache with a live source.
        {
            let source = FakeSource::new(&[(url, &frag_bytes)]);
            let ctx = ctx_for(&source, &dir, "warm");
            let path = write(&dir, "profile.json", &importing_profile(url, Some(&pin)));
            resolve_with_cache(&path, &ctx).expect("warm-run must succeed");
        }

        // Second run: dead source, same cache directory.
        let dead = DeadSource::new();
        let ctx = ResolveCtx {
            source: &dead,
            cache_root: dir.join("cache-warm"),
        };
        let path = write(&dir, "profile.json", &importing_profile(url, Some(&pin)));
        resolve_with_cache(&path, &ctx).expect("warm cache must serve");
        assert!(
            dead.0.lock().unwrap().is_empty(),
            "cache hit must not consult the network"
        );
    }

    /// A cache entry that fails to parse is a miss: refetched,
    /// overwritten with the good bytes.
    #[test]
    fn a_corrupted_cache_entry_is_a_miss() {
        let dir = temp_dir("remote-corrupt");
        let frag_bytes = serde_json::to_vec(&shexec_fragment()).unwrap();
        let pin = pin_of(&frag_bytes);
        let url = "https://example.com/frag.json";
        let source = FakeSource::new(&[(url, &frag_bytes)]);
        let ctx = ctx_for(&source, &dir, "corrupt");
        std::fs::create_dir_all(&ctx.cache_root).unwrap();
        // Plant garbage under the key the resolver would look up.
        std::fs::write(ctx.cache_root.join(&pin), b"{not valid json").unwrap();

        let path = write(&dir, "profile.json", &importing_profile(url, Some(&pin)));
        resolve_with_cache(&path, &ctx).expect("corrupted entry must fall back to fetch");
        assert_eq!(source.calls(), 1, "the fetch must have been called");

        let after = std::fs::read(ctx.cache_root.join(&pin)).unwrap();
        assert!(
            after != b"{not valid json",
            "the cache entry must have been rewritten"
        );
        assert_eq!(
            canonical::hash(&frontend::load_profile_bytes(&after, true, &IdGen::new()).unwrap()),
            pin,
            "the rewritten entry must re-hash to the pin"
        );
    }

    /// A cache entry that parses but re-hashes wrong (e.g. an entry
    /// stored under key A that actually encodes something else) is a
    /// miss too — same treatment.
    #[test]
    fn a_cache_entry_that_rehashes_wrong_is_a_miss() {
        let dir = temp_dir("remote-mishash");
        let frag_bytes = serde_json::to_vec(&shexec_fragment()).unwrap();
        let pin = pin_of(&frag_bytes);
        let url = "https://example.com/frag.json";

        // Build a *different* fragment and store it under `pin`.
        let other = json!({
            "type": "Fragment",
            "name": "other",
            "phases": [{ "type": "ShExec", "argv": ["different"] }]
        });
        let other_bytes = serde_json::to_vec(&other).unwrap();

        let source = FakeSource::new(&[(url, &frag_bytes)]);
        let ctx = ctx_for(&source, &dir, "mishash");
        std::fs::create_dir_all(&ctx.cache_root).unwrap();
        std::fs::write(ctx.cache_root.join(&pin), &other_bytes).unwrap();

        let path = write(&dir, "profile.json", &importing_profile(url, Some(&pin)));
        resolve_with_cache(&path, &ctx).expect("mishashed entry must fall back to fetch");
        assert_eq!(source.calls(), 1);
    }

    /// A remote fragment with a relative import: resolves same-origin
    /// against the fragment's URL (spec 11 §Resolution step 2 — a
    /// remote fragment's relative import stays same-origin and
    /// therefore remote).
    #[test]
    fn a_remote_fragment_with_a_relative_import_resolves_same_origin() {
        let dir = temp_dir("remote-relative");
        let inner = json!({
            "type": "Fragment",
            "name": "inner",
            "capabilities": ["net.http_get"],
            "phases": [
                { "type": "NetHttpGet", "url": "https://example.com/ping" }
            ]
        });
        let inner_bytes = serde_json::to_vec(&inner).unwrap();
        let inner_pin = pin_of(&inner_bytes);

        let outer = json!({
            "type": "Fragment",
            "name": "outer",
            "capabilities": ["sh.exec"],
            "phases": [
                { "type": "Import", "src": "./inner.json", "hash": inner_pin },
                { "type": "ShExec", "argv": ["true"] }
            ]
        });
        let outer_bytes = serde_json::to_vec(&outer).unwrap();
        // The outer fragment's *expanded* form is what its pin hashes.
        let outer_expanded = {
            let source = FakeSource::new(&[(
                "https://host.example/frag/inner.json",
                inner_bytes.as_slice(),
            )]);
            let ctx = ctx_for(&source, &dir, "prep");
            // Resolve outer standalone against its own URL. Use a temp
            // file trick: write to disk and resolve as a *local*
            // document, then take its hash. Because outer imports inner
            // by a bare relative path, we need the anchor to be a URL,
            // so we use a small helper instead.
            let ast = frontend::load_profile_bytes(&outer_bytes, true, &IdGen::new()).unwrap();
            let outer_url = Url::parse("https://host.example/frag/outer.json").unwrap();
            let mut chain = vec![outer_url.as_str().to_string()];
            let mut stack = vec![Location::Https(outer_url.clone()).stable_key()];
            let ids = IdGen::new();
            for _ in 0..=crate::normalize::max_node_id(&ast) {
                ids.node();
            }
            expand_document(
                ast,
                &Location::Https(outer_url),
                &ctx,
                &ids,
                &mut stack,
                &mut chain,
            )
            .expect("outer must expand against its own URL")
        };
        let outer_pin = canonical::hash(&outer_expanded);

        // Now the consumer: imports the outer URL, which imports
        // ./inner.json — served on the same origin.
        let source = FakeSource::new(&[
            (
                "https://host.example/frag/outer.json",
                outer_bytes.as_slice(),
            ),
            (
                "https://host.example/frag/inner.json",
                inner_bytes.as_slice(),
            ),
        ]);
        let ctx = ctx_for(&source, &dir, "relative");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("https://host.example/frag/outer.json", Some(&outer_pin)),
        );
        let expanded = resolve_with_cache(&path, &ctx).expect("relative remote must resolve");
        let ProfileNode::Spec { phases, .. } = &expanded else {
            panic!("expanded root must stay a Spec");
        };
        // apt + inner's NetHttpGet + outer's ShExec + trailing ShExec.
        assert_eq!(phases.len(), 4);
        assert!(matches!(&phases[1], ProfileNode::NetHttpGet { .. }));
    }

    /// A remote fragment importing an absolute local path is
    /// [`ResolveError::ImportReferentialSanity`] — a document reached
    /// over HTTPS may only import HTTPS sources.
    #[test]
    fn a_remote_fragment_may_not_import_a_local_path() {
        let dir = temp_dir("remote-refsan");
        let bad_frag = json!({
            "type": "Fragment",
            "name": "bad",
            "phases": [
                { "type": "Import", "src": "/etc/passwd-frag.json" }
            ]
        });
        let bad_bytes = serde_json::to_vec(&bad_frag).unwrap();
        // The pin has to check out first (or the fetch fails at
        // hash-verify before the inner referential-sanity ever fires),
        // so pin against the fragment expanded against its own URL —
        // which itself trips referential sanity, meaning the pin
        // computation matches the resolver's later verdict.
        let source = FakeSource::new(&[("https://host.example/bad.json", bad_bytes.as_slice())]);
        let ctx = ctx_for(&source, &dir, "refsan");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("https://host.example/bad.json", Some(&"a".repeat(64))),
        );
        match resolve_with_cache(&path, &ctx) {
            Err(ResolveError::ImportReferentialSanity { src, .. }) => {
                assert_eq!(src, "/etc/passwd-frag.json");
            }
            other => panic!("expected ImportReferentialSanity, got {other:?}"),
        }
    }

    /// A remote hash mismatch is [`ResolveError::ImportHashMismatch`]
    /// with nothing merged and nothing cached.
    #[test]
    fn a_remote_hash_mismatch_keeps_nothing() {
        let dir = temp_dir("remote-mismatch");
        let frag_bytes = serde_json::to_vec(&shexec_fragment()).unwrap();
        let real_pin = pin_of(&frag_bytes);
        let bad_pin = "0".repeat(64);
        let url = "https://example.com/frag.json";
        let source = FakeSource::new(&[(url, &frag_bytes)]);
        let ctx = ctx_for(&source, &dir, "mismatch");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile(url, Some(&bad_pin)),
        );
        match resolve_with_cache(&path, &ctx) {
            Err(ResolveError::ImportHashMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(expected, bad_pin);
                assert_eq!(actual, real_pin);
            }
            other => panic!("expected ImportHashMismatch, got {other:?}"),
        }
        // Nothing cached under either the real or the bogus pin.
        assert!(!ctx.cache_root.join(&bad_pin).exists());
        assert!(!ctx.cache_root.join(&real_pin).exists());
    }

    /// A malformed pin on a remote import is
    /// [`ResolveError::ImportPinShape`], and no fetch is ever
    /// attempted.
    #[test]
    fn a_malformed_remote_pin_never_fetches() {
        let dir = temp_dir("remote-pin-shape");
        let source = FakeSource::new(&[]); // no entries
        let ctx = ctx_for(&source, &dir, "pinshape");
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("https://example.com/frag.json", Some("not-a-hash")),
        );
        assert!(matches!(
            resolve_with_cache(&path, &ctx),
            Err(ResolveError::ImportPinShape { .. })
        ));
        assert_eq!(source.calls(), 0, "malformed pins must not fetch");
    }

    /// Local imports never touch the cache directory: it stays empty
    /// (or nonexistent) across the resolve.
    #[test]
    fn local_imports_never_touch_the_cache() {
        let dir = temp_dir("local-no-cache");
        write(&dir, "frag.json", &shexec_fragment());
        let path = write(
            &dir,
            "profile.json",
            &importing_profile("./frag.json", None),
        );
        let source = FakeSource::new(&[]);
        let ctx = ctx_for(&source, &dir, "no-cache");
        resolve_with_cache(&path, &ctx).expect("local import must resolve");
        assert!(
            !ctx.cache_root.exists() || ctx.cache_root.read_dir().unwrap().next().is_none(),
            "cache root must stay empty for a local import"
        );
    }

    // -----------------------------------------------------------------
    // Helper predicate the pin subcommand + resolver share.
    // -----------------------------------------------------------------

    #[test]
    fn name_at_version_shape_predicate_matches_the_spec() {
        for good in [
            "comfyui-base@0.1.0",
            "qwen-vllm-serve@0.2.0",
            "a@b",
            "name.with-dots_and-dashes@1.2.3",
        ] {
            assert!(looks_like_name_at_version(good), "{good} must match");
        }
        for bad in [
            "no-at-sign",
            "@leading-at",
            "trailing-at@",
            "double@at@sign",
            "has/slash@1.0",
            "https://host/frag@1.0",
            "spaces are@bad",
            "with!bang@1.0",
        ] {
            assert!(!looks_like_name_at_version(bad), "{bad} must not match");
        }
    }
}
