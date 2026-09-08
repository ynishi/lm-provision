//! Where the provisioner comes from.
//!
//! **The provisioner** is the binary that lands on a pod and does the
//! work there: it reads a profile, installs and configures the machine,
//! and exits with a report. The name is not coined here — the crate that
//! produces it already describes itself as a "static on-pod provisioner"
//! (`crates/lm-provision/Cargo.toml`), and 08 §Inputs titles it "The
//! provisioner binary artifact". It is the word Packer uses for the
//! thing that "install[s] and configure[s] the machine image after
//! booting" [documented:
//! <https://developer.hashicorp.com/packer/docs/provisioners>].
//!
//! It is deliberately not called an **agent**: `agentless` is the
//! industry's own word for "nothing is installed on the managed node"
//! [documented: Ansible, "The managed node does not require Ansible to
//! be installed",
//! <https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html>],
//! so calling a one-shot binary an agent makes every reader's first
//! question — is it still running, does it need stopping, how does it
//! relate to the lease — the wrong question. Nor a **runner** (a runner
//! polls for work; this is pushed and invoked) nor an **executor** (in
//! GitLab's usage that names an execution environment, not a program).
//! And **artifact** is taken: in this workspace it means what a profile
//! declares and an apply pulls back off the pod (`--artifacts-dir`, 08
//! §Session steps pull-artifacts).
//!
//! CI builds it. The release workflow builds
//! `x86_64-unknown-linux-musl` on every tag (`dist-workspace.toml`
//! §targets names it "the pod-side deployment target") and publishes
//! `lm-provision-x86_64-unknown-linux-musl.tar.xz` beside a `.sha256`
//! of it [measured: 2026-09-08, both assets present on the v0.8.0
//! release]. This module is how a session gets that release artifact,
//! so that running `apply` needs a network rather than a toolchain.
//!
//! # Why not a local build
//!
//! A local path used to be required, which put a `cargo build --target
//! x86_64-unknown-linux-musl` in front of every apply and made what
//! lands on the pod a property of the operator's machine: some working
//! tree, some toolchain, some day, under a version number nothing
//! recorded. The release asset is the opposite of each of those — one
//! build per version, made once, hashed by the builder, and verified
//! here before it is pushed anywhere. `--provisioner-path` stays, as
//! the override a person developing the provisioner itself needs
//! (§[`Source::Override`]); it is no longer the only way in.
//!
//! # The shape is not novel
//!
//! Version-pinned, checksum-verified, cached under the user's cache
//! directory: the shape a plugin download has. Terraform verifies a
//! provider against the checksum file published beside it and keeps
//! what it verified in a plugin cache directory rather than fetching
//! per run [documented:
//! <https://developer.hashicorp.com/terraform/cli/config/config-file#provider-plugin-cache>].
//! The cache location is `$XDG_CACHE_HOME`, falling back to
//! `$HOME/.cache` [documented: XDG Base Directory Specification 0.8].
//!
//! # What is verified, and against what
//!
//! The digest comes from the release, and so does the archive: a
//! sidecar published by the same run is not an independent witness, and
//! this module does not claim it is. What the check does buy is what a
//! checksum buys — a truncated download, a proxy that rewrote the body,
//! a cache serving the previous version's bytes under this version's
//! name — all of which are failures this would otherwise push to a pod
//! and run as root. Provenance (who built it, from which commit) is
//! attestation's job and is not claimed here.

use std::ffi::OsStr;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sha2::{Digest, Sha256};

/// The target triple the pod runs. Static-linked musl, because the pod
/// is not promised a libc, a language runtime, or anything else (08
/// §Inputs "The provisioner binary artifact").
pub const POD_TARGET: &str = "x86_64-unknown-linux-musl";

/// The `[[bin]]` name the workspace produces, which is also the entry
/// to pull out of the archive and the name it keeps in the cache.
pub const BINARY_NAME: &str = "lm-provision";

/// Per-process counter in a staging file's name — the same reason the
/// three sibling sites in the core crate have one: one process can have
/// two of these in flight (an MCP server holds concurrent sessions),
/// and a pid alone would give both the same staging path.
static STAGING_SEQ: AtomicU32 = AtomicU32::new(0);

/// Where a resolved provisioner came from. Carried out so the caller
/// can put it on stderr: an operator reading a failed apply needs to
/// know whether the binary that ran came off the network, off the disk,
/// or off their own build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `--provisioner-path <path>`, used as given and not verified
    /// against anything — the operator named this file, so naming it is
    /// the authorization.
    Override,
    /// Already in the cache from an earlier run.
    Cached,
    /// Downloaded from the release and verified in this run.
    Fetched {
        /// The archive the binary came out of.
        url: String,
    },
}

/// A local path holding the provisioner, and how it got there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The file to push.
    pub path: PathBuf,
    /// Where it came from, for the trace.
    pub source: Source,
}

/// Why a provisioner could not be resolved. One variant per thing an
/// operator would do differently, since each is rendered as the single
/// stderr failure line (07-cli.md §Error surface).
#[derive(Debug, thiserror::Error)]
pub enum ProvisionerError {
    /// No cache directory: neither `XDG_CACHE_HOME` nor `HOME` is set,
    /// which is not a state to guess a path out of.
    #[error("no cache directory: neither XDG_CACHE_HOME nor HOME is set (pass --provisioner-path to name a local file instead)")]
    NoCacheDir,

    /// The cache directory could not be made or written.
    #[error("provisioner cache at {path}: {message}")]
    Cache {
        /// The path that refused.
        path: PathBuf,
        /// What the filesystem said.
        message: String,
    },

    /// The download failed. Carries the URL because the first thing to
    /// check is whether that version was ever released.
    #[error("fetching {url}: {message}")]
    Download {
        /// What was being fetched.
        url: String,
        /// What the transfer said.
        message: String,
    },

    /// The `.sha256` sidecar was not a digest.
    #[error("checksum file {url}: {message}")]
    Sidecar {
        /// The sidecar that could not be read.
        url: String,
        /// Why it could not be.
        message: String,
    },

    /// The archive is not what the release says it is. **Nothing is
    /// cached and nothing is pushed** — a mismatch here is the one this
    /// module exists to stop.
    #[error(
        "checksum mismatch for {url}: release states {expected}, downloaded bytes hash to {actual}"
    )]
    Digest {
        /// The archive that failed.
        url: String,
        /// What the sidecar stated.
        expected: String,
        /// What arrived.
        actual: String,
    },

    /// The archive did not contain the binary.
    #[error("unpacking {url}: {message}")]
    Unpack {
        /// The archive.
        url: String,
        /// What went wrong inside it.
        message: String,
    },
}

/// The `x86_64-unknown-linux-musl` archive's asset name, as `dist`
/// publishes it.
pub fn archive_name() -> String {
    format!("{BINARY_NAME}-{POD_TARGET}.tar.xz")
}

/// The release download URL for `version`.
///
/// Built from `CARGO_PKG_REPOSITORY` rather than a literal: the
/// repository is already declared once in `Cargo.toml`, and a second
/// spelling of it here is a second thing to update when it moves.
pub fn archive_url(version: &str) -> String {
    format!(
        "{}/releases/download/v{version}/{}",
        env!("CARGO_PKG_REPOSITORY").trim_end_matches('/'),
        archive_name()
    )
}

/// The default version to resolve: this driver's own.
///
/// A driver and the provisioner it pushes are built from one workspace
/// version (`[workspace.package] version`), so the driver knows which
/// provisioner it was written against without being told.
pub fn default_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `$XDG_CACHE_HOME/lm-provision/provisioner`, else `$HOME/.cache/...`.
pub fn cache_root() -> Result<PathBuf, ProvisionerError> {
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match std::env::var_os("HOME") {
            Some(home) if !home.is_empty() => PathBuf::from(home).join(".cache"),
            _ => return Err(ProvisionerError::NoCacheDir),
        },
    };
    Ok(base.join("lm-provision").join("provisioner"))
}

/// Resolve the provisioner for `version` under the default cache.
pub fn resolve(version: &str) -> Result<Resolved, ProvisionerError> {
    resolve_in(version, &cache_root()?)
}

/// Resolve the provisioner from an archive URL named by the caller,
/// under the default cache.
///
/// The URL is the escape hatch for a release this build cannot name: a
/// fork's releases, a mirror inside a network that cannot reach
/// github.com, an asset uploaded by hand. It is verified exactly as the
/// default path is — against `<url>.sha256`, which the publisher has to
/// have put beside it — because an operator naming a *download* has not
/// inspected its bytes, unlike an operator naming a local file.
pub fn resolve_url(url: &str) -> Result<Resolved, ProvisionerError> {
    resolve_url_in(url, &cache_root()?)
}

/// [`resolve`] with the cache root named by the caller, so a test can
/// have one that is not the developer's.
///
/// Cache first: a hit never touches the network, which is what makes
/// repeated applies against the same version cheap and what makes an
/// apply possible on a host that has run one before and is now offline.
pub fn resolve_in(version: &str, root: &Path) -> Result<Resolved, ProvisionerError> {
    fetch_in(&archive_url(version), &root.join(version), root)
}

/// [`resolve_url`] with the cache root named by the caller.
///
/// Cached under a directory named for the URL rather than for a
/// version, because a URL does not have to carry one and two URLs that
/// do carry the same one need not name the same bytes (a fork's `v0.8.0`
/// is not this repository's). The name is a digest of the URL, which is
/// how any cache keyed by request does it.
pub fn resolve_url_in(url: &str, root: &Path) -> Result<Resolved, ProvisionerError> {
    let key = format!("url-{}", &digest_hex(url.as_bytes())[..16]);
    fetch_in(url, &root.join(key), root)
}

/// The body both resolvers share: cache hit, else download, verify,
/// unpack, admit.
///
/// `dir` is where the binary lands; `root` is where staging files go
/// while it is still in question.
fn fetch_in(url: &str, dir: &Path, root: &Path) -> Result<Resolved, ProvisionerError> {
    let dest = dir.join(BINARY_NAME);
    if dest.is_file() {
        return Ok(Resolved {
            path: dest,
            source: Source::Cached,
        });
    }

    // The entry's own directory is not made here: a typo in
    // `--provisioner-version` would leave an empty one behind for a
    // release that does not exist, and a cache full of those is a cache
    // nobody can read. Staging happens in the root, and `admit` makes
    // the directory when there is something to put in it.
    std::fs::create_dir_all(root).map_err(|error| ProvisionerError::Cache {
        path: root.to_path_buf(),
        message: error.to_string(),
    })?;

    let url = url.to_string();
    let sidecar_url = format!("{url}.sha256");
    let archive = download(&url, root)?;
    let sidecar = download(&sidecar_url, root)?;

    let expected = parse_sidecar(&String::from_utf8_lossy(&sidecar)).map_err(|message| {
        ProvisionerError::Sidecar {
            url: sidecar_url,
            message,
        }
    })?;
    let actual = digest_hex(&archive);
    if actual != expected {
        return Err(ProvisionerError::Digest {
            url,
            expected,
            actual,
        });
    }

    let binary = unpack(&archive).map_err(|message| ProvisionerError::Unpack {
        url: url.clone(),
        message,
    })?;
    admit(&binary, &dest)?;

    Ok(Resolved {
        path: dest,
        source: Source::Fetched { url },
    })
}

/// GET `url` into memory, by way of a staging file under `dir`.
///
/// The transfer is the core crate's — one downloader in this workspace,
/// with the redirect handling and the stalled-supplier deadline already
/// argued for there (`exec::effects::transfer`). It writes to a path,
/// so this reads the path back and removes it; the archive is
/// single-digit megabytes [measured: 2026-09-08, 2,607,976 bytes for
/// v0.8.0], which is a size to hold in memory rather than to stream
/// through a verifier twice.
fn download(url: &str, dir: &Path) -> Result<Vec<u8>, ProvisionerError> {
    let staging = dir.join(staging_name(url));
    let staging_str = staging.to_str().ok_or_else(|| ProvisionerError::Cache {
        path: staging.clone(),
        message: "cache path is not UTF-8".to_string(),
    })?;

    // The downloader is async because `reqwest` is, and both callers of
    // this are synchronous — a CLI subcommand and a server's startup
    // configuration. So there is a runtime and a `block_on`, for the
    // same reason the core crate's CLI has one.
    //
    // **On a thread of its own**, always. One of those callers is the
    // MCP server, whose `main` is already inside a runtime, and
    // `block_on` from a runtime thread panics outright ("Cannot start a
    // runtime from within a runtime") [measured: 2026-09-08, running
    // `lm-provision-mcp` with no `LM_PROVISION_BINARY` set aborted with
    // exit 101 before this]. Branching on `Handle::try_current` would
    // make the two contexts take different code paths, and the one that
    // panics is the one that is harder to reach from a test; a thread
    // that owns its runtime behaves the same either way. It costs one
    // spawn per download, against a transfer measured in megabytes.
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime =
                    tokio::runtime::Runtime::new().map_err(|error| ProvisionerError::Download {
                        url: url.to_string(),
                        message: format!("starting the async runtime: {error}"),
                    })?;
                runtime
                    .block_on(lm_provision::exec::effects::transfer(
                        url,
                        staging_str,
                        lm_provision::exec::effects::ignore_progress(),
                    ))
                    .map_err(|error| ProvisionerError::Download {
                        url: url.to_string(),
                        message: error.to_string(),
                    })
            })
            .join()
            // A panic inside the download thread is this process's bug,
            // not a download failure; re-raising it keeps it that way
            // rather than reporting it as an unreachable release.
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    });

    let read = outcome.and_then(|_| {
        std::fs::read(&staging).map_err(|error| ProvisionerError::Download {
            url: url.to_string(),
            message: error.to_string(),
        })
    });
    // Whether it arrived or not, the staging file is this function's
    // litter and nobody else's.
    let _ = std::fs::remove_file(&staging);
    read
}

/// Land `binary` at `dest` as an executable, via a staging file.
///
/// Written and renamed rather than written in place: a half-written
/// file at the cache path is a binary a later run would find, believe,
/// and push.
fn admit(binary: &[u8], dest: &Path) -> Result<(), ProvisionerError> {
    let staging = dest.with_extension(format!(
        "part-{}-{}",
        std::process::id(),
        STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let cache_error = |path: &Path, error: std::io::Error| ProvisionerError::Cache {
        path: path.to_path_buf(),
        message: error.to_string(),
    };

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|error| cache_error(parent, error))?;
    }
    std::fs::write(&staging, binary).map_err(|error| cache_error(&staging, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The pod-side push runs it; a mode without the execute bit
        // would fail on the machine rather than here.
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| cache_error(&staging, error))?;
    }
    std::fs::rename(&staging, dest).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        cache_error(dest, error)
    })
}

/// The staging file for a download: the asset's name plus the pid and a
/// per-process counter.
fn staging_name(url: &str) -> String {
    let asset = url.rsplit('/').next().unwrap_or("provisioner");
    format!(
        "{asset}.part-{}-{}",
        std::process::id(),
        STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Lowercase hex SHA-256, the encoding the sidecar is written in.
fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The digest a `.sha256` sidecar states.
///
/// The file is `sha256sum` output — `<hex>  <filename>` — so the digest
/// is the first field. Rejecting anything that is not 64 hex digits is
/// what keeps an error page served with a `200` from being compared
/// against, and reported as, a checksum.
pub fn parse_sidecar(text: &str) -> Result<String, String> {
    let field = text
        .split_whitespace()
        .next()
        .ok_or_else(|| "empty".to_string())?;
    if field.len() != 64 || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "expected 64 hex digits, got {} characters",
            field.chars().count()
        ));
    }
    Ok(field.to_ascii_lowercase())
}

/// Pull the provisioner out of a `dist` archive.
///
/// The archive holds the binary under a directory named for the target,
/// beside the README and the licences, so the entry is picked by name
/// and by being a regular file — a directory called `lm-provision` would
/// otherwise match and unpack as zero bytes.
pub fn unpack(archive: &[u8]) -> Result<Vec<u8>, String> {
    let mut tarball = Vec::new();
    lzma_rs::xz_decompress(&mut Cursor::new(archive), &mut tarball)
        .map_err(|error| format!("xz: {error:?}"))?;

    let mut entries = tar::Archive::new(Cursor::new(tarball));
    for entry in entries.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let is_binary = entry
            .path()
            .map(|path| path.file_name() == Some(OsStr::new(BINARY_NAME)))
            .unwrap_or(false);
        if !is_binary {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        return Ok(bytes);
    }
    Err(format!("no `{BINARY_NAME}` entry in the archive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `dist`-shaped archive: the binary under a target-named
    /// directory, beside the files `dist` ships with it.
    fn dist_archive(payload: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let prefix = format!("{BINARY_NAME}-{POD_TARGET}");

        let mut readme = tar::Header::new_gnu();
        readme.set_size(6);
        readme.set_mode(0o644);
        readme.set_cksum();
        builder
            .append_data(&mut readme, format!("{prefix}/README"), &b"readme"[..])
            .unwrap();

        let mut binary = tar::Header::new_gnu();
        binary.set_size(payload.len() as u64);
        binary.set_mode(0o755);
        binary.set_cksum();
        builder
            .append_data(&mut binary, format!("{prefix}/{BINARY_NAME}"), payload)
            .unwrap();

        let tarball = builder.into_inner().unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(tarball), &mut xz).unwrap();
        xz
    }

    #[test]
    fn the_url_names_the_release_asset_for_the_version() {
        let url = archive_url("0.8.0");
        assert!(
            url.ends_with(
                "/releases/download/v0.8.0/lm-provision-x86_64-unknown-linux-musl.tar.xz"
            ),
            "{url}"
        );
        assert!(url.starts_with("https://"), "{url}");
    }

    #[test]
    fn the_default_version_is_the_drivers_own() {
        assert_eq!(default_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn the_sidecars_first_field_is_the_digest() {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            parse_sidecar(&format!("{digest}  lm-provision.tar.xz\n")).unwrap(),
            digest
        );
    }

    #[test]
    fn an_uppercase_digest_is_the_same_digest() {
        let digest = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert_eq!(parse_sidecar(digest).unwrap(), digest.to_ascii_lowercase());
    }

    /// An error page served with a `200` is the case this refuses: it
    /// has a first field, and comparing an archive against it would
    /// report a checksum mismatch for a checksum that was never there.
    #[test]
    fn a_sidecar_that_is_not_a_digest_is_refused() {
        assert!(parse_sidecar("<!DOCTYPE html>").is_err());
        assert!(parse_sidecar("").is_err());
        assert!(parse_sidecar("deadbeef  file").is_err());
    }

    #[test]
    fn the_digest_is_lowercase_hex_sha256() {
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn unpacking_takes_the_binary_and_not_its_neighbours() {
        let payload = b"\x7fELF and the rest of it";
        assert_eq!(unpack(&dist_archive(payload)).unwrap(), payload);
    }

    #[test]
    fn an_archive_without_the_binary_is_an_error() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "somewhere/README", &b"readme"[..])
            .unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(builder.into_inner().unwrap()), &mut xz).unwrap();

        assert!(unpack(&xz).unwrap_err().contains(BINARY_NAME));
    }

    /// The cache hit is the whole point of the cache: it resolves
    /// without a network, which this proves by asking for a version
    /// that was never released.
    #[test]
    fn a_cached_provisioner_resolves_without_the_network() {
        let root = std::env::temp_dir().join(format!(
            "lm-provision-provisioner-test-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = root.join("0.0.0-never-released");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(BINARY_NAME), b"cached").unwrap();

        let resolved = resolve_in("0.0.0-never-released", &root).unwrap();
        assert_eq!(resolved.source, Source::Cached);
        assert_eq!(resolved.path, dir.join(BINARY_NAME));

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A URL caches under a name derived from the URL, so two URLs
    /// carrying the same version string — a fork's release and this
    /// repository's — do not land on each other.
    #[test]
    fn a_url_caches_under_the_urls_own_name() {
        let root = std::env::temp_dir().join(format!(
            "lm-provision-url-test-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mine = "https://example.invalid/a/v0.8.0/lm-provision.tar.xz";
        let fork = "https://example.invalid/b/v0.8.0/lm-provision.tar.xz";

        let key = format!("url-{}", &digest_hex(mine.as_bytes())[..16]);
        let dir = root.join(&key);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(BINARY_NAME), b"cached").unwrap();

        let resolved = resolve_url_in(mine, &root).unwrap();
        assert_eq!(resolved.source, Source::Cached);
        assert_eq!(resolved.path, dir.join(BINARY_NAME));

        // The fork's URL is not a hit on the same entry; with no
        // network for `example.invalid` it can only fail to fetch.
        assert!(matches!(
            resolve_url_in(fork, &root),
            Err(ProvisionerError::Download { .. })
        ));

        std::fs::remove_dir_all(&root).unwrap();
    }
}
