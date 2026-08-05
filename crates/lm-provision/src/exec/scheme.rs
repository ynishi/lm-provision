//! Scheme resolution for the `net.transfer` bridge: the single place
//! that decides what a `(src, dst)` pair means.
//!
//! Two callers ask the same question. [`super::lifecycle`] asks it when
//! a credential-free `sync.pull` composes its download step, and
//! [`super::effects::transfer`] asks it for the direct `net.transfer`
//! op. They used to answer it separately — two copies of the same
//! `b2://` / `hf://` rejection, drifting independently — so the answer
//! lives here and both read it.
//!
//! The rules are `04-bridge.md` §`net.transfer`:
//!
//! - `https://` / `http://` src → download, verbatim;
//! - `hf://<owner>/<repo>[@<rev>]/<path>` → download, rewritten to
//!   `https://huggingface.co/<owner>/<repo>/resolve/<rev>/<path>` with
//!   `main` for an unpinned repo;
//! - `b2://<bucket>/<path>` → the deployment's public download endpoint,
//!   which **no profile field declares**, so it is an explicit
//!   unsupported error naming that gap rather than a guessed host;
//! - a scheme on `dst` and a plain path on `src` → upload;
//! - every other scheme (`gs://`, `s3://`, `ftp://`, `file://`) stays
//!   rejected.
//!
//! `04` §Stability marks the URL templates **provisional** — upstream
//! endpoint churn may force a revision — which is the reason they are
//! worth having in exactly one file.

use super::ExecError;

/// Host serving HuggingFace's public file endpoint.
const HF_HOST: &str = "https://huggingface.co";

/// Revision a `hf://` URI resolves to when it pins none.
const HF_DEFAULT_REVISION: &str = "main";

/// What a `(src, dst)` pair resolves to on the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transfer {
    /// GET `url`, streaming the body into the local destination path.
    Download {
        /// Fully resolved `https://` URL.
        url: String,
    },
    /// PUT the local source file to `url`.
    Upload {
        /// Fully resolved `https://` URL.
        url: String,
    },
}

/// Resolve a `net.transfer` `(src, dst)` pair into its bridge route.
///
/// The direction is read off the schemes, matching what validate
/// enforces at the precondition stage (`02` §Catalog kinds
/// `net.transfer`): a scheme on `src` is a download, one on `dst` is an
/// upload. A pair carrying both or neither reaches here only when
/// validate was skipped — `apply` does not run it (`07` §Invocation) —
/// so it fails explicitly rather than picking a direction.
pub(crate) fn resolve(op: &str, src: &str, dst: &str) -> Result<Transfer, ExecError> {
    let src_scheme = src.contains("://");
    let dst_scheme = dst.contains("://");

    match (src_scheme, dst_scheme) {
        (true, true) => Err(ExecError::Unsupported(format!(
            "{op} '{src}' -> '{dst}': src and dst both carry a scheme, so the \
             transfer direction is undetermined"
        ))),
        (false, false) => Err(ExecError::Unsupported(format!(
            "{op} '{src}' -> '{dst}': neither src nor dst carries a scheme, so \
             the transfer direction is undetermined"
        ))),
        (true, false) => Ok(Transfer::Download {
            url: download_url(op, src, None)?,
        }),
        (false, true) => Ok(Transfer::Upload {
            url: upload_url(op, dst)?,
        }),
    }
}

/// The `https://` URL a public download source resolves to.
///
/// `revision` is the phase's `revision` payload field, used only when
/// the URI pins none itself: a URL-carried revision wins over
/// `opts.revision` because the URL is the more specific address
/// (`02` §Dispatch routing).
pub(crate) fn download_url(
    op: &str,
    src: &str,
    revision: Option<&str>,
) -> Result<String, ExecError> {
    if src.starts_with("https://") || src.starts_with("http://") {
        return Ok(src.to_string());
    }

    if let Some(rest) = src.strip_prefix("hf://") {
        let (owner, repo, url_rev, path_in_repo) = parse_hf_uri(rest, op, src)?;
        // A download needs the file path inside the repo — an
        // `hf://<owner>/<repo>` with no trailing path names a repo, not
        // a file (that shape is `llm_models`' snapshot download).
        let Some(path_in_repo) = path_in_repo else {
            return Err(ExecError::EffectFailed {
                op: op.to_string(),
                message: format!("hf:// download URI is missing the file path segment: {src}"),
            });
        };
        let rev = url_rev
            .or_else(|| revision.map(str::to_string))
            .unwrap_or_else(|| HF_DEFAULT_REVISION.to_string());
        return Ok(format!(
            "{HF_HOST}/{owner}/{repo}/resolve/{rev}/{path_in_repo}"
        ));
    }

    if src.starts_with("b2://") {
        return Err(ExecError::Unsupported(format!(
            "{op} '{src}': a public b2:// download resolves to the deployment's \
             own download endpoint (cluster- and account-specific), and no \
             profile field declares one — give the phase a credential `env` to \
             take the b2 CLI route instead (chapter 04 §net.transfer)"
        )));
    }

    Err(ExecError::Unsupported(format!(
        "{op} '{src}': only https:// and hf:// sources resolve on the \
         net.transfer bridge"
    )))
}

/// The `https://` URL an upload destination resolves to.
///
/// A `b2://` / `hf://` dst never belongs here: uploads to those are
/// CLI-routed unconditionally (`02` §Dispatch routing), so reaching the
/// bridge with one is a routing bug rather than an author error, and
/// saying so beats inventing an endpoint.
fn upload_url(op: &str, dst: &str) -> Result<String, ExecError> {
    if dst.starts_with("https://") || dst.starts_with("http://") {
        return Ok(dst.to_string());
    }
    if dst.starts_with("b2://") || dst.starts_with("hf://") {
        return Err(ExecError::Unsupported(format!(
            "{op} -> '{dst}': b2:// / hf:// uploads are CLI-routed and never \
             reach the net.transfer bridge (chapter 02 §Dispatch routing)"
        )));
    }
    Err(ExecError::Unsupported(format!(
        "{op} -> '{dst}': only https:// destinations upload over the \
         net.transfer bridge"
    )))
}

/// Split the remainder of a `b2://` URI (everything after `b2://`) into
/// its bucket and path parts.
pub(crate) fn split_b2_uri<'a>(
    rest: &'a str,
    op: &str,
    uri: &str,
) -> Result<(&'a str, &'a str), ExecError> {
    match rest.split_once('/') {
        Some((bucket, path)) if !bucket.is_empty() && !path.is_empty() => Ok((bucket, path)),
        _ => Err(ExecError::EffectFailed {
            op: op.to_string(),
            message: format!("malformed b2:// URI (missing bucket or path): {uri}"),
        }),
    }
}

/// Parse the remainder of an `hf://` URI (everything after `hf://`) into
/// its owner / repo / revision / trailing-path parts (spec 02 §Dispatch
/// routing: `hf://<owner>/<repo>@<rev>/<path>` — the `@<rev>` suffix on
/// the repo segment pins a revision; `@` is rejected in the owner
/// segment). Ported from the POC `lua/lm/dispatch.lua` `parse_hf_uri`.
pub(crate) fn parse_hf_uri(
    rest: &str,
    op: &str,
    uri: &str,
) -> Result<(String, String, Option<String>, Option<String>), ExecError> {
    let fail = |message: String| ExecError::EffectFailed {
        op: op.to_string(),
        message,
    };
    let (owner, remainder) = rest
        .split_once('/')
        .ok_or_else(|| fail(format!("hf:// URI is missing an owner/repo segment: {uri}")))?;
    if owner.contains('@') {
        return Err(fail(format!(
            "'@' is not allowed in the hf:// owner segment: {owner}"
        )));
    }
    let (repo_and_rev, path_in_repo) = match remainder.split_once('/') {
        Some((repo_and_rev, path)) if !path.is_empty() => (repo_and_rev, Some(path.to_string())),
        Some((repo_and_rev, _)) => (repo_and_rev, None),
        None => (remainder, None),
    };
    let (repo, rev) = match repo_and_rev.split_once('@') {
        Some((repo, rev)) => (repo.to_string(), Some(rev.to_string())),
        None => (repo_and_rev.to_string(), None),
    };
    Ok((owner.to_string(), repo, rev, path_in_repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_https_source_passes_through_verbatim() {
        assert_eq!(
            download_url("net_transfer", "https://example.com/a.bin", None).unwrap(),
            "https://example.com/a.bin"
        );
    }

    #[test]
    fn an_unpinned_hf_uri_resolves_to_main() {
        assert_eq!(
            download_url("sync_pull", "hf://owner/repo/model.bin", None).unwrap(),
            "https://huggingface.co/owner/repo/resolve/main/model.bin"
        );
    }

    #[test]
    fn a_url_carried_revision_wins_over_the_payload_field() {
        assert_eq!(
            download_url("sync_pull", "hf://owner/repo@abc123/model.bin", Some("v1")).unwrap(),
            "https://huggingface.co/owner/repo/resolve/abc123/model.bin"
        );
    }

    #[test]
    fn the_payload_revision_is_used_when_the_uri_pins_none() {
        assert_eq!(
            download_url("sync_pull", "hf://owner/repo/model.bin", Some("v1")).unwrap(),
            "https://huggingface.co/owner/repo/resolve/v1/model.bin"
        );
    }

    #[test]
    fn a_nested_path_survives_the_rewrite() {
        assert_eq!(
            download_url("sync_pull", "hf://owner/repo/sub/dir/model.bin", None).unwrap(),
            "https://huggingface.co/owner/repo/resolve/main/sub/dir/model.bin"
        );
    }

    #[test]
    fn an_hf_uri_without_a_file_path_is_an_error() {
        let err = download_url("sync_pull", "hf://owner/repo", None).unwrap_err();
        assert!(
            format!("{err}").contains("missing the file path segment"),
            "{err}"
        );
    }

    /// The b2 gap is named, not guessed: no profile field carries the
    /// deployment's download endpoint.
    #[test]
    fn a_public_b2_source_names_the_missing_endpoint() {
        let err = download_url("sync_pull", "b2://bucket/a.bin", None).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("download endpoint"), "{rendered}");
        assert!(rendered.contains("credential `env`"), "{rendered}");
    }

    #[test]
    fn other_schemes_stay_rejected() {
        for src in ["gs://b/o", "s3://b/o", "ftp://h/p", "file:///tmp/x"] {
            assert!(
                download_url("net_transfer", src, None).is_err(),
                "{src} must not resolve"
            );
        }
    }

    #[test]
    fn the_direction_follows_the_scheme_side() {
        assert_eq!(
            resolve(
                "net_transfer",
                "https://example.com/a.bin",
                "/workspace/a.bin"
            )
            .unwrap(),
            Transfer::Download {
                url: "https://example.com/a.bin".to_string()
            }
        );
        assert_eq!(
            resolve(
                "net_transfer",
                "/workspace/a.bin",
                "https://example.com/a.bin"
            )
            .unwrap(),
            Transfer::Upload {
                url: "https://example.com/a.bin".to_string()
            }
        );
    }

    #[test]
    fn a_pair_with_both_or_neither_scheme_is_undetermined() {
        assert!(resolve("net_transfer", "https://h/a", "b2://b/a").is_err());
        assert!(resolve("net_transfer", "/tmp/a", "/tmp/b").is_err());
    }

    #[test]
    fn a_cli_routed_upload_destination_says_so() {
        let err = resolve("net_transfer", "/workspace/a.bin", "hf://owner/repo/a.bin").unwrap_err();
        assert!(format!("{err}").contains("CLI-routed"), "{err}");
    }
}
