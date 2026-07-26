//! Lifecycle-op step composition (ported from the POC
//! `lua/lm/dispatch.lua`).
//!
//! The 15 lifecycle ops in the catalog rarely map 1:1 onto an effect
//! primitive: `system.apt` becomes one `apt-get install -y ...` shell
//! invocation, `custom_nodes` fans out to a clone / checkout / pip
//! sequence per entry, `models` fans out to one download per entry, and
//! so on. This module reduces every lifecycle payload to a pure list of
//! [`Step`]s — the smallest thing an effect can execute — so that the
//! registry can render them for a dry-run trace and execute them for
//! real without duplicating the composition logic.
//!
//! [`expand`] is deliberately pure (no I/O). The registry decides what
//! to do with the resulting steps based on the [`ExecMode`](super::ExecMode);
//! [`render_dry`] and [`execute_step`] provide the two rendering
//! strategies.
//!
//! ## Payload subset carried by the AST
//!
//! The `ProfileNode` payload is still a partial projection of the full
//! spec-02 payload (`ServiceStart` has no platform detail, `PythonDeps`
//! has no `force_reinstall`, and so on). So:
//!
//! - Fields with a defensible built-in default are constant-substituted
//!   (`PythonDeps.in_comfy_venv=false` → the system `pip` on `PATH`;
//!   `ComfyUiInstall.repo=None` → `comfyanonymous/ComfyUI`; a `models`
//!   entry with no `subdir`/`kind` → `checkpoints`).
//! - Ops whose invocation cannot be constructed from the AST fields
//!   alone (`ComfyUiRestart` lacks its restart command / `extra_args`;
//!   `ServiceStart` lacks per-platform launch detail) expand to a single
//!   [`Step::Note`] recording that fact, rather than inventing an argv.
//!
//! ## Env-routed CLI dispatch (spec 02 §Dispatch routing, step ③)
//!
//! `SyncPull` / `StagingPush` carry an `env` keyed slot and a `revision`
//! (step ②); this module now consumes them (step ③). The registry
//! resolves the phase `env` map once through
//! [`EnvPolicy`](super::policy::EnvPolicy) and hands the resolved
//! `name → value` map to [`render_dry`] / [`execute_step`], which inject
//! it into the composed [`Step::Sh`] steps. Scheme routing:
//!
//! - `SyncPull` `b2://` src **with a non-empty `env`** → the native
//!   `b2 download-file-by-name <bucket> <path> <dst>` over `sh.exec`.
//! - `SyncPull` `hf://` src with a non-empty `env` → a deferred
//!   [`Step::Note`]: `huggingface-cli download --local-dir` names a
//!   destination *directory*, while `dst` here is an exact destination
//!   *file* path (04-bridge §net.transfer), so no concrete argv is
//!   invented — mirroring the POC `lua/lm/dispatch.lua` decision (a
//!   spec 02 vs 04 tension, see plan.md §KNOWN LIMITATION).
//! - `SyncPull` with an empty `env` keeps its prior behaviour (an
//!   `https://` src maps to a plain download; a `b2://` / `hf://` src is
//!   [`ExecError::Unsupported`] — the public `net.transfer`-bridge
//!   scheme resolution is not implemented).
//! - `StagingPush` uploads are **always** CLI-routed (04-bridge
//!   §net.transfer): `b2://` dst → `b2 upload-file`, `hf://` dst →
//!   `huggingface-cli upload`; an `https://` dst (HTTP PUT) is
//!   [`ExecError::Unsupported`].

use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{effects, ExecError};
use crate::dsl_poc::ProfileNode;

/// ComfyUI clone target (spec 02 §Built-in path constants).
const COMFYUI_INSTALL_DIR: &str = "/workspace/ComfyUI";
/// Venv-relative pip binary (spec 02 §Built-in path constants).
const COMFYUI_VENV_PIP: &str = "/workspace/ComfyUI/venv/bin/pip";
/// Root of the ComfyUI model store (spec 02 §Built-in path constants).
const MODELS_ROOT: &str = "/workspace/ComfyUI/models";
/// Root of the ComfyUI custom-nodes store (spec 02 §Built-in path constants).
const CUSTOM_NODES_ROOT: &str = "/workspace/ComfyUI/custom_nodes";
/// `models` entry default subdir when neither `subdir` nor `kind` is set.
const DEFAULT_MODEL_SUBDIR: &str = "checkpoints";
/// `llm_models` entry default destination directory
/// (`huggingface-cli download --local-dir` target).
const DEFAULT_LLM_MODELS_DST_DIR: &str = "/tmp/";
/// `comfyui.install` default repo when the payload omits `repo`.
const DEFAULT_COMFYUI_REPO: &str = "comfyanonymous/ComfyUI";
/// Health-poll deadline (spec 02: 60 s HTTP poll loop).
const HTTP_POLL_TIMEOUT_SEC: u64 = 60;
/// Poll interval between GETs while waiting for a 2xx.
const HTTP_POLL_INTERVAL_SEC: u64 = 2;

/// One executable step a lifecycle op expands into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Run `argv` via [`effects::sh_exec`]. In real mode a non-zero exit
    /// fails the op.
    Sh(Vec<String>),
    /// Download `src` to `dst` via [`effects::transfer`].
    Transfer {
        /// Source URI or path.
        src: String,
        /// Destination path (never a URI here — transfer only downloads).
        dst: String,
    },
    /// Poll `url` via [`effects::http_get`] until a 2xx response or
    /// `timeout_sec` elapses.
    HttpPoll {
        /// URL to poll.
        url: String,
        /// Overall poll deadline, in seconds.
        timeout_sec: u64,
    },
    /// No effect; `message` is preserved in the log so the operator can
    /// tell that an op ran and what it decided.
    Note(String),
}

/// Expand a lifecycle payload node into its list of executable steps.
///
/// Pure (no I/O) — the registry decides what to do with the steps based
/// on the [`ExecMode`](super::ExecMode). Returns
/// [`ExecError::PayloadVariant`] when called with a non-lifecycle node
/// (a programmer error: the registry only routes the 15 lifecycle op
/// names here). `custom_nodes` / `models` / `llm_models` return
/// [`ExecError::EffectFailed`] on a malformed payload JSON string
/// (that shape is authored input, so a parse error is an op failure,
/// not an internal programmer error).
pub fn expand(payload: &ProfileNode) -> Result<Vec<Step>, ExecError> {
    match payload {
        ProfileNode::SystemApt { packages, .. } => Ok(expand_system_apt(packages)),
        ProfileNode::ComfyUiInstall { ref_name, repo, .. } => {
            Ok(expand_comfyui_install(ref_name, repo.as_deref()))
        }
        ProfileNode::PythonVersionCheck { want, .. } => Ok(expand_python_version_check(want)),
        ProfileNode::PythonDeps {
            deps,
            in_comfy_venv,
            ..
        } => Ok(expand_python_deps(deps, *in_comfy_venv)),
        ProfileNode::CustomNodes { nodes_json, .. } => expand_custom_nodes(nodes_json),
        ProfileNode::SyncPull { src, dst, env, .. } => expand_sync_pull(src, dst, env),
        ProfileNode::SyncPush { src, dst, .. } => Ok(vec![Step::Note(format!(
            "sync_push src={src} dst={dst}: marker only; not executed during apply"
        ))]),
        ProfileNode::StagingPush {
            src, dst, revision, ..
        } => expand_staging_push(src, dst, revision.as_deref()),
        ProfileNode::Models { models_json, .. } => expand_models(models_json),
        ProfileNode::LlmModels { models_json, .. } => expand_llm_models(models_json),
        ProfileNode::PostInstall { script, .. } => Ok(vec![Step::Sh(vec![
            "sh".to_string(),
            "-c".to_string(),
            script.clone(),
        ])]),
        ProfileNode::ComfyUiRestart { port, .. } => Ok(vec![Step::Note(format!(
            "comfyui_restart port={port}: restart argv unsupported — the AST \
             carries no restart command or extra_args (spec 02 comfyui.restart), \
             out of scope for the env-injection work"
        ))]),
        ProfileNode::ComfyUiHealth { port, .. } => Ok(vec![Step::HttpPoll {
            url: format!("http://127.0.0.1:{port}/"),
            timeout_sec: HTTP_POLL_TIMEOUT_SEC,
        }]),
        ProfileNode::ServiceStart {
            name,
            platform_kind,
            ..
        } => Ok(vec![Step::Note(format!(
            "service_start name={name} platform_kind={platform_kind}: \
             per-platform argv unsupported pending AST extension"
        ))]),
        ProfileNode::ServiceReady { check_url, .. } => Ok(vec![Step::HttpPoll {
            url: check_url.clone(),
            timeout_sec: HTTP_POLL_TIMEOUT_SEC,
        }]),
        other => {
            use dsl_kit::DslNode as _;
            Err(ExecError::PayloadVariant {
                node: other.node_id().0,
                expected: "lifecycle",
            })
        }
    }
}

fn expand_system_apt(packages: &[String]) -> Vec<Step> {
    let mut argv = vec![
        "apt-get".to_string(),
        "install".to_string(),
        "-y".to_string(),
    ];
    argv.extend(packages.iter().cloned());
    vec![Step::Sh(argv)]
}

fn expand_comfyui_install(ref_name: &str, repo: Option<&str>) -> Vec<Step> {
    let repo = repo.unwrap_or(DEFAULT_COMFYUI_REPO);
    let url = format!("https://github.com/{repo}.git");
    let script = format!(
        "git clone {url} {dir} && git -C {dir} checkout {ref_name}",
        dir = COMFYUI_INSTALL_DIR
    );
    vec![Step::Sh(vec!["sh".to_string(), "-c".to_string(), script])]
}

fn expand_python_version_check(want: &str) -> Vec<Step> {
    vec![
        Step::Sh(vec!["python3".to_string(), "--version".to_string()]),
        Step::Note(format!(
            "python_version_check want={want}: advisory only; \
             concrete check command pending AST extension"
        )),
    ]
}

fn expand_python_deps(deps: &[String], in_comfy_venv: bool) -> Vec<Step> {
    let pip = if in_comfy_venv {
        COMFYUI_VENV_PIP
    } else {
        "pip"
    };
    let mut argv = vec![pip.to_string(), "install".to_string()];
    argv.extend(deps.iter().cloned());
    vec![Step::Sh(argv)]
}

#[derive(Debug, Deserialize)]
struct CustomNodeSpec {
    name: String,
    repo: String,
    #[serde(rename = "ref", default)]
    git_ref: Option<String>,
    #[serde(default)]
    pip: bool,
}

fn expand_custom_nodes(json: &str) -> Result<Vec<Step>, ExecError> {
    let nodes: Vec<CustomNodeSpec> =
        serde_json::from_str(json).map_err(|err| ExecError::EffectFailed {
            op: "custom_nodes".to_string(),
            message: format!("nodes_json parse: {err}"),
        })?;
    let mut steps = Vec::with_capacity(nodes.len() * 2);
    for node in nodes {
        let node_dir = format!("{CUSTOM_NODES_ROOT}/{}", node.name);
        steps.push(Step::Sh(vec![
            "git".to_string(),
            "clone".to_string(),
            format!("https://github.com/{}.git", node.repo),
            node_dir.clone(),
        ]));
        if let Some(git_ref) = node.git_ref {
            steps.push(Step::Sh(vec![
                "git".to_string(),
                "-C".to_string(),
                node_dir.clone(),
                "checkout".to_string(),
                git_ref,
            ]));
        }
        if node.pip {
            steps.push(Step::Sh(vec![
                COMFYUI_VENV_PIP.to_string(),
                "install".to_string(),
                "-r".to_string(),
                format!("{node_dir}/requirements.txt"),
            ]));
        }
    }
    Ok(steps)
}

/// Route a `sync.pull` download (spec 02 §Dispatch routing).
///
/// The resolved env is not needed here — the registry resolves the phase
/// `env` map and injects it into the emitted [`Step::Sh`] steps; this
/// function only decides the *shape* of those steps from the scheme and
/// whether `env` is non-empty.
fn expand_sync_pull(
    src: &str,
    dst: &str,
    env: &BTreeMap<String, ProfileNode>,
) -> Result<Vec<Step>, ExecError> {
    if env.is_empty() {
        // Public download: `https://` streams to the destination file;
        // a public `b2://` / `hf://` src would need the net.transfer
        // bridge's scheme resolution (chapter 04), not implemented yet.
        if src.starts_with("b2://") || src.starts_with("hf://") {
            return Err(ExecError::Unsupported(format!(
                "sync_pull '{src}': public b2:// / hf:// download over the \
                 net.transfer bridge (chapter 04 scheme resolution) is not implemented"
            )));
        }
        return Ok(vec![Step::Transfer {
            src: src.to_string(),
            dst: dst.to_string(),
        }]);
    }

    // Non-empty env → credential-carrying download routed to the native
    // CLI over sh.exec (spec 02 §Dispatch routing).
    if let Some(rest) = src.strip_prefix("b2://") {
        let (bucket, path) = split_b2_uri(rest, "sync_pull", src)?;
        return Ok(vec![Step::Sh(vec![
            "b2".to_string(),
            "download-file-by-name".to_string(),
            bucket.to_string(),
            path.to_string(),
            dst.to_string(),
        ])]);
    }
    if src.starts_with("hf://") {
        // Deferred, not invented: `huggingface-cli download`'s
        // `--local-dir` names a destination *directory*, but `dst` here
        // is an exact destination *file* path (04-bridge §net.transfer).
        // Mirrors the POC lua/lm/dispatch.lua degradation to a visible
        // no-op (spec 02 vs 04 tension; see the module header).
        return Ok(vec![Step::Note(format!(
            "sync_pull '{src}' -> '{dst}': hf:// CLI download routing is unconfirmed — \
             huggingface-cli download's --local-dir names a destination directory, but \
             dst here is an exact destination file path (04 §net.transfer); deferred"
        ))]);
    }
    // Any other scheme (e.g. https://) with a non-empty env stays on the
    // plain download path — env is inert for a bridge download (spec 02
    // §Dispatch routing: only b2/hf route to a CLI).
    Ok(vec![Step::Transfer {
        src: src.to_string(),
        dst: dst.to_string(),
    }])
}

/// Route a `staging.push` upload (spec 02 §Dispatch routing).
///
/// Unlike downloads, a `b2://` / `hf://` upload dst is **always**
/// CLI-routed, unconditional on `env` (04-bridge §net.transfer). The
/// resolved env is injected by the registry into the emitted
/// [`Step::Sh`] step.
fn expand_staging_push(
    src: &str,
    dst: &str,
    revision: Option<&str>,
) -> Result<Vec<Step>, ExecError> {
    if let Some(rest) = dst.strip_prefix("b2://") {
        let (bucket, path) = split_b2_uri(rest, "staging_push", dst)?;
        return Ok(vec![Step::Sh(vec![
            "b2".to_string(),
            "upload-file".to_string(),
            bucket.to_string(),
            src.to_string(),
            path.to_string(),
        ])]);
    }
    if let Some(rest) = dst.strip_prefix("hf://") {
        let (owner, repo, url_rev, path_in_repo) = parse_hf_uri(rest, "staging_push", dst)?;
        let rev = url_rev.or_else(|| revision.map(str::to_string));
        let mut argv = vec![
            "huggingface-cli".to_string(),
            "upload".to_string(),
            format!("{owner}/{repo}"),
            src.to_string(),
        ];
        if let Some(path_in_repo) = path_in_repo {
            argv.push(path_in_repo);
        }
        if let Some(rev) = rev {
            argv.push("--revision".to_string());
            argv.push(rev);
        }
        return Ok(vec![Step::Sh(argv)]);
    }
    // `https://` dst is an HTTP PUT upload over the net.transfer bridge,
    // which is not implemented yet.
    Err(ExecError::Unsupported(format!(
        "staging_push '{src}' -> '{dst}': upload over the net.transfer bridge \
         (HTTP PUT) is not implemented"
    )))
}

/// Split the remainder of a `b2://<bucket>/<path>` URI into its bucket
/// and path components, both required non-empty (spec 02 `sync.pull` /
/// `sync.push` route shape).
fn split_b2_uri<'a>(rest: &'a str, op: &str, uri: &str) -> Result<(&'a str, &'a str), ExecError> {
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
fn parse_hf_uri(
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

#[derive(Debug, Deserialize)]
struct ModelItemSpec {
    src: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    subdir: Option<String>,
    #[serde(default)]
    kind: Option<String>,
}

fn expand_models(json: &str) -> Result<Vec<Step>, ExecError> {
    let models: Vec<ModelItemSpec> =
        serde_json::from_str(json).map_err(|err| ExecError::EffectFailed {
            op: "models".to_string(),
            message: format!("models_json parse: {err}"),
        })?;
    let mut steps = Vec::with_capacity(models.len());
    for (i, model) in models.into_iter().enumerate() {
        let subdir = model
            .subdir
            .or(model.kind)
            .unwrap_or_else(|| DEFAULT_MODEL_SUBDIR.to_string());
        let filename = model
            .dst
            .or(model.name)
            .ok_or_else(|| ExecError::EffectFailed {
                op: "models".to_string(),
                message: format!(
                    "models[{i}]: entry must declare either 'dst' or 'name' for the target file"
                ),
            })?;
        let dst = format!("{MODELS_ROOT}/{subdir}/{filename}");
        steps.push(Step::Transfer {
            src: model.src,
            dst,
        });
    }
    Ok(steps)
}

#[derive(Debug, Deserialize)]
struct LlmModelSpec {
    src: String,
    #[serde(default)]
    dst_dir: Option<String>,
    #[serde(default)]
    revision: Option<String>,
}

fn expand_llm_models(json: &str) -> Result<Vec<Step>, ExecError> {
    let models: Vec<LlmModelSpec> =
        serde_json::from_str(json).map_err(|err| ExecError::EffectFailed {
            op: "llm_models".to_string(),
            message: format!("models_json parse: {err}"),
        })?;
    let mut steps = Vec::with_capacity(models.len());
    for (i, model) in models.into_iter().enumerate() {
        let rest = model
            .src
            .strip_prefix("hf://")
            .ok_or_else(|| ExecError::EffectFailed {
                op: "llm_models".to_string(),
                message: format!("models[{i}].src must be an hf:// URI, got {}", model.src),
            })?;
        let (owner_repo_at, url_rev) = match rest.split_once('@') {
            Some((prefix, rev)) => (prefix, Some(rev.to_string())),
            None => (rest, None),
        };
        let (owner, repo) =
            owner_repo_at
                .split_once('/')
                .ok_or_else(|| ExecError::EffectFailed {
                    op: "llm_models".to_string(),
                    message: format!(
                        "models[{i}].src is missing an owner/repo segment: {}",
                        model.src
                    ),
                })?;
        if owner.is_empty() || repo.is_empty() || owner.contains('@') {
            return Err(ExecError::EffectFailed {
                op: "llm_models".to_string(),
                message: format!(
                    "models[{i}].src has an invalid owner/repo segment: {}",
                    model.src
                ),
            });
        }
        let rev = url_rev.or(model.revision);
        let dst_dir = model
            .dst_dir
            .unwrap_or_else(|| DEFAULT_LLM_MODELS_DST_DIR.to_string());
        let mut argv = vec![
            "huggingface-cli".to_string(),
            "download".to_string(),
            format!("{owner}/{repo}"),
            "--local-dir".to_string(),
            dst_dir,
        ];
        if let Some(rev) = rev {
            argv.push("--revision".to_string());
            argv.push(rev);
        }
        steps.push(Step::Sh(argv));
    }
    Ok(steps)
}

/// Render one step for the dry-run trace log.
///
/// Used by the registry to build a single per-op log line
/// (`"<op> <step_1>; <step_2>; ..."`) without touching the filesystem
/// or network. `env` is the phase's resolved env-injection map (empty
/// for env-less ops); a [`Step::Sh`] renders its *key* names only —
/// resolved values are never logged (spec 06 opacity).
pub fn render_dry(step: &Step, env: &BTreeMap<String, String>) -> String {
    match step {
        Step::Sh(argv) if env.is_empty() => format!("sh argv={argv:?}"),
        Step::Sh(argv) => format!(
            "sh argv={argv:?} env_keys={:?}",
            env.keys().collect::<Vec<_>>()
        ),
        Step::Transfer { src, dst } => format!("transfer src={src} dst={dst}"),
        Step::HttpPoll { url, timeout_sec } => {
            format!("http_poll url={url} timeout={timeout_sec}s")
        }
        Step::Note(message) => format!("note \"{message}\""),
    }
}

/// Execute one step for real, returning its result summary fragment
/// (the registry joins them per op).
///
/// `op` is the registry op name — used only to label the
/// [`ExecError::EffectFailed`] surface, so the engine's node-located
/// error carries the op that ran. `env` is the phase's resolved
/// env-injection map, injected into a [`Step::Sh`] child process.
pub fn execute_step(
    step: &Step,
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, ExecError> {
    match step {
        Step::Sh(argv) => execute_sh(argv, op, env),
        Step::Transfer { src, dst } => {
            let outcome = effects::transfer(src, dst)?;
            Ok(format!(
                "transfer src={src} dst={} bytes={}",
                outcome.dst, outcome.bytes
            ))
        }
        Step::HttpPoll { url, timeout_sec } => execute_http_poll(url, *timeout_sec, op),
        Step::Note(message) => Ok(format!("note \"{message}\"")),
    }
}

fn execute_sh(
    argv: &[String],
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, ExecError> {
    let outcome = effects::sh_exec(argv, &effects::ShOpts::new(env.clone()))?;
    if outcome.exit_code != 0 {
        return Err(ExecError::EffectFailed {
            op: op.to_string(),
            message: format!(
                "sh {argv:?} failed: exit {} stderr={:?}",
                outcome.exit_code, outcome.stderr_tail
            ),
        });
    }
    Ok(format!(
        "sh exit={} stdout={:?}",
        outcome.exit_code, outcome.stdout_tail
    ))
}

fn execute_http_poll(url: &str, timeout_sec: u64, op: &str) -> Result<String, ExecError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_sec);
    let mut last_status: Option<u16> = None;
    let mut last_err: Option<String> = None;
    loop {
        match effects::http_get(url) {
            Ok(outcome) => {
                if (200..300).contains(&outcome.status) {
                    return Ok(format!("http_poll url={url} status={}", outcome.status));
                }
                last_status = Some(outcome.status);
            }
            Err(err) => {
                last_err = Some(err.to_string());
            }
        }
        if Instant::now() >= deadline {
            let detail = last_status
                .map(|s| format!("last status={s}"))
                .or(last_err)
                .unwrap_or_else(|| "no response".to_string());
            return Err(ExecError::EffectFailed {
                op: op.to_string(),
                message: format!("HTTP poll of {url} timed out after {timeout_sec}s ({detail})"),
            });
        }
        sleep(Duration::from_secs(HTTP_POLL_INTERVAL_SEC));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    fn node_id(ids: &IdGen) -> dsl_kit::NodeId {
        ids.node()
    }

    // -------------------------------------------------------------
    // expand: one variant per lifecycle op (15 total).
    // -------------------------------------------------------------

    #[test]
    fn expand_system_apt_prepends_the_non_interactive_install_flags() {
        let ids = IdGen::new();
        let payload = ProfileNode::SystemApt {
            id: node_id(&ids),
            packages: vec!["git".to_string(), "curl".to_string()],
        };
        let steps = expand(&payload).expect("system_apt expands");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "apt-get".to_string(),
                "install".to_string(),
                "-y".to_string(),
                "git".to_string(),
                "curl".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_comfyui_install_uses_the_default_repo_when_none_is_given() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiInstall {
            id: node_id(&ids),
            ref_name: "v0.1.0".to_string(),
            repo: None,
        };
        let steps = expand(&payload).expect("comfyui_install expands");
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            Step::Sh(argv) => {
                assert_eq!(argv[0], "sh");
                assert_eq!(argv[1], "-c");
                assert!(argv[2]
                    .contains("https://github.com/comfyanonymous/ComfyUI.git /workspace/ComfyUI"));
                assert!(argv[2].contains("checkout v0.1.0"));
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    fn expand_comfyui_install_honours_a_declared_repo() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiInstall {
            id: node_id(&ids),
            ref_name: "main".to_string(),
            repo: Some("fork/ComfyUI".to_string()),
        };
        let steps = expand(&payload).expect("comfyui_install expands");
        match &steps[0] {
            Step::Sh(argv) => {
                assert!(argv[2].contains("https://github.com/fork/ComfyUI.git"));
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    fn expand_python_version_check_emits_probe_plus_advisory_note() {
        let ids = IdGen::new();
        let payload = ProfileNode::PythonVersionCheck {
            id: node_id(&ids),
            want: "3.12".to_string(),
        };
        let steps = expand(&payload).expect("python_version_check expands");
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0],
            Step::Sh(vec!["python3".to_string(), "--version".to_string()])
        );
        match &steps[1] {
            Step::Note(msg) => {
                assert!(msg.contains("want=3.12"));
                assert!(msg.contains("pending AST extension"));
            }
            other => panic!("expected Note, got {other:?}"),
        }
    }

    #[test]
    fn expand_python_deps_selects_venv_pip_when_in_comfy_venv_is_true() {
        let ids = IdGen::new();
        let payload = ProfileNode::PythonDeps {
            id: node_id(&ids),
            deps: vec!["torch".to_string(), "vllm".to_string()],
            in_comfy_venv: true,
        };
        let steps = expand(&payload).expect("python_deps expands");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "/workspace/ComfyUI/venv/bin/pip".to_string(),
                "install".to_string(),
                "torch".to_string(),
                "vllm".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_python_deps_falls_back_to_system_pip_outside_the_venv() {
        let ids = IdGen::new();
        let payload = ProfileNode::PythonDeps {
            id: node_id(&ids),
            deps: vec!["ruff".to_string()],
            in_comfy_venv: false,
        };
        let steps = expand(&payload).expect("python_deps expands");
        match &steps[0] {
            Step::Sh(argv) => assert_eq!(argv[0], "pip"),
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    fn expand_custom_nodes_fans_out_clone_ref_and_pip_per_declared_flag() {
        let ids = IdGen::new();
        let payload = ProfileNode::CustomNodes {
            id: node_id(&ids),
            nodes_json: r#"[
                {"name":"only-clone","repo":"a/b"},
                {"name":"with-ref","repo":"c/d","ref":"v2"},
                {"name":"with-pip","repo":"e/f","pip":true},
                {"name":"full","repo":"g/h","ref":"main","pip":true}
            ]"#
            .to_string(),
        };
        let steps = expand(&payload).expect("custom_nodes expands");
        // only-clone: 1, with-ref: 2, with-pip: 2, full: 3 → 8 steps.
        assert_eq!(steps.len(), 8);
        assert!(matches!(&steps[0], Step::Sh(a) if a[2] == "https://github.com/a/b.git"));
        assert!(matches!(&steps[1], Step::Sh(a) if a[2] == "https://github.com/c/d.git"));
        assert!(matches!(
            &steps[2],
            Step::Sh(a) if a[0] == "git" && a[3] == "checkout" && a[4] == "v2"
        ));
        assert!(matches!(
            &steps[4],
            Step::Sh(a) if a[0] == "/workspace/ComfyUI/venv/bin/pip"
        ));
        assert!(matches!(
            &steps[7],
            Step::Sh(a) if a[0] == "/workspace/ComfyUI/venv/bin/pip"
                && a[3] == "/workspace/ComfyUI/custom_nodes/full/requirements.txt"
        ));
    }

    #[test]
    fn expand_custom_nodes_returns_effect_failed_on_malformed_json() {
        let ids = IdGen::new();
        let payload = ProfileNode::CustomNodes {
            id: node_id(&ids),
            nodes_json: "not-json".to_string(),
        };
        let err = expand(&payload).expect_err("malformed JSON must fail");
        match err {
            ExecError::EffectFailed { op, message } => {
                assert_eq!(op, "custom_nodes");
                assert!(message.contains("nodes_json parse"));
            }
            other => panic!("expected EffectFailed, got {other:?}"),
        }
    }

    #[test]
    fn expand_sync_pull_maps_an_https_source_to_a_transfer_step() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "https://example.com/m.bin".to_string(),
            dst: "/workspace/m.bin".to_string(),
            env: Default::default(),
            revision: None,
        };
        let steps = expand(&payload).expect("sync_pull expands");
        assert_eq!(
            steps,
            vec![Step::Transfer {
                src: "https://example.com/m.bin".to_string(),
                dst: "/workspace/m.bin".to_string(),
            }]
        );
    }

    #[test]
    fn expand_sync_pull_rejects_a_public_b2_source_without_env_as_unsupported() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "b2://bucket/model.safetensors".to_string(),
            dst: "/workspace/model.safetensors".to_string(),
            env: Default::default(),
            revision: None,
        };
        let err = expand(&payload).expect_err("public b2:// (no env) must be unsupported");
        match err {
            ExecError::Unsupported(msg) => {
                assert!(msg.contains("net.transfer bridge") && msg.contains("not implemented"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn expand_sync_pull_b2_with_env_routes_to_the_native_cli() {
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert(
            "B2_APPLICATION_KEY".to_string(),
            ProfileNode::EnvSecret {
                id: node_id(&ids),
                name: "B2_APPLICATION_KEY".to_string(),
            },
        );
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "b2://my-bucket/models/model.bin".to_string(),
            dst: "/workspace/model.bin".to_string(),
            env,
            revision: None,
        };
        let steps = expand(&payload).expect("b2 + env expands to a CLI step");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "b2".to_string(),
                "download-file-by-name".to_string(),
                "my-bucket".to_string(),
                "models/model.bin".to_string(),
                "/workspace/model.bin".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_sync_pull_hf_with_env_degrades_to_a_deferred_note() {
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert(
            "HF_TOKEN".to_string(),
            ProfileNode::EnvSecret {
                id: node_id(&ids),
                name: "HF_TOKEN".to_string(),
            },
        );
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "hf://owner/repo/file.bin".to_string(),
            dst: "/workspace/file.bin".to_string(),
            env,
            revision: None,
        };
        let steps = expand(&payload).expect("hf + env degrades to a note, not an error");
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            Step::Note(msg) => {
                assert!(
                    msg.contains("directory") && msg.contains("unconfirmed"),
                    "{msg}"
                );
            }
            other => panic!("expected a deferred Note, got {other:?}"),
        }
    }

    #[test]
    fn expand_sync_pull_https_with_env_stays_a_plain_transfer() {
        let ids = IdGen::new();
        let mut env = BTreeMap::new();
        env.insert(
            "SOME_VAR".to_string(),
            ProfileNode::EnvLiteral {
                id: node_id(&ids),
                value: "x".to_string(),
            },
        );
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "https://example.com/m.bin".to_string(),
            dst: "/workspace/m.bin".to_string(),
            env,
            revision: None,
        };
        let steps = expand(&payload).expect("https + env stays on the plain download path");
        assert_eq!(
            steps,
            vec![Step::Transfer {
                src: "https://example.com/m.bin".to_string(),
                dst: "/workspace/m.bin".to_string(),
            }]
        );
    }

    #[test]
    fn expand_sync_push_records_a_marker_note() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "https://example.com/out.bin".to_string(),
        };
        let steps = expand(&payload).expect("sync_push expands");
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            Step::Note(msg) => {
                assert!(msg.contains("marker only"));
                assert!(msg.contains("not executed during apply"));
            }
            other => panic!("expected Note, got {other:?}"),
        }
    }

    #[test]
    fn expand_staging_push_b2_dst_builds_the_upload_argv() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "b2://bucket/out/out.bin".to_string(),
            env: Default::default(),
            revision: None,
        };
        let steps = expand(&payload).expect("b2 staging upload expands to a CLI step");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "b2".to_string(),
                "upload-file".to_string(),
                "bucket".to_string(),
                "/workspace/out.bin".to_string(),
                "out/out.bin".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_staging_push_hf_dst_builds_upload_argv_with_revision_and_path_in_repo() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo/artifact.bin".to_string(),
            env: Default::default(),
            revision: Some("main".to_string()),
        };
        let steps = expand(&payload).expect("hf staging upload expands to a CLI step");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "huggingface-cli".to_string(),
                "upload".to_string(),
                "owner/repo".to_string(),
                "/workspace/out.bin".to_string(),
                "artifact.bin".to_string(),
                "--revision".to_string(),
                "main".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_staging_push_hf_url_revision_wins_over_opts_revision() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo@urlrev/artifact.bin".to_string(),
            env: Default::default(),
            revision: Some("optsrev".to_string()),
        };
        let steps = expand(&payload).expect("hf staging upload expands");
        match &steps[0] {
            Step::Sh(argv) => {
                assert_eq!(argv[2], "owner/repo");
                // The URL-carried @urlrev wins over the opts revision.
                assert_eq!(argv.last().map(String::as_str), Some("urlrev"));
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    fn expand_staging_push_https_dst_is_unsupported() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "https://example.com/out.bin".to_string(),
            env: Default::default(),
            revision: None,
        };
        let err = expand(&payload).expect_err("https upload must be unsupported");
        match err {
            ExecError::Unsupported(msg) => {
                assert!(
                    msg.contains("HTTP PUT") && msg.contains("not implemented"),
                    "{msg}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn expand_models_composes_the_target_path_from_subdir_and_dst() {
        let ids = IdGen::new();
        let payload = ProfileNode::Models {
            id: node_id(&ids),
            models_json: r#"[
                {"src":"https://ex/a.bin","dst":"a.bin","subdir":"lora"},
                {"src":"https://ex/b.bin","name":"b.bin","kind":"vae"},
                {"src":"https://ex/c.bin","dst":"c.bin"}
            ]"#
            .to_string(),
        };
        let steps = expand(&payload).expect("models expands");
        assert_eq!(
            steps,
            vec![
                Step::Transfer {
                    src: "https://ex/a.bin".to_string(),
                    dst: "/workspace/ComfyUI/models/lora/a.bin".to_string(),
                },
                Step::Transfer {
                    src: "https://ex/b.bin".to_string(),
                    dst: "/workspace/ComfyUI/models/vae/b.bin".to_string(),
                },
                Step::Transfer {
                    src: "https://ex/c.bin".to_string(),
                    dst: "/workspace/ComfyUI/models/checkpoints/c.bin".to_string(),
                },
            ]
        );
    }

    #[test]
    fn expand_models_returns_effect_failed_on_malformed_json() {
        let ids = IdGen::new();
        let payload = ProfileNode::Models {
            id: node_id(&ids),
            models_json: "{not json".to_string(),
        };
        let err = expand(&payload).expect_err("malformed JSON must fail");
        match err {
            ExecError::EffectFailed { op, .. } => assert_eq!(op, "models"),
            other => panic!("expected EffectFailed, got {other:?}"),
        }
    }

    #[test]
    fn expand_llm_models_builds_the_huggingface_cli_argv() {
        let ids = IdGen::new();
        let payload = ProfileNode::LlmModels {
            id: node_id(&ids),
            models_json: r#"[
                {"src":"hf://owner/repo"},
                {"src":"hf://owner/repo@abc123","dst_dir":"/models/x/"}
            ]"#
            .to_string(),
        };
        let steps = expand(&payload).expect("llm_models expands");
        assert_eq!(
            steps[0],
            Step::Sh(vec![
                "huggingface-cli".to_string(),
                "download".to_string(),
                "owner/repo".to_string(),
                "--local-dir".to_string(),
                "/tmp/".to_string(),
            ])
        );
        assert_eq!(
            steps[1],
            Step::Sh(vec![
                "huggingface-cli".to_string(),
                "download".to_string(),
                "owner/repo".to_string(),
                "--local-dir".to_string(),
                "/models/x/".to_string(),
                "--revision".to_string(),
                "abc123".to_string(),
            ])
        );
    }

    #[test]
    fn expand_llm_models_rejects_a_non_hf_source() {
        let ids = IdGen::new();
        let payload = ProfileNode::LlmModels {
            id: node_id(&ids),
            models_json: r#"[{"src":"https://example.com/model"}]"#.to_string(),
        };
        let err = expand(&payload).expect_err("non-hf src must fail");
        match err {
            ExecError::EffectFailed { op, message } => {
                assert_eq!(op, "llm_models");
                assert!(message.contains("must be an hf:// URI"));
            }
            other => panic!("expected EffectFailed, got {other:?}"),
        }
    }

    #[test]
    fn expand_llm_models_returns_effect_failed_on_malformed_json() {
        let ids = IdGen::new();
        let payload = ProfileNode::LlmModels {
            id: node_id(&ids),
            models_json: "not-json".to_string(),
        };
        let err = expand(&payload).expect_err("malformed JSON must fail");
        match err {
            ExecError::EffectFailed { op, .. } => assert_eq!(op, "llm_models"),
            other => panic!("expected EffectFailed, got {other:?}"),
        }
    }

    #[test]
    fn expand_post_install_wraps_the_script_in_sh_c() {
        let ids = IdGen::new();
        let payload = ProfileNode::PostInstall {
            id: node_id(&ids),
            script: "echo done".to_string(),
        };
        let steps = expand(&payload).expect("post_install expands");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo done".to_string(),
            ])]
        );
    }

    #[test]
    fn expand_comfyui_restart_emits_a_pending_note() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiRestart {
            id: node_id(&ids),
            port: 8188,
        };
        let steps = expand(&payload).expect("comfyui_restart expands");
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            Step::Note(msg) => {
                assert!(msg.contains("port=8188"));
                assert!(msg.contains("extra_args") && msg.contains("out of scope"));
            }
            other => panic!("expected Note, got {other:?}"),
        }
    }

    #[test]
    fn expand_comfyui_health_polls_the_local_port() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiHealth {
            id: node_id(&ids),
            port: 8188,
        };
        let steps = expand(&payload).expect("comfyui_health expands");
        assert_eq!(
            steps,
            vec![Step::HttpPoll {
                url: "http://127.0.0.1:8188/".to_string(),
                timeout_sec: HTTP_POLL_TIMEOUT_SEC,
            }]
        );
    }

    #[test]
    fn expand_service_start_emits_a_pending_note() {
        let ids = IdGen::new();
        let payload = ProfileNode::ServiceStart {
            id: node_id(&ids),
            name: "llm".to_string(),
            platform_kind: "vllm".to_string(),
        };
        let steps = expand(&payload).expect("service_start expands");
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            Step::Note(msg) => {
                assert!(msg.contains("name=llm"));
                assert!(msg.contains("platform_kind=vllm"));
                assert!(msg.contains("pending AST extension"));
            }
            other => panic!("expected Note, got {other:?}"),
        }
    }

    #[test]
    fn expand_service_ready_polls_the_declared_check_url() {
        let ids = IdGen::new();
        let payload = ProfileNode::ServiceReady {
            id: node_id(&ids),
            name: "llm".to_string(),
            check_url: "http://127.0.0.1:9000/health".to_string(),
        };
        let steps = expand(&payload).expect("service_ready expands");
        assert_eq!(
            steps,
            vec![Step::HttpPoll {
                url: "http://127.0.0.1:9000/health".to_string(),
                timeout_sec: HTTP_POLL_TIMEOUT_SEC,
            }]
        );
    }

    #[test]
    fn expand_rejects_a_non_lifecycle_node() {
        let ids = IdGen::new();
        let payload = ProfileNode::ShExec {
            id: node_id(&ids),
            argv: vec!["ls".to_string()],
            env: Default::default(),
        };
        let err = expand(&payload).expect_err("ShExec is not a lifecycle payload");
        assert!(matches!(
            err,
            ExecError::PayloadVariant {
                expected: "lifecycle",
                ..
            }
        ));
    }

    #[test]
    fn render_dry_labels_each_step_shape() {
        let no_env = BTreeMap::new();
        assert_eq!(
            render_dry(&Step::Sh(vec!["ls".into()]), &no_env),
            "sh argv=[\"ls\"]"
        );
        assert!(render_dry(
            &Step::Transfer {
                src: "s".into(),
                dst: "d".into()
            },
            &no_env
        )
        .starts_with("transfer src=s dst=d"));
        assert!(render_dry(
            &Step::HttpPoll {
                url: "u".into(),
                timeout_sec: 5
            },
            &no_env
        )
        .starts_with("http_poll url=u timeout=5s"));
        assert!(render_dry(&Step::Note("n".into()), &no_env).starts_with("note "));
    }

    #[test]
    fn render_dry_shows_env_keys_but_not_values_for_a_sh_step() {
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "super-secret".to_string());
        let rendered = render_dry(&Step::Sh(vec!["huggingface-cli".into()]), &env);
        assert!(
            rendered.contains("env_keys=") && rendered.contains("HF_TOKEN"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("super-secret"),
            "values must be redacted: {rendered}"
        );
    }
}
