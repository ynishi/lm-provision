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
//! spec-02 payload (`PythonDeps` has no `force_reinstall`,
//! `ServiceStart` carries no `port` / `tensor_parallel_size`, and so
//! on). So:
//!
//! - Fields with a defensible built-in default are constant-substituted
//!   (`PythonDeps.in_comfy_venv=false` → the system `pip` on `PATH`;
//!   `ComfyUiInstall.repo=None` → `comfyanonymous/ComfyUI`; a `models`
//!   entry with no `subdir`/`kind` → `checkpoints`).
//! - An op the profile has under-specified expands to a single
//!   [`Step::Note`] recording that fact rather than an invented argv —
//!   a `service.start` on an unrecognised platform, or on `vllm` /
//!   `llamacpp` with no `model`. A guessed command would run on the
//!   operator's pod with the profile's `sh.exec` capability behind it,
//!   and in the report a guess is indistinguishable from a specified
//!   one.
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
//! - `SyncPull` `hf://` src **with a non-empty `env`** → the native
//!   `huggingface-cli download <owner>/<repo> <path> --local-dir <dst>
//!   [--revision <rev>]`. On this route `dst` is the `--local-dir`
//!   target, so the file lands at `<dst>/<path>` and `dst` names a
//!   *directory* — asymmetric with the b2 route, where `dst` is the
//!   destination file path. The asymmetry is hf-cli's (it exposes no
//!   output-file flag) and is recorded in spec 02 §Dispatch routing
//!   rather than papered over with a synthesized rename step.
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
/// Venv-relative python binary, the ComfyUI launch interpreter
/// (spec 02 §Built-in path constants).
const COMFYUI_VENV_PY: &str = "/workspace/ComfyUI/venv/bin/python";
/// ComfyUI entry point (spec 02 §Built-in path constants).
const COMFYUI_MAIN_PY: &str = "/workspace/ComfyUI/main.py";
/// ComfyUI launch log (spec 02 §Built-in path constants).
const COMFYUI_LOG_PATH: &str = "/tmp/comfyui.log";
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
        ProfileNode::SyncPull {
            src,
            dst,
            env,
            revision,
            ..
        } => expand_sync_pull(src, dst, env, revision.as_deref()),
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
        ProfileNode::ComfyUiRestart {
            port, extra_args, ..
        } => Ok(expand_comfyui_restart(*port, extra_args)),
        ProfileNode::ComfyUiHealth { port, .. } => Ok(vec![Step::HttpPoll {
            // `/object_info` is the API readiness endpoint. `/` serves
            // the UI's HTML and answers 200 before the backend can take
            // an API call, so polling it reports ready too early.
            url: format!("http://127.0.0.1:{port}/object_info"),
            timeout_sec: HTTP_POLL_TIMEOUT_SEC,
        }]),
        ProfileNode::ServiceStart {
            name,
            platform_kind,
            model,
            dtype,
            extra_args,
            ..
        } => Ok(expand_service_start(
            name,
            platform_kind,
            model.as_deref(),
            dtype.as_deref(),
            extra_args,
        )),
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

/// `python3 -c '<assert>'` — exits non-zero when the running
/// interpreter's version does not start with `want`, printing the
/// actual `sys.version` so the mismatch is visible in the report's
/// captured stderr.
///
/// Emitting `python3 --version` and letting the operator compare was
/// the earlier shape; it called itself advisory while checking nothing,
/// so a version mismatch passed silently.
fn expand_python_version_check(want: &str) -> Vec<Step> {
    let script = format!(
        "import sys; assert sys.version.startswith(\"{want}\"), \
         \"python version mismatch: want {want}, got \" + sys.version"
    );
    vec![Step::Sh(vec![
        "python3".to_string(),
        "-c".to_string(),
        script,
    ])]
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
    revision: Option<&str>,
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
    if let Some(rest) = src.strip_prefix("hf://") {
        let (owner, repo, url_rev, path_in_repo) = parse_hf_uri(rest, "sync_pull", src)?;
        // A download needs the file path inside the repo — an
        // `hf://<owner>/<repo>` with no trailing path names a repo, not
        // a file (that is `llm_models`' snapshot shape).
        let Some(path_in_repo) = path_in_repo else {
            return Err(ExecError::EffectFailed {
                op: "sync_pull".to_string(),
                message: format!("hf:// download URI is missing the file path segment: {src}"),
            });
        };
        // The URL-carried revision wins over the payload's (spec 02
        // §Dispatch routing: "a URL-carried revision wins over
        // opts.revision") — the URL is the more specific address.
        let rev = url_rev.or_else(|| revision.map(str::to_string));
        let mut argv = vec![
            "huggingface-cli".to_string(),
            "download".to_string(),
            format!("{owner}/{repo}"),
            path_in_repo,
            // `dst` is the --local-dir target: hf-cli lands the file at
            // `<dst>/<path_in_repo>`, so on this route `dst` names a
            // *directory*, asymmetric with the b2 route's file path.
            // Spec 02 §Dispatch routing records the asymmetry.
            "--local-dir".to_string(),
            dst.to_string(),
        ];
        if let Some(rev) = rev {
            argv.push("--revision".to_string());
            argv.push(rev);
        }
        return Ok(vec![Step::Sh(argv)]);
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

// ---------------------------------------------------------------------
// Spawn-and-poll launches (`comfyui.restart` / `service.start`).
//
// Both background the server with `nohup … &` and return immediately,
// leaving readiness to the poll phase that canonical ordering places
// right after them (`comfyui.health` / `service.ready`). That split is
// deliberate, not an omission: apply is normally driven over SSH, where
// a connection held open for the life of a server process is the thing
// most likely to break. Spawning detached and asking again over a fresh
// call survives a dropped connection; a foreground launch does not.
//
// Consequence to keep in mind when reading a report: the launch step
// only reports whether the *spawn* was accepted. Whether the server
// came up is the poll step's verdict.
// ---------------------------------------------------------------------

/// The `nohup <argv…> > <log> 2>&1 &` command text shared by both
/// launch kinds. Returned as text (not a [`Step`]) so a caller can
/// prefix it — `comfyui.restart` needs a `cd` in the same shell.
///
/// The redirect is load-bearing, not cosmetic. [`effects::sh_exec`]
/// uses `Command::output()`, which reads the child's stdout / stderr
/// pipes until EOF; a backgrounded grandchild that inherited those
/// pipes would hold them open and hang apply for as long as the server
/// runs. Sending its output to a file closes the inherited ends, so
/// `sh` exits and `output()` returns at once. Do not "tidy away" the
/// redirect.
fn spawn_detached_command(argv: &[String], log_path: &str) -> String {
    format!("nohup {} > {log_path} 2>&1 &", argv.join(" "))
}

/// Wrap a command line in `sh -c` so the shell — not `Command` —
/// parses the redirect and the `&`.
fn sh_c(command: String) -> Step {
    Step::Sh(vec!["sh".to_string(), "-c".to_string(), command])
}

fn expand_comfyui_restart(port: u16, extra_args: &[String]) -> Vec<Step> {
    let mut argv = vec![
        COMFYUI_VENV_PY.to_string(),
        COMFYUI_MAIN_PY.to_string(),
        "--port".to_string(),
        port.to_string(),
    ];
    argv.extend(extra_args.iter().cloned());
    // `cd` first: ComfyUI resolves `models/` / `custom_nodes/` relative
    // to its working directory.
    vec![sh_c(format!(
        "cd {COMFYUI_INSTALL_DIR} && {}",
        spawn_detached_command(&argv, COMFYUI_LOG_PATH)
    ))]
}

/// Per-platform launch invocation. An unrecognised platform expands to
/// a note rather than a guessed argv — running an invented command on
/// the operator's pod under the profile's `sh.exec` capability is worse
/// than reporting that nothing was launched.
///
/// `vllm` / `llamacpp` also note-out when no `model` is declared: both
/// take the model as a required `--model` value, and emitting the flag
/// with an empty value makes the *next* token the model, launching
/// something other than what the profile asked for.
///
/// No `--port` / `--tensor-parallel-size` is synthesized. The AST does
/// not carry them (see [`ProfileNode::ServiceStart`] on the dsl-kit
/// `Option<u16>` gap), and the values the predecessor passed by default
/// — 8000 for `vllm`, 8080 for `llamacpp` — are each platform's own
/// default, so omitting the flag lands on the same port. A profile that
/// wants another one declares it in `extra_args`, where it appears
/// exactly once instead of overriding a flag this function already
/// emitted.
fn expand_service_start(
    name: &str,
    platform_kind: &str,
    model: Option<&str>,
    dtype: Option<&str>,
    extra_args: &[String],
) -> Vec<Step> {
    let log_path = format!("/tmp/{name}.log");
    let argv = match platform_kind {
        "vllm" => {
            let Some(model) = model else {
                return vec![missing_model_note(name, platform_kind)];
            };
            let mut argv = vec![
                "python".to_string(),
                "-m".to_string(),
                "vllm.entrypoints.openai.api_server".to_string(),
                "--model".to_string(),
                model.to_string(),
            ];
            if let Some(dtype) = dtype {
                argv.push("--dtype".to_string());
                argv.push(dtype.to_string());
            }
            argv.extend(extra_args.iter().cloned());
            argv
        }
        // Ollama serves on 11434 and takes its bind address from
        // `OLLAMA_HOST`, so it has no port / model flag to pass.
        "ollama" => vec!["ollama".to_string(), "serve".to_string()],
        "llamacpp" => {
            let Some(model) = model else {
                return vec![missing_model_note(name, platform_kind)];
            };
            let mut argv = vec![
                "llama-server".to_string(),
                "--model".to_string(),
                model.to_string(),
            ];
            argv.extend(extra_args.iter().cloned());
            argv
        }
        other => {
            return vec![Step::Note(format!(
                "service_start name={name} platform_kind={other}: no launch \
                 invocation — spec 02 specifies vllm / ollama / llamacpp"
            ))]
        }
    };
    vec![sh_c(spawn_detached_command(&argv, &log_path))]
}

fn missing_model_note(name: &str, platform_kind: &str) -> Step {
    Step::Note(format!(
        "service_start name={name} platform_kind={platform_kind}: no launch \
         invocation — the platform requires `model` and the profile declares none"
    ))
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

/// What executing one [`Step`] observed.
///
/// The `summary` fragment is the trace-log text the registry joins per
/// op (unchanged from when this was the whole return value); the
/// remaining fields are the observations the apply report's per-sub-step
/// entry carries (spec 09 §Apply report). Before this type existed the
/// exec layer discarded them, so a lifecycle sub-step's report entry
/// showed only its declared inputs even in real mode — a regression
/// against the predecessor Lua report, which carried
/// `status` / `stdout` / `stderr` / `bytes` per executed op.
///
/// A *failing* step carries the same observations, through
/// [`StepFailure::observed`] — the error and what was seen before it
/// travel together rather than the observation collapsing into the
/// error's message text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepResult {
    /// Trace-log summary fragment.
    pub summary: String,
    /// Process exit code / HTTP status / `0` for an effectless step.
    pub status: i64,
    /// Captured stdout tail (`sh` steps).
    pub stdout: Option<String>,
    /// Captured stderr tail (`sh` steps).
    pub stderr: Option<String>,
    /// Bytes transferred (`transfer` steps).
    pub bytes: Option<u64>,
    /// Destination actually written (`transfer` steps).
    pub dst: Option<String>,
}

impl StepResult {
    /// A result carrying only a trace summary (effectless steps).
    fn summary_only(summary: String) -> Self {
        Self {
            summary,
            ..Self::default()
        }
    }
}

/// A step that failed, plus whatever it managed to observe first.
///
/// A non-zero `sh` exit is the motivating case: the exit code and the
/// captured stdout / stderr are real observations, but they used to
/// reach the caller only quoted inside [`ExecError::EffectFailed`]'s
/// message. The registry copies [`observed`](Self::observed) onto the
/// failing report entry before marking it failed, so a failing
/// lifecycle sub-step is as informative as a failing direct op
/// (spec 09 §Apply report).
///
/// A failure with nothing to report (a payload error, a transfer the
/// effect layer rejected outright) converts from its [`ExecError`] and
/// leaves `observed` at its default — the registry's `status = -1`
/// then stands.
#[derive(Debug)]
pub struct StepFailure {
    /// The error to surface to the engine.
    pub error: ExecError,
    /// What was observed up to the point of failure. Default when the
    /// failure happened before anything could be observed.
    ///
    /// Boxed so the `Err` variant of every `execute_*` signature stays
    /// small (`clippy::result_large_err`); a failure is the rare path,
    /// so the allocation costs nothing on the hot one.
    pub observed: Box<StepResult>,
}

impl StepFailure {
    /// A failure that observed something before it happened.
    fn observing(error: ExecError, observed: StepResult) -> Self {
        Self {
            error,
            observed: Box::new(observed),
        }
    }
}

impl From<ExecError> for StepFailure {
    fn from(error: ExecError) -> Self {
        Self {
            error,
            observed: Box::default(),
        }
    }
}

/// Execute one step for real, returning what it observed.
///
/// `op` is the registry op name — used only to label the
/// [`ExecError::EffectFailed`] surface, so the engine's node-located
/// error carries the op that ran. `env` is the phase's resolved
/// env-injection map, injected into a [`Step::Sh`] child process.
///
/// On failure the error travels with whatever the step observed first
/// ([`StepFailure`]); callers that only need the error take
/// [`StepFailure::error`].
pub fn execute_step(
    step: &Step,
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<StepResult, StepFailure> {
    match step {
        Step::Sh(argv) => execute_sh(argv, op, env),
        Step::Transfer { src, dst } => {
            let outcome = effects::transfer(src, dst)?;
            Ok(StepResult {
                summary: format!(
                    "transfer src={src} dst={} bytes={}",
                    outcome.dst, outcome.bytes
                ),
                bytes: Some(outcome.bytes),
                dst: Some(outcome.dst),
                ..StepResult::default()
            })
        }
        Step::HttpPoll { url, timeout_sec } => execute_http_poll(url, *timeout_sec, op),
        Step::Note(message) => Ok(StepResult::summary_only(format!("note \"{message}\""))),
    }
}

fn execute_sh(
    argv: &[String],
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<StepResult, StepFailure> {
    let outcome = effects::sh_exec(argv, &effects::ShOpts::new(env.clone()))?;
    if outcome.exit_code != 0 {
        let error = ExecError::EffectFailed {
            op: op.to_string(),
            message: format!(
                "sh {argv:?} failed: exit {} stderr={:?}",
                outcome.exit_code, outcome.stderr_tail
            ),
        };
        // The exit code and captured tails are genuine observations —
        // they ride along instead of surviving only as quoted text
        // inside the error message.
        let observed = StepResult {
            summary: format!(
                "sh exit={} stdout={:?}",
                outcome.exit_code, outcome.stdout_tail
            ),
            status: i64::from(outcome.exit_code),
            stdout: Some(outcome.stdout_tail),
            stderr: Some(outcome.stderr_tail),
            ..StepResult::default()
        };
        return Err(StepFailure::observing(error, observed));
    }
    Ok(StepResult {
        summary: format!(
            "sh exit={} stdout={:?}",
            outcome.exit_code, outcome.stdout_tail
        ),
        status: i64::from(outcome.exit_code),
        stdout: Some(outcome.stdout_tail),
        stderr: Some(outcome.stderr_tail),
        ..StepResult::default()
    })
}

fn execute_http_poll(url: &str, timeout_sec: u64, op: &str) -> Result<StepResult, StepFailure> {
    let deadline = Instant::now() + Duration::from_secs(timeout_sec);
    let mut last_status: Option<u16> = None;
    let mut last_err: Option<String> = None;
    loop {
        match effects::http_get(url) {
            Ok(outcome) => {
                if (200..300).contains(&outcome.status) {
                    return Ok(StepResult {
                        summary: format!("http_poll url={url} status={}", outcome.status),
                        status: i64::from(outcome.status),
                        ..StepResult::default()
                    });
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
            }
            .into());
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

    /// The check must *fail* on a mismatch, not print a version and
    /// leave the comparison to the reader.
    #[test]
    fn expand_python_version_check_asserts_the_wanted_version() {
        let ids = IdGen::new();
        let payload = ProfileNode::PythonVersionCheck {
            id: node_id(&ids),
            want: "3.12".to_string(),
        };
        let steps = expand(&payload).expect("python_version_check expands");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "python3".to_string(),
                "-c".to_string(),
                "import sys; assert sys.version.startswith(\"3.12\"), \
             \"python version mismatch: want 3.12, got \" + sys.version"
                    .to_string(),
            ])]
        );
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

    /// The credential-carrying hf download routes to hf-cli with `dst`
    /// as the `--local-dir` target (the file lands at
    /// `<dst>/<path_in_repo>`, spec 02 §Dispatch routing).
    #[test]
    fn expand_sync_pull_hf_with_env_routes_to_the_native_cli() {
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
            src: "hf://my-org/private-lora/weights/v1.safetensors".to_string(),
            dst: "/workspace/loras".to_string(),
            env,
            revision: None,
        };
        let steps = expand(&payload).expect("hf + env expands to a CLI step");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "huggingface-cli".to_string(),
                "download".to_string(),
                "my-org/private-lora".to_string(),
                "weights/v1.safetensors".to_string(),
                "--local-dir".to_string(),
                "/workspace/loras".to_string(),
            ])]
        );
    }

    /// A URL-carried `@<rev>` wins over the payload's `revision`
    /// (spec 02 §Dispatch routing: the URL is the more specific
    /// address).
    #[test]
    fn expand_sync_pull_hf_prefers_the_url_revision_over_the_payload_one() {
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
            src: "hf://owner/repo@v2.0/weights/model.bin".to_string(),
            dst: "/workspace/models".to_string(),
            env,
            revision: Some("ignored-payload-rev".to_string()),
        };
        let steps = expand(&payload).expect("hf + env + @rev expands");
        assert_eq!(
            steps,
            vec![Step::Sh(vec![
                "huggingface-cli".to_string(),
                "download".to_string(),
                "owner/repo".to_string(),
                "weights/model.bin".to_string(),
                "--local-dir".to_string(),
                "/workspace/models".to_string(),
                "--revision".to_string(),
                "v2.0".to_string(),
            ])]
        );
    }

    /// With no `@<rev>` in the URL the payload's `revision` is used.
    #[test]
    fn expand_sync_pull_hf_falls_back_to_the_payload_revision() {
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
            src: "hf://owner/repo/model.bin".to_string(),
            dst: "/workspace/models".to_string(),
            env,
            revision: Some("abc123".to_string()),
        };
        let steps = expand(&payload).expect("hf + env + payload revision expands");
        match &steps[0] {
            Step::Sh(argv) => {
                assert_eq!(argv[argv.len() - 2..], ["--revision", "abc123"]);
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    /// `hf://<owner>/<repo>` with no trailing path names a repo, not a
    /// file — that is `llm_models`' snapshot shape, not a `sync.pull`.
    #[test]
    fn expand_sync_pull_hf_without_a_file_path_is_an_error() {
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
            src: "hf://owner/repo".to_string(),
            dst: "/workspace/models".to_string(),
            env,
            revision: None,
        };
        let err = expand(&payload).expect_err("a repo-only hf:// URI must fail");
        assert!(
            err.to_string().contains("missing the file path segment"),
            "{err}"
        );
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

    // -------------------------------------------------------------
    // Spawn-and-poll launches. The expected argv are the predecessor's
    // literals (`pod-setup/dispatch.lua`), which the
    // production pod-setup script uses verbatim — they are the
    // specification here, so the tests pin them exactly rather than
    // asserting on fragments.
    // -------------------------------------------------------------

    fn sh_command(step: &Step) -> &str {
        match step {
            Step::Sh(argv) => {
                assert_eq!(argv[..2], ["sh".to_string(), "-c".to_string()]);
                &argv[2]
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    fn expand_comfyui_restart_backgrounds_the_launch_from_the_install_dir() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiRestart {
            id: node_id(&ids),
            port: 8188,
            extra_args: Vec::new(),
        };
        let steps = expand(&payload).expect("comfyui_restart expands");
        assert_eq!(steps.len(), 1);
        assert_eq!(
            sh_command(&steps[0]),
            "cd /workspace/ComfyUI && nohup /workspace/ComfyUI/venv/bin/python \
             /workspace/ComfyUI/main.py --port 8188 > /tmp/comfyui.log 2>&1 &"
        );
    }

    /// Declared `extra_args` land as argv positions after `--port`.
    #[test]
    fn expand_comfyui_restart_appends_declared_extra_args() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiRestart {
            id: node_id(&ids),
            port: 8188,
            extra_args: vec!["--listen".to_string(), "--highvram".to_string()],
        };
        let steps = expand(&payload).expect("comfyui_restart expands");
        assert_eq!(
            sh_command(&steps[0]),
            "cd /workspace/ComfyUI && nohup /workspace/ComfyUI/venv/bin/python \
             /workspace/ComfyUI/main.py --port 8188 --listen --highvram \
             > /tmp/comfyui.log 2>&1 &"
        );
    }

    /// The redirect keeps `Command::output()` from blocking on pipes the
    /// backgrounded server would otherwise hold open for its lifetime.
    #[test]
    fn a_backgrounded_launch_always_redirects_its_output_to_a_file() {
        let ids = IdGen::new();
        let restart = expand(&ProfileNode::ComfyUiRestart {
            id: node_id(&ids),
            port: 8188,
            extra_args: Vec::new(),
        })
        .expect("comfyui_restart expands");
        let start = expand(&ProfileNode::ServiceStart {
            id: node_id(&ids),
            name: "llm".to_string(),
            platform_kind: "ollama".to_string(),
            model: None,
            dtype: None,
            extra_args: Vec::new(),
        })
        .expect("service_start expands");

        for step in [&restart[0], &start[0]] {
            let command = sh_command(step);
            assert!(
                command.contains("2>&1 &") && command.contains("> /tmp/"),
                "a detached launch must redirect to a file: {command}"
            );
        }
    }

    #[test]
    fn expand_comfyui_health_polls_the_api_endpoint_not_the_ui_root() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiHealth {
            id: node_id(&ids),
            port: 8188,
        };
        let steps = expand(&payload).expect("comfyui_health expands");
        assert_eq!(
            steps,
            vec![Step::HttpPoll {
                // `/` answers 200 from the UI before the API is usable.
                url: "http://127.0.0.1:8188/object_info".to_string(),
                timeout_sec: HTTP_POLL_TIMEOUT_SEC,
            }]
        );
    }

    fn service_start(
        ids: &IdGen,
        platform_kind: &str,
        model: Option<&str>,
        dtype: Option<&str>,
        extra_args: &[&str],
    ) -> Vec<Step> {
        let payload = ProfileNode::ServiceStart {
            id: node_id(ids),
            name: "llm".to_string(),
            platform_kind: platform_kind.to_string(),
            model: model.map(str::to_string),
            dtype: dtype.map(str::to_string),
            extra_args: extra_args.iter().map(|s| s.to_string()).collect(),
        };
        expand(&payload).expect("service_start expands")
    }

    #[test]
    fn expand_service_start_vllm_uses_the_openai_api_server_entry_point() {
        let ids = IdGen::new();
        let steps = service_start(&ids, "vllm", Some("meta-llama/Llama-3-8B"), None, &[]);
        assert_eq!(
            sh_command(&steps[0]),
            "nohup python -m vllm.entrypoints.openai.api_server \
             --model meta-llama/Llama-3-8B > /tmp/llm.log 2>&1 &"
        );
    }

    /// `--port` / `--tensor-parallel-size` are the author's to place in
    /// `extra_args`; nothing synthesizes them, so they appear exactly
    /// once and after the flags this function does emit.
    #[test]
    fn expand_service_start_vllm_appends_declared_knobs_after_dtype() {
        let ids = IdGen::new();
        let steps = service_start(
            &ids,
            "vllm",
            Some("m"),
            Some("bfloat16"),
            &["--port", "9000", "--tensor-parallel-size", "4"],
        );
        assert_eq!(
            sh_command(&steps[0]),
            "nohup python -m vllm.entrypoints.openai.api_server --model m \
             --dtype bfloat16 --port 9000 --tensor-parallel-size 4 \
             > /tmp/llm.log 2>&1 &"
        );
    }

    /// Ollama binds 11434 and reads `OLLAMA_HOST`, so it takes neither
    /// a model nor a port on the command line.
    #[test]
    fn expand_service_start_ollama_just_serves() {
        let ids = IdGen::new();
        let steps = service_start(&ids, "ollama", None, None, &[]);
        assert_eq!(
            sh_command(&steps[0]),
            "nohup ollama serve > /tmp/llm.log 2>&1 &"
        );
    }

    #[test]
    fn expand_service_start_llamacpp_uses_llama_server() {
        let ids = IdGen::new();
        let steps = service_start(&ids, "llamacpp", Some("/models/q4.gguf"), None, &[]);
        assert_eq!(
            sh_command(&steps[0]),
            "nohup llama-server --model /models/q4.gguf > /tmp/llm.log 2>&1 &"
        );
    }

    /// Emitting `--model` with nothing after it would make the next
    /// token the model, launching something the profile never asked
    /// for — so a missing model is reported, not papered over.
    #[test]
    fn expand_service_start_notes_out_when_a_required_model_is_absent() {
        let ids = IdGen::new();
        for platform in ["vllm", "llamacpp"] {
            let steps = service_start(&ids, platform, None, None, &[]);
            match &steps[0] {
                Step::Note(msg) => {
                    assert!(msg.contains("name=llm"), "{msg}");
                    assert!(msg.contains("requires `model`"), "{msg}");
                }
                other => panic!("expected Note for {platform}, got {other:?}"),
            }
        }
    }

    #[test]
    fn expand_service_start_notes_out_an_unspecified_platform() {
        let ids = IdGen::new();
        let steps = service_start(&ids, "tgi", Some("m"), None, &[]);
        match &steps[0] {
            Step::Note(msg) => {
                assert!(msg.contains("platform_kind=tgi"), "{msg}");
                assert!(msg.contains("vllm / ollama / llamacpp"), "{msg}");
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

    // -------------------------------------------------------------
    // execute_step: a failing step carries its partial observation.
    // -------------------------------------------------------------

    #[test]
    fn a_non_zero_sh_exit_carries_its_exit_code_and_captured_output() {
        let step = Step::Sh(vec![
            "sh".into(),
            "-c".into(),
            "echo out-before-failing; echo err-before-failing 1>&2; exit 7".into(),
        ]);
        let failure = execute_step(&step, "post_install", &BTreeMap::new())
            .expect_err("a non-zero exit is a step failure");

        // The error still names the op, as before.
        match &failure.error {
            ExecError::EffectFailed { op, .. } => assert_eq!(op, "post_install"),
            other => panic!("expected EffectFailed, got {other:?}"),
        }
        // …and the observation now rides along in structured form
        // instead of surviving only inside the error message.
        assert_eq!(failure.observed.status, 7);
        assert!(
            failure
                .observed
                .stdout
                .as_deref()
                .is_some_and(|s| s.contains("out-before-failing")),
            "stdout observed before the failure: {:?}",
            failure.observed.stdout
        );
        assert!(
            failure
                .observed
                .stderr
                .as_deref()
                .is_some_and(|s| s.contains("err-before-failing")),
            "stderr observed before the failure: {:?}",
            failure.observed.stderr
        );
    }

    #[test]
    fn a_failure_with_nothing_observed_keeps_the_default_result() {
        let failure: StepFailure = ExecError::EffectFailed {
            op: "models".to_string(),
            message: "malformed payload".to_string(),
        }
        .into();
        assert_eq!(*failure.observed, StepResult::default());
        assert_eq!(failure.observed.status, 0, "the registry substitutes -1");
    }
}
