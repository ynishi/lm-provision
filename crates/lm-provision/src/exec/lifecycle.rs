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
//! spec-02 payload (`PythonDeps` has no `force_reinstall`, and so on).
//! So:
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
//!   `hf download <owner>/<repo> <path> --local-dir <dst>
//!   [--revision <rev>]`. (`hf` superseded `huggingface-cli` — the old
//!   entry point prints a deprecation and exits 1 on current
//!   huggingface_hub, observed live 2026-08-01; the argument shape is
//!   unchanged.) On this route `dst` is the `--local-dir`
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
//!   `hf upload`; an `https://` dst (HTTP PUT) is
//!   [`ExecError::Unsupported`].

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::time::sleep;

use serde::Deserialize;

use super::assert::{self, Done as _};
use super::observe::LocalObserve;
use super::scheme::{self, parse_hf_uri, split_b2_uri};
use super::{effects, ExecError, ExecMode};
use crate::profile_ast::ProfileNode;

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
/// (`hf download --local-dir` target).
const DEFAULT_LLM_MODELS_DST_DIR: &str = "/tmp/";
/// Venv-relative python binary, the ComfyUI launch interpreter
/// (spec 02 §Built-in path constants).
const COMFYUI_VENV_PY: &str = "/workspace/ComfyUI/venv/bin/python";
/// ComfyUI entry point (spec 02 §Built-in path constants).
const COMFYUI_MAIN_PY: &str = "/workspace/ComfyUI/main.py";
/// ComfyUI launch log (spec 02 §Built-in path constants).
const COMFYUI_LOG_PATH: &str = "/tmp/comfyui.log";
/// ComfyUI launch pid file, written by `comfyui.restart` and read by
/// `comfyui.health`'s poll (spec 02 §Built-in path constants).
const COMFYUI_PID_PATH: &str = "/tmp/comfyui.pid";
/// `comfyui.install` default repo when the payload omits `repo`.
const DEFAULT_COMFYUI_REPO: &str = "comfyanonymous/ComfyUI";
/// `comfyui.health` poll deadline when the payload declares no
/// `timeout_sec` (spec 02 `comfyui.health`).
///
/// 180 s matches the predecessor implementation's ComfyUI readiness
/// bound. A cold boot spends that budget before the API answers:
/// ComfyUI-Manager's prestartup script alone took 49.7 s on the pod
/// this was measured on, and model / custom-node scanning follows it.
/// The earlier flat 60 s deadline failed apply on a server that was
/// merely still starting.
const COMFYUI_HEALTH_TIMEOUT_SEC: u64 = 180;
/// `service.ready` poll deadline when the payload declares no
/// `timeout_sec` (spec 02 `service.ready` `check.timeout_sec`).
///
/// 300 s matches the predecessor implementation's `ready_check`
/// default. An inference engine's start-up is dominated by weight
/// loading and CUDA graph capture — a vllm engine init measured ~100 s
/// on the same pod — so the deadline is a multiple of that, not of an
/// HTTP round trip.
const SERVICE_READY_TIMEOUT_SEC: u64 = 300;
/// Poll interval between GETs while waiting for a 2xx.
const HTTP_POLL_INTERVAL_SEC: u64 = 2;
/// Linux procfs root. A running process has a `/proc/<pid>` directory,
/// which is how a poll step decides whether the launch it is waiting
/// for is still alive (§Died-during-wait detection).
const PROC_ROOT: &str = "/proc";
/// Lines of the launch log a died-during-wait / died-immediately
/// failure carries, matching the predecessor's `tail -100`.
const DIED_LOG_TAIL_LINES: usize = 100;

/// One executable step a lifecycle op expands into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Run `argv` via [`effects::sh_exec`]. In real mode a non-zero exit
    /// fails the op.
    Sh(Vec<String>),
    /// Transfer `src` to `dst` via [`effects::transfer`], which reads
    /// the direction off the two schemes: a URL `src` downloads into
    /// the local `dst`, a URL `dst` uploads the local `src`
    /// (chapter 04 §net.transfer).
    Transfer {
        /// Source URL or local path.
        src: String,
        /// Destination local path or URL.
        dst: String,
    },
    /// Poll `url` via [`effects::http_get`] until a 2xx response or
    /// `timeout_sec` elapses.
    HttpPoll {
        /// URL to poll.
        url: String,
        /// Overall poll deadline, in seconds.
        timeout_sec: u64,
        /// Pid file the preceding launch step wrote, when the poll is
        /// waiting on a spawn-and-poll launch. Each iteration re-reads
        /// it to notice a process that died during the wait
        /// (§Died-during-wait detection); `None` disables the check.
        pid_file: Option<String>,
        /// Launch log tailed into a died-during-wait failure, so the
        /// report carries the crash instead of only the pid.
        log_path: Option<String>,
    },
    /// No effect; `message` is preserved in the log so the operator can
    /// tell that an op ran and what it decided.
    Note(String),
}

/// One step, plus what its being finished looks like.
///
/// **The condition sits beside the step rather than inside it**, which
/// is where the second entity put it. While `models` was the only phase
/// deriving one, `done` was a field on [`Step::Transfer`]; `Checkout`
/// gives `comfyui.install` and `custom_nodes` a condition on a
/// [`Step::Sh`], and adding a second field would have meant a third
/// when `Service` reaches [`Step::HttpPoll`] — with the skip written
/// out once per shape each time. Here it is written once, for every
/// shape, in [`execute_step`] and [`dry_run_step`].
///
/// The split is not only convenience. What a step *is* — the capability
/// it demands ([`super::demand::step`]), the audit event it emits, the
/// report fields it declares — is a property of the effect, and every
/// one of those readers still takes a [`Step`]. What being finished
/// looks like is a property of the entity the phase derived, and
/// nothing about it is per-effect: the answer is folded the same way and
/// only `Satisfied` skips, whether the step clones a repository or
/// downloads a weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// The effect to run.
    pub step: Step,
    /// What has to hold for the step to be finished.
    ///
    /// Evaluated before the step runs; an
    /// [`AssertOutcome::Satisfied`](assert::AssertOutcome::Satisfied)
    /// answer skips it (design §3.1: the same predicate, used to skip
    /// rather than to fail). Every other answer — including
    /// `NotChecked` and `CheckFailed` — runs the step, which is the
    /// safe direction.
    ///
    /// `None` is a step whose phase derives no entity: a `sync.pull`
    /// transfer names an arbitrary source and destination, a
    /// `hooks.post_install` runs a script only its author can judge, a
    /// `custom_nodes` pip install puts requirements in a venv — none of
    /// them has a declared identity to check, so they run every time.
    pub done: Option<assert::Assert>,
}

impl PlannedStep {
    /// A step that runs on every apply.
    pub fn always(step: Step) -> Self {
        Self { step, done: None }
    }

    /// A step that is skipped once `done` holds.
    pub fn done_when(step: Step, done: assert::Assert) -> Self {
        Self {
            step,
            done: Some(done),
        }
    }
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
pub fn expand(payload: &ProfileNode) -> Result<Vec<PlannedStep>, ExecError> {
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
        ProfileNode::SyncPush { src, dst, .. } => Ok(vec![PlannedStep::always(Step::Note(
            format!("sync_push src={src} dst={dst}: marker only; not executed during apply"),
        ))]),
        ProfileNode::StagingPush {
            src, dst, revision, ..
        } => expand_staging_push(src, dst, revision.as_deref()),
        ProfileNode::Models { models_json, .. } => expand_models(models_json),
        ProfileNode::LlmModels { models_json, .. } => expand_llm_models(models_json),
        // No `done`: `hooks.post_install` is the spec's sanctioned
        // escape hatch for raw shell, so only its author knows what
        // finishing it looks like — and an author cannot write a
        // condition yet (design §3.4).
        ProfileNode::PostInstall { script, .. } => Ok(vec![PlannedStep::always(Step::Sh(vec![
            "sh".to_string(),
            "-c".to_string(),
            script.clone(),
        ]))]),
        ProfileNode::ComfyUiRestart {
            port, extra_args, ..
        } => Ok(expand_comfyui_restart(*port, extra_args)),
        ProfileNode::ComfyUiHealth {
            port, timeout_sec, ..
        } => Ok(vec![PlannedStep::always(Step::HttpPoll {
            // `/object_info` is the API readiness endpoint. `/` serves
            // the UI's HTML and answers 200 before the backend can take
            // an API call, so polling it reports ready too early.
            url: format!("http://127.0.0.1:{port}/object_info"),
            timeout_sec: poll_timeout(*timeout_sec, COMFYUI_HEALTH_TIMEOUT_SEC),
            // Paired with `comfyui.restart`'s launch, which canonical
            // ordering places directly before this poll.
            pid_file: Some(COMFYUI_PID_PATH.to_string()),
            log_path: Some(COMFYUI_LOG_PATH.to_string()),
        })]),
        ProfileNode::ServiceStart {
            name,
            platform_kind,
            model,
            port,
            dtype,
            tensor_parallel_size,
            extra_args,
            ..
        } => Ok(expand_service_start(
            name,
            platform_kind,
            model.as_deref(),
            *port,
            dtype.as_deref(),
            *tensor_parallel_size,
            extra_args,
        )),
        ProfileNode::ServiceReady {
            name,
            check_url,
            timeout_sec,
            ..
        } => Ok(vec![PlannedStep::always(Step::HttpPoll {
            url: check_url.clone(),
            timeout_sec: poll_timeout(*timeout_sec, SERVICE_READY_TIMEOUT_SEC),
            // Paired with the `service.start` of the same `name`, whose
            // launch wrote these two paths.
            pid_file: Some(service_pid_path(name)),
            log_path: Some(service_log_path(name)),
        })]),
        other => {
            use dsl_kit::DslNode as _;
            Err(ExecError::PayloadVariant {
                node: other.node_id().0,
                expected: "lifecycle",
            })
        }
    }
}

/// The deadline a poll step runs with: the payload's `timeout_sec`
/// when the profile declares one, otherwise the kind's default
/// ([`COMFYUI_HEALTH_TIMEOUT_SEC`] / [`SERVICE_READY_TIMEOUT_SEC`]).
///
/// The declared value is authoritative even when it is shorter than
/// the default — a profile that asks for a fast failure gets one.
fn poll_timeout(declared: Option<u16>, default_sec: u64) -> u64 {
    declared.map_or(default_sec, u64::from)
}

fn expand_system_apt(packages: &[String]) -> Vec<PlannedStep> {
    let mut argv = vec![
        "apt-get".to_string(),
        "install".to_string(),
        "-y".to_string(),
    ];
    argv.extend(packages.iter().cloned());
    // No `done`: what "these packages are installed" looks like is a
    // per-package query (`dpkg -s`) over a list, which needs `ForEach`
    // and a predicate neither of which exists. `apt-get install -y` is
    // idempotent on its own, so nothing is broken by re-running it —
    // unlike the clone below.
    vec![PlannedStep::always(Step::Sh(argv))]
}

/// `comfyui.install` — clone and check out, in **one** composed step.
///
/// The step's condition is therefore the whole [`Checkout`], not half
/// of it: the two commands are joined by `&&` inside a single `sh -c`,
/// so there is no position between them for a second condition to
/// describe. That the conjunction falls out of the step's own shape,
/// rather than being imposed, is the point of deriving it from an
/// entity.
///
/// This is the phase the stage exists for: without a condition, the
/// `git clone` fails on the second apply because its destination is
/// already there (design §4.4). The predecessor implementation guards
/// the same clone with `test -d {name} ||`; the condition here asks the
/// stronger question — is there a *repository*, and is it at the ref
/// the profile named.
fn expand_comfyui_install(ref_name: &str, repo: Option<&str>) -> Vec<PlannedStep> {
    let repo = repo.unwrap_or(DEFAULT_COMFYUI_REPO);
    let url = format!("https://github.com/{repo}.git");
    let script = format!(
        "git clone {url} {dir} && git -C {dir} checkout {ref_name}",
        dir = COMFYUI_INSTALL_DIR
    );
    vec![PlannedStep::done_when(
        Step::Sh(vec!["sh".to_string(), "-c".to_string(), script]),
        assert::Checkout::new(COMFYUI_INSTALL_DIR, Some(ref_name.to_string())).done(),
    )]
}

/// `python3 -c '<assert>'` — exits non-zero when the running
/// interpreter's version does not start with `want`, printing the
/// actual `sys.version` so the mismatch is visible in the report's
/// captured stderr.
///
/// Emitting `python3 --version` and letting the operator compare was
/// the earlier shape; it called itself advisory while checking nothing,
/// so a version mismatch passed silently.
fn expand_python_version_check(want: &str) -> Vec<PlannedStep> {
    let script = format!(
        "import sys; assert sys.version.startswith(\"{want}\"), \
         \"python version mismatch: want {want}, got \" + sys.version"
    );
    // No `done`, and deliberately: this step *is* an assertion. Skipping
    // it when it already held would mean not checking, which is the one
    // thing it exists to do.
    vec![PlannedStep::always(Step::Sh(vec![
        "python3".to_string(),
        "-c".to_string(),
        script,
    ]))]
}

fn expand_python_deps(deps: &[String], in_comfy_venv: bool) -> Vec<PlannedStep> {
    let pip = if in_comfy_venv {
        COMFYUI_VENV_PIP
    } else {
        "pip"
    };
    let mut argv = vec![pip.to_string(), "install".to_string()];
    argv.extend(deps.iter().cloned());
    // No `done`: same shape as `system.apt` — a per-requirement query
    // over a list, and `pip install` is already idempotent.
    vec![PlannedStep::always(Step::Sh(argv))]
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

/// `custom_nodes` — clone, optionally check out, optionally pip, per
/// entry.
///
/// Unlike `comfyui.install` the clone and the checkout are **separate**
/// steps, so each carries its own condition and the two are different
/// (design §3.2e: a step's completion is not derived from its
/// neighbours'):
///
/// - the clone is finished once there is a repository at the node's
///   directory — [`assert::Checkout`] with no ref, because at this
///   position the profile's `ref` has not been applied yet and asking
///   for it would make the clone's condition describe the checkout's
///   work;
/// - the checkout is finished once that repository holds the declared
///   ref — the full two-conjunct condition.
///
/// **The pip step gets none**, and that absence is the honest answer
/// rather than an omission. "The requirements are installed" is a
/// statement about a venv's contents, not about a checkout; deriving it
/// from [`assert::Checkout`] would say the pip step is finished the
/// moment the repository exists, which would skip the install on the
/// very first apply. The entity that could answer it does not exist
/// yet, so the step runs every time — `pip install -r` being idempotent
/// is what makes that acceptable, exactly as it is for `python.deps`.
fn expand_custom_nodes(json: &str) -> Result<Vec<PlannedStep>, ExecError> {
    let nodes: Vec<CustomNodeSpec> =
        serde_json::from_str(json).map_err(|err| ExecError::EffectFailed {
            op: "custom_nodes".to_string(),
            message: format!("nodes_json parse: {err}"),
        })?;
    let mut steps = Vec::with_capacity(nodes.len() * 2);
    for node in nodes {
        let node_dir = format!("{CUSTOM_NODES_ROOT}/{}", node.name);
        steps.push(PlannedStep::done_when(
            Step::Sh(vec![
                "git".to_string(),
                "clone".to_string(),
                format!("https://github.com/{}.git", node.repo),
                node_dir.clone(),
            ]),
            assert::Checkout::new(node_dir.clone(), None).done(),
        ));
        if let Some(git_ref) = node.git_ref {
            steps.push(PlannedStep::done_when(
                Step::Sh(vec![
                    "git".to_string(),
                    "-C".to_string(),
                    node_dir.clone(),
                    "checkout".to_string(),
                    git_ref.clone(),
                ]),
                assert::Checkout::new(node_dir.clone(), Some(git_ref)).done(),
            ));
        }
        if node.pip {
            steps.push(PlannedStep::always(Step::Sh(vec![
                COMFYUI_VENV_PIP.to_string(),
                "install".to_string(),
                "-r".to_string(),
                format!("{node_dir}/requirements.txt"),
            ])));
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
) -> Result<Vec<PlannedStep>, ExecError> {
    if env.is_empty() {
        // Public download: the bridge's scheme resolution turns the
        // source into the URL it will actually GET (chapter 04
        // §net.transfer), so a public `hf://` pull streams to the
        // destination file exactly as an `https://` one does. The step
        // carries the resolved URL, which is what the dry-run trace and
        // the report then show.
        // A `sync.pull` names an arbitrary source and destination and
        // declares no digest, so there is no entity to ask and nothing
        // to skip on.
        return Ok(vec![PlannedStep::always(Step::Transfer {
            src: scheme::download_url("sync_pull", src, revision)?,
            dst: dst.to_string(),
        })]);
    }

    // Non-empty env → credential-carrying download routed to the native
    // CLI over sh.exec (spec 02 §Dispatch routing).
    if let Some(rest) = src.strip_prefix("b2://") {
        let (bucket, path) = split_b2_uri(rest, "sync_pull", src)?;
        return Ok(vec![PlannedStep::always(Step::Sh(vec![
            "b2".to_string(),
            "download-file-by-name".to_string(),
            bucket.to_string(),
            path.to_string(),
            dst.to_string(),
        ]))]);
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
            "hf".to_string(),
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
        return Ok(vec![PlannedStep::always(Step::Sh(argv))]);
    }
    // Any other scheme (e.g. https://) with a non-empty env stays on the
    // plain download path — env is inert for a bridge download (spec 02
    // §Dispatch routing: only b2/hf route to a CLI).
    Ok(vec![PlannedStep::always(Step::Transfer {
        src: src.to_string(),
        dst: dst.to_string(),
    })])
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
) -> Result<Vec<PlannedStep>, ExecError> {
    if let Some(rest) = dst.strip_prefix("b2://") {
        let (bucket, path) = split_b2_uri(rest, "staging_push", dst)?;
        return Ok(vec![PlannedStep::always(Step::Sh(vec![
            "b2".to_string(),
            "upload-file".to_string(),
            bucket.to_string(),
            src.to_string(),
            path.to_string(),
        ]))]);
    }
    if let Some(rest) = dst.strip_prefix("hf://") {
        let (owner, repo, url_rev, path_in_repo) = parse_hf_uri(rest, "staging_push", dst)?;
        let rev = url_rev.or_else(|| revision.map(str::to_string));
        let mut argv = vec![
            "hf".to_string(),
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
        return Ok(vec![PlannedStep::always(Step::Sh(argv))]);
    }
    // An `https://` dst is an HTTP PUT over the net.transfer bridge; the
    // step carries the pair unresolved and the bridge reads the
    // direction off the schemes (chapter 04 §net.transfer). No `done`:
    // an upload's destination is remote, and nothing here observes it.
    Ok(vec![PlannedStep::always(Step::Transfer {
        src: src.to_string(),
        dst: dst.to_string(),
    })])
}

// The `b2://` / `hf://` URI parsers and the public-download URL
// templates live in [`super::scheme`] — one file per rule, so a template
// revision (`04` §Stability marks them provisional) lands in one place.

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
    /// The declared content digest of the downloaded file, lowercase
    /// hex (spec 02 `models[].sha256`).
    ///
    /// Read since this stage, and only here — the field was in the
    /// payload spec from the start but was dropped on the way into
    /// [`Step`], which is why a second apply re-downloaded every weight
    /// (04-bridge.md §209 recorded it as deferred).
    ///
    /// **Decoding it does not move any profile's hash.** The AST
    /// carries this payload as one opaque string
    /// ([`ProfileNode::Models::models_json`]) and the canonical encoder
    /// writes that string verbatim, so a declared `sha256` has been
    /// inside the hash all along — dropped only here, at expansion.
    /// What changes is what the provisioner does with it.
    #[serde(default)]
    sha256: Option<String>,
}

fn expand_models(json: &str) -> Result<Vec<PlannedStep>, ExecError> {
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
        // The `done` is derived from the kind, not declared: a `models`
        // element is a `ModelFile`, and what a finished one looks like
        // is that entity's business (design §3.4). A profile cannot
        // write its own condition yet — that form is settled once three
        // entities exist, so it is not shaped by this one.
        let done = assert::ModelFile::new(dst.clone(), model.sha256).done();
        steps.push(PlannedStep::done_when(
            Step::Transfer {
                src: model.src,
                dst,
            },
            done,
        ));
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

fn expand_llm_models(json: &str) -> Result<Vec<PlannedStep>, ExecError> {
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
            "hf".to_string(),
            "download".to_string(),
            format!("{owner}/{repo}"),
            "--local-dir".to_string(),
            dst_dir,
        ];
        if let Some(rev) = rev {
            argv.push("--revision".to_string());
            argv.push(rev);
        }
        // No `done`: `hf download` lands a whole repository snapshot in
        // `--local-dir`, and what "that snapshot is here" looks like is
        // a different entity from `ModelFile`'s single file. hf-cli's
        // own cache makes a repeat cheap, which is why this is a
        // deferral rather than a defect.
        steps.push(PlannedStep::always(Step::Sh(argv)));
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
//
// ## Died-during-wait detection
//
// The launch writes `$!` to a pid file next to its log, so the poll
// that follows can tell "not up yet" from "gone". Two checks use it:
//
// - the launch itself sleeps 1 s and `kill -0`s the pid, which catches
//   the fastest failures (missing binary, argument parse error);
// - every poll iteration re-reads the pid file and checks the process
//   still exists, failing at once when a pid it saw running is gone.
//
// The second check is the one that matters in practice: an inference
// engine crashes tens of seconds in — after its import phase, on
// `bind()` — which is long past any settle sleep. Without it the poll
// spends its whole deadline (300 s by default) asking a socket nobody
// is listening on, and reports a timeout for what was a crash. The
// launch log's tail travels with the failure so the crash itself is in
// the report.
//
// The poll only treats a dead pid as fatal after it has seen that pid
// alive — a resume profile polls without launching anything, and a
// leftover pid file at the well-known path must not turn into a death
// verdict (the arming rule on `execute_http_poll_in`).
//
// This is *not* process supervision: nothing restarts, nothing keeps
// watching. The pid file is read only inside the readiness window, so
// a crash after the poll succeeded is still undetected (spec 02
// §Spawn-and-poll invocations).
// ---------------------------------------------------------------------

/// `service.start` / `service.ready` launch log for a service `name`
/// (spec 02 §Built-in path constants).
fn service_log_path(name: &str) -> String {
    format!("/tmp/{name}.log")
}

/// `service.start` / `service.ready` pid file for a service `name`
/// (spec 02 §Built-in path constants).
fn service_pid_path(name: &str) -> String {
    format!("/tmp/{name}.pid")
}

/// The detached-launch command text shared by both launch kinds:
/// background `argv`, record its pid, and fail the step if it is gone
/// a second later. Returned as text (not a [`Step`]) so a caller can
/// prefix it — `comfyui.restart` needs a `cd` in the same shell.
///
/// `label` names the launch in the died-immediately message
/// (`comfyui` / `service <name>`); it reaches the shell inside single
/// quotes and is validate-stage shell-safe.
///
/// The redirect is load-bearing, not cosmetic. [`effects::sh_exec`]
/// uses `Command::output()`, which reads the child's stdout / stderr
/// pipes until EOF; a backgrounded grandchild that inherited those
/// pipes would hold them open and hang apply for as long as the server
/// runs. Sending its output to a file closes the inherited ends, so
/// `sh` exits and `output()` returns at once. Do not "tidy away" the
/// redirect.
///
/// `pid=$!` must be the *server's* pid, so only the `nohup` is
/// backgrounded here — a caller that prefixes a `cd` has to group this
/// text (see [`expand_comfyui_restart`]), otherwise `&` would
/// background the whole `cd … && nohup …` list and `$!` would name the
/// subshell instead.
fn spawn_detached_command(argv: &[String], log_path: &str, pid_path: &str, label: &str) -> String {
    format!(
        "nohup {argv} > {log_path} 2>&1 & pid=$!; echo $pid > {pid_path}; sleep 1; \
         kill -0 $pid 2>/dev/null || {{ echo '{label} died immediately' >&2; \
         tail -{DIED_LOG_TAIL_LINES} {log_path} >&2; exit 1; }}",
        argv = argv.join(" ")
    )
}

/// Brace-group a launch command so a caller can put something in front
/// of it with `&&`.
///
/// Without the group, `cd dir && nohup … &` backgrounds the *whole*
/// `&&` list, and `$!` then names the subshell running it rather than
/// the server — the recorded pid would belong to a process that exits
/// as soon as the launch is spawned, and the readiness poll would read
/// every wait as a death.
fn grouped(command: String) -> String {
    format!("{{ {command}; }}")
}

/// Wrap a command line in `sh -c` so the shell — not `Command` —
/// parses the redirect and the `&`.
fn sh_c(command: String) -> Step {
    Step::Sh(vec!["sh".to_string(), "-c".to_string(), command])
}

fn expand_comfyui_restart(port: u16, extra_args: &[String]) -> Vec<PlannedStep> {
    let mut argv = vec![
        COMFYUI_VENV_PY.to_string(),
        COMFYUI_MAIN_PY.to_string(),
        "--port".to_string(),
        port.to_string(),
    ];
    argv.extend(extra_args.iter().cloned());
    // `cd` first: ComfyUI resolves `models/` / `custom_nodes/` relative
    // to its working directory. The launch is braced so `&` backgrounds
    // only the `nohup` — `cd … && nohup … &` would background the whole
    // list and leave `$!` naming the subshell, not the server. A failing
    // `cd` short-circuits the group and fails the step.
    //
    // No `done` yet: what a running service looks like is `Service`
    // (段 4), and a restart is the step whose condition has to be read
    // most carefully — a satisfied one means "the server is already up
    // with these arguments", which is precisely when a restart should
    // be skipped and precisely what an unconditional restart gets
    // wrong.
    vec![PlannedStep::always(sh_c(format!(
        "cd {COMFYUI_INSTALL_DIR} && {}",
        grouped(spawn_detached_command(
            &argv,
            COMFYUI_LOG_PATH,
            COMFYUI_PID_PATH,
            "comfyui"
        ))
    )))]
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
/// `port` / `tensor_parallel_size` become `--port` / `--tensor-parallel-size`
/// when set; when `None`, the flag is omitted and each platform's own
/// default takes over (`vllm` 8000, `llamacpp` 8080, `ollama` reads
/// `OLLAMA_HOST`). `extra_args` is still appended verbatim after the
/// declared flags, so an author who prefers to write `["--port", "9000"]`
/// there directly stays in control; if both are declared the argv
/// carries both, which the platform CLI will normally reject as
/// duplicate — validate does not police that overlap yet.
fn expand_service_start(
    name: &str,
    platform_kind: &str,
    model: Option<&str>,
    port: Option<u16>,
    dtype: Option<&str>,
    tensor_parallel_size: Option<u16>,
    extra_args: &[String],
) -> Vec<PlannedStep> {
    let log_path = service_log_path(name);
    let pid_path = service_pid_path(name);
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
            if let Some(port) = port {
                argv.push("--port".to_string());
                argv.push(port.to_string());
            }
            if let Some(dtype) = dtype {
                argv.push("--dtype".to_string());
                argv.push(dtype.to_string());
            }
            if let Some(size) = tensor_parallel_size {
                argv.push("--tensor-parallel-size".to_string());
                argv.push(size.to_string());
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
            if let Some(port) = port {
                argv.push("--port".to_string());
                argv.push(port.to_string());
            }
            argv.extend(extra_args.iter().cloned());
            argv
        }
        other => {
            return vec![PlannedStep::always(Step::Note(format!(
                "service_start name={name} platform_kind={other}: no launch \
                 invocation — spec 02 specifies vllm / ollama / llamacpp"
            )))]
        }
    };
    // No `done` — same as `comfyui.restart`; `Service` is 段 4.
    vec![PlannedStep::always(sh_c(spawn_detached_command(
        &argv,
        &log_path,
        &pid_path,
        &format!("service {name}"),
    )))]
}

fn missing_model_note(name: &str, platform_kind: &str) -> PlannedStep {
    PlannedStep::always(Step::Note(format!(
        "service_start name={name} platform_kind={platform_kind}: no launch \
         invocation — the platform requires `model` and the profile declares none"
    )))
}

/// Render one step for the dry-run trace log, **without** answering its
/// condition.
///
/// `env` is the phase's resolved env-injection map (empty for env-less
/// ops); a [`Step::Sh`] renders its *key* names only — resolved values
/// are never logged (spec 06 opacity).
///
/// This takes a [`Step`] rather than a [`PlannedStep`], so a condition
/// cannot reach it: a dry run *evaluates* the condition, and what it
/// answered belongs with the answer. [`dry_run_step`] is the whole
/// dry-run rendering, and it uses this for the half that describes the
/// step itself — as does the skip line in [`execute_step`], so the two
/// spell a step identically.
pub fn render_dry(step: &Step, env: &BTreeMap<String, String>) -> String {
    match step {
        Step::Sh(argv) if env.is_empty() => format!("sh argv={argv:?}"),
        Step::Sh(argv) => format!(
            "sh argv={argv:?} env_keys={:?}",
            env.keys().collect::<Vec<_>>()
        ),
        Step::Transfer { src, dst, .. } => format!("transfer src={src} dst={dst}"),
        Step::HttpPoll {
            url,
            timeout_sec,
            pid_file,
            ..
        } => {
            // The pid file is shown because it changes what the step
            // can fail *for*: with one, a launch that dies during the
            // wait fails the poll immediately instead of at the
            // deadline.
            let liveness = pid_file
                .as_deref()
                .map(|path| format!(" pid_file={path}"))
                .unwrap_or_default();
            format!("http_poll url={url} timeout={timeout_sec}s{liveness}")
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
    /// Why the step did what it did, when that is not obvious from the
    /// other fields — currently, that it was skipped and which parts of
    /// its `done` were true.
    ///
    /// Reaches the report as `StepReport::note`, which *is* serialized
    /// into the step entry (unlike `reason`). Chef prints
    /// `(skipped due to not_if)` and leaves the operator to go read the
    /// cookbook; a skip that does not say what was true is the same
    /// thing (design §3.8).
    pub note: Option<String>,
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
///
/// **`async`, and with no [`effects::block_on_effect`] under it.** Two
/// of the four step kinds reach an async effect (`transfer` streams a
/// file, `http_poll` reads a URL), and while a whole composed step list
/// ran inside one `dsl_kit::Op::apply` — a synchronous trait method —
/// those two had to be driven from that seam. They no longer are: a
/// lifecycle step is its own `Call` node ([`super::steps`]), so the host
/// resolver awaits this directly and the two seams that used to sit here
/// are gone.
/// **Only [`AssertOutcome::Satisfied`](assert::AssertOutcome::Satisfied)
/// skips.** `Unsatisfied` obviously runs; so do `NotChecked` and
/// `CheckFailed`, because neither is a statement that the work is
/// already done. Re-running something that was already finished costs
/// bandwidth, or a failed `git clone`; skipping something that was not
/// costs a broken pod.
///
/// **The condition's answers are reported either way**, skip or not.
/// The fold gives `Unsatisfied` absolute priority, so a `CheckFailed`
/// in the same conjunction disappears from the top answer — a
/// permission failure on the digest read, or a `git` that could not be
/// started, would otherwise be invisible with the repeated work as its
/// only symptom. The note carries the whole evaluated tree, which is
/// what the tree exists for (design §3.2b').
pub async fn execute_step(
    planned: &PlannedStep,
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<StepResult, StepFailure> {
    let evaluated = match &planned.done {
        // `Real`, not the context's mode: this function is the real
        // path by construction — a dry run goes through
        // [`dry_run_step`] and never reaches an effect.
        Some(done) => Some((
            done,
            assert::eval(done, ExecMode::Real, &LocalObserve).await,
        )),
        None => None,
    };

    if let Some((done, node)) = &evaluated {
        if node.is_satisfied() {
            let condition = assert::describe_execution(done, node);
            return Ok(StepResult {
                // The step renders exactly as a dry run renders it, so
                // a skip line reads as "here is the step, and here is
                // why it did not run".
                summary: format!("{} skipped: {condition}", render_dry(&planned.step, env)),
                note: Some(format!("skipped, already done: {condition}")),
                ..StepResult::default()
            });
        }
    }

    let mut result = run_effect(&planned.step, op, env).await?;
    if let Some((done, node)) = &evaluated {
        result.note = Some(format!(
            "not done: {}",
            assert::describe_execution(done, node)
        ));
    }
    Ok(result)
}

/// Run one step's effect, with no reference to any condition.
///
/// Split from [`execute_step`] so the skip is decided in exactly one
/// place for every step shape. Before a second entity existed the two
/// were entangled — the transfer arm evaluated its own condition — and
/// giving `Sh` a condition under that shape would have meant writing
/// the same decision a second time.
async fn run_effect(
    step: &Step,
    op: &str,
    env: &BTreeMap<String, String>,
) -> Result<StepResult, StepFailure> {
    match step {
        Step::Sh(argv) => execute_sh(argv, op, env),
        Step::Transfer { src, dst } => {
            let outcome = effects::transfer(src, dst).await?;
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
        Step::HttpPoll {
            url,
            timeout_sec,
            pid_file,
            log_path,
        } => {
            execute_http_poll(
                url,
                *timeout_sec,
                pid_file.as_deref(),
                log_path.as_deref(),
                op,
            )
            .await
        }
        Step::Note(message) => Ok(StepResult::summary_only(format!("note \"{message}\""))),
    }
}

/// What a dry run has to say about one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryStep {
    /// Trace-log summary fragment.
    pub summary: String,
    /// The report note, present exactly when the step had a condition
    /// and therefore an answer to report.
    pub note: Option<String>,
}

/// Render one step for a dry run, **evaluating its `done`**.
///
/// This is where a dry run stopped being a static description. It used
/// to print the condition and call the skip undecided — a sentence about
/// the profile, equally true whatever the host looked like. The model
/// always allowed better: [`assert::Assert::FileExists`] is a cheap
/// observation and answers under
/// [`ExecMode::DryRun`](super::ExecMode::DryRun), which is the same call
/// Ansible's `creates` guard makes in check mode (design §3.7). What
/// stood in the way was the wiring — the evaluator is async and the
/// dry-run arm sat behind the synchronous `dsl_kit::Op::apply` — and
/// that is what [`super::steps`] removed.
///
/// So the four answers a step can get are now all real:
///
/// | answer | what a dry run says |
/// |---|---|
/// | `Satisfied` | would skip: the destination is already what was asked for |
/// | `Unsatisfied` | **would transfer**: the destination is not there |
/// | `NotChecked` | undecided: the digest is not read in a dry run |
/// | `CheckFailed` | undecided: the condition itself could not be read |
///
/// The middle two are the point. A `models` entry whose destination is
/// absent answers `Unsatisfied` even though its digest conjunct is
/// `NotChecked`, because the fold gives `Unsatisfied` priority — so one
/// item in a phase can say "this transfers" while the next says "this is
/// undecided", from the same profile, in the same run.
///
/// The whole evaluated tree reaches the note, not just the top answer:
/// the fold hides a `CheckFailed` under an `Unsatisfied` sibling, and
/// the tree is what exists to undo that (design §3.2b').
///
/// **The table above was written for a transfer and now holds for a
/// clone as well.** A `Checkout`'s condition answers in a dry run in
/// both halves — [`assert::Assert::GitTreeAt`] runs its `git` in either
/// mode — so the `NotChecked` row is one a `comfyui.install` never
/// reaches: a dry run says either "would skip" or "would run", and
/// only a `git` that could not answer at all lands in the last row.
pub async fn dry_run_step(planned: &PlannedStep, env: &BTreeMap<String, String>) -> DryStep {
    let rendered = render_dry(&planned.step, env);
    let Some(done) = &planned.done else {
        return DryStep {
            summary: rendered,
            note: None,
        };
    };
    let node = assert::eval(done, ExecMode::DryRun, &LocalObserve).await;
    let verdict = dry_run_verdict(node.outcome(), would_verb(&planned.step));
    let condition = assert::describe_execution(done, &node);
    DryStep {
        summary: format!("{rendered} {verdict}: {condition}"),
        note: Some(format!("{verdict}: {condition}")),
    }
}

/// What a dry run says the step *would* do, in the step's own words.
///
/// A transfer "would transfer" and a command "would run": the phrasing
/// is per shape rather than a single neutral verb, because the first
/// clause of the note is what an operator reads down the left-hand edge
/// of a plan, and "would run" for a 4 GiB download would be a worse
/// sentence than either.
fn would_verb(step: &Step) -> &'static str {
    match step {
        Step::Transfer { .. } => "transfer",
        Step::HttpPoll { .. } => "poll",
        // A `Note` runs no effect and never carries a condition, so it
        // reaches this only if one is ever given to it.
        Step::Sh(_) | Step::Note(_) => "run",
    }
}

/// What running one step produced, in whichever mode it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepRun {
    /// A dry run: the step was rendered and its condition answered.
    Dry(DryStep),
    /// A real run: the step's effect happened.
    Real(StepResult),
}

/// Run one step in `mode` — **the one entry point both engine drivers
/// use**.
///
/// There are two drivers, and they reach an effect differently:
///
/// - [`crate::apply`] drives the engine with `drive_async`, and a
///   lifecycle step is a `Call` node ([`super::steps`]), so its resolver
///   `await`s this directly;
/// - [`crate::profile_ast::create_profile_engine`] drives the engine
///   with a synchronous `Stepper` (the MCP debugger host and the exec
///   integration tests), where a lifecycle phase is still an `Apply` and
///   `dsl_kit::Op::apply` cannot await — so that one hands this whole
///   future to [`effects::block_on_effect`], once per step.
///
/// Both therefore run **the same function**, in both modes. That is the
/// point of it existing: a dry run that answers a step's `done` and a
/// real run that skips on it must not depend on which driver is turning
/// the engine.
pub async fn run_step(
    planned: &PlannedStep,
    op: &str,
    env: &BTreeMap<String, String>,
    mode: ExecMode,
) -> Result<StepRun, StepFailure> {
    match mode {
        ExecMode::DryRun => Ok(StepRun::Dry(dry_run_step(planned, env).await)),
        ExecMode::Real => execute_step(planned, op, env).await.map(StepRun::Real),
    }
}

/// How a dry run words each of the four answers, for a step that would
/// `verb` ([`would_verb`]).
///
/// Only `Satisfied` skips, so the other three all say the step would run
/// — the same safe direction [`execute_step`] takes. They are still
/// worded apart: "the destination is not there" and "the condition could
/// not be read" are different pieces of news for whoever reads the plan,
/// and collapsing them is the granularity this model exists to get away
/// from.
fn dry_run_verdict(outcome: &assert::AssertOutcome, verb: &str) -> String {
    match outcome {
        assert::AssertOutcome::Satisfied => "would skip, already done".to_string(),
        assert::AssertOutcome::Unsatisfied => format!("would {verb}, not done"),
        assert::AssertOutcome::NotChecked => {
            format!("undecided (not evaluated in a dry run), would {verb}")
        }
        assert::AssertOutcome::CheckFailed(_) => {
            format!("undecided (the condition could not be read), would {verb}")
        }
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

/// What one liveness probe of a launch's pid file concluded.
///
/// A verdict on its own is never enough to fail a poll — see the
/// arming rule in [`execute_http_poll_in`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// The pid file names a process that still exists.
    Alive,
    /// The pid file names a process that is gone.
    Dead(u32),
    /// Nothing to conclude — the pid file is absent, unreadable, or
    /// does not (yet) hold a number. Deliberately *not* a death: the
    /// launch writes the file a moment after backgrounding the server,
    /// and losing that race must not fail a poll that would otherwise
    /// have succeeded.
    Unknown,
}

/// Read `pid_file` and decide whether the process it names is still
/// running, looking under `proc_root` (`/proc` in production).
///
/// `proc_root` is a parameter so the decision can be tested without a
/// procfs — on a host without `/proc` every pid would otherwise read as
/// dead.
fn probe_liveness(pid_file: &str, proc_root: &Path) -> Liveness {
    let Ok(text) = fs::read_to_string(pid_file) else {
        return Liveness::Unknown;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return Liveness::Unknown;
    };
    if proc_root.join(pid.to_string()).exists() {
        Liveness::Alive
    } else {
        Liveness::Dead(pid)
    }
}

/// Last `DIED_LOG_TAIL_LINES` lines of `log_path`, rendered for a
/// failure message. An unreadable log yields a note saying so rather
/// than silently dropping the section — "the log is missing" is itself
/// worth reporting when a launch has just died.
fn log_tail(log_path: &str) -> String {
    match fs::read_to_string(log_path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            let start = lines.len().saturating_sub(DIED_LOG_TAIL_LINES);
            format!(
                "\n--- {log_path} (last {} lines) ---\n{}",
                lines.len() - start,
                lines[start..].join("\n")
            )
        }
        Err(err) => format!("\n--- {log_path} unreadable: {err} ---"),
    }
}

async fn execute_http_poll(
    url: &str,
    timeout_sec: u64,
    pid_file: Option<&str>,
    log_path: Option<&str>,
    op: &str,
) -> Result<StepResult, StepFailure> {
    execute_http_poll_in(
        url,
        timeout_sec,
        pid_file,
        log_path,
        op,
        Path::new(PROC_ROOT),
    )
    .await
}

/// [`execute_http_poll`] with the procfs root injected (tests supply a
/// directory they control; production supplies [`PROC_ROOT`]).
///
/// ## Arming rule
///
/// A `Dead` verdict only fails the poll once this call has *itself*
/// seen the pid alive. A pid file that reads dead from the very first
/// probe is not this poll's launch dying — it is almost always a stale
/// file left at the well-known path by an earlier apply, and a resume
/// profile (a `comfyui.health` / `service.ready` declared without the
/// launch that pairs with it) is a first-class shape here. Failing
/// those on a leftover file would be a wrong verdict; falling through
/// to the deadline is merely the old behaviour.
///
/// The cost is a small blind spot: a launch that dies between its own
/// settle check and this poll's first probe is never observed alive,
/// so it surfaces as a timeout rather than as a death. That window is
/// a couple of seconds wide, while the crash this exists for (an
/// engine failing to `bind()` after its import phase) happens tens of
/// seconds in, comfortably inside the armed window.
async fn execute_http_poll_in(
    url: &str,
    timeout_sec: u64,
    pid_file: Option<&str>,
    log_path: Option<&str>,
    op: &str,
    proc_root: &Path,
) -> Result<StepResult, StepFailure> {
    let deadline = Instant::now() + Duration::from_secs(timeout_sec);
    let mut last_status: Option<u16> = None;
    let mut last_err: Option<String> = None;
    // Set once the launch has been seen running; until then a death
    // verdict is not this poll's to report (§Arming rule).
    let mut armed = false;
    // The poll's own probes carry no declared headers and use the
    // effect-default per-request timeout: the phase's `timeout_sec` is
    // the *deadline for the whole poll* (`deadline` above), not a
    // per-probe one.
    let probe_opts = effects::HttpOpts::default();
    loop {
        match effects::http_get(url, &probe_opts).await {
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
        // The server did not answer this round. Before waiting again,
        // ask whether it is still there at all: a launch that crashed
        // during the wait must fail now, not after the full deadline
        // (§Died-during-wait detection).
        if let Some(pid_file) = pid_file {
            match probe_liveness(pid_file, proc_root) {
                // From here on, this pid disappearing is a death this
                // poll witnessed (§Arming rule).
                Liveness::Alive => armed = true,
                Liveness::Dead(pid) if armed => {
                    let tail = log_path.map(log_tail).unwrap_or_default();
                    return Err(ExecError::EffectFailed {
                        op: op.to_string(),
                        message: format!(
                            "process died during readiness wait (pid {pid}); \
                             {url} never answered{tail}"
                        ),
                    }
                    .into());
                }
                // Dead before ever being seen alive (a stale pid file,
                // or a poll declared without its launch), or nothing
                // readable yet: keep waiting on the URL alone.
                Liveness::Dead(_) | Liveness::Unknown => {}
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
        sleep(Duration::from_secs(HTTP_POLL_INTERVAL_SEC)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn node_id(ids: &IdGen) -> dsl_kit::NodeId {
        ids.node()
    }

    /// The effects a phase composed, with the conditions beside them
    /// dropped.
    ///
    /// For the tests whose subject is *which command a payload builds*.
    /// Where the condition is the subject — `comfyui.install`,
    /// `custom_nodes`, `models` — the whole [`PlannedStep`] is compared
    /// instead, and `every_composed_step_declares_its_condition`
    /// pins which phases have one at all, so nothing hides in the gap
    /// this helper opens.
    fn effects(steps: &[PlannedStep]) -> Vec<Step> {
        steps.iter().map(|planned| planned.step.clone()).collect()
    }

    /// The condition of a phase's `index`-th step, as rendered.
    fn condition(steps: &[PlannedStep], index: usize) -> Option<String> {
        steps[index].done.as_ref().map(assert::describe)
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
            effects(&steps),
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
        match &steps[0].step {
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

    /// **The UC of this stage**: the one step `comfyui.install` composes
    /// carries the whole `Checkout` condition, so a second apply does
    /// not re-run a `git clone` whose destination is already there.
    ///
    /// The condition is compared as a value, not by substring: it is
    /// what decides whether the clone runs, and the shape of it — the
    /// repository directory, then the ref — is the part a reader has to
    /// be able to trust.
    #[test]
    fn expand_comfyui_install_guards_its_clone_with_the_checkout_condition() {
        let ids = IdGen::new();
        let steps = expand(&ProfileNode::ComfyUiInstall {
            id: node_id(&ids),
            ref_name: "v0.1.0".to_string(),
            repo: None,
        })
        .expect("comfyui_install expands");

        assert_eq!(steps.len(), 1, "clone and checkout are one composed step");
        assert_eq!(
            steps[0].done,
            Some(assert::Checkout::new("/workspace/ComfyUI", Some("v0.1.0".to_string())).done()),
        );
        assert_eq!(
            condition(&steps, 0).as_deref(),
            Some("all[exists(/workspace/ComfyUI/.git), git_tree(/workspace/ComfyUI)=v0.1.0]"),
            "the repository first, then the ref it must hold",
        );
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
        match &steps[0].step {
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
            effects(&steps),
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
            effects(&steps),
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
        match &steps[0].step {
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
        assert!(matches!(&steps[0].step, Step::Sh(a) if a[2] == "https://github.com/a/b.git"));
        assert!(matches!(&steps[1].step, Step::Sh(a) if a[2] == "https://github.com/c/d.git"));
        assert!(matches!(
            &steps[2].step,
            Step::Sh(a) if a[0] == "git" && a[3] == "checkout" && a[4] == "v2"
        ));
        assert!(matches!(
            &steps[4].step,
            Step::Sh(a) if a[0] == "/workspace/ComfyUI/venv/bin/pip"
        ));
        assert!(matches!(
            &steps[7].step,
            Step::Sh(a) if a[0] == "/workspace/ComfyUI/venv/bin/pip"
                && a[3] == "/workspace/ComfyUI/custom_nodes/full/requirements.txt"
        ));
    }

    /// Each of a `custom_nodes` entry's steps answers for **itself**:
    /// the clone for the repository being there, the checkout for the
    /// ref being out — and the pip install for nothing at all.
    ///
    /// The last one is the load-bearing absence. Deriving a condition
    /// for it from the same `Checkout` would make it satisfied the
    /// moment the clone succeeded, so the requirements would never be
    /// installed; "the requirements are in the venv" is a different
    /// entity, and it does not exist yet.
    #[test]
    fn expand_custom_nodes_conditions_the_clone_and_the_checkout_but_not_the_pip() {
        let ids = IdGen::new();
        let steps = expand(&ProfileNode::CustomNodes {
            id: node_id(&ids),
            nodes_json: r#"[{"name":"full","repo":"g/h","ref":"main","pip":true}]"#.to_string(),
        })
        .expect("custom_nodes expands");
        assert_eq!(steps.len(), 3);

        let node_dir = "/workspace/ComfyUI/custom_nodes/full";
        assert_eq!(
            steps[0].done,
            Some(assert::Checkout::new(node_dir, None).done()),
            "the clone is finished once the repository is there — the ref is the next step's work",
        );
        assert_eq!(
            condition(&steps, 0).as_deref(),
            Some("exists(/workspace/ComfyUI/custom_nodes/full/.git)"),
            "one predicate, no conjunction around it",
        );
        assert_eq!(
            steps[1].done,
            Some(assert::Checkout::new(node_dir, Some("main".to_string())).done()),
        );
        assert_eq!(
            steps[2].done, None,
            "the pip install has no condition: 'the requirements are installed' is not a Checkout",
        );
    }

    /// Which composed steps carry a condition at all, in one place.
    ///
    /// Most of the tests above compare argv through `effects`, which
    /// drops the conditions; this is what keeps that from hiding a
    /// condition that was added — or lost — by accident. A phase that
    /// gains an entity is expected to change this test.
    #[test]
    fn every_composed_step_declares_its_condition() {
        let ids = IdGen::new();
        // (payload, one `Some(rendered)` / `None` per composed step)
        let cases: Vec<(ProfileNode, Vec<Option<&str>>)> = vec![
            (
                ProfileNode::SystemApt {
                    id: node_id(&ids),
                    packages: vec!["git".into()],
                },
                vec![None],
            ),
            (
                ProfileNode::ComfyUiInstall {
                    id: node_id(&ids),
                    ref_name: "v1".into(),
                    repo: None,
                },
                vec![Some(
                    "all[exists(/workspace/ComfyUI/.git), git_tree(/workspace/ComfyUI)=v1]",
                )],
            ),
            (
                ProfileNode::PythonVersionCheck {
                    id: node_id(&ids),
                    want: "3.12".into(),
                },
                vec![None],
            ),
            (
                ProfileNode::PythonDeps {
                    id: node_id(&ids),
                    deps: vec!["torch".into()],
                    in_comfy_venv: true,
                },
                vec![None],
            ),
            (
                ProfileNode::CustomNodes {
                    id: node_id(&ids),
                    nodes_json: r#"[{"name":"n","repo":"a/b","ref":"v2","pip":true}]"#.into(),
                },
                vec![
                    Some("exists(/workspace/ComfyUI/custom_nodes/n/.git)"),
                    Some(
                        "all[exists(/workspace/ComfyUI/custom_nodes/n/.git), \
                         git_tree(/workspace/ComfyUI/custom_nodes/n)=v2]",
                    ),
                    None,
                ],
            ),
            (
                ProfileNode::SyncPull {
                    id: node_id(&ids),
                    src: "https://ex/m.bin".into(),
                    dst: "/workspace/m.bin".into(),
                    env: Default::default(),
                    revision: None,
                },
                vec![None],
            ),
            (
                ProfileNode::SyncPush {
                    id: node_id(&ids),
                    src: "/workspace/out.bin".into(),
                    dst: "https://ex/out.bin".into(),
                },
                vec![None],
            ),
            (
                ProfileNode::StagingPush {
                    id: node_id(&ids),
                    src: "/workspace/out.bin".into(),
                    dst: "b2://bucket/out.bin".into(),
                    env: Default::default(),
                    revision: None,
                },
                vec![None],
            ),
            (
                ProfileNode::Models {
                    id: node_id(&ids),
                    models_json: r#"[{"src":"https://ex/a.bin","dst":"a.bin"}]"#.into(),
                },
                vec![Some("exists(/workspace/ComfyUI/models/checkpoints/a.bin)")],
            ),
            (
                ProfileNode::LlmModels {
                    id: node_id(&ids),
                    models_json: r#"[{"src":"hf://owner/repo"}]"#.into(),
                },
                vec![None],
            ),
            (
                ProfileNode::PostInstall {
                    id: node_id(&ids),
                    script: "true".into(),
                },
                vec![None],
            ),
            (
                ProfileNode::ComfyUiRestart {
                    id: node_id(&ids),
                    port: 8188,
                    extra_args: Vec::new(),
                },
                vec![None],
            ),
            (
                ProfileNode::ComfyUiHealth {
                    id: node_id(&ids),
                    port: 8188,
                    timeout_sec: None,
                },
                vec![None],
            ),
            (
                ProfileNode::ServiceStart {
                    id: node_id(&ids),
                    name: "llm".into(),
                    platform_kind: "ollama".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: Vec::new(),
                },
                vec![None],
            ),
            (
                ProfileNode::ServiceReady {
                    id: node_id(&ids),
                    name: "llm".into(),
                    check_url: "http://127.0.0.1:9000/health".into(),
                    timeout_sec: None,
                },
                vec![None],
            ),
        ];
        assert_eq!(cases.len(), 15, "one case per lifecycle kind");

        for (payload, want) in cases {
            let kind = crate::plan::kind_of(&payload);
            let steps = expand(&payload).unwrap_or_else(|err| panic!("{kind} expands: {err}"));
            let got: Vec<Option<String>> = (0..steps.len())
                .map(|index| condition(&steps, index))
                .collect();
            let got: Vec<Option<&str>> = got.iter().map(Option::as_deref).collect();
            assert_eq!(got, want, "{kind}");
        }
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
            // A `sync.pull` derives no entity, so it keeps running
            // every time.
            vec![PlannedStep::always(Step::Transfer {
                src: "https://example.com/m.bin".to_string(),
                dst: "/workspace/m.bin".to_string(),
            })]
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
                assert!(
                    msg.contains("download endpoint") && msg.contains("b2 CLI route"),
                    "{msg}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// A public `hf://` pull resolves to the repo's public file URL and
    /// streams over the bridge — the same step shape an `https://` pull
    /// produces (chapter 04 §net.transfer).
    #[test]
    fn expand_sync_pull_resolves_a_public_hf_source_to_its_https_url() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "hf://owner/repo/model.safetensors".to_string(),
            dst: "/workspace/model.safetensors".to_string(),
            env: Default::default(),
            revision: None,
        };
        assert_eq!(
            expand(&payload).expect("public hf:// resolves"),
            vec![PlannedStep::always(Step::Transfer {
                src: "https://huggingface.co/owner/repo/resolve/main/model.safetensors".to_string(),
                dst: "/workspace/model.safetensors".to_string(),
            })],
        );
    }

    /// The phase's `revision` reaches the resolved URL on the public
    /// route, as it does on the CLI route's `--revision`.
    #[test]
    fn expand_sync_pull_pins_the_declared_revision_on_the_public_route() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "hf://owner/repo/model.safetensors".to_string(),
            dst: "/workspace/model.safetensors".to_string(),
            env: Default::default(),
            revision: Some("v2".to_string()),
        };
        assert_eq!(
            expand(&payload).expect("public hf:// resolves"),
            vec![PlannedStep::always(Step::Transfer {
                src: "https://huggingface.co/owner/repo/resolve/v2/model.safetensors".to_string(),
                dst: "/workspace/model.safetensors".to_string(),
            })],
        );
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
            effects(&steps),
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
            effects(&steps),
            vec![Step::Sh(vec![
                "hf".to_string(),
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
            effects(&steps),
            vec![Step::Sh(vec![
                "hf".to_string(),
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
        match &steps[0].step {
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
            vec![PlannedStep::always(Step::Transfer {
                src: "https://example.com/m.bin".to_string(),
                dst: "/workspace/m.bin".to_string(),
            })]
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
        match &steps[0].step {
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
            effects(&steps),
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
            effects(&steps),
            vec![Step::Sh(vec![
                "hf".to_string(),
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
        match &steps[0].step {
            Step::Sh(argv) => {
                assert_eq!(argv[2], "owner/repo");
                // The URL-carried @urlrev wins over the opts revision.
                assert_eq!(argv.last().map(String::as_str), Some("urlrev"));
            }
            other => panic!("expected Sh, got {other:?}"),
        }
    }

    #[test]
    /// An `https://` dst leaves the CLI routes behind and composes a
    /// bridge transfer; the bridge reads the upload direction off the
    /// schemes (chapter 04 §net.transfer).
    fn expand_staging_push_https_dst_composes_a_bridge_upload() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "https://example.com/out.bin".to_string(),
            env: Default::default(),
            revision: None,
        };
        assert_eq!(
            expand(&payload).expect("https upload composes a transfer step"),
            vec![PlannedStep::always(Step::Transfer {
                src: "/workspace/out.bin".to_string(),
                dst: "https://example.com/out.bin".to_string(),
            })],
        );
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
        let existence = |path: &str| {
            Some(assert::Assert::FileExists {
                path: std::path::PathBuf::from(path),
            })
        };
        assert_eq!(
            steps,
            vec![
                // No declared digest, so the condition is existence of
                // the composed destination — the same path the step
                // downloads to, derived once.
                PlannedStep {
                    step: Step::Transfer {
                        src: "https://ex/a.bin".to_string(),
                        dst: "/workspace/ComfyUI/models/lora/a.bin".to_string(),
                    },
                    done: existence("/workspace/ComfyUI/models/lora/a.bin"),
                },
                PlannedStep {
                    step: Step::Transfer {
                        src: "https://ex/b.bin".to_string(),
                        dst: "/workspace/ComfyUI/models/vae/b.bin".to_string(),
                    },
                    done: existence("/workspace/ComfyUI/models/vae/b.bin"),
                },
                PlannedStep {
                    step: Step::Transfer {
                        src: "https://ex/c.bin".to_string(),
                        dst: "/workspace/ComfyUI/models/checkpoints/c.bin".to_string(),
                    },
                    done: existence("/workspace/ComfyUI/models/checkpoints/c.bin"),
                },
            ]
        );
    }

    /// A declared `sha256` reaches the step as the content half of its
    /// condition — the field the payload spec has carried since the
    /// start and the expansion used to drop, which is why a second
    /// apply re-downloaded every weight.
    #[test]
    fn expand_models_carries_a_declared_digest_into_the_step_condition() {
        let ids = IdGen::new();
        let digest = crate::digest::hex_sha256(b"weights");
        let payload = ProfileNode::Models {
            id: node_id(&ids),
            models_json: format!(
                r#"[{{"src":"https://ex/a.bin","dst":"a.bin","subdir":"lora","sha256":"{digest}"}}]"#
            ),
        };

        let steps = expand(&payload).expect("models expands");
        let dst = "/workspace/ComfyUI/models/lora/a.bin";
        assert_eq!(
            steps,
            vec![PlannedStep::done_when(
                Step::Transfer {
                    src: "https://ex/a.bin".to_string(),
                    dst: dst.to_string(),
                },
                assert::ModelFile::new(dst, Some(digest)).done(),
            )],
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
            steps[0].step,
            Step::Sh(vec![
                "hf".to_string(),
                "download".to_string(),
                "owner/repo".to_string(),
                "--local-dir".to_string(),
                "/tmp/".to_string(),
            ])
        );
        assert_eq!(
            steps[1].step,
            Step::Sh(vec![
                "hf".to_string(),
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
            effects(&steps),
            vec![Step::Sh(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo done".to_string(),
            ])]
        );
    }

    // -------------------------------------------------------------
    // Spawn-and-poll launches. The expected argv are the pod-setup
    // dispatch script's literals, which the production script uses
    // verbatim — they are the specification here, so the tests pin
    // them exactly rather than asserting on fragments.
    // -------------------------------------------------------------

    fn sh_command(planned: &PlannedStep) -> &str {
        match &planned.step {
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
            "cd /workspace/ComfyUI && { nohup /workspace/ComfyUI/venv/bin/python \
             /workspace/ComfyUI/main.py --port 8188 > /tmp/comfyui.log 2>&1 & \
             pid=$!; echo $pid > /tmp/comfyui.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'comfyui died immediately' >&2; \
             tail -100 /tmp/comfyui.log >&2; exit 1; }; }"
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
            "cd /workspace/ComfyUI && { nohup /workspace/ComfyUI/venv/bin/python \
             /workspace/ComfyUI/main.py --port 8188 --listen --highvram \
             > /tmp/comfyui.log 2>&1 & pid=$!; echo $pid > /tmp/comfyui.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'comfyui died immediately' >&2; \
             tail -100 /tmp/comfyui.log >&2; exit 1; }; }"
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
            port: None,
            dtype: None,
            tensor_parallel_size: None,
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

    /// Every detached launch records the *server's* pid and settles for
    /// a second before returning, so a binary that is missing or
    /// rejects its arguments fails the launch step instead of the poll
    /// that follows.
    #[test]
    fn a_backgrounded_launch_records_its_pid_and_checks_it_survived() {
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
            port: None,
            dtype: None,
            tensor_parallel_size: None,
            extra_args: Vec::new(),
        })
        .expect("service_start expands");

        for (step, pid_path) in [
            (&restart[0], "/tmp/comfyui.pid"),
            (&start[0], "/tmp/llm.pid"),
        ] {
            let command = sh_command(step);
            assert!(
                command.contains(&format!("pid=$!; echo $pid > {pid_path}")),
                "the launch must record the backgrounded pid: {command}"
            );
            assert!(
                command.contains("sleep 1; kill -0 $pid 2>/dev/null || {"),
                "the launch must settle-check the pid it recorded: {command}"
            );
            assert!(
                command.contains("died immediately") && command.contains("tail -100 /tmp/"),
                "a died-immediately launch must fail with its log tail: {command}"
            );
            assert!(
                command.contains("exit 1"),
                "a died-immediately launch must fail the step: {command}"
            );
        }
    }

    /// The pid file a launch writes is the one its poll reads. The two
    /// halves are composed by different `expand` arms, so nothing but a
    /// test keeps the paths in step — and a mismatch would silently
    /// disable died-during-wait detection rather than break anything
    /// visible.
    #[test]
    fn each_launch_pid_path_is_the_one_its_poll_watches() {
        let ids = IdGen::new();
        let pairs = [
            (
                expand(&ProfileNode::ComfyUiRestart {
                    id: node_id(&ids),
                    port: 8188,
                    extra_args: Vec::new(),
                })
                .expect("comfyui_restart expands"),
                expand(&ProfileNode::ComfyUiHealth {
                    id: node_id(&ids),
                    port: 8188,
                    timeout_sec: None,
                })
                .expect("comfyui_health expands"),
            ),
            (
                expand(&ProfileNode::ServiceStart {
                    id: node_id(&ids),
                    name: "engine".to_string(),
                    platform_kind: "ollama".to_string(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: Vec::new(),
                })
                .expect("service_start expands"),
                expand(&ProfileNode::ServiceReady {
                    id: node_id(&ids),
                    name: "engine".to_string(),
                    check_url: "http://127.0.0.1:11434/".to_string(),
                    timeout_sec: None,
                })
                .expect("service_ready expands"),
            ),
        ];

        for (launch, poll) in pairs {
            let command = sh_command(&launch[0]);
            match &poll[0].step {
                Step::HttpPoll {
                    pid_file: Some(pid_file),
                    log_path: Some(log_path),
                    ..
                } => {
                    assert!(
                        command.contains(&format!("echo $pid > {pid_file}")),
                        "poll watches {pid_file}, launch writes elsewhere: {command}"
                    );
                    assert!(
                        command.contains(&format!("> {log_path} 2>&1 &")),
                        "poll tails {log_path}, launch logs elsewhere: {command}"
                    );
                }
                other => panic!("expected a poll with liveness paths, got {other:?}"),
            }
        }
    }

    #[test]
    fn expand_comfyui_health_polls_the_api_endpoint_not_the_ui_root() {
        let ids = IdGen::new();
        let payload = ProfileNode::ComfyUiHealth {
            id: node_id(&ids),
            port: 8188,
            timeout_sec: None,
        };
        let steps = expand(&payload).expect("comfyui_health expands");
        assert_eq!(
            effects(&steps),
            vec![Step::HttpPoll {
                // `/` answers 200 from the UI before the API is usable.
                url: "http://127.0.0.1:8188/object_info".to_string(),
                // An undeclared deadline falls back to the kind default,
                // which is sized for a cold boot rather than for an HTTP
                // round trip.
                timeout_sec: COMFYUI_HEALTH_TIMEOUT_SEC,
                // Wired to `comfyui.restart`'s launch so a ComfyUI that
                // dies during the wait fails the poll at once.
                pid_file: Some("/tmp/comfyui.pid".to_string()),
                log_path: Some("/tmp/comfyui.log".to_string()),
            }]
        );
        assert_eq!(COMFYUI_HEALTH_TIMEOUT_SEC, 180);
    }

    /// A declared `timeout_sec` replaces the kind default — including
    /// when it is shorter, so a profile can ask for a fast failure.
    #[test]
    fn expand_comfyui_health_honours_a_declared_timeout() {
        let ids = IdGen::new();
        for declared in [30u16, 600] {
            let payload = ProfileNode::ComfyUiHealth {
                id: node_id(&ids),
                port: 8188,
                timeout_sec: Some(declared),
            };
            let steps = expand(&payload).expect("comfyui_health expands");
            assert_eq!(
                effects(&steps),
                vec![Step::HttpPoll {
                    url: "http://127.0.0.1:8188/object_info".to_string(),
                    timeout_sec: u64::from(declared),
                    pid_file: Some("/tmp/comfyui.pid".to_string()),
                    log_path: Some("/tmp/comfyui.log".to_string()),
                }]
            );
        }
    }

    fn service_start(
        ids: &IdGen,
        platform_kind: &str,
        model: Option<&str>,
        port: Option<u16>,
        dtype: Option<&str>,
        tensor_parallel_size: Option<u16>,
        extra_args: &[&str],
    ) -> Vec<PlannedStep> {
        let payload = ProfileNode::ServiceStart {
            id: node_id(ids),
            name: "llm".to_string(),
            platform_kind: platform_kind.to_string(),
            model: model.map(str::to_string),
            port,
            dtype: dtype.map(str::to_string),
            tensor_parallel_size,
            extra_args: extra_args.iter().map(|s| s.to_string()).collect(),
        };
        expand(&payload).expect("service_start expands")
    }

    #[test]
    fn expand_service_start_vllm_uses_the_openai_api_server_entry_point() {
        let ids = IdGen::new();
        let steps = service_start(
            &ids,
            "vllm",
            Some("meta-llama/Llama-3-8B"),
            None,
            None,
            None,
            &[],
        );
        assert_eq!(
            sh_command(&steps[0]),
            "nohup python -m vllm.entrypoints.openai.api_server \
             --model meta-llama/Llama-3-8B > /tmp/llm.log 2>&1 & \
             pid=$!; echo $pid > /tmp/llm.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'service llm died immediately' >&2; \
             tail -100 /tmp/llm.log >&2; exit 1; }"
        );
    }

    /// Named `port` / `dtype` / `tensor_parallel_size` become their own
    /// `--flag` / value pairs in declaration order; `extra_args` still
    /// trails them verbatim for anything the named surface does not
    /// cover.
    #[test]
    fn expand_service_start_vllm_appends_declared_knobs_after_dtype() {
        let ids = IdGen::new();
        let steps = service_start(
            &ids,
            "vllm",
            Some("m"),
            Some(9000),
            Some("bfloat16"),
            Some(4),
            &["--max-model-len=8192"],
        );
        assert_eq!(
            sh_command(&steps[0]),
            "nohup python -m vllm.entrypoints.openai.api_server --model m \
             --port 9000 --dtype bfloat16 --tensor-parallel-size 4 \
             --max-model-len=8192 > /tmp/llm.log 2>&1 & \
             pid=$!; echo $pid > /tmp/llm.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'service llm died immediately' >&2; \
             tail -100 /tmp/llm.log >&2; exit 1; }"
        );
    }

    /// Ollama binds 11434 and reads `OLLAMA_HOST`, so it takes neither
    /// a model nor a port on the command line — a declared `port`
    /// here is ignored (spec 02 §Kinds with a spawn-and-poll invocation
    /// documents this asymmetry).
    #[test]
    fn expand_service_start_ollama_just_serves() {
        let ids = IdGen::new();
        let steps = service_start(&ids, "ollama", None, Some(9999), None, None, &[]);
        assert_eq!(
            sh_command(&steps[0]),
            "nohup ollama serve > /tmp/llm.log 2>&1 & \
             pid=$!; echo $pid > /tmp/llm.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'service llm died immediately' >&2; \
             tail -100 /tmp/llm.log >&2; exit 1; }"
        );
    }

    #[test]
    fn expand_service_start_llamacpp_uses_llama_server() {
        let ids = IdGen::new();
        let steps = service_start(
            &ids,
            "llamacpp",
            Some("/models/q4.gguf"),
            None,
            None,
            None,
            &[],
        );
        assert_eq!(
            sh_command(&steps[0]),
            "nohup llama-server --model /models/q4.gguf > /tmp/llm.log 2>&1 & \
             pid=$!; echo $pid > /tmp/llm.pid; sleep 1; \
             kill -0 $pid 2>/dev/null || { echo 'service llm died immediately' >&2; \
             tail -100 /tmp/llm.log >&2; exit 1; }"
        );
    }

    /// Emitting `--model` with nothing after it would make the next
    /// token the model, launching something the profile never asked
    /// for — so a missing model is reported, not papered over.
    #[test]
    fn expand_service_start_notes_out_when_a_required_model_is_absent() {
        let ids = IdGen::new();
        for platform in ["vllm", "llamacpp"] {
            let steps = service_start(&ids, platform, None, None, None, None, &[]);
            match &steps[0].step {
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
        let steps = service_start(&ids, "tgi", Some("m"), None, None, None, &[]);
        match &steps[0].step {
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
            timeout_sec: None,
        };
        let steps = expand(&payload).expect("service_ready expands");
        assert_eq!(
            effects(&steps),
            vec![Step::HttpPoll {
                url: "http://127.0.0.1:9000/health".to_string(),
                // Engine start-up, not an HTTP round trip, sets this
                // default.
                timeout_sec: SERVICE_READY_TIMEOUT_SEC,
                // The paths `service.start name=llm` wrote — the poll
                // watches the process it is waiting for.
                pid_file: Some("/tmp/llm.pid".to_string()),
                log_path: Some("/tmp/llm.log".to_string()),
            }]
        );
        assert_eq!(SERVICE_READY_TIMEOUT_SEC, 300);
    }

    /// A declared `check.timeout_sec` replaces the kind default in
    /// both directions.
    #[test]
    fn expand_service_ready_honours_a_declared_timeout() {
        let ids = IdGen::new();
        for declared in [15u16, 900] {
            let payload = ProfileNode::ServiceReady {
                id: node_id(&ids),
                name: "llm".to_string(),
                check_url: "http://127.0.0.1:9000/health".to_string(),
                timeout_sec: Some(declared),
            };
            let steps = expand(&payload).expect("service_ready expands");
            assert_eq!(
                effects(&steps),
                vec![Step::HttpPoll {
                    url: "http://127.0.0.1:9000/health".to_string(),
                    timeout_sec: u64::from(declared),
                    pid_file: Some("/tmp/llm.pid".to_string()),
                    log_path: Some("/tmp/llm.log".to_string()),
                }]
            );
        }
    }

    /// The two poll kinds do not share one deadline: a ComfyUI cold
    /// boot and an inference-engine init are different budgets, which
    /// is why the single flat constant they used to share is gone.
    #[test]
    fn the_two_poll_kinds_carry_separate_defaults() {
        let ids = IdGen::new();
        let health = expand(&ProfileNode::ComfyUiHealth {
            id: node_id(&ids),
            port: 8188,
            timeout_sec: None,
        })
        .expect("comfyui_health expands");
        let ready = expand(&ProfileNode::ServiceReady {
            id: node_id(&ids),
            name: "llm".to_string(),
            check_url: "http://127.0.0.1:9000/health".to_string(),
            timeout_sec: None,
        })
        .expect("service_ready expands");
        let deadline = |steps: &[PlannedStep]| match &steps[0].step {
            Step::HttpPoll { timeout_sec, .. } => *timeout_sec,
            other => panic!("expected HttpPoll, got {other:?}"),
        };
        assert_eq!(deadline(&health), 180);
        assert_eq!(deadline(&ready), 300);
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
                dst: "d".into(),
            },
            &no_env
        )
        .starts_with("transfer src=s dst=d"));
        assert_eq!(
            render_dry(
                &Step::HttpPoll {
                    url: "u".into(),
                    timeout_sec: 5,
                    pid_file: None,
                    log_path: None,
                },
                &no_env
            ),
            "http_poll url=u timeout=5s"
        );
        assert!(render_dry(&Step::Note("n".into()), &no_env).starts_with("note "));
    }

    #[test]
    fn render_dry_shows_env_keys_but_not_values_for_a_sh_step() {
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "super-secret".to_string());
        let rendered = render_dry(&Step::Sh(vec!["hf".into()]), &env);
        assert!(
            rendered.contains("env_keys=") && rendered.contains("HF_TOKEN"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("super-secret"),
            "values must be redacted: {rendered}"
        );
    }

    /// A poll wired to a launch shows the pid file it watches: with one
    /// the step can fail for a reason ("the process is gone") that a
    /// bare poll cannot.
    #[test]
    fn render_dry_shows_the_pid_file_a_poll_watches() {
        let no_env = BTreeMap::new();
        let rendered = render_dry(
            &Step::HttpPoll {
                url: "http://127.0.0.1:8188/object_info".into(),
                timeout_sec: 180,
                pid_file: Some("/tmp/comfyui.pid".into()),
                log_path: Some("/tmp/comfyui.log".into()),
            },
            &no_env,
        );
        assert_eq!(
            rendered,
            "http_poll url=http://127.0.0.1:8188/object_info timeout=180s \
             pid_file=/tmp/comfyui.pid"
        );
    }

    // -------------------------------------------------------------
    // The launch script, run by a real `sh`. The composed text is what
    // reaches the pod, so its two load-bearing properties — the pid it
    // records is the server's, and a launch that dies fails the step —
    // are asserted against an actual shell rather than by reading.
    // -------------------------------------------------------------

    /// Write an executable script that records its own pid and then
    /// lingers, standing in for a server that started successfully.
    #[cfg(unix)]
    fn write_server_stub(dir: &std::path::Path, self_pid_path: &std::path::Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("server-stub.sh");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\necho $$ > {}\nsleep 3\n",
                self_pid_path.to_string_lossy()
            ),
        )
        .expect("write server stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        path.to_string_lossy().into_owned()
    }

    /// `$!` must name the server, not a shell that wrapped it — in both
    /// launch shapes, including the `cd … && …` one `comfyui.restart`
    /// composes. A pid belonging to a wrapper exits with the spawn, so
    /// the readiness poll would call every wait a death.
    #[cfg(unix)]
    #[test]
    fn the_launch_script_records_the_pid_of_the_server_itself() {
        for grouping in ["plain", "cd-prefixed"] {
            let dir = scratch_dir("launch-pid");
            let self_pid_path = dir.join("self.pid");
            let stub = write_server_stub(&dir, &self_pid_path);
            let log = dir.join("stub.log");
            let pid_file = dir.join("stub.pid");

            let launch = spawn_detached_command(
                &[stub],
                &log.to_string_lossy(),
                &pid_file.to_string_lossy(),
                "svc",
            );
            let command = match grouping {
                "plain" => launch,
                // What `comfyui.restart` emits around the same text.
                _ => format!("cd {} && {}", dir.to_string_lossy(), grouped(launch)),
            };

            let outcome = std::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .output()
                .expect("run the launch command");
            assert!(
                outcome.status.success(),
                "{grouping} launch failed: {command}\nstderr={}",
                String::from_utf8_lossy(&outcome.stderr)
            );

            let recorded = fs::read_to_string(&pid_file).expect("launch wrote a pid file");
            // The launch command returns as soon as `$!` is recorded; the
            // detached stub writes its own pid asynchronously, so wait for
            // the file instead of racing the read.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let reported = loop {
                match fs::read_to_string(&self_pid_path) {
                    Ok(text) if !text.trim().is_empty() => break text,
                    result => {
                        if std::time::Instant::now() >= deadline {
                            let text = result.expect("the server wrote its pid");
                            panic!("{grouping} stub wrote an empty pid file: {text:?}");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
            };
            assert_eq!(
                recorded.trim(),
                reported.trim(),
                "{grouping} launch recorded a pid that is not the server's"
            );

            fs::remove_dir_all(&dir).ok();
        }
    }

    /// The settle check is what turns "the spawn was accepted" into
    /// "the process survived a second": a command that cannot run at
    /// all fails the launch step, with its log tail on stderr.
    #[cfg(unix)]
    #[test]
    fn the_launch_script_fails_when_the_process_dies_immediately() {
        let dir = scratch_dir("launch-died");
        let log = dir.join("stub.log");
        let pid_file = dir.join("stub.pid");
        let missing = dir.join("no-such-binary").to_string_lossy().into_owned();

        let command = spawn_detached_command(
            &[missing],
            &log.to_string_lossy(),
            &pid_file.to_string_lossy(),
            "svc",
        );
        let outcome = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
            .expect("run the launch command");

        assert_eq!(
            outcome.status.code(),
            Some(1),
            "a launch that cannot start must fail the step"
        );
        let stderr = String::from_utf8_lossy(&outcome.stderr);
        assert!(
            stderr.contains("svc died immediately"),
            "stderr should name the dead launch: {stderr}"
        );
        assert!(
            stderr.contains("not found") || stderr.contains("No such file"),
            "the log tail should carry the shell's own diagnosis: {stderr}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------
    // Died-during-wait detection (liveness probe + poll behaviour).
    // -------------------------------------------------------------

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lm-lifecycle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// A pid with a directory under the procfs root is running; one
    /// without is not. The root is injected so the decision is the same
    /// on a host that has no `/proc`.
    #[test]
    fn probe_liveness_reads_the_pid_file_against_the_proc_root() {
        let dir = scratch_dir("liveness");
        let proc_root = dir.join("proc");
        fs::create_dir_all(proc_root.join("4242")).expect("create fake procfs entry");

        let alive = dir.join("alive.pid");
        fs::write(&alive, "4242\n").expect("write pid file");
        assert_eq!(
            probe_liveness(&alive.to_string_lossy(), &proc_root),
            Liveness::Alive
        );

        let dead = dir.join("dead.pid");
        fs::write(&dead, "4243").expect("write pid file");
        assert_eq!(
            probe_liveness(&dead.to_string_lossy(), &proc_root),
            Liveness::Dead(4243)
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// An absent, empty, or half-written pid file says *nothing* about
    /// the process — the launch writes it a moment after backgrounding
    /// the server, and losing that race must not fail a poll.
    #[test]
    fn probe_liveness_treats_an_unusable_pid_file_as_unknown() {
        let dir = scratch_dir("liveness-unknown");
        let proc_root = dir.join("proc");
        fs::create_dir_all(&proc_root).expect("create fake procfs");

        let absent = dir.join("absent.pid");
        assert_eq!(
            probe_liveness(&absent.to_string_lossy(), &proc_root),
            Liveness::Unknown
        );

        for content in ["", "   ", "not-a-pid"] {
            let path = dir.join("partial.pid");
            fs::write(&path, content).expect("write pid file");
            assert_eq!(
                probe_liveness(&path.to_string_lossy(), &proc_root),
                Liveness::Unknown,
                "content {content:?} must not read as a death"
            );
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// The motivating case: a launch the poll *saw running* disappears
    /// mid-wait, so the poll fails on the next iteration rather than
    /// spending its whole deadline on a socket nobody is listening on.
    /// The launch log travels with the failure.
    #[tokio::test]
    async fn a_poll_fails_at_once_when_a_launch_it_saw_running_disappears() {
        let dir = scratch_dir("died");
        let proc_root = dir.join("proc");
        let procfs_entry = proc_root.join("31337");
        fs::create_dir_all(&procfs_entry).expect("create fake procfs entry");
        let pid_file = dir.join("svc.pid");
        fs::write(&pid_file, "31337").expect("write pid file");
        let log_path = dir.join("svc.log");
        fs::write(
            &log_path,
            "loading weights\nOSError: address already in use\n",
        )
        .expect("write log");

        // The process exits between two poll iterations: the first
        // probe finds it running and arms the check, the second finds
        // it gone.
        let exit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            fs::remove_dir_all(&procfs_entry).expect("the launch exits");
        });

        // A port nothing listens on: every GET fails, so the poll is
        // decided by the liveness probe alone. The deadline is long
        // enough that reaching it would be a visible hang, proving the
        // early return is what ended the wait.
        let started = Instant::now();
        let failure = execute_http_poll_in(
            "http://127.0.0.1:1/health",
            600,
            Some(&pid_file.to_string_lossy()),
            Some(&log_path.to_string_lossy()),
            "service_ready",
            &proc_root,
        )
        .await
        .expect_err("a launch that died during the wait must fail the poll");

        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the poll must not wait out its deadline"
        );
        match &failure.error {
            ExecError::EffectFailed { op, message } => {
                assert_eq!(op, "service_ready");
                assert!(
                    message.contains("process died during readiness wait (pid 31337)"),
                    "{message}"
                );
                assert!(
                    message.contains("OSError: address already in use"),
                    "the launch log tail must ride along: {message}"
                );
            }
            other => panic!("expected EffectFailed, got {other:?}"),
        }

        exit.join().expect("exit thread joins");
        fs::remove_dir_all(&dir).ok();
    }

    /// A pid file that is already dead on the *first* probe is not this
    /// poll's launch dying — a resume profile (a `service.ready` /
    /// `comfyui.health` declared without the launch that pairs with it)
    /// finds whatever an earlier apply left at the well-known path.
    /// Reporting that as a death would fail a profile that never
    /// launched anything, so the poll falls through to its ordinary
    /// timeout.
    #[tokio::test]
    async fn a_stale_pid_file_never_becomes_a_death_verdict() {
        let dir = scratch_dir("stale");
        let proc_root = dir.join("proc");
        // No procfs entry for the pid: dead from the very first probe.
        fs::create_dir_all(&proc_root).expect("create fake procfs");
        let pid_file = dir.join("svc.pid");
        fs::write(&pid_file, "31337").expect("write stale pid file");
        let log_path = dir.join("svc.log");
        fs::write(&log_path, "from a previous apply\n").expect("write log");

        let failure = execute_http_poll_in(
            "http://127.0.0.1:1/health",
            0,
            Some(&pid_file.to_string_lossy()),
            Some(&log_path.to_string_lossy()),
            "service_ready",
            &proc_root,
        )
        .await
        .expect_err("an unreachable URL still fails the poll");
        match &failure.error {
            ExecError::EffectFailed { op, message } => {
                assert_eq!(op, "service_ready");
                assert!(message.contains("timed out after 0s"), "{message}");
                assert!(
                    !message.contains("died"),
                    "a pid never seen alive must not be reported as a death: {message}"
                );
            }
            other => panic!("expected EffectFailed, got {other:?}"),
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// The same stale pid file does not stand between a resume poll and
    /// a server that is already up: the URL answering is the whole
    /// verdict.
    #[tokio::test]
    async fn a_stale_pid_file_does_not_block_a_resume_poll_from_passing() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let dir = scratch_dir("stale-pass");
        let proc_root = dir.join("proc");
        fs::create_dir_all(&proc_root).expect("create fake procfs");
        let pid_file = dir.join("svc.pid");
        fs::write(&pid_file, "31337").expect("write stale pid file");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write response");
        });

        let result = execute_http_poll_in(
            &format!("http://{addr}/health"),
            5,
            Some(&pid_file.to_string_lossy()),
            None,
            "service_ready",
            &proc_root,
        )
        .await
        .expect("a running server must pass regardless of a stale pid file");
        assert_eq!(result.status, 200);

        handle.join().expect("server thread joins");
        fs::remove_dir_all(&dir).ok();
    }

    /// Without a pid file the poll behaves exactly as it did before the
    /// liveness check existed: it waits out its deadline and reports a
    /// timeout.
    #[tokio::test]
    async fn a_poll_without_a_pid_file_still_reports_a_timeout() {
        let failure = execute_http_poll_in(
            "http://127.0.0.1:1/health",
            0,
            None,
            None,
            "comfyui_health",
            Path::new("/nonexistent-proc"),
        )
        .await
        .expect_err("an unreachable URL must fail the poll");
        match &failure.error {
            ExecError::EffectFailed { op, message } => {
                assert_eq!(op, "comfyui_health");
                assert!(message.contains("timed out after 0s"), "{message}");
                assert!(
                    !message.contains("died"),
                    "no pid file means no death verdict: {message}"
                );
            }
            other => panic!("expected EffectFailed, got {other:?}"),
        }
    }

    /// A live launch that answers 2xx succeeds — the liveness probe
    /// only runs on iterations where the server did not answer, so a
    /// ready server is never second-guessed.
    #[tokio::test]
    async fn a_poll_succeeds_when_the_server_answers_while_its_pid_is_live() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let dir = scratch_dir("alive");
        let proc_root = dir.join("proc");
        // The running process is this test itself.
        let pid = std::process::id();
        fs::create_dir_all(proc_root.join(pid.to_string())).expect("create fake procfs entry");
        let pid_file = dir.join("svc.pid");
        fs::write(&pid_file, pid.to_string()).expect("write pid file");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write response");
        });

        let result = execute_http_poll_in(
            &format!("http://{addr}/health"),
            5,
            Some(&pid_file.to_string_lossy()),
            None,
            "service_ready",
            &proc_root,
        )
        .await
        .expect("a live server answering 200 must pass");
        assert_eq!(result.status, 200);

        handle.join().expect("server thread joins");
        fs::remove_dir_all(&dir).ok();
    }

    /// The production entry point resolves the procfs root itself
    /// ([`PROC_ROOT`]) — this drives that call path end to end with a
    /// pid no process can hold, which is the resume shape: never seen
    /// alive, so never fatal, and the step ends as an ordinary timeout.
    ///
    /// The armed transition cannot be driven portably here (a host
    /// without `/proc` reads every pid as dead), so the fatal branch is
    /// covered against an injected root by
    /// `a_poll_fails_at_once_when_a_launch_it_saw_running_disappears`.
    #[tokio::test]
    async fn the_real_poll_entry_point_reads_liveness_from_the_host_procfs() {
        let dir = scratch_dir("real-proc");
        let pid_file = dir.join("svc.pid");
        // Above every platform's pid_max, so no process can hold it.
        fs::write(&pid_file, "4194305").expect("write pid file");

        let failure = execute_http_poll(
            "http://127.0.0.1:1/health",
            0,
            Some(&pid_file.to_string_lossy()),
            None,
            "service_ready",
        )
        .await
        .expect_err("an unreachable URL must fail the poll");
        let message = failure.error.to_string();
        assert!(message.contains("timed out after 0s"), "{message}");
        assert!(
            !message.contains("died"),
            "a pid this poll never saw alive must not read as a death: {message}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------
    // execute_step: a failing step carries its partial observation.
    // -------------------------------------------------------------

    #[tokio::test]
    async fn a_non_zero_sh_exit_carries_its_exit_code_and_captured_output() {
        let step = PlannedStep::always(Step::Sh(vec![
            "sh".into(),
            "-c".into(),
            "echo out-before-failing; echo err-before-failing 1>&2; exit 7".into(),
        ]));
        let failure = execute_step(&step, "post_install", &BTreeMap::new())
            .await
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

    // -------------------------------------------------------------
    // A step's `done`: what gets skipped, and what does not.
    //
    // These drive `execute_step` rather than a whole profile, because
    // a `models` phase composes its destination under the built-in
    // `/workspace/ComfyUI/models` root, which a test cannot write to.
    // The step is what the skip is decided on, so it is what is
    // exercised; that the phase builds this step with this condition
    // is `expand_models_carries_a_declared_digest_into_the_step_condition`.
    // -------------------------------------------------------------

    /// A local HTTP server that answers every request with `body`,
    /// counting how many it served.
    ///
    /// The count is the point: "the second apply did not download it
    /// again" is a statement about requests, and asserting it on the
    /// destination's contents alone would pass for a re-download that
    /// wrote the same bytes.
    ///
    /// The thread is deliberately not joined. A skip means the server
    /// is never asked, so a `join` would wait on an `accept` that is
    /// not coming — the test would hang exactly when it is supposed to
    /// pass. It ends with the test binary.
    fn serving_local_server(body: &'static [u8]) -> (String, std::sync::Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let addr = listener.local_addr().expect("local addr");
        let served = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&served);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(header.as_bytes()).is_err() || stream.write_all(body).is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        (format!("http://{addr}/payload.bin"), served)
    }

    fn transfer_step(src: &str, dst: &std::path::Path, sha256: Option<String>) -> PlannedStep {
        PlannedStep::done_when(
            Step::Transfer {
                src: src.to_string(),
                dst: dst.to_string_lossy().into_owned(),
            },
            assert::ModelFile::new(dst, sha256).done(),
        )
    }

    /// The UC this stage exists for: **a second apply does not download
    /// the weight again.** The first call transfers, the second finds
    /// the declared digest already satisfied and skips — and says which
    /// parts of the condition were true when it did.
    ///
    /// Multi-threaded flavour because the transfer's own client wants a
    /// reactor turning beside it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_declared_digest_skips_the_second_transfer() {
        const BODY: &[u8] = b"model weights";
        let dir = scratch_dir("skip-on-digest");
        let dst = dir.join("weights.safetensors");
        let (url, served) = serving_local_server(BODY);
        let step = transfer_step(&url, &dst, Some(crate::digest::hex_sha256(BODY)));
        let env = BTreeMap::new();

        let first = execute_step(&step, "models", &env)
            .await
            .expect("the first apply downloads");
        assert_eq!(first.bytes, Some(BODY.len() as u64));
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read(&dst).expect("destination written"), BODY);

        let second = execute_step(&step, "models", &env)
            .await
            .expect("the second apply skips");
        assert_eq!(
            served.load(Ordering::SeqCst),
            1,
            "the second apply must not ask the server again",
        );
        assert_eq!(second.bytes, None, "nothing was transferred");

        // …and the skip says what was true, rather than Chef's bare
        // `(skipped due to not_if)` (design §3.8).
        let note = second.note.expect("a skipped step carries a note");
        assert!(note.starts_with("skipped, already done: "), "{note}");
        assert!(
            note.contains(&format!("exists({})=satisfied", dst.display())),
            "the existence conjunct's answer is in the note: {note}",
        );
        assert!(
            note.contains("=satisfied]=satisfied"),
            "so is the digest conjunct's, and the conjunction's: {note}",
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// The other half: a destination whose content does not match the
    /// declared digest is **not** skipped. Present-but-different is a
    /// different thing, not the same thing (design §3.6).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_digest_mismatch_transfers_again() {
        const BODY: &[u8] = b"model weights";
        let dir = scratch_dir("mismatch");
        let dst = dir.join("weights.safetensors");
        let (url, served) = serving_local_server(BODY);
        let step = transfer_step(&url, &dst, Some(crate::digest::hex_sha256(BODY)));
        let env = BTreeMap::new();

        execute_step(&step, "models", &env)
            .await
            .expect("the first apply downloads");
        fs::write(&dst, b"truncated or tampered").expect("overwrite the destination");

        let second = execute_step(&step, "models", &env)
            .await
            .expect("a mismatching destination must be downloaded again");
        assert_eq!(served.load(Ordering::SeqCst), 2);
        assert_eq!(second.bytes, Some(BODY.len() as u64));
        assert_eq!(fs::read(&dst).expect("destination rewritten"), BODY);

        // The condition still reports, so a report reader can see *why*
        // it ran: the file was there and the content was not.
        let note = second.note.expect("an executed step reports its condition");
        assert!(note.starts_with("not done: "), "{note}");
        assert!(
            note.contains("=satisfied") && note.contains("=unsatisfied"),
            "existence held, content did not: {note}",
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// With no declared digest the condition is existence alone, so a
    /// destination that is present — whatever it contains — is skipped.
    ///
    /// This is the honest consequence of a profile that names no
    /// digest, not a defect: a half-written file from an interrupted
    /// download exists too. Declaring `sha256` is what buys the
    /// stronger identity.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_declared_digest_existence_alone_decides() {
        const BODY: &[u8] = b"model weights";
        let dir = scratch_dir("existence-only");
        let dst = dir.join("weights.safetensors");
        fs::write(&dst, b"something else entirely").expect("pre-existing destination");
        let (url, served) = serving_local_server(BODY);
        let step = transfer_step(&url, &dst, None);

        let result = execute_step(&step, "models", &BTreeMap::new())
            .await
            .expect("the step decides");

        assert_eq!(served.load(Ordering::SeqCst), 0, "nothing was downloaded");
        let note = result.note.expect("a skipped step carries a note");
        assert_eq!(
            note,
            format!("skipped, already done: exists({})=satisfied", dst.display()),
            "one predicate, no conjunction around it",
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------
    // `Checkout`: the second apply, against a real repository.
    //
    // These run `git` rather than a fixed-response observer. The
    // predicate's whole content is what git's exit status means, so a
    // test that supplied that status itself would be checking the
    // mapping and nothing else — and the failure this stage exists to
    // remove (a `git clone` onto an existing directory) is git's
    // behaviour, not this crate's.
    //
    // Nothing here reaches the network: the clone source is a local
    // repository the test builds. `git` not being installed fails these
    // loudly rather than skipping them — a skip would report green for
    // an unverified feature.
    // -------------------------------------------------------------

    /// Run `argv` and require it to succeed.
    fn git_ok(argv: &[&str]) {
        let argv: Vec<String> = argv.iter().map(|arg| arg.to_string()).collect();
        let outcome = effects::sh_exec(&argv, &effects::ShOpts::default())
            .unwrap_or_else(|err| panic!("these tests require git on PATH: {err}"));
        assert_eq!(
            outcome.exit_code, 0,
            "{argv:?} failed: {}",
            outcome.stderr_tail
        );
    }

    /// A local source repository with two commits whose **contents
    /// differ**, tagged `v1` and `v2`.
    ///
    /// The contents have to differ: the condition compares what two
    /// refs name, so two commits with identical trees would answer
    /// "finished" for either tag and the ref half of the test would
    /// prove nothing.
    ///
    /// Returns `(scratch dir, source repo, clone destination)`; the
    /// destination does not exist yet.
    fn source_repo(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = scratch_dir(tag);
        let src = dir.join("source");
        let src_text = src.to_string_lossy().into_owned();
        fs::create_dir_all(&src).expect("create the source repo dir");
        git_ok(&["git", "init", "-q", "-b", "main", &src_text]);
        for (content, tag) in [("one", "v1"), ("two", "v2")] {
            fs::write(src.join("file.txt"), content).expect("write the tracked file");
            git_ok(&["git", "-C", &src_text, "add", "file.txt"]);
            git_ok(&[
                "git",
                "-C",
                &src_text,
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-q",
                "-m",
                content,
            ]);
            git_ok(&["git", "-C", &src_text, "tag", tag]);
        }
        (dir.clone(), src, dir.join("clone"))
    }

    /// The step `comfyui.install` composes, with the destination and
    /// source substituted — one `sh -c` that clones and checks out,
    /// guarded by the whole `Checkout`.
    fn clone_step(src: &std::path::Path, dst: &std::path::Path, git_ref: &str) -> PlannedStep {
        let script = format!(
            "git clone -q {src} {dst} && git -C {dst} checkout -q {git_ref}",
            src = src.display(),
            dst = dst.display(),
        );
        PlannedStep::done_when(
            Step::Sh(vec!["sh".to_string(), "-c".to_string(), script]),
            assert::Checkout::new(dst, Some(git_ref.to_string())).done(),
        )
    }

    /// **The UC of this stage: a second apply does not fail on the
    /// clone.**
    ///
    /// The same test also shows what it is protecting against — the
    /// identical command without the condition fails the second time,
    /// which is the `git clone` refusing a destination that already
    /// exists (design §4.4).
    #[tokio::test]
    async fn a_second_apply_skips_the_clone_instead_of_failing_on_it() {
        let (dir, src, dst) = source_repo("checkout-second-apply");
        let step = clone_step(&src, &dst, "v1");
        let env = BTreeMap::new();

        let first = execute_step(&step, "comfyui_install", &env)
            .await
            .expect("the first apply clones");
        assert!(dst.join(".git").is_dir(), "the repository was cloned");
        assert_eq!(fs::read_to_string(dst.join("file.txt")).unwrap(), "one");
        let note = first.note.expect("an executed step reports its condition");
        assert!(note.starts_with("not done: "), "{note}");

        let second = execute_step(&step, "comfyui_install", &env)
            .await
            .expect("the second apply skips rather than failing");
        let note = second.note.expect("a skipped step carries a note");
        assert!(note.starts_with("skipped, already done: "), "{note}");
        assert!(
            note.contains(&format!("exists({}/.git)=satisfied", dst.display()))
                && note.contains(&format!("git_tree({})=v1=satisfied", dst.display())),
            "the skip says which halves were true: {note}",
        );

        // And the same command *without* the condition is exactly the
        // failure this stage removes.
        let unguarded = PlannedStep::always(step.step.clone());
        let failure = execute_step(&unguarded, "comfyui_install", &env)
            .await
            .expect_err("an unguarded second clone fails");
        assert_eq!(failure.observed.status, 128, "git refused the destination");

        fs::remove_dir_all(&dir).ok();
    }

    /// **The completion is not "the directory is there".** With the
    /// clone already at `v1`, a step that asks for `v2` is not
    /// satisfied — same directory, different answer — and running it
    /// makes it satisfied.
    ///
    /// The `v1` condition is checked alongside on the same host, so the
    /// two answers differ by the ref alone.
    #[tokio::test]
    async fn a_different_ref_is_not_finished_even_though_the_directory_is_there() {
        let (dir, src, dst) = source_repo("checkout-other-ref");
        let env = BTreeMap::new();
        execute_step(&clone_step(&src, &dst, "v1"), "comfyui_install", &env)
            .await
            .expect("the first apply clones at v1");

        let at_v1 = assert::Checkout::new(&dst, Some("v1".to_string())).done();
        let at_v2 = assert::Checkout::new(&dst, Some("v2".to_string())).done();
        assert!(
            assert::eval(&at_v1, ExecMode::Real, &LocalObserve)
                .await
                .is_satisfied(),
            "the clone is at v1",
        );
        assert!(
            !assert::eval(&at_v2, ExecMode::Real, &LocalObserve)
                .await
                .is_satisfied(),
            "…and therefore not at v2, though the directory exists either way",
        );

        // The checkout step `custom_nodes` composes, guarded the same
        // way: it runs, because the ref is not out yet.
        let checkout = PlannedStep::done_when(
            Step::Sh(vec![
                "git".to_string(),
                "-C".to_string(),
                dst.to_string_lossy().into_owned(),
                "checkout".to_string(),
                "-q".to_string(),
                "v2".to_string(),
            ]),
            at_v2.clone(),
        );
        let ran = execute_step(&checkout, "custom_nodes", &env)
            .await
            .expect("the checkout runs");
        assert!(ran
            .note
            .expect("a condition is reported")
            .starts_with("not done: "));
        assert_eq!(fs::read_to_string(dst.join("file.txt")).unwrap(), "two");
        assert!(
            assert::eval(&at_v2, ExecMode::Real, &LocalObserve)
                .await
                .is_satisfied(),
            "running the step is what makes its condition true",
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// **A dry run answers the clone**, in the words §(2) settled on:
    /// `Unsatisfied` / `Satisfied`, never `NotChecked`.
    ///
    /// This is the whole payoff of evaluating the command predicate in
    /// both modes. A `plan` run against a fresh pod says "would run" for
    /// the install and, run again after the apply, says "would skip" —
    /// neither of which a `NotChecked` could have said.
    ///
    /// The dry run must also **not clone anything**, which is checked
    /// on the destination before the real apply happens.
    #[tokio::test]
    async fn a_dry_run_decides_the_clone_in_both_directions() {
        let (dir, src, dst) = source_repo("checkout-dry-run");
        let step = clone_step(&src, &dst, "v1");
        let no_env = BTreeMap::new();

        let before = dry_run_step(&step, &no_env).await;
        let note = before.note.expect("a step with a condition answers");
        assert!(
            note.starts_with("would run, not done: "),
            "an absent repository is decided, not undecided: {note}",
        );
        assert!(
            !note.contains("not-checked"),
            "nothing in a Checkout goes unread in a dry run: {note}",
        );
        assert!(
            !dst.exists(),
            "answering the condition must not clone anything",
        );

        execute_step(&step, "comfyui_install", &no_env)
            .await
            .expect("the apply clones");

        let after = dry_run_step(&step, &no_env).await;
        assert_eq!(
            after.note.as_deref(),
            Some(
                format!(
                    "would skip, already done: all[exists({dst}/.git)=satisfied, \
                     git_tree({dst})=v1=satisfied]=satisfied",
                    dst = dst.display(),
                )
                .as_str()
            ),
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// **A dry run now answers the condition**, and the two answers it
    /// can give about a `sha256`-carrying entry are different sentences
    /// about the host — which is the whole point of evaluating it.
    ///
    /// Both entries here declare a digest, so the digest conjunct is
    /// `NotChecked` in both. What separates them is existence:
    ///
    /// - the absent destination folds to `Unsatisfied` — **this one
    ///   transfers**, and a dry run can say so;
    /// - the present destination folds to `NotChecked` — undecided,
    ///   because deciding it would mean reading the whole file.
    #[tokio::test]
    async fn a_dry_run_answers_the_condition_and_tells_the_two_apart() {
        let dir = scratch_dir("dry-run-verdicts");
        let present = dir.join("present.safetensors");
        let absent = dir.join("absent.safetensors");
        fs::write(&present, b"weights").expect("write the present destination");
        let digest = crate::digest::hex_sha256(b"weights");
        let no_env = BTreeMap::new();

        let will_transfer = dry_run_step(
            &transfer_step("https://ex/a.bin", &absent, Some(digest.clone())),
            &no_env,
        )
        .await;
        let note = will_transfer.note.expect("a step with a condition answers");
        assert!(
            note.starts_with("would transfer, not done: "),
            "an absent destination is decided, not undecided: {note}",
        );
        assert!(
            note.contains(&format!("exists({})=unsatisfied", absent.display()))
                && note.contains("=not-checked"),
            "the existence conjunct decided it while the digest stayed unread: {note}",
        );

        let undecided = dry_run_step(
            &transfer_step("https://ex/b.bin", &present, Some(digest.clone())),
            &no_env,
        )
        .await;
        let note = undecided.note.expect("a step with a condition answers");
        assert!(
            note.starts_with("undecided (not evaluated in a dry run), would transfer: "),
            "a present destination cannot be decided without reading it: {note}",
        );
        assert!(
            note.contains(&format!("exists({})=satisfied", present.display()))
                && note.contains(&digest),
            "…and says what it did see, and what it would have compared: {note}",
        );

        // Without a digest the condition is existence alone, which *is*
        // answerable in a dry run — so a present destination is a
        // decided skip rather than an undecided one.
        let decided_skip =
            dry_run_step(&transfer_step("https://ex/c.bin", &present, None), &no_env).await;
        assert_eq!(
            decided_skip.note.as_deref(),
            Some(
                format!(
                    "would skip, already done: exists({})=satisfied",
                    present.display()
                )
                .as_str()
            ),
        );

        // A step with no condition has no answer to report.
        assert_eq!(
            dry_run_step(
                &PlannedStep::always(Step::Transfer {
                    src: "s".into(),
                    dst: "d".into(),
                }),
                &no_env,
            )
            .await,
            DryStep {
                summary: "transfer src=s dst=d".to_string(),
                note: None,
            },
        );
        assert_eq!(
            dry_run_step(&PlannedStep::always(Step::Sh(vec!["ls".into()])), &no_env)
                .await
                .note,
            None
        );

        fs::remove_dir_all(&dir).ok();
    }
}
