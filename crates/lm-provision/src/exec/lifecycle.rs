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
//! has no `force_reinstall`, and so on). `SyncPull` / `StagingPush` now
//! carry an `env` keyed slot and a `revision` (step ②), but the
//! exec-time consumption of those fields — env-routed CLI dispatch,
//! spec 02 §Dispatch routing — is deferred to step ③. So:
//!
//! - Fields with a defensible built-in default are constant-substituted
//!   (`PythonDeps.in_comfy_venv=false` → the system `pip` on `PATH`;
//!   `ComfyUiInstall.repo=None` → `comfyanonymous/ComfyUI`; a `models`
//!   entry with no `subdir`/`kind` → `checkpoints`).
//! - Ops whose invocation cannot be constructed from the AST fields
//!   alone (`ComfyUiRestart`, `ServiceStart`) expand to a single
//!   [`Step::Note`] recording that fact, rather than inventing an argv.
//! - `SyncPull` with a non-empty `env`, a `b2://` / `hf://` src, and
//!   `StagingPush` (always) return [`ExecError::Unsupported`]: all need
//!   the env-routed CLI dispatch documented in spec 02 §Dispatch
//!   routing. A `SyncPull` whose `env` is empty keeps its prior
//!   behaviour (an `https://` src maps to a plain download).

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
        ProfileNode::StagingPush { src, dst, .. } => Err(ExecError::Unsupported(format!(
            "staging_push '{src}' -> '{dst}': requires env-routed CLI dispatch; \
             pending exec env injection (spec 02 dispatch routing)"
        ))),
        ProfileNode::Models { models_json, .. } => expand_models(models_json),
        ProfileNode::LlmModels { models_json, .. } => expand_llm_models(models_json),
        ProfileNode::PostInstall { script, .. } => Ok(vec![Step::Sh(vec![
            "sh".to_string(),
            "-c".to_string(),
            script.clone(),
        ])]),
        ProfileNode::ComfyUiRestart { port, .. } => Ok(vec![Step::Note(format!(
            "comfyui_restart port={port}: restart argv unsupported \
             pending AST extension"
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

fn expand_sync_pull(
    src: &str,
    dst: &str,
    env: &std::collections::BTreeMap<String, ProfileNode>,
) -> Result<Vec<Step>, ExecError> {
    // A non-empty `env` needs env-routed CLI dispatch, which the exec
    // layer does not yet implement (step ③). Fail loudly rather than
    // silently dropping the injection.
    if !env.is_empty() {
        return Err(ExecError::Unsupported(format!(
            "sync_pull '{src}': env injection not yet implemented; \
             pending exec env injection (spec 02 dispatch routing)"
        )));
    }
    if src.starts_with("b2://") || src.starts_with("hf://") {
        return Err(ExecError::Unsupported(format!(
            "sync_pull '{src}': requires env-routed CLI dispatch; \
             pending exec env injection (spec 02 dispatch routing)"
        )));
    }
    Ok(vec![Step::Transfer {
        src: src.to_string(),
        dst: dst.to_string(),
    }])
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
/// or network.
pub fn render_dry(step: &Step) -> String {
    match step {
        Step::Sh(argv) => format!("sh argv={argv:?}"),
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
/// error carries the op that ran.
pub fn execute_step(step: &Step, op: &str) -> Result<String, ExecError> {
    match step {
        Step::Sh(argv) => execute_sh(argv, op),
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

fn execute_sh(argv: &[String], op: &str) -> Result<String, ExecError> {
    let outcome = effects::sh_exec(argv, &effects::ShOpts)?;
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
    fn expand_sync_pull_rejects_a_b2_source_as_unsupported() {
        let ids = IdGen::new();
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "b2://bucket/model.safetensors".to_string(),
            dst: "/workspace/model.safetensors".to_string(),
            env: Default::default(),
            revision: None,
        };
        let err = expand(&payload).expect_err("b2:// must be unsupported");
        match err {
            ExecError::Unsupported(msg) => {
                assert!(msg.contains("env-routed CLI dispatch"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn expand_sync_pull_with_a_non_empty_env_is_unsupported() {
        let ids = IdGen::new();
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "B2_KEY".to_string(),
            ProfileNode::EnvSecret {
                id: node_id(&ids),
                name: "B2_KEY".to_string(),
            },
        );
        // Even an otherwise-downloadable https src must fail while exec
        // env injection is pending (step ③).
        let payload = ProfileNode::SyncPull {
            id: node_id(&ids),
            src: "https://example.com/m.bin".to_string(),
            dst: "/workspace/m.bin".to_string(),
            env,
            revision: None,
        };
        let err = expand(&payload).expect_err("non-empty env must be unsupported");
        match err {
            ExecError::Unsupported(msg) => {
                assert!(msg.contains("env injection not yet implemented"), "{msg}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
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
    fn expand_staging_push_is_unsupported_pending_the_ast_env_extension() {
        let ids = IdGen::new();
        let payload = ProfileNode::StagingPush {
            id: node_id(&ids),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo".to_string(),
            env: Default::default(),
            revision: None,
        };
        let err = expand(&payload).expect_err("staging_push must be unsupported");
        match err {
            ExecError::Unsupported(msg) => {
                assert!(msg.contains("env-routed CLI dispatch"));
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
                assert!(msg.contains("pending AST extension"));
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
        assert!(render_dry(&Step::Sh(vec!["ls".into()])).starts_with("sh argv="));
        assert!(render_dry(&Step::Transfer {
            src: "s".into(),
            dst: "d".into()
        })
        .starts_with("transfer src=s dst=d"));
        assert!(render_dry(&Step::HttpPoll {
            url: "u".into(),
            timeout_sec: 5
        })
        .starts_with("http_poll url=u timeout=5s"));
        assert!(render_dry(&Step::Note("n".into())).starts_with("note "));
    }
}
