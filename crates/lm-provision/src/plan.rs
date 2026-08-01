//! Expand a [`ProfileNode`] AST into the ordered plan artifact
//! (`03-pipeline-stage-artifacts.md` §plan).
//!
//! Respecified from the legacy Lua `lm.plan.expand` onto the typed
//! AST: buckets, ordering, per-declaration `service.*` indexing, the
//! `python.version_check` default-value suppression rule, the
//! `sync.routes` plan-internal bundle, the implicit `comfyui.restart` /
//! `comfyui.health` insertion, and the trailing `zz_unknown` bucket
//! are ported 1:1 from `lua/lm/plan.lua`.
//!
//! Unlike [`crate::canonical`], this stage is **not** hash-sensitive:
//! declared lists inside each phase's payload keep their declaration
//! order (canonical sorts them for the hash-parity guarantee; plan
//! preserves them). JSON object key order is `serde_json::Map`'s
//! insertion order and is semantically insignificant
//! (`03-pipeline-stage-artifacts.md` §Stability: "plan artifact shape
//! ... stable" — key order is not part of the shape).
//!
//! The output has no `schema` field: the typed AST carries no schema
//! marker, and downstream stages read `profile_name` / `steps` only.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::profile_ast::ProfileNode;

/// Default port used when [`crate::profile_ast::ProfileNode::ComfyUiRestart`]
/// or [`crate::profile_ast::ProfileNode::ComfyUiHealth`] is implicitly
/// inserted (`02-phase-catalog.md` §Canonical phase ordering).
const DEFAULT_COMFYUI_PORT: u16 = 8188;

/// Default `want` value that suppresses the
/// [`crate::profile_ast::ProfileNode::PythonVersionCheck`] step
/// (`02-phase-catalog.md` §Catalog kinds `python.version_check`).
const DEFAULT_PYTHON_VERSION_WANT: &str = "3.12";

/// Expand `root` into the ordered plan artifact.
///
/// Returns a [`serde_json::Value`] shaped as
/// `{ profile_name, steps: [ { index, id, kind, payload }, ... ] }`,
/// ready to pretty-print. When `root` is not a
/// [`ProfileNode::Spec`] the artifact carries an empty `profile_name`
/// and no steps: the frontend only ever hands a `Spec` root here, so
/// the fallback is a total-function convenience rather than an
/// exercised path.
pub fn expand(root: &ProfileNode) -> Value {
    let (profile_name, phases) = match root {
        ProfileNode::Spec { name, phases, .. } => (name.as_str(), phases.as_slice()),
        _ => ("", [].as_slice()),
    };

    let steps = build_steps(phases);
    let mut top = Map::new();
    top.insert("profile_name".into(), Value::String(profile_name.into()));
    top.insert("steps".into(), Value::Array(steps));
    Value::Object(top)
}

/// Iterate `phases` once, bucketing by canonical id / handling the
/// content-sensitive rules, then emit steps in the fixed canonical
/// order (`02-phase-catalog.md` §Canonical phase ordering) with a
/// 1-based contiguous `index`.
fn build_steps(phases: &[ProfileNode]) -> Vec<Value> {
    let mut buckets = Buckets::default();
    let mut service_steps: Vec<(String, &'static str, Value)> = Vec::new();
    let mut zz: Vec<(&'static str, Value)> = Vec::new();

    let mut next_service_index: u32 = 0;
    let mut current_service_index: u32 = 0;

    for phase in phases {
        match phase {
            ProfileNode::SystemApt { .. } => buckets.system_apt.push(phase),
            ProfileNode::ComfyUiInstall { .. } => buckets.comfyui_install.push(phase),
            ProfileNode::PythonVersionCheck { .. } => buckets.python_version_check.push(phase),
            ProfileNode::PythonDeps { .. } => buckets.python_deps.push(phase),
            ProfileNode::CustomNodes { .. } => buckets.custom_nodes.push(phase),
            ProfileNode::SyncPull { .. } => buckets.sync_pull.push(phase),
            ProfileNode::SyncPush { .. } => buckets.sync_push.push(phase),
            ProfileNode::StagingPush { .. } => buckets.staging_push.push(phase),
            ProfileNode::Models { .. } => buckets.models.push(phase),
            ProfileNode::LlmModels { .. } => buckets.llm_models.push(phase),
            ProfileNode::PostInstall { .. } => buckets.post_install.push(phase),
            ProfileNode::ComfyUiRestart { .. } => buckets.comfyui_restart.push(phase),
            ProfileNode::ComfyUiHealth { .. } => buckets.comfyui_health.push(phase),
            ProfileNode::ServiceStart { .. } => {
                let idx = next_service_index;
                next_service_index += 1;
                current_service_index = idx;
                service_steps.push((
                    format!("11_service_{idx}_start"),
                    kind_of(phase),
                    payload_of(phase),
                ));
            }
            ProfileNode::ServiceReady { .. } => {
                let idx = current_service_index;
                service_steps.push((
                    format!("11_service_{idx}_ready"),
                    kind_of(phase),
                    payload_of(phase),
                ));
            }
            // Direct-operation kinds land in the trailing `zz_unknown`
            // bucket in declaration order (`02-phase-catalog.md`
            // §Canonical phase ordering). The typed AST has no
            // truly-unknown variant, so this arm covers every
            // direct-op kind exhaustively.
            ProfileNode::ShExec { .. }
            | ProfileNode::FsWrite { .. }
            | ProfileNode::NetHttpGet { .. }
            | ProfileNode::NetHttpPost { .. }
            | ProfileNode::NetTransfer { .. }
            | ProfileNode::MountBind { .. }
            | ProfileNode::MountUmount { .. } => {
                zz.push((kind_of(phase), payload_of(phase)));
            }
            // A `Spec` variant nested inside `phases`, or an `Env*`
            // value node appearing outside its `env` slot, is a
            // malformed AST the frontend does not produce; skip rather
            // than panic to keep [`expand`] total.
            ProfileNode::Spec { .. }
            | ProfileNode::EnvLiteral { .. }
            | ProfileNode::EnvSecret { .. }
            | ProfileNode::EnvRef { .. } => {}
        }
    }

    let mut steps: Vec<Value> = Vec::new();

    // 1_system_apt
    for p in &buckets.system_apt {
        steps.push(step_value("1_system_apt", kind_of(p), payload_of(p)));
    }
    // 2_comfyui_install
    for p in &buckets.comfyui_install {
        steps.push(step_value("2_comfyui_install", kind_of(p), payload_of(p)));
    }
    // 3a_python_version_check — suppressed when `want == "3.12"`.
    for p in &buckets.python_version_check {
        if let ProfileNode::PythonVersionCheck { want, .. } = p {
            if want != DEFAULT_PYTHON_VERSION_WANT {
                steps.push(step_value(
                    "3a_python_version_check",
                    kind_of(p),
                    payload_of(p),
                ));
            }
        }
    }
    // 3_python_deps
    for p in &buckets.python_deps {
        steps.push(step_value("3_python_deps", kind_of(p), payload_of(p)));
    }
    // 4_custom_nodes
    for p in &buckets.custom_nodes {
        steps.push(step_value("4_custom_nodes", kind_of(p), payload_of(p)));
    }
    // 5_sync_routes — bundle sync.pull / sync.push / staging.push
    // into a single plan-internal step, only when at least one of
    // them is present.
    if !buckets.sync_pull.is_empty()
        || !buckets.sync_push.is_empty()
        || !buckets.staging_push.is_empty()
    {
        let payload = json!({
            "pull": buckets.sync_pull.iter().map(|p| payload_of(p)).collect::<Vec<_>>(),
            "push_markers": buckets.sync_push.iter().map(|p| payload_of(p)).collect::<Vec<_>>(),
            "staging_push": buckets.staging_push.iter().map(|p| payload_of(p)).collect::<Vec<_>>(),
        });
        steps.push(step_value("5_sync_routes", "sync.routes", payload));
    }
    // 7_models
    for p in &buckets.models {
        steps.push(step_value("7_models", kind_of(p), payload_of(p)));
    }
    // 7b_llm_models
    for p in &buckets.llm_models {
        steps.push(step_value("7b_llm_models", kind_of(p), payload_of(p)));
    }
    // 8_post_install
    for p in &buckets.post_install {
        steps.push(step_value("8_post_install", kind_of(p), payload_of(p)));
    }
    // 9_comfyui_restart / 10_comfyui_health, with implicit insertion
    // when `comfyui.install` is declared (`02` §Canonical phase
    // ordering: "when comfyui.install is present and the user did not
    // declare comfyui.restart / comfyui.health, both are inserted with
    // the default port (or the port carried by whichever of the two
    // the user did declare)").
    let (restart_payloads, health_payloads) = resolve_comfyui_lifecycle(&buckets);
    for payload in restart_payloads {
        steps.push(step_value("9_comfyui_restart", "comfyui.restart", payload));
    }
    for payload in health_payloads {
        steps.push(step_value("10_comfyui_health", "comfyui.health", payload));
    }

    // 11_service_<N>_start / 11_service_<N>_ready
    for (id, kind, payload) in service_steps {
        steps.push(step_value(&id, kind, payload));
    }

    // zz_unknown — trailing bucket, declaration order.
    for (kind, payload) in zz {
        steps.push(step_value("zz_unknown", kind, payload));
    }

    // 1-based contiguous index in emission order.
    for (i, step) in steps.iter_mut().enumerate() {
        if let Value::Object(map) = step {
            map.insert("index".into(), Value::from((i + 1) as u64));
        }
    }

    steps
}

// ---------------------------------------------------------------------
// Bucket state
// ---------------------------------------------------------------------

#[derive(Default)]
struct Buckets<'a> {
    system_apt: Vec<&'a ProfileNode>,
    comfyui_install: Vec<&'a ProfileNode>,
    python_version_check: Vec<&'a ProfileNode>,
    python_deps: Vec<&'a ProfileNode>,
    custom_nodes: Vec<&'a ProfileNode>,
    sync_pull: Vec<&'a ProfileNode>,
    sync_push: Vec<&'a ProfileNode>,
    staging_push: Vec<&'a ProfileNode>,
    models: Vec<&'a ProfileNode>,
    llm_models: Vec<&'a ProfileNode>,
    post_install: Vec<&'a ProfileNode>,
    comfyui_restart: Vec<&'a ProfileNode>,
    comfyui_health: Vec<&'a ProfileNode>,
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn step_value(id: &str, kind: &str, payload: Value) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::String(id.into()));
    m.insert("kind".into(), Value::String(kind.into()));
    m.insert("payload".into(), payload);
    Value::Object(m)
}

/// Resolve the effective restart / health payload lists after the
/// implicit-insertion rule fires.
///
/// Each returned `Vec<Value>` is the list of payload objects the
/// caller then wraps into `9_comfyui_restart` / `10_comfyui_health`
/// steps.
fn resolve_comfyui_lifecycle(buckets: &Buckets<'_>) -> (Vec<Value>, Vec<Value>) {
    let mut restart: Vec<Value> = buckets
        .comfyui_restart
        .iter()
        .map(|p| payload_of(p))
        .collect();
    let mut health: Vec<Value> = buckets
        .comfyui_health
        .iter()
        .map(|p| payload_of(p))
        .collect();

    if buckets.comfyui_install.is_empty() {
        return (restart, health);
    }

    if restart.is_empty() && health.is_empty() {
        restart.push(json!({ "port": DEFAULT_COMFYUI_PORT }));
        health.push(json!({ "port": DEFAULT_COMFYUI_PORT }));
    } else if restart.is_empty() {
        let port = port_from_payload(&health[0]).unwrap_or(DEFAULT_COMFYUI_PORT);
        restart.push(json!({ "port": port }));
    } else if health.is_empty() {
        let port = port_from_payload(&restart[0]).unwrap_or(DEFAULT_COMFYUI_PORT);
        health.push(json!({ "port": port }));
    }

    (restart, health)
}

fn port_from_payload(value: &Value) -> Option<u16> {
    value.get("port").and_then(Value::as_u64).and_then(|n| {
        if n <= u64::from(u16::MAX) {
            Some(n as u16)
        } else {
            None
        }
    })
}

/// The canonical kind string for `phase`
/// (`02-phase-catalog.md` §Catalog kinds).
///
/// `pub(crate)` so [`crate::exec`] can label each executed phase's report
/// entry with the same kind string the plan artifact uses, rather than
/// forking a second variant→kind map that could drift.
pub(crate) fn kind_of(phase: &ProfileNode) -> &'static str {
    match phase {
        ProfileNode::Spec { .. } => "",
        ProfileNode::SystemApt { .. } => "system.apt",
        ProfileNode::ComfyUiInstall { .. } => "comfyui.install",
        ProfileNode::PythonVersionCheck { .. } => "python.version_check",
        ProfileNode::PythonDeps { .. } => "python.deps",
        ProfileNode::CustomNodes { .. } => "custom_nodes",
        ProfileNode::SyncPull { .. } => "sync.pull",
        ProfileNode::SyncPush { .. } => "sync.push",
        ProfileNode::StagingPush { .. } => "staging.push",
        ProfileNode::Models { .. } => "models",
        ProfileNode::LlmModels { .. } => "llm_models",
        ProfileNode::PostInstall { .. } => "hooks.post_install",
        ProfileNode::ComfyUiRestart { .. } => "comfyui.restart",
        ProfileNode::ComfyUiHealth { .. } => "comfyui.health",
        ProfileNode::ServiceStart { .. } => "service.start",
        ProfileNode::ServiceReady { .. } => "service.ready",
        ProfileNode::EnvLiteral { .. } => "env.literal",
        ProfileNode::EnvSecret { .. } => "env.secret",
        ProfileNode::EnvRef { .. } => "env.ref",
        ProfileNode::ShExec { .. } => "sh.exec",
        ProfileNode::FsWrite { .. } => "fs.write",
        ProfileNode::NetHttpGet { .. } => "net.http_get",
        ProfileNode::NetHttpPost { .. } => "net.http_post",
        ProfileNode::NetTransfer { .. } => "net.transfer",
        ProfileNode::MountBind { .. } => "mount.bind",
        ProfileNode::MountUmount { .. } => "mount.umount",
    }
}

/// Per-variant payload object (variant field set, `NodeId` excluded).
///
/// Unlike [`crate::canonical::encode`] this does **not** sort declared
/// lists: plan preserves declaration order inside each payload (the
/// hash-parity sort rule is canonical-only).
fn payload_of(phase: &ProfileNode) -> Value {
    match phase {
        ProfileNode::Spec { .. } => Value::Object(Map::new()),
        ProfileNode::SystemApt { packages, .. } => json!({ "packages": packages }),
        ProfileNode::ComfyUiInstall { ref_name, repo, .. } => {
            let mut m = Map::new();
            m.insert("ref_name".into(), Value::String(ref_name.clone()));
            if let Some(v) = repo {
                m.insert("repo".into(), Value::String(v.clone()));
            }
            Value::Object(m)
        }
        ProfileNode::PythonVersionCheck { want, .. } => json!({ "want": want }),
        ProfileNode::PythonDeps {
            deps,
            in_comfy_venv,
            ..
        } => json!({ "deps": deps, "in_comfy_venv": in_comfy_venv }),
        ProfileNode::CustomNodes { nodes_json, .. } => json!({ "nodes_json": nodes_json }),
        ProfileNode::SyncPull {
            src,
            dst,
            env,
            revision,
            ..
        } => route_payload(src, dst, env, revision.as_deref()),
        ProfileNode::SyncPush { src, dst, .. } => json!({ "src": src, "dst": dst }),
        ProfileNode::StagingPush {
            src,
            dst,
            env,
            revision,
            ..
        } => route_payload(src, dst, env, revision.as_deref()),
        ProfileNode::Models { models_json, .. } => json!({ "models_json": models_json }),
        ProfileNode::LlmModels { models_json, .. } => json!({ "models_json": models_json }),
        ProfileNode::PostInstall { script, .. } => json!({ "script": script }),
        // `extra_args` is omitted when empty, mirroring the canonical
        // encoder: the plan renders what the author declared, and an
        // absent list is not the same statement as an empty one.
        ProfileNode::ComfyUiRestart {
            port, extra_args, ..
        } => {
            if extra_args.is_empty() {
                json!({ "port": port })
            } else {
                json!({ "port": port, "extra_args": extra_args })
            }
        }
        ProfileNode::ComfyUiHealth { port, .. } => json!({ "port": port }),
        // Platform detail follows the same omit-when-unset rule as the
        // canonical encoder: the plan renders what the author declared,
        // and an absent field is not the same statement as a zero one.
        ProfileNode::ServiceStart {
            name,
            platform_kind,
            model,
            port,
            dtype,
            tensor_parallel_size,
            extra_args,
            ..
        } => {
            let mut m = Map::new();
            m.insert("name".into(), json!(name));
            m.insert("platform_kind".into(), json!(platform_kind));
            if let Some(model) = model {
                m.insert("model".into(), json!(model));
            }
            if let Some(port) = port {
                m.insert("port".into(), json!(port));
            }
            if let Some(dtype) = dtype {
                m.insert("dtype".into(), json!(dtype));
            }
            if let Some(size) = tensor_parallel_size {
                m.insert("tensor_parallel_size".into(), json!(size));
            }
            if !extra_args.is_empty() {
                m.insert("extra_args".into(), json!(extra_args));
            }
            Value::Object(m)
        }
        ProfileNode::ServiceReady {
            name, check_url, ..
        } => json!({ "name": name, "check_url": check_url }),
        ProfileNode::ShExec { argv, env, .. } => {
            let mut m = Map::new();
            m.insert("argv".into(), json!(argv));
            if !env.is_empty() {
                m.insert("env".into(), env_object(env));
            }
            Value::Object(m)
        }
        // `content` renders in its `env`-map value form: a literal is
        // its bare string (matching the pre-node plan output), a secret
        // / ref is its marker object — the resolved value never enters
        // a plan.
        ProfileNode::FsWrite { path, content, .. } => {
            json!({ "path": path, "content": env_value(content) })
        }
        ProfileNode::NetHttpGet { url, .. } => json!({ "url": url }),
        ProfileNode::NetHttpPost { url, .. } => json!({ "url": url }),
        ProfileNode::NetTransfer { src, dst, .. } => json!({ "src": src, "dst": dst }),
        ProfileNode::MountBind { src, dst, .. } => json!({ "src": src, "dst": dst }),
        ProfileNode::MountUmount { path, .. } => json!({ "path": path }),
        // Env value nodes never occur as top-level phases; the arm keeps
        // [`payload_of`] total. Rendered in their `env`-map value form.
        ProfileNode::EnvLiteral { .. }
        | ProfileNode::EnvSecret { .. }
        | ProfileNode::EnvRef { .. } => env_value(phase),
    }
}

/// Payload for a `sync.pull` / `staging.push` route: `src` / `dst`,
/// plus an `env` object (only when non-empty) and `revision` (only when
/// present). Matches the legacy `lm.plan` bundle, whose `env` entries
/// render each secret as its `{"__secret":"NAME"}` marker.
fn route_payload(
    src: &str,
    dst: &str,
    env: &BTreeMap<String, ProfileNode>,
    revision: Option<&str>,
) -> Value {
    let mut m = Map::new();
    m.insert("src".into(), Value::String(src.to_string()));
    m.insert("dst".into(), Value::String(dst.to_string()));
    if !env.is_empty() {
        m.insert("env".into(), env_object(env));
    }
    if let Some(rev) = revision {
        m.insert("revision".into(), Value::String(rev.to_string()));
    }
    Value::Object(m)
}

/// Render an `env` keyed slot as a JSON object mapping each key to its
/// value node's plan form ([`env_value`]).
fn env_object(env: &BTreeMap<String, ProfileNode>) -> Value {
    let mut m = Map::new();
    for (key, value) in env {
        m.insert(key.clone(), env_value(value));
    }
    Value::Object(m)
}

/// Render one `env`-map value: an [`ProfileNode::EnvLiteral`] as its
/// plain string, an [`ProfileNode::EnvSecret`] as the
/// `{"__secret":"NAME"}` marker, an [`ProfileNode::EnvRef`] as the
/// `{"__env_ref":"NAME"}` marker (mirroring [`crate::canonical`]).
/// Any other node is a malformed AST the frontend never produces.
fn env_value(node: &ProfileNode) -> Value {
    match node {
        ProfileNode::EnvLiteral { value, .. } => Value::String(value.clone()),
        ProfileNode::EnvSecret { name, .. } => json!({ "__secret": name }),
        ProfileNode::EnvRef { name, .. } => json!({ "__env_ref": name }),
        _ => Value::Null,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dsl_kit::IdGen;

    /// Build a `Spec` root wrapping `phases` with a fresh `IdGen`.
    /// `NodeId`s are opaque here — the plan strips them, so tests do
    /// not need to inspect them.
    fn spec(name: &str, phases: Vec<ProfileNode>) -> ProfileNode {
        let ids = IdGen::new();
        ProfileNode::Spec {
            id: ids.node(),
            name: name.into(),
            version: None,
            description: None,
            capabilities: Vec::new(),
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths: Vec::new(),
            http_allowlist: Vec::new(),
            phases,
        }
    }

    fn ids() -> IdGen {
        IdGen::new()
    }

    fn step_ids(plan: &Value) -> Vec<String> {
        plan["steps"]
            .as_array()
            .expect("steps is an array")
            .iter()
            .map(|s| s["id"].as_str().expect("id is a string").to_string())
            .collect()
    }

    fn step_kinds(plan: &Value) -> Vec<String> {
        plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["kind"].as_str().unwrap().to_string())
            .collect()
    }

    fn step_indices(plan: &Value) -> Vec<u64> {
        plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["index"].as_u64().unwrap())
            .collect()
    }

    // -----------------------------------------------------------------
    // comfyui.restart payload (02 §Catalog kinds `extra_args`).
    // -----------------------------------------------------------------

    #[test]
    fn restart_payload_omits_extra_args_when_undeclared() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::ComfyUiRestart {
                id: g.node(),
                port: 8188,
                extra_args: Vec::new(),
            }],
        ));
        let payload = &plan["steps"][0]["payload"];
        assert_eq!(payload["port"].as_u64(), Some(8188));
        assert!(
            payload.get("extra_args").is_none(),
            "an undeclared extra_args must not appear as an empty list: {payload}"
        );
    }

    #[test]
    fn restart_payload_carries_declared_extra_args_in_order() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::ComfyUiRestart {
                id: g.node(),
                port: 8188,
                extra_args: vec!["--port=9000".into(), "--listen".into()],
            }],
        ));
        let payload = &plan["steps"][0]["payload"];
        assert_eq!(
            payload["extra_args"],
            serde_json::json!(["--port=9000", "--listen"]),
            "plan preserves declaration order (it does not sort payload lists)"
        );
    }

    // -----------------------------------------------------------------
    // Canonical bucket order (02 §Canonical phase ordering).
    // -----------------------------------------------------------------

    #[test]
    fn steps_are_emitted_in_the_canonical_bucket_order() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                // Deliberately declared out of canonical order.
                ProfileNode::ShExec {
                    id: g.node(),
                    argv: vec!["echo".into(), "tail".into()],
                    env: BTreeMap::new(),
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceReady {
                    id: g.node(),
                    name: "svc".into(),
                    check_url: "http://x/health".into(),
                },
                ProfileNode::ComfyUiRestart {
                    id: g.node(),
                    port: 9000,
                    extra_args: Vec::new(),
                },
                ProfileNode::ComfyUiHealth {
                    id: g.node(),
                    port: 9000,
                },
                ProfileNode::PostInstall {
                    id: g.node(),
                    script: "echo hi".into(),
                },
                ProfileNode::LlmModels {
                    id: g.node(),
                    models_json: "[]".into(),
                },
                ProfileNode::Models {
                    id: g.node(),
                    models_json: "[]".into(),
                },
                ProfileNode::SyncPull {
                    id: g.node(),
                    src: "b2://bucket/a.bin".into(),
                    dst: "/workspace/a.bin".into(),
                    env: BTreeMap::new(),
                    revision: None,
                },
                ProfileNode::CustomNodes {
                    id: g.node(),
                    nodes_json: "[]".into(),
                },
                ProfileNode::PythonDeps {
                    id: g.node(),
                    deps: vec!["torch".into()],
                    in_comfy_venv: false,
                },
                ProfileNode::ComfyUiInstall {
                    id: g.node(),
                    ref_name: "abc123".into(),
                    repo: None,
                },
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["curl".into()],
                },
            ],
        ));

        assert_eq!(
            step_ids(&plan),
            vec![
                "1_system_apt",
                "2_comfyui_install",
                "3_python_deps",
                "4_custom_nodes",
                "5_sync_routes",
                "7_models",
                "7b_llm_models",
                "8_post_install",
                "9_comfyui_restart",
                "10_comfyui_health",
                "11_service_0_start",
                "11_service_0_ready",
                "zz_unknown",
            ],
        );
    }

    #[test]
    fn multiple_phases_of_the_same_kind_preserve_declaration_order() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["first".into()],
                },
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["second".into()],
                },
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["third".into()],
                },
            ],
        ));

        let steps = plan["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0]["payload"]["packages"][0], json!("first"));
        assert_eq!(steps[1]["payload"]["packages"][0], json!("second"));
        assert_eq!(steps[2]["payload"]["packages"][0], json!("third"));
    }

    // -----------------------------------------------------------------
    // Implicit comfyui lifecycle insertion.
    // -----------------------------------------------------------------

    #[test]
    fn comfyui_install_alone_inserts_both_restart_and_health_with_the_default_port() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::ComfyUiInstall {
                id: g.node(),
                ref_name: "abc".into(),
                repo: None,
            }],
        ));

        assert_eq!(
            step_ids(&plan),
            vec![
                "2_comfyui_install",
                "9_comfyui_restart",
                "10_comfyui_health"
            ],
        );
        let steps = plan["steps"].as_array().unwrap();
        assert_eq!(steps[1]["payload"]["port"], json!(8188));
        assert_eq!(steps[2]["payload"]["port"], json!(8188));
    }

    #[test]
    fn declared_restart_makes_implicit_health_inherit_its_port() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ComfyUiInstall {
                    id: g.node(),
                    ref_name: "abc".into(),
                    repo: None,
                },
                ProfileNode::ComfyUiRestart {
                    id: g.node(),
                    port: 9001,
                    extra_args: Vec::new(),
                },
            ],
        ));

        assert_eq!(
            step_ids(&plan),
            vec![
                "2_comfyui_install",
                "9_comfyui_restart",
                "10_comfyui_health"
            ],
        );
        assert_eq!(
            plan["steps"][2]["payload"]["port"],
            json!(9001),
            "health must inherit the declared restart port",
        );
    }

    #[test]
    fn declared_health_makes_implicit_restart_inherit_its_port() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ComfyUiInstall {
                    id: g.node(),
                    ref_name: "abc".into(),
                    repo: None,
                },
                ProfileNode::ComfyUiHealth {
                    id: g.node(),
                    port: 9002,
                },
            ],
        ));

        assert_eq!(
            step_ids(&plan),
            vec![
                "2_comfyui_install",
                "9_comfyui_restart",
                "10_comfyui_health"
            ],
        );
        assert_eq!(
            plan["steps"][1]["payload"]["port"],
            json!(9002),
            "restart must inherit the declared health port",
        );
    }

    #[test]
    fn both_declared_disables_implicit_insertion() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ComfyUiInstall {
                    id: g.node(),
                    ref_name: "abc".into(),
                    repo: None,
                },
                ProfileNode::ComfyUiRestart {
                    id: g.node(),
                    port: 1111,
                    extra_args: Vec::new(),
                },
                ProfileNode::ComfyUiHealth {
                    id: g.node(),
                    port: 2222,
                },
            ],
        ));
        assert_eq!(plan["steps"][1]["payload"]["port"], json!(1111));
        assert_eq!(plan["steps"][2]["payload"]["port"], json!(2222));
    }

    #[test]
    fn no_comfyui_install_means_no_implicit_lifecycle_steps() {
        let plan = expand(&spec("demo", vec![]));
        assert!(plan["steps"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------
    // service.start / service.ready per-declaration indexing.
    // -----------------------------------------------------------------

    #[test]
    fn service_ready_before_any_start_gets_index_zero() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::ServiceReady {
                id: g.node(),
                name: "svc".into(),
                check_url: "http://x/health".into(),
            }],
        ));
        assert_eq!(step_ids(&plan), vec!["11_service_0_ready"]);
    }

    #[test]
    fn multiple_services_are_numbered_by_declaration_index() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-a".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceReady {
                    id: g.node(),
                    name: "svc-a".into(),
                    check_url: "http://a/health".into(),
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-b".into(),
                    platform_kind: "ollama".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceReady {
                    id: g.node(),
                    name: "svc-b".into(),
                    check_url: "http://b/health".into(),
                },
            ],
        ));
        assert_eq!(
            step_ids(&plan),
            vec![
                "11_service_0_start",
                "11_service_0_ready",
                "11_service_1_start",
                "11_service_1_ready",
            ],
        );
    }

    #[test]
    fn ready_inherits_the_most_recently_declared_start_index() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-a".into(),
                    platform_kind: "vllm".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceStart {
                    id: g.node(),
                    name: "svc-b".into(),
                    platform_kind: "ollama".into(),
                    model: None,
                    port: None,
                    dtype: None,
                    tensor_parallel_size: None,
                    extra_args: vec![],
                },
                ProfileNode::ServiceReady {
                    id: g.node(),
                    name: "svc-b".into(),
                    check_url: "http://b/health".into(),
                },
            ],
        ));
        assert_eq!(
            step_ids(&plan),
            vec![
                "11_service_0_start",
                "11_service_1_start",
                "11_service_1_ready",
            ],
        );
    }

    // -----------------------------------------------------------------
    // python.version_check default suppression.
    // -----------------------------------------------------------------

    #[test]
    fn python_version_check_is_suppressed_when_want_equals_the_default() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::PythonVersionCheck {
                id: g.node(),
                want: "3.12".into(),
            }],
        ));
        assert!(plan["steps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn python_version_check_is_kept_when_want_differs_from_the_default() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::PythonVersionCheck {
                id: g.node(),
                want: "3.11".into(),
            }],
        ));
        assert_eq!(step_ids(&plan), vec!["3a_python_version_check"]);
        assert_eq!(step_kinds(&plan), vec!["python.version_check"]);
        assert_eq!(plan["steps"][0]["payload"]["want"], json!("3.11"));
    }

    // -----------------------------------------------------------------
    // sync.routes plan-internal bundle.
    // -----------------------------------------------------------------

    #[test]
    fn sync_pull_push_and_staging_push_bundle_into_a_single_sync_routes_step() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::SyncPull {
                    id: g.node(),
                    src: "b2://bucket/a.bin".into(),
                    dst: "/workspace/a.bin".into(),
                    env: BTreeMap::new(),
                    revision: None,
                },
                ProfileNode::SyncPush {
                    id: g.node(),
                    src: "/workspace/out.bin".into(),
                    dst: "b2://bucket/out.bin".into(),
                },
                ProfileNode::StagingPush {
                    id: g.node(),
                    src: "/workspace/stage.bin".into(),
                    dst: "hf://owner/repo/stage.bin".into(),
                    env: BTreeMap::new(),
                    revision: None,
                },
            ],
        ));
        assert_eq!(step_ids(&plan), vec!["5_sync_routes"]);
        assert_eq!(step_kinds(&plan), vec!["sync.routes"]);
        let payload = &plan["steps"][0]["payload"];
        assert_eq!(payload["pull"].as_array().unwrap().len(), 1);
        assert_eq!(payload["push_markers"].as_array().unwrap().len(), 1);
        assert_eq!(payload["staging_push"].as_array().unwrap().len(), 1);
        assert_eq!(payload["pull"][0]["src"], json!("b2://bucket/a.bin"));
        assert_eq!(
            payload["push_markers"][0]["dst"],
            json!("b2://bucket/out.bin")
        );
        assert_eq!(
            payload["staging_push"][0]["src"],
            json!("/workspace/stage.bin")
        );
    }

    #[test]
    fn sync_pull_env_and_revision_appear_in_the_route_payload() {
        let g = ids();
        let mut env = BTreeMap::new();
        env.insert(
            "LOG".to_string(),
            ProfileNode::EnvLiteral {
                id: g.node(),
                value: "debug".into(),
            },
        );
        env.insert(
            "TOKEN".to_string(),
            ProfileNode::EnvSecret {
                id: g.node(),
                name: "HF_TOKEN".into(),
            },
        );
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "hf://owner/repo/m.bin".into(),
                dst: "/workspace/m.bin".into(),
                env,
                revision: Some("main".into()),
            }],
        ));
        let pull0 = &plan["steps"][0]["payload"]["pull"][0];
        assert_eq!(pull0["env"]["LOG"], json!("debug"));
        assert_eq!(pull0["env"]["TOKEN"], json!({ "__secret": "HF_TOKEN" }));
        assert_eq!(pull0["revision"], json!("main"));
    }

    #[test]
    fn sh_exec_env_appears_in_the_payload() {
        let g = ids();
        let mut env = BTreeMap::new();
        env.insert(
            "API".to_string(),
            ProfileNode::EnvSecret {
                id: g.node(),
                name: "API".into(),
            },
        );
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::ShExec {
                id: g.node(),
                argv: vec!["run".into()],
                env,
            }],
        ));
        assert_eq!(
            plan["steps"][0]["payload"]["env"]["API"],
            json!({ "__secret": "API" })
        );
    }

    #[test]
    fn sync_pull_without_env_omits_the_env_and_revision_keys() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::SyncPull {
                id: g.node(),
                src: "b2://bucket/m.bin".into(),
                dst: "/workspace/m.bin".into(),
                env: BTreeMap::new(),
                revision: None,
            }],
        ));
        let pull0 = &plan["steps"][0]["payload"]["pull"][0];
        assert!(pull0.get("env").is_none(), "env must be omitted: {pull0}");
        assert!(
            pull0.get("revision").is_none(),
            "revision must be omitted: {pull0}"
        );
    }

    #[test]
    fn no_sync_phases_means_no_sync_routes_step() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::SystemApt {
                id: g.node(),
                packages: vec!["curl".into()],
            }],
        ));
        assert!(!step_ids(&plan).contains(&"5_sync_routes".to_string()));
    }

    // -----------------------------------------------------------------
    // zz_unknown trailing bucket.
    // -----------------------------------------------------------------

    #[test]
    fn direct_operation_kinds_land_in_zz_unknown_in_declaration_order() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::ShExec {
                    id: g.node(),
                    argv: vec!["echo".into(), "a".into()],
                    env: BTreeMap::new(),
                },
                ProfileNode::FsWrite {
                    id: g.node(),
                    path: "/workspace/x".into(),
                    content: Box::new(ProfileNode::EnvLiteral {
                        id: g.node(),
                        value: "y".into(),
                    }),
                },
                ProfileNode::NetHttpGet {
                    id: g.node(),
                    url: "https://example/".into(),
                },
                ProfileNode::MountBind {
                    id: g.node(),
                    src: "/a".into(),
                    dst: "/b".into(),
                },
            ],
        ));
        assert_eq!(
            step_ids(&plan),
            vec!["zz_unknown", "zz_unknown", "zz_unknown", "zz_unknown"],
        );
        assert_eq!(
            step_kinds(&plan),
            vec!["sh.exec", "fs.write", "net.http_get", "mount.bind"],
        );
    }

    // -----------------------------------------------------------------
    // 1-based contiguous index in emission order.
    // -----------------------------------------------------------------

    #[test]
    fn index_is_a_1_based_contiguous_counter_in_emission_order() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![
                ProfileNode::SystemApt {
                    id: g.node(),
                    packages: vec!["curl".into()],
                },
                ProfileNode::PostInstall {
                    id: g.node(),
                    script: "echo hi".into(),
                },
                ProfileNode::ShExec {
                    id: g.node(),
                    argv: vec!["ls".into()],
                    env: BTreeMap::new(),
                },
            ],
        ));
        assert_eq!(step_indices(&plan), vec![1, 2, 3]);
    }

    // -----------------------------------------------------------------
    // profile_name / no schema field.
    // -----------------------------------------------------------------

    #[test]
    fn plan_carries_the_profile_name_and_omits_schema() {
        let plan = expand(&spec("demo-profile", vec![]));
        assert_eq!(plan["profile_name"], json!("demo-profile"));
        assert!(
            plan.get("schema").is_none(),
            "AST plan output must not carry a schema field",
        );
    }

    // -----------------------------------------------------------------
    // Payload lists preserve declaration order (plan does NOT sort).
    // -----------------------------------------------------------------

    #[test]
    fn payload_lists_preserve_declaration_order_unlike_canonical() {
        let g = ids();
        let plan = expand(&spec(
            "demo",
            vec![ProfileNode::SystemApt {
                id: g.node(),
                packages: vec!["zzz".into(), "aaa".into(), "mmm".into()],
            }],
        ));
        assert_eq!(
            plan["steps"][0]["payload"]["packages"],
            json!(["zzz", "aaa", "mmm"]),
        );
    }
}
