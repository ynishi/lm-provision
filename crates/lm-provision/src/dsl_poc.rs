//! Provisioning Profile DSL defined using dsl-kit with dsl-kit-core Engine Integration.

use dsl_kit::{
    DslExec as DslExecTrait, DslSemantics, Engine, LoopDecision, NodeId, OwnedDerivedAst,
    ReducerRegistry,
};
use dsl_kit_macros::{DslBuild, DslExec, DslNode, DslSchema};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Unified AST for provision profile declarations and 22 Phase catalog kinds (`02-phase-catalog.md`).
#[derive(Debug, Clone, PartialEq, Eq, DslNode, DslSchema, DslBuild, DslExec)]
pub enum ProfileNode {
    /// Top-level Profile Spec.
    #[dsl_exec(seq)]
    Spec {
        /// Stable node ID.
        id: NodeId,
        /// Profile name.
        name: String,
        /// Profile version (semver string, defaults host-side to "0.0.0").
        version: Option<String>,
        /// Human-readable description.
        description: Option<String>,
        /// Allowed capabilities.
        capabilities: Vec<String>,
        /// Non-secret env allowlist.
        env: Vec<String>,
        /// Secret env allowlist.
        env_secrets: Vec<String>,
        /// Allowed filesystem path roots. `fs.write` / `mount.*` /
        /// `net.transfer` destinations are rejected when the target
        /// path is not under one of these roots (chapter 05 §L3 path
        /// policy).
        paths: Vec<String>,
        /// Allowed HTTP URL patterns. `net.http_get` / `net.http_post` /
        /// `net.transfer` (when `src` is `http://` or `https://`) URLs
        /// are rejected when they match no pattern (chapter 05 §L3
        /// HTTP policy). Pattern = literal prefix with an optional
        /// single `*` confined to the authority component.
        http_allowlist: Vec<String>,
        /// Sequential list of phases.
        phases: Vec<ProfileNode>,
    },

    // --- Catalog Kinds: Setup Lifecycle ---
    /// `system.apt`: Apt package installation
    #[dsl_exec(apply = "system_apt")]
    SystemApt {
        /// Stable node ID.
        id: NodeId,
        /// List of package names to install.
        packages: Vec<String>,
    },

    /// `comfyui.install`: ComfyUI repository checkout
    #[dsl_exec(apply = "comfyui_install")]
    ComfyUiInstall {
        /// Stable node ID.
        id: NodeId,
        /// Git ref / commit hash.
        ref_name: String,
        /// Optional repository owner/name.
        repo: Option<String>,
    },

    /// `python.version_check`: Ensure Python version requirement
    #[dsl_exec(apply = "python_version_check")]
    PythonVersionCheck {
        /// Stable node ID.
        id: NodeId,
        /// Required Python version (e.g. "3.12").
        want: String,
    },

    /// `python.deps`: Python package installation
    #[dsl_exec(apply = "python_deps")]
    PythonDeps {
        /// Stable node ID.
        id: NodeId,
        /// List of python dependencies.
        deps: Vec<String>,
        /// Install inside ComfyUI venv if true.
        in_comfy_venv: bool,
    },

    /// `custom_nodes`: Install ComfyUI custom nodes
    #[dsl_exec(apply = "custom_nodes")]
    CustomNodes {
        /// Stable node ID.
        id: NodeId,
        /// JSON encoded custom node specifications.
        nodes_json: String,
    },

    /// `sync.pull`: Synchronize files/artifacts from remote storage
    #[dsl_exec(apply = "sync_pull")]
    SyncPull {
        /// Stable node ID.
        id: NodeId,
        /// Source URI.
        src: String,
        /// Destination path.
        dst: String,
        /// Env injection map (spec 02 `sync.pull`). A keyed slot whose
        /// values are [`ProfileNode::EnvLiteral`] / [`ProfileNode::EnvSecret`]
        /// value nodes (dsl-kit 0.5 `Multiplicity::Map`). Empty when the
        /// author declared no env.
        env: BTreeMap<String, ProfileNode>,
        /// Optional hf revision (spec 02 `sync.pull` `revision`).
        revision: Option<String>,
    },

    /// `sync.push`: Synchronize files/artifacts to remote storage (marker)
    #[dsl_exec(apply = "sync_push")]
    SyncPush {
        /// Stable node ID.
        id: NodeId,
        /// Source path.
        src: String,
        /// Destination URI.
        dst: String,
    },

    /// `staging.push`: Push staging artifacts
    #[dsl_exec(apply = "staging_push")]
    StagingPush {
        /// Stable node ID.
        id: NodeId,
        /// Source path.
        src: String,
        /// Destination URI.
        dst: String,
        /// Env injection map (spec 02 `staging.push`). Same keyed-slot
        /// shape as [`ProfileNode::SyncPull`]'s `env`.
        env: BTreeMap<String, ProfileNode>,
        /// Optional hf revision (spec 02 `staging.push` `revision`).
        revision: Option<String>,
    },

    /// `models`: Model downloads for ComfyUI
    #[dsl_exec(apply = "models")]
    Models {
        /// Stable node ID.
        id: NodeId,
        /// JSON encoded model items.
        models_json: String,
    },

    /// `llm_models`: LLM model snapshot downloads
    #[dsl_exec(apply = "llm_models")]
    LlmModels {
        /// Stable node ID.
        id: NodeId,
        /// JSON encoded LLM model items.
        models_json: String,
    },

    /// `hooks.post_install`: Raw shell escape script
    #[dsl_exec(apply = "post_install")]
    PostInstall {
        /// Stable node ID.
        id: NodeId,
        /// Raw shell script.
        script: String,
    },

    /// `comfyui.restart`: Restart ComfyUI service
    #[dsl_exec(apply = "comfyui_restart")]
    ComfyUiRestart {
        /// Stable node ID.
        id: NodeId,
        /// Target port.
        port: u16,
    },

    /// `comfyui.health`: Poll HTTP health check endpoint
    #[dsl_exec(apply = "comfyui_health")]
    ComfyUiHealth {
        /// Stable node ID.
        id: NodeId,
        /// Target port.
        port: u16,
    },

    /// `service.start`: Start background service
    #[dsl_exec(apply = "service_start")]
    ServiceStart {
        /// Stable node ID.
        id: NodeId,
        /// Service name.
        name: String,
        /// Platform kind (vllm, ollama, llamacpp).
        platform_kind: String,
    },

    /// `service.ready`: Wait for service readiness
    #[dsl_exec(apply = "service_ready")]
    ServiceReady {
        /// Stable node ID.
        id: NodeId,
        /// Service name.
        name: String,
        /// HTTP health check URL.
        check_url: String,
    },

    // --- Catalog Kinds: Direct Operations ---
    /// `sh.exec`: Execute raw shell command with arguments
    #[dsl_exec(apply = "sh_exec")]
    ShExec {
        /// Stable node ID.
        id: NodeId,
        /// Argument vector.
        argv: Vec<String>,
        /// Env injection map (spec 04 `sh.exec` `opts.env`). Same
        /// keyed-slot shape as [`ProfileNode::SyncPull`]'s `env`.
        env: BTreeMap<String, ProfileNode>,
    },

    /// `fs.write`: Write file content
    #[dsl_exec(apply = "fs_write")]
    FsWrite {
        /// Stable node ID.
        id: NodeId,
        /// Path to target file.
        path: String,
        /// File content.
        content: String,
    },

    /// `net.http_get`: Perform HTTP GET request
    #[dsl_exec(apply = "net_http_get")]
    NetHttpGet {
        /// Stable node ID.
        id: NodeId,
        /// Target URL.
        url: String,
    },

    /// `net.http_post`: Perform HTTP POST request
    #[dsl_exec(apply = "net_http_post")]
    NetHttpPost {
        /// Stable node ID.
        id: NodeId,
        /// Target URL.
        url: String,
    },

    /// `net.transfer`: Transfer file across network
    #[dsl_exec(apply = "net_transfer")]
    NetTransfer {
        /// Stable node ID.
        id: NodeId,
        /// Source path/URL.
        src: String,
        /// Destination path.
        dst: String,
    },

    /// `mount.bind`: Bind mount directory
    #[dsl_exec(apply = "mount_bind")]
    MountBind {
        /// Stable node ID.
        id: NodeId,
        /// Source directory.
        src: String,
        /// Destination mount point.
        dst: String,
    },

    /// `mount.umount`: Unmount directory
    #[dsl_exec(apply = "mount_umount")]
    MountUmount {
        /// Stable node ID.
        id: NodeId,
        /// Target path.
        path: String,
    },

    // --- Env value nodes (spec 06 §Inputs) ---
    /// A literal (non-secret) `env` map value. Occurs only as a value in
    /// an `env` keyed slot; never as a top-level phase. Canonicalizes to
    /// its plain string (spec 03 §canonical). Executed as an inert literal
    /// leaf — exec-time env injection is deferred (spec 02 §Dispatch
    /// routing).
    #[dsl_exec(value)]
    EnvLiteral {
        /// Stable node ID.
        id: NodeId,
        /// The literal env value.
        value: String,
    },

    /// A secret `env` map value — the `env.ref(NAME)` form (spec 06
    /// §`env.ref`). Occurs only as a value in an `env` keyed slot.
    /// Canonicalizes to the `{"__secret":"NAME"}` marker (spec 03 /
    /// spec 06 §SecretRef); `name` is the logical secret name, which
    /// [`crate::validate`] cross-checks against `Spec.env_secrets`.
    #[dsl_exec(value)]
    EnvSecret {
        /// Stable node ID.
        id: NodeId,
        /// Logical secret name (must appear in `Spec.env_secrets`).
        name: String,
    },
}

/// Execution value type for provision phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileValue {
    /// Unit result indicating successful execution of a phase step.
    Success(String),
}

impl From<()> for ProfileValue {
    fn from(_: ()) -> Self {
        ProfileValue::Success("ok".into())
    }
}

/// Literal env value nodes ([`ProfileNode::EnvLiteral`] /
/// [`ProfileNode::EnvSecret`]) carry a `String` `LitValue`; the engine
/// converts it into a [`ProfileValue`] when it evaluates the leaf. The
/// value is inert (exec-time env injection is deferred, spec 02
/// §Dispatch routing), so the string is wrapped as a success marker.
impl From<String> for ProfileValue {
    fn from(value: String) -> Self {
        ProfileValue::Success(value)
    }
}

/// Semantics adapter for provisioning AST execution under dsl-kit-core.
#[derive(Debug, Clone, Copy)]
pub struct ProfileSemantics;

impl DslSemantics for ProfileSemantics {
    type Value = ProfileValue;
    type Delta = ();
    type EffectError = std::convert::Infallible;
    type Cursor = ();

    fn unit_value(&self) -> ProfileValue {
        ProfileValue::Success("ok".into())
    }

    fn continue_loop(
        &self,
        _node: NodeId,
        _last: &ProfileValue,
        _iteration: usize,
    ) -> LoopDecision {
        LoopDecision::Break
    }
}

/// Owned AST projection: the engine borrows nothing, so hosts can hold
/// program and engine together without `Box::leak`.
pub type ProfileAst = OwnedDerivedAst<<ProfileNode as DslExecTrait>::LitValue, ProfileSemantics>;

/// Instantiates a dsl-kit-core Engine driving real execution of a
/// `ProfileNode` AST through the [`crate::exec`] bridge.
///
/// `mode` selects dry-run tracing vs real effects; `executed_log`
/// collects each op's trace line / result summary. Construction fails
/// with [`crate::exec::ExecError`] only when the profile declares a
/// capability outside [`crate::exec::capgate::KNOWN_CAPABILITIES`]; the
/// engine wiring itself is a host invariant and is asserted.
pub fn create_profile_engine(
    root: &ProfileNode,
    mode: crate::exec::ExecMode,
    executed_log: Arc<std::sync::Mutex<Vec<String>>>,
) -> Result<Engine<ProfileAst>, crate::exec::ExecError> {
    let ctx = Arc::new(crate::exec::ExecContext::from_root(
        root,
        mode,
        executed_log,
    )?);
    let engine = Engine::new_with_ops(
        OwnedDerivedAst::new(root, ProfileSemantics),
        Arc::new(ReducerRegistry::new()),
        crate::exec::registry::profile_op_registry(ctx),
    )
    .expect("Engine initialization should succeed");
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ExecMode;
    use dsl_kit::{IdGen, StepOutcome, Stepper};
    use dsl_kit_parse::{example_gen, schema_gen, serde_bridge::from_json_value, DslBuild as _};

    use dsl_kit_schema::DslSchema as _;

    #[test]
    fn test_schema_and_grammar_generation() {
        let id_gen = IdGen::new();
        let schema = ProfileNode::schema();
        assert_eq!(schema.name, "ProfileNode");

        let grammar = schema_gen::checked_grammar_from_schema(&schema, &id_gen)
            .expect("grammar generation failed");

        let examples =
            example_gen::examples_from_grammar(&grammar).expect("example generation failed");
        assert!(
            !examples.composite.is_empty(),
            "examples should be generated"
        );
    }

    #[test]
    fn test_json_parse_build_and_engine_execution() {
        let id_gen = IdGen::new();

        // Complete JSON Profile containing lifecycle and direct operation phases
        let json_data = serde_json::json!({
            "type": "Spec",
            "name": "comfyui-vllm-pod",
            "version": "1.0.0",
            "capabilities": ["sh.exec", "net.transfer"],
            "phases": [
                {
                    "type": "SystemApt",
                    "packages": ["git", "curl", "ffmpeg"]
                },
                {
                    "type": "PythonDeps",
                    "deps": ["torch", "vllm"],
                    "in_comfy_venv": false
                },
                {
                    "type": "SyncPull",
                    "src": "https://example.com/model.safetensors",
                    "dst": "/workspace/model.safetensors"
                },
                {
                    "type": "PostInstall",
                    "script": "echo 'Setup complete!'"
                },
                {
                    "type": "ShExec",
                    "argv": ["ls", "-la"]
                }
            ]
        });

        // 1. Serde bridge JSON -> ParseTree
        let tree = from_json_value(&json_data, &ProfileNode::schema())
            .expect("failed to convert JSON to ParseTree");

        // 2. Build typed AST
        let profile_ast = ProfileNode::from_parse_tree(&tree, &id_gen)
            .expect("failed to build ProfileNode AST from ParseTree");

        // Optional Spec fields (dsl-kit 0.3): omitted keys bind to
        // None / empty list via the built-in Option<T> / Vec<T> mapping.
        match &profile_ast {
            ProfileNode::Spec {
                version,
                description,
                env,
                env_secrets,
                ..
            } => {
                assert_eq!(version.as_deref(), Some("1.0.0"));
                assert_eq!(*description, None);
                assert!(env.is_empty());
                assert!(env_secrets.is_empty());
            }
            other => panic!("expected Spec root, got {other:?}"),
        }

        // 3. Instantiate dsl-kit-core Engine (dry-run: cap checks still
        //    run, effects do not).
        let executed_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut engine =
            create_profile_engine(&profile_ast, ExecMode::DryRun, Arc::clone(&executed_log))
                .expect("engine construction should succeed for a valid capability set");

        // 4. Step execution using dsl-kit-core Stepper
        let mut steps = 0;
        loop {
            let outcome = engine.step().expect("step execution failed");
            steps += 1;
            if matches!(outcome, StepOutcome::Done(_)) {
                break;
            }
            if steps > 100 {
                panic!("execution exceeded expected step limit");
            }
        }

        // Every phase produces one op-name-prefixed log line, in
        // declaration order — lifecycle ops (system_apt / python_deps /
        // sync_pull / post_install) collapse their expanded steps into
        // one line each, and `sh_exec` renders a dry-run trace.
        let log = executed_log.lock().unwrap();
        assert_eq!(log.len(), 5);
        assert!(log[0].starts_with("system_apt"));
        assert!(log[1].starts_with("python_deps"));
        assert!(log[2].starts_with("sync_pull"));
        assert!(log[3].starts_with("post_install"));
        assert!(log[4].starts_with("sh_exec"));
    }

    /// The canonical text syntax generated by dsl-kit-parse
    /// (`schema_gen::checked_grammar_from_schema`) round-trips through
    /// [`ProfileNode::from_parse_tree`] into the typed AST. Exercises the
    /// text-input path end-to-end (the JSON path above already covers
    /// the serde bridge).
    #[test]
    fn canonical_text_parses_into_the_typed_ast() {
        use dsl_kit_parse::peg::Grammar;

        let ids = IdGen::new();
        let schema = ProfileNode::schema();
        let grammar = Grammar::from_schema(&schema, &ids)
            .expect("grammar generation must succeed for the ProfileNode schema");

        // A minimal Spec: one lifecycle phase, one direct phase, so the
        // assertion can distinguish variants by field content. Optional
        // Spec fields (version / description) use the `none` spelling.
        let text = concat!(
            "Spec(",
            "name: \"canonical-demo\", ",
            "version: none, ",
            "description: none, ",
            "capabilities: [\"sh.exec\"], ",
            "env: [], ",
            "env_secrets: [], ",
            "paths: [], ",
            "http_allowlist: [], ",
            "phases: [",
            "SystemApt(packages: [\"git\", \"curl\"]), ",
            "ShExec(argv: [\"ls\", \"-la\"])",
            "])",
        );
        let tree = grammar
            .parse(text)
            .expect("canonical text must parse against the generated grammar");
        let ast = ProfileNode::from_parse_tree(&tree, &ids)
            .expect("parse tree must build into a typed ProfileNode AST");

        match ast {
            ProfileNode::Spec {
                name,
                version,
                description,
                capabilities,
                phases,
                ..
            } => {
                assert_eq!(name, "canonical-demo");
                assert_eq!(version, None);
                assert_eq!(description, None);
                assert_eq!(capabilities, vec!["sh.exec".to_string()]);
                assert_eq!(phases.len(), 2);
                match &phases[0] {
                    ProfileNode::SystemApt { packages, .. } => {
                        assert_eq!(packages, &vec!["git".to_string(), "curl".to_string()]);
                    }
                    other => panic!("expected first phase = SystemApt, got {other:?}"),
                }
                match &phases[1] {
                    ProfileNode::ShExec { argv, .. } => {
                        assert_eq!(argv, &vec!["ls".to_string(), "-la".to_string()]);
                    }
                    other => panic!("expected second phase = ShExec, got {other:?}"),
                }
            }
            other => panic!("expected Spec root, got {other:?}"),
        }
    }
}
