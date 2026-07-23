//! Provisioning Profile DSL defined using dsl-kit with dsl-kit-core Engine Integration.

use std::sync::Arc;
use dsl_kit::{
    DslExec as DslExecTrait, DslSemantics, Engine, LoopDecision, NodeId, Op, OpRegistry,
    OwnedDerivedAst, ReducerRegistry,
};
use dsl_kit_macros::{DslBuild, DslExec, DslNode, DslSchema};

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

    fn continue_loop(&self, _node: NodeId, _last: &ProfileValue, _iteration: usize) -> LoopDecision {
        LoopDecision::Break
    }
}

/// Phase operation handler struct.
struct PhaseOp {
    name: String,
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Op<ProfileValue> for PhaseOp {
    fn apply(&self, _node: NodeId, _args: &[ProfileValue]) -> Result<ProfileValue, dsl_kit::EngineError> {
        self.log.lock().unwrap().push(self.name.clone());
        Ok(ProfileValue::Success(format!("{} executed", self.name)))
    }
}

/// Creates an OpRegistry containing mock handlers for all 22 catalog phase apply targets.
pub fn profile_op_registry(executed_log: Arc<std::sync::Mutex<Vec<String>>>) -> Arc<OpRegistry<ProfileValue>> {
    let mut r = OpRegistry::new();

    let ops = vec![
        "system_apt",
        "comfyui_install",
        "python_version_check",
        "python_deps",
        "custom_nodes",
        "sync_pull",
        "sync_push",
        "staging_push",
        "models",
        "llm_models",
        "post_install",
        "comfyui_restart",
        "comfyui_health",
        "service_start",
        "service_ready",
        "sh_exec",
        "fs_write",
        "net_http_get",
        "net_http_post",
        "net_transfer",
        "mount_bind",
        "mount_umount",
    ];

    for op_name in ops {
        r.register(
            op_name,
            Arc::new(PhaseOp {
                name: op_name.to_string(),
                log: Arc::clone(&executed_log),
            }),
        );
    }

    Arc::new(r)
}

/// Owned AST projection: the engine borrows nothing, so hosts can hold
/// program and engine together without `Box::leak`.
pub type ProfileAst =
    OwnedDerivedAst<<ProfileNode as DslExecTrait>::LitValue, ProfileSemantics>;

/// Instantiates a dsl-kit-core Engine for driving execution of a ProfileNode AST.
pub fn create_profile_engine(
    root: &ProfileNode,
    executed_log: Arc<std::sync::Mutex<Vec<String>>>,
) -> Engine<ProfileAst> {
    Engine::new_with_ops(
        OwnedDerivedAst::new(root, ProfileSemantics),
        Arc::new(ReducerRegistry::new()),
        profile_op_registry(executed_log),
    )
    .expect("Engine initialization should succeed")
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let examples = example_gen::examples_from_grammar(&grammar)
            .expect("example generation failed");
        assert!(!examples.composite.is_empty(), "examples should be generated");
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
                    "src": "b2://bucket/model.safetensors",
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

        // 3. Instantiate dsl-kit-core Engine
        let executed_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut engine = create_profile_engine(&profile_ast, Arc::clone(&executed_log));

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

        // Verify all phases in the sequence were executed in declaration order
        let log = executed_log.lock().unwrap();
        assert_eq!(
            *log,
            vec![
                "system_apt",
                "python_deps",
                "sync_pull",
                "post_install",
                "sh_exec"
            ]
        );
    }
}
