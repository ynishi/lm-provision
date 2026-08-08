//! End-to-end exec-bridge tests driving a real dsl-kit engine over a
//! `ProfileNode` AST (backlog D).

use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex};

use dsl_kit::{Engine, EngineError, ExecError, IdGen, StepOutcome, Stepper};
use lm_provision::exec::ExecMode;
use lm_provision::profile_ast::{create_profile_engine, ProfileAst, ProfileNode};

/// Drive the engine to `Done`, surfacing the first step error.
///
/// The engine's `Stepper::Error` is [`ExecError<Infallible>`]: an op's
/// [`EngineError`] arrives wrapped as [`ExecError::Engine`].
fn run_to_done(engine: &mut Engine<ProfileAst>) -> Result<(), ExecError<Infallible>> {
    let mut steps = 0;
    loop {
        let outcome = engine.step()?;
        steps += 1;
        if matches!(outcome, StepOutcome::Done(_)) {
            return Ok(());
        }
        assert!(steps <= 100, "execution exceeded expected step limit");
    }
}

/// Profile whose single `ShExec` phase requires `sh.exec` while the
/// profile declares no capabilities — even in dry-run the op must fail,
/// proving the physical "declared ⊆ used" enforcement.
#[test]
fn an_undeclared_capability_fails_the_op_even_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "no-caps".to_string(),
        version: None,
        description: None,
        capabilities: Vec::new(),
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // sh_exec does not consult path / http policy, so the empty
        // allowlists are fine for this fixture — the point is that the
        // capability gate rejects the op first.
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["echo".to_string(), "hi".to_string()],
            env: Default::default(),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, log)
        .expect("an empty capability set is valid and builds");

    let err = run_to_done(&mut engine)
        .expect_err("a ShExec phase without sh.exec declared must fail at step");
    assert!(matches!(
        err,
        ExecError::Engine(EngineError::EvalFailed { .. })
    ));
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source
            .to_string()
            .contains("not declared in profile.capabilities"),
        "expected the capability-denied cause, got: {source}"
    );
}

/// Dry-run over all seven direct ops leaves one op-name-prefixed trace
/// line per op, in declaration order, and runs no real effect.
#[test]
fn dry_run_traces_every_direct_op() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "direct-7".to_string(),
        version: None,
        description: None,
        capabilities: vec![
            "sh.exec".to_string(),
            "fs.write".to_string(),
            "net.http_get".to_string(),
            "net.http_post".to_string(),
            "net.transfer".to_string(),
            "mount.bind".to_string(),
            "mount.umount".to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // Declared roots cover every filesystem target the phases
        // touch (FsWrite path, NetTransfer dst, MountBind src / dst,
        // MountUmount path) and the URL allowlist covers every URL
        // (both NetHttp* ops and the NetTransfer source), so policy
        // check passes for every direct op and the dry-run trace
        // reaches its full 7-line shape.
        paths: vec!["/tmp".to_string(), "/src".to_string(), "/dst".to_string()],
        http_allowlist: vec!["https://example.com".to_string()],
        phases: vec![
            ProfileNode::ShExec {
                id: ids.node(),
                argv: vec!["ls".to_string()],
                env: Default::default(),
            },
            ProfileNode::FsWrite {
                id: ids.node(),
                path: "/tmp/should-not-be-written".to_string(),
                content: Box::new(ProfileNode::EnvLiteral {
                    id: ids.node(),
                    value: "x".to_string(),
                }),
            },
            ProfileNode::NetHttpGet {
                id: ids.node(),
                url: "https://example.com/get".to_string(),
                headers: std::collections::BTreeMap::new(),
                timeout_sec: None,
            },
            ProfileNode::NetHttpPost {
                id: ids.node(),
                url: "https://example.com/post".to_string(),
                headers: std::collections::BTreeMap::new(),
                body: None,
                body_json: None,
                timeout_sec: None,
            },
            ProfileNode::NetTransfer {
                id: ids.node(),
                src: "https://example.com/a".to_string(),
                dst: "/tmp/a".to_string(),
            },
            ProfileNode::MountBind {
                id: ids.node(),
                src: "/src".to_string(),
                dst: "/dst".to_string(),
            },
            ProfileNode::MountUmount {
                id: ids.node(),
                path: "/dst".to_string(),
            },
        ],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds for a fully declared capability set");
    run_to_done(&mut engine).expect("dry run must complete without running effects");

    // The dry-run FsWrite must not have touched the filesystem.
    assert!(
        !std::path::Path::new("/tmp/should-not-be-written").exists(),
        "dry-run fs_write must not perform the effect"
    );

    let log = log.lock().unwrap();
    let expected = [
        "sh_exec",
        "fs_write",
        "net_http_get",
        "net_http_post",
        "net_transfer",
        "mount_bind",
        "mount_umount",
    ];
    assert_eq!(log.len(), expected.len());
    for (line, op) in log.iter().zip(expected) {
        assert!(
            line.starts_with(op),
            "trace line {line:?} should start with the op name {op:?}"
        );
    }
}

/// Real mode runs `sh_exec` for real: `echo hello` exits 0 and its
/// stdout reaches the summary log line.
#[test]
fn real_mode_runs_sh_exec_and_summarises_the_result() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "real-sh".to_string(),
        version: None,
        description: None,
        capabilities: vec!["sh.exec".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // sh_exec has no path / URL surface, so the empty allowlists
        // are inert here.
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["echo".to_string(), "hello".to_string()],
            env: Default::default(),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::Real, Arc::clone(&log))
        .expect("engine builds for a declared sh.exec capability");
    run_to_done(&mut engine).expect("a real `echo hello` must succeed");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("sh_exec"));
    assert!(
        log[0].contains("exit=0"),
        "summary should report exit=0: {}",
        log[0]
    );
    assert!(
        log[0].contains("hello"),
        "summary should carry stdout: {}",
        log[0]
    );
}

/// Dry-run trace for every lifecycle op that can compose successfully
/// from the current AST payload — 14 of the 15. `staging_push` is
/// structurally always [`ExecError::Unsupported`] (env-routed CLI
/// dispatch, pending an AST `env` field extension), so it cannot be
/// part of a happy-path trace and is asserted separately below. Also
/// asserts that the previous placeholder trace line
/// (`"(lifecycle: wiring pending)"`) never appears — the wiring is
/// real now.
#[test]
fn dry_run_traces_every_traceable_lifecycle_op() {
    use std::net::TcpListener;

    // Bind an ephemeral port for the two HttpPoll steps
    // (comfyui_health / service_ready). Dry-run does not touch the
    // socket, but the port has to be valid for the URL substitution.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "lifecycle-traceable".to_string(),
        version: None,
        description: None,
        // The two HTTP polls (comfyui_health / service_ready) are gated
        // on `net.http_get`, not `sh.exec` — they expand into a single
        // poll step (spec 02 §Catalog kinds / 05 §L4).
        capabilities: vec![
            "sh.exec".to_string(),
            "net.transfer".to_string(),
            "net.http_get".to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // A lifecycle op reaches the same bridges a direct op does and
        // answers to the same allowlists (spec 05 §L3), so every
        // destination the phases below write to and every host they
        // reach is declared here.
        paths: vec![
            "/workspace".to_string(),
            "/workspace/ComfyUI/models".to_string(),
        ],
        http_allowlist: vec![
            "https://example.com".to_string(),
            "https://ex".to_string(),
            format!("http://127.0.0.1:{}", addr.port()),
        ],
        phases: vec![
            ProfileNode::SystemApt {
                id: ids.node(),
                packages: vec!["git".to_string()],
            },
            ProfileNode::ComfyUiInstall {
                id: ids.node(),
                ref_name: "v0.1.0".to_string(),
                repo: None,
            },
            ProfileNode::PythonVersionCheck {
                id: ids.node(),
                want: "3.12".to_string(),
            },
            ProfileNode::PythonDeps {
                id: ids.node(),
                deps: vec!["torch".to_string()],
                in_comfy_venv: true,
            },
            ProfileNode::CustomNodes {
                id: ids.node(),
                nodes_json: r#"[{"name":"n1","repo":"a/b","ref":"v1","pip":true}]"#.to_string(),
            },
            ProfileNode::SyncPull {
                id: ids.node(),
                src: "https://example.com/m.bin".to_string(),
                dst: "/workspace/m.bin".to_string(),
                env: Default::default(),
                revision: None,
            },
            ProfileNode::SyncPush {
                id: ids.node(),
                src: "/workspace/out.bin".to_string(),
                dst: "https://example.com/out.bin".to_string(),
            },
            ProfileNode::Models {
                id: ids.node(),
                models_json: r#"[{"src":"https://ex/a.bin","dst":"a.bin"}]"#.to_string(),
            },
            ProfileNode::LlmModels {
                id: ids.node(),
                models_json: r#"[{"src":"hf://owner/repo@main"}]"#.to_string(),
            },
            ProfileNode::PostInstall {
                id: ids.node(),
                script: "echo done".to_string(),
            },
            ProfileNode::ComfyUiRestart {
                id: ids.node(),
                port: addr.port(),
                extra_args: Vec::new(),
            },
            ProfileNode::ComfyUiHealth {
                id: ids.node(),
                port: addr.port(),
                timeout_sec: None,
            },
            ProfileNode::ServiceStart {
                id: ids.node(),
                name: "llm".to_string(),
                platform_kind: "vllm".to_string(),
                model: None,
                port: None,
                dtype: None,
                tensor_parallel_size: None,
                extra_args: vec![],
            },
            ProfileNode::ServiceReady {
                id: ids.node(),
                name: "llm".to_string(),
                check_url: format!("http://127.0.0.1:{}/health", addr.port()),
                timeout_sec: None,
            },
        ],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds for the declared capability set");
    run_to_done(&mut engine).expect("dry run must complete without running effects");

    let log = log.lock().unwrap();
    let expected_prefixes = [
        "system_apt",
        "comfyui_install",
        "python_version_check",
        "python_deps",
        "custom_nodes",
        "sync_pull",
        "sync_push",
        "models",
        "llm_models",
        "post_install",
        "comfyui_restart",
        "comfyui_health",
        "service_start",
        "service_ready",
    ];
    assert_eq!(log.len(), expected_prefixes.len());
    for (line, op) in log.iter().zip(expected_prefixes) {
        assert!(
            line.starts_with(op),
            "trace line {line:?} should start with the op name {op:?}"
        );
    }
    for line in log.iter() {
        assert!(
            !line.contains("(lifecycle: wiring pending)"),
            "lifecycle wiring is live now; placeholder text must not appear: {line}"
        );
    }
    // The launch records a pid and the poll that follows watches it, so
    // a server that dies during the readiness wait fails at once rather
    // than at the deadline (spec 02 §Spawn-and-poll invocations). The
    // trace is where an operator sees that pairing.
    let line_for = |op: &str| {
        log.iter()
            .find(|line| line.starts_with(op))
            .unwrap_or_else(|| panic!("no trace line for {op}"))
    };
    let restart = line_for("comfyui_restart");
    assert!(
        restart.contains("echo $pid > /tmp/comfyui.pid") && restart.contains("kill -0 $pid"),
        "the launch should record and settle-check its pid: {restart}"
    );
    assert!(
        line_for("comfyui_health").contains("pid_file=/tmp/comfyui.pid"),
        "the health poll should watch the launch's pid file: {}",
        line_for("comfyui_health")
    );
    assert!(
        line_for("service_ready").contains("pid_file=/tmp/llm.pid"),
        "the readiness poll should watch its service's pid file: {}",
        line_for("service_ready")
    );
    // The dry-run must not touch the filesystem or network — the
    // custom_nodes / models / llm_models targets stay absent.
    assert!(
        !std::path::Path::new("/workspace/ComfyUI/models/checkpoints/a.bin").exists(),
        "dry-run models must not perform the transfer"
    );
}

/// `staging_push` to an `hf://` dst now composes a concrete
/// `hf upload` step (spec 02 §Dispatch routing); a dry run
/// renders the CLI trace without touching the network. The upload is
/// always CLI-routed regardless of `env` (04-bridge §net.transfer), so
/// the capability it demands is `sh.exec` — the resolved route's, not
/// the kind's (spec 02 §Dispatch routing "What the L4 gate sees").
#[test]
fn staging_push_hf_dst_composes_a_cli_upload_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "staging-push".to_string(),
        version: None,
        description: None,
        capabilities: vec!["sh.exec".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::StagingPush {
            id: ids.node(),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo/artifact.bin".to_string(),
            env: Default::default(),
            revision: Some("main".to_string()),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine =
        create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log)).expect("engine builds");
    run_to_done(&mut engine).expect("staging_push hf dst composes a dry-run trace");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("staging_push"), "{}", log[0]);
    assert!(
        log[0].contains("\"hf\"")
            && log[0].contains("upload")
            && log[0].contains("owner/repo")
            && log[0].contains("--revision")
            && log[0].contains("main"),
        "dry-run trace should carry the upload argv: {}",
        log[0]
    );
}

/// The gate sees the route, not the kind: a `staging.push` is always
/// CLI-routed, so a profile granting only `net.transfer` — the
/// capability its *kind* carries in the catalog table — is denied
/// before the shell runs (spec 02 §Dispatch routing "What the L4 gate
/// sees"). Granting the union of both routes up front would let a
/// shell run under a profile that never asked for one.
#[test]
fn staging_push_is_denied_when_only_net_transfer_is_granted() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "staging-push-ungated".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.transfer".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::StagingPush {
            id: ids.node(),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo/artifact.bin".to_string(),
            env: Default::default(),
            revision: None,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine =
        create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log)).expect("engine builds");
    let err = run_to_done(&mut engine).expect_err("the CLI-routed upload demands sh.exec");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source")
        .to_string();
    assert!(
        source.contains("sh.exec"),
        "the denial should name the capability the resolved route needs: {source}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing runs once the gate denies the phase"
    );
}

/// A `sync.pull` moves between the two demands with its payload: an
/// `https://` src stays on the bridge and needs `net.transfer`, while
/// an `hf://` src with a credential `env` routes to the CLI and needs
/// `sh.exec` (spec 02 §Dispatch routing "What the L4 gate sees").
#[test]
fn sync_pull_demands_the_capability_of_the_route_its_payload_resolves_to() {
    /// `bridge` picks the `https://` src (net.transfer route) over the
    /// credential-`env` `hf://` src (CLI route); `capability` is the
    /// profile's single declared capability.
    fn pull(bridge: bool, capability: &str) -> Result<(), String> {
        let ids = IdGen::new();
        let mut env = std::collections::BTreeMap::new();
        if !bridge {
            env.insert(
                "HF_TOKEN".to_string(),
                ProfileNode::EnvLiteral {
                    id: ids.node(),
                    value: "credential-value".to_string(),
                },
            );
        }
        let src = if bridge {
            "https://example.com/model.bin"
        } else {
            "hf://owner/repo/model.bin"
        };
        let program = ProfileNode::Spec {
            id: ids.node(),
            name: "sync-pull-route".to_string(),
            version: None,
            description: None,
            capabilities: vec![capability.to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths: vec!["/workspace".to_string()],
            http_allowlist: vec!["https://example.com".to_string()],
            phases: vec![ProfileNode::SyncPull {
                id: ids.node(),
                src: src.to_string(),
                dst: "/workspace/model.bin".to_string(),
                env,
                revision: None,
            }],
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
            .expect("engine builds");
        run_to_done(&mut engine).map(|_| ()).map_err(|err| {
            err.source()
                .map_or_else(|| err.to_string(), |source| source.to_string())
        })
    }

    assert_eq!(
        pull(true, "net.transfer"),
        Ok(()),
        "an https:// pull stays on the net.transfer bridge"
    );
    assert!(
        pull(true, "sh.exec").is_err(),
        "a bridge pull must not pass on sh.exec alone"
    );
    assert_eq!(
        pull(false, "sh.exec"),
        Ok(()),
        "a credential env moves the pull onto the CLI route"
    );
    assert!(
        pull(false, "net.transfer").is_err(),
        "the CLI route must not pass on the kind's net.transfer alone"
    );
}

/// Policy on a `net.transfer` follows the resolved route, not the field
/// names (spec 04 §net.transfer): an upload's `dst` is the remote side,
/// so it goes through the http allowlist rather than the path roots,
/// and its local `src` goes through the path roots.
#[test]
fn a_net_transfer_upload_gates_its_destination_on_the_http_allowlist() {
    fn upload(allowlist: Vec<String>, paths: Vec<String>) -> Result<(), String> {
        let ids = IdGen::new();
        let program = ProfileNode::Spec {
            id: ids.node(),
            name: "upload-policy".to_string(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths,
            http_allowlist: allowlist,
            phases: vec![ProfileNode::NetTransfer {
                id: ids.node(),
                src: "/workspace/out.bin".to_string(),
                dst: "https://example.com/out.bin".to_string(),
            }],
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
            .expect("engine builds");
        run_to_done(&mut engine).map(|_| ()).map_err(|err| {
            err.source()
                .map_or_else(|| err.to_string(), |source| source.to_string())
        })
    }

    assert_eq!(
        upload(
            vec!["https://example.com".to_string()],
            vec!["/workspace".to_string()]
        ),
        Ok(()),
        "a listed host and a declared source root pass"
    );
    let unlisted = upload(Vec::new(), vec!["/workspace".to_string()])
        .expect_err("an unlisted upload host must be denied");
    assert!(
        unlisted.contains("http_allowlist"),
        "the denial should name the allowlist: {unlisted}"
    );
    let unrooted = upload(vec!["https://example.com".to_string()], Vec::new())
        .expect_err("an undeclared source root must be denied");
    assert!(
        unrooted.contains("outside profile.paths"),
        "the denial should name the path roots: {unrooted}"
    );
}

/// An `hf://` source is gated on the URL it resolves to, not on the
/// authored URI: the allowlist has to name `huggingface.co`, otherwise a
/// profile could reach a host it never declared (spec 05 L3).
#[test]
fn a_public_hf_download_gates_on_the_resolved_host() {
    fn pull(allowlist: Vec<String>) -> Result<(), String> {
        let ids = IdGen::new();
        let program = ProfileNode::Spec {
            id: ids.node(),
            name: "hf-policy".to_string(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths: vec!["/workspace".to_string()],
            http_allowlist: allowlist,
            phases: vec![ProfileNode::NetTransfer {
                id: ids.node(),
                src: "hf://owner/repo/model.bin".to_string(),
                dst: "/workspace/model.bin".to_string(),
            }],
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
            .expect("engine builds");
        run_to_done(&mut engine).map(|_| ()).map_err(|err| {
            err.source()
                .map_or_else(|| err.to_string(), |source| source.to_string())
        })
    }

    assert_eq!(
        pull(vec!["https://huggingface.co".to_string()]),
        Ok(()),
        "the resolved host is what the allowlist has to carry"
    );
    assert!(
        pull(Vec::new()).is_err(),
        "an empty allowlist must not let the resolved host through"
    );
}

/// A lifecycle phase answers to the same allowlists a direct op does
/// (spec 05 §L3): the `sync.pull` spelling of a download is gated on
/// `paths` / `http_allowlist` exactly as the `net.transfer` spelling
/// is, and a poll's URL is gated like any other bridge GET. Both fire
/// in dry-run, before any effect.
#[test]
fn lifecycle_steps_answer_to_the_path_and_http_allowlists() {
    fn run(phase: ProfileNode, paths: Vec<String>, allowlist: Vec<String>) -> Result<(), String> {
        let ids = IdGen::new();
        let program = ProfileNode::Spec {
            id: ids.node(),
            name: "lifecycle-policy".to_string(),
            version: None,
            description: None,
            capabilities: vec!["net.transfer".to_string(), "net.http_get".to_string()],
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            paths,
            http_allowlist: allowlist,
            phases: vec![phase],
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
            .expect("engine builds");
        run_to_done(&mut engine).map(|_| ()).map_err(|err| {
            err.source()
                .map_or_else(|| err.to_string(), |source| source.to_string())
        })
    }

    let pull = |ids: &IdGen| ProfileNode::SyncPull {
        id: ids.node(),
        src: "https://example.com/m.bin".to_string(),
        dst: "/workspace/m.bin".to_string(),
        env: Default::default(),
        revision: None,
    };
    let ids = IdGen::new();
    assert_eq!(
        run(
            pull(&ids),
            vec!["/workspace".to_string()],
            vec!["https://example.com".to_string()]
        ),
        Ok(()),
        "a declared destination and host pass"
    );
    let unrooted = run(
        pull(&ids),
        Vec::new(),
        vec!["https://example.com".to_string()],
    )
    .expect_err("an undeclared destination root must be denied");
    assert!(
        unrooted.contains("outside profile.paths"),
        "expected the path denial, got: {unrooted}"
    );
    let unlisted = run(pull(&ids), vec!["/workspace".to_string()], Vec::new())
        .expect_err("an unlisted download host must be denied");
    assert!(
        unlisted.contains("http_allowlist"),
        "expected the allowlist denial, got: {unlisted}"
    );

    let poll = ProfileNode::ComfyUiHealth {
        id: ids.node(),
        port: 8188,
        timeout_sec: Some(1),
    };
    let poll_denied = run(poll, Vec::new(), Vec::new())
        .expect_err("a poll against an unlisted host must be denied");
    assert!(
        poll_denied.contains("http_allowlist"),
        "expected the allowlist denial for the poll, got: {poll_denied}"
    );
}

/// A `ShExec` referencing a secret that is not declared in
/// `profile.env_secrets` fails at step time even under dry-run — spec 06
/// §Resolution "dry-run resolves too": the decode path runs, so the
/// undeclared-secret error surfaces identically whether or not the
/// effect executes.
#[test]
fn sh_exec_undeclared_secret_fails_in_dry_run() {
    use std::error::Error;

    let ids = IdGen::new();
    let mut env = std::collections::BTreeMap::new();
    env.insert(
        "HF_TOKEN".to_string(),
        ProfileNode::EnvSecret {
            id: ids.node(),
            name: "HF_TOKEN".to_string(),
        },
    );
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "undeclared-secret".to_string(),
        version: None,
        description: None,
        capabilities: vec!["sh.exec".to_string()],
        env: std::collections::BTreeMap::new(),
        // env_secrets is EMPTY: HF_TOKEN is referenced but not declared.
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["true".to_string()],
            env,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, log).expect("engine builds");
    let err = run_to_done(&mut engine).expect_err("an undeclared secret must fail even in dry-run");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source
            .to_string()
            .contains("is not declared in profile.env_secrets"),
        "expected the undeclared-secret error, got: {source}"
    );
}

/// Real-mode `ShExec` injects a resolved secret into the child process:
/// the declared secret is read from the host env and appears in the
/// child's environment (proven by echoing it back on stdout). The trace
/// line records the env *key* only, never the value.
#[test]
fn sh_exec_injects_a_declared_secret_into_the_child_in_real_mode() {
    let var = format!("LM_EXEC_IT_SECRET_{}", std::process::id());
    std::env::set_var(&var, "top-secret-token");

    let ids = IdGen::new();
    let mut env = std::collections::BTreeMap::new();
    env.insert(
        "SLOT".to_string(),
        ProfileNode::EnvSecret {
            id: ids.node(),
            name: var.clone(),
        },
    );
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "inject-secret".to_string(),
        version: None,
        description: None,
        capabilities: vec!["sh.exec".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: vec![var.clone()],
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf %s \"$SLOT\"".to_string(),
            ],
            env,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine =
        create_profile_engine(&program, ExecMode::Real, Arc::clone(&log)).expect("engine builds");
    let result = run_to_done(&mut engine);
    std::env::remove_var(&var);
    result.expect("real-mode sh_exec with an injected secret succeeds");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(
        log[0].contains("top-secret-token"),
        "the child echoed the injected secret back on stdout: {}",
        log[0]
    );
}

/// Real-mode `comfyui_health` polls a local HTTP server that answers
/// `200` on the first request, so the poll loop succeeds immediately
/// (no sleep). Uses the raw-TCP mock server pattern from the effects
/// module test.
///
/// Real mode drives an async effect, which blocks its thread on the
/// current runtime — hence the multi-threaded flavour (see
/// `lm_provision::exec::effects::block_on_effect`). Every other test in
/// this file either stays in dry run or runs a synchronous effect, so
/// they need no runtime at all.
#[tokio::test(flavor = "multi_thread")]
async fn comfyui_health_polls_a_local_server_when_executing_effects() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let body = "ok";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });

    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "health".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_get".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // The poll answers to the http allowlist like any other bridge
        // GET (spec 05 §L3), so the local server it waits on is
        // declared.
        paths: Vec::new(),
        http_allowlist: vec![format!("http://127.0.0.1:{port}")],
        phases: vec![ProfileNode::ComfyUiHealth {
            id: ids.node(),
            port,
            // The server answers on the first GET, so the deadline is
            // never approached; a short one keeps a regression here
            // from stalling the suite for the kind default's 180 s.
            timeout_sec: Some(5),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::Real, Arc::clone(&log))
        .expect("engine builds for a declared net.http_get capability");
    run_to_done(&mut engine).expect("health poll must succeed on the first attempt");

    handle.join().expect("server thread joins");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("comfyui_health"));
    assert!(
        log[0].contains("status=200"),
        "summary should record status=200: {}",
        log[0]
    );
}

/// The two HTTP polls are gated on the capability of the effect they
/// expand into, which is a GET (spec 02 §Catalog kinds, chapter 05
/// §L4): `sh.exec` alone no longer reaches either poll, and
/// `net.http_get` alone is the whole requirement — the pid file the
/// poll re-reads is a provisioner-internal read, not a bridge op.
/// Dry-run is enough to prove both halves: the gate is an entry check
/// that fires before any effect.
#[test]
fn http_poll_lifecycle_ops_are_gated_on_net_http_get_not_sh_exec() {
    let poll_profile = |capabilities: Vec<String>| {
        let ids = IdGen::new();
        ProfileNode::Spec {
            id: ids.node(),
            name: "poll-gate".to_string(),
            version: None,
            description: None,
            capabilities,
            env: std::collections::BTreeMap::new(),
            env_secrets: Vec::new(),
            // Both poll targets are declared so the capability gate is
            // the only thing under test here — the http allowlist has
            // its own coverage below.
            paths: Vec::new(),
            http_allowlist: vec![
                "http://127.0.0.1:8188".to_string(),
                "http://127.0.0.1:9000".to_string(),
            ],
            phases: vec![
                ProfileNode::ComfyUiHealth {
                    id: ids.node(),
                    port: 8188,
                    timeout_sec: Some(1),
                },
                ProfileNode::ServiceReady {
                    id: ids.node(),
                    name: "llm".to_string(),
                    check_url: "http://127.0.0.1:9000/health".to_string(),
                    timeout_sec: Some(1),
                },
            ],
        }
    };

    let sh_only = poll_profile(vec!["sh.exec".to_string()]);
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&sh_only, ExecMode::DryRun, log).expect("engine builds");
    let err = run_to_done(&mut engine)
        .expect_err("a poll without net.http_get declared must fail at step");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    let message = source.to_string();
    assert_eq!(
        message, "capability 'net.http_get' not declared in profile.capabilities",
        "the denial must name the GET capability, not sh.exec: {message}"
    );

    let http_only = poll_profile(vec!["net.http_get".to_string()]);
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&http_only, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds");
    run_to_done(&mut engine)
        .expect("net.http_get alone must open both polls, with no sh.exec declared");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2);
    assert!(log[0].starts_with("comfyui_health"), "{}", log[0]);
    assert!(log[1].starts_with("service_ready"), "{}", log[1]);
}

/// A dry-run `FsWrite` whose target path is not covered by any
/// declared `paths` root fails with `PathDenied` — spec 07 says
/// "dry-run does policy", so the physical enforcement runs even
/// though no bytes reach the filesystem.
#[test]
fn fs_write_to_an_undeclared_path_root_fails_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "no-paths".to_string(),
        version: None,
        description: None,
        capabilities: vec!["fs.write".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // Capability is declared but the path allowlist is empty:
        // policy denies even before the dry-run trace is recorded.
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::FsWrite {
            id: ids.node(),
            path: "/tmp/blocked".to_string(),
            content: Box::new(ProfileNode::EnvLiteral {
                id: ids.node(),
                value: "x".to_string(),
            }),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared fs.write capability");
    let err = run_to_done(&mut engine).expect_err("undeclared path must be rejected");
    assert!(matches!(
        err,
        ExecError::Engine(EngineError::EvalFailed { .. })
    ));
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source.to_string().contains("outside profile.paths"),
        "expected the path-denied cause, got: {source}"
    );
    // Nothing traced: policy fired before the dry-run record step.
    assert!(log.lock().unwrap().is_empty());
}

/// The same profile with `/tmp` declared traces the dry-run line
/// (proves the failure above is not a compile-time artefact — the
/// path policy is the only thing standing between denial and success).
#[test]
fn fs_write_under_a_declared_path_root_traces_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "declared-paths".to_string(),
        version: None,
        description: None,
        capabilities: vec!["fs.write".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: vec!["/tmp".to_string()],
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::FsWrite {
            id: ids.node(),
            path: "/tmp/allowed".to_string(),
            content: Box::new(ProfileNode::EnvLiteral {
                id: ids.node(),
                value: "x".to_string(),
            }),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared fs.write capability");
    run_to_done(&mut engine).expect("declared path must pass the policy check");

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("fs_write"));
    assert!(log[0].contains("/tmp/allowed"));
}

/// A dry-run `NetHttpGet` whose URL matches no declared pattern
/// fails with `HttpDenied` — the HTTP policy runs in dry-run too.
#[test]
fn http_get_to_an_undeclared_url_fails_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "no-http".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_get".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::NetHttpGet {
            id: ids.node(),
            url: "https://denied.example/".to_string(),
            headers: std::collections::BTreeMap::new(),
            timeout_sec: None,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared net.http_get capability");
    let err = run_to_done(&mut engine).expect_err("undeclared URL must be rejected");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source
            .to_string()
            .contains("matches no pattern in profile.http_allowlist"),
        "expected the http-denied cause, got: {source}"
    );
    assert!(log.lock().unwrap().is_empty());
}

/// A `NetTransfer` whose source is an HTTP URL is denied when the
/// URL is not on the allowlist, *even though* the destination path
/// is declared: both checks apply.
#[test]
fn net_transfer_denies_when_the_http_source_is_not_allowlisted() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "half-declared".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.transfer".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // Path is declared but HTTP source is not.
        paths: vec!["/tmp".to_string()],
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::NetTransfer {
            id: ids.node(),
            src: "https://denied.example/a".to_string(),
            dst: "/tmp/a".to_string(),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared net.transfer capability");
    let err = run_to_done(&mut engine).expect_err("undeclared HTTP source must be rejected");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source
            .to_string()
            .contains("matches no pattern in profile.http_allowlist"),
        "expected the http-denied cause, got: {source}"
    );
}

/// `MountBind` checks both `src` and `dst`; a rejection on either
/// side surfaces `PathDenied` and no trace line is recorded.
#[test]
fn mount_bind_denies_when_only_the_source_is_declared() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "half-mount".to_string(),
        version: None,
        description: None,
        capabilities: vec!["mount.bind".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: vec!["/src".to_string()],
        http_allowlist: Vec::new(),
        phases: vec![ProfileNode::MountBind {
            id: ids.node(),
            src: "/src".to_string(),
            dst: "/dst".to_string(),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared mount.bind capability");
    let err = run_to_done(&mut engine).expect_err("undeclared destination must be rejected");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source.to_string().contains("outside profile.paths"),
        "expected the path-denied cause, got: {source}"
    );
}

// ---------------------------------------------------------------------
// net.http_* request fields: headers / body / body_json / timeout_sec
// (spec 04 §`net.http_get` / `net.http_post`, spec 06 consumption
// point 4).
// ---------------------------------------------------------------------

/// Spawn a one-shot local HTTP server. Returns `(url, allowlist
/// pattern, handle)`; the handle yields the raw request text so a test
/// can assert on what actually went over the wire.
fn one_shot_server() -> (String, String, std::thread::JoinHandle<String>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        // Headers and body may arrive in separate TCP segments, so keep
        // reading until the header terminator is seen and, when a
        // Content-Length is declared, until the full body has arrived.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            if let Some(header_end) = text.find("\r\n\r\n") {
                let content_length = text[..header_end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let body = "ok";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        String::from_utf8_lossy(&buf).into_owned()
    });
    (
        format!("http://{addr}/post"),
        format!("http://{addr}"),
        handle,
    )
}

/// A secret header and a secret body resolve in **dry-run** (spec 06
/// §Resolution "dry-run resolves too") — and neither resolved value
/// reaches the trace line, which carries header *names* and the body's
/// form plus byte length only (spec 09).
#[test]
fn http_post_dry_run_resolves_the_secret_header_and_body_without_tracing_them() {
    let header_var = format!("LM_HTTP_HEADER_TOKEN_{}", std::process::id());
    let body_var = format!("LM_HTTP_BODY_SECRET_{}", std::process::id());
    std::env::set_var(&header_var, "header-value-that-must-not-leak");
    std::env::set_var(&body_var, "body-value-that-must-not-leak");

    let ids = IdGen::new();
    let headers = std::collections::BTreeMap::from([
        (
            "Authorization".to_string(),
            ProfileNode::EnvSecret {
                id: ids.node(),
                name: header_var.clone(),
            },
        ),
        (
            "Accept".to_string(),
            ProfileNode::EnvLiteral {
                id: ids.node(),
                value: "application/json".to_string(),
            },
        ),
    ]);
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "http-secrets".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_post".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: vec![header_var.clone(), body_var.clone()],
        paths: Vec::new(),
        http_allowlist: vec!["https://example.com".to_string()],
        phases: vec![ProfileNode::NetHttpPost {
            id: ids.node(),
            url: "https://example.com/post".to_string(),
            headers,
            body: Some(Box::new(ProfileNode::EnvSecret {
                id: ids.node(),
                name: body_var.clone(),
            })),
            body_json: None,
            timeout_sec: Some(7),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared net.http_post capability");
    run_to_done(&mut engine).expect("a dry run with resolvable secrets must succeed");
    std::env::remove_var(&header_var);
    std::env::remove_var(&body_var);

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    let line = &log[0];
    assert!(
        !line.contains("header-value-that-must-not-leak")
            && !line.contains("body-value-that-must-not-leak"),
        "no resolved value may reach the trace: {line}"
    );
    assert!(
        line.contains("Authorization") && line.contains("Accept"),
        "header names are traced: {line}"
    );
    assert!(
        line.contains(&format!("body=body:secret:{body_var}")),
        "the body is named by its source form, not its content: {line}"
    );
    assert!(
        line.contains(&format!(
            "body_bytes={}",
            "body-value-that-must-not-leak".len()
        )),
        "the body's byte length is traced: {line}"
    );
    assert!(
        line.contains("timeout_sec=7"),
        "the declared deadline is traced: {line}"
    );
}

/// A header naming a secret that is missing from the host env fails the
/// **dry run**, identically to a real run — the header slot goes through
/// the same check-then-resolve pipe as an `env` slot.
#[test]
fn http_get_with_a_host_absent_header_secret_fails_in_dry_run() {
    let var = format!("LM_HTTP_HEADER_ABSENT_{}", std::process::id());
    std::env::remove_var(&var);

    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "http-missing-secret".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_get".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: vec![var.clone()],
        paths: Vec::new(),
        http_allowlist: vec!["https://example.com".to_string()],
        phases: vec![ProfileNode::NetHttpGet {
            id: ids.node(),
            url: "https://example.com/get".to_string(),
            headers: std::collections::BTreeMap::from([(
                "Authorization".to_string(),
                ProfileNode::EnvSecret {
                    id: ids.node(),
                    name: var.clone(),
                },
            )]),
            timeout_sec: None,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared net.http_get capability");
    let err = run_to_done(&mut engine).expect_err("a host-absent header secret must fail");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source.to_string().contains("missing in host env"),
        "expected the missing-secret cause, got: {source}"
    );
    assert!(log.lock().unwrap().is_empty());
}

/// `apply` does not run validate first (spec 07 §Invocation), so the
/// `body` / `body_json` exclusivity rule is re-checked at exec: an AST
/// carrying both fails the step rather than silently acquiring an
/// invented precedence.
#[test]
fn declaring_both_body_forms_fails_the_step_even_without_validate() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "http-both-bodies".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_post".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: vec!["https://example.com".to_string()],
        phases: vec![ProfileNode::NetHttpPost {
            id: ids.node(),
            url: "https://example.com/post".to_string(),
            headers: std::collections::BTreeMap::new(),
            body: Some(Box::new(ProfileNode::EnvLiteral {
                id: ids.node(),
                value: "raw".to_string(),
            })),
            body_json: Some("{\"k\":1}".to_string()),
            timeout_sec: None,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, Arc::clone(&log))
        .expect("engine builds with a declared net.http_post capability");
    let err = run_to_done(&mut engine).expect_err("declaring both body forms must fail");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source
            .to_string()
            .contains("body and body_json are mutually exclusive"),
        "expected the exclusivity cause, got: {source}"
    );
    assert!(log.lock().unwrap().is_empty());
}

/// Real mode: the declared headers and the `body_json` document reach
/// the wire, with `Content-Type: application/json` derived from the body
/// form (spec 04 §`net.http_post`). Multi-threaded for the same reason
/// as `comfyui_health_polls_a_local_server_when_executing_effects`.
#[tokio::test(flavor = "multi_thread")]
async fn http_post_real_mode_sends_the_declared_headers_and_json_body() {
    let (url, allow, handle) = one_shot_server();
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "http-real".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.http_post".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        paths: Vec::new(),
        http_allowlist: vec![allow],
        phases: vec![ProfileNode::NetHttpPost {
            id: ids.node(),
            url: url.clone(),
            headers: std::collections::BTreeMap::from([(
                "X-Demo".to_string(),
                ProfileNode::EnvLiteral {
                    id: ids.node(),
                    value: "demo-value".to_string(),
                },
            )]),
            body: None,
            body_json: Some(r#"{"prompt":"hi"}"#.to_string()),
            timeout_sec: Some(10),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::Real, Arc::clone(&log))
        .expect("engine builds with a declared net.http_post capability");
    run_to_done(&mut engine).expect("the local server answers 200");

    let request = handle.join().expect("server thread joins");
    let lowered = request.to_lowercase();
    assert!(
        lowered.contains("x-demo: demo-value"),
        "declared header must reach the wire: {request}"
    );
    assert!(
        lowered.contains("content-type: application/json"),
        "body_json derives the JSON content type: {request}"
    );
    assert!(
        request.contains(r#"{"prompt":"hi"}"#),
        "the JSON body must reach the wire: {request}"
    );

    let log = log.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(
        log[0].contains("status=200"),
        "the summary carries the status: {}",
        log[0]
    );
}
