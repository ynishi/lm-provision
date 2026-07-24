//! End-to-end exec-bridge tests driving a real dsl-kit engine over a
//! `ProfileNode` AST (backlog D).

use std::convert::Infallible;
use std::error::Error;
use std::sync::{Arc, Mutex};

use dsl_kit::{Engine, EngineError, ExecError, IdGen, StepOutcome, Stepper};
use lm_provision::dsl_poc::{create_profile_engine, ProfileAst, ProfileNode};
use lm_provision::exec::ExecMode;

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
        env: Vec::new(),
        env_secrets: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["echo".to_string(), "hi".to_string()],
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
        env: Vec::new(),
        env_secrets: Vec::new(),
        phases: vec![
            ProfileNode::ShExec {
                id: ids.node(),
                argv: vec!["ls".to_string()],
            },
            ProfileNode::FsWrite {
                id: ids.node(),
                path: "/tmp/should-not-be-written".to_string(),
                content: "x".to_string(),
            },
            ProfileNode::NetHttpGet {
                id: ids.node(),
                url: "https://example.com/get".to_string(),
            },
            ProfileNode::NetHttpPost {
                id: ids.node(),
                url: "https://example.com/post".to_string(),
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
        env: Vec::new(),
        env_secrets: Vec::new(),
        phases: vec![ProfileNode::ShExec {
            id: ids.node(),
            argv: vec!["echo".to_string(), "hello".to_string()],
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
        capabilities: vec!["sh.exec".to_string(), "net.transfer".to_string()],
        env: Vec::new(),
        env_secrets: Vec::new(),
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
            },
            ProfileNode::ComfyUiHealth {
                id: ids.node(),
                port: addr.port(),
            },
            ProfileNode::ServiceStart {
                id: ids.node(),
                name: "llm".to_string(),
                platform_kind: "vllm".to_string(),
            },
            ProfileNode::ServiceReady {
                id: ids.node(),
                name: "llm".to_string(),
                check_url: format!("http://127.0.0.1:{}/health", addr.port()),
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
    // The dry-run must not touch the filesystem or network — the
    // custom_nodes / models / llm_models targets stay absent.
    assert!(
        !std::path::Path::new("/workspace/ComfyUI/models/checkpoints/a.bin").exists(),
        "dry-run models must not perform the transfer"
    );
}

/// `staging_push` is structurally unsupported until the AST grows an
/// `env` field — dry-run surfaces the failure at step time so an
/// operator cannot ship a profile that would silently no-op in real
/// mode.
#[test]
fn staging_push_fails_in_dry_run_pending_ast_env_extension() {
    use std::error::Error;

    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "staging-push".to_string(),
        version: None,
        description: None,
        capabilities: vec!["net.transfer".to_string()],
        env: Vec::new(),
        env_secrets: Vec::new(),
        phases: vec![ProfileNode::StagingPush {
            id: ids.node(),
            src: "/workspace/out.bin".to_string(),
            dst: "hf://owner/repo".to_string(),
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::DryRun, log).expect("engine builds");
    let err = run_to_done(&mut engine).expect_err("staging_push must fail");
    let source = err
        .source()
        .expect("EvalFailed carries the ExecError source");
    assert!(
        source.to_string().contains("env-routed CLI dispatch"),
        "expected the KNOWN LIMITATION message, got: {source}"
    );
}

/// Real-mode `comfyui_health` polls a local HTTP server that answers
/// `200` on the first request, so the poll loop succeeds immediately
/// (no sleep). Uses the raw-TCP mock server pattern from the effects
/// module test.
#[test]
fn comfyui_health_polls_a_local_server_when_executing_effects() {
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
        capabilities: vec!["sh.exec".to_string()],
        env: Vec::new(),
        env_secrets: Vec::new(),
        phases: vec![ProfileNode::ComfyUiHealth {
            id: ids.node(),
            port,
        }],
    };

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut engine = create_profile_engine(&program, ExecMode::Real, Arc::clone(&log))
        .expect("engine builds for a declared sh.exec capability");
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
