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
        capabilities: vec!["sh.exec".to_string(), "net.transfer".to_string()],
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // Lifecycle ops do not run through the direct-op path / URL
        // policy check (spec 07 §"lifecycle op internal steps" is
        // deferred to a later revision), so this fixture leaves both
        // allowlists empty and still traces every lifecycle op.
        paths: Vec::new(),
        http_allowlist: Vec::new(),
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
            },
            ProfileNode::ServiceStart {
                id: ids.node(),
                name: "llm".to_string(),
                platform_kind: "vllm".to_string(),
                model: None,
                dtype: None,
                extra_args: vec![],
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

/// `staging_push` to an `hf://` dst now composes a concrete
/// `huggingface-cli upload` step (spec 02 §Dispatch routing); a dry run
/// renders the CLI trace without touching the network. The upload is
/// always CLI-routed regardless of `env` (04-bridge §net.transfer).
#[test]
fn staging_push_hf_dst_composes_a_cli_upload_in_dry_run() {
    let ids = IdGen::new();
    let program = ProfileNode::Spec {
        id: ids.node(),
        name: "staging-push".to_string(),
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
        log[0].contains("huggingface-cli")
            && log[0].contains("upload")
            && log[0].contains("owner/repo")
            && log[0].contains("--revision")
            && log[0].contains("main"),
        "dry-run trace should carry the upload argv: {}",
        log[0]
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
        env: std::collections::BTreeMap::new(),
        env_secrets: Vec::new(),
        // ComfyUiHealth is a lifecycle op; the direct-op HTTP policy
        // does not gate its internal poll (see the lifecycle carry
        // note).
        paths: Vec::new(),
        http_allowlist: Vec::new(),
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
            content: "x".to_string(),
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
            content: "x".to_string(),
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
