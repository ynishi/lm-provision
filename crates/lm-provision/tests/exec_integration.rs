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
