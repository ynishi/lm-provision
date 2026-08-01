//! Structured tracing events for the stderr audit transcript
//! (spec 09 §Audit log).
//!
//! Every effect invocation — both direct ops in [`super::registry`] and
//! lifecycle sub-steps in [`super::lifecycle`] — emits **one**
//! `tracing::info!` event through the helpers here **before the effect
//! runs**. The events go to the stderr `fmt` subscriber the binary
//! installs from `main.rs`, so `apply` produces the operational
//! transcript the driver in spec 08 collects.
//!
//! ## Redaction rules (spec 09)
//!
//! - Env keys: key **names** are logged; a name matching the
//!   sensitive-key set (spec 02 §Shared vocabulary,
//!   [`crate::validate::is_secret_shaped_key`]) is rendered as
//!   `NAME [REDACTED]` so the reader can tell a value was withheld.
//!   Values are never logged, sensitive or not.
//! - `fs.write` logs path + byte count + `content_source` — `"string"`
//!   for a literal `content: String`, `"secret:<name>"` once the
//!   secret-content form lands. Content bytes are never logged.
//! - HTTP logs URL and (once available) status + body byte count;
//!   header names are logged, header values never; bodies never.
//! - `sh.exec` logs argv verbatim (validate's shell-safety and the
//!   env-injection design keep secrets out of argv).
//! - `note` sub-steps log their kind + note text — they carry no
//!   effect input to redact.
//!
//! Emission runs in both [`super::ExecMode::DryRun`] and
//! [`super::ExecMode::Real`], mirroring the "dry-run does policy /
//! resolves secrets too" rule (spec 06 / 07). A dry-run trace is what
//! the profile *would* run; a real trace is what it *did*. Filter with
//! `--log-level` / `RUST_LOG` (chapter 07 §Global flags).

use std::collections::BTreeMap;

use crate::validate::is_secret_shaped_key;

/// The `mode` value on every event, so a caller filtering the stderr
/// stream can separate `dry-run` audits from `real` ones with a single
/// field match.
pub fn mode_label(mode: super::ExecMode) -> &'static str {
    match mode {
        super::ExecMode::DryRun => "dry-run",
        super::ExecMode::Real => "real",
    }
}

/// Render an env-injection map as the audit transcript sees it:
/// key names only, with a `[REDACTED]` marker appended to any name that
/// matches the sensitive-key set. Values never appear.
///
/// The rendered list is sorted (the input is a [`BTreeMap`] already, so
/// this is inherent, not a re-sort) so two runs of the same profile
/// produce byte-identical audit output — useful for diff-driven review
/// of a driver's collected stderr.
pub fn env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .map(|name| {
            if is_secret_shaped_key(name) {
                format!("{name} [REDACTED]")
            } else {
                name.clone()
            }
        })
        .collect()
}

/// `sh.exec` audit event. `argv` is the argv the effect will run,
/// verbatim; `env` is the resolved env-injection map whose *keys* the
/// event carries.
pub fn sh_exec(mode: super::ExecMode, kind: &str, argv: &[String], env: &BTreeMap<String, String>) {
    tracing::info!(
        mode = mode_label(mode),
        op = "sh.exec",
        kind = kind,
        argv = ?argv,
        env_keys = ?env_keys(env),
        "audit"
    );
}

/// `fs.write` audit event. `content_source` names where the content
/// came from without carrying it (spec 09 names-not-values):
/// `"string"` for a literal payload, `"secret:<name>"` for an
/// [`EnvSecret`](crate::profile_ast::ProfileNode::EnvSecret) content
/// node, `"env_ref:<name>"` for an
/// [`EnvRef`](crate::profile_ast::ProfileNode::EnvRef) pointing at a
/// `Spec.env` entry. Content bytes never enter the event.
pub fn fs_write(mode: super::ExecMode, kind: &str, path: &str, bytes: u64, content_source: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "fs.write",
        kind = kind,
        path = path,
        bytes = bytes,
        content_source = content_source,
        "audit"
    );
}

/// `net.http_get` audit event.
pub fn http_get(mode: super::ExecMode, kind: &str, url: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_get",
        kind = kind,
        url = url,
        "audit"
    );
}

/// `net.http_post` audit event.
pub fn http_post(mode: super::ExecMode, kind: &str, url: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_post",
        kind = kind,
        url = url,
        "audit"
    );
}

/// `net.transfer` audit event (direct op *and* lifecycle
/// [`super::lifecycle::Step::Transfer`]).
pub fn transfer(mode: super::ExecMode, kind: &str, src: &str, dst: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.transfer",
        kind = kind,
        src = src,
        dst = dst,
        "audit"
    );
}

/// `net.http_get` audit event carrying the poll deadline
/// (`comfyui.health` / `service.ready` — [`super::lifecycle::Step::HttpPoll`]).
pub fn http_poll(mode: super::ExecMode, kind: &str, url: &str, timeout_sec: u64) {
    tracing::info!(
        mode = mode_label(mode),
        op = "net.http_get",
        kind = kind,
        url = url,
        timeout_sec = timeout_sec,
        "audit"
    );
}

/// `mount.bind` audit event.
pub fn mount_bind(mode: super::ExecMode, kind: &str, src: &str, dst: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "mount.bind",
        kind = kind,
        src = src,
        dst = dst,
        "audit"
    );
}

/// `mount.umount` audit event.
pub fn mount_umount(mode: super::ExecMode, kind: &str, path: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "mount.umount",
        kind = kind,
        path = path,
        "audit"
    );
}

/// `note` audit event — the lifecycle no-op sub-step. Not an effect,
/// but the operator can still tell that a phase decided to do nothing
/// (and why, from `message`) rather than the phase being silently
/// absent from the transcript.
pub fn note(mode: super::ExecMode, kind: &str, message: &str) {
    tracing::info!(
        mode = mode_label(mode),
        op = "note",
        kind = kind,
        note = message,
        "audit"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_keys_leaves_a_non_sensitive_name_alone() {
        let mut env = BTreeMap::new();
        env.insert("MODE".to_string(), "fast".to_string());
        assert_eq!(env_keys(&env), vec!["MODE".to_string()]);
    }

    #[test]
    fn env_keys_appends_redacted_marker_for_a_sensitive_name() {
        let mut env = BTreeMap::new();
        env.insert("HF_TOKEN".to_string(), "should-never-appear".to_string());
        env.insert("api_key".to_string(), "also-secret".to_string());
        let out = env_keys(&env);
        // Both are marked; the sort comes from the BTreeMap.
        assert_eq!(
            out,
            vec![
                "HF_TOKEN [REDACTED]".to_string(),
                "api_key [REDACTED]".to_string(),
            ]
        );
        // Values are never in the output regardless of the name.
        for line in &out {
            assert!(!line.contains("should-never-appear"));
            assert!(!line.contains("also-secret"));
        }
    }

    #[test]
    fn env_keys_result_is_stable_across_runs() {
        // A BTreeMap already sorts by key, so re-inserting in a
        // different order must produce the same output.
        let mut a = BTreeMap::new();
        a.insert("MODE".to_string(), "fast".to_string());
        a.insert("HF_TOKEN".to_string(), "v1".to_string());
        let mut b = BTreeMap::new();
        b.insert("HF_TOKEN".to_string(), "v2".to_string());
        b.insert("MODE".to_string(), "slow".to_string());
        assert_eq!(env_keys(&a), env_keys(&b));
    }

    #[test]
    fn mode_label_is_the_expected_string() {
        assert_eq!(mode_label(super::super::ExecMode::DryRun), "dry-run");
        assert_eq!(mode_label(super::super::ExecMode::Real), "real");
    }
}
