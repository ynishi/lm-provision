//! Structured audit tracing + redaction (09-apply-report-and-ledger.md
//! §Audit log; milestone M4-2).
//!
//! [`redact`] holds the pure, side-effect-free redaction primitives
//! (case-insensitive sensitive-key match, env-key-name rendering, the
//! general `(key, value)` redact helper, and the `[secret:NAME]` marker
//! rendering) — kept pure specifically so they are unit-testable without
//! a `tracing` subscriber capturing output. This module is the thin
//! `tracing::info!` emission layer built on top of them, called from
//! each bridge's entry function ([`crate::bridge::sh`] /
//! [`crate::bridge::fs`] / [`crate::bridge::net`] /
//! [`crate::bridge::mount`]) with whatever fields are known at the point
//! of the call — argv / path / env key names / stdin byte count are
//! known ahead of the effect itself, while HTTP status and body /
//! transfer byte counts only exist once the bridge's own effect (or its
//! `dry_run` echo) has produced a result, so those emit immediately
//! after building that result rather than strictly "before" it.
//!
//! 09 §Audit log's literal rule list covers `sh.exec`, `fs.write`, HTTP
//! (`net.http_get` / `net.http_post` / `net.transfer`), env keys, and
//! secret markers; it does not name `mount.bind` / `mount.umount`
//! specifically. This module extends the same "every bridge invocation
//! emits a line" intent (workspace/tasks/lm-provision-impl/plan.md
//! M4-2: "各 bridge invocation が effect 前に structured tracing 1 行を
//! emit") to both mount operations too — reported as an interpretive
//! extension rather than a literal 09 transcription, since neither
//! operation's fields (`src` / `dst` / `path`) are secret-shaped values
//! needing redaction in the first place.
//!
//! Every line here is emitted under the `"lm_provision::audit"` tracing
//! target, so an operator's `--log-level` / `RUST_LOG` filter
//! (07-cli.md §Global flags, e.g. `lm_provision::audit=info`) can
//! isolate the audit trail from the rest of this crate's tracing output.

pub mod redact;

use redact::redact_env_key_name;

/// The tracing target every audit line below emits under.
const AUDIT_TARGET: &str = "lm_provision::audit";

/// `sh.exec` audit line (09 §Audit log "sh.exec"): `argv` is logged
/// verbatim (validate's shell-safety and the env-injection design keep
/// secrets out of argv); `stdin` is logged as a byte count only; `env`
/// key NAMES only are logged — never values, sensitive or not (09
/// §Audit log "Env keys") — with a sensitive-shaped name rendered as
/// `<KEY> [REDACTED]` via [`redact_env_key_name`].
pub fn sh_exec(
    argv: &[String],
    env: &[(String, String)],
    stdin_bytes: usize,
    sensitive_keys: &[String],
) {
    let env_keys: Vec<String> = env
        .iter()
        .map(|(key, _)| redact_env_key_name(key, sensitive_keys))
        .collect();
    tracing::info!(
        target: AUDIT_TARGET,
        op = "sh.exec",
        argv = ?argv,
        env_keys = ?env_keys,
        stdin_bytes,
    );
}

/// `fs.write` audit line (09 §Audit log "fs.write": "logs path + byte
/// count + `content_source` — the string `\"string\"` for literal
/// content or `\"secret:<name>\"` when a SecretRef wrote the file.
/// Content bytes are never logged.").
pub fn fs_write(path: &str, bytes: usize, content_source: &str) {
    tracing::info!(
        target: AUDIT_TARGET,
        op = "fs.write",
        path,
        bytes,
        content_source,
    );
}

/// HTTP audit line, shared by `net.http_get` / `net.http_post` (09
/// §Audit log "HTTP": "URL, status, and body byte counts are logged;
/// header names are logged, header values never (headers may carry
/// tokens); bodies never.").
pub fn http(op: &str, url: &str, status: i64, body_bytes: usize, headers: &[(String, String)]) {
    let header_names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    tracing::info!(
        target: AUDIT_TARGET,
        op,
        url,
        status,
        body_bytes,
        headers = ?header_names,
    );
}

/// `net.transfer` audit line (09 §Audit log "HTTP" applies to
/// `net.transfer` too — it is HTTP-shaped under the hood — kept as its
/// own function because a transfer's identity is `(direction, src,
/// dst)` rather than a single URL): the transfer direction
/// (`"download"` / `"upload"`), `src`, `dst`, and the transferred byte
/// count. Bodies are never logged, matching the HTTP rule.
pub fn net_transfer(direction: &str, src: &str, dst: &str, bytes: u64) {
    tracing::info!(
        target: AUDIT_TARGET,
        op = "net.transfer",
        direction,
        src,
        dst,
        bytes,
    );
}

/// `mount.bind` audit line (interpretive extension, see the module doc
/// comment): `src` + `dst`, neither of which is a secret-shaped value.
pub fn mount_bind(src: &str, dst: &str) {
    tracing::info!(target: AUDIT_TARGET, op = "mount.bind", src, dst);
}

/// `mount.umount` audit line (interpretive extension, see the module
/// doc comment): the umount target `path`.
pub fn mount_umount(path: &str) {
    tracing::info!(target: AUDIT_TARGET, op = "mount.umount", path);
}
