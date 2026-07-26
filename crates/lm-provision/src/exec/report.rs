//! Structured per-step apply-report entries for the AST exec path.
//!
//! The mlua apply pipeline builds its report in Lua (`lm.apply` /
//! `lm.report`, `lua/lm/apply.lua` + `lua/lm/report.lua`); the AST exec
//! path has no Lua layer, so this module is the Rust equivalent:
//! [`StepReport`] mirrors `lm.apply`'s per-step entry table
//! (`build_step_entry`) and [`build_envelope`] mirrors `lm.report`'s
//! top-level envelope (`{ ok, dry_run, profile_name, steps, error? }`).
//!
//! ## Deliberate divergence from the legacy report (semantics-honest)
//!
//! The envelope is field-name compatible with the legacy report, but the
//! `steps` array is the AST exec layer's own step structure, **not** the
//! legacy `lm.dispatch` op-step stream. Three differences are intentional
//! (see the AST apply entry point [`crate::apply::run_apply_ast`]):
//!
//! - **No dispatch fan-out ids.** The legacy report ids come from
//!   `lm.dispatch` (`5_sync_routes/pull_1`, `4_custom_nodes/1_clone`, …).
//!   The AST path reports the exec layer's own step structure: one entry
//!   per direct-op phase, and one entry per lifecycle sub-step. Ids are
//!   `<phase_index>_<kind>` for a direct op and
//!   `<phase_index>_<kind>_<n>` for the `n`-th lifecycle sub-step —
//!   unique within a report, but not the legacy id scheme.
//! - **No `dispatch_pending` skips.** The legacy report degrades
//!   `comfyui.restart` / `service.start` / … to a `dispatch_pending`
//!   visible skip. The AST exec layer executes lifecycle ops for real;
//!   a sub-step that has no concrete effect surfaces honestly as an
//!   `op = "note"` step (`ok = true`), never a "pending" pretence.
//! - **Per-step fields.** Fields whose meaning matches the legacy entry
//!   (`id` / `kind` / `op` / `ok` / `status` / `argv` / `stdout` /
//!   `stderr` / `path` / `bytes` / `url` / `src` / `dst`) keep the same
//!   name. Legacy-only fields born of dispatch fan-out are not emitted;
//!   the exec-only `note` field is added.

use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};

/// Shared, mutable handle to the per-step report entries an exec run
/// accumulates ([`crate::exec::ExecContext::reports`]). A named alias so
/// the collecting-engine constructor and the context accessor keep a
/// simple signature.
pub type SharedReports = Arc<Mutex<Vec<StepReport>>>;

/// One executed (or dry-run-traced) step's report entry.
///
/// Optional fields are emitted only when set (see [`StepReport::to_json`]),
/// matching the legacy per-op field table's "only the fields this op
/// carries" shape.
#[derive(Debug, Clone)]
pub struct StepReport {
    /// Report-unique step id (see the module doc's id scheme).
    pub id: String,
    /// Phase kind (`sh.exec`, `system.apt`, `custom_nodes`, …).
    pub kind: String,
    /// Effect op name (`sh.exec` / `fs.write` / `net.transfer` /
    /// `net.http_get` / `net.http_post` / `mount.bind` / `mount.umount` /
    /// `note`).
    pub op: String,
    /// True iff the step succeeded (or is an inert `note` / dry-run).
    pub ok: bool,
    /// Process exit code / HTTP status / `0` for a successful effectless
    /// step / `-1` for a pre-effect failure.
    pub status: i64,
    /// Present (and `true`) for effect-bearing steps under dry-run.
    pub dry_run: Option<bool>,
    /// `sh.exec` argv (direct op or lifecycle `Sh` sub-step).
    pub argv: Option<Vec<String>>,
    /// Captured stdout tail (real-mode `sh.exec`).
    pub stdout: Option<String>,
    /// Captured stderr tail (real-mode `sh.exec`).
    pub stderr: Option<String>,
    /// `fs.write` target path.
    pub path: Option<String>,
    /// Bytes written / transferred.
    pub bytes: Option<u64>,
    /// `net.http_*` / `http_poll` URL.
    pub url: Option<String>,
    /// `net.transfer` / `mount.bind` source.
    pub src: Option<String>,
    /// `net.transfer` / `mount.bind` destination.
    pub dst: Option<String>,
    /// Human-readable note (an effectless lifecycle `note` sub-step).
    pub note: Option<String>,
    /// Failure reason for the envelope's `error` line. Never serialized
    /// into the step entry (the step's `ok = false` + `stderr` already
    /// carry the machine-readable signal); [`StepReport::failure_reason`]
    /// reads it.
    pub reason: Option<String>,
}

impl StepReport {
    /// A successful base entry (`ok = true`, `status = 0`, no optional
    /// fields). Callers set the op-specific fields and, on failure, flip
    /// `ok` / `status` / `reason`.
    pub fn new(id: String, kind: String, op: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            op: op.into(),
            ok: true,
            status: 0,
            dry_run: None,
            argv: None,
            stdout: None,
            stderr: None,
            path: None,
            bytes: None,
            url: None,
            src: None,
            dst: None,
            note: None,
            reason: None,
        }
    }

    /// The reason string the envelope's `error` line reports for a failing
    /// step (`step <id> (<kind>) failed: <reason>`). Prefers the captured
    /// [`reason`](Self::reason), falls back to a non-empty `stderr`, then
    /// to `"unknown error"`.
    pub fn failure_reason(&self) -> String {
        self.reason
            .clone()
            .or_else(|| self.stderr.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown error".to_string())
    }

    /// Serialize to the legacy per-step entry JSON shape (only the set
    /// fields, `reason` excluded).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(self.id.clone()));
        m.insert("kind".into(), Value::String(self.kind.clone()));
        m.insert("op".into(), Value::String(self.op.clone()));
        m.insert("ok".into(), Value::Bool(self.ok));
        m.insert("status".into(), Value::Number(self.status.into()));
        if let Some(dry_run) = self.dry_run {
            m.insert("dry_run".into(), Value::Bool(dry_run));
        }
        if let Some(argv) = &self.argv {
            m.insert(
                "argv".into(),
                Value::Array(argv.iter().cloned().map(Value::String).collect()),
            );
        }
        if let Some(stdout) = &self.stdout {
            m.insert("stdout".into(), Value::String(stdout.clone()));
        }
        if let Some(stderr) = &self.stderr {
            m.insert("stderr".into(), Value::String(stderr.clone()));
        }
        if let Some(path) = &self.path {
            m.insert("path".into(), Value::String(path.clone()));
        }
        if let Some(bytes) = self.bytes {
            m.insert("bytes".into(), Value::Number(bytes.into()));
        }
        if let Some(url) = &self.url {
            m.insert("url".into(), Value::String(url.clone()));
        }
        if let Some(src) = &self.src {
            m.insert("src".into(), Value::String(src.clone()));
        }
        if let Some(dst) = &self.dst {
            m.insert("dst".into(), Value::String(dst.clone()));
        }
        if let Some(note) = &self.note {
            m.insert("note".into(), Value::String(note.clone()));
        }
        Value::Object(m)
    }
}

/// Build the top-level apply report envelope
/// (`{ ok, dry_run, profile_name, steps, error? }`, mirroring
/// `lua/lm/report.lua` `M.build`). `ok` is `true` iff `error` is absent.
pub fn build_envelope(
    profile_name: &str,
    dry_run: bool,
    steps: &[StepReport],
    error: Option<&str>,
) -> Value {
    let mut m = Map::new();
    m.insert("ok".into(), Value::Bool(error.is_none()));
    m.insert("dry_run".into(), Value::Bool(dry_run));
    m.insert(
        "profile_name".into(),
        Value::String(profile_name.to_string()),
    );
    m.insert(
        "steps".into(),
        Value::Array(steps.iter().map(StepReport::to_json).collect()),
    );
    if let Some(error) = error {
        m.insert("error".into(), Value::String(error.to_string()));
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_emits_only_the_set_fields_and_never_reason() {
        let mut r = StepReport::new("2_sh.exec".to_string(), "sh.exec".to_string(), "sh.exec");
        r.argv = Some(vec!["echo".to_string(), "hi".to_string()]);
        r.dry_run = Some(true);
        r.reason = Some("should not leak".to_string());
        let json = r.to_json();

        assert_eq!(json["id"], serde_json::json!("2_sh.exec"));
        assert_eq!(json["kind"], serde_json::json!("sh.exec"));
        assert_eq!(json["op"], serde_json::json!("sh.exec"));
        assert_eq!(json["ok"], serde_json::json!(true));
        assert_eq!(json["status"], serde_json::json!(0));
        assert_eq!(json["dry_run"], serde_json::json!(true));
        assert_eq!(json["argv"], serde_json::json!(["echo", "hi"]));
        assert!(json.get("reason").is_none(), "reason must not serialize");
        assert!(json.get("stdout").is_none(), "unset fields are omitted");
    }

    #[test]
    fn failure_reason_prefers_reason_then_stderr_then_default() {
        let mut r = StepReport::new("1_sh.exec".to_string(), "sh.exec".to_string(), "sh.exec");
        assert_eq!(r.failure_reason(), "unknown error");
        r.stderr = Some("boom".to_string());
        assert_eq!(r.failure_reason(), "boom");
        r.reason = Some("exit 3".to_string());
        assert_eq!(r.failure_reason(), "exit 3");
    }

    #[test]
    fn build_envelope_sets_ok_from_error_presence() {
        let ok = build_envelope("demo", true, &[], None);
        assert_eq!(ok["ok"], serde_json::json!(true));
        assert_eq!(ok["dry_run"], serde_json::json!(true));
        assert_eq!(ok["profile_name"], serde_json::json!("demo"));
        assert_eq!(ok["steps"], serde_json::json!([]));
        assert!(ok.get("error").is_none());

        let failed = build_envelope("demo", false, &[], Some("step 1 (sh.exec) failed: boom"));
        assert_eq!(failed["ok"], serde_json::json!(false));
        assert_eq!(
            failed["error"],
            serde_json::json!("step 1 (sh.exec) failed: boom")
        );
    }
}
