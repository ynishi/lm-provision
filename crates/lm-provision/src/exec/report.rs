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

/// The position an entry was **declared** at: the phase's 1-based
/// declaration index paired with the step's 1-based position inside it.
///
/// Only entries whose push order stopped carrying their declaration order
/// need one — see [`StepReport::declared_at`].
pub type DeclaredAt = (usize, usize);

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
    /// Where the entry sits in **declaration** order, for entries the
    /// push order no longer places correctly. Never serialized.
    ///
    /// A phase whose steps run at the same time appends its entries as
    /// they *finish*, so the array order it produces is completion order.
    /// A lifecycle sub-step therefore carries the position it was
    /// declared at and [`in_declaration_order`] puts the array back.
    /// `None` for every entry a single-threaded push already placed —
    /// a direct op's phase entry, a phase-level failure — and those are
    /// left exactly where they were pushed.
    pub declared_at: Option<DeclaredAt>,
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
            declared_at: None,
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

/// Put the entries a parallel phase pushed out of order back into
/// declaration order, in place.
///
/// **Why the array order is worth restoring at all.** A partial apply is
/// readable because the report reads like the profile: the first entry is
/// the first thing the profile asked for. Once a phase's steps run at the
/// same time the array order becomes "whichever finished first", which is
/// a fact about the network rather than about the profile — and the one
/// thing a reader wants from a `models` phase of twenty weights is to
/// find the third one third.
///
/// **Why a sort and not a reserved slot.** The ids already carry the
/// order (`<phase_index>_<kind>_<n>`), so the key exists; reserving the
/// row instead would mean the array had to hold rows for steps that have
/// not answered yet, and a run that stops early would have to know which
/// of those to drop.
///
/// The sort is confined to maximal runs of entries that carry a
/// [`StepReport::declared_at`]: everything else keeps the position it was
/// pushed at, so an entry with no declared position can neither move nor
/// be moved past. [`slice::sort_by_key`] is stable, so entries sharing a
/// position (none do today — the ids are unique) keep their push order.
pub fn in_declaration_order(steps: &mut [StepReport]) {
    let mut start = 0;
    while start < steps.len() {
        if steps[start].declared_at.is_none() {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < steps.len() && steps[end].declared_at.is_some() {
            end += 1;
        }
        steps[start..end].sort_by_key(|entry| entry.declared_at);
        start = end;
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

    /// A declared position never serializes: it is how the array is
    /// ordered, not something the report says.
    #[test]
    fn to_json_never_emits_the_declared_position() {
        let mut r = StepReport::new(
            "1_models_1".to_string(),
            "models".to_string(),
            "net.transfer",
        );
        r.declared_at = Some((1, 1));
        let json = r.to_json();
        assert!(json.get("declared_at").is_none());
        assert_eq!(json.as_object().expect("object").len(), 5);
    }

    fn placed(id: &str, at: Option<DeclaredAt>) -> StepReport {
        let mut entry = StepReport::new(id.to_string(), "models".to_string(), "net.transfer");
        entry.declared_at = at;
        entry
    }

    fn ids(steps: &[StepReport]) -> Vec<&str> {
        steps.iter().map(|s| s.id.as_str()).collect()
    }

    /// The case the parallel phase produces: entries pushed as they
    /// finished, read back in the order the profile declared them.
    #[test]
    fn in_declaration_order_sorts_a_run_of_placed_entries() {
        let mut steps = vec![
            placed("1_models_3", Some((1, 3))),
            placed("1_models_1", Some((1, 1))),
            placed("1_models_2", Some((1, 2))),
        ];
        in_declaration_order(&mut steps);
        assert_eq!(ids(&steps), vec!["1_models_1", "1_models_2", "1_models_3"]);
    }

    /// Two parallel phases in a row form one run, and sorting it does not
    /// interleave them: the phase index is the first half of the key.
    #[test]
    fn in_declaration_order_keeps_two_adjacent_phases_apart() {
        let mut steps = vec![
            placed("2_models_2", Some((2, 2))),
            placed("1_models_2", Some((1, 2))),
            placed("2_models_1", Some((2, 1))),
            placed("1_models_1", Some((1, 1))),
        ];
        in_declaration_order(&mut steps);
        assert_eq!(
            ids(&steps),
            vec!["1_models_1", "1_models_2", "2_models_1", "2_models_2"]
        );
    }

    /// An entry with no declared position is a fence: it neither moves
    /// nor lets a placed entry cross it.
    #[test]
    fn in_declaration_order_leaves_unplaced_entries_where_they_were() {
        let mut steps = vec![
            placed("1_models_2", Some((1, 2))),
            placed("1_models_1", Some((1, 1))),
            placed("2_sh.exec", None),
            placed("3_models_2", Some((3, 2))),
            placed("3_models_1", Some((3, 1))),
        ];
        in_declaration_order(&mut steps);
        assert_eq!(
            ids(&steps),
            vec![
                "1_models_1",
                "1_models_2",
                "2_sh.exec",
                "3_models_1",
                "3_models_2"
            ]
        );
    }

    /// A wholly sequential report is untouched — the property that keeps
    /// every pre-existing `step_ids` assertion true without amendment.
    #[test]
    fn in_declaration_order_is_the_identity_on_a_sequential_report() {
        let before = vec![
            placed("1_system.apt_1", Some((1, 1))),
            placed("2_sh.exec", None),
            placed("3_models_1", Some((3, 1))),
            placed("3_models_2", Some((3, 2))),
        ];
        let mut after = before.clone();
        in_declaration_order(&mut after);
        assert_eq!(ids(&after), ids(&before));
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
