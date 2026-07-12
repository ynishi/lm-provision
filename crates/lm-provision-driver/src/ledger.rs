//! Append-only apply ledger (09-apply-report-and-ledger.md §Ledger):
//! one row per driver-collected apply invocation, physically encoded as
//! newline-delimited JSON (JSON Lines) — the ledger owner's internal
//! choice (09 §Stability: "Ledger physical encoding: internal";
//! plan.md §未確定事項 #3). A dependency-free flat file was chosen over
//! an embedded SQLite table for this milestone: the row shape is fixed
//! and tiny (four fields, one verbatim JSON blob), the only access
//! patterns this milestone needs are "append one row" and "read every
//! row back", and a SQL engine buys nothing over that for either.
//!
//! ## Design
//!
//! - **Append-only**: [`append`] is the only write operation this
//!   module exposes — there is no `update` / `delete`, matching 09
//!   §Ledger: "rows are never mutated or deleted; corrections are new
//!   rows."
//! - **`(pod_id, profile_hash)` non-unique**: [`append`] never checks
//!   for an existing row with the same pair before writing (09 §Ledger:
//!   "deliberately not unique ... the full history is the value").
//! - **JSON Lines**: one [`LedgerRow`] per line; [`list`] parses every
//!   line back in file order and reverses it to the newest-first shape
//!   downstream readers (chapter 10's `lm_ledger_list` / `lm_ledger_get`,
//!   milestone M6) will want.
//! - **No file locking**: concurrent writers each issue one `O_APPEND`
//!   write per row, which is atomic on POSIX for writes at or under
//!   `PIPE_BUF` — adequate for this milestone's single-process driver
//!   usage; multi-process concurrent-writer safety beyond that is an
//!   open item for whoever owns the ledger file path in a given
//!   deployment (see plan.md §未確定事項).

use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One ledger row (09-apply-report-and-ledger.md §Ledger).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerRow {
    /// Driver-provided provisioning context (09 §Ledger).
    pub pod_id: String,
    /// 64-hex sha256 digest of the applied profile (03 §hash; 09
    /// §Ledger).
    pub profile_hash: String,
    /// The apply report, verbatim as collected (09 §Outputs "Apply
    /// report"; 08 §Outputs).
    pub report: serde_json::Value,
    /// RFC 3339 UTC, driver clock (09 §Ledger).
    pub collected_at: String,
}

/// Errors raised while appending to or reading a ledger file.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// Opening, writing, or reading the ledger file failed (09 §Error
    /// surface: "Ledger append failures (disk / transport): driver-side,
    /// retryable ... an apply is not 'unrecorded-successful' — drivers
    /// must treat append failure as an operational error to retry, not
    /// swallow"). This is that error; callers are expected to retry
    /// [`append`] rather than discard it.
    #[error("ledger i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A row failed to encode, or an existing line failed to decode
    /// back into [`LedgerRow`].
    #[error("ledger row (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append one row to `ledger_path` (creating the file if it does not
/// exist). Never mutates or removes any existing line (09 §Ledger
/// "append-only"); a duplicate `(pod_id, profile_hash)` pair is
/// accepted without complaint (09 §Ledger: "deliberately not unique").
pub fn append(ledger_path: &Path, row: &LedgerRow) -> Result<(), LedgerError> {
    let line = serde_json::to_string(row)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Read every row in `ledger_path`, newest first — the shape milestone
/// M6's `lm_ledger_list` will build its response around (09 §Ledger). A
/// missing file is an empty ledger, not an error: a ledger with zero
/// applies recorded yet is a valid, if uninteresting, state.
pub fn list(ledger_path: &Path) -> Result<Vec<LedgerRow>, LedgerError> {
    if !ledger_path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(ledger_path)?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(&line)?);
    }
    rows.reverse();
    Ok(rows)
}

/// Fetch the row at `index` in the newest-first ordering [`list`]
/// returns (`index = 0` is the most recently appended row). `Ok(None)`
/// for an out-of-range index or a missing/empty ledger.
pub fn get(ledger_path: &Path, index: usize) -> Result<Option<LedgerRow>, LedgerError> {
    Ok(list(ledger_path)?.into_iter().nth(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_ledger_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-driver-ledger-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn sample_row(pod_id: &str, hash: &str) -> LedgerRow {
        LedgerRow {
            pod_id: pod_id.to_string(),
            profile_hash: hash.to_string(),
            report: serde_json::json!({
                "ok": true,
                "dry_run": true,
                "profile_name": "demo",
                "steps": []
            }),
            collected_at: "2026-07-12T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn append_then_list_round_trips_a_single_row() {
        let path = tmp_ledger_path("single");
        let row = sample_row("pod-1", &"a".repeat(64));
        append(&path, &row).expect("append should succeed");

        let rows = list(&path).expect("list should succeed");
        assert_eq!(rows, vec![row]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_returns_newest_first() {
        let path = tmp_ledger_path("ordering");
        let first = sample_row("pod-1", &"a".repeat(64));
        let second = sample_row("pod-1", &"b".repeat(64));
        append(&path, &first).expect("append first");
        append(&path, &second).expect("append second");

        let rows = list(&path).expect("list should succeed");
        assert_eq!(rows, vec![second, first], "09 §Ledger: newest first");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn same_pod_id_and_hash_may_be_appended_more_than_once() {
        let path = tmp_ledger_path("non-unique");
        let row = sample_row("pod-1", &"a".repeat(64));
        append(&path, &row).expect("append 1");
        append(&path, &row).expect("append 2");

        let rows = list(&path).expect("list should succeed");
        assert_eq!(
            rows.len(),
            2,
            "09 §Ledger: (pod_id, profile_hash) is deliberately not unique"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn get_returns_the_row_at_the_newest_first_index() {
        let path = tmp_ledger_path("get");
        let first = sample_row("pod-1", &"a".repeat(64));
        let second = sample_row("pod-1", &"b".repeat(64));
        append(&path, &first).expect("append first");
        append(&path, &second).expect("append second");

        assert_eq!(get(&path, 0).expect("get 0"), Some(second));
        assert_eq!(get(&path, 1).expect("get 1"), Some(first));
        assert_eq!(get(&path, 2).expect("get 2"), None);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_on_a_missing_file_is_an_empty_ledger_not_an_error() {
        let path = tmp_ledger_path("missing");
        assert!(!path.exists());
        assert_eq!(list(&path).expect("missing ledger is empty"), Vec::new());
    }

    #[test]
    fn get_on_a_missing_file_is_none_not_an_error() {
        let path = tmp_ledger_path("missing-get");
        assert!(!path.exists());
        assert_eq!(get(&path, 0).expect("missing ledger get is None"), None);
    }
}
