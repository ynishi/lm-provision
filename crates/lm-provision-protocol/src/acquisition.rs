//! Append-only acquisitions record (09-apply-report-and-ledger.md
//! §Acquisitions record): one row per machine the driver created, in
//! the same JSON Lines shape and with the same discipline as
//! [`crate::ledger`].
//!
//! The accident this exists to remove: `acquire` creates a billable
//! machine and the only place its identifier lands is the run's stdout.
//! Close the terminal and the machine keeps running with nothing on the
//! host that knows it is there. A row per acquisition makes the fleet
//! something the host can read back — and gives the expiry sweep
//! (08 §Acquisitions and sweep) a list to work from.
//!
//! ## Design
//!
//! - **Append-only**: [`append`] is the only write this module exposes.
//!   A release is not an edit to the row that recorded the acquisition;
//!   it is a **new row** naming the same `id` with
//!   [`AcquisitionRow::released_at`] set. Same rule as 09 §Ledger
//!   ("rows are never mutated or deleted; corrections are new rows"),
//!   and the same reason: a file only ever appended to cannot lose an
//!   earlier statement to a half-finished rewrite, which matters most
//!   for exactly the record whose job is to survive the process that
//!   wrote it.
//! - **[`outstanding`] is an id-join over the whole file**, not a
//!   property of any single row. Nothing marks a row as retired,
//!   because marking would mean going back and mutating it; what
//!   retires an `id` is the existence of *some* row for it carrying a
//!   `released_at`. Reading the whole file to answer is the cost of
//!   never rewriting one, and the file holds one row per machine
//!   created and one per machine released — a fleet's worth, not a log
//!   line's worth.
//! - **JSON Lines / no file locking**: as [`crate::ledger`], one
//!   `O_APPEND` write per row.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One acquisitions row (09-apply-report-and-ledger.md §Acquisitions
/// record) — either a machine this host created, or the correction
/// that retires one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionRow {
    /// The identifier the service gave the machine — the join key for
    /// [`outstanding`], and the same id the ledger's `pod_id` carries
    /// for a session driven against it.
    pub id: String,
    /// Which platform it was bought from (`runpod`, `vast`,
    /// `deepinfra`, `deepinfra-deploy`), as the operator named it. What
    /// a sweep looks the adapter up by, since the credential to release
    /// it is the platform's.
    pub provider: String,
    /// RFC 3339 UTC, driver clock — same convention as the ledger's
    /// `collected_at`.
    pub acquired_at: String,
    /// RFC 3339 UTC: when the lease this machine was acquired under
    /// runs out (`acquired_at` + the acquire's `--ttl-hours`).
    ///
    /// **Recorded, not enforced by whoever wrote it.** The acquire that
    /// stamped this has exited long before the moment passes; what acts
    /// on it is a later sweep.
    pub expires_at: String,
    /// 64-hex sha256 digest of the profile the machine was acquired
    /// for (03 §hash) — the same digest the ledger stamps on applies,
    /// so a machine can be tied to what it was bought to run.
    pub profile_hash: String,
    /// The argv that destroys the machine, with `{id}` still in place —
    /// the template the acquiring adapter rendered, kept verbatim so a
    /// sweep can release a machine without re-deriving it from a
    /// profile that may have changed or moved since.
    ///
    /// **Credential-free by construction.** Every target this repo
    /// drives takes its key from the environment or from its own CLI's
    /// key file, never from the command line, so nothing secret can
    /// reach this field — it holds a program name and its arguments.
    pub release: Vec<String>,
    /// RFC 3339 UTC, present on a **correction row**: this row says the
    /// machine named by `id` was given back at that moment.
    ///
    /// Absent on an acquisition row, and omitted from the encoded row
    /// then, so an acquisition and a correction are told apart by the
    /// key's presence rather than by a sentinel value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
}

/// Errors raised while appending to or reading an acquisitions file.
#[derive(Debug, thiserror::Error)]
pub enum AcquisitionError {
    /// Opening, writing, or reading the file failed.
    ///
    /// **Never swallowable**, and for a sharper reason than the
    /// ledger's: an append that fails after the machine exists is the
    /// original accident happening again — a running, billing machine
    /// with no record of it on the host. The caller's duty is to put
    /// the machine's id and this error where the operator will see
    /// them.
    #[error("acquisitions i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A row failed to encode, or an existing line failed to decode
    /// back into [`AcquisitionRow`].
    #[error("acquisitions row (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append one row to `path` (creating the file if it does not exist).
/// Never mutates or removes an existing line: a release is appended as
/// a correction row, not written over the acquisition it retires.
pub fn append(path: &Path, row: &AcquisitionRow) -> Result<(), AcquisitionError> {
    // One write, newline included — see [`crate::ledger::append`] for
    // why `writeln!` is not used.
    let mut line = serde_json::to_string(row)?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Read every row in `path`, newest first — the same ordering
/// [`crate::ledger::list`] returns, and for the same reason: the row a
/// reader wants about a machine is almost always the last thing said
/// about it. A missing file is an empty record, not an error: a host
/// that has acquired nothing yet is a valid state.
pub fn list(path: &Path) -> Result<Vec<AcquisitionRow>, AcquisitionError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
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

/// The machines this record still believes are running: the newest row
/// for each `id` that no row — acquisition or correction — has given a
/// `released_at`.
///
/// **One row per machine**, however many rows name it. A record that
/// somehow holds two acquisitions for one id is describing one machine,
/// and handing a sweep the same machine twice would have it try to
/// release something already gone.
///
/// A correction for an id the file never acquired retires nothing,
/// because there was nothing outstanding to retire — it is simply not
/// in the answer, exactly as it would not be if the acquisition had
/// been recorded and released in order. That is the shape a driver run
/// against a machine acquired elsewhere leaves behind, and it is not an
/// error to report.
pub fn outstanding(path: &Path) -> Result<Vec<AcquisitionRow>, AcquisitionError> {
    let rows = list(path)?;
    let retired: BTreeSet<&str> = rows
        .iter()
        .filter(|row| row.released_at.is_some())
        .map(|row| row.id.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    let still_running: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| !retired.contains(row.id.as_str()) && seen.insert(row.id.clone()))
        .map(|(index, _)| index)
        .collect();
    Ok(still_running
        .into_iter()
        .map(|index| rows[index].clone())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-protocol-acquisition-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn acquired(id: &str) -> AcquisitionRow {
        AcquisitionRow {
            id: id.to_string(),
            provider: "runpod".to_string(),
            acquired_at: "2026-09-01T00:00:00Z".to_string(),
            expires_at: "2026-09-02T00:00:00Z".to_string(),
            profile_hash: "a".repeat(64),
            release: vec![
                "runpod-cli".to_string(),
                "pods".to_string(),
                "delete-pod".to_string(),
                "{id}".to_string(),
            ],
            released_at: None,
        }
    }

    fn released(id: &str) -> AcquisitionRow {
        AcquisitionRow {
            released_at: Some("2026-09-01T06:00:00Z".to_string()),
            ..acquired(id)
        }
    }

    #[test]
    fn append_then_list_round_trips_a_single_row() {
        let path = tmp_path("single");
        let row = acquired("pod-1");
        append(&path, &row).expect("append should succeed");

        assert_eq!(list(&path).expect("list should succeed"), vec![row]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_returns_newest_first() {
        let path = tmp_path("ordering");
        append(&path, &acquired("pod-1")).expect("append first");
        append(&path, &acquired("pod-2")).expect("append second");

        let rows = list(&path).expect("list should succeed");
        assert_eq!(
            rows.iter().map(|it| it.id.as_str()).collect::<Vec<_>>(),
            vec!["pod-2", "pod-1"],
            "newest first, as the ledger reads"
        );

        std::fs::remove_file(&path).ok();
    }

    /// **An acquisition row is outstanding until some row retires it,
    /// and the row that retires it is a new one.** The acquisition
    /// itself is still in the file afterwards, unchanged — which is
    /// what makes "what did this host run last week" answerable at all.
    #[test]
    fn a_correction_row_retires_its_id_and_leaves_the_acquisition_intact() {
        let path = tmp_path("correction");
        append(&path, &acquired("pod-1")).expect("append acquisition");
        append(&path, &acquired("pod-2")).expect("append acquisition");
        assert_eq!(
            outstanding(&path)
                .expect("outstanding should succeed")
                .iter()
                .map(|it| it.id.as_str())
                .collect::<Vec<_>>(),
            vec!["pod-2", "pod-1"]
        );

        append(&path, &released("pod-1")).expect("append correction");
        assert_eq!(
            outstanding(&path)
                .expect("outstanding should succeed")
                .iter()
                .map(|it| it.id.as_str())
                .collect::<Vec<_>>(),
            vec!["pod-2"],
            "the released machine is no longer believed to be running"
        );
        assert_eq!(
            list(&path).expect("list should succeed").len(),
            3,
            "nothing was rewritten: the acquisition row is still there"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A release recorded for a machine this file never acquired — a
    /// driver run against something acquired elsewhere — retires
    /// nothing it did not know about and is not itself outstanding.
    #[test]
    fn a_correction_without_an_acquisition_retires_nothing_and_is_not_outstanding() {
        let path = tmp_path("orphan-correction");
        append(&path, &acquired("pod-1")).expect("append acquisition");
        append(&path, &released("pod-elsewhere")).expect("append orphan correction");

        assert_eq!(
            outstanding(&path)
                .expect("outstanding should succeed")
                .iter()
                .map(|it| it.id.as_str())
                .collect::<Vec<_>>(),
            vec!["pod-1"],
            "the orphan retires only itself, and pod-1 is untouched"
        );

        std::fs::remove_file(&path).ok();
    }

    /// **One machine, one entry.** Two acquisition rows for the same id
    /// describe one machine; a sweep handed it twice would try to
    /// release something already gone.
    #[test]
    fn outstanding_reports_a_machine_once_however_many_rows_name_it() {
        let path = tmp_path("duplicate");
        append(&path, &acquired("pod-1")).expect("append 1");
        append(
            &path,
            &AcquisitionRow {
                expires_at: "2026-09-03T00:00:00Z".to_string(),
                ..acquired("pod-1")
            },
        )
        .expect("append 2");

        let outstanding = outstanding(&path).expect("outstanding should succeed");
        assert_eq!(outstanding.len(), 1);
        assert_eq!(
            outstanding[0].expires_at, "2026-09-03T00:00:00Z",
            "the newest statement about the machine is the one that counts"
        );

        std::fs::remove_file(&path).ok();
    }

    /// An acquisition row writes no `released_at` key at all, so what
    /// distinguishes it from a correction is the key's presence rather
    /// than a value that has to be interpreted.
    #[test]
    fn an_acquisition_row_writes_no_released_at_key() {
        let path = tmp_path("no-key");
        append(&path, &acquired("pod-1")).expect("append");
        let bytes = std::fs::read_to_string(&path).expect("file readable");
        assert!(!bytes.contains("released_at"), "{bytes}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_file_is_an_empty_record_not_an_error() {
        let path = tmp_path("missing");
        assert!(!path.exists());
        assert_eq!(list(&path).expect("missing list"), Vec::new());
        assert_eq!(outstanding(&path).expect("missing outstanding"), Vec::new());
    }
}
