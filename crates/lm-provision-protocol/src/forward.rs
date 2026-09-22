//! The forwards record (09-apply-report-and-ledger.md §Forwards record):
//! what `port-forward --detach` left running, one row per detached
//! `ssh`, so that a tunnel handed to the operator as a pid is not lost
//! the moment the terminal that printed it closes.
//!
//! Neutral and wire-shaped for the reason [`crate::acquisition`] is: a
//! row written by the operator CLI today is read by the endpoint
//! inventory and by the control plane later, and both sides must agree
//! on it without depending on each other.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One detached forward (09 §Forwards record): the `ssh` process that
/// carries it, and what it carries.
///
/// **The pid alone does not name the process.** Pids are reused, and a
/// row read after a reboot would point at whatever now holds the
/// number. `started_at` is the kernel's own start time for the pid, so a
/// reader can tell "this pid is our `ssh`" from "this pid is something
/// else now" — the check every pidfile convention that survives a
/// reboot makes [documented: proc_pid_stat(5), field 22; systemd's
/// `PIDFile=` and the stale-check discussions around it].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRow {
    /// The detached `ssh`'s process id, as `port-forward --detach`
    /// printed it.
    pub pid: u32,
    /// The kernel's start time for that pid, in the unit the platform
    /// reports it (clock ticks since boot on Linux, from
    /// `/proc/<pid>/stat` field 22). `None` where the writer could not
    /// read one — a reader then has only the pid, and says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// RFC 3339 UTC, driver clock — when the forward was opened.
    pub opened_at: String,
    /// The local address the listening ports are bound on.
    pub address: String,
    /// What is carried, in the order it was asked for.
    pub forwards: Vec<ForwardPair>,
    /// The machine the forward reaches, when the operator named it by
    /// platform and id — what lets an inventory tie the tunnel back to
    /// the acquisition it serves. `None` when the pod was named by
    /// address alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<ForwardPod>,
}

/// One `LOCAL:REMOTE` pair of a forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardPair {
    /// The port on the operator's host.
    pub local: u16,
    /// The port on the pod, reached from the pod's own loopback.
    pub remote: u16,
}

/// The machine a forward reaches, as the operator named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardPod {
    /// The platform, as the operator named it (`runpod`, …).
    pub provider: String,
    /// The identifier the platform lists the machine under.
    pub id: String,
}

/// What can go wrong reading or writing the record.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// The file could not be opened, read, or written.
    #[error("forwards i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A line was not a row.
    #[error("forwards row (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append one row.
///
/// One write, newline included, as [`crate::acquisition::append`]
/// does and for the same reason.
pub fn append(path: &Path, row: &ForwardRow) -> Result<(), ForwardError> {
    let mut line = serde_json::to_string(row)?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Every row, in file order. A missing file is an empty record.
pub fn list(path: &Path) -> Result<Vec<ForwardRow>, ForwardError> {
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
    Ok(rows)
}

/// Replace the record with `rows` — what a writer does after dropping
/// the rows whose process is gone, so the file does not grow with every
/// forward ever opened.
///
/// Written whole and then renamed into place, so a reader never sees a
/// half-written record.
pub fn rewrite(path: &Path, rows: &[ForwardRow]) -> Result<(), ForwardError> {
    let mut body = String::new();
    for row in rows {
        body.push_str(&serde_json::to_string(row)?);
        body.push('\n');
    }
    let staging = path.with_extension("jsonl.tmp");
    std::fs::write(&staging, body)?;
    std::fs::rename(&staging, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-protocol-forward-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn row(pid: u32) -> ForwardRow {
        ForwardRow {
            pid,
            started_at: Some(123_456),
            opened_at: "2026-09-23T00:00:00Z".to_string(),
            address: "127.0.0.1".to_string(),
            forwards: vec![ForwardPair {
                local: 18000,
                remote: 8000,
            }],
            pod: Some(ForwardPod {
                provider: "runpod".to_string(),
                id: "pod-1".to_string(),
            }),
        }
    }

    /// **A row survives the round trip, and the optional fields are
    /// absent from the wire when unset** — a row for a pod named by
    /// address carries no `pod`, and one whose start time could not be
    /// read carries no `started_at`, rather than a null a reader might
    /// take for a value.
    #[test]
    fn rows_round_trip_and_optional_fields_are_omitted_when_unset() {
        let path = tmp_path("roundtrip");
        append(&path, &row(7)).unwrap();
        let mut bare = row(8);
        bare.started_at = None;
        bare.pod = None;
        append(&path, &bare).unwrap();

        let read = list(&path).unwrap();
        assert_eq!(read, vec![row(7), bare.clone()]);

        let text = std::fs::read_to_string(&path).unwrap();
        let second = text.lines().nth(1).unwrap();
        assert!(!second.contains("started_at"), "{second}");
        assert!(!second.contains("\"pod\""), "{second}");
        std::fs::remove_file(&path).ok();
    }

    /// **A missing record is an empty one**, and a rewrite leaves only
    /// what was handed to it — the pruning a writer does after dropping
    /// dead forwards.
    #[test]
    fn a_missing_record_is_empty_and_a_rewrite_replaces_it_whole() {
        let path = tmp_path("rewrite");
        assert_eq!(list(&path).unwrap(), Vec::<ForwardRow>::new());
        append(&path, &row(1)).unwrap();
        append(&path, &row(2)).unwrap();
        rewrite(&path, &[row(2)]).unwrap();
        assert_eq!(list(&path).unwrap(), vec![row(2)]);
        assert!(!path.with_extension("jsonl.tmp").exists());
        std::fs::remove_file(&path).ok();
    }

    /// A line that is not a row is an error, never a row skipped.
    #[test]
    fn an_unreadable_line_is_an_error() {
        let path = tmp_path("unreadable");
        std::fs::write(&path, "{\"pid\": \"seven\"}\n").unwrap();
        assert!(matches!(list(&path), Err(ForwardError::Json(_))));
        std::fs::remove_file(&path).ok();
    }
}
