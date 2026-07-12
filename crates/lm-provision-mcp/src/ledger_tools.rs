//! `lm_ledger_list` / `lm_ledger_get` (10-mcp.md §Tool set): read-only
//! wrappers over [`lm_provision_driver::ledger`]
//! (09-apply-report-and-ledger.md §Ledger). The row locator format is
//! provisional (10 §Stability: "until the ledger storage owner fixes
//! it") — this MVP reuses the same newest-first integer index
//! [`ledger::get`] already defines rather than inventing a second one.

use std::path::Path;

use lm_provision_driver::ledger::{self, LedgerError, LedgerRow};

/// `lm_ledger_list(pod_id?, profile_hash?, limit?)` (10 §Tool set):
/// newest-first rows (09 §Ledger), optionally filtered by `pod_id` /
/// `profile_hash` and capped at `limit`. `limit` truncates *after*
/// filtering — "the newest `limit` rows that match", not "the first
/// `limit` rows of the unfiltered ledger, then filtered down".
pub fn lm_ledger_list(
    ledger_path: &Path,
    pod_id: Option<&str>,
    profile_hash: Option<&str>,
    limit: Option<usize>,
) -> Result<Vec<LedgerRow>, LedgerError> {
    let mut rows = ledger::list(ledger_path)?;
    if let Some(pod_id) = pod_id {
        rows.retain(|row| row.pod_id == pod_id);
    }
    if let Some(profile_hash) = profile_hash {
        rows.retain(|row| row.profile_hash == profile_hash);
    }
    if let Some(limit) = limit {
        rows.truncate(limit);
    }
    Ok(rows)
}

/// `lm_ledger_get(row_id)` (10 §Tool set): the row at newest-first
/// index `row_id` in the *unfiltered* ledger (09 §Ledger).
pub fn lm_ledger_get(ledger_path: &Path, row_id: usize) -> Result<Option<LedgerRow>, LedgerError> {
    ledger::get(ledger_path, row_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_ledger_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-mcp-ledger-tools-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn row(pod_id: &str, hash: &str) -> LedgerRow {
        LedgerRow {
            pod_id: pod_id.to_string(),
            profile_hash: hash.to_string(),
            report: serde_json::json!({ "ok": true, "dry_run": true, "profile_name": "demo", "steps": [] }),
            collected_at: "2026-07-12T00:00:00Z".to_string(),
        }
    }

    fn seeded_ledger(label: &str) -> PathBuf {
        let path = temp_ledger_path(label);
        ledger::append(&path, &row("pod-a", &"1".repeat(64))).expect("append 1");
        ledger::append(&path, &row("pod-b", &"2".repeat(64))).expect("append 2");
        ledger::append(&path, &row("pod-a", &"3".repeat(64))).expect("append 3");
        path
    }

    #[test]
    fn lm_ledger_list_with_no_filters_returns_every_row_newest_first() {
        let path = seeded_ledger("no-filter");
        let rows = lm_ledger_list(&path, None, None, None).expect("list should succeed");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].profile_hash, "3".repeat(64));
        assert_eq!(rows[2].profile_hash, "1".repeat(64));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lm_ledger_list_filters_by_pod_id() {
        let path = seeded_ledger("pod-filter");
        let rows = lm_ledger_list(&path, Some("pod-a"), None, None).expect("list should succeed");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.pod_id == "pod-a"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lm_ledger_list_filters_by_profile_hash() {
        let path = seeded_ledger("hash-filter");
        let rows =
            lm_ledger_list(&path, None, Some(&"2".repeat(64)), None).expect("list should succeed");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_id, "pod-b");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lm_ledger_list_applies_limit_after_filtering() {
        let path = seeded_ledger("limit");
        let rows =
            lm_ledger_list(&path, Some("pod-a"), None, Some(1)).expect("list should succeed");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].profile_hash,
            "3".repeat(64),
            "newest pod-a row wins"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lm_ledger_list_on_a_missing_ledger_is_an_empty_vec_not_an_error() {
        let path = temp_ledger_path("missing");
        assert!(!path.exists());
        let rows = lm_ledger_list(&path, None, None, None).expect("missing ledger is empty");
        assert!(rows.is_empty());
    }

    #[test]
    fn lm_ledger_get_returns_the_row_at_the_newest_first_index() {
        let path = seeded_ledger("get");
        assert_eq!(
            lm_ledger_get(&path, 0)
                .expect("get 0")
                .map(|r| r.profile_hash),
            Some("3".repeat(64))
        );
        assert_eq!(
            lm_ledger_get(&path, 2)
                .expect("get 2")
                .map(|r| r.profile_hash),
            Some("1".repeat(64))
        );
        assert_eq!(lm_ledger_get(&path, 3).expect("get 3 out of range"), None);
        std::fs::remove_file(&path).ok();
    }
}
