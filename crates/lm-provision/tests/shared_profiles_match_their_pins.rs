//! The shared-profile pins are hand-written twice — `profile_hash` in
//! `docs/profiles/index.json`, and the worked `fetch` example in
//! `docs/profiles/README.md` — and a stale pin fails every user who
//! copy-pastes the documented command against a perfectly healthy
//! source. Per the repo rule for hand-synced values (CLAUDE.md
//! 「手で同期する数を書かない」), this test recomputes each published
//! profile's canonical hash and names the file to fix on mismatch.

use std::path::{Path, PathBuf};

fn profiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/profiles")
}

fn hash_of(path: &Path) -> String {
    let node = lm_provision::frontend::load_profile(path)
        .unwrap_or_else(|err| panic!("{} must load: {err}", path.display()));
    lm_provision::canonical::hash(&node)
}

#[test]
fn every_index_pin_matches_the_profile_it_names() {
    let dir = profiles_dir();
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("index.json")).unwrap()).unwrap();
    let entries = index["profiles"]
        .as_array()
        .expect("index.json: profiles array");
    assert!(!entries.is_empty(), "index.json lists no profiles");

    for entry in entries {
        let path = dir.join(entry["path"].as_str().expect("entry.path"));
        let pinned = entry["profile_hash"].as_str().expect("entry.profile_hash");
        let actual = hash_of(&path);
        assert_eq!(
            pinned,
            actual,
            "docs/profiles/index.json pins {} for {}, but the profile hashes to {} — \
             update the pin (and the README example if it quotes it)",
            pinned,
            path.display(),
            actual,
        );
    }
}

/// Every 64-hex literal quoted in the README must be a current pin —
/// the worked `fetch` example is exactly the line users copy.
#[test]
fn every_hash_quoted_in_the_readme_is_current() {
    let dir = profiles_dir();
    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("index.json")).unwrap()).unwrap();
    let current: Vec<String> = index["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| hash_of(&dir.join(entry["path"].as_str().unwrap())))
        .collect();

    let mut quoted = 0;
    for token in readme.split(|c: char| !c.is_ascii_hexdigit()) {
        if token.len() == 64 {
            quoted += 1;
            assert!(
                current.contains(&token.to_string()),
                "docs/profiles/README.md quotes hash {token}, which matches no \
                 published profile — refresh the worked example",
            );
        }
    }
    assert!(quoted > 0, "the README's worked example should quote a pin");
}
