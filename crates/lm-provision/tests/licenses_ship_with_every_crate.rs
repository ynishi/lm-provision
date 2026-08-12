//! Each publishable crate carries its own copy of both license texts,
//! and each copy matches the workspace's.
//!
//! **Why the duplication exists.** The crates declare
//! `license = "MIT OR Apache-2.0"` and the README points at the two
//! files, so a reader who takes a crate from the registry should find
//! them. `cargo package` does not follow symlinks and `include` cannot
//! reach outside a package directory, so the only way a workspace
//! member ships them is by holding them — six copies of two files.
//!
//! Prose that has to be hand-synchronised is a liability, which is why
//! this exists: the copies are the kind of thing nobody notices going
//! stale. If one diverges, this test names which.

use std::path::{Path, PathBuf};

const CRATES: [&str; 3] = ["lm-provision", "lm-provision-driver", "lm-provision-mcp"];
const LICENSES: [&str; 2] = ["LICENSE-MIT", "LICENSE-APACHE"];

/// The workspace root, or `None` when this runs from somewhere the
/// workspace is not — an unpacked tarball, for instance, where there is
/// nothing to compare against and nothing to have drifted.
fn workspace_root() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    root.join("LICENSE-MIT")
        .exists()
        .then(|| root.to_path_buf())
}

#[test]
fn every_publishable_crate_carries_both_licenses_verbatim() {
    let Some(root) = workspace_root() else {
        return;
    };

    for name in LICENSES {
        let canonical = std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("reading {name} at the workspace root: {err}"));

        for crate_name in CRATES {
            let path = root.join("crates").join(crate_name).join(name);
            let copy = std::fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!(
                    "{crate_name} does not carry {name} ({err}) — a crate that \
                     declares a license and does not ship it leaves the reader \
                     of the registry without one"
                )
            });
            assert_eq!(
                copy, canonical,
                "{crate_name}/{name} has drifted from the workspace copy; \
                 replace it rather than editing one of the two"
            );
        }
    }
}
