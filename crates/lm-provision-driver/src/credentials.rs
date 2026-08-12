//! Where a target's credential comes from, and what happens when it is
//! not there.
//!
//! # Why this is the tool's job
//!
//! A tool that starts machines has to own the means of starting them,
//! and on every target this drives, that means includes a credential.
//! The service CLI this crate drives reads `RUNPOD_API_KEY` from its
//! environment and offers no flag and no configuration file to pass it
//! any other way [measured: 2026-08-12, `runpod-cli --help` lists
//! `--base-url` / `-o` / `--dry-run` / `-v` and nothing else]. So the
//! only place a resolution order can live is the caller, and the caller
//! is this.
//!
//! Leaving it out did not remove the problem, it moved it: the
//! environment still had to be arranged, by whoever happened to be
//! running the driver. That is the failure this module exists to close
//! [measured: 2026-08-12, an operator went looking through another tool's
//! configuration for a key, found it, and hand-carried it into a
//! subprocess to make an acquisition run].
//!
//! # The shape is not novel
//!
//! Ordered sources, first hit wins, nothing hardcoded. Every AWS SDK
//! resolves credentials this way — "a series of places ... they check
//! in order ... after valid credentials are found, the search is
//! stopped" [documented:
//! <https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html>].
//! Terraform lists a literal key in the provider block first in its own
//! chain and marks it *not recommended*, pointing at environment
//! variables and role-based sources instead [documented:
//! <https://developer.hashicorp.com/terraform/language/providers/configuration>].
//! The provisioning tool this repo's lifecycle work was modelled on
//! does the same, in the same order.
//!
//! # Values are never handled here
//!
//! This module reads names, reports names, and reports which files were
//! consulted. A value passes from a file into the process environment
//! inside `dotenvy` and from there into the child process by ordinary
//! inheritance. Nothing in this module binds one to a variable, formats
//! one, or logs one — so there is no place for one to leak from.

use std::path::PathBuf;

/// The file the loader reads before falling back to the standard
/// locations, named by the environment.
pub const ENV_FILE: &str = "LM_PROVISION_ENV_FILE";

/// Fill the process environment from the first of these that says
/// something, without overwriting what is already set.
///
/// In order:
///
/// 1. what the process already has,
/// 2. the file named by [`ENV_FILE`],
/// 3. `~/.config/lm-provision/.env`,
/// 4. `./.env`.
///
/// **First writer wins.** `dotenvy::from_path` does not overwrite a
/// variable that is already set, so an exported value beats a file and
/// an explicitly named file beats the defaults. That ordering is what
/// makes an override an override rather than a coin toss.
///
/// A missing file is not an error — most of these are absent on any
/// given host, which is the point of having several. Returns the ones
/// that were read, for the report a failure prints.
pub fn load() -> Vec<PathBuf> {
    let mut loaded = Vec::new();
    for path in candidates() {
        if !path.exists() {
            continue;
        }
        if dotenvy::from_path(&path).is_ok() {
            loaded.push(path);
        }
    }
    loaded
}

/// The files [`load`] consults, in order, whether or not they exist.
pub fn candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(named) = std::env::var_os(ENV_FILE) {
        candidates.push(PathBuf::from(named));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/lm-provision/.env"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(".env"));
    }
    candidates
}

/// A credential a target needs and the environment does not have.
///
/// Carries the search so the message can say where it looked. An error
/// that names only the variable leaves the reader guessing which of
/// several files they were supposed to write it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// Which target asked.
    pub target: &'static str,
    /// The variable, by name. Never a value.
    pub name: &'static str,
    /// Where it was looked for, in order, and what was there.
    pub searched: Vec<Looked>,
}

/// One place the loader consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Looked {
    /// The file.
    pub path: PathBuf,
    /// What was found there.
    pub outcome: Found,
}

/// What a place turned out to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// No such file.
    Absent,
    /// Read, and it did not define this variable.
    ///
    /// Distinct from [`Found::Absent`] because it is the more confusing
    /// case by far: the file the reader is looking at is being read, and
    /// the line they want is simply not in it.
    Silent,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} needs {}, which is not set", self.target, self.name)?;
        for looked in &self.searched {
            let what = match looked.outcome {
                Found::Absent => "no such file",
                Found::Silent => "read, does not define it",
            };
            write!(f, "\n  searched: {} ({what})", looked.path.display())?;
        }
        Ok(())
    }
}

impl std::error::Error for Missing {}

/// Every name `target` needs, or the first one that is not there.
///
/// Call this **before** anything that spends money. The whole value of
/// checking is that it happens while the bill is still zero; a
/// credential discovered missing by a half-finished acquisition has
/// already cost something.
pub fn require(target: &'static str, names: &[&'static str]) -> Result<(), Missing> {
    for name in names {
        if std::env::var_os(name).is_some() {
            continue;
        }
        return Err(Missing {
            target,
            name,
            searched: candidates()
                .into_iter()
                .map(|path| {
                    // Already loaded by now, so a file that defines it
                    // would have set it and we would not be here.
                    let outcome = if path.exists() {
                        Found::Silent
                    } else {
                        Found::Absent
                    };
                    Looked { path, outcome }
                })
                .collect(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The order is the contract: an explicit file beats the defaults,
    /// and the process's own environment beats every file.
    #[test]
    fn the_search_order_puts_the_explicit_file_first() {
        // Serial with the other env-touching test in this module by
        // construction: they use different variables and this one reads
        // only what it sets.
        let named = "/tmp/lm-provision-test-explicit.env";
        // SAFETY: single-threaded within this test, and the variable is
        // read back only here.
        unsafe { std::env::set_var(ENV_FILE, named) };
        let candidates = candidates();
        unsafe { std::env::remove_var(ENV_FILE) };

        assert_eq!(candidates.first().unwrap(), &PathBuf::from(named));
        assert!(
            candidates
                .iter()
                .any(|it| it.ends_with(".config/lm-provision/.env")),
            "{candidates:?}"
        );
        assert!(
            candidates.last().unwrap().ends_with(".env"),
            "the project-local file is the last resort: {candidates:?}"
        );
    }

    /// **What the operator reads when it is not there.** The name, and
    /// every place that was consulted — including the ones that exist
    /// and stayed quiet, which is the case that wastes the most time.
    #[test]
    fn the_refusal_names_the_variable_and_where_it_looked() {
        let missing = Missing {
            target: "runpod",
            name: "RUNPOD_API_KEY",
            searched: vec![
                Looked {
                    path: PathBuf::from("/home/x/.config/lm-provision/.env"),
                    outcome: Found::Absent,
                },
                Looked {
                    path: PathBuf::from("/work/.env"),
                    outcome: Found::Silent,
                },
            ],
        };
        let rendered = missing.to_string();
        assert!(
            rendered.contains("runpod needs RUNPOD_API_KEY"),
            "{rendered}"
        );
        assert!(rendered.contains("/home/x/.config/lm-provision/.env (no such file)"));
        assert!(rendered.contains("/work/.env (read, does not define it)"));
    }

    /// **The chain delivers, and does not overwrite.**
    ///
    /// Both halves matter and neither is visible from
    /// [`candidates`] alone: a loader that reads the right files and
    /// drops what it finds looks identical from the outside, and one
    /// that clobbers an exported value turns an override into a
    /// coin toss.
    ///
    /// Uses names nothing else reads, so it does not race the rest of
    /// the suite over the process environment.
    #[test]
    fn a_file_reaches_the_environment_without_displacing_what_is_there() {
        let dir = std::env::temp_dir().join("lm-provision-credentials-test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("chain.env");
        std::fs::write(
            &file,
            "LM_PROVISION_TEST_FROM_FILE=arrived\nLM_PROVISION_TEST_ALREADY_SET=from-file\n",
        )
        .unwrap();

        // SAFETY: these three names are read nowhere else in the
        // workspace, so no other test observes them mid-flight.
        unsafe {
            std::env::set_var("LM_PROVISION_TEST_ALREADY_SET", "from-environment");
            std::env::set_var(ENV_FILE, &file);
        }
        let loaded = load();
        unsafe { std::env::remove_var(ENV_FILE) };

        assert!(loaded.contains(&file), "{loaded:?}");
        assert_eq!(
            std::env::var("LM_PROVISION_TEST_FROM_FILE").as_deref(),
            Ok("arrived"),
            "a file that defines a name is what makes it set"
        );
        assert_eq!(
            std::env::var("LM_PROVISION_TEST_ALREADY_SET").as_deref(),
            Ok("from-environment"),
            "first writer wins: an exported value is not replaced by a file"
        );

        assert!(require("t", &["LM_PROVISION_TEST_FROM_FILE"]).is_ok());
        unsafe {
            std::env::remove_var("LM_PROVISION_TEST_FROM_FILE");
            std::env::remove_var("LM_PROVISION_TEST_ALREADY_SET");
        }
        std::fs::remove_file(&file).ok();
    }

    /// A name the environment has is not a refusal, and a target that
    /// needs nothing is not either.
    #[test]
    fn a_target_that_needs_nothing_is_never_refused() {
        assert!(require("container", &[]).is_ok());
        assert!(require("anything", &["PATH"]).is_ok(), "PATH is always set");
    }
}
