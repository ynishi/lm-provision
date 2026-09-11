//! What a platform is running, read and rendered once.
//!
//! Two surfaces ask this question — `lm-provision machine list` and the
//! MCP `lm_machine_list` tool — and they have to get the same answer,
//! so the reading and the rendering live here rather than beside either
//! caller. 08 §Acquisitions and sweep is the rationale the listing
//! stands on: "the platform's list is the inventory; the record is not",
//! because a record is a file that can be lost while the machine keeps
//! billing.
//!
//! **Nothing here destroys anything.** The credential is still
//! required — the key buys the question — and that is the whole of what
//! it buys: this module has no release path, and a machine carrying no
//! lease stamp is reported exactly like one that does.

use crate::credentials;
use crate::infra::{self, Fleet, Machine};

/// One platform's own list, and what the platform's CLI said while
/// being asked.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// How the listing was read, and how a machine in it would be
    /// released — carried out so a caller acting on the list acts from
    /// the same description it was read through, rather than from a
    /// second lookup.
    pub fleet: Fleet,
    /// The machines, as [`infra::machines`] read them.
    pub machines: Vec<Machine>,
    /// The platform CLI's own stderr, and the program to attribute it
    /// to. This module never writes to a stream.
    pub said: (String, Vec<u8>),
}

/// Ask one platform what it is running.
///
/// The credential is required first: a listing without one is the
/// platform CLI's own error in the middle of somebody else's run, and
/// this way the refusal names the variable and where it was looked for.
pub fn fetch(provider: &str) -> Result<Fetched, String> {
    let adapter = infra::adapter_named(provider)?;
    credentials::require(adapter.provider_namespace(), adapter.credentials())
        .map_err(|missing| missing.to_string())?;
    let fleet = adapter
        .fleet()
        .ok_or_else(|| format!("{provider} cannot be asked what it is running"))?;
    let listing = infra::list(&fleet).map_err(|err| err.to_string())?;
    let program = fleet
        .list
        .first()
        .cloned()
        .unwrap_or_else(|| provider.to_string());
    Ok(Fetched {
        fleet,
        machines: listing.machines,
        said: (program, listing.said),
    })
}

/// A listing of every named platform: the machines, the platforms that
/// could not be asked, and what each platform CLI said while being
/// asked.
///
/// The fields are typed rather than a bag of JSON so that a caller
/// deciding an exit code or writing a log line reads a `&str`, not
/// `artifact["failed"][0]["reason"].as_str().unwrap_or("?")`. The
/// document is rendered from them ([`Listing::artifact`]), so the two
/// cannot disagree.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The machines, one JSON object each, in the order the platforms
    /// were named and each platform listed them.
    pub machines: Vec<serde_json::Value>,
    /// The platforms that could not be listed, and why: `(provider,
    /// reason)`.
    pub failed: Vec<(String, String)>,
    /// Each platform CLI's stderr under the program that said it, for
    /// the caller to relay or log.
    pub said: Vec<(String, Vec<u8>)>,
}

impl Listing {
    /// The one machine-readable document (07-cli.md §Stream split: one
    /// artifact per run), also the MCP tool's result.
    ///
    /// **`failed` is part of the document, not an alternative to it.**
    /// A run that could not ask one platform still knows what the
    /// others are running, and a caller told only "something went
    /// wrong" would have to ask again to find out what did not.
    pub fn artifact(&self) -> serde_json::Value {
        serde_json::json!({
            "machines": self.machines,
            "failed": self
                .failed
                .iter()
                .map(|(provider, reason)| serde_json::json!({
                    "provider": provider,
                    "reason": reason,
                }))
                .collect::<Vec<_>>(),
        })
    }

    /// Whether every named platform answered. False when any of them
    /// could not be listed — a plane nobody could read may be running
    /// anything, so the caller's exit code has to say so.
    pub fn complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Ask each named platform what it is running.
///
/// A platform that cannot be listed lands in [`Listing::failed`] rather
/// than ending the run: with two platforms named, one unreadable key
/// would otherwise hide the machines on the other.
pub fn list(providers: &[String]) -> Listing {
    let mut listing = Listing {
        machines: Vec::new(),
        failed: Vec::new(),
        said: Vec::new(),
    };
    for provider in providers {
        match fetch(provider) {
            Ok(fetched) => {
                listing.said.push(fetched.said);
                listing.machines.extend(
                    fetched
                        .machines
                        .iter()
                        .map(|machine| listed(machine, provider)),
                );
            }
            Err(reason) => listing.failed.push((provider.clone(), reason)),
        }
    }
    listing
}

/// One machine as the artifact reports it.
///
/// `expires_at` is the lease read off the machine's own name
/// ([`infra::expiry_of`]) in RFC 3339, the encoding the acquisitions
/// record writes its timestamps in — so a row here and a row there are
/// comparable without a second format to parse. `stamped` says whether
/// there was one to read at all: a machine this tool did not name is
/// not a machine with an expiry of zero, and the two have to be
/// distinguishable by something other than a `null` a reader might take
/// for "never expires".
fn listed(machine: &Machine, provider: &str) -> serde_json::Value {
    let expires_at = machine.name.as_deref().and_then(infra::expiry_of);
    serde_json::json!({
        "id": machine.id,
        "name": machine.name,
        "provider": provider,
        "expires_at": expires_at.map(|it| it.to_string()),
        "stamped": expires_at.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The lease is read off the machine, and an unstamped machine
    /// says so rather than reading as one that never expires.** Both
    /// surfaces render from this, so the shape is the contract: a
    /// `null` `expires_at` beside `stamped: false` is a machine this
    /// tool did not name.
    #[test]
    fn a_listed_machine_carries_the_lease_its_own_name_states() {
        let stamped = listed(
            &Machine {
                id: "pod-1".to_string(),
                name: Some("lmp-exp-20260902T063000Z".to_string()),
            },
            "runpod",
        );
        assert_eq!(
            stamped,
            serde_json::json!({
                "id": "pod-1",
                "name": "lmp-exp-20260902T063000Z",
                "provider": "runpod",
                "expires_at": "2026-09-02T06:30:00Z",
                "stamped": true,
            })
        );

        let unstamped = listed(
            &Machine {
                id: "49229000".to_string(),
                name: Some("jupyter-scratch".to_string()),
            },
            "vast",
        );
        assert_eq!(unstamped["stamped"], serde_json::json!(false));
        assert_eq!(unstamped["expires_at"], serde_json::Value::Null);
        assert_eq!(
            unstamped["name"],
            serde_json::json!("jupyter-scratch"),
            "what it is called is reported even when it is not a lease"
        );

        let nameless = listed(
            &Machine {
                id: "pod-2".to_string(),
                name: None,
            },
            "runpod",
        );
        assert_eq!(nameless["name"], serde_json::Value::Null);
        assert_eq!(nameless["stamped"], serde_json::json!(false));
    }

    /// **A platform that cannot be asked is reported, not fatal**, and
    /// the run is marked incomplete — with two platforms named, one
    /// unreadable credential must not hide what the other is running.
    #[test]
    fn an_unaskable_platform_lands_in_failed_and_costs_completeness() {
        let listing = list(&["not-a-platform".to_string()]);
        assert!(!listing.complete());
        assert!(listing.machines.is_empty());
        let (provider, reason) = &listing.failed[0];
        assert_eq!(provider, "not-a-platform");
        assert!(
            reason.contains("unknown provider"),
            "the reason names what was wrong with the request: {reason}"
        );

        let artifact = listing.artifact();
        assert_eq!(artifact["machines"], serde_json::json!([]));
        assert_eq!(
            artifact["failed"],
            serde_json::json!([{ "provider": provider, "reason": reason }]),
            "the document is rendered from the typed fields, so it cannot disagree with them"
        );

        let nothing = list(&[]);
        assert!(
            nothing.complete(),
            "no platform named is not a platform that failed"
        );
        assert_eq!(
            nothing.artifact(),
            serde_json::json!({ "machines": [], "failed": [] }),
            "the one document is emitted with every field present"
        );
    }
}
