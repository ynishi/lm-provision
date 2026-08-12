//! What the machine itself must be, and which targets can be that.
//!
//! # Why the profile has to be able to say this
//!
//! `comfyui.health` polls 8188 and cannot succeed unless the machine
//! exposes it. `models` pulls tens of gigabytes and cannot succeed
//! without the disk. Neither of those facts was expressible in a
//! profile, so a profile could fail for a reason the profile did not
//! contain — and the knowledge lived instead in whatever tool happened
//! to create the machine.
//!
//! This module is the vocabulary for saying it, and the contract a
//! target implements to be judged against it.
//!
//! # The line: this places a machine, it does not build infrastructure
//!
//! Networks, firewall rules, subnets, keys and identities are assumed to
//! exist. What is added is **one machine placed into them**.
//!
//! That is not a preference. A design that starts creating firewall
//! rules has to keep going — into routing, into identity — and arrives
//! at a worse Terraform. Where infrastructure genuinely has to be built,
//! delegating to a tool that builds infrastructure beats reimplementing
//! one. So [`Requirements`] describes the machine, and anything that
//! names infrastructure the machine attaches to lives in the profile's
//! `provider` slot instead, as a reference to something already there.
//!
//! # Requirements are not negotiable
//!
//! A target that cannot satisfy a requirement is **refused by name**. It
//! is not given a nearby capability instead.
//!
//! That is what every comparable tool does, and in two of them it is
//! what they changed *to*: Kubernetes leaves a Pod `Pending` and
//! enumerates each unsatisfied predicate rather than relaxing a filter
//! ([kube-scheduler](https://kubernetes.io/docs/concepts/scheduling-eviction/kube-scheduler/)),
//! Nomad blocks the evaluation
//! ([constraint](https://developer.hashicorp.com/nomad/docs/job-specification/constraint)),
//! Ansible fails during argument validation where `ignore_errors` cannot
//! reach it, and Terraform defines a provider that quietly returns
//! something other than what was declared as **a bug in the provider**
//! ([0.12 compatibility](https://developer.hashicorp.com/terraform/plugin/sdkv2/guides/terraform-0.12-compatibility)).
//!
//! For [`Exposure::PublicHttp`] the case is stronger than "less than
//! asked for": serving plaintext where HTTPS was declared is a
//! **downgrade of a security property**, and a profile author reading
//! their own declaration would not expect it. RFC 5280 §4.2 states the
//! shape for exactly this — reject "a critical extension that contains
//! information that it cannot process"
//! ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)). A
//! container runtime understands `public_http` perfectly well and cannot
//! process it.
//!
//! **There is deliberately no soft form.** Every tool that lets an
//! author say "preferred" gives it a different spelling at the point of
//! declaration — `requiredDuringScheduling…` against
//! `preferredDuringScheduling…`, `constraint` against `affinity`,
//! systemd's `Assert*=` against `Condition*=`, a critical against a
//! non-critical extension. If that is ever wanted here the shape is
//! known; building it before anything needs it would be inventing
//! vocabulary for an absent reader.

use std::collections::BTreeMap;
use std::fmt;

/// How a port must be reachable.
///
/// **This is what the workload needs, not what a platform offers.** A
/// managed pod service spells its own version `8188/http`; a container
/// runtime spells its `-p 8188:8188`. Naming either of those forms here
/// would make every profile that used it a profile for that platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exposure {
    /// Reachable over HTTPS from outside the machine.
    ///
    /// The TLS is part of the requirement, not an extra: this is what a
    /// profile declares when something off the machine will speak to
    /// this port over the public internet.
    PublicHttp,
    /// Reachable over TCP from outside the machine.
    ///
    /// What SSH wants, and anything else whose own protocol carries its
    /// security.
    RawTcp,
}

impl Exposure {
    /// The literal a profile writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicHttp => "public_http",
            Self::RawTcp => "raw_tcp",
        }
    }

    /// Parse a profile's literal, `None` for anything else.
    ///
    /// A closed set rather than a free string: an author who writes
    /// `https` should be told so, not have it silently mean nothing.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "public_http" => Some(Self::PublicHttp),
            "raw_tcp" => Some(Self::RawTcp),
            _ => None,
        }
    }

    /// Every exposure, for error messages that list the alternatives.
    pub const ALL: [Self; 2] = [Self::PublicHttp, Self::RawTcp];
}

impl fmt::Display for Exposure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One port and how it must be reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortRequirement {
    /// The port number on the machine.
    pub port: u16,
    /// How it must be reachable.
    pub exposure: Exposure,
}

/// What a profile requires of the machine it runs on.
///
/// Ordered and de-duplicated by port: the profile's slot is keyed by
/// port, so one port cannot carry two exposures — the map shape is the
/// invariant rather than a check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirements {
    /// Ports that must be reachable, ascending.
    pub ports: Vec<PortRequirement>,
}

impl Requirements {
    /// Read a profile's `requires_ports` slot.
    ///
    /// Fails on the first malformed entry rather than dropping it: an
    /// unreadable requirement that is silently skipped is the same
    /// machine as one that was never declared, which is the failure this
    /// whole slot exists to remove.
    pub fn from_slot(slot: &BTreeMap<String, String>) -> Result<Self, RequirementError> {
        let mut ports = Vec::with_capacity(slot.len());
        for (port, exposure) in slot {
            let parsed_port: u16 = port
                .parse()
                .ok()
                .filter(|it| *it != 0)
                .ok_or_else(|| RequirementError::BadPort { port: port.clone() })?;
            let parsed_exposure =
                Exposure::parse(exposure).ok_or_else(|| RequirementError::BadExposure {
                    port: parsed_port,
                    exposure: exposure.clone(),
                })?;
            ports.push(PortRequirement {
                port: parsed_port,
                exposure: parsed_exposure,
            });
        }
        ports.sort();
        Ok(Self { ports })
    }

    /// Whether anything is required at all.
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

/// A `requires_ports` entry that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequirementError {
    /// The key is not a port number.
    #[error("requires_ports[{port:?}] is not a port number (1-65535)")]
    BadPort {
        /// The unreadable key.
        port: String,
    },

    /// The value names no exposure.
    #[error(
        "requires_ports[{port}] = {exposure:?} names no exposure (expected one of: \
         public_http, raw_tcp)"
    )]
    BadExposure {
        /// The port whose value could not be read.
        port: u16,
        /// The unrecognised value.
        exposure: String,
    },
}

/// What a target can do, declared by its adapter.
///
/// Static: this answers "could this target ever satisfy that", which is
/// the admission question, and is separate from "is this machine in that
/// state right now", which is an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// A name for the target, for error messages.
    pub target: &'static str,
    /// The exposures this target can provide.
    pub exposures: &'static [Exposure],
}

impl Capability {
    /// Which of `required` this target cannot provide, in the order the
    /// profile declared them.
    pub fn shortfall(&self, required: &Requirements) -> Vec<Unsatisfiable> {
        required
            .ports
            .iter()
            .filter(|it| !self.exposures.contains(&it.exposure))
            .map(|it| Unsatisfiable {
                port: it.port,
                exposure: it.exposure,
                target: self.target,
            })
            .collect()
    }
}

/// One requirement a target cannot meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsatisfiable {
    /// The port whose requirement is unmet.
    pub port: u16,
    /// What was asked for.
    pub exposure: Exposure,
    /// The target that cannot provide it.
    pub target: &'static str,
}

impl fmt::Display for Unsatisfiable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "requires_ports[{}]={} is not available on {}",
            self.port, self.exposure, self.target
        )
    }
}

/// Refuse `required` on a target that cannot meet it, naming every
/// unmet requirement rather than the first.
///
/// The shape follows Kubernetes' `FailedScheduling`, which reports each
/// unsatisfied predicate alongside how many candidates it eliminated
/// rather than stopping at one
/// ([debugging Pods](https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/)).
/// An author who is told only the first of three problems fixes one and
/// runs again; the point of an admission check is to spend one round
/// trip.
///
/// `Ok(())` when everything is satisfiable. Whether the machine is
/// *currently* in that state is a different question, asked by
/// observation rather than here.
pub fn admit(required: &Requirements, capability: &Capability) -> Result<(), AdmissionError> {
    let unmet = capability.shortfall(required);
    if unmet.is_empty() {
        return Ok(());
    }
    Err(AdmissionError {
        target: capability.target,
        available: capability.exposures.to_vec(),
        unmet,
    })
}

/// A target was asked for something it cannot provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionError {
    /// The target that was judged.
    pub target: &'static str,
    /// What it can provide, so the message can say what to write instead.
    pub available: Vec<Exposure>,
    /// Everything it cannot, in profile order.
    pub unmet: Vec<Unsatisfiable>,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} cannot satisfy {} of this profile's port requirements: ",
            self.target,
            self.unmet.len()
        )?;
        for (index, unmet) in self.unmet.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{} ({})", unmet.port, unmet.exposure)?;
        }
        f.write_str("; it provides ")?;
        if self.available.is_empty() {
            f.write_str("no exposure at all")?;
        } else {
            for (index, exposure) in self.available.iter().enumerate() {
                if index > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{exposure}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for AdmissionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn requirements_read_in_ascending_port_order() {
        let read = Requirements::from_slot(&slot(&[("8188", "public_http"), ("22", "raw_tcp")]))
            .expect("both entries are well-formed");
        assert_eq!(
            read.ports,
            vec![
                PortRequirement {
                    port: 22,
                    exposure: Exposure::RawTcp
                },
                PortRequirement {
                    port: 8188,
                    exposure: Exposure::PublicHttp
                },
            ]
        );
    }

    #[test]
    fn an_empty_slot_requires_nothing() {
        assert!(Requirements::from_slot(&slot(&[]))
            .expect("empty is well-formed")
            .is_empty());
    }

    /// A key that is not a port is an error rather than a skipped entry:
    /// a requirement quietly dropped leaves exactly the machine the slot
    /// exists to stop shipping.
    #[test]
    fn an_unreadable_port_is_refused_not_skipped() {
        assert_eq!(
            Requirements::from_slot(&slot(&[("http", "public_http")])),
            Err(RequirementError::BadPort {
                port: "http".to_string()
            })
        );
        assert_eq!(
            Requirements::from_slot(&slot(&[("0", "raw_tcp")])),
            Err(RequirementError::BadPort {
                port: "0".to_string()
            })
        );
        assert_eq!(
            Requirements::from_slot(&slot(&[("70000", "raw_tcp")])),
            Err(RequirementError::BadPort {
                port: "70000".to_string()
            })
        );
    }

    /// The exposure set is closed, so `https` is told it is not a word
    /// here rather than meaning nothing.
    #[test]
    fn an_unknown_exposure_names_the_alternatives() {
        let err = Requirements::from_slot(&slot(&[("8188", "https")]))
            .expect_err("https is not an exposure");
        assert_eq!(
            err,
            RequirementError::BadExposure {
                port: 8188,
                exposure: "https".to_string()
            }
        );
        let rendered = err.to_string();
        assert!(rendered.contains("public_http"), "{rendered}");
        assert!(rendered.contains("raw_tcp"), "{rendered}");
    }

    const BOTH: Capability = Capability {
        target: "test-both",
        exposures: &[Exposure::PublicHttp, Exposure::RawTcp],
    };
    const TCP_ONLY: Capability = Capability {
        target: "test-tcp-only",
        exposures: &[Exposure::RawTcp],
    };

    #[test]
    fn a_target_that_provides_everything_admits() {
        let required =
            Requirements::from_slot(&slot(&[("8188", "public_http"), ("22", "raw_tcp")])).unwrap();
        assert!(admit(&required, &BOTH).is_ok());
    }

    #[test]
    fn no_requirement_admits_anywhere() {
        assert!(admit(&Requirements::default(), &TCP_ONLY).is_ok());
    }

    /// The refusal names **every** unmet requirement, not the first. An
    /// author told about one of three fixes one and runs again.
    #[test]
    fn a_refusal_names_every_unmet_requirement_and_what_is_available() {
        let required = Requirements::from_slot(&slot(&[
            ("8188", "public_http"),
            ("22", "raw_tcp"),
            ("9000", "public_http"),
        ]))
        .unwrap();
        let err = admit(&required, &TCP_ONLY).expect_err("public_http is unavailable");
        assert_eq!(err.unmet.len(), 2, "{err:?}");

        let rendered = err.to_string();
        assert!(rendered.contains("test-tcp-only"), "{rendered}");
        assert!(rendered.contains("8188"), "{rendered}");
        assert!(rendered.contains("9000"), "{rendered}");
        assert!(
            !rendered.contains(" 22 "),
            "the satisfiable requirement is not listed as a problem: {rendered}"
        );
        assert!(
            rendered.contains("it provides raw_tcp"),
            "the refusal says what the target can do: {rendered}"
        );
    }
}
