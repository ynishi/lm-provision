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

/// What a profile requires of the machine's accelerators.
///
/// **Neither field is a platform's word.** A managed pod service selects
/// from its own catalogue of about fifty model names and has no VRAM
/// field at all [実測: `PodCreateInput`, which carries `gpuTypeIds`,
/// `gpuCount` and a `minRAMPerGPU` that is system RAM]; a container
/// runtime's `--gpus` takes a count or device ids and cannot select on
/// either model or VRAM. What a *workload* knows is how much memory its
/// weights need and how many devices it will use, so that is what is
/// written here.
///
/// Translating "at least 24 GB" into a set of model names is the
/// adapter's work, because the catalogue is the adapter's knowledge —
/// fifty rows that grow whenever the service adds hardware. Putting that
/// table in the vocabulary would make every profile carry a copy of one
/// vendor's price list, and it would go stale the way a hand-synchronised
/// number does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GpuRequirement {
    /// How many accelerators the workload will use.
    ///
    /// `0` is a machine with none, which is a real answer rather than an
    /// absent requirement — it is what a CPU-only profile says.
    pub count: u32,
    /// The least memory each one must have, in gigabytes.
    ///
    /// `None` when the profile does not care, which is different from
    /// zero: a profile that needs *a* GPU but not a particular size
    /// leaves this out rather than asking for 0 GB.
    pub min_vram_gb: Option<u32>,
}

/// What a profile requires of the machine's storage.
///
/// **Two levels, because the supplier's own words draw the line there.**
/// A managed pod service describes its container disk as "wiped when the
/// Pod restarts" and its volume as "persisted across Pod restarts"
/// [実測: `PodCreateInput`]. A profile that pulls forty gigabytes of
/// weights cares which of those it lands on, and nothing in a profile
/// could say so.
///
/// A third level exists — storage that outlives the machine itself, so
/// "future Pods can access it" — and it is **not here**. That is a
/// reference to something already created, which is what the `provider`
/// slot is for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskRequirement {
    /// Scratch space, in gigabytes, that may vanish when the machine
    /// restarts.
    ///
    /// `None` when the profile does not care how much there is.
    pub ephemeral_gb: Option<u32>,
    /// Space, in gigabytes, that survives a restart of the machine.
    ///
    /// `None` when the profile needs none. When set,
    /// [`Self::persistent_at`] must be too: a size with nowhere to
    /// appear cannot be rendered — a container runtime's mount needs a
    /// path, and a managed service needs to know where to attach it.
    pub persistent_gb: Option<u32>,
    /// Where the persistent space appears in the filesystem.
    pub persistent_at: Option<String>,
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
    /// Accelerators, when the profile asks for any.
    pub gpu: Option<GpuRequirement>,
    /// Storage, when the profile asks for any.
    pub disk: Option<DiskRequirement>,
    /// The base image the machine runs.
    ///
    /// The one requirement both targets take verbatim — a managed pod
    /// service's `imageName` and a container runtime's image argument are
    /// the same string. It is a requirement rather than a setting because
    /// the provisioner needs what is in it: a profile running
    /// `comfyui.install` needs git, and one running `toolchain.python`
    /// needs an interpreter.
    pub image: Option<String>,
}

impl Requirements {
    /// Read a profile's `requires_ports` and `requires_gpu` slots.
    ///
    /// Fails on the first malformed entry rather than dropping it: an
    /// unreadable requirement that is silently skipped is the same
    /// machine as one that was never declared, which is the failure this
    /// whole slot exists to remove.
    pub fn from_slots(
        ports: &BTreeMap<String, String>,
        gpu: &BTreeMap<String, String>,
        disk: &BTreeMap<String, String>,
        image: Option<&str>,
    ) -> Result<Self, RequirementError> {
        Ok(Self {
            gpu: Self::gpu_from_slot(gpu)?,
            disk: Self::disk_from_slot(disk)?,
            image: image.map(str::to_string),
            ..Self::from_slot(ports)?
        })
    }

    /// Read a profile's `requires_disk` slot.
    fn disk_from_slot(
        slot: &BTreeMap<String, String>,
    ) -> Result<Option<DiskRequirement>, RequirementError> {
        if slot.is_empty() {
            return Ok(None);
        }
        let mut disk = DiskRequirement::default();
        for (key, value) in slot {
            let gigabytes = || {
                value
                    .parse::<u32>()
                    .map_err(|_| RequirementError::BadDiskValue {
                        key: key.clone(),
                        value: value.clone(),
                    })
            };
            match key.as_str() {
                "ephemeral_gb" => disk.ephemeral_gb = Some(gigabytes()?),
                "persistent_gb" => disk.persistent_gb = Some(gigabytes()?),
                "persistent_at" => disk.persistent_at = Some(value.clone()),
                _ => return Err(RequirementError::UnknownDiskKey { key: key.clone() }),
            }
        }
        // A size with nowhere to appear cannot be rendered: a container
        // runtime's mount takes a path, and a managed service has to be
        // told where to attach the volume. Catching it here means the
        // author hears about it before a machine is spent.
        if disk.persistent_gb.is_some() && disk.persistent_at.is_none() {
            return Err(RequirementError::PersistentWithoutPath);
        }
        Ok(Some(disk))
    }

    /// Read a profile's `requires_gpu` slot: `count` and, optionally,
    /// `min_vram_gb`.
    ///
    /// A key that is neither is an error rather than an ignored line —
    /// an author who writes `vram` should be told it is not a word here,
    /// not have it mean nothing.
    fn gpu_from_slot(
        slot: &BTreeMap<String, String>,
    ) -> Result<Option<GpuRequirement>, RequirementError> {
        if slot.is_empty() {
            return Ok(None);
        }
        let mut gpu = GpuRequirement::default();
        let mut saw_count = false;
        for (key, value) in slot {
            let number: u32 = value.parse().map_err(|_| RequirementError::BadGpuValue {
                key: key.clone(),
                value: value.clone(),
            })?;
            match key.as_str() {
                "count" => {
                    gpu.count = number;
                    saw_count = true;
                }
                "min_vram_gb" => gpu.min_vram_gb = Some(number),
                _ => {
                    return Err(RequirementError::UnknownGpuKey { key: key.clone() });
                }
            }
        }
        if !saw_count {
            return Err(RequirementError::GpuWithoutCount);
        }
        Ok(Some(gpu))
    }

    /// Read a profile's `requires_ports` slot alone.
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
        Ok(Self {
            ports,
            gpu: None,
            disk: None,
            image: None,
        })
    }

    /// Whether anything is required at all.
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty() && self.gpu.is_none()
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

    /// A `requires_gpu` value is not a number.
    #[error("requires_gpu[{key}] = {value:?} is not a number")]
    BadGpuValue {
        /// Which entry.
        key: String,
        /// The unreadable value.
        value: String,
    },

    /// A `requires_gpu` key names nothing.
    #[error("requires_gpu[{key:?}] names nothing (expected one of: count, min_vram_gb)")]
    UnknownGpuKey {
        /// The unrecognised key.
        key: String,
    },

    /// `requires_gpu` was written without saying how many.
    ///
    /// A memory floor with no count does not describe a machine: it is
    /// unclear whether one accelerator is wanted or none, and the
    /// difference is whether the profile can run at all.
    #[error("requires_gpu declares no count (write `count`, using 0 for a machine with none)")]
    GpuWithoutCount,

    /// A `requires_disk` size is not a number.
    #[error("requires_disk[{key}] = {value:?} is not a number of gigabytes")]
    BadDiskValue {
        /// Which entry.
        key: String,
        /// The unreadable value.
        value: String,
    },

    /// A `requires_disk` key names nothing.
    #[error(
        "requires_disk[{key:?}] names nothing (expected one of: ephemeral_gb, \
         persistent_gb, persistent_at)"
    )]
    UnknownDiskKey {
        /// The unrecognised key.
        key: String,
    },

    /// Persistent space was asked for with no path to appear at.
    ///
    /// Neither target can render it: a container runtime's mount takes a
    /// path, and a managed service has to be told where to attach the
    /// volume.
    #[error(
        "requires_disk declares persistent_gb without persistent_at (where should it appear?)"
    )]
    PersistentWithoutPath,
}

/// What an adapter answers when asked whether it can meet a requirement.
///
/// **Four answers, and they are the `AssertOutcome` four.** A target
/// asked for an accelerator is not always in a position to say yes or
/// no: a container runtime cannot select on memory size at all, and
/// whether the host it lands on happens to have enough is a property of
/// where it was run rather than of the adapter. Saying "no" there would
/// refuse a machine that would have worked; saying "yes" would promise
/// something never checked. The honest answer is that it was not
/// examined, and this crate already had a word for that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The target can meet it, by choosing the named things.
    ///
    /// **The selection is not a substitution.** Picking the models that
    /// carry at least the requested memory is how the requirement is
    /// satisfied, the way a scheduler asked for four CPUs picks a node
    /// with at least four and says which. What the refusal rule forbids
    /// is *lowering* a requirement — handing back plaintext where HTTPS
    /// was asked for — and that is a different act from selecting
    /// something that meets it.
    ///
    /// Empty when nothing had to be chosen.
    Met {
        /// What the adapter picked, named so the choice is legible.
        using: Vec<String>,
    },
    /// The target cannot meet it, for the stated reason.
    Unmet {
        /// Why, in terms an author can act on.
        reason: String,
    },
    /// The target has no means to decide this before running.
    ///
    /// Not a refusal and not an approval — the question is settled by
    /// observing the machine, once there is one.
    NotExamined {
        /// Why it cannot be decided here.
        reason: String,
    },
}

impl Answer {
    /// Nothing had to be chosen and it holds.
    pub fn met() -> Self {
        Self::Met { using: Vec::new() }
    }

    /// It holds, by choosing these.
    pub fn met_using<I, S>(using: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Met {
            using: using.into_iter().map(Into::into).collect(),
        }
    }

    /// It does not hold.
    pub fn unmet(reason: impl Into<String>) -> Self {
        Self::Unmet {
            reason: reason.into(),
        }
    }

    /// It cannot be decided here.
    pub fn not_examined(reason: impl Into<String>) -> Self {
        Self::NotExamined {
            reason: reason.into(),
        }
    }

    /// Whether this answer blocks the run.
    ///
    /// Only [`Answer::Unmet`] does. An unexamined requirement is carried
    /// forward to be observed rather than treated as a failure — the
    /// distinction that makes the fourth answer worth having.
    pub fn blocks(&self) -> bool {
        matches!(self, Self::Unmet { .. })
    }
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

/// What an adapter found when it looked at an actual machine.
///
/// **Every field is optional, and absent means "not observed" rather
/// than "not there".** An adapter reports what it could see; a container
/// runtime asked about a proxy in front of it has no way to look, and
/// saying zero would be a claim it did not make.
///
/// This is the other half of the pair [`admit`] opens. Admission asks
/// what a target *could* provide and runs before anything exists;
/// this asks what a machine *does* provide and runs once one does. The
/// requirements an adapter could not decide statically — a memory floor
/// on a runtime that cannot select one — are settled here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineState {
    /// How each port is actually reachable, by port number.
    ///
    /// A port absent from the map was not seen exposed; the map being
    /// empty because nothing was looked at is [`Self::ports_observed`].
    pub exposed: BTreeMap<u16, Exposure>,
    /// Whether the exposure of ports could be observed at all.
    pub ports_observed: bool,
    /// How many accelerators the machine has.
    pub gpu_count: Option<u32>,
    /// How much memory each one has, in gigabytes.
    pub gpu_vram_gb: Option<u32>,
    /// Scratch space, in gigabytes.
    pub ephemeral_gb: Option<u32>,
    /// Space surviving a restart, in gigabytes.
    pub persistent_gb: Option<u32>,
    /// Where that space is mounted.
    pub persistent_at: Option<String>,
    /// The image the machine is running.
    pub image: Option<String>,
}

/// One requirement, and what looking at the machine said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The requirement, in the words the profile wrote.
    pub requirement: String,
    /// What was found.
    pub outcome: Outcome,
}

/// What observing one requirement concluded.
///
/// **The same three values [`crate::exec::assert::AssertOutcome`]
/// carries** for the requirements it can see — and deliberately the same
/// words, because "I looked and it is not so" and "I did not look" are
/// the distinction this whole model exists to keep. The fourth,
/// `CheckFailed`, belongs to an observation that broke; an adapter that
/// cannot reach the platform reports that as an error rather than as a
/// finding, so it does not appear here.
///
/// A separate type rather than the enum itself: that one names host
/// predicates evaluated *on* the machine, and these are answers from a
/// platform *about* one. Sharing the values without sharing the
/// predicate set is the point — a provisioner running on the machine has
/// no credentials to ask a platform anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The machine has it.
    Satisfied,
    /// The machine does not have it.
    Unsatisfied,
    /// Nothing here could tell.
    NotChecked,
}

/// Compare what a profile requires against what a machine turned out to
/// be.
///
/// Returns one finding per requirement, in the order a profile reads:
/// image, accelerators, storage, ports. **Every requirement produces a
/// finding**, including the ones nothing could see — an omitted line
/// would read as a requirement that was met.
pub fn observe(required: &Requirements, state: &MachineState) -> Vec<Finding> {
    let mut findings = Vec::new();

    let compare = |name: String, want: &str, got: Option<&str>| Finding {
        requirement: name,
        outcome: match got {
            None => Outcome::NotChecked,
            Some(found) if found == want => Outcome::Satisfied,
            Some(_) => Outcome::Unsatisfied,
        },
    };

    let at_least = |name: String, floor: u32, got: Option<u32>| Finding {
        requirement: name,
        outcome: match got {
            None => Outcome::NotChecked,
            Some(found) if found >= floor => Outcome::Satisfied,
            Some(_) => Outcome::Unsatisfied,
        },
    };

    if let Some(image) = &required.image {
        findings.push(compare(
            format!("image={image}"),
            image,
            state.image.as_deref(),
        ));
    }

    if let Some(gpu) = &required.gpu {
        findings.push(at_least(
            format!("gpu.count={}", gpu.count),
            gpu.count,
            state.gpu_count,
        ));
        if let Some(floor) = gpu.min_vram_gb {
            findings.push(at_least(
                format!("gpu.min_vram_gb={floor}"),
                floor,
                state.gpu_vram_gb,
            ));
        }
    }

    if let Some(disk) = &required.disk {
        if let Some(gb) = disk.ephemeral_gb {
            findings.push(at_least(
                format!("disk.ephemeral_gb={gb}"),
                gb,
                state.ephemeral_gb,
            ));
        }
        if let Some(gb) = disk.persistent_gb {
            findings.push(at_least(
                format!("disk.persistent_gb={gb}"),
                gb,
                state.persistent_gb,
            ));
        }
        if let Some(path) = &disk.persistent_at {
            findings.push(compare(
                format!("disk.persistent_at={path}"),
                path,
                state.persistent_at.as_deref(),
            ));
        }
    }

    for port in &required.ports {
        findings.push(Finding {
            requirement: format!("ports[{}]={}", port.port, port.exposure),
            outcome: if !state.ports_observed {
                Outcome::NotChecked
            } else if state.exposed.get(&port.port) == Some(&port.exposure) {
                Outcome::Satisfied
            } else {
                Outcome::Unsatisfied
            },
        });
    }

    findings
}

/// Whether a machine is finished being what the profile asked for.
///
/// **`NotChecked` does not make it done.** A run that proceeds on
/// requirements nothing looked at is a run whose failures arrive later
/// and further from their cause — which is the shape this whole slot
/// exists to remove. So the answer is three-valued too, and the caller
/// decides what an unexamined machine is worth.
pub fn verdict(findings: &[Finding]) -> Outcome {
    if findings.iter().any(|it| it.outcome == Outcome::Unsatisfied) {
        return Outcome::Unsatisfied;
    }
    if findings.iter().any(|it| it.outcome == Outcome::NotChecked) {
        return Outcome::NotChecked;
    }
    Outcome::Satisfied
}

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

    fn gpu_slot(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        slot(pairs)
    }

    #[test]
    fn a_gpu_requirement_reads_its_count_and_optional_floor() {
        let read = Requirements::from_slots(
            &slot(&[]),
            &gpu_slot(&[("count", "2"), ("min_vram_gb", "24")]),
            &slot(&[]),
            None,
        )
        .expect("well-formed");
        assert_eq!(
            read.gpu,
            Some(GpuRequirement {
                count: 2,
                min_vram_gb: Some(24)
            })
        );
    }

    /// A floor with no count does not describe a machine: whether one
    /// accelerator is wanted or none is the difference between a profile
    /// that can run and one that cannot.
    #[test]
    fn a_gpu_requirement_without_a_count_is_refused() {
        assert_eq!(
            Requirements::from_slots(
                &slot(&[]),
                &gpu_slot(&[("min_vram_gb", "24")]),
                &slot(&[]),
                None
            ),
            Err(RequirementError::GpuWithoutCount)
        );
    }

    /// Zero is a real answer — a machine with no accelerator, which is
    /// what a CPU-only profile says — and is not the same as writing
    /// nothing at all.
    #[test]
    fn zero_accelerators_is_a_requirement_and_absence_is_not() {
        let declared =
            Requirements::from_slots(&slot(&[]), &gpu_slot(&[("count", "0")]), &slot(&[]), None)
                .expect("well-formed");
        assert_eq!(
            declared.gpu,
            Some(GpuRequirement {
                count: 0,
                min_vram_gb: None
            })
        );
        assert!(!declared.is_empty());

        let absent = Requirements::from_slots(&slot(&[]), &gpu_slot(&[]), &slot(&[]), None)
            .expect("well-formed");
        assert_eq!(absent.gpu, None);
        assert!(absent.is_empty());
    }

    #[test]
    fn an_unknown_gpu_key_names_the_alternatives() {
        let err =
            Requirements::from_slots(&slot(&[]), &gpu_slot(&[("vram", "24")]), &slot(&[]), None)
                .expect_err("vram is not a key here");
        assert_eq!(
            err,
            RequirementError::UnknownGpuKey {
                key: "vram".to_string()
            }
        );
        let rendered = err.to_string();
        assert!(rendered.contains("count"), "{rendered}");
        assert!(rendered.contains("min_vram_gb"), "{rendered}");
    }

    #[test]
    fn a_gpu_value_that_is_not_a_number_is_refused() {
        assert_eq!(
            Requirements::from_slots(&slot(&[]), &gpu_slot(&[("count", "one")]), &slot(&[]), None),
            Err(RequirementError::BadGpuValue {
                key: "count".to_string(),
                value: "one".to_string()
            })
        );
    }

    /// Only [`Answer::Unmet`] stops a run. Not having looked is carried
    /// forward to be observed — which is the whole reason the answer has
    /// four arms rather than two.
    #[test]
    fn only_a_refusal_blocks() {
        assert!(!Answer::met().blocks());
        assert!(!Answer::met_using(["NVIDIA A40"]).blocks());
        assert!(!Answer::not_examined("cannot select on memory").blocks());
        assert!(Answer::unmet("nothing carries that much").blocks());
    }

    fn required_all() -> Requirements {
        Requirements::from_slots(
            &slot(&[("8188", "public_http")]),
            &slot(&[("count", "1"), ("min_vram_gb", "24")]),
            &slot(&[("persistent_gb", "50"), ("persistent_at", "/workspace")]),
            Some("runpod/pytorch:2.4.0"),
        )
        .expect("well-formed fixture")
    }

    /// **What stage 4 settles.** A memory floor a container adapter
    /// could not decide at admission is decided here, by looking.
    #[test]
    fn looking_at_the_machine_settles_what_admission_could_not() {
        let required = required_all();
        let state = MachineState {
            exposed: [(8188, Exposure::PublicHttp)].into_iter().collect(),
            ports_observed: true,
            gpu_count: Some(1),
            gpu_vram_gb: Some(48),
            persistent_gb: Some(100),
            persistent_at: Some("/workspace".into()),
            image: Some("runpod/pytorch:2.4.0".into()),
            ..MachineState::default()
        };
        let findings = observe(&required, &state);
        assert_eq!(verdict(&findings), Outcome::Satisfied, "{findings:#?}");
        assert!(
            findings.iter().any(
                |it| it.requirement == "gpu.min_vram_gb=24" && it.outcome == Outcome::Satisfied
            ),
            "the floor admission left unexamined is now answered: {findings:#?}"
        );
    }

    /// A floor is a floor: more than asked for satisfies it, less does
    /// not.
    #[test]
    fn a_machine_smaller_than_the_floor_is_unsatisfied() {
        let state = MachineState {
            gpu_count: Some(1),
            gpu_vram_gb: Some(16),
            ..MachineState::default()
        };
        let required = Requirements::from_slots(
            &slot(&[]),
            &slot(&[("count", "1"), ("min_vram_gb", "24")]),
            &slot(&[]),
            None,
        )
        .unwrap();
        let findings = observe(&required, &state);
        assert_eq!(verdict(&findings), Outcome::Unsatisfied, "{findings:#?}");
    }

    /// **Nothing observed is not "done".** A machine nobody looked at
    /// is not a machine that met the requirements, and treating it as
    /// one is how a failure arrives later and further from its cause.
    #[test]
    fn an_unobserved_requirement_does_not_pass() {
        let required = required_all();
        let findings = observe(&required, &MachineState::default());
        assert_eq!(verdict(&findings), Outcome::NotChecked, "{findings:#?}");
        assert!(
            findings.iter().all(|it| it.outcome == Outcome::NotChecked),
            "{findings:#?}"
        );
    }

    /// Every requirement gets a line, including the unseen ones — an
    /// omitted finding reads as a requirement that was met.
    #[test]
    fn every_requirement_produces_a_finding() {
        let findings = observe(&required_all(), &MachineState::default());
        let names: Vec<&str> = findings.iter().map(|it| it.requirement.as_str()).collect();
        assert!(names.contains(&"image=runpod/pytorch:2.4.0"), "{names:?}");
        assert!(names.contains(&"gpu.count=1"), "{names:?}");
        assert!(names.contains(&"gpu.min_vram_gb=24"), "{names:?}");
        assert!(names.contains(&"disk.persistent_gb=50"), "{names:?}");
        assert!(
            names.contains(&"disk.persistent_at=/workspace"),
            "{names:?}"
        );
        assert!(names.contains(&"ports[8188]=public_http"), "{names:?}");
    }

    /// One failure outranks any number of unexamined lines: a machine
    /// known to be wrong is wrong whatever else went unlooked at.
    #[test]
    fn a_failure_outranks_an_unexamined_line() {
        let required = required_all();
        let state = MachineState {
            image: Some("some/other:tag".into()),
            ..MachineState::default()
        };
        assert_eq!(verdict(&observe(&required, &state)), Outcome::Unsatisfied);
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
