//! The targets a machine can be placed on, and what each can provide.
//!
//! [`Infra`] is to the machine what [`crate::transport::Transport`] is to
//! reaching it: the port in the ports-and-adapters sense, with one
//! implementation per target. It is not called `Port` because a profile's
//! requirements are about network ports, and two meanings of that word in
//! one file would cost more than the convention is worth — `Transport`
//! set that precedent, naming itself for what it does.
//!
//! # Two adapters from the start, deliberately
//!
//! [`RunPodAdapter`] is the target this repo actually provisions.
//! [`ContainerAdapter`] is here to keep the vocabulary honest: a
//! requirement language designed against one platform records that
//! platform's shape and calls it universal. This crate has made that
//! mistake once already — a download route was built around one
//! supplier's behaviour and turned out to describe only that supplier —
//! and the cost of not making it again is a few lines of `docker run`.
//!
//! The second adapter earns its place immediately: it is the one that
//! *cannot* provide [`Exposure::PublicHttp`], so it is what proves the
//! refusal path is real rather than theoretical.
//!
//! # What an adapter does not do
//!
//! It does not create infrastructure. A network, a firewall rule, a
//! subnet, a key: assumed to exist, and named — when a target needs to
//! be told which one — through the profile's `provider` slot. See
//! [`lm_provision::machine`] for why that line is where it is.

use std::collections::BTreeMap;

use lm_provision::machine::{
    Answer, Capability, DiskRequirement, Exposure, GpuRequirement, MachineState, Requirements,
};

/// A target that a machine can be placed on.
pub trait Infra {
    /// What this target can provide, for the admission check.
    ///
    /// Static, and deliberately so: this answers "could this target ever
    /// satisfy that", which is decidable before anything runs. Whether a
    /// particular machine is *currently* in the required state is an
    /// observation, and a different question.
    fn capability(&self) -> Capability;

    /// Render `required` as the arguments this target takes.
    ///
    /// Only called once [`lm_provision::machine::admit`] has passed, so
    /// an implementation may assume every requirement is one it declared
    /// it could provide — an unprovidable one reaching here would be an
    /// admission bug, not an input to handle.
    fn render(&self, required: &Requirements) -> Vec<String>;

    /// Which `provider` keys this adapter reads, by namespace.
    ///
    /// A key outside it belongs to some other target. That is neither an
    /// error nor silently fine: see [`unexamined`].
    fn provider_namespace(&self) -> &'static str;

    /// Whether this target can give the workload the accelerators it
    /// asked for, and — when a choice was involved — which ones.
    ///
    /// Separate from [`Infra::capability`] because the answer is not a
    /// yes or a no. A target may be unable to *decide*: a container
    /// runtime cannot select on memory size, so whether the host it
    /// lands on has enough is settled by looking at the machine rather
    /// than by reading the adapter.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer;

    /// Whether this target can give the workload the storage it asked
    /// for.
    ///
    /// Same shape as [`Infra::gpu_answer`] and for the same reason: a
    /// target may be able to *provide* persistence without being able to
    /// *size* it, and neither yes nor no describes that.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer;

    /// The request that would bring a machine meeting `required` into
    /// existence.
    ///
    /// **Rendered, not sent.** Returning the request rather than
    /// performing it keeps the one operation here that spends money and
    /// changes state outside anything that runs by accident: a caller
    /// has to take this and execute it deliberately. It is also what
    /// makes the shape testable without a machine, and what lets a
    /// `plan` show an operator the acquisition before it happens.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
    ) -> Result<Acquisition, AcquisitionError>;

    /// Read what [`Acquisition::inspect`] returned into the state
    /// [`lm_provision::machine::observe`] judges.
    ///
    /// **Absent means not observed.** A field this cannot find is left
    /// `None` rather than defaulted, because a zero would be a claim
    /// about the machine that nothing made.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState;
}

/// What to run to obtain a machine, and what to run to give it back.
///
/// Both halves together, because an acquisition whose release is worked
/// out later is an acquisition that leaks. This session produced two
/// orphaned machines by hand for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acquisition {
    /// The program and arguments that create the machine.
    pub create: Vec<String>,
    /// The request body, when the create call takes one.
    pub body: Option<String>,
    /// How to read back what was created, given its id.
    ///
    /// `{id}` is replaced with the identifier the create call returns.
    pub inspect: Vec<String>,
    /// How to destroy it, with the same substitution.
    pub release: Vec<String>,
}

/// An acquisition that cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcquisitionError {
    /// This target has no acquisition wired.
    #[error("{target} cannot acquire a machine here: {reason}")]
    Unsupported {
        /// Which target.
        target: &'static str,
        /// Why not.
        reason: &'static str,
    },

    /// A requirement this target needs in order to create anything.
    #[error("{target} needs {missing} to create a machine")]
    Incomplete {
        /// Which target.
        target: &'static str,
        /// What was not declared.
        missing: &'static str,
    },
}

/// A GPU model and how much memory it carries.
///
/// **This table is adapter knowledge, and that is the point.** A managed
/// pod service selects by model name from its own catalogue and has no
/// memory field at all, so somebody has to know which models carry 24 GB
/// — and the only party that should is the one whose catalogue it is. In
/// the vocabulary it would be one vendor's price list embedded in every
/// profile.
struct Gpu {
    /// The name the service's API expects.
    id: &'static str,
    /// Memory per device, in gigabytes.
    vram_gb: u32,
}

/// A subset of the service's catalogue, largest-selling models first.
///
/// **Deliberately partial.** The catalogue runs to about fifty entries
/// [実測: `PodCreateInput.gpuTypeIds`, 49 values] and grows with the
/// service's hardware; carrying all of it here would be a second copy of
/// somebody else's list, going stale on their release schedule rather
/// than this repo's. What is here is enough to select against, and an
/// absent model costs a profile nothing it could not get by naming the
/// model itself through `provider.runpod.gpuTypeIds`.
const RUNPOD_CATALOGUE: &[Gpu] = &[
    Gpu {
        id: "NVIDIA A40",
        vram_gb: 48,
    },
    Gpu {
        id: "NVIDIA L40S",
        vram_gb: 48,
    },
    Gpu {
        id: "NVIDIA RTX A6000",
        vram_gb: 48,
    },
    Gpu {
        id: "NVIDIA A100 80GB PCIe",
        vram_gb: 80,
    },
    Gpu {
        id: "NVIDIA H100 PCIe",
        vram_gb: 80,
    },
    Gpu {
        id: "NVIDIA GeForce RTX 4090",
        vram_gb: 24,
    },
    Gpu {
        id: "NVIDIA RTX A5000",
        vram_gb: 24,
    },
    Gpu {
        id: "NVIDIA L4",
        vram_gb: 24,
    },
];

/// A managed GPU-pod service: the machine is one API object, and the
/// service owns the network in front of it.
///
/// Its port form is `[port]/[protocol]`, where the protocol is `http` or
/// `tcp` and selects **how the port is exposed** rather than what speaks
/// over it: `http` puts the port behind the service's own HTTPS reverse
/// proxy, `tcp` maps it to a public port on the machine's address
/// [実測: 2026-08-11 — `8188/http` answered on a proxied `https://` URL,
/// `22/tcp` answered on a mapped port of the public IP].
///
/// That is why a bare port number is not enough vocabulary. Rendering
/// `22` as `http` would put SSH behind an HTTPS proxy, and an adapter
/// asked to guess would have to.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunPodAdapter;

impl Infra for RunPodAdapter {
    fn capability(&self) -> Capability {
        Capability {
            target: "runpod",
            exposures: &[Exposure::PublicHttp, Exposure::RawTcp],
        }
    }

    fn render(&self, required: &Requirements) -> Vec<String> {
        required
            .ports
            .iter()
            .map(|it| {
                let protocol = match it.exposure {
                    Exposure::PublicHttp => "http",
                    Exposure::RawTcp => "tcp",
                };
                format!("{}/{}", it.port, protocol)
            })
            .collect()
    }

    fn provider_namespace(&self) -> &'static str {
        "runpod"
    }

    /// Selecting the models that carry at least the requested memory,
    /// and saying which.
    ///
    /// **Selection is not substitution.** The requirement was a memory
    /// floor; every model returned clears it. That is a scheduler asked
    /// for four CPUs picking a node with at least four and reporting
    /// which — not the thing the refusal rule forbids, which is handing
    /// back *less* than was declared.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        if required.count == 0 {
            return Answer::met();
        }
        let Some(floor) = required.min_vram_gb else {
            // No floor: the service attaches whatever is available, and
            // there is nothing to choose between.
            return Answer::met();
        };
        let mut fits: Vec<&Gpu> = RUNPOD_CATALOGUE
            .iter()
            .filter(|it| it.vram_gb >= floor)
            .collect();
        if fits.is_empty() {
            return Answer::unmet(format!(
                "no catalogued GPU carries {floor} GB; the largest known here is {} GB \
                 (name a model directly with provider.runpod.gpuTypeIds if the \
                 catalogue is behind)",
                RUNPOD_CATALOGUE
                    .iter()
                    .map(|it| it.vram_gb)
                    .max()
                    .unwrap_or(0),
            ));
        }
        // Smallest first: the requirement was a floor, so the cheapest
        // thing that clears it is the one to ask for, and the rest are
        // fallbacks the service can rent when it is short.
        fits.sort_by_key(|it| (it.vram_gb, it.id));
        Answer::met_using(fits.into_iter().map(|it| it.id))
    }

    /// Both levels are settable: the service takes a size for the disk
    /// that is wiped on restart and a size for the volume that is not,
    /// plus where the second one is mounted.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        let mut using = Vec::new();
        if let Some(gb) = required.ephemeral_gb {
            using.push(format!("containerDiskInGb={gb}"));
        }
        if let Some(gb) = required.persistent_gb {
            using.push(format!("volumeInGb={gb}"));
        }
        if let Some(path) = &required.persistent_at {
            using.push(format!("volumeMountPath={path}"));
        }
        Answer::Met { using }
    }

    /// The service's own CLI, which is generated from its OpenAPI
    /// description and already handles authentication from the
    /// environment.
    ///
    /// Driving that rather than speaking the REST API here is the same
    /// judgement the transport layer makes: the useful thing this repo
    /// adds is the requirements, not a second REST client that has to
    /// track somebody else's schema.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
    ) -> Result<Acquisition, AcquisitionError> {
        let image = required
            .image
            .as_deref()
            .ok_or(AcquisitionError::Incomplete {
                target: "runpod",
                missing: "requires_image",
            })?;

        let mut body = serde_json::Map::new();
        body.insert("imageName".into(), serde_json::json!(image));
        body.insert("ports".into(), serde_json::json!(self.render(required)));

        if let Some(gpu) = &required.gpu {
            body.insert(
                "computeType".into(),
                serde_json::json!(if gpu.count == 0 { "CPU" } else { "GPU" }),
            );
            if gpu.count > 0 {
                body.insert("gpuCount".into(), serde_json::json!(gpu.count));
                // The models that clear the floor, in the order the
                // answer put them: cheapest first, the rest as what the
                // service can fall back to when it is short.
                if let Answer::Met { using } = self.gpu_answer(gpu) {
                    if !using.is_empty() {
                        body.insert("gpuTypeIds".into(), serde_json::json!(using));
                    }
                }
            }
        }

        if let Some(disk) = &required.disk {
            if let Some(gb) = disk.ephemeral_gb {
                body.insert("containerDiskInGb".into(), serde_json::json!(gb));
            }
            if let Some(gb) = disk.persistent_gb {
                body.insert("volumeInGb".into(), serde_json::json!(gb));
            }
            if let Some(path) = &disk.persistent_at {
                body.insert("volumeMountPath".into(), serde_json::json!(path));
            }
        }

        // Whatever the profile addressed to this target, verbatim and
        // last, so a network volume named there replaces the sizes above
        // the way the service documents it doing.
        for (key, value) in provider {
            if let Some(field) = key.strip_prefix("runpod.") {
                body.insert(field.to_string(), serde_json::json!(value));
            }
        }

        Ok(Acquisition {
            create: vec![
                "runpod-cli".into(),
                "pods".into(),
                "create-pod".into(),
                "-j".into(),
            ],
            body: Some(serde_json::Value::Object(body).to_string()),
            inspect: vec![
                "runpod-cli".into(),
                "pods".into(),
                "get-pod".into(),
                "{id}".into(),
            ],
            release: vec![
                "runpod-cli".into(),
                "pods".into(),
                "delete-pod".into(),
                "{id}".into(),
            ],
        })
    }

    /// Read the service's own pod description.
    ///
    /// The `ports` array comes back in the same `[port]/[protocol]` form
    /// it went out in, so what the machine exposes is read with the same
    /// vocabulary the requirement was written in.
    ///
    /// Device memory is the one field that has to be looked up rather
    /// than read: the description names the model
    /// (`machine.gpuTypeId`) and never the size, which is the same
    /// asymmetry that put the catalogue in this adapter in the first
    /// place. A model outside it leaves the memory unobserved — `None`,
    /// not a guess.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState {
        let number = |value: &serde_json::Value| value.as_u64().map(|it| it as u32);
        let text = |value: &serde_json::Value| value.as_str().map(str::to_string);

        let mut exposed = BTreeMap::new();
        let ports = inspected.get("ports").and_then(|it| it.as_array());
        if let Some(ports) = ports {
            for entry in ports.iter().filter_map(|it| it.as_str()) {
                let Some((port, protocol)) = entry.split_once('/') else {
                    continue;
                };
                let Ok(port) = port.parse::<u16>() else {
                    continue;
                };
                let exposure = match protocol {
                    "http" => Exposure::PublicHttp,
                    "tcp" => Exposure::RawTcp,
                    _ => continue,
                };
                exposed.insert(port, exposure);
            }
        }

        let gpu_vram_gb = inspected
            .get("machine")
            .and_then(|it| it.get("gpuTypeId"))
            .and_then(|it| it.as_str())
            .and_then(|model| {
                RUNPOD_CATALOGUE
                    .iter()
                    .find(|it| it.id == model)
                    .map(|it| it.vram_gb)
            });

        MachineState {
            exposed,
            // The description carries the field whether or not anything
            // is in it, so an empty list is "nothing exposed" rather
            // than "nobody looked".
            ports_observed: ports.is_some(),
            gpu_count: inspected.get("gpuCount").and_then(number),
            gpu_vram_gb,
            ephemeral_gb: inspected.get("containerDiskInGb").and_then(number),
            persistent_gb: inspected.get("volumeInGb").and_then(number),
            persistent_at: inspected.get("volumeMountPath").and_then(text),
            image: inspected.get("imageName").and_then(text),
        }
    }
}

/// A container runtime: the machine is a container, and whatever is in
/// front of it was put there by someone else.
///
/// **It cannot provide [`Exposure::PublicHttp`].** `-p` publishes a port;
/// it does not terminate TLS and does not put a reverse proxy in front,
/// because those are infrastructure — and building infrastructure is the
/// line this tool does not cross. A profile that needs HTTPS from
/// outside is refused here by name rather than given plaintext, since
/// the difference between those two is a security property and not an
/// amount.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContainerAdapter;

impl Infra for ContainerAdapter {
    fn capability(&self) -> Capability {
        Capability {
            target: "container",
            exposures: &[Exposure::RawTcp],
        }
    }

    fn render(&self, required: &Requirements) -> Vec<String> {
        required
            .ports
            .iter()
            .flat_map(|it| {
                // `-p host:container`, same number on both sides: the
                // profile named the port the workload listens on, and
                // renumbering it would make the profile's own
                // `comfyui.health` (which polls that number) wrong.
                ["-p".to_string(), format!("{}:{}", it.port, it.port)]
            })
            .collect()
    }

    fn provider_namespace(&self) -> &'static str {
        "container"
    }

    /// A count it can pass on; a memory floor it cannot decide.
    ///
    /// `--gpus` takes a number or device ids — **there is no way to ask
    /// for a size**. Whether the host this lands on carries 24 GB per
    /// device is a property of the host, not of the runtime, so refusing
    /// here would turn away a machine that would have worked and
    /// approving would promise something never looked at.
    ///
    /// So it says it did not examine it, and the question is settled by
    /// observing the machine. That answer is the reason this enum has
    /// four arms instead of two.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        match required.min_vram_gb {
            None => Answer::met(),
            Some(floor) => Answer::not_examined(format!(
                "a container runtime cannot select on device memory, so \
                 {floor} GB per device is a property of the host this runs on"
            )),
        }
    }

    /// It can mount, but it cannot size.
    ///
    /// `-v` puts a volume at a path, so persistence itself is
    /// providable. How large that volume is comes from the host's
    /// filesystem, and the container's own writable layer is likewise
    /// the host's disk — `--storage-opt size=` exists but only on some
    /// storage drivers, so it is not something to promise.
    ///
    /// So a size is not examined and a path is met, which is the same
    /// answer split two ways rather than an awkward middle: the part
    /// that can be provided is, and the part that cannot be decided says
    /// so.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        let mut unsized_levels = Vec::new();
        if required.ephemeral_gb.is_some() {
            unsized_levels.push("the container's writable layer");
        }
        if required.persistent_gb.is_some() {
            unsized_levels.push("a mounted volume");
        }
        if unsized_levels.is_empty() {
            return match &required.persistent_at {
                Some(path) => Answer::met_using([format!("-v {path}")]),
                None => Answer::met(),
            };
        }
        Answer::not_examined(format!(
            "a container runtime cannot request a size for {}; how much there is \
             comes from the host's filesystem",
            unsized_levels.join(" or ")
        ))
    }

    /// Not wired, and said rather than faked.
    ///
    /// `docker run` would create the machine readily enough. Reaching it
    /// afterwards is the missing half: this crate's transports are SSH
    /// and same-host execution, and a container wants `docker exec` —
    /// which spec 08 names as an extension point precisely because it
    /// does not exist yet. An acquisition whose result nothing can be
    /// run against is not an acquisition.
    ///
    /// This adapter earns its place on the vocabulary, which is what it
    /// was added for: it is what proves the requirements are the
    /// workload's words rather than one service's. Execution is a
    /// separate claim, and it is not being made.
    fn acquisition(
        &self,
        _required: &Requirements,
        _provider: &BTreeMap<String, String>,
    ) -> Result<Acquisition, AcquisitionError> {
        Err(AcquisitionError::Unsupported {
            target: "container",
            reason: "no transport reaches a container yet (spec 08 names `docker exec` \
                     as an extension point; it is not implemented)",
        })
    }

    /// Nothing observed, because nothing was acquired.
    ///
    /// This adapter renders no acquisition, so it is never handed
    /// anything to read. An empty state is the honest answer: every
    /// requirement comes back unexamined rather than met.
    fn read_state(&self, _inspected: &serde_json::Value) -> MachineState {
        MachineState::default()
    }
}

/// A machine that exists because [`acquire`] made it.
///
/// Carries what it takes to give it back, so that a caller holding one
/// of these never has to reconstruct how — the release is not something
/// to work out after the fact.
#[derive(Debug, Clone)]
pub struct Acquired {
    /// The identifier the service gave it.
    pub id: String,
    /// What the service said about it when last inspected.
    pub inspected: serde_json::Value,
    /// How to inspect and destroy it, with `{id}` still in place.
    acquisition: Acquisition,
}

impl Acquired {
    /// Ask the service what this machine is now.
    pub fn inspect(&mut self) -> Result<&serde_json::Value, ExecuteError> {
        self.inspected = run_json(&substitute(&self.acquisition.inspect, &self.id), None)?;
        Ok(&self.inspected)
    }

    /// Destroy it.
    ///
    /// Takes `self`, so the handle is spent: a machine cannot be
    /// released twice, and one that was released cannot be inspected
    /// afterwards as though it were still there.
    pub fn release(self) -> Result<(), ExecuteError> {
        run(&substitute(&self.acquisition.release, &self.id), None).map(|_| ())
    }
}

/// Something went wrong obtaining or inspecting a machine.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// The command could not be started.
    #[error("could not run `{command}`: {source}")]
    Spawn {
        /// What was being run.
        command: String,
        /// Why it could not start.
        source: std::io::Error,
    },

    /// It ran and failed.
    #[error("`{command}` exited with status {status}: {stderr}")]
    Failed {
        /// What was run.
        command: String,
        /// How it exited.
        status: String,
        /// What it said about it.
        stderr: String,
    },

    /// It succeeded and said something unreadable.
    #[error("`{command}` returned no readable JSON: {detail}")]
    Unreadable {
        /// What was run.
        command: String,
        /// What could not be read.
        detail: String,
    },

    /// The created machine has no identifier, so nothing could release
    /// it.
    ///
    /// Reported rather than tolerated: a machine that exists and cannot
    /// be named is the shape of a bill nobody can stop.
    #[error("`{command}` created something without returning an id: {body}")]
    Anonymous {
        /// What was run.
        command: String,
        /// What came back instead.
        body: String,
    },
}

/// Create a machine from a rendered [`Acquisition`].
///
/// **This is the call that spends money.** It is a free function rather
/// than a method on [`Infra`] so that rendering an acquisition and
/// performing one are separate acts in the source as well as in the
/// design: a caller that only wants to show an operator what would
/// happen cannot reach this by accident.
pub fn acquire(acquisition: Acquisition) -> Result<Acquired, ExecuteError> {
    let created = run_json(&acquisition.create, acquisition.body.as_deref())?;
    let id = created
        .get("id")
        .and_then(|it| it.as_str())
        .ok_or_else(|| ExecuteError::Anonymous {
            command: acquisition.create.join(" "),
            body: created.to_string(),
        })?
        .to_string();
    Ok(Acquired {
        id,
        inspected: created,
        acquisition,
    })
}

/// `{id}` replaced throughout.
fn substitute(argv: &[String], id: &str) -> Vec<String> {
    argv.iter()
        .map(|it| it.replace("{id}", id))
        .collect::<Vec<_>>()
}

/// Run `argv`, optionally appending `body` as its last argument.
fn run(argv: &[String], body: Option<&str>) -> Result<String, ExecuteError> {
    let Some((program, rest)) = argv.split_first() else {
        return Err(ExecuteError::Unreadable {
            command: String::new(),
            detail: "no command to run".to_string(),
        });
    };
    let mut command = std::process::Command::new(program);
    command.args(rest);
    if let Some(body) = body {
        command.arg(body);
    }
    let rendered = argv.join(" ");
    let output = command.output().map_err(|source| ExecuteError::Spawn {
        command: rendered.clone(),
        source,
    })?;
    if !output.status.success() {
        return Err(ExecuteError::Failed {
            command: rendered,
            status: output
                .status
                .code()
                .map(|it| it.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// [`run`], reading the output as JSON.
fn run_json(argv: &[String], body: Option<&str>) -> Result<serde_json::Value, ExecuteError> {
    let stdout = run(argv, body)?;
    // The CLI prints its own progress before the payload, so the object
    // is found rather than assumed to start at byte zero.
    let start = stdout.find('{').unwrap_or(0);
    serde_json::from_str(&stdout[start..]).map_err(|err| ExecuteError::Unreadable {
        command: argv.join(" "),
        detail: err.to_string(),
    })
}

/// The `provider` keys addressed to somebody else.
///
/// **Not an error, and not silently fine.** A key namespaced for another
/// target is *unexamined* — the same distinction the `Assert` model
/// draws between "I looked and it was not so" and "I did not look". A
/// `runpod.networkVolumeId` may be where the weights were meant to live,
/// so a container run that ignores it is not equivalent to one that was
/// never given it.
///
/// Callers report what this returns. Falling back is allowed; falling
/// back *quietly* is what `net.transfer.route` exists to prevent, and the
/// rule is the same here.
pub fn unexamined<'a>(
    adapter: &dyn Infra,
    provider: &'a BTreeMap<String, String>,
) -> Vec<&'a String> {
    let mine = adapter.provider_namespace();
    provider
        .keys()
        .filter(|key| key.split('.').next() != Some(mine))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(pairs: &[(&str, &str)]) -> Requirements {
        let slot: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Requirements::from_slot(&slot).expect("well-formed fixture")
    }

    /// **The check the second adapter exists for.** One declaration, two
    /// targets, two spellings — and if only one of them could be
    /// produced from it, the vocabulary would be that target's rather
    /// than neutral.
    #[test]
    fn one_declaration_renders_on_both_targets() {
        let required = required(&[("8188", "public_http"), ("22", "raw_tcp")]);
        assert_eq!(
            RunPodAdapter.render(&required),
            vec!["22/tcp".to_string(), "8188/http".to_string()]
        );
        assert_eq!(
            ContainerAdapter.render(&required.clone()),
            vec![
                "-p".to_string(),
                "22:22".to_string(),
                "-p".to_string(),
                "8188:8188".to_string()
            ]
        );
    }

    /// The exposure decides the protocol, so SSH does not end up behind
    /// an HTTPS proxy. A bare port number could not carry this.
    #[test]
    fn the_exposure_and_not_the_port_number_picks_the_protocol() {
        assert_eq!(
            RunPodAdapter.render(&required(&[("22", "raw_tcp")])),
            vec!["22/tcp".to_string()]
        );
        assert_eq!(
            RunPodAdapter.render(&required(&[("22", "public_http")])),
            vec!["22/http".to_string()],
            "the number carries no meaning of its own here"
        );
    }

    /// A container runtime publishes a port; it does not terminate TLS.
    /// Saying so is what makes the refusal real.
    #[test]
    fn a_container_cannot_offer_https_from_outside() {
        let capability = ContainerAdapter.capability();
        assert!(!capability.exposures.contains(&Exposure::PublicHttp));
        let refusal =
            lm_provision::machine::admit(&required(&[("8188", "public_http")]), &capability)
                .expect_err("a container cannot terminate TLS");
        let rendered = refusal.to_string();
        assert!(rendered.contains("container"), "{rendered}");
        assert!(rendered.contains("8188"), "{rendered}");
    }

    #[test]
    fn a_managed_pod_service_offers_both() {
        assert!(lm_provision::machine::admit(
            &required(&[("8188", "public_http"), ("22", "raw_tcp")]),
            &RunPodAdapter.capability(),
        )
        .is_ok());
    }

    /// **What stage 2 is for.** The same requirement gets three
    /// different *kinds* of answer, and none of them is a lie:
    /// the managed service can choose, so it chooses and says what; the
    /// container runtime has no way to ask, so it says it did not look.
    ///
    /// A two-valued answer would have to call one of those a refusal,
    /// which would turn away a host that carries the memory perfectly
    /// well.
    #[test]
    fn a_memory_floor_is_selected_on_one_target_and_unexamined_on_the_other() {
        let required = GpuRequirement {
            count: 1,
            min_vram_gb: Some(40),
        };

        match RunPodAdapter.gpu_answer(&required) {
            Answer::Met { using } => {
                assert!(
                    using.iter().all(|it| it.contains("A40")
                        || it.contains("L40S")
                        || it.contains("A6000")
                        || it.contains("A100")
                        || it.contains("H100")),
                    "everything chosen clears 40 GB: {using:?}"
                );
                assert!(
                    !using
                        .iter()
                        .any(|it| it.contains("L4\"") || it == "NVIDIA L4"),
                    "a 24 GB device does not clear a 40 GB floor: {using:?}"
                );
            }
            other => panic!("the catalogue carries 40 GB devices: {other:?}"),
        }

        let container = ContainerAdapter.gpu_answer(&required);
        assert!(
            matches!(container, Answer::NotExamined { .. }),
            "a container runtime cannot select on memory: {container:?}"
        );
        assert!(
            !container.blocks(),
            "not examining something is not a refusal — the host may well carry it"
        );
    }

    /// The floor is a floor: the cheapest thing that clears it comes
    /// first, and the rest are what the service can fall back to when it
    /// is short of the first.
    #[test]
    fn the_selection_starts_at_the_smallest_device_that_clears_the_floor() {
        let answer = RunPodAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(24),
        });
        let Answer::Met { using } = answer else {
            panic!("24 GB is well inside the catalogue: {answer:?}");
        };
        assert_eq!(
            using.first().map(String::as_str),
            Some("NVIDIA GeForce RTX 4090"),
            "24 GB devices sort ahead of 48 GB ones: {using:?}"
        );
    }

    /// A floor nothing carries is refused, and the refusal says both how
    /// far off it is and how to say what the catalogue cannot.
    #[test]
    fn a_floor_beyond_the_catalogue_is_refused_with_a_way_out() {
        let answer = RunPodAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(512),
        });
        let Answer::Unmet { reason } = &answer else {
            panic!("no catalogued device carries 512 GB: {answer:?}");
        };
        assert!(reason.contains("512"), "{reason}");
        assert!(
            reason.contains("provider.runpod.gpuTypeIds"),
            "the refusal points at the slot that can name what the catalogue cannot: {reason}"
        );
        assert!(answer.blocks());
    }

    /// No floor is nothing to choose between, on either target.
    #[test]
    fn a_count_without_a_floor_needs_no_selection() {
        let required = GpuRequirement {
            count: 2,
            min_vram_gb: None,
        };
        assert_eq!(RunPodAdapter.gpu_answer(&required), Answer::met());
        assert_eq!(ContainerAdapter.gpu_answer(&required), Answer::met());
    }

    /// The two storage levels are the supplier's own distinction —
    /// wiped on restart against persisted across one — and the managed
    /// service takes a size for each plus where the second is mounted.
    #[test]
    fn a_managed_service_sizes_both_storage_levels() {
        let answer = RunPodAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: Some(100),
            persistent_gb: Some(50),
            persistent_at: Some("/workspace".into()),
        });
        let Answer::Met { using } = answer else {
            panic!("a managed service sizes both: {answer:?}");
        };
        assert!(
            using.iter().any(|it| it == "containerDiskInGb=100"),
            "{using:?}"
        );
        assert!(using.iter().any(|it| it == "volumeInGb=50"), "{using:?}");
        assert!(
            using.iter().any(|it| it == "volumeMountPath=/workspace"),
            "{using:?}"
        );
    }

    /// **The same split as the accelerator floor, one level down.** A
    /// container runtime can put a volume at a path but cannot say how
    /// large it is — that comes from the host's filesystem. Refusing
    /// would turn away a host with plenty of room.
    #[test]
    fn a_container_mounts_but_does_not_size() {
        let sized = ContainerAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: None,
            persistent_gb: Some(50),
            persistent_at: Some("/workspace".into()),
        });
        assert!(
            matches!(sized, Answer::NotExamined { .. }),
            "a size is the host's business: {sized:?}"
        );
        assert!(!sized.blocks(), "not knowing is not refusing");

        let unsized_request = ContainerAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: None,
            persistent_gb: None,
            persistent_at: Some("/workspace".into()),
        });
        assert_eq!(
            unsized_request,
            Answer::met_using(["-v /workspace".to_string()]),
            "a path with no size is something it can simply do"
        );
    }

    fn full_requirements() -> Requirements {
        Requirements::from_slots(
            &[("8188", "public_http"), ("22", "raw_tcp")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("count", "1"), ("min_vram_gb", "40")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[
                ("ephemeral_gb", "100"),
                ("persistent_gb", "150"),
                ("persistent_at", "/workspace"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            Some("runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04"),
        )
        .expect("well-formed fixture")
    }

    /// The whole vocabulary becomes one request, and every part of it is
    /// traceable back to a line the profile wrote.
    #[test]
    fn the_requirements_become_the_services_own_request() {
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &BTreeMap::new())
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().expect("create takes a body"))
                .expect("the body is JSON");

        assert_eq!(body["ports"], serde_json::json!(["22/tcp", "8188/http"]));
        assert_eq!(body["computeType"], "GPU");
        assert_eq!(body["gpuCount"], 1);
        assert_eq!(body["containerDiskInGb"], 100);
        assert_eq!(body["volumeInGb"], 150);
        assert_eq!(body["volumeMountPath"], "/workspace");
        assert!(
            body["gpuTypeIds"]
                .as_array()
                .expect("a floor selects models")
                .iter()
                .all(|it| it != "NVIDIA L4"),
            "a 24 GB device does not clear a 40 GB floor: {}",
            body["gpuTypeIds"]
        );
    }

    /// **Every field this emits exists in the service's schema, with the
    /// right type, and every model named is in its enumeration**
    /// [実測: 2026-08-12, checked against the OpenAPI description the
    /// service's own CLI is generated from].
    ///
    /// Pinned here rather than left to a live call, because a live call
    /// costs a machine to find out and this does not. The list is what
    /// the check verified; a field added to the request without being
    /// added here has not been checked against anything.
    #[test]
    fn every_field_emitted_is_one_the_service_defines() {
        const CHECKED: &[&str] = &[
            "computeType",
            "containerDiskInGb",
            "gpuCount",
            "gpuTypeIds",
            "imageName",
            "ports",
            "volumeInGb",
            "volumeMountPath",
        ];
        let provider: BTreeMap<String, String> = [("runpod.networkVolumeId", "vol-1")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &provider)
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        let emitted: Vec<&String> = body
            .as_object()
            .expect("the body is an object")
            .keys()
            .collect();

        for key in emitted {
            assert!(
                CHECKED.contains(&key.as_str()) || key == "networkVolumeId",
                "{key} is emitted but was never checked against the service's schema"
            );
        }
    }

    /// A profile's provider keys go in verbatim and last, so a network
    /// volume named there replaces the size above it the way the service
    /// documents.
    #[test]
    fn provider_keys_land_in_the_request_unchanged() {
        let provider: BTreeMap<String, String> = [
            ("runpod.networkVolumeId", "vol-1"),
            ("container.network", "bridge"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &provider)
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();

        assert_eq!(body["networkVolumeId"], "vol-1");
        assert!(
            body.get("container.network").is_none() && body.get("network").is_none(),
            "another target's key is not this target's: {body}"
        );
    }

    /// A machine cannot be created without knowing what to run on it,
    /// and that is said before anything is spent finding out.
    #[test]
    fn creating_without_an_image_is_refused() {
        let no_image =
            Requirements::from_slots(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new(), None)
                .unwrap();
        assert_eq!(
            RunPodAdapter.acquisition(&no_image, &BTreeMap::new()),
            Err(AcquisitionError::Incomplete {
                target: "runpod",
                missing: "requires_image"
            })
        );
    }

    /// **Every acquisition carries its release.** One worked out later
    /// is one that leaks, and this repo has leaked two machines by hand
    /// for exactly that reason.
    #[test]
    fn an_acquisition_says_how_to_give_the_machine_back() {
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &BTreeMap::new())
            .unwrap();
        assert!(acquisition.release.contains(&"delete-pod".to_string()));
        assert!(acquisition.release.contains(&"{id}".to_string()));
        assert!(acquisition.inspect.contains(&"get-pod".to_string()));
    }

    /// Not wired is said, not faked. A `docker run` would create a
    /// machine that no transport here can reach.
    #[test]
    fn a_container_says_it_cannot_acquire_rather_than_pretending() {
        let err = ContainerAdapter
            .acquisition(&full_requirements(), &BTreeMap::new())
            .expect_err("no transport reaches a container");
        let rendered = err.to_string();
        assert!(rendered.contains("docker exec"), "{rendered}");
    }

    /// The shape the service returns for a pod, with the fields this
    /// reads and the identifying ones neutralised.
    ///
    /// Taken from real responses rather than invented [実測: 2026-08-11,
    /// four pods created and destroyed while measuring transfers].
    fn inspected_pod() -> serde_json::Value {
        serde_json::json!({
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
            "gpuCount": 1,
            "containerDiskInGb": 100,
            "volumeInGb": 150,
            "volumeMountPath": "/workspace",
            "ports": ["8188/http", "22/tcp"],
            "portMappings": { "22": 22016 },
            "publicIp": "203.0.113.10",
            "machine": {
                "gpuTypeId": "NVIDIA A40",
                "dataCenterId": "EU-SE-1"
            }
        })
    }

    /// **The loop closes.** What the requirements asked for, the request
    /// carried, and the machine came back as — read with the same
    /// vocabulary at both ends.
    #[test]
    fn a_pod_description_reads_back_into_a_judgeable_state() {
        let state = RunPodAdapter.read_state(&inspected_pod());
        assert!(state.ports_observed);
        assert_eq!(state.exposed.get(&8188), Some(&Exposure::PublicHttp));
        assert_eq!(state.exposed.get(&22), Some(&Exposure::RawTcp));
        assert_eq!(state.gpu_count, Some(1));
        assert_eq!(state.ephemeral_gb, Some(100));
        assert_eq!(state.persistent_gb, Some(150));
        assert_eq!(state.persistent_at.as_deref(), Some("/workspace"));

        let findings = lm_provision::machine::observe(&full_requirements(), &state);
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Satisfied,
            "{findings:#?}"
        );
    }

    /// Memory is the one field that is looked up rather than read: the
    /// description names the model and never the size, which is the same
    /// asymmetry that put the catalogue in this adapter.
    #[test]
    fn device_memory_comes_from_the_catalogue_and_absence_is_not_zero() {
        let known = RunPodAdapter.read_state(&inspected_pod());
        assert_eq!(known.gpu_vram_gb, Some(48), "an A40 carries 48 GB");

        let mut unknown_model = inspected_pod();
        unknown_model["machine"]["gpuTypeId"] = serde_json::json!("NVIDIA SOMETHING NEW");
        assert_eq!(
            RunPodAdapter.read_state(&unknown_model).gpu_vram_gb,
            None,
            "a model outside the catalogue leaves the size unobserved, not zero"
        );
    }

    /// A description with no ports field is one nobody looked at; a
    /// description with an empty one exposed nothing. Those are
    /// different answers.
    #[test]
    fn an_absent_ports_field_is_not_an_empty_one() {
        let mut without = inspected_pod();
        without.as_object_mut().unwrap().remove("ports");
        assert!(!RunPodAdapter.read_state(&without).ports_observed);

        let mut empty = inspected_pod();
        empty["ports"] = serde_json::json!([]);
        let state = RunPodAdapter.read_state(&empty);
        assert!(state.ports_observed);
        assert!(state.exposed.is_empty());
    }

    /// A machine that came back without what was asked for is caught by
    /// looking, not by the run failing later somewhere else.
    #[test]
    fn a_machine_missing_a_port_is_unsatisfied() {
        let mut missing = inspected_pod();
        missing["ports"] = serde_json::json!(["22/tcp"]);
        let findings = lm_provision::machine::observe(
            &full_requirements(),
            &RunPodAdapter.read_state(&missing),
        );
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Unsatisfied,
            "{findings:#?}"
        );
    }

    /// Keys for another target are reported, not dropped in silence: the
    /// one being ignored may be where the weights live.
    #[test]
    fn keys_for_another_target_are_reported() {
        let provider: BTreeMap<String, String> = [
            ("runpod.networkVolumeId", "vol-1"),
            ("container.network", "bridge"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        assert_eq!(
            unexamined(&ContainerAdapter, &provider),
            vec!["runpod.networkVolumeId"]
        );
        assert_eq!(
            unexamined(&RunPodAdapter, &provider),
            vec!["container.network"]
        );
    }
}
