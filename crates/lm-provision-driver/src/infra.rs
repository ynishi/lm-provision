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

use lm_provision::machine::{Answer, Capability, Exposure, GpuRequirement, Requirements};

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
