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

use lm_provision::machine::{Capability, Exposure, Requirements};

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
}

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
