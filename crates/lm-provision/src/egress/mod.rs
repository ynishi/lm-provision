//! sh.exec egress pin — route every subprocess's network egress through a
//! declared host allowlist (issue 45930cb0, spec 05 §L3).
//!
//! `sh.exec` puts a subprocess's writes and connects structurally out of the
//! op layer's reach (spec 05): `git clone`, `pip install`, the `hf` / `b2`
//! CLIs reach the network without passing an op handler, so the profile's
//! `http_allowlist` — which gates only bridge ops — never sees them. This
//! module closes the **exfiltration** half of that gap (credential-bearing
//! transfers, uploads, arbitrary `sh`) by pinning subprocess egress to a
//! declared host allowlist. The supply-chain-hijack half (a poisoned package
//! from a *permitted* registry) is not an egress problem and is out of scope.
//!
//! Three responsibilities, deliberately separated:
//!
//! - **declaration** — the profile's `sh_egress` host list (host-independent).
//! - **supply** — who runs the proxy: this crate self-hosts one in-process by
//!   default ([`EgressSupply::SelfHosted`]), or a deployment points at an
//!   external egress gateway ([`EgressSupply::External`]). A deployment
//!   concern, resolved from the host environment, never from the profile.
//! - **enforcement** — the [`proxy`] soft layer (route via `HTTPS_PROXY` +
//!   host/SNI allowlist). A hard layer (seccomp `connect` pin) is a later
//!   slice; enforcement is always the pod-local best effort, and the profile
//!   states intent, never which mechanism took effect.

use std::collections::BTreeMap;

use crate::profile_ast::ProfileNode;

#[cfg(target_os = "linux")]
pub mod hardpin;
pub mod host_match;
pub mod policy;
pub mod proxy;
pub mod sni;

pub use policy::EgressPolicy;
pub use proxy::Proxy;

/// The egress pin a profile root declares, or `None` when it declares none.
///
/// Reads `Spec.sh_egress`: a non-empty list is an opt-in pin (build a policy);
/// an empty list — which is also how an absent field decodes — is "no pin", so
/// existing profiles run unrouted and unchanged. A non-`Spec` root declares
/// nothing.
pub fn policy_from_root(root: &ProfileNode) -> Option<EgressPolicy> {
    match root {
        ProfileNode::Spec { sh_egress, .. } if !sh_egress.is_empty() => {
            Some(EgressPolicy::new(sh_egress.iter().cloned()))
        }
        _ => None,
    }
}

/// Host environment variable naming an external egress proxy. When set, the
/// deployment supplies the proxy (a VPC / gateway) and this crate does not
/// start its own; the external proxy owns the allowlist. Unset means
/// self-host.
pub const EXTERNAL_PROXY_ENV: &str = "LM_EGRESS_PROXY";

/// Where the egress proxy comes from, once resolved for a run.
pub enum EgressSupply {
    /// This crate ran a proxy in-process; hold it for the run's lifetime.
    SelfHosted(Proxy),
    /// A deployment-supplied proxy at this URL; nothing to hold.
    External(String),
}

impl EgressSupply {
    /// The proxy URL to inject into subprocess env.
    pub fn url(&self) -> String {
        match self {
            EgressSupply::SelfHosted(p) => p.url(),
            EgressSupply::External(url) => url.clone(),
        }
    }

    /// The proxy endpoint the seccomp hard pin should admit, or `None`
    /// when the hard pin does not apply.
    ///
    /// Only a self-hosted proxy carries an address the pin can key on: it
    /// binds a loopback listener, and pinning subprocess egress to *that
    /// endpoint* (plus configured DNS resolvers, [`hardpin`]) forces every
    /// subprocess through it. An external gateway is off-host and owns its
    /// own enforcement, so the hard pin stays off there — `None`.
    ///
    /// [`hardpin`]: crate::egress::hardpin
    pub fn hard_pin_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            EgressSupply::SelfHosted(proxy) => Some(proxy.addr()),
            EgressSupply::External(_) => None,
        }
    }
}

/// Resolve and start egress enforcement for a declared `sh_egress` policy.
///
/// `None` when the profile declares no egress pin (`sh_egress` absent) — the
/// caller then injects nothing and subprocesses run as before (opt-in, so
/// existing profiles are unchanged). When a pin **is** declared:
///
/// - `LM_EGRESS_PROXY` set → [`EgressSupply::External`] with that URL (the
///   declared allowlist is the external gateway's to enforce; the local
///   `policy` is not consulted).
/// - unset → bind and serve an in-process proxy over `policy`.
///
/// Must run on a tokio runtime (apply provides one).
pub async fn start(policy: Option<EgressPolicy>) -> std::io::Result<Option<EgressSupply>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    if let Ok(url) = std::env::var(EXTERNAL_PROXY_ENV) {
        if !url.is_empty() {
            return Ok(Some(EgressSupply::External(url)));
        }
    }
    let proxy = proxy::serve(policy).await?;
    Ok(Some(EgressSupply::SelfHosted(proxy)))
}

/// The env-var overlay that routes a subprocess through `proxy_url`.
///
/// Both upper- and lower-case forms are set because tooling is split on which
/// it reads (curl reads lower-case, many libraries read either). `NO_PROXY`
/// keeps loopback direct so a subprocess touching the pod's own readiness port
/// does not bounce through the proxy. Merged **onto** a phase's resolved env,
/// so a profile that sets its own proxy var still wins (its value overwrites
/// these when the caller merges in order).
pub fn proxy_env(proxy_url: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.insert(key.to_string(), proxy_url.to_string());
    }
    for key in ["NO_PROXY", "no_proxy"] {
        env.insert(key.to_string(), "127.0.0.1,localhost,::1".to_string());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_policy_starts_nothing() {
        assert!(start(None).await.unwrap().is_none());
    }

    #[test]
    fn proxy_env_sets_both_cases_and_keeps_loopback_direct() {
        let env = proxy_env("http://127.0.0.1:4000");
        assert_eq!(env["HTTPS_PROXY"], "http://127.0.0.1:4000");
        assert_eq!(env["https_proxy"], "http://127.0.0.1:4000");
        assert!(env["NO_PROXY"].contains("127.0.0.1"));
    }
}
