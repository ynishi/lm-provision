//! Whether the image a profile names actually exists where the machine
//! will pull it from — asked **before** the machine exists.
//!
//! The failure this closes was found live: a marketplace host accepts
//! the create call without looking at the image, then sits at
//! `loading` retrying `manifest unknown` forever — on billing — for a
//! tag that was never going to arrive [measured: 2026-08-30, instance
//! 49228600, `pytorch/pytorch:2.4.0`: the create succeeded, the host
//! logged `manifest for pytorch/pytorch:2.4.0 not found` once a minute,
//! and only the materializing cap bounded the bill]. The registry could
//! have said so in one round trip while nothing existed yet.
//!
//! ## What is asked, and of whom
//!
//! The registry's own manifest endpoint (`GET /v2/<name>/manifests/
//! <reference>`), through `curl` — the same judgment every provider
//! call in this crate makes: drive a CLI that already exists rather
//! than link a second HTTP client. The anonymous-pull token dance is
//! the one the Distribution spec defines: an unauthenticated request
//! answers 401 with a `WWW-Authenticate` challenge naming a realm, the
//! realm hands out a pull token without credentials for public images,
//! and the retry answers 200 or 404 [documented:
//! distribution.github.io/distribution/spec/api/ §API Version Check /
//! docs.docker.com/registry/spec/auth/token/].
//!
//! ## Three answers, deliberately
//!
//! `Absent` is the only refusal — a definitive 404 from the registry
//! that would serve the pull. Everything else that is not a 200 is
//! [`Manifest::Undetermined`]: a private registry this check has no
//! credential for, a network that did not answer, a missing `curl`.
//! **Undetermined must not refuse** — a machine this driver could have
//! acquired, refused over a question the operator never asked it to be
//! able to answer, would make the preflight cost more than the failure
//! it prevents. It is reported and stepped past.

use std::process::Command;

/// What the registry said about the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    /// The manifest is there; a host that pulls this will get it.
    Present,
    /// The registry that would serve the pull says the manifest does
    /// not exist — the pull can only ever retry into the same answer.
    Absent {
        /// The registry that answered.
        registry: String,
    },
    /// Nothing definitive: auth this check cannot do, a network that
    /// did not answer, no `curl` on the host. Never a refusal.
    Undetermined {
        /// Why no answer, for the note an operator reads.
        reason: String,
    },
}

/// One image reference, split the way the registry API wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageRef {
    /// Registry host (with port when given).
    registry: String,
    /// Repository path within it.
    repository: String,
    /// Tag or digest.
    reference: String,
}

/// Split `image` into registry / repository / reference, by docker's
/// own rules: the first segment is a registry only when it could not be
/// a repository name (a dot, a colon, or `localhost`); a bare Docker
/// Hub name gets the `library/` prefix; no tag means `latest`.
fn image_reference(image: &str) -> ImageRef {
    let (name, reference) = match image.split_once('@') {
        // A digest reference passes through whole — the manifests
        // endpoint takes either form.
        Some((name, digest)) => (name, digest.to_string()),
        None => {
            // The tag colon is the one after the last slash; a colon
            // before that is a registry port.
            let after_slash = image.rfind('/').map(|it| it + 1).unwrap_or(0);
            match image[after_slash..].split_once(':') {
                Some((repo_tail, tag)) => {
                    (&image[..after_slash + repo_tail.len()], tag.to_string())
                }
                None => (image, "latest".to_string()),
            }
        }
    };

    let (registry, repository) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first.to_string(), rest.to_string())
        }
        _ => {
            let repository = if name.contains('/') {
                name.to_string()
            } else {
                // Docker Hub's official images live under a namespace
                // the short name omits.
                format!("library/{name}")
            };
            ("registry-1.docker.io".to_string(), repository)
        }
    };
    ImageRef {
        registry,
        repository,
        reference,
    }
}

/// Ask the image's registry whether its manifest exists.
pub fn manifest_check(image: &str) -> Manifest {
    let image = image_reference(image);
    let url = format!(
        "https://{}/v2/{}/manifests/{}",
        image.registry, image.repository, image.reference
    );
    // Every manifest media type in circulation, so a registry serving
    // only OCI or only schema2 answers 200 rather than 404-by-format.
    let accept = "application/vnd.oci.image.index.v1+json, \
                  application/vnd.oci.image.manifest.v1+json, \
                  application/vnd.docker.distribution.manifest.list.v2+json, \
                  application/vnd.docker.distribution.manifest.v2+json";

    let first = match curl_head(&url, accept, None) {
        Ok(response) => response,
        Err(reason) => return Manifest::Undetermined { reason },
    };
    let response = match first.status {
        401 => {
            // The challenge names where anonymous pull tokens come
            // from; without one to parse there is nothing to retry
            // with.
            let Some(token_url) = token_url(&first.www_authenticate, &image.repository) else {
                return Manifest::Undetermined {
                    reason: format!("{} wants auth this check cannot do", image.registry),
                };
            };
            let Some(token) = fetch_token(&token_url) else {
                return Manifest::Undetermined {
                    reason: format!("{} did not hand out an anonymous token", image.registry),
                };
            };
            match curl_head(&url, accept, Some(&token)) {
                Ok(response) => response,
                Err(reason) => return Manifest::Undetermined { reason },
            }
        }
        _ => first,
    };

    match response.status {
        200 => Manifest::Present,
        404 => Manifest::Absent {
            registry: image.registry,
        },
        other => Manifest::Undetermined {
            reason: format!("{} answered {other}", image.registry),
        },
    }
}

/// Status line and the one header the auth dance reads.
struct HeadResponse {
    status: u16,
    www_authenticate: String,
}

/// `curl -sS -I` against `url`, capturing status and headers.
///
/// HEAD rather than GET: the question is existence, and no registry
/// needs to ship a manifest body to answer it.
fn curl_head(url: &str, accept: &str, token: Option<&str>) -> Result<HeadResponse, String> {
    let mut command = Command::new("curl");
    command.args(["-sS", "-I", "--max-time", "15", "-H"]);
    command.arg(format!("Accept: {accept}"));
    if let Some(token) = token {
        // An anonymous pull token — handed to anyone who asks, so its
        // appearance on an argv discloses nothing.
        command.arg("-H");
        command.arg(format!("Authorization: Bearer {token}"));
    }
    command.arg(url);
    let output = command
        .output()
        .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // With redirects and 100-continues a response can carry several
    // status lines; the last block is the answer.
    let status = text
        .lines()
        .filter(|it| it.starts_with("HTTP/"))
        .filter_map(|it| it.split_whitespace().nth(1))
        .filter_map(|it| it.parse::<u16>().ok())
        .next_back()
        .ok_or_else(|| format!("no status line from {url}"))?;
    let www_authenticate = text
        .lines()
        .find(|it| it.to_ascii_lowercase().starts_with("www-authenticate:"))
        .and_then(|it| it.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default();
    Ok(HeadResponse {
        status,
        www_authenticate,
    })
}

/// The token endpoint a `WWW-Authenticate: Bearer` challenge names,
/// with the pull scope for `repository` — `None` when the challenge is
/// not one this check can answer anonymously.
fn token_url(challenge: &str, repository: &str) -> Option<String> {
    let bearer = challenge.strip_prefix("Bearer ")?;
    let field = |name: &str| {
        bearer.split(',').find_map(|part| {
            let part = part.trim();
            part.strip_prefix(&format!("{name}=\""))?
                .strip_suffix('"')
                .map(str::to_string)
        })
    };
    let realm = field("realm")?;
    let mut url = format!("{realm}?scope=repository:{repository}:pull");
    if let Some(service) = field("service") {
        url.push_str(&format!("&service={service}"));
    }
    Some(url)
}

/// The anonymous pull token the realm hands out, or `None`.
fn fetch_token(url: &str) -> Option<String> {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|it| it.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Docker's own splitting rules, each on the form that motivates
    /// it.
    #[test]
    fn an_image_reference_splits_the_way_the_registry_wants_it() {
        assert_eq!(
            image_reference("pytorch/pytorch:2.4.0-cuda12.4-cudnn9-runtime"),
            ImageRef {
                registry: "registry-1.docker.io".into(),
                repository: "pytorch/pytorch".into(),
                reference: "2.4.0-cuda12.4-cudnn9-runtime".into(),
            }
        );
        assert_eq!(
            image_reference("ubuntu"),
            ImageRef {
                registry: "registry-1.docker.io".into(),
                repository: "library/ubuntu".into(),
                reference: "latest".into(),
            },
            "a bare official name lives under library/"
        );
        assert_eq!(
            image_reference("ghcr.io/owner/tool:v1"),
            ImageRef {
                registry: "ghcr.io".into(),
                repository: "owner/tool".into(),
                reference: "v1".into(),
            },
            "a dotted first segment is a registry"
        );
        assert_eq!(
            image_reference("localhost:5000/thing"),
            ImageRef {
                registry: "localhost:5000".into(),
                repository: "thing".into(),
                reference: "latest".into(),
            },
            "a registry port is not a tag"
        );
        assert_eq!(
            image_reference("repo/name@sha256:abcd").reference,
            "sha256:abcd",
            "a digest passes through whole"
        );
    }

    /// The challenge parser reads the one shape the token spec defines,
    /// and declines the ones it does not.
    #[test]
    fn a_bearer_challenge_yields_a_token_url_and_basic_does_not() {
        let url = token_url(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#,
            "library/ubuntu",
        )
        .expect("the spec's own example shape");
        assert!(url.starts_with("https://auth.docker.io/token?"), "{url}");
        assert!(url.contains("scope=repository:library/ubuntu:pull"), "{url}");
        assert!(url.contains("service=registry.docker.io"), "{url}");

        assert_eq!(
            token_url(r#"Basic realm="private""#, "x"),
            None,
            "auth this check cannot do is not a refusal path"
        );
    }
}
