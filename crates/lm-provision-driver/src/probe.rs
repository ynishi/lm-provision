//! One token, now: ask each endpoint for a one-token completion and
//! report what came back (09 §Endpoint inventory, `probe`). The one
//! question that finds an exhausted account (402) or a dead key (401)
//! before a run spends a build on finding it. **It spends money** —
//! a few input tokens and one output token per endpoint — which is why
//! it runs only when asked for.

/// What one token got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// 2xx with a completion.
    Ok,
    /// 401 / 403.
    Unauthorized,
    /// 402.
    PaymentRequired,
    /// 404 — the URL or the model.
    NotFound,
    /// Any other HTTP status.
    Failed,
    /// No HTTP answer: the host did not resolve, refused, or timed out.
    Unreachable,
    /// The row names a key variable that is not set — nothing was sent.
    NoKey,
}

/// One endpoint's answer to one token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Probe {
    /// What came back, by class.
    pub state: State,
    /// The HTTP status, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<u16>,
    /// The platform's own words when it refused: `error.message`,
    /// `detail` (a string, or an object's `error` / `message`), `message`,
    /// or the first 200 bytes of the body. Absent on `Ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub said: Option<String>,
    /// The platform's `usage` object, verbatim, on `Ok` — it is the one
    /// place a platform states what the request cost it (DeepInfra:
    /// `estimated_cost`, `prompt_tokens_details.cached_tokens`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<serde_json::Value>,
}

/// How long one probe waits for an answer, in seconds — the same bound
/// the other questions this crate asks over HTTP are given.
const TIMEOUT_SEC: &str = "20";

/// The request body sent, for `model`.
pub fn body(model: &str) -> String {
    serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 1,
    })
    .to_string()
}

/// Send one. `api_key_env` names the variable (curl imports it by name,
/// [`crate::infra::curl_bearer`]'s form with
/// `-X POST -H Content-Type: application/json --data <body>`, `-m 20`,
/// `-o <tmp file> -w %{http_code}`); `None` sends no `Authorization`
/// header (a tunnel to a pod's own server). A named variable that is
/// not set returns [`State::NoKey`] without sending.
pub fn probe(base_url: &str, model: &str, api_key_env: Option<&str>) -> Probe {
    if let Some(name) = api_key_env {
        if std::env::var_os(name).is_none() {
            // Nothing is sent: a request with no key is a 401 this host
            // already knows the answer to, and the row's own variable
            // name is the thing to say about it.
            return Probe {
                state: State::NoKey,
                http: None,
                said: Some(format!("{name} is not set")),
                usage: None,
            };
        }
    }

    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let mut argv = match api_key_env {
        Some(name) => crate::infra::curl_bearer(name, &url),
        // The same shape without the header: a tunnel to a pod's own
        // server takes no key, and sending an empty one would be a
        // refusal this host invented.
        None => vec![
            "curl".to_string(),
            "-sS".to_string(),
            "--fail-with-body".to_string(),
            url.clone(),
        ],
    };
    // The body is written to a file and the status to stdout, so what
    // the platform said and what it answered are read apart.
    let body_file = std::env::temp_dir().join(format!(
        "lm-provision-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|it| it.as_nanos())
            .unwrap_or_default()
    ));
    let request = body(model);
    let written_to = body_file.display().to_string();
    for argument in [
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "--data",
        request.as_str(),
        "-m",
        TIMEOUT_SEC,
        "-o",
        written_to.as_str(),
        "-w",
        "%{http_code}",
    ] {
        argv.push(argument.to_string());
    }

    let Some((program, rest)) = argv.split_first() else {
        return classify(None, b"no command to run");
    };
    let output = match std::process::Command::new(program).args(rest).output() {
        Ok(output) => output,
        Err(err) => return classify(None, format!("could not run curl: {err}").as_bytes()),
    };
    let http = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u16>()
        .ok()
        // `000` is curl's word for "no HTTP answer at all", which is
        // not a status a server sent.
        .filter(|code| *code != 0);
    let answered = std::fs::read(&body_file).unwrap_or_default();
    std::fs::remove_file(&body_file).ok();
    match http {
        Some(code) => classify(Some(code), &answered),
        None => classify(None, &output.stderr),
    }
}

/// Status + body → the answer. Pure; tested.
pub fn classify(http: Option<u16>, body: &[u8]) -> Probe {
    let Some(status) = http else {
        // No status: what curl has to say is the only account of why,
        // and it is the platform's stand-in here.
        return Probe {
            state: State::Unreachable,
            http: None,
            said: said_by(body),
            usage: None,
        };
    };
    let state = match status {
        200..=299 => State::Ok,
        401 | 403 => State::Unauthorized,
        402 => State::PaymentRequired,
        404 => State::NotFound,
        _ => State::Failed,
    };
    if state == State::Ok {
        return Probe {
            state,
            http: Some(status),
            said: None,
            usage: serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|document| document.get("usage").cloned()),
        };
    }
    Probe {
        state,
        http: Some(status),
        said: said_by(body),
        usage: None,
    }
}

/// What the platform said, in the places platforms say it: `error.message`,
/// `detail` (a string, or an object's `error` / `message`), `message` —
/// and, for a body that is not JSON at all, its first 200 bytes. `None`
/// only when there is nothing there to relay.
fn said_by(body: &[u8]) -> Option<String> {
    let text = |value: &serde_json::Value| value.as_str().map(str::to_string);
    if let Ok(document) = serde_json::from_slice::<serde_json::Value>(body) {
        let said = document
            .get("error")
            .and_then(|it| it.get("message"))
            .and_then(text)
            .or_else(|| {
                document.get("detail").and_then(|detail| {
                    text(detail).or_else(|| {
                        detail
                            .get("error")
                            .and_then(text)
                            .or_else(|| detail.get("message").and_then(text))
                    })
                })
            })
            .or_else(|| document.get("message").and_then(text));
        if let Some(said) = said {
            return Some(said);
        }
    }
    // A body this tool has no field for is still the platform's word
    // about the refusal; it is relayed as it came, bounded so a log
    // line cannot become a page.
    let bytes = &body[..body.len().min(200)];
    let said = String::from_utf8_lossy(bytes).trim().to_string();
    (!said.is_empty()).then_some(said)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The status says what happened and the platform says why.** The
    /// two refusals a probe exists to find — an exhausted account (402)
    /// and a dead key (401) — are distinct states rather than one
    /// "failed", because what an operator does about them is different;
    /// and on a good answer the `usage` object travels verbatim, since
    /// it is the one place a platform states what the request cost it.
    #[test]
    fn a_probe_is_classified_by_status_and_says_what_the_platform_said() {
        let answered = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "Hi" } }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 1,
                "total_tokens": 6,
                "estimated_cost": 6.3e-07,
                "prompt_tokens_details": { "cached_tokens": 0, "cache_write_tokens": null },
            },
        })
        .to_string();
        let probe = classify(Some(200), answered.as_bytes());
        assert_eq!(probe.state, State::Ok);
        assert_eq!(probe.http, Some(200));
        assert!(
            probe.said.is_none(),
            "nothing was refused: {:?}",
            probe.said
        );
        let usage = probe.usage.expect("the platform stated what it used");
        assert_eq!(usage["estimated_cost"], serde_json::json!(6.3e-07));
        assert_eq!(usage["prompt_tokens"], serde_json::json!(5));

        let probe = classify(Some(401), br#"{"detail":"Invalid token"}"#);
        assert_eq!(probe.state, State::Unauthorized);
        assert_eq!(probe.said.as_deref(), Some("Invalid token"));

        let probe = classify(
            Some(402),
            br#"{"detail":{"error":"You need positive balance"}}"#,
        );
        assert_eq!(probe.state, State::PaymentRequired);
        assert!(
            probe
                .said
                .as_deref()
                .is_some_and(|it| it.contains("positive balance")),
            "{:?}",
            probe.said
        );

        let probe = classify(
            Some(402),
            br#"{"error":{"message":"Insufficient credits","code":402}}"#,
        );
        assert_eq!(probe.state, State::PaymentRequired);
        assert_eq!(probe.said.as_deref(), Some("Insufficient credits"));

        let probe = classify(Some(404), b"not found");
        assert_eq!(probe.state, State::NotFound);
        assert_eq!(
            probe.said.as_deref(),
            Some("not found"),
            "a body that is not JSON is still what the platform said"
        );

        let probe = classify(None, b"curl: (7) Failed to connect");
        assert_eq!(probe.state, State::Unreachable);
        assert!(probe.http.is_none(), "there was no status to report");
        assert!(
            probe
                .said
                .as_deref()
                .is_some_and(|it| it.contains("Failed to connect")),
            "{:?}",
            probe.said
        );
    }

    /// **One token, and one only.** The body is the smallest request an
    /// OpenAI-compatible server answers, so what a probe costs is a few
    /// input tokens and one output token wherever it is sent.
    #[test]
    fn the_request_body_asks_for_one_token() {
        let document: serde_json::Value =
            serde_json::from_str(&body("m")).expect("the body is JSON");
        assert_eq!(document["max_tokens"], serde_json::json!(1));
        assert_eq!(document["model"], serde_json::json!("m"));
        assert_eq!(document["messages"][0]["role"], serde_json::json!("user"));
    }

    /// **A row whose key variable is not set is not sent.** The answer
    /// would be a 401 this host can already state, and sending it would
    /// spend a request to be told what the environment says — so
    /// nothing leaves, and the state says which.
    #[test]
    fn a_row_naming_an_unset_key_is_not_sent() {
        let probe = probe(
            "http://127.0.0.1:1/v1",
            "m",
            Some("LM_PROVISION_TEST_UNSET_KEY_XYZ"),
        );
        assert_eq!(probe.state, State::NoKey);
        assert!(probe.http.is_none());
        assert!(
            probe
                .said
                .as_deref()
                .is_some_and(|it| it.contains("LM_PROVISION_TEST_UNSET_KEY_XYZ")),
            "the variable that was not set is named: {:?}",
            probe.said
        );
    }
}
