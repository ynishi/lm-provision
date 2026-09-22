//! What a platform this tool spends from says is left on the account
//! (09 §Endpoint inventory, `balance`). Three of the four say — RunPod,
//! Vast, DeepInfra — each in its own shape and sign; Together does not,
//! and for it the account is read only by being refused with a 402,
//! which is what [`crate::probe`] is for. A platform this tool has no
//! adapter for is not asked: there is no account of this tool's there.

use crate::credentials;

/// What one platform says is left.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Balance {
    /// Funds ready to spend, decimal text in `currency`; negative when
    /// the platform says money is owed (DeepInfra's sign already
    /// flipped to this convention).
    pub amount: String,
    /// `USD` — every platform here bills in it.
    pub currency: String,
    /// What the account is spending per hour now, when the platform
    /// states it (RunPod `currentSpendPerHr`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_per_hour: Option<String>,
    /// Whether the platform has stopped serving the account, when it
    /// says (DeepInfra `suspended`) …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended: Option<bool>,
    /// … and why, in its own word (`balance` / `payment-method` / …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspend_reason: Option<String>,
    /// RFC 3339 UTC: when it was read.
    pub as_of: String,
    /// The URL it was read from.
    pub source: String,
}

/// The one endpoint RunPod answers account questions on [measured:
/// 2026-09-22, `{"data":{"myself":{"clientBalance":1.0080424408,
/// "currentSpendPerHr":0,"spendLimit":80}}}`].
pub const RUNPOD_GRAPHQL: &str = "https://api.runpod.io/graphql";
/// The variable RunPod's key is read from, by name.
pub const RUNPOD_API_KEY: &str = "RUNPOD_API_KEY";
/// The one query, asking only for what a normal key may read.
///
/// `clientLifetimeSpend` is **not** asked for: a normal key is refused
/// it, and the refusal comes back as an `errors` array beside a `data`
/// document — one field too many turns every answer into a refusal
/// [measured: 2026-09-22].
pub const RUNPOD_QUERY: &str =
    r#"{"query":"query { myself { clientBalance currentSpendPerHr spendLimit } }"}"#;
/// Where Vast states the account, in ~60 keys of which one is money.
pub const VAST_USER: &str = "https://console.vast.ai/api/v0/users/current/";
/// The variable Vast's key is read from, by name.
pub const VAST_API_KEY: &str = "VASTAI_API_KEY";
/// Where DeepInfra states the account — `?checklist=true` is what puts
/// the amounts in the document at all.
pub const DEEPINFRA_ME: &str = "https://api.deepinfra.com/v1/me?checklist=true";
/// The variable DeepInfra's key is read from, by name. The same account
/// and the same key serve `deepinfra-deploy`.
pub const DEEPINFRA_API_KEY: &str = "DEEPINFRA_API_KEY";

/// How long one question waits for an answer, in seconds — the bound
/// the other questions this crate asks over HTTP are given.
const TIMEOUT_SEC: &str = "20";

/// The currency every platform here bills in.
const USD: &str = "USD";

/// Ask `provider` what is left.
///
/// `Ok(None)` for `together` (publishes none [documented:
/// docs.together.ai — its API reference has `billing/usage` and
/// `whoami` only]) and for any name this tool has no adapter for: there
/// is no account of this tool's there, so there is nothing to ask and
/// nothing to report. `Err` only for a platform that **was** asked and
/// could not answer — a missing key, a request that failed, a document
/// one of the readers refuses.
///
/// `now` is RFC 3339 UTC `Z` form ([`crate::prices::now_utc`]) and
/// becomes the answer's `as_of`.
pub fn read(provider: &str, now: &str) -> Result<Option<Balance>, String> {
    match provider {
        "runpod" => {
            credentials::require("runpod", &[RUNPOD_API_KEY]).map_err(|it| it.to_string())?;
            asked(
                RUNPOD_API_KEY,
                RUNPOD_GRAPHQL,
                Some(RUNPOD_QUERY),
                runpod_balance,
                now,
            )
            .map(Some)
        }
        "vast" => {
            credentials::require("vast", &[VAST_API_KEY]).map_err(|it| it.to_string())?;
            asked(VAST_API_KEY, VAST_USER, None, vast_balance, now).map(Some)
        }
        // One account behind both names: the deploy target spends the
        // same key's money as the serverless one.
        "deepinfra" | "deepinfra-deploy" => {
            credentials::require("deepinfra", &[DEEPINFRA_API_KEY]).map_err(|it| it.to_string())?;
            asked(
                DEEPINFRA_API_KEY,
                DEEPINFRA_ME,
                None,
                deepinfra_balance,
                now,
            )
            .map(Some)
        }
        // Together, and every name that is not a platform this tool
        // spends through: absent is "there is nothing here to ask",
        // which is not a failure to have asked.
        _ => Ok(None),
    }
}

/// `data.myself.clientBalance` → `amount`, `currentSpendPerHr` →
/// `spend_per_hour`.
///
/// A document carrying `errors[0].message` and no numeric
/// `clientBalance` is the platform refusing the question, and its own
/// message is what comes back; otherwise a missing number is refused by
/// field name, since "no balance" and "a balance of nothing" are
/// different statements.
pub fn runpod_balance(document: &serde_json::Value, now: &str) -> Result<Balance, String> {
    let myself = document.pointer("/data/myself");
    let stated = |field: &str| {
        myself
            .and_then(|it| it.get(field))
            .and_then(serde_json::Value::as_f64)
            .and_then(usd_text)
    };
    let Some(amount) = stated("clientBalance") else {
        if let Some(message) = document
            .pointer("/errors/0/message")
            .and_then(serde_json::Value::as_str)
        {
            return Err(format!("{RUNPOD_GRAPHQL} refused the question: {message}"));
        }
        return Err(format!(
            "{RUNPOD_GRAPHQL} did not state data.myself.clientBalance as a number"
        ));
    };
    Ok(Balance {
        amount,
        currency: USD.to_string(),
        spend_per_hour: stated("currentSpendPerHr"),
        suspended: None,
        suspend_reason: None,
        as_of: now.to_string(),
        source: RUNPOD_GRAPHQL.to_string(),
    })
}

/// `credit` → `amount`.
///
/// **Not `balance`.** The document carries both, and `credit` is the
/// prepaid amount the platform's own CLI prints as money [documented:
/// `vast-cli` `user_fields`: `("credit","Credit","{:0.2f}")`]. A
/// document without a numeric `credit` is refused by name.
pub fn vast_balance(document: &serde_json::Value, now: &str) -> Result<Balance, String> {
    let Some(amount) = document
        .get("credit")
        .and_then(serde_json::Value::as_f64)
        .and_then(usd_text)
    else {
        return Err(format!("{VAST_USER} did not state credit as a number"));
    };
    Ok(Balance {
        amount,
        currency: USD.to_string(),
        spend_per_hour: None,
        suspended: None,
        suspend_reason: None,
        as_of: now.to_string(),
        source: VAST_USER.to_string(),
    })
}

/// `checklist.stripe_balance` negated → `amount`;
/// `checklist.suspended` / `checklist.suspend_reason` relayed.
///
/// The sign is the platform's: "Negative value indicates funds
/// ready-to-spend. Positive value indicates money owed" [documented:
/// docs.deepinfra.com/api-reference/billing/get-checklist], flipped
/// here so positive is funds on every platform.
///
/// **It reads those three fields and no other.** The same document
/// carries the account's billing address and card digits
/// (`billing_address_info`, `payment_method_info`); nothing here copies
/// a field it was not sent for, and a refusal names the field it wanted
/// rather than quoting what it got.
pub fn deepinfra_balance(document: &serde_json::Value, now: &str) -> Result<Balance, String> {
    let checklist = document.get("checklist");
    let stated = |field: &str| checklist.and_then(|it| it.get(field));
    let Some(amount) = stated("stripe_balance")
        .and_then(serde_json::Value::as_f64)
        .map(|owed| -owed)
        .and_then(usd_text)
    else {
        return Err(format!(
            "{DEEPINFRA_ME} did not state checklist.stripe_balance as a number"
        ));
    };
    Ok(Balance {
        amount,
        currency: USD.to_string(),
        spend_per_hour: None,
        suspended: stated("suspended").and_then(serde_json::Value::as_bool),
        suspend_reason: stated("suspend_reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        as_of: now.to_string(),
        source: DEEPINFRA_ME.to_string(),
    })
}

/// A signed USD float as decimal text with at most six places.
///
/// [`lm_provision_protocol::price::format_usd`] over the rounded
/// magnitude in micro-dollars, `-` prefixed when the amount is
/// negative — the same money-as-integers shape the price record holds,
/// so an amount printed here and an amount printed there read alike.
/// `None` when the platform stated something no amount can be made of:
/// not a finite number, or larger than micro-dollars hold.
fn usd_text(amount: f64) -> Option<String> {
    if !amount.is_finite() {
        return None;
    }
    let micros = (amount.abs() * 1e6).round();
    if micros >= u64::MAX as f64 {
        return None;
    }
    let text = lm_provision_protocol::price::format_usd(micros as u64);
    // Nothing owed and nothing left are the same amount, and `-0` is
    // not how anyone writes it.
    Some(if amount < 0.0 && micros > 0.0 {
        format!("-{text}")
    } else {
        text
    })
}

/// One curl, and the document it answered with.
///
/// The key reaches curl **by name only** ([`crate::infra::curl_bearer`]
/// imports the variable inside curl), `-m 20` bounds the wait, and a
/// body — which carries no key — makes it a `POST` with a JSON content
/// type. JSON on stdout goes to `document_says`.
///
/// Anything else is an `Err` built from curl's status and **its stderr
/// only**: the body of a refusal is never relayed, because on one of
/// these platforms the document the key opens carries the account's
/// billing address and card digits.
fn asked(
    key_var: &str,
    url: &str,
    body: Option<&str>,
    document_says: fn(&serde_json::Value, &str) -> Result<Balance, String>,
    now: &str,
) -> Result<Balance, String> {
    let mut argv = crate::infra::curl_bearer(key_var, url);
    for argument in ["-m", TIMEOUT_SEC] {
        argv.push(argument.to_string());
    }
    if let Some(body) = body {
        for argument in [
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data",
            body,
        ] {
            argv.push(argument.to_string());
        }
    }
    let Some((program, rest)) = argv.split_first() else {
        return Err("no command to run".to_string());
    };
    let output = std::process::Command::new(program)
        .args(rest)
        .output()
        .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not read {url} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("{url} did not answer with JSON: {err}"))?;
    document_says(&document, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instant these readings are stamped with, in the shape the
    /// rest of this crate writes instants in.
    const NOW: &str = "2026-09-22T00:00:00Z";

    /// **RunPod states the account and the rate it is draining at.**
    /// Both are worth having beside an endpoint: what is left answers
    /// "can this run start", and what is being spent per hour answers
    /// "for how long". A refusal is relayed in the platform's own
    /// words — it is the only account of why the question failed —
    /// and a document with neither a number nor a refusal is refused
    /// by the field that was missing.
    #[test]
    fn a_runpod_balance_is_the_account_and_its_spend_rate() {
        let document = serde_json::json!({
            "data": { "myself": {
                "clientBalance": 1.0080424408,
                "currentSpendPerHr": 0,
                "spendLimit": 80,
            } },
        });
        let balance = runpod_balance(&document, NOW).expect("the platform stated one");
        assert_eq!(balance.amount, "1.008042");
        assert_eq!(balance.spend_per_hour.as_deref(), Some("0"));
        assert_eq!(balance.currency, "USD");
        assert_eq!(balance.as_of, NOW);
        assert_eq!(balance.source, RUNPOD_GRAPHQL);

        let refused = serde_json::json!({
            "errors": [{ "message": "Unauthorized" }],
            "data": { "myself": serde_json::Value::Null },
        });
        let err = runpod_balance(&refused, NOW).expect_err("the platform refused");
        assert!(err.contains("Unauthorized"), "{err}");

        let silent = serde_json::json!({ "data": { "myself": {} } });
        let err = runpod_balance(&silent, NOW).expect_err("there is no amount there");
        assert!(
            err.contains("clientBalance"),
            "the field that was missing is named: {err}"
        );
    }

    /// **The money is `credit`, not `balance`.** The document states
    /// both, and the one the platform's own CLI prints as money is
    /// `credit`; reading the other would report an account of nothing
    /// on an account with ten dollars in it.
    #[test]
    fn a_vast_balance_is_the_credit_its_cli_prints_as_money() {
        let document = serde_json::json!({ "credit": 9.97897533467, "balance": 0 });
        let balance = vast_balance(&document, NOW).expect("the platform stated one");
        assert_eq!(balance.amount, "9.978975");
        assert_eq!(balance.currency, "USD");
        assert_eq!(balance.source, VAST_USER);

        let err = vast_balance(&serde_json::json!({ "balance": 0 }), NOW)
            .expect_err("`balance` is not the answer");
        assert!(err.contains("credit"), "{err}");
    }

    /// **The sign is flipped, and nothing else is taken.** DeepInfra
    /// documents a negative `stripe_balance` as funds ready to spend
    /// and a positive one as money owed; every other platform here says
    /// it the other way round, so the flip happens once, at the reader,
    /// and `amount` means the same thing on every row. The document
    /// this key opens also carries the billing address and the card —
    /// so the reader takes three named fields, and neither an answer
    /// nor a refusal can carry the rest.
    #[test]
    fn a_deepinfra_balance_flips_the_sign_and_reads_nothing_else() {
        let funded = serde_json::json!({ "checklist": {
            "stripe_balance": -10.0,
            "suspended": false,
            "suspend_reason": serde_json::Value::Null,
            "billing_address_info": { "line1": "SECRET" },
        } });
        let balance = deepinfra_balance(&funded, NOW).expect("the platform stated one");
        assert_eq!(balance.amount, "10", "negative is funds, stated as funds");
        assert_eq!(balance.suspended, Some(false));
        assert_eq!(balance.suspend_reason, None);
        let rendered = serde_json::to_string(&balance).expect("a balance renders");
        assert!(
            !rendered.contains("SECRET"),
            "the document's other fields are not in the answer: {rendered}"
        );

        let owing = serde_json::json!({ "checklist": {
            "stripe_balance": 3.5,
            "suspended": true,
            "suspend_reason": "balance",
        } });
        let balance = deepinfra_balance(&owing, NOW).expect("the platform stated one");
        assert_eq!(balance.amount, "-3.5", "money owed is a negative balance");
        assert_eq!(balance.suspended, Some(true));
        assert_eq!(balance.suspend_reason.as_deref(), Some("balance"));

        let silent = serde_json::json!({ "checklist": {
            "billing_address_info": { "line1": "SECRET" },
        } });
        let err = deepinfra_balance(&silent, NOW).expect_err("there is no amount there");
        assert!(err.contains("stripe_balance"), "{err}");
        assert!(
            !err.contains("SECRET"),
            "a refusal names the field it wanted and quotes nothing: {err}"
        );
    }

    /// **A platform with nothing to say is not a platform that could
    /// not be asked.** Together publishes no balance, and a name this
    /// tool has no adapter for has no account of this tool's behind it;
    /// both answer `Ok(None)` before anything is sent, so their rows
    /// are left as they were rather than landing in `failed`.
    #[test]
    fn a_platform_that_does_not_say_leaves_its_rows_as_they_were() {
        assert_eq!(
            read("together", NOW),
            Ok(None),
            "the platform publishes none"
        );
        assert_eq!(
            read("acme", NOW),
            Ok(None),
            "a static row's own provider is not an account of this tool's"
        );
        assert_eq!(read("nope", NOW), Ok(None), "nor is a name nobody serves");
    }

    /// **Money is printed as money, not as a float.** The magnitude is
    /// rounded to micro-dollars — the unit the price record holds — and
    /// printed as the shortest exact decimal, so an amount reads the
    /// same wherever this tool states one. What is not a number at all
    /// is no amount, and says so by being absent.
    #[test]
    fn usd_text_prints_a_signed_amount_with_at_most_six_places() {
        assert_eq!(usd_text(1.0080424408).as_deref(), Some("1.008042"));
        assert_eq!(usd_text(-10.0).as_deref(), Some("-10"));
        assert_eq!(usd_text(0.0).as_deref(), Some("0"));
        assert_eq!(usd_text(f64::NAN), None);
    }
}
