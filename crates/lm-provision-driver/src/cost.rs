//! The cost of a run, from what it used and what the record says a
//! token cost where it ran (09 §Cost). A reading: nothing is written.

use std::path::Path;

use lm_provision_protocol::price::{self, Usage};

use crate::{balance, credentials};

/// The shapes a `usage` document arrives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UsageFormat {
    /// `lm_provision_protocol::price::Usage` as written.
    Plain,
    /// OpenAI Chat Completions / Responses `usage`: `prompt_tokens` (or
    /// `input_tokens`) **includes** cached tokens
    /// [documented: developers.openai.com/api/docs/guides/prompt-caching].
    Openai,
    /// DeepSeek `usage`: `prompt_cache_hit_tokens` + `prompt_cache_miss_tokens`
    /// [documented: api-docs.deepseek.com, the usage object].
    Deepseek,
    /// Anthropic Messages `usage`: `input_tokens` is uncached only
    /// [documented: platform.claude.com/docs/en/build-with-claude/prompt-caching].
    Anthropic,
}

/// The value at a dotted path (`prompt_tokens_details.cached_tokens`),
/// when the document carries one that is not `null` — a platform that
/// writes the key with nothing in it has said nothing, which is what an
/// absent key says.
fn at<'a>(document: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut here = document;
    for key in path.split('.') {
        here = here.get(key)?;
    }
    (!here.is_null()).then_some(here)
}

/// The count at `path`: `None` when the document does not carry it,
/// `Some(Err)` when it carries something that is not a token count.
///
/// The two are kept apart because they are different statements: a
/// `usage` with no `cached_tokens` did not say how much was cached, and
/// a `cached_tokens` of `-1` said something this reader must refuse
/// rather than read as a zero.
fn count(document: &serde_json::Value, path: &str) -> Option<Result<u64, String>> {
    let value = at(document, path)?;
    Some(value.as_u64().ok_or_else(|| {
        format!("`{path}` is `{value}`, which is not a token count at or above zero")
    }))
}

/// The first of `paths` the document carries, refused by every name it
/// was looked for under when it carries none.
fn required(document: &serde_json::Value, paths: &[&str]) -> Result<u64, String> {
    for path in paths {
        if let Some(found) = count(document, path) {
            return found;
        }
    }
    Err(format!("the usage carries no {}", paths.join(" or ")))
}

/// The first of `paths` the document carries, with the name it was
/// found under — the name a refusal has to quote, since a usage
/// document may spell the same count either way.
fn optional<'p>(
    document: &serde_json::Value,
    paths: &[&'p str],
) -> Result<Option<(&'p str, u64)>, String> {
    for path in paths {
        if let Some(found) = count(document, path) {
            return found.map(|count| Some((*path, count)));
        }
    }
    Ok(None)
}

/// Take `part` out of `whole`, refusing a part larger than the total it
/// is counted inside — the one arithmetic here that a platform's
/// document could make impossible, and a subtraction this reader must
/// not do on a guess.
fn inside(whole: u64, part: Option<(&str, u64)>) -> Result<(u64, Option<u64>), String> {
    match part {
        Some((path, part)) if part > whole => Err(format!(
            "`{path}` is {part}, more than the {whole} tokens it is counted inside"
        )),
        Some((_, part)) => Ok((whole - part, Some(part))),
        None => Ok((whole, None)),
    }
}

/// The output half every OpenAI-shaped document states the same way:
/// the completion total, less the reasoning tokens counted inside it.
fn openai_output(document: &serde_json::Value) -> Result<(u64, Option<u64>), String> {
    let completion = required(document, &["completion_tokens", "output_tokens"])?;
    let reasoning = optional(
        document,
        &[
            "completion_tokens_details.reasoning_tokens",
            "output_tokens_details.reasoning_tokens",
        ],
    )?;
    inside(completion, reasoning)
}

/// Translate one `usage` document into the five buckets. Refuses (by
/// field name) a required count that is absent or not a non-negative
/// integer, and a cached count larger than the total it is inside.
pub fn usage_from(format: UsageFormat, document: &serde_json::Value) -> Result<Usage, String> {
    match format {
        UsageFormat::Plain => {
            serde_json::from_value::<Usage>(document.clone()).map_err(|err| err.to_string())
        }
        UsageFormat::Openai => {
            // `prompt_tokens` counts the cached tokens too, so the
            // uncached input is what is left after they are taken out —
            // the one translation that stops a cache hit being paid for
            // twice (protocol `price::Usage`).
            let total = required(document, &["prompt_tokens", "input_tokens"])?;
            let cached = optional(
                document,
                &[
                    "prompt_tokens_details.cached_tokens",
                    "input_tokens_details.cached_tokens",
                ],
            )?;
            let (input, cache_read) = inside(total, cached)?;
            let (output, reasoning) = openai_output(document)?;
            Ok(Usage {
                input,
                output,
                cache_read,
                cache_write: None,
                reasoning,
            })
        }
        UsageFormat::Deepseek => {
            // DeepSeek states the split itself: the miss is the uncached
            // input and the hit is the cache read, so nothing is
            // subtracted. A document with only `prompt_tokens` is the
            // older shape, which said nothing about a cache.
            let hit = optional(document, &["prompt_cache_hit_tokens"])?;
            let miss = optional(document, &["prompt_cache_miss_tokens"])?;
            let (input, cache_read) = match (hit, miss) {
                (Some((_, hit)), Some((_, miss))) => (miss, Some(hit)),
                _ => (required(document, &["prompt_tokens"])?, None),
            };
            let (output, reasoning) = openai_output(document)?;
            Ok(Usage {
                input,
                output,
                cache_read,
                cache_write: None,
                reasoning,
            })
        }
        UsageFormat::Anthropic => Ok(Usage {
            input: required(document, &["input_tokens"])?,
            output: required(document, &["output_tokens"])?,
            cache_read: optional(document, &["cache_read_input_tokens"])?.map(|(_, it)| it),
            cache_write: optional(document, &["cache_creation_input_tokens"])?.map(|(_, it)| it),
            reasoning: None,
        }),
    }
}

/// The priced answer, the one artifact `machine cost` prints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Costed {
    /// The platform the row priced.
    pub provider: String,
    /// The model, as that platform names it.
    pub model: String,
    /// The record row that priced it: when it was read and from where.
    pub price_as_of: String,
    /// Where the amounts came from — the URL a sync read, or `operator`.
    pub price_source: String,
    /// The usage as charged (translated into the five buckets).
    pub usage: Usage,
    /// Whether the usage said how much of its input was cached; `false`
    /// makes [`Cost::amount`] an upper bound.
    pub cache_known: bool,
    /// What it comes to.
    pub cost: Cost,
}

/// Named after the attributes OTel's GenAI conventions are converging
/// on (`gen_ai.usage.cost.amount` / `.currency` / `.source`, PR #443,
/// not yet standard) so a consumer that adopts them maps 1:1.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Cost {
    /// USD, decimal text (`price::format_usd`).
    pub amount: String,
    /// Always `USD`.
    pub currency: String,
    /// `estimate` — computed from a published rate ([`cost`]) — or
    /// `platform`: read from the platform's own bill ([`billed`]), the
    /// authority an estimate is not.
    pub source: String,
}

/// Price `usage` on (`provider`, `model`) from the record at `path`,
/// at `at` (an RFC 3339 `Z` instant; `None` = the newest row).
/// `Err` names what is missing: no row for that pair at that instant
/// ("no price row for `deepinfra` `x` at or before 2026-…" / "…in the
/// record"), or a record that cannot be read.
pub fn cost(
    path: &Path,
    provider: &str,
    model: &str,
    at: Option<&str>,
    usage: &Usage,
) -> Result<Costed, String> {
    let rows = price::list(path).map_err(|err| err.to_string())?;
    let row = price::latest(&rows, provider, model, at).ok_or_else(|| match at {
        Some(at) => format!("no price row for `{provider}` `{model}` at or before {at}"),
        None => format!("no price row for `{provider}` `{model}` in the record"),
    })?;
    // The check the record's own writer runs before a row reaches the
    // file, run again here: a row written by a hand that did not is the
    // one that would be read a million out (the unit) or sorted into
    // the wrong month (the `as_of`), and both are refused by name
    // rather than priced.
    row.check().map_err(|err| err.to_string())?;
    let charged = price::charge(usage, &row.price.micros().map_err(|err| err.to_string())?);
    Ok(Costed {
        provider: row.provider.clone(),
        model: row.model.clone(),
        price_as_of: row.as_of.clone(),
        price_source: row.source.clone(),
        usage: *usage,
        cache_known: charged.cache_known,
        cost: Cost {
            amount: price::format_usd(charged.micros),
            currency: "USD".to_string(),
            source: "estimate".to_string(),
        },
    })
}

// ---- The platform's own bill ----

/// What the platform itself says one period cost — its bill, not this
/// tool's estimate (09 §Cost). `cost.source` is `platform`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Billed {
    /// The platform whose bill this is.
    pub provider: String,
    /// `YYYY.MM`, as the platform names the period.
    pub period: String,
    /// One per (model, bucket) the platform listed, in its order, or
    /// only those of `model` when one was asked for.
    pub items: Vec<BilledItem>,
    /// The sum of `items`.
    pub cost: Cost,
    /// The URL it was read from.
    pub source: String,
}

/// One line of the bill: what a model cost in one of the platform's
/// own buckets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BilledItem {
    /// The model, as the platform names it — or, for an `uptime` line,
    /// the machine this tool acquired.
    pub model: String,
    /// The platform's own bucket word: `input_tokens` / `output_tokens` /
    /// `cached_tokens` / `uptime` / ….
    pub bucket: String,
    /// How many of them: tokens, or minutes for `uptime`.
    pub units: u64,
    /// USD per **million** units, decimal text — the price record's own
    /// unit for a token bucket (`1.3` here is `1.3` there), and exact
    /// where USD per unit is not: a per-token rate sits below the
    /// micro-dollar. DeepInfra states cents per unit; converted.
    pub rate_per_million_units: String,
    /// USD, decimal text (DeepInfra states cents; converted).
    pub amount: String,
}

/// Where DeepInfra states what a month cost: `?from=YYYY.MM` (the dot
/// is the platform's own separator — `2026-09` is refused "separator
/// should be .") and the account's key as a bearer.
pub const DEEPINFRA_USAGE: &str = "https://api.deepinfra.com/payment/usage";

/// Read `provider`'s bill for `period` (`YYYY.MM`), optionally only
/// `model`'s lines. `deepinfra` today; every other name is refused:
/// "`{p}` publishes no bill this tool reads (deepinfra)". The period
/// shape is checked before anything is sent (7 chars, `YYYY.MM`, digits
/// and one dot at index 4) and refused by name otherwise.
pub fn billed(provider: &str, period: &str, model: Option<&str>) -> Result<Billed, String> {
    // Before the key is looked for and before anything is sent: the
    // platform answers a period of another shape with a complaint about
    // its separator, and that is a question this tool should not have
    // asked rather than an answer to relay.
    if !is_period(period) {
        return Err(format!(
            "`{period}` is not a period this tool reads: a month is `YYYY.MM`"
        ));
    }
    match provider {
        "deepinfra" => {
            credentials::require("deepinfra", &[balance::DEEPINFRA_API_KEY])
                .map_err(|it| it.to_string())?;
            let document = balance::fetch_json(
                balance::DEEPINFRA_API_KEY,
                &format!("{DEEPINFRA_USAGE}?from={period}"),
                None,
            )?;
            deepinfra_billed(&document, period, model)
        }
        other => Err(format!(
            "`{other}` publishes no bill this tool reads (deepinfra)"
        )),
    }
}

/// `YYYY.MM`: seven characters, digits, and the platform's own dot at
/// index 4.
fn is_period(period: &str) -> bool {
    let bytes = period.as_bytes();
    bytes.len() == 7
        && bytes.iter().enumerate().all(|(index, byte)| {
            if index == 4 {
                *byte == b'.'
            } else {
                byte.is_ascii_digit()
            }
        })
}

/// The DeepInfra document → the bill. Pure; tested.
///
/// The month whose `period` is the one asked for is the only one read
/// (a document without it is refused, naming the period); every item
/// states `model.model_name`, `pricing_type`, `units`, `rate` and
/// `cost`, and one missing any of them is refused by that field rather
/// than counted as a zero.
///
/// **The amounts are cents.** The platform's `payment/usage` states
/// `total_cost` in cents [documented: docs.deepinfra.com], and a cent
/// is 10⁴ micro-dollars — the unit the price record holds — so each
/// amount is converted once, at the reader, and the answer is USD like
/// every other amount this tool prints.
///
/// **`total_cost` is not read.** It is null until the month is
/// invoiced, and a bill that said nothing for the current month would
/// be the one question this is for. The items are summed instead.
pub fn deepinfra_billed(
    document: &serde_json::Value,
    period: &str,
    model: Option<&str>,
) -> Result<Billed, String> {
    let months = document
        .get("months")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let month = months
        .iter()
        .find(|it| it.get("period").and_then(serde_json::Value::as_str) == Some(period))
        .ok_or_else(|| format!("{DEEPINFRA_USAGE} states no month `{period}`"))?;
    let entries = month
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut items: Vec<(u64, BilledItem)> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let missing = |field: &str| format!("item {index} of `{period}` states no {field}");
        let name = entry
            .pointer("/model/model_name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| missing("model.model_name"))?;
        let bucket = entry
            .get("pricing_type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| missing("pricing_type"))?;
        let units = entry
            .get("units")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| missing("units"))?;
        // cents per unit × 10⁴ is micro-dollars per unit; × 10⁶ more is
        // per million units, the resolution a per-token rate needs.
        let rate = entry
            .get("rate")
            .and_then(serde_json::Value::as_f64)
            .and_then(|cents| micro_usd(cents * 1_000_000.0))
            .ok_or_else(|| missing("rate"))?;
        let amount = entry
            .get("cost")
            .and_then(serde_json::Value::as_f64)
            .and_then(micro_usd)
            .ok_or_else(|| missing("cost"))?;
        items.push((
            amount,
            BilledItem {
                model: name.to_string(),
                bucket: bucket.to_string(),
                units,
                rate_per_million_units: price::format_usd(rate),
                amount: price::format_usd(amount),
            },
        ));
    }

    if let Some(model) = model {
        items.retain(|(_, item)| item.model == model);
    }
    let mut total: u64 = 0;
    for (amount, _) in &items {
        total = total.checked_add(*amount).ok_or_else(|| {
            format!("the items of `{period}` sum to more than micro-dollars hold")
        })?;
    }

    Ok(Billed {
        provider: "deepinfra".to_string(),
        period: period.to_string(),
        items: items.into_iter().map(|(_, item)| item).collect(),
        cost: Cost {
            amount: price::format_usd(total),
            currency: "USD".to_string(),
            source: "platform".to_string(),
        },
        source: DEEPINFRA_USAGE.to_string(),
    })
}

/// Cents as micro-dollars: a cent is 10⁴ of them, rounded to the
/// nearest. `None` for what no amount can be made of — not a finite
/// number, below zero, or larger than micro-dollars hold — so the
/// caller refuses it by the field it came from.
fn micro_usd(cents: f64) -> Option<u64> {
    if !cents.is_finite() || cents < 0.0 {
        return None;
    }
    let micros = (cents * 10_000.0).round();
    (micros < u64::MAX as f64).then_some(micros as u64)
}

/// The (provider, model) of the inventory row called `name`, read
/// from the same sources `machine endpoints` reads (network: an
/// acquisition is asked about through its platform).
///
/// Refuses a name no row carries, a row that names no provider or no
/// model — the join a price is made on has to stand on both — and,
/// when the inventory could not be fully read and the name was not
/// found, says so with what could not be read: a row that is missing
/// because its source failed is not a row that does not exist.
pub fn endpoint_named(
    sources: &crate::inventory::EndpointSources<'_>,
    name: &str,
) -> Result<(String, String), String> {
    let inventory = crate::inventory::endpoints(sources);
    let Some(row) = inventory.rows.iter().find(|row| row.name == name) else {
        let mut refusal = format!("no endpoint named `{name}` in the inventory");
        if !inventory.complete() {
            let unread = inventory
                .failed
                .iter()
                .map(|(what, reason)| format!("{what}: {reason}"))
                .collect::<Vec<_>>()
                .join("; ");
            refusal.push_str(&format!(", which could not be fully read ({unread})"));
        }
        return Err(refusal);
    };
    let (Some(provider), Some(model)) = (row.provider.as_deref(), row.model.as_deref()) else {
        return Err(format!(
            "endpoint `{name}` names no provider/model to price by"
        ));
    };
    Ok((provider.to_string(), model.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lm_provision_protocol::price::{Price, PriceRow, UNIT_USD_PER_MTOK};
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-driver-cost-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    /// **The cache hit is taken out of the prompt total.** OpenAI counts
    /// it inside `prompt_tokens`, so a reader that did not subtract
    /// would charge those tokens once at the input rate and again at
    /// the cache rate.
    #[test]
    fn an_openai_usage_is_split_into_uncached_input_and_cache_read() {
        let document = serde_json::json!({
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "prompt_tokens_details": { "cached_tokens": 60 },
            "completion_tokens_details": { "reasoning_tokens": 4 }
        });
        assert_eq!(
            usage_from(UsageFormat::Openai, &document).expect("an OpenAI usage"),
            Usage {
                input: 40,
                output: 6,
                cache_read: Some(60),
                cache_write: None,
                reasoning: Some(4),
            }
        );

        let plain = serde_json::json!({ "prompt_tokens": 100, "completion_tokens": 10 });
        assert_eq!(
            usage_from(UsageFormat::Openai, &plain).expect("a usage with no details objects"),
            Usage {
                input: 100,
                output: 10,
                cache_read: None,
                cache_write: None,
                reasoning: None,
            },
            "no details object said nothing about a cache, which is not a cache of nothing"
        );

        let impossible = serde_json::json!({
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "prompt_tokens_details": { "cached_tokens": 200 }
        });
        let refused = usage_from(UsageFormat::Openai, &impossible)
            .expect_err("more cached than prompted is not a usage this reader can split");
        assert!(refused.contains("cached_tokens"), "{refused}");
    }

    /// DeepSeek states the split itself, hit and miss, so the uncached
    /// input is read rather than computed.
    #[test]
    fn a_deepseek_usage_reads_hit_and_miss() {
        let document = serde_json::json!({
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "prompt_cache_hit_tokens": 75,
            "prompt_cache_miss_tokens": 25
        });
        assert_eq!(
            usage_from(UsageFormat::Deepseek, &document).expect("a DeepSeek usage"),
            Usage {
                input: 25,
                output: 10,
                cache_read: Some(75),
                cache_write: None,
                reasoning: None,
            }
        );
    }

    /// Anthropic's `input_tokens` is already the uncached input, which
    /// is why it is the convention the five buckets are written in.
    #[test]
    fn an_anthropic_usage_is_already_in_the_five_buckets() {
        let document = serde_json::json!({
            "input_tokens": 5,
            "output_tokens": 7,
            "cache_read_input_tokens": 90,
            "cache_creation_input_tokens": 3
        });
        assert_eq!(
            usage_from(UsageFormat::Anthropic, &document).expect("an Anthropic usage"),
            Usage {
                input: 5,
                output: 7,
                cache_read: Some(90),
                cache_write: Some(3),
                reasoning: None,
            }
        );

        let missing = serde_json::json!({ "input_tokens": 5 });
        let refused = usage_from(UsageFormat::Anthropic, &missing)
            .expect_err("a usage with no output count is not one this reader can price");
        assert!(refused.contains("output_tokens"), "{refused}");
    }

    /// **`--at` re-prices at the rate that was in force.** The newest
    /// row answers for now; an instant before it answers with the row
    /// that stated the amounts then, which is the only way a cost said
    /// about the past stays true after the platform moves its prices.
    #[test]
    fn a_cost_reads_the_record_row_at_the_instant_and_prices_the_usage() {
        let path = scratch("at-the-instant");
        let row = |input: &str, cache_read: Option<&str>, as_of: &str| PriceRow {
            provider: "deepinfra".to_string(),
            model: "m".to_string(),
            price: Price {
                input: input.to_string(),
                output: "2.6".to_string(),
                cache_read: cache_read.map(str::to_string),
                cache_write: None,
                reasoning: None,
            },
            unit: UNIT_USD_PER_MTOK.to_string(),
            as_of: as_of.to_string(),
            source: "https://deepinfra.com/pricing".to_string(),
        };
        price::append(&path, &row("2", Some("0.1"), "2026-09-01T00:00:00Z"))
            .expect("the older row");
        price::append(&path, &row("1.3", Some("0.1"), "2026-09-22T00:00:00Z"))
            .expect("the newer row");

        let usage = Usage {
            input: 1_000_000,
            output: 100_000,
            cache_read: Some(2_000_000),
            cache_write: None,
            reasoning: None,
        };

        let now = cost(&path, "deepinfra", "m", None, &usage).expect("the newest row prices it");
        assert_eq!(now.cost.amount, "1.76");
        assert_eq!(now.cost.currency, "USD");
        assert_eq!(
            now.cost.source, "estimate",
            "the platform's bill is the authority and this is not it"
        );
        assert_eq!(now.price_as_of, "2026-09-22T00:00:00Z");
        assert_eq!(now.price_source, "https://deepinfra.com/pricing");
        assert_eq!(now.provider, "deepinfra");
        assert_eq!(now.model, "m");
        assert_eq!(now.usage, usage);
        assert!(now.cache_known);

        let then = cost(
            &path,
            "deepinfra",
            "m",
            Some("2026-09-10T00:00:00Z"),
            &usage,
        )
        .expect("the row in force then prices it");
        assert_eq!(
            then.cost.amount, "2.46",
            "the older row's own amounts: input at 2, output at 2.6, cached input at 0.1"
        );
        assert_eq!(then.price_as_of, "2026-09-01T00:00:00Z");

        let refused = cost(&path, "x", "m", None, &usage)
            .expect_err("the record prices nothing on that platform");
        assert!(refused.contains('x') && refused.contains('m'), "{refused}");

        std::fs::remove_file(&path).ok();
    }

    /// The month the platform stated, in the shape it stated it
    /// [live read 2026-09-23, this host's key].
    fn a_month() -> serde_json::Value {
        let line = |model: &str, units: u64, rate: f64, cost: u64, bucket: &str| {
            serde_json::json!({
                "model": { "provider": "di", "model_name": model,
                           "task": "text-generation", "private": false },
                "units": units, "rate": rate, "cost": cost,
                "pricing_type": bucket,
            })
        };
        serde_json::json!({ "months": [{
            "period": "2026.09",
            "interval": { "fr": 1788246000000u64, "to": 1790837999999u64 },
            "items": [
                line("deepseek-ai/DeepSeek-V4-Pro", 2286051, 0.00013, 297, "input_tokens"),
                line("deepseek-ai/DeepSeek-V4-Pro", 175592, 0.00026, 46, "output_tokens"),
                line("deepseek-ai/DeepSeek-V4-Pro", 12126464, 1.00000004e-05, 121, "cached_tokens"),
                line("ynishi/lmp-exp-20260923T022040Z", 15, 0.06111111, 1, "uptime"),
            ],
            "total_cost": serde_json::Value::Null,
            "invoice_id": serde_json::Value::Null,
        }]})
    }

    /// **The bill is the month's own lines, summed from cents.** The
    /// platform states each (model, bucket) apart — tokens in three
    /// buckets, a machine's minutes in a fourth — in cents, and leaves
    /// `total_cost` null until the month is invoiced, so the sum is the
    /// items and not the field. A month the document does not carry is
    /// refused by the period asked for rather than answered with
    /// whatever month it did carry, and a line missing an amount is
    /// refused by that field rather than counted as nothing.
    #[test]
    fn a_deepinfra_bill_is_the_months_items_summed_from_cents() {
        let document = a_month();
        let bill = deepinfra_billed(&document, "2026.09", None).expect("the month is in there");
        assert_eq!(bill.items.len(), 4);
        assert_eq!(bill.items[0].bucket, "input_tokens");
        assert_eq!(bill.items[0].model, "deepseek-ai/DeepSeek-V4-Pro");
        assert_eq!(bill.items[0].units, 2286051);
        assert_eq!(
            bill.items[0].rate_per_million_units, "1.3",
            "0.00013 cents per token is 1.30 USD per million tokens — the record's own number"
        );
        assert_eq!(bill.items[0].amount, "2.97", "297 cents");
        assert_eq!(
            bill.cost.amount, "4.65",
            "297 + 46 + 121 + 1 cents, summed in micro-dollars"
        );
        assert_eq!(bill.cost.currency, "USD");
        assert_eq!(
            bill.cost.source, "platform",
            "the platform's own bill is the authority the estimate is not"
        );
        assert_eq!(bill.period, "2026.09");
        assert_eq!(bill.provider, "deepinfra");
        assert_eq!(bill.source, DEEPINFRA_USAGE);

        let one_model = deepinfra_billed(&document, "2026.09", Some("deepseek-ai/DeepSeek-V4-Pro"))
            .expect("the month is in there");
        assert_eq!(
            one_model.items.len(),
            3,
            "the machine's uptime is another model's line"
        );
        assert_eq!(one_model.cost.amount, "4.64");

        let refused = deepinfra_billed(&document, "2026.08", None)
            .expect_err("the document carries no such month");
        assert!(refused.contains("2026.08"), "{refused}");

        let mut silent = a_month();
        silent["months"][0]["items"][2]
            .as_object_mut()
            .expect("an item is an object")
            .remove("cost");
        let refused =
            deepinfra_billed(&silent, "2026.09", None).expect_err("that line states no amount");
        assert!(
            refused.contains("cost"),
            "the field that was missing is named: {refused}"
        );
    }

    /// **A period of the wrong shape is not sent.** The platform names
    /// a month `YYYY.MM` and answers anything else with a complaint
    /// about its separator; the shape is checked here, before the key
    /// is looked for and before anything is sent. A platform that
    /// publishes no bill this tool reads is refused by its own name,
    /// whether it is one this tool spends through or one nobody serves.
    #[test]
    fn a_bill_period_is_the_platforms_own_shape_and_others_are_refused_by_name() {
        let refused =
            billed("deepinfra", "2026-09", None).expect_err("a dash is not the separator");
        assert!(refused.contains("YYYY.MM"), "{refused}");

        let refused = billed("together", "2026.09", None)
            .expect_err("the platform publishes no bill this tool reads");
        assert!(refused.contains("together"), "{refused}");

        let refused = billed("nope", "2026.09", None).expect_err("nor does a name nobody serves");
        assert!(refused.contains("nope"), "{refused}");
    }

    /// **An endpoint prices by the row's own words.** A run that
    /// reached an endpoint by the name the profile or the operator gave
    /// it is priced without re-typing where it ran — the row names the
    /// platform and the model, and those are the two words the price
    /// record joins on. A row that names neither gives the join nothing
    /// to stand on, and a name no row carries is refused by that name.
    #[test]
    fn an_endpoint_is_priced_by_the_provider_and_model_its_row_names() {
        let dir = scratch("endpoint-named");
        std::fs::create_dir_all(&dir).expect("the scratch directory is writable");
        let statics = dir.join("endpoints.json");
        std::fs::write(
            &statics,
            r#"[{"name": "flash", "provider": "deepinfra",
                 "model": "deepseek-ai/DeepSeek-V4-Flash", "base_url": "u"},
                {"name": "bare", "base_url": "u"}]"#,
        )
        .expect("the static file is writable");
        // Absent: no machine is asked about through its platform, and
        // no record prices anything — the lookup is the rows' own
        // words and nothing else.
        let absent = dir.join("absent.jsonl");
        let sources = crate::inventory::EndpointSources {
            acquisitions: &absent,
            forwards: &absent,
            statics: Some(&statics),
            prices: &absent,
        };

        assert_eq!(
            endpoint_named(&sources, "flash"),
            Ok((
                "deepinfra".to_string(),
                "deepseek-ai/DeepSeek-V4-Flash".to_string()
            ))
        );

        let refused =
            endpoint_named(&sources, "bare").expect_err("that row names nothing to price by");
        assert!(refused.contains("no provider"), "{refused}");

        let refused = endpoint_named(&sources, "nope").expect_err("no row carries that name");
        assert!(refused.contains("nope"), "{refused}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
