//! The cost of a run, from what it used and what the record says a
//! token cost where it ran (09 §Cost). A reading: nothing is written.

use std::path::Path;

use lm_provision_protocol::price::{self, Usage};

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
    /// Always `estimate`: computed from a published rate, not read
    /// from the platform's bill.
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
}
