//! The price record's writer: ask a platform what its models cost and
//! append what changed (09 §Price record). One platform for now; the
//! function per platform is the adapter knowledge, the loop around it
//! is shared.

use std::path::Path;

use lm_provision_protocol::price::{self, format_usd, Price, PriceRow, UNIT_USD_PER_MTOK};

/// Where DeepInfra publishes every model's price, with no key
/// [documented: docs.deepinfra.com/api-reference/models/models-list;
/// read 2026-09-22: 379 rows, `pricing.type == "tokens"` rows carry
/// `cents_per_input_token` / `cents_per_output_token` as US cents per
/// one token and `rate_per_input_token_cached` as a ratio of the input rate].
pub const DEEPINFRA_MODELS: &str = "https://api.deepinfra.com/models/list";

/// What a sync found: the rows the platform states now, and the rows
/// it stated in a shape this tool does not read, each with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// One row per token-priced model, `as_of` = the instant passed in.
    pub rows: Vec<PriceRow>,
    /// `(model_name or "<entry N>", reason)` for every entry not read
    /// as a token price — the `time`-priced models, an amount that is
    /// not a finite non-negative number, an entry with no name.
    pub skipped: Vec<(String, String)>,
}

/// What a sync appended, for the artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Synced {
    /// The platform that was asked.
    pub provider: String,
    /// Where it was asked — the URL the amounts came from, the same
    /// word every appended row carries as its `source`.
    pub source: String,
    /// The instant the rows were stamped with.
    pub as_of: String,
    /// Rows the platform stated.
    pub read: usize,
    /// Rows appended because the record's newest row for that model
    /// stated different amounts (or none).
    pub appended: usize,
    /// Rows not appended because the newest row already states them.
    pub unchanged: usize,
    /// What the platform stated in a shape this tool does not read.
    pub skipped: Vec<Skipped>,
}

/// One entry a sync did not read as a token price.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Skipped {
    /// The model, as the platform named it, or `<entry N>` when the
    /// entry carried no name to report it under.
    pub model: String,
    /// Why it was not read.
    pub reason: String,
}

/// The instant a sync stamps its rows with, in the one shape
/// [`lm_provision_protocol::price::PriceRow::check`] accepts:
/// `YYYY-MM-DDTHH:MM:SSZ`.
///
/// **Not `Timestamp::now().to_string()`.** That prints the sub-second
/// digits the clock gave it (`2026-09-22T06:30:00.123456789Z`), and a
/// row carrying them is refused by the record's own writer before it
/// reaches the file. Both callers — the CLI's `machine prices sync`
/// and the MCP `lm_price_sync` — take the instant from here, so the
/// shape the record accepts is written in one place rather than in
/// each of them.
pub fn now_utc() -> String {
    jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Ask `provider` for its prices.
///
/// `runpod` / `vast` / `deepinfra-deploy` / `together` are refused by
/// name: they rent machines or serve endpoints this tool has no price
/// list for. An unknown name is refused as [`crate::infra::adapter_named`]
/// refuses it, so one spelling mistake gets one answer wherever it is
/// made. `now` is RFC 3339 UTC `Z` form ([`now_utc`]) and becomes every
/// row's `as_of`.
pub fn read(provider: &str, now: &str) -> Result<Read, String> {
    match provider {
        "deepinfra" => {}
        other => {
            // A name no adapter speaks for is that refusal, with every
            // platform this tool knows in it; a name that is a platform
            // but publishes no token price list is this one.
            let _ = crate::infra::adapter_named(other)?;
            return Err(format!("{other} publishes no token prices this tool reads"));
        }
    }

    // The shape `inventory::served_model_at` asks its question in: one
    // subprocess, `-f` so an HTTP error is a non-zero exit rather than
    // an error document parsed as prices, `-sS` so what curl has to say
    // is on stderr and comes back in the refusal.
    let output = std::process::Command::new("curl")
        .args(["-sS", "-f", "-m", "20", DEEPINFRA_MODELS])
        .output()
        .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not read {DEEPINFRA_MODELS} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("{DEEPINFRA_MODELS} did not answer with JSON: {err}"))?;
    Ok(deepinfra_rows(&document, now))
}

/// The DeepInfra document → rows. Pure; the fixture test runs this.
///
/// One row per entry whose `pricing.type` is `tokens`; everything else
/// is reported in [`Read::skipped`] by name rather than dropped, since
/// a model this tool silently did not price is indistinguishable from
/// a model the platform stopped serving.
///
/// **The amounts are the list price; the platform's `discount` field is
/// recorded nowhere until its meaning is confirmed.** The same goes for
/// `rate_per_service_tier_priority` / `_flex`: a row here states what
/// the pricing page states, and a multiplier applied on a guess would
/// be a number nobody could check against that page.
pub fn deepinfra_rows(document: &serde_json::Value, now: &str) -> Read {
    let mut rows = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let entries = document.as_array().map(Vec::as_slice).unwrap_or_default();

    for (index, entry) in entries.iter().enumerate() {
        let Some(name) = entry.get("model_name").and_then(|it| it.as_str()) else {
            skipped.push((format!("<entry {index}>"), "no model_name".to_string()));
            continue;
        };
        let Some(pricing) = entry.get("pricing") else {
            skipped.push((name.to_string(), "no pricing".to_string()));
            continue;
        };
        let Some(kind) = pricing.get("type").and_then(|it| it.as_str()) else {
            skipped.push((name.to_string(), "no pricing.type".to_string()));
            continue;
        };
        if kind != "tokens" {
            // The type's own word, so the report says what the platform
            // said rather than "not a token price".
            skipped.push((name.to_string(), format!("pricing.type is `{kind}`")));
            continue;
        }

        let amount = |key: &str| -> Result<u64, String> {
            let stated = pricing
                .get(key)
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| format!("{key} is not a number"))?;
            micros_from_cents_per_token(stated).ok_or_else(|| {
                format!("{key} is `{stated}`, which is not an amount at or above zero")
            })
        };
        let input = match amount("cents_per_input_token") {
            Ok(input) => input,
            Err(why) => {
                skipped.push((name.to_string(), why));
                continue;
            }
        };
        let output = match amount("cents_per_output_token") {
            Ok(output) => output,
            Err(why) => {
                skipped.push((name.to_string(), why));
                continue;
            }
        };

        // The cache rates are ratios of the input rate, not amounts:
        // absent (or `null`) is "not priced separately", which is the
        // key left out rather than a zero (09 §Price record: absent is
        // not zero).
        let of_input = |key: &str| -> Option<String> {
            let rate = pricing.get(key).and_then(serde_json::Value::as_f64)?;
            if !rate.is_finite() || rate < 0.0 {
                return None;
            }
            let micros = (input as f64 * rate).round();
            (micros < u64::MAX as f64).then(|| format_usd(micros as u64))
        };

        rows.push(PriceRow {
            provider: "deepinfra".to_string(),
            model: name.to_string(),
            price: Price {
                input: format_usd(input),
                output: format_usd(output),
                cache_read: of_input("rate_per_input_token_cached"),
                cache_write: of_input("rate_per_input_token_cache_write"),
                reasoning: None,
            },
            unit: UNIT_USD_PER_MTOK.to_string(),
            as_of: now.to_string(),
            source: DEEPINFRA_MODELS.to_string(),
        });
    }

    Read { rows, skipped }
}

/// US cents per one token → micro-dollars per million tokens, the
/// integer the record holds.
///
/// `cents × 10_000` is US dollars per million tokens (a cent is 10⁻²
/// USD, a million tokens is 10⁶ of them), and a micro-dollar is 10⁻⁶
/// USD, so the whole conversion is `cents × 10¹⁰`, rounded to the
/// nearest micro-dollar: `0.00013` cents/token is `1_300_000`, which
/// prints as `1.3` USD per million tokens.
///
/// `None` for an amount that is not a finite number at or above zero,
/// and for one too large to hold — a platform that states either is
/// stating something this reader would have to guess at.
fn micros_from_cents_per_token(cents: f64) -> Option<u64> {
    if !cents.is_finite() || cents < 0.0 {
        return None;
    }
    let micros = (cents * 1e10).round();
    (micros < u64::MAX as f64).then_some(micros as u64)
}

/// [`read`], then append to `path` every row whose amounts differ from
/// [`price::latest`] for its (provider, model) — a sync writes the
/// change log, not a snapshot.
///
/// Rows are appended in the platform's order. An append that fails
/// stops the sync with the error; what was appended before it stays
/// (the record is append-only and nothing is rolled back), so a second
/// sync after the disk is fixed appends the rest.
pub fn sync(provider: &str, path: &Path, now: &str) -> Result<Synced, String> {
    let found = read(provider, now)?;
    // The directory the record lives in is this side's business: the
    // first sync on a fresh host is exactly when `~/.lm-provision` does
    // not exist yet, and both callers (the CLI and the MCP tool) would
    // otherwise have to remember that separately.
    if let Some(parent) = path.parent().filter(|it| !it.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("could not make {}: {err}", parent.display()))?;
    }
    let mut synced = sync_rows(found.rows, path, provider)?;
    // A sync that read no row has none to take these from, and still
    // states what it asked and when.
    if synced.source.is_empty() {
        synced.source = source_of(provider).to_string();
    }
    if synced.as_of.is_empty() {
        synced.as_of = now.to_string();
    }
    synced.skipped = found
        .skipped
        .into_iter()
        .map(|(model, reason)| Skipped { model, reason })
        .collect();
    Ok(synced)
}

/// Where the platform publishes what [`read`] asked it. Empty for a
/// platform this tool reads no prices from — [`read`] has refused it
/// by name long before this is asked.
fn source_of(provider: &str) -> &'static str {
    match provider {
        "deepinfra" => DEEPINFRA_MODELS,
        _ => "",
    }
}

/// The half of [`sync`] that has no platform in it: compare each row
/// against the record's newest row for that model and append the ones
/// that say something new.
///
/// The record is read once, before the first append: a sync states the
/// platform's list as of one instant, and comparing later rows against
/// what this same sync just wrote would be comparing them against
/// themselves. `source` and `as_of` are taken from the rows rather
/// than from arguments that could disagree with what was written.
fn sync_rows(rows: Vec<PriceRow>, path: &Path, provider: &str) -> Result<Synced, String> {
    let existing = price::list(path).map_err(|err| err.to_string())?;
    let source = rows
        .first()
        .map(|row| row.source.clone())
        .unwrap_or_default();
    let as_of = rows
        .first()
        .map(|row| row.as_of.clone())
        .unwrap_or_default();

    let mut appended = 0;
    let mut unchanged = 0;
    for row in &rows {
        if price::latest(&existing, provider, &row.model, None).map(|it| &it.price)
            == Some(&row.price)
        {
            unchanged += 1;
            continue;
        }
        price::append(path, row).map_err(|err| err.to_string())?;
        appended += 1;
    }

    Ok(Synced {
        provider: provider.to_string(),
        source,
        as_of,
        read: rows.len(),
        appended,
        unchanged,
        skipped: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const NOW: &str = "2026-09-22T00:00:00Z";

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-driver-prices-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn row(model: &str, output: &str, as_of: &str) -> PriceRow {
        PriceRow {
            provider: "deepinfra".to_string(),
            model: model.to_string(),
            price: Price {
                input: "1.3".to_string(),
                output: output.to_string(),
                cache_read: None,
                cache_write: None,
                reasoning: None,
            },
            unit: UNIT_USD_PER_MTOK.to_string(),
            as_of: as_of.to_string(),
            source: DEEPINFRA_MODELS.to_string(),
        }
    }

    fn lines(path: &Path) -> usize {
        std::fs::read_to_string(path)
            .expect("the record is readable")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    }

    /// **The conversion is the one thing here nobody can check by
    /// reading the output**, so it is pinned against the platform's own
    /// pricing page: `0.00013` cents per token is `1.30` USD per
    /// million tokens, the amount `deepseek-ai/DeepSeek-V4-Pro` is
    /// advertised at.
    #[test]
    fn deepinfra_cents_per_token_become_micro_usd_per_million_tokens_exactly() {
        assert_eq!(micros_from_cents_per_token(0.00013), Some(1_300_000));
        assert_eq!(micros_from_cents_per_token(2e-05), Some(200_000));
        assert_eq!(micros_from_cents_per_token(6e-06), Some(60_000));
        assert_eq!(micros_from_cents_per_token(0.0), Some(0));
        assert_eq!(
            micros_from_cents_per_token(-1.0),
            None,
            "a negative price is not a discount, it is a document this reader does not understand"
        );
        assert_eq!(micros_from_cents_per_token(f64::NAN), None);
    }

    /// The instant a sync stamps a row with is the shape the record's
    /// own writer accepts — the sub-second digits `Timestamp::now()`
    /// carries would be refused by [`PriceRow::check`] at the file.
    #[test]
    fn the_instant_a_sync_stamps_rows_with_is_the_shape_the_record_accepts() {
        let now = now_utc();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert!(!now.contains('.'), "no fractional seconds: {now}");

        let mut stamped = row("deepseek-ai/DeepSeek-V4-Pro", "2.6", NOW);
        stamped.as_of = now;
        stamped
            .check()
            .expect("the record accepts what a sync stamps");
    }

    /// One row per token-priced model, and everything else reported by
    /// name: a model priced per second of compute, and an entry with no
    /// name to report it under.
    #[test]
    fn the_deepinfra_document_reads_as_one_row_per_token_priced_model() {
        let document = serde_json::json!([
            {
                "model_name": "deepseek-ai/DeepSeek-V4-Pro",
                "type": "text-generation",
                "deprecated": null,
                "pricing": {
                    "type": "tokens",
                    "cents_per_input_token": 0.00013,
                    "cents_per_output_token": 0.00026,
                    "rate_per_input_token_cached": 0.07692308,
                    "rate_per_input_token_cache_write": null,
                    "discount": null,
                    "discount_ends_at": null,
                    "rate_per_service_tier_priority": 1.5,
                    "rate_per_service_tier_flex": 0.8
                }
            },
            {
                "model_name": "deepseek-ai/DeepSeek-V4-Flash-0731",
                "type": "text-generation",
                "pricing": {
                    "type": "tokens",
                    "cents_per_input_token": 6e-06,
                    "cents_per_output_token": 1.8e-05,
                    "rate_per_input_token_cached": 0.25,
                    "rate_per_input_token_cache_write": null,
                    "discount": null
                }
            },
            { "model_name": "x/whisper", "pricing": { "type": "time", "cents_per_sec": 0.001 } },
            { "pricing": { "type": "tokens" } }
        ]);

        let found = deepinfra_rows(&document, NOW);

        assert_eq!(found.rows.len(), 2, "{:?}", found.rows);
        let pro = &found.rows[0];
        assert_eq!(pro.model, "deepseek-ai/DeepSeek-V4-Pro");
        assert_eq!(pro.provider, "deepinfra");
        assert_eq!(pro.price.input, "1.3");
        assert_eq!(pro.price.output, "2.6");
        assert_eq!(
            pro.price.cache_read.as_deref(),
            Some("0.1"),
            "the cached rate is a ratio of the input rate, rounded to the micro-dollar"
        );
        assert_eq!(
            pro.price.cache_write, None,
            "a rate the platform states as null is not priced, which is not priced at nothing"
        );
        assert_eq!(pro.as_of, NOW);
        assert_eq!(pro.source, DEEPINFRA_MODELS);
        assert_eq!(pro.unit, UNIT_USD_PER_MTOK);

        let flash = &found.rows[1];
        assert_eq!(flash.price.input, "0.06");
        assert_eq!(flash.price.cache_read.as_deref(), Some("0.015"));

        assert_eq!(found.skipped.len(), 2, "{:?}", found.skipped);
        assert_eq!(found.skipped[0].0, "x/whisper");
        assert!(
            found.skipped[0].1.contains("time"),
            "the report carries the platform's own word: {}",
            found.skipped[0].1
        );
        assert_eq!(found.skipped[1].0, "<entry 3>");
    }

    /// **A sync writes the change log, not the snapshot.** Running it
    /// twice against a platform that moved nothing appends nothing, so
    /// the row an operator reads is still the instant the amounts were
    /// first seen rather than the last time anybody looked.
    #[test]
    fn a_sync_appends_only_what_changed() {
        let path = scratch("appends-what-changed");
        let first = vec![
            row("deepseek-ai/DeepSeek-V4-Pro", "2.6", NOW),
            row("deepseek-ai/DeepSeek-V4-Flash", "1", NOW),
        ];

        let synced = sync_rows(first.clone(), &path, "deepinfra").expect("the first sync");
        assert_eq!((synced.read, synced.appended, synced.unchanged), (2, 2, 0));
        assert_eq!(synced.as_of, NOW);
        assert_eq!(synced.source, DEEPINFRA_MODELS);
        assert_eq!(lines(&path), 2);

        let synced = sync_rows(first, &path, "deepinfra").expect("the same prices again");
        assert_eq!((synced.read, synced.appended, synced.unchanged), (2, 0, 2));
        assert_eq!(lines(&path), 2, "nothing moved, so nothing was written");

        let later = "2026-09-23T00:00:00Z";
        let moved = vec![
            row("deepseek-ai/DeepSeek-V4-Pro", "2.6", later),
            row("deepseek-ai/DeepSeek-V4-Flash", "1.2", later),
        ];
        let synced = sync_rows(moved, &path, "deepinfra").expect("one amount moved");
        assert_eq!((synced.read, synced.appended, synced.unchanged), (2, 1, 1));
        assert_eq!(lines(&path), 3);

        let rows = price::list(&path).expect("the record is readable");
        let newest = price::latest(&rows, "deepinfra", "deepseek-ai/DeepSeek-V4-Flash", None)
            .expect("the model that moved");
        assert_eq!(newest.price.output, "1.2");
        assert_eq!(newest.as_of, later);
        let unmoved = price::latest(&rows, "deepinfra", "deepseek-ai/DeepSeek-V4-Pro", None)
            .expect("the model that did not");
        assert_eq!(
            unmoved.as_of, NOW,
            "`as_of` is when the amounts were first seen, not when they were last looked at"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A platform this tool has no price list for is refused before
    /// anything is asked of the network, and a name no platform answers
    /// to is refused the way every other subcommand refuses it.
    #[test]
    fn a_platform_that_publishes_no_token_prices_is_refused_by_name() {
        let refusal = read("together", NOW).expect_err("together publishes no token price list");
        assert!(refusal.contains("together"), "{refusal}");

        let refusal = read("nope", NOW).expect_err("no platform answers to `nope`");
        assert!(refusal.contains("unknown provider"), "{refusal}");
    }
}
