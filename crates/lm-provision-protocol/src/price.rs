//! The price record: what one token costs on one (platform, model),
//! as of one instant. Appended by `machine prices sync` and by hand;
//! read by the endpoint inventory, which joins a row's `price` onto
//! the endpoint that serves that model on that platform. (09 §Price
//! record.)

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// The one unit a row may carry: US dollars per one million tokens,
/// the unit every platform's own pricing page states.
pub const UNIT_USD_PER_MTOK: &str = "usd_per_mtok";

/// One price row (09 §Price record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceRow {
    /// The platform, as the operator names it (`deepinfra`, `together`,
    /// `openrouter`, …) — the same word an endpoint row's `provider` carries.
    pub provider: String,
    /// The model, as that platform names it — the same word an endpoint
    /// row's `model` carries. The join is on (`provider`, `model`).
    pub model: String,
    /// The amounts.
    pub price: Price,
    /// Always [`UNIT_USD_PER_MTOK`]. Written into every row so a reader
    /// that meets a row from a future writer with another unit refuses
    /// it by name instead of misreading it by a factor of a million.
    pub unit: String,
    /// RFC 3339 UTC, `Z` form, the instant the amounts were read — the
    /// writer's clock for a sync, the operator's word for a hand row.
    pub as_of: String,
    /// Where the amounts came from: the URL a sync read, or `operator`.
    pub source: String,
}

/// The amounts of one row, each a decimal string in USD per million
/// tokens (`"1.30"`, `"0.028"`). Strings, not floats: the platforms
/// that return money over an API return it as text, and a reader that
/// needs arithmetic parses to [`Micros`] and works in integers.
///
/// **Absent is not zero.** A platform that does not price cache reads
/// leaves `cache_read` out; a platform that prices them at nothing
/// writes `"0"`. Both are true statements and a reader must be able to
/// tell them apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price {
    /// Uncached input tokens.
    pub input: String,
    /// Output tokens.
    pub output: String,
    /// Input tokens served from the platform's prompt cache, when the
    /// platform prices them separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<String>,
    /// Input tokens written into that cache, when the platform charges
    /// for the write (some do not, and leave this out).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<String>,
    /// Reasoning / thinking tokens, when priced apart from output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
}

/// The same amounts as integers: micro-dollars (10⁻⁶ USD) per million
/// tokens, so `tokens × amount / 1_000_000` is the charge in micro-dollars
/// with no rounding until it is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Micros {
    /// Uncached input, micro-USD per million tokens.
    pub input: u64,
    /// Output.
    pub output: u64,
    /// Cache read, when priced.
    pub cache_read: Option<u64>,
    /// Cache write, when priced.
    pub cache_write: Option<u64>,
    /// Reasoning, when priced apart from output.
    pub reasoning: Option<u64>,
}

/// Errors raised while appending to or reading a price record, or
/// reading an amount out of one.
#[derive(Debug, thiserror::Error)]
pub enum PriceError {
    /// Opening, writing, or reading the file failed.
    #[error("price record i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A row failed to encode, or an existing line failed to decode
    /// back into [`PriceRow`].
    #[error("price row (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// A row carries a unit this reader does not speak.
    #[error("price row unit `{0}` is not `{UNIT_USD_PER_MTOK}`")]
    Unit(String),
    /// An amount is not a decimal this reader can hold exactly.
    #[error("price `{field}` amount `{text}` is not usable: {why}")]
    Amount {
        /// Which amount (`input`, `output`, `cache_read`, …).
        field: &'static str,
        /// The text as written.
        text: String,
        /// What was wrong with it.
        why: &'static str,
    },
}

/// Parse a USD amount written as a decimal string into micro-dollars.
///
/// Accepts digits with at most one `.` and at most six digits after it
/// (`"1.30"`, `"0.028"`, `"0"`, `"12"`, `".5"` is refused). Refuses a
/// sign, whitespace, a thousands separator, an exponent, an empty
/// string, and a seventh decimal place — the last because it cannot
/// be held exactly and rounding money silently is the bug this type
/// exists to prevent. Overflow of `u64` is refused too.
pub fn parse_usd(field: &'static str, text: &str) -> Result<u64, PriceError> {
    let refuse = |why: &'static str| PriceError::Amount {
        field,
        text: text.to_string(),
        why,
    };

    if text.is_empty() {
        return Err(refuse("empty"));
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if fraction.contains('.') {
        return Err(refuse("more than one decimal point"));
    }
    if whole.is_empty() {
        return Err(refuse("no digits before the decimal point"));
    }
    if text.contains('.') && fraction.is_empty() {
        return Err(refuse("no digits after the decimal point"));
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return Err(refuse(
            "not digits and at most one `.` — no sign, space, separator, or exponent",
        ));
    }
    // A seventh decimal place is refused rather than rounded: the whole
    // point of holding money as integers is that nothing is dropped
    // where nobody can see it.
    if fraction.len() > 6 {
        return Err(refuse(
            "more decimal places than micro-dollars hold exactly",
        ));
    }

    let too_large = || refuse("larger than micro-dollars hold");
    let whole: u64 = whole.parse().map_err(|_| too_large())?;
    let micros = whole.checked_mul(1_000_000).ok_or_else(too_large)?;
    if fraction.is_empty() {
        return Ok(micros);
    }
    // Right-pad to six places: `"3"` is three hundred thousandths of a
    // dollar, not three micro-dollars.
    let scaled: u64 = format!("{fraction:0<6}").parse().map_err(|_| too_large())?;
    micros.checked_add(scaled).ok_or_else(too_large)
}

/// Print micro-dollars as the shortest exact decimal: `1_300_000` →
/// `"1.3"`, `28_000` → `"0.028"`, `0` → `"0"`, `1_000_000` → `"1"`.
pub fn format_usd(micros: u64) -> String {
    let whole = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:06}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// The shape [`PriceRow::as_of`] is written in, checked as text.
///
/// There is no date library here and this is not a calendar check: a
/// row whose `as_of` is `"2026-09-22"` or `"22/09/2026"` would sort
/// against the other rows wherever its text sorts, which is how
/// [`latest`] would silently answer with the wrong month. Refusing the
/// shape at the writer is what keeps the ordering the reader assumes
/// true of every line in the file.
fn check_as_of(as_of: &str) -> Result<(), PriceError> {
    let shaped = as_of.len() == 20
        && as_of.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    if shaped {
        return Ok(());
    }
    Err(PriceError::Amount {
        field: "as_of",
        text: as_of.to_string(),
        why: "not RFC 3339 UTC in Z form (YYYY-MM-DDTHH:MM:SSZ)",
    })
}

impl Price {
    /// The amounts as integers, or the first amount that is not usable.
    pub fn micros(&self) -> Result<Micros, PriceError> {
        let optional = |field: &'static str, text: &Option<String>| match text {
            Some(text) => parse_usd(field, text).map(Some),
            None => Ok(None),
        };
        Ok(Micros {
            input: parse_usd("input", &self.input)?,
            output: parse_usd("output", &self.output)?,
            cache_read: optional("cache_read", &self.cache_read)?,
            cache_write: optional("cache_write", &self.cache_write)?,
            reasoning: optional("reasoning", &self.reasoning)?,
        })
    }
}

impl PriceRow {
    /// Refuse a row this reader cannot use: a unit other than
    /// [`UNIT_USD_PER_MTOK`], or an amount [`parse_usd`] refuses.
    /// Called by [`append`] before writing, so the record never holds
    /// a row its own reader would reject.
    pub fn check(&self) -> Result<(), PriceError> {
        if self.unit != UNIT_USD_PER_MTOK {
            return Err(PriceError::Unit(self.unit.clone()));
        }
        check_as_of(&self.as_of)?;
        self.price.micros()?;
        Ok(())
    }
}

/// Append one row (after [`PriceRow::check`]). Never rewrites.
pub fn append(path: &Path, row: &PriceRow) -> Result<(), PriceError> {
    row.check()?;
    // One write, newline included — see [`crate::ledger::append`] for
    // why `writeln!` is not used.
    let mut line = serde_json::to_string(row)?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Every row, newest first (by file order reversed, as
/// [`crate::acquisition::list`] does). A missing file is an empty record.
pub fn list(path: &Path) -> Result<Vec<PriceRow>, PriceError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    let mut rows = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(&line)?);
    }
    rows.reverse();
    Ok(rows)
}

/// The row that priced (`provider`, `model`) at `at` — the newest row
/// whose `as_of` is at or before `at`, or the newest row of all when
/// `at` is `None`. `rows` is as [`list`] returns it (newest first).
///
/// The comparison is on the `as_of` text: both sides are RFC 3339 UTC
/// in `Z` form, which orders as text orders — the convention the
/// acquisitions record's timestamps already rely on. A row whose
/// `as_of` is not in that form sorts wherever its text sorts; the
/// writer's duty ([`append`] via `check`) is not to write one.
pub fn latest<'a>(
    rows: &'a [PriceRow],
    provider: &str,
    model: &str,
    at: Option<&str>,
) -> Option<&'a PriceRow> {
    rows.iter().find(|row| {
        row.provider == provider
            && row.model == model
            && at.is_none_or(|at| row.as_of.as_str() <= at)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lm-provision-protocol-price-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn row(model: &str, as_of: &str) -> PriceRow {
        PriceRow {
            provider: "deepinfra".to_string(),
            model: model.to_string(),
            price: Price {
                input: "0.028".to_string(),
                output: "0.042".to_string(),
                cache_read: None,
                cache_write: None,
                reasoning: None,
            },
            unit: UNIT_USD_PER_MTOK.to_string(),
            as_of: as_of.to_string(),
            source: "https://deepinfra.com/pricing".to_string(),
        }
    }

    #[test]
    fn a_price_row_round_trips_through_its_line() {
        let path = tmp_path("round-trip");
        let mut written = row("deepseek-ai/DeepSeek-V4-Flash", "2026-09-22T00:00:00Z");
        written.price.cache_read = Some("0.014".to_string());
        append(&path, &written).expect("append should succeed");

        assert_eq!(
            list(&path).expect("list should succeed"),
            vec![written.clone()]
        );

        // Absent is absent: a reader tells "not priced" from "priced at
        // nothing" by the key, so the key must not be written.
        let line = std::fs::read_to_string(&path).expect("file readable");
        assert!(line.contains("cache_read"), "{line}");
        assert!(!line.contains("cache_write"), "{line}");
        assert!(!line.contains("reasoning"), "{line}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_amount_is_parsed_to_micro_usd_per_million_tokens_exactly() {
        assert_eq!(parse_usd("input", "1.30").expect("1.30"), 1_300_000);
        assert_eq!(parse_usd("input", "0.028").expect("0.028"), 28_000);
        assert_eq!(parse_usd("input", "0").expect("0"), 0);
        assert_eq!(parse_usd("input", "12").expect("12"), 12_000_000);
        assert_eq!(parse_usd("input", "0.000001").expect("0.000001"), 1);

        for refused in ["0.0000001", "-1", "1,30", " 1.3", "", ".5", "1e3", "1.2.3"] {
            let error =
                parse_usd("input", refused).expect_err(&format!("`{refused}` should be refused"));
            assert!(
                matches!(error, PriceError::Amount { .. }),
                "`{refused}` gave {error}"
            );
        }
    }

    #[test]
    fn formatting_micro_usd_prints_the_shortest_exact_decimal() {
        assert_eq!(format_usd(1_300_000), "1.3");
        assert_eq!(format_usd(28_000), "0.028");
        assert_eq!(format_usd(0), "0");
        assert_eq!(format_usd(1_000_000), "1");
        assert_eq!(
            format_usd(parse_usd("input", "0.028").expect("0.028")),
            "0.028",
            "a round trip through micro-dollars changes no amount"
        );
    }

    #[test]
    fn the_latest_row_for_a_model_is_the_newest_at_or_before_the_instant() {
        let path = tmp_path("latest");
        let model = "deepseek-ai/DeepSeek-V4-Flash";
        append(&path, &row(model, "2026-09-01T00:00:00Z")).expect("append 09-01");
        append(&path, &row(model, "2026-09-15T00:00:00Z")).expect("append 09-15");
        append(&path, &row("other/Model", "2026-09-20T00:00:00Z")).expect("append other");
        append(&path, &row(model, "2026-09-22T00:00:00Z")).expect("append 09-22");
        let rows = list(&path).expect("list should succeed");

        assert_eq!(
            latest(&rows, "deepinfra", model, None).map(|it| it.as_of.as_str()),
            Some("2026-09-22T00:00:00Z"),
            "no instant asked for: the newest row"
        );
        assert_eq!(
            latest(&rows, "deepinfra", model, Some("2026-09-16T00:00:00Z"))
                .map(|it| it.as_of.as_str()),
            Some("2026-09-15T00:00:00Z"),
            "a run is re-priced at the rate that was in force when it ran"
        );
        assert_eq!(
            latest(&rows, "deepinfra", model, Some("2026-08-01T00:00:00Z")),
            None,
            "the record says nothing about a moment before its first row"
        );
        assert_eq!(
            latest(&rows, "deepinfra", "other/Model", None).map(|it| it.model.as_str()),
            Some("other/Model"),
            "the other model answers only for itself"
        );
        assert_eq!(
            latest(&rows, "together", model, None),
            None,
            "a provider this record never priced"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_record_is_empty_not_an_error() {
        let path = tmp_path("missing");
        assert!(!path.exists());
        assert_eq!(list(&path).expect("missing list"), Vec::new());
        assert_eq!(
            latest(&[], "deepinfra", "deepseek-ai/DeepSeek-V4-Flash", None),
            None
        );
    }

    /// A row the reader would refuse never reaches the file: [`append`]
    /// checks first, so nothing in the record needs a reader prepared
    /// to meet a line it cannot use.
    #[test]
    fn a_row_this_reader_cannot_use_is_refused_before_it_is_written() {
        let model = "deepseek-ai/DeepSeek-V4-Flash";

        let path = tmp_path("wrong-unit");
        let mut wrong_unit = row(model, "2026-09-22T00:00:00Z");
        wrong_unit.unit = "usd_per_token".to_string();
        let error = append(&path, &wrong_unit).expect_err("the unit is not this reader's");
        assert!(matches!(error, PriceError::Unit(ref unit) if unit == "usd_per_token"));
        assert!(!path.exists(), "nothing was written");

        let path = tmp_path("bad-amount");
        let mut bad_amount = row(model, "2026-09-22T00:00:00Z");
        bad_amount.price.input = "1.2.3".to_string();
        let error = append(&path, &bad_amount).expect_err("the amount is not a decimal");
        assert!(
            matches!(error, PriceError::Amount { field: "input", .. }),
            "{error}"
        );
        assert!(!path.exists(), "nothing was written");

        let path = tmp_path("bad-as-of");
        let bad_as_of = row(model, "2026-09-22");
        let error = append(&path, &bad_as_of).expect_err("the instant is not RFC 3339 UTC");
        assert!(
            matches!(error, PriceError::Amount { field: "as_of", .. }),
            "{error}"
        );
        assert!(!path.exists(), "nothing was written");
    }
}
