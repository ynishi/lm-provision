//! What a platform is running, read and rendered once.
//!
//! Two surfaces ask this question — `lm-provision machine list` and the
//! MCP `lm_machine_list` tool — and they have to get the same answer,
//! so the reading and the rendering live here rather than beside either
//! caller. 08 §Acquisitions and sweep is the rationale the listing
//! stands on: "the platform's list is the inventory; the record is not",
//! because a record is a file that can be lost while the machine keeps
//! billing.
//!
//! **Nothing here destroys anything.** The credential is still
//! required — the key buys the question — and that is the whole of what
//! it buys: this module has no release path, and a machine carrying no
//! lease stamp is reported exactly like one that does.

use std::path::Path;

use lm_provision_protocol::price::{self, PriceRow, UNIT_USD_PER_MTOK};

use crate::credentials;
use crate::infra::{self, Fleet, Machine};

/// One platform's own list, and what the platform's CLI said while
/// being asked.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// How the listing was read, and how a machine in it would be
    /// released — carried out so a caller acting on the list acts from
    /// the same description it was read through, rather than from a
    /// second lookup.
    pub fleet: Fleet,
    /// The machines, as [`infra::machines`] read them.
    pub machines: Vec<Machine>,
    /// The platform CLI's own stderr, and the program to attribute it
    /// to. This module never writes to a stream.
    pub said: (String, Vec<u8>),
}

/// Ask one platform what it is running.
///
/// The credential is required first: a listing without one is the
/// platform CLI's own error in the middle of somebody else's run, and
/// this way the refusal names the variable and where it was looked for.
pub fn fetch(provider: &str) -> Result<Fetched, String> {
    let adapter = infra::adapter_named(provider)?;
    credentials::require(adapter.provider_namespace(), adapter.credentials())
        .map_err(|missing| missing.to_string())?;
    let fleet = adapter
        .fleet()
        .ok_or_else(|| format!("{provider} cannot be asked what it is running"))?;
    let listing = infra::list(&fleet).map_err(|err| err.to_string())?;
    let program = fleet
        .list
        .first()
        .cloned()
        .unwrap_or_else(|| provider.to_string());
    Ok(Fetched {
        fleet,
        machines: listing.machines,
        said: (program, listing.said),
    })
}

/// Where one machine can be reached, read from the platform's own
/// description.
///
/// The same projection `acquire` reports after it creates a machine
/// ([`infra::Infra::connection`]), reached by an identifier instead of
/// by having just created it. That is the whole point: an operator who
/// has a pod id should not have to hand-carry a `host:port` out of
/// whatever printed it last, and a second caller re-deriving the
/// address by querying the platform directly would need the platform
/// credential arranged in its own shell for a fact the driver already
/// pays to learn.
///
/// Read-only and costs nothing but the question. The credential is
/// required first for the reason [`fetch`] requires it: otherwise the
/// refusal is the platform CLI's own error in the middle of somebody
/// else's run, rather than a line naming the variable and the files it
/// was looked for in.
///
/// **A machine still booting is not an error.** It answers with a
/// description carrying no address yet, and that projects to a
/// [`infra::Connection`] whose `ssh` is `None` — the caller decides
/// what to do about a pod that is not up, which is not something this
/// can decide for it.
pub fn connection(provider: &str, id: &str) -> Result<infra::Connection, String> {
    let adapter = infra::adapter_named(provider)?;
    credentials::require(adapter.provider_namespace(), adapter.credentials())
        .map_err(|missing| missing.to_string())?;
    let fleet = adapter
        .fleet()
        .ok_or_else(|| format!("{provider} cannot be asked about a machine"))?;
    let inspected = infra::inspect(&fleet, id).map_err(|err| err.to_string())?;
    Ok(adapter.connection(&inspected))
}

/// A listing of every named platform: the machines, the platforms that
/// could not be asked, and what each platform CLI said while being
/// asked.
///
/// The fields are typed rather than a bag of JSON so that a caller
/// deciding an exit code or writing a log line reads a `&str`, not
/// `artifact["failed"][0]["reason"].as_str().unwrap_or("?")`. The
/// document is rendered from them ([`Listing::artifact`]), so the two
/// cannot disagree.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The machines, one JSON object each, in the order the platforms
    /// were named and each platform listed them.
    pub machines: Vec<serde_json::Value>,
    /// The platforms that could not be listed, and why: `(provider,
    /// reason)`.
    pub failed: Vec<(String, String)>,
    /// Each platform CLI's stderr under the program that said it, for
    /// the caller to relay or log.
    pub said: Vec<(String, Vec<u8>)>,
}

impl Listing {
    /// The one machine-readable document (07-cli.md §Stream split: one
    /// artifact per run), also the MCP tool's result.
    ///
    /// **`failed` is part of the document, not an alternative to it.**
    /// A run that could not ask one platform still knows what the
    /// others are running, and a caller told only "something went
    /// wrong" would have to ask again to find out what did not.
    pub fn artifact(&self) -> serde_json::Value {
        serde_json::json!({
            "machines": self.machines,
            "failed": self
                .failed
                .iter()
                .map(|(provider, reason)| serde_json::json!({
                    "provider": provider,
                    "reason": reason,
                }))
                .collect::<Vec<_>>(),
        })
    }

    /// Whether every named platform answered. False when any of them
    /// could not be listed — a plane nobody could read may be running
    /// anything, so the caller's exit code has to say so.
    pub fn complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Ask each named platform what it is running.
///
/// A platform that cannot be listed lands in [`Listing::failed`] rather
/// than ending the run: with two platforms named, one unreadable key
/// would otherwise hide the machines on the other.
pub fn list(providers: &[String]) -> Listing {
    let mut listing = Listing {
        machines: Vec::new(),
        failed: Vec::new(),
        said: Vec::new(),
    };
    for provider in providers {
        match fetch(provider) {
            Ok(fetched) => {
                listing.said.push(fetched.said);
                listing.machines.extend(
                    fetched
                        .machines
                        .iter()
                        .map(|machine| listed(machine, provider)),
                );
            }
            Err(reason) => listing.failed.push((provider.clone(), reason)),
        }
    }
    listing
}

/// One machine as the artifact reports it.
///
/// `expires_at` is the lease read off the machine's own name
/// ([`infra::expiry_of`]) in RFC 3339, the encoding the acquisitions
/// record writes its timestamps in — so a row here and a row there are
/// comparable without a second format to parse. `stamped` says whether
/// there was one to read at all: a machine this tool did not name is
/// not a machine with an expiry of zero, and the two have to be
/// distinguishable by something other than a `null` a reader might take
/// for "never expires".
fn listed(machine: &Machine, provider: &str) -> serde_json::Value {
    let expires_at = machine.name.as_deref().and_then(infra::expiry_of);
    serde_json::json!({
        "id": machine.id,
        "name": machine.name,
        "provider": provider,
        "expires_at": expires_at.map(|it| it.to_string()),
        "stamped": expires_at.is_some(),
    })
}

// ---- The endpoint inventory ----

/// One OpenAI-compatible endpoint this tool knows about, or a machine
/// that could carry one — a row of the endpoint inventory (09
/// §Endpoint inventory).
///
/// **The key travels by name.** `api_key_env` is the variable the
/// consumer reads the key from; the value is in no row, as it is in no
/// artifact this crate writes. A consumer rendering this into its own
/// configuration writes the same name (`api_key: os.environ/NAME`,
/// `export X_API_KEY="$NAME"`), and the value stays where the operator
/// put it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Endpoint {
    /// What a consumer calls it: the profile's `service.start` name for
    /// a machine this tool acquired (falling back to the platform id),
    /// the operator's own name for a static row.
    pub name: String,
    /// `deployment` (a served model on a managed platform), `tunnel` (a
    /// detached forward to a pod, reachable on this host's loopback),
    /// `pod` (a machine this tool acquired that no forward reaches —
    /// `base_url` is absent), or `serverless` (a static row).
    pub kind: EndpointKind,
    /// The platform, for rows that came from one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The machine's id on that platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Where an OpenAI client is pointed, when there is somewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// What to send as `model`, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The environment variable holding the key, by name; absent when
    /// the endpoint takes none (a tunnel to a pod's own vLLM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// The lease, for a machine this tool acquired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// What a token costs here, when a price is known (09 §Price
    /// record): the newest record row for this (`provider`, `model`),
    /// or the amounts the operator wrote on a static row. Absent when
    /// no row prices it — a tunnel to a pod's own vLLM, a machine no
    /// row names, a model the record has not been synced for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<EndpointPrice>,
    /// Where the row came from: `acquisitions`, `forwards`, or the
    /// static file's path.
    pub source: String,
}

/// A price beside an endpoint: the amounts of the newest price row
/// for the endpoint's (`provider`, `model`) — or the operator's own
/// amounts on a static row — with when they were read and from where.
/// Amounts are decimal text in USD per million tokens
/// (`lm_provision_protocol::price::UNIT_USD_PER_MTOK`); absent is
/// not zero (09 §Price record).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EndpointPrice {
    /// `input` / `output` / `cache_read?` / `cache_write?` / `reasoning?`.
    #[serde(flatten)]
    pub amounts: lm_provision_protocol::price::Price,
    /// Always `usd_per_mtok`; written so a reader never has to guess.
    pub unit: String,
    /// RFC 3339 UTC: when the amounts were read.
    pub as_of: String,
    /// The record row's `source`, or the static file's path.
    pub source: String,
}

/// The kinds of row the inventory carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    /// A served model on a managed platform.
    Deployment,
    /// A detached forward to a pod, on this host's loopback.
    Tunnel,
    /// An acquired machine no forward reaches.
    Pod,
    /// A static row the operator wrote.
    Serverless,
}

/// Where the inventory's rows are read from.
#[derive(Debug, Clone)]
pub struct EndpointSources<'a> {
    /// The acquisitions record (09 §Acquisitions record).
    pub acquisitions: &'a Path,
    /// The forwards record (09 §Forwards record).
    pub forwards: &'a Path,
    /// The operator's static rows, when they keep any: a JSON array of
    /// `{name, base_url, model?, api_key_env?, provider?, price?}`.
    pub statics: Option<&'a Path>,
    /// The price record (09 §Price record); a missing file is an empty
    /// record, as for the acquisitions record.
    pub prices: &'a Path,
}

/// The inventory: every row that could be read, and every source or
/// machine that could not — typed, as [`Listing`] is, so a caller
/// deciding an exit code reads a field rather than a document.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The rows, deployments and tunnels first.
    pub rows: Vec<Endpoint>,
    /// What could not be read, as `(what, reason)`: a platform that
    /// could not be asked about a recorded machine, a record that
    /// could not be parsed, a static file that is not the shape above.
    pub failed: Vec<(String, String)>,
    /// Each platform CLI's stderr under the program that said it.
    pub said: Vec<(String, Vec<u8>)>,
}

impl Endpoints {
    /// The one machine-readable document (07 §Stream split).
    pub fn artifact(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoints": self.rows,
            "failed": self
                .failed
                .iter()
                .map(|(what, reason)| serde_json::json!({ "source": what, "reason": reason }))
                .collect::<Vec<_>>(),
        })
    }

    /// Whether every source and every recorded machine answered.
    pub fn complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Read the inventory.
///
/// Three sources, each read on its own so one that cannot be read does
/// not hide the others:
///
/// - **The acquisitions record**, every outstanding row: the machine is
///   asked about through its platform ([`connection`]), and what it
///   projects decides the row — an inference endpoint is a
///   `deployment`, an SSH endpoint (or nothing yet) is a `pod`. The
///   platform's credential is needed for the question, and a machine
///   whose platform cannot be asked lands in `failed` under its id.
/// - **The forwards record**, every row whose `ssh` is still the
///   process the row named ([`forward_is_live`]): a `tunnel` on this
///   host's loopback, its model read off the pod's own `/v1/models`
///   when it answers. A row whose process is gone is left out, and
///   said in `failed` so the next `port-forward` can prune it.
/// - **The static file**, when named: the operator's own rows, verbatim.
///
/// Then one join: the price record is read once and its newest row for
/// each endpoint's (`provider`, `model`) is put beside it ([`priced`]).
pub fn endpoints(sources: &EndpointSources<'_>) -> Endpoints {
    let mut out = Endpoints {
        rows: Vec::new(),
        failed: Vec::new(),
        said: Vec::new(),
    };

    // Read first and joined last: one reading prices every row, and a
    // record that cannot be read prices nothing rather than ending the
    // run — the rows it would have priced are still listed, and the
    // file that could not be read is in `failed` under its own path.
    let prices = match price::list(sources.prices) {
        Ok(rows) => rows,
        Err(err) => {
            out.failed
                .push((sources.prices.display().to_string(), err.to_string()));
            Vec::new()
        }
    };

    match lm_provision_protocol::acquisition::outstanding(sources.acquisitions) {
        Ok(rows) => {
            for row in rows {
                match connection(&row.provider, &row.id) {
                    Ok(projected) => out.rows.push(endpoint_of_acquired(&row, &projected)),
                    Err(reason) => out
                        .failed
                        .push((format!("{}/{}", row.provider, row.id), reason)),
                }
            }
        }
        Err(err) => out
            .failed
            .push((sources.acquisitions.display().to_string(), err.to_string())),
    }

    match lm_provision_protocol::forward::list(sources.forwards) {
        Ok(rows) => {
            for row in rows {
                if !forward_is_live(&row) {
                    out.failed.push((
                        format!("forward pid {}", row.pid),
                        "the ssh that carried it is gone; the next port-forward prunes the row"
                            .to_string(),
                    ));
                    continue;
                }
                for pair in &row.forwards {
                    let base_url = format!("http://{}:{}/v1", row.address, pair.local);
                    out.rows.push(Endpoint {
                        name: row
                            .pod
                            .as_ref()
                            .map(|it| format!("{}-{}-{}", it.provider, it.id, pair.remote))
                            .unwrap_or_else(|| format!("tunnel-{}-{}", row.address, pair.local)),
                        kind: EndpointKind::Tunnel,
                        provider: row.pod.as_ref().map(|it| it.provider.clone()),
                        id: row.pod.as_ref().map(|it| it.id.clone()),
                        model: served_model_at(&base_url),
                        base_url: Some(base_url),
                        api_key_env: None,
                        expires_at: None,
                        price: None,
                        source: "forwards".to_string(),
                    });
                }
            }
        }
        Err(err) => out
            .failed
            .push((sources.forwards.display().to_string(), err.to_string())),
    }

    if let Some(path) = sources.statics {
        match static_rows(path) {
            Ok(rows) => out.rows.extend(rows),
            Err(reason) => out.failed.push((path.display().to_string(), reason)),
        }
    }

    for row in &mut out.rows {
        priced(row, &prices);
    }

    out
}

/// Put the record's newest row for a row's (`provider`, `model`)
/// beside it.
///
/// A row that already carries a price keeps it: that is a static row
/// the operator priced themselves, and their word about their own row
/// beats the record. A row the record does not price is left without
/// one — absent is not zero (09 §Price record) — as is a row that
/// names no provider or no model, since the join has nothing to be on.
fn priced(row: &mut Endpoint, prices: &[PriceRow]) {
    if row.price.is_some() {
        return;
    }
    let (Some(provider), Some(model)) = (row.provider.as_deref(), row.model.as_deref()) else {
        return;
    };
    let Some(found) = price::latest(prices, provider, model, None) else {
        return;
    };
    row.price = Some(EndpointPrice {
        amounts: found.price.clone(),
        unit: found.unit.clone(),
        as_of: found.as_of.clone(),
        source: found.source.clone(),
    });
}

/// The row an acquired machine makes, from its record and what its
/// platform says about it now.
fn endpoint_of_acquired(
    row: &lm_provision_protocol::acquisition::AcquisitionRow,
    projected: &infra::Connection,
) -> Endpoint {
    let name = row.service.clone().unwrap_or_else(|| row.id.clone());
    match &projected.endpoint {
        Some(served) => Endpoint {
            name,
            kind: EndpointKind::Deployment,
            provider: Some(row.provider.clone()),
            id: Some(row.id.clone()),
            base_url: Some(served.base_url.clone()),
            model: Some(served.model.clone()),
            api_key_env: Some(served.api_key_env.clone()),
            expires_at: Some(row.expires_at.clone()),
            price: None,
            source: "acquisitions".to_string(),
        },
        None => Endpoint {
            name,
            kind: EndpointKind::Pod,
            provider: Some(row.provider.clone()),
            id: Some(row.id.clone()),
            base_url: None,
            model: None,
            api_key_env: None,
            expires_at: Some(row.expires_at.clone()),
            price: None,
            source: "acquisitions".to_string(),
        },
    }
}

/// Whether the process a forward row names is still the `ssh` that was
/// detached: the pid exists **and**, where the row recorded one, its
/// start time is the one recorded. Pids are reused; a start time is
/// not [documented: proc_pid_stat(5)]. A row with no recorded start
/// time is judged on the pid alone, which is the weaker answer the
/// writer already declared by leaving the field out.
pub fn forward_is_live(row: &lm_provision_protocol::forward::ForwardRow) -> bool {
    match (process_start_time(row.pid), row.started_at) {
        (None, _) => false,
        (Some(now), Some(then)) => now == then,
        (Some(_), None) => true,
    }
}

/// The kernel's start time for `pid`, or `None` when there is no such
/// process (or no `/proc` to ask).
///
/// Linux only: field 22 of `/proc/<pid>/stat`, read after the last `)`
/// so a command name containing spaces or parentheses cannot shift the
/// fields [documented: proc_pid_stat(5)].
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    // `after_comm` starts at field 3 (state); field 22 is therefore the
    // 20th whitespace-separated word from here.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// The first model a tunnel's pod serves, read off `/v1/models` — the
/// one question an OpenAI-compatible server answers without a key.
/// `None` when it does not answer within a couple of seconds: a pod
/// still starting, or a port that carries something else.
fn served_model_at(base_url: &str) -> Option<String> {
    let output = std::process::Command::new("curl")
        .args(["-sS", "-f", "-m", "3", &format!("{base_url}/models")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    body.get("data")?
        .as_array()?
        .first()?
        .get("id")?
        .as_str()
        .map(str::to_string)
}

/// The operator's static rows: a JSON array of objects with `name` and
/// `base_url` (required) and `model` / `api_key_env` / `provider` /
/// `price` (optional).
/// Anything else in an object is refused by name rather than dropped.
fn static_rows(path: &Path) -> Result<Vec<Endpoint>, String> {
    let text = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let items = value
        .as_array()
        .ok_or_else(|| "the static endpoints file is not a JSON array".to_string())?;
    let mut rows = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let object = item
            .as_object()
            .ok_or_else(|| format!("entry {index} is not an object"))?;
        let text_field = |key: &str| {
            object
                .get(key)
                .and_then(|it| it.as_str())
                .map(str::to_string)
        };
        for key in object.keys() {
            if ![
                "name",
                "base_url",
                "model",
                "api_key_env",
                "provider",
                "price",
            ]
            .contains(&key.as_str())
            {
                return Err(format!(
                    "entry {index} carries `{key}`, which is not a field of a static row \
                     (name, base_url, model, api_key_env, provider, price)"
                ));
            }
        }
        let provider = text_field("provider");
        let model = text_field("model");
        let price = match object.get("price") {
            Some(price) => Some(static_price(
                index,
                price,
                path,
                provider.as_deref(),
                model.as_deref(),
            )?),
            None => None,
        };
        rows.push(Endpoint {
            name: text_field("name").ok_or_else(|| format!("entry {index} has no name"))?,
            kind: EndpointKind::Serverless,
            provider,
            id: None,
            base_url: Some(
                text_field("base_url").ok_or_else(|| format!("entry {index} has no base_url"))?,
            ),
            model,
            api_key_env: text_field("api_key_env"),
            expires_at: None,
            price,
            source: path.display().to_string(),
        });
    }
    Ok(rows)
}

/// The price the operator wrote on one static row.
///
/// Checked by the reader that checks a record row ([`PriceRow::check`])
/// rather than by a second set of rules here: an amount this host would
/// refuse in the record is refused on a static row too, so the two
/// cannot disagree about what an amount is. A key outside the permitted
/// set is refused by name, for the reason the row's own fields are — a
/// mistyped `cache_read` dropped would be a price that looked complete.
fn static_price(
    index: usize,
    price: &serde_json::Value,
    path: &Path,
    provider: Option<&str>,
    model: Option<&str>,
) -> Result<EndpointPrice, String> {
    let object = price
        .as_object()
        .ok_or_else(|| format!("entry {index} price: not an object"))?;
    for key in object.keys() {
        if ![
            "input",
            "output",
            "cache_read",
            "cache_write",
            "reasoning",
            "as_of",
        ]
        .contains(&key.as_str())
        {
            return Err(format!(
                "entry {index} price carries `{key}`, which is not a field of a price \
                 (input, output, cache_read, cache_write, reasoning, as_of)"
            ));
        }
    }
    let text_field = |key: &str| {
        object
            .get(key)
            .and_then(|it| it.as_str())
            .map(str::to_string)
    };
    let required =
        |key: &str| text_field(key).ok_or_else(|| format!("entry {index} price has no {key}"));
    // The check wants a whole row, and the row a static entry would
    // make is this one: its own provider and model (empty where it
    // names none — the check is about the amounts and the instant), the
    // one unit this reader speaks, and the file as the source.
    let row = PriceRow {
        provider: provider.unwrap_or_default().to_string(),
        model: model.unwrap_or_default().to_string(),
        price: lm_provision_protocol::price::Price {
            input: required("input")?,
            output: required("output")?,
            cache_read: text_field("cache_read"),
            cache_write: text_field("cache_write"),
            reasoning: text_field("reasoning"),
        },
        unit: UNIT_USD_PER_MTOK.to_string(),
        as_of: required("as_of")?,
        source: path.display().to_string(),
    };
    row.check()
        .map_err(|err| format!("entry {index} price: {err}"))?;
    Ok(EndpointPrice {
        amounts: row.price,
        unit: row.unit,
        as_of: row.as_of,
        source: row.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The lease is read off the machine, and an unstamped machine
    /// says so rather than reading as one that never expires.** Both
    /// surfaces render from this, so the shape is the contract: a
    /// `null` `expires_at` beside `stamped: false` is a machine this
    /// tool did not name.
    #[test]
    fn a_listed_machine_carries_the_lease_its_own_name_states() {
        let stamped = listed(
            &Machine {
                id: "pod-1".to_string(),
                name: Some("lmp-exp-20260902T063000Z".to_string()),
            },
            "runpod",
        );
        assert_eq!(
            stamped,
            serde_json::json!({
                "id": "pod-1",
                "name": "lmp-exp-20260902T063000Z",
                "provider": "runpod",
                "expires_at": "2026-09-02T06:30:00Z",
                "stamped": true,
            })
        );

        let unstamped = listed(
            &Machine {
                id: "49229000".to_string(),
                name: Some("jupyter-scratch".to_string()),
            },
            "vast",
        );
        assert_eq!(unstamped["stamped"], serde_json::json!(false));
        assert_eq!(unstamped["expires_at"], serde_json::Value::Null);
        assert_eq!(
            unstamped["name"],
            serde_json::json!("jupyter-scratch"),
            "what it is called is reported even when it is not a lease"
        );

        let nameless = listed(
            &Machine {
                id: "pod-2".to_string(),
                name: None,
            },
            "runpod",
        );
        assert_eq!(nameless["name"], serde_json::Value::Null);
        assert_eq!(nameless["stamped"], serde_json::json!(false));
    }

    /// **What `connection` hands back is the platform's own
    /// description, projected by the adapter that speaks that
    /// platform** — the same projection `acquire` reports, so the
    /// address an operator gets from an id and the one they got at
    /// creation are the same fields read the same way.
    ///
    /// The read itself is a subprocess and is covered end to end by
    /// the CLI suite; what is checked here is the half that decides
    /// what an operator can dial, including the booting machine that
    /// has no address yet.
    #[test]
    fn a_read_back_projects_to_the_endpoint_an_operator_dials() {
        let adapter = infra::adapter_named("runpod").expect("a wired platform");
        // A `get-pod` answer, in the shape a read-back has: the
        // address fields are there, the creation-time `machine` object
        // is not.
        let described = serde_json::json!({
            "id": "pod-1",
            "desiredStatus": "RUNNING",
            "publicIp": "203.0.113.9",
            "portMappings": { "22": 21001, "8188": 21002 },
            "machine": {}
        });
        let connection = adapter.connection(&described);
        let ssh = connection.ssh.expect("22 is mapped and the address is set");
        assert_eq!(ssh.host, "203.0.113.9");
        assert_eq!(ssh.port, 21001);
        assert_eq!(
            connection.endpoints.get(&8188),
            Some(&"203.0.113.9:21002".to_string()),
            "every declared port's public address comes back with it"
        );

        let booting = serde_json::json!({ "id": "pod-1", "publicIp": "" });
        assert!(
            adapter.connection(&booting).ssh.is_none(),
            "a pod that has no address yet reports none, rather than one to dial"
        );
    }

    /// A platform nobody wired is a request that cannot be used, and it
    /// is refused before anything is run.
    #[test]
    fn asking_an_unknown_platform_about_a_machine_names_what_was_wrong() {
        let refusal = connection("not-a-platform", "pod-1").expect_err("no such platform");
        assert!(refusal.contains("unknown provider"), "{refusal}");
    }

    /// **A platform that cannot be asked is reported, not fatal**, and
    /// the run is marked incomplete — with two platforms named, one
    /// unreadable credential must not hide what the other is running.
    #[test]
    fn an_unaskable_platform_lands_in_failed_and_costs_completeness() {
        let listing = list(&["not-a-platform".to_string()]);
        assert!(!listing.complete());
        assert!(listing.machines.is_empty());
        let (provider, reason) = &listing.failed[0];
        assert_eq!(provider, "not-a-platform");
        assert!(
            reason.contains("unknown provider"),
            "the reason names what was wrong with the request: {reason}"
        );

        let artifact = listing.artifact();
        assert_eq!(artifact["machines"], serde_json::json!([]));
        assert_eq!(
            artifact["failed"],
            serde_json::json!([{ "provider": provider, "reason": reason }]),
            "the document is rendered from the typed fields, so it cannot disagree with them"
        );

        let nothing = list(&[]);
        assert!(
            nothing.complete(),
            "no platform named is not a platform that failed"
        );
        assert_eq!(
            nothing.artifact(),
            serde_json::json!({ "machines": [], "failed": [] }),
            "the one document is emitted with every field present"
        );
    }

    /// **A forward is live only while the pid is the process the row
    /// named.** The test's own process is such a pid; a start time
    /// that disagrees is a reused number, and a pid nothing holds is
    /// gone. On a platform with no `/proc` the answer is "not live",
    /// which is the safe way to be wrong about a tunnel.
    #[test]
    fn a_forward_is_live_only_while_its_pid_is_the_recorded_process() {
        use lm_provision_protocol::forward::{ForwardPair, ForwardRow};
        let me = std::process::id();
        let now = process_start_time(me);
        let row = |pid: u32, started_at: Option<u64>| ForwardRow {
            pid,
            started_at,
            opened_at: "2026-09-23T00:00:00Z".to_string(),
            address: "127.0.0.1".to_string(),
            forwards: vec![ForwardPair {
                local: 18000,
                remote: 8000,
            }],
            pod: None,
        };
        if let Some(now) = now {
            assert!(forward_is_live(&row(me, Some(now))));
            assert!(
                !forward_is_live(&row(me, Some(now.wrapping_add(1)))),
                "a different start time is a different process holding the same number"
            );
            assert!(
                forward_is_live(&row(me, None)),
                "with no recorded start time the pid alone decides"
            );
        }
        // Pid 0 is never a user process a forward could be.
        assert!(!forward_is_live(&row(0, None)));
        assert!(!forward_is_live(&row(0, Some(1))));
    }

    /// **The rows the record makes**: a machine whose platform projects
    /// an inference endpoint is a deployment, carrying the endpoint and
    /// the lease; one that projects none is a pod with no `base_url`;
    /// both are named by the profile's service when the record has one.
    #[test]
    fn an_acquired_machine_is_a_deployment_or_a_pod_by_what_it_projects() {
        use lm_provision_protocol::acquisition::AcquisitionRow;
        let row = AcquisitionRow {
            id: "dep-1".to_string(),
            provider: "deepinfra-deploy".to_string(),
            acquired_at: "2026-09-23T00:00:00Z".to_string(),
            expires_at: "2026-09-24T00:00:00Z".to_string(),
            profile_hash: "0".repeat(64),
            release: vec!["true".to_string()],
            released_at: None,
            service: Some("qwen".to_string()),
        };
        let served = infra::Connection {
            ssh: None,
            endpoint: Some(infra::InferenceEndpoint {
                base_url: "https://api.deepinfra.com/v1/openai".to_string(),
                model: "deploy_id:dep-1".to_string(),
                api_key_env: "DEEPINFRA_API_KEY".to_string(),
            }),
            endpoints: Default::default(),
            read: Vec::new(),
        };
        let deployment = endpoint_of_acquired(&row, &served);
        assert_eq!(deployment.kind, EndpointKind::Deployment);
        assert_eq!(deployment.name, "qwen");
        assert_eq!(
            deployment.base_url.as_deref(),
            Some("https://api.deepinfra.com/v1/openai")
        );
        assert_eq!(deployment.model.as_deref(), Some("deploy_id:dep-1"));
        assert_eq!(deployment.api_key_env.as_deref(), Some("DEEPINFRA_API_KEY"));
        assert_eq!(
            deployment.expires_at.as_deref(),
            Some("2026-09-24T00:00:00Z")
        );
        let artifact = serde_json::to_value(&deployment).unwrap();
        assert_eq!(artifact["kind"], "deployment");
        assert!(
            !artifact.to_string().contains("sk-"),
            "no key value anywhere: {artifact}"
        );

        let mut unnamed = row.clone();
        unnamed.service = None;
        let pod = endpoint_of_acquired(&unnamed, &infra::Connection::default());
        assert_eq!(pod.kind, EndpointKind::Pod);
        assert_eq!(pod.name, "dep-1", "no service, so the platform id names it");
        assert!(pod.base_url.is_none() && pod.model.is_none() && pod.api_key_env.is_none());
        let artifact = serde_json::to_value(&pod).unwrap();
        assert!(
            artifact.get("base_url").is_none(),
            "absent, not null: {artifact}"
        );
    }

    /// **Static rows are the operator's, verbatim, and a field this
    /// tool does not know is refused by name** — a typo in `api_key_env`
    /// silently dropped would be a row with no key that looked complete.
    #[test]
    fn static_rows_are_read_verbatim_and_unknown_fields_are_refused() {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-inventory-static-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoints.json");
        std::fs::write(
            &path,
            r#"[{"name": "deepinfra-ds", "base_url": "https://api.deepinfra.com/v1/openai",
                 "model": "deepseek-ai/DeepSeek-V4-Flash", "api_key_env": "DEEPINFRA_API_KEY",
                 "provider": "deepinfra"},
                {"name": "bare", "base_url": "http://127.0.0.1:8000/v1"}]"#,
        )
        .unwrap();
        let rows = static_rows(&path).expect("two well-formed rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, EndpointKind::Serverless);
        assert_eq!(rows[0].name, "deepinfra-ds");
        assert_eq!(rows[0].api_key_env.as_deref(), Some("DEEPINFRA_API_KEY"));
        assert_eq!(
            rows[0].provider.as_deref(),
            Some("deepinfra"),
            "the platform the operator named is the word the price record joins on"
        );
        assert_eq!(rows[1].model, None);
        assert_eq!(rows[1].source, path.display().to_string());

        std::fs::write(
            &path,
            r#"[{"name": "x", "base_url": "u", "api_key": "sk-live"}]"#,
        )
        .unwrap();
        let refusal = static_rows(&path).expect_err("a key value is not a field of a row");
        assert!(
            refusal.contains("`api_key`")
                && refusal.contains("api_key_env")
                && refusal.contains("provider")
                && refusal.contains("price"),
            "the refusal names every field a row may carry: {refusal}"
        );

        std::fs::write(&path, r#"{"name": "x"}"#).unwrap();
        assert!(static_rows(&path).unwrap_err().contains("not a JSON array"));

        // The whole inventory, from these sources: no record, no
        // forwards, the static file — reads as the static rows alone,
        // complete.
        let none = dir.join("absent.jsonl");
        std::fs::write(
            &path,
            r#"[{"name": "only", "base_url": "http://127.0.0.1:1/v1"}]"#,
        )
        .unwrap();
        let inventory = endpoints(&EndpointSources {
            acquisitions: &none,
            forwards: &none,
            statics: Some(&path),
            prices: &none,
        });
        assert!(inventory.complete(), "{:?}", inventory.failed);
        assert_eq!(inventory.rows.len(), 1);
        assert_eq!(
            inventory.artifact()["endpoints"][0]["name"],
            serde_json::json!("only")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A price is a join, not a field a source carries** — and the
    /// operator's word about their own row beats the record. A static
    /// row that names a platform and a model is priced by the newest
    /// record row for that pair; one carrying its own amounts keeps
    /// them; one the join has nothing to stand on carries no price,
    /// since an unpriced endpoint is not one that costs nothing.
    #[test]
    fn a_static_row_carries_its_own_price_or_the_records_newest() {
        use lm_provision_protocol::price::{append, Price};
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-inventory-priced-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let record = dir.join("prices.jsonl");
        let row = |input: &str, output: &str, as_of: &str| PriceRow {
            provider: "deepinfra".to_string(),
            model: "deepseek-ai/DeepSeek-V4-Flash".to_string(),
            price: Price {
                input: input.to_string(),
                output: output.to_string(),
                cache_read: None,
                cache_write: None,
                reasoning: None,
            },
            unit: UNIT_USD_PER_MTOK.to_string(),
            as_of: as_of.to_string(),
            source: "https://deepinfra.com/pricing".to_string(),
        };
        append(&record, &row("0.30", "0.44", "2026-09-01T00:00:00Z")).unwrap();
        append(&record, &row("0.28", "0.42", "2026-09-22T00:00:00Z")).unwrap();

        let path = dir.join("endpoints.json");
        std::fs::write(
            &path,
            r#"[{"name": "from-record", "base_url": "https://api.deepinfra.com/v1/openai",
                 "provider": "deepinfra", "model": "deepseek-ai/DeepSeek-V4-Flash"},
                {"name": "own-price", "base_url": "https://api.deepinfra.com/v1/openai",
                 "provider": "deepinfra", "model": "deepseek-ai/DeepSeek-V4-Flash",
                 "price": {"input": "0.25", "output": "0.50",
                           "as_of": "2026-09-20T00:00:00Z"}},
                {"name": "no-model", "base_url": "http://127.0.0.1:8000/v1",
                 "provider": "deepinfra"}]"#,
        )
        .unwrap();

        let absent = dir.join("absent.jsonl");
        let inventory = endpoints(&EndpointSources {
            acquisitions: &absent,
            forwards: &absent,
            statics: Some(&path),
            prices: &record,
        });
        assert!(inventory.complete(), "{:?}", inventory.failed);
        assert_eq!(inventory.rows.len(), 3);

        let joined = inventory.rows[0]
            .price
            .as_ref()
            .expect("the record prices this pair");
        assert_eq!(
            joined.amounts.input, "0.28",
            "the newest row for the pair, not the first one written"
        );
        assert_eq!(joined.amounts.output, "0.42");
        assert_eq!(joined.unit, UNIT_USD_PER_MTOK);
        assert_eq!(joined.as_of, "2026-09-22T00:00:00Z");
        assert_eq!(
            joined.source, "https://deepinfra.com/pricing",
            "where the amounts were read, carried out of the record row"
        );

        let own = inventory.rows[1]
            .price
            .as_ref()
            .expect("the operator priced this row");
        assert_eq!(
            own.amounts.input, "0.25",
            "the operator's word about their own row beats the record"
        );
        assert_eq!(own.as_of, "2026-09-20T00:00:00Z");
        assert_eq!(
            own.source,
            path.display().to_string(),
            "the file the amounts were written in is the source"
        );

        assert!(
            inventory.rows[2].price.is_none(),
            "a row naming no model gives the join nothing to stand on"
        );

        let artifact = serde_json::to_value(&inventory.rows[0]).unwrap();
        assert_eq!(artifact["price"]["input"], serde_json::json!("0.28"));
        assert_eq!(artifact["price"]["unit"], serde_json::json!("usd_per_mtok"));
        assert!(
            artifact["price"].get("cache_write").is_none(),
            "absent is not zero, so the key is not written: {artifact}"
        );
        let unpriced = serde_json::to_value(&inventory.rows[2]).unwrap();
        assert!(
            unpriced.get("price").is_none(),
            "no price, no key: {unpriced}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A static price this host could not use is refused by field**,
    /// through the same check a record row passes ([`PriceRow::check`]):
    /// an amount or an instant the record would refuse is refused on a
    /// static row too, and a mistyped amount is named rather than
    /// dropped — a price missing its cache rate would otherwise look
    /// complete.
    #[test]
    fn a_static_price_that_cannot_be_read_is_refused_by_field() {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-inventory-price-refused-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoints.json");
        let refusal_for = |price: &str| {
            std::fs::write(
                &path,
                format!(
                    r#"[{{"name": "x", "base_url": "u", "provider": "deepinfra",
                          "model": "m", "price": {price}}}]"#
                ),
            )
            .unwrap();
            static_rows(&path).expect_err("this price cannot be read")
        };

        let refusal =
            refusal_for(r#"{"input": "1.2.3", "output": "1", "as_of": "2026-09-22T00:00:00Z"}"#);
        assert!(
            refusal.contains("input") && refusal.contains("1.2.3"),
            "{refusal}"
        );

        let refusal = refusal_for(r#"{"input": "1", "output": "1", "as_of": "2026-09-22"}"#);
        assert!(refusal.contains("as_of"), "{refusal}");

        let refusal = refusal_for(
            r#"{"input": "1", "output": "1", "as_of": "2026-09-22T00:00:00Z", "cache_reed": "0"}"#,
        );
        assert!(refusal.contains("cache_reed"), "{refusal}");

        let refusal = refusal_for(r#"{"output": "1", "as_of": "2026-09-22T00:00:00Z"}"#);
        assert!(refusal.contains("input"), "{refusal}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// **A record that cannot be read prices nothing, and says so.** It
    /// is one entry in `failed` under its own path and costs the run
    /// its completeness; the rows it would have priced are still
    /// listed, because what the inventory is for — where the endpoints
    /// are — does not depend on what they cost.
    #[test]
    fn a_price_record_that_cannot_be_read_lands_in_failed_and_prices_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "lm-provision-inventory-price-unreadable-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let record = dir.join("prices.jsonl");
        std::fs::write(&record, "not json\n").unwrap();
        let path = dir.join("endpoints.json");
        std::fs::write(
            &path,
            r#"[{"name": "ds", "base_url": "https://api.deepinfra.com/v1/openai",
                 "provider": "deepinfra", "model": "deepseek-ai/DeepSeek-V4-Flash"}]"#,
        )
        .unwrap();

        let absent = dir.join("absent.jsonl");
        let inventory = endpoints(&EndpointSources {
            acquisitions: &absent,
            forwards: &absent,
            statics: Some(&path),
            prices: &record,
        });
        assert_eq!(inventory.rows.len(), 1, "the row is still listed");
        assert!(
            inventory.rows[0].price.is_none(),
            "a record nobody could read prices nothing"
        );
        assert_eq!(inventory.failed.len(), 1, "{:?}", inventory.failed);
        assert_eq!(inventory.failed[0].0, record.display().to_string());
        assert!(!inventory.complete());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The kernel's start time is readable for a live process and absent
    /// for a pid nothing holds.
    #[test]
    fn a_start_time_is_read_for_a_live_process_and_absent_otherwise() {
        if std::path::Path::new("/proc/self/stat").exists() {
            assert!(process_start_time(std::process::id()).is_some());
        }
        assert_eq!(process_start_time(0), None);
    }
}
