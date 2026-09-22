//! The targets a machine can be placed on, and what each can provide.
//!
//! [`Infra`] is to the machine what [`crate::transport::Transport`] is to
//! reaching it: the port in the ports-and-adapters sense, with one
//! implementation per target. It is not called `Port` because a profile's
//! requirements are about network ports, and two meanings of that word in
//! one file would cost more than the convention is worth — `Transport`
//! set that precedent, naming itself for what it does.
//!
//! # Two adapters from the start, deliberately (and a fourth since)
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
//! refusal path is real rather than theoretical. [`VastAdapter`] and
//! [`DeepInfraAdapter`] came after, each with a shape the first two do
//! not have — offers selected before create, and a machine with an
//! address and no mapping at all.
//!
//! # What an adapter does not do
//!
//! It does not create infrastructure. A network, a firewall rule, a
//! subnet, a key: assumed to exist, and named — when a target needs to
//! be told which one — through the profile's `provider` slot. See
//! [`lm_provision::machine`] for why that line is where it is.

use std::collections::BTreeMap;

use lm_provision::machine::{
    gb_to_mib, Answer, Capability, DiskRequirement, Exposure, GpuRequirement, MachineState,
    Requirements,
};

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

    /// The environment variables this target's tooling reads its
    /// credential from, **by name**.
    ///
    /// Declared by the adapter because the adapter is what knows the
    /// target. A tool that starts machines owns the means of starting
    /// them, and on a paid target that means includes a credential; the
    /// alternative is not "no credential", it is a credential nobody is
    /// responsible for arranging. See [`crate::credentials`].
    ///
    /// Names only. Nothing in this module ever binds the value — it
    /// travels from the environment into the child process by
    /// inheritance, and never through here.
    ///
    /// Empty for a target that needs none, which is a real answer.
    ///
    /// Also empty for a target whose tooling holds its own key — the
    /// vast CLI reads the file its `set api-key` wrote and never the
    /// environment, so there is no name to require here and a missing
    /// key surfaces as that CLI's own error, before anything is spent.
    fn credentials(&self) -> &'static [&'static str];

    /// Whether this target can give the workload the accelerators it
    /// asked for, and — when a choice was involved — which ones.
    ///
    /// Separate from [`Infra::capability`] because the answer is not a
    /// yes or a no. A target may be unable to *decide*: a container
    /// runtime cannot select on memory size, so whether the host it
    /// lands on has enough is settled by looking at the machine rather
    /// than by reading the adapter.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer;

    /// Whether this target can give the workload the storage it asked
    /// for.
    ///
    /// Same shape as [`Infra::gpu_answer`] and for the same reason: a
    /// target may be able to *provide* persistence without being able to
    /// *size* it, and neither yes nor no describes that.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer;

    /// The request that would bring a machine meeting `required` into
    /// existence.
    ///
    /// **Rendered, not sent.** Returning the request rather than
    /// performing it keeps the one operation here that spends money and
    /// changes state outside anything that runs by accident: a caller
    /// has to take this and execute it deliberately. It is also what
    /// makes the shape testable without a machine, and what lets a
    /// `plan` show an operator the acquisition before it happens.
    ///
    /// `expires_at` is the lease the machine is being bought under, and
    /// the adapter writes it **onto the machine** as
    /// [`expiry_stamp`] in whatever field the platform lets an operator
    /// name a resource. That is what makes [`Fleet`] enforcement
    /// possible: the sweeper reads the expiry off the thing it is about
    /// to kill rather than off a file that may have been lost. It is a
    /// parameter of the request rather than something stamped onto the
    /// result afterwards because the request is built in one pass — a
    /// later mutation would have to parse the body back and could
    /// silently do nothing, which is precisely the failure (a machine
    /// running without an expiry on it) this exists to prevent.
    ///
    /// `None` when there is no lease to write: a caller that only wants
    /// the release template out of the rendering is not buying anything.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError>;

    /// How to ask this target what it is running, and how to read the
    /// answer — the enumerate-and-kill surface a sweeper works from.
    ///
    /// **This is the inventory, and the acquisitions record is not.**
    /// A record can be lost, moved, or written on one host while the
    /// machine is billed to another; the platform's own list cannot be,
    /// because the list *is* the fleet. Every established reaper works
    /// this way round (Netflix's Janitor Monkey, `aws-nuke`,
    /// `cloud-nuke`, the AWS Instance Scheduler, the Kubernetes TTL
    /// controllers): enumerate from the API, read the policy off the
    /// resource's own tag or label, act. Anything holding a credential
    /// can then enforce leases with no state to keep in step.
    ///
    /// `None` for a target that cannot be asked — which is a real
    /// answer, not a gap: nothing is acquired on it either.
    fn fleet(&self) -> Option<Fleet>;

    /// Read what [`Acquisition::inspect`] returned into the state
    /// [`lm_provision::machine::observe`] judges.
    ///
    /// **Absent means not observed.** A field this cannot find is left
    /// `None` rather than defaulted, because a zero would be a claim
    /// about the machine that nothing made.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState;

    /// The provider key this target reads its base image from, when it
    /// takes one — what `acquire` preflights against the image's own
    /// registry before anything is created to pull it and fail
    /// (`crate::image`).
    ///
    /// `None` for a target that takes no image, which is a real answer:
    /// there is nothing to preflight.
    fn image_key(&self) -> Option<&'static str>;

    /// Whether the platform says this machine is still being brought
    /// into existence — pulling its image, starting its container.
    ///
    /// Read by `acquire`'s bounded wait: a deadline reached while the
    /// service itself reports *still loading* is not a machine that
    /// failed to answer, it is a question asked too early, and giving
    /// up on it judged a good machine `NotChecked` [measured:
    /// 2026-08-30, a marketplace instance was still pulling a
    /// multi-gigabyte image when the 300s wait expired]. `false` when
    /// the platform makes no such claim — absence of "loading" is not
    /// evidence of readiness, and the port wait still decides.
    fn still_materializing(&self, inspected: &serde_json::Value) -> bool;

    /// Read the same description into how the machine is **reached** —
    /// the caller's half of spec 08's `ConnectionSpec`, projected from
    /// where this platform writes its addresses.
    ///
    /// Per-platform by necessity: the requirement vocabulary is the
    /// workload's, but where the resulting address lands is each
    /// service's own (a managed pod service writes `publicIp` +
    /// `portMappings`; a container runtime would write host port
    /// bindings). Before this existed, every caller re-derived the
    /// address by querying the service directly — which meant arranging
    /// the service credential in the caller's own shell for a fact the
    /// driver had already paid to learn [measured: 2026-08-30, the
    /// artifacts verification script polled `get-pod` by hand and
    /// spun on a missing `RUNPOD_API_KEY`].
    ///
    /// Absent means not reachable **yet**, same rule as
    /// [`Infra::read_state`]: a machine still booting answers with an
    /// empty projection, not a guess.
    fn connection(&self, inspected: &serde_json::Value) -> Connection;
}

/// How to reach a machine, as the platform reports it — the created
/// side of spec 08's `ConnectionSpec` input (§Session contract).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct Connection {
    /// The SSH endpoint a driver session can be pointed at, when the
    /// machine exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshEndpoint>,
    /// The inference endpoint the machine answers at, when the machine
    /// *is* a served model rather than a host — a managed deployment
    /// projects this and no `ssh`. The row an endpoint inventory or a
    /// router's configuration is generated from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<InferenceEndpoint>,
    /// Every declared port's public address, as `machine port →
    /// "host:port"` — what a caller polls a health check against
    /// without asking the service where things landed.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<u16, String>,
    /// What the projection read to arrive at the above, one `field:
    /// shape` entry per field the adapter consulted (`publicIp: empty`,
    /// `portMappings: [22]`, `ssh_port: absent`) — presence and shape,
    /// never a value.
    ///
    /// For the operator who is refused because `ssh` is `None`: an
    /// empty projection says only "no endpoint", and whether that is a
    /// pod still booting or a description that came back without the
    /// field cannot be told from the outside [measured: 2026-09-20, a
    /// RUNNING pod's read-back projected to no endpoint once, with the
    /// three read-backs after it complete — nothing recorded which
    /// field was missing]. Not serialized: `machine acquire`'s artifact
    /// is a caller's input, and this is a diagnostic.
    #[serde(skip)]
    pub read: Vec<String>,
}

/// The `field: shape` entry [`Connection::read`] carries for one
/// string-valued field: present, empty, or absent.
fn read_text(inspected: &serde_json::Value, key: &str) -> String {
    let shape = match inspected.get(key).and_then(|it| it.as_str()) {
        Some("") => "empty",
        Some(_) => "present",
        None => "absent",
    };
    format!("{key}: {shape}")
}

/// The `field: shape` entry for a field expected to be an object keyed
/// by port: its keys, or why there are none.
fn read_keys(inspected: &serde_json::Value, key: &str) -> String {
    match inspected.get(key) {
        Some(serde_json::Value::Object(map)) => {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            format!("{key}: [{}]", keys.join(", "))
        }
        Some(serde_json::Value::Null) => format!("{key}: null"),
        Some(_) => format!("{key}: not an object"),
        None => format!("{key}: absent"),
    }
}

/// One OpenAI-compatible inference endpoint, in the fields a consumer
/// needs to send a request: where, which model, and which variable
/// holds the key. The key's **name**, never its value — the same rule
/// as everywhere else this crate handles a credential.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InferenceEndpoint {
    /// The base URL an OpenAI client is pointed at (`…/v1` or the
    /// platform's equivalent), without a path beyond it.
    pub base_url: String,
    /// What to send as `model` — the platform's own reference to this
    /// deployment, which on a platform whose model name carries the
    /// lease is the deployment's id rather than that name.
    pub model: String,
    /// The environment variable the platform's key is read from, by
    /// the platform's own name for it.
    pub api_key_env: String,
}

/// One SSH endpoint, in the fields spec 08's `ConnectionSpec` takes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SshEndpoint {
    /// Host name or address.
    pub host: String,
    /// TCP port the machine's sshd is reachable on.
    pub port: u16,
    /// Remote user ([`crate::ssh::DEFAULT_SSH_USER`] on a platform
    /// that runs workloads as root).
    pub user: String,
}

/// What to run to obtain a machine, and what to run to give it back.
///
/// Both halves together, because an acquisition whose release is worked
/// out later is an acquisition that leaks — this repo has leaked two
/// machines by hand for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acquisition {
    /// What to run first, when the target sells *offers* rather than
    /// letting a create call describe a machine: prints a JSON array of
    /// candidates, and the first row's `id` fills `{offer_id}` in
    /// `create`.
    ///
    /// **The query carries the policy.** Which offers qualify and which
    /// comes first are written into this argv as the service's own
    /// filter and sort words — so the selection stays data an operator
    /// can read in a dry-run, and this module needs no callback to ask
    /// an adapter "which one?". Taking the first row of a query that
    /// sorts by price *is* taking the cheapest thing that qualifies.
    ///
    /// `None` for a target whose create call selects by itself.
    pub discover: Option<Vec<String>>,
    /// The program and arguments that create the machine.
    pub create: Vec<String>,
    /// The request body, when the create call takes one.
    pub body: Option<String>,
    /// The key the create response names the new machine under.
    ///
    /// Each service's own word: `id` on one, `new_contract` on another
    /// — and the whole reason [`acquire`] cannot hardcode either is
    /// that a machine created under a key nobody read is a bill nobody
    /// can stop (see [`ExecuteError::Anonymous`]).
    pub created_id_key: &'static str,
    /// How to read back what was created, given its id.
    ///
    /// `{id}` is replaced with the identifier the create call returns.
    pub inspect: Vec<String>,
    /// How to destroy it, with the same substitution.
    pub release: Vec<String>,
}

/// How to enumerate the machines a target is running for this account,
/// and how to destroy one — [`Infra::fleet`]'s answer.
///
/// Argv plus the two field names the rows are read by, in the same
/// shape [`Acquisition`] takes, and for the same reason: the platform's
/// own CLI already speaks its API, and the useful thing this repo adds
/// is the requirements, not a second REST client tracking somebody
/// else's schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fleet {
    /// What to run to list this account's machines. Prints JSON.
    pub list: Vec<String>,
    /// The key each listed row names the machine under.
    pub id: &'static str,
    /// The key each row carries its operator-set text under — `name` on
    /// one platform, `label` on another. Where [`expiry_stamp`] rides.
    pub stamp: &'static str,
    /// Whether the platform returns that field under its own namespace
    /// — `<account>/<what the operator wrote>` — so that the operator's
    /// text is what follows the last slash. `false` on a platform that
    /// returns the field as written: a slash in one of those names is
    /// the operator's own, and reading past it would misread a name.
    pub stamp_namespaced: bool,
    /// How to destroy one, `{id}` unsubstituted — the same template
    /// [`Acquisition::release`] carries, from the same source, so a
    /// machine released off the record and one released off the list
    /// are released by the same command.
    pub release: Vec<String>,
    /// How to read back one machine, `{id}` unsubstituted — again the
    /// template [`Acquisition::inspect`] carries, from the same
    /// source.
    ///
    /// What it buys: a machine can be asked about by its id alone,
    /// with nothing written down. That is how an operator who has only
    /// the identifier the platform printed reaches the machine's own
    /// address ([`Infra::connection`]) instead of hand-carrying a
    /// `host:port` out of whatever printed it last.
    pub inspect: Vec<String>,
}

/// One machine a target says it is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    /// The identifier the platform lists it under — what a release
    /// substitutes into [`Fleet::release`].
    pub id: String,
    /// The operator-set text on it, when it carries any. `None` is a
    /// machine nothing named: it may be somebody else's work, and
    /// [`expiry_of`] refuses to read a lease into silence.
    pub name: Option<String>,
}

/// The adapter sold under `name`, or which names would have worked.
///
/// A static reference rather than a box because the adapters are unit
/// structs: there is nothing to construct, only one of four
/// vocabularies to speak.
///
/// Here rather than beside the caller because there are now three
/// callers — the operator CLI, the MCP server's listing tool, and
/// [`crate::inventory`] between them — and a second `match` on these
/// names would be a second place a target has to be wired into.
pub fn adapter_named(name: &str) -> Result<&'static dyn Infra, String> {
    match name {
        "runpod" => Ok(&RunPodAdapter),
        "vast" => Ok(&VastAdapter),
        "deepinfra" => Ok(&DeepInfraAdapter),
        "deepinfra-deploy" => Ok(&DeepInfraDeployAdapter),
        other => Err(format!(
            "unknown provider `{other}` (runpod, vast, deepinfra, deepinfra-deploy)"
        )),
    }
}

/// The prefix that marks a name as this tool's lease stamp.
///
/// Fixed, and matched exactly: a machine named anything else was not
/// stamped by this tool, and a sweeper that guessed would be deleting
/// somebody's work on the strength of a naming coincidence.
pub const EXPIRY_PREFIX: &str = "lmp-exp-";

/// The lease, written the way it can ride on a machine's own name.
///
/// [`EXPIRY_PREFIX`] then RFC 3339 UTC with the separators taken out:
/// `lmp-exp-20260902T063000Z`. Colon-free because these land in fields
/// each platform constrains its own way, and a colon is the character
/// most likely to be one of the ones they refuse.
///
/// **Second granularity**, so this is the recorded `expires_at`
/// truncated rather than reproduced: the record keeps whatever
/// precision the clock gave it, and the machine carries the second the
/// lease ends. A sweep can therefore find a machine due up to a second
/// before the record says so, which is the harmless direction — the
/// lease was bought in hours.
pub fn expiry_stamp(expires_at: jiff::Timestamp) -> String {
    format!("{EXPIRY_PREFIX}{}", expires_at.strftime("%Y%m%dT%H%M%SZ"))
}

/// The lease [`expiry_stamp`] wrote, read back — or `None` for anything
/// else.
///
/// Tolerant of nothing: the whole field must be the prefix and a
/// well-formed compact timestamp. A machine whose name this cannot read
/// is *unknown*, which is a thing to report and never a thing to
/// delete.
///
/// The fixed-width form is rebuilt into ordinary RFC 3339 and handed to
/// the same parser the record's timestamps go through, rather than
/// matched by a format string: the digits run together here, so what
/// rejects `lmp-exp-20261301T000000Z` is a real date parse and not a
/// length check.
pub fn expiry_of(name: &str) -> Option<jiff::Timestamp> {
    let compact = name.strip_prefix(EXPIRY_PREFIX)?.strip_suffix('Z')?;
    let (date, time) = compact.split_once('T')?;
    if date.len() != 8 || time.len() != 6 {
        return None;
    }
    if !date
        .bytes()
        .chain(time.bytes())
        .all(|it| it.is_ascii_digit())
    {
        return None;
    }
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &date[..4],
        &date[4..6],
        &date[6..],
        &time[..2],
        &time[2..4],
        &time[4..],
    )
    .parse()
    .ok()
}

/// The machines in what a [`Fleet::list`] printed — or why the
/// document cannot be read as a fleet.
///
/// **The array is found rather than assumed at the root.** One CLI
/// prints the rows as the whole document and another wraps them in an
/// object under a name of its own choosing, and which of those a
/// sweeper is looking at is not something the enforcement should turn
/// on. When the wrapper holds several arrays, the rows are the one
/// whose entries carry the [`Fleet::id`] key — taking the *first*
/// array would let an empty sibling (`"errors": []` sorts before
/// `"pods"`) shadow the fleet entirely.
///
/// **A listing this cannot read is an error, never an empty fleet.**
/// The caller treats "listed, and absent from the list" as proof a
/// recorded machine is gone and retires its row (see the sweep's
/// bookkeeping) — so a shape change that silently read as zero
/// machines would retire the whole record while every machine on it
/// kept billing. Only a document whose rows are genuinely empty is an
/// empty account. A single unreadable row among readable ones is still
/// skipped: nothing could be released from it, and inventing an
/// identifier for it would be worse than leaving it out.
pub fn machines(listed: &serde_json::Value, fleet: &Fleet) -> Result<Vec<Machine>, String> {
    let rows = match listed {
        serde_json::Value::Array(rows) => rows,
        serde_json::Value::Object(fields) => {
            let arrays: Vec<&Vec<serde_json::Value>> =
                fields.values().filter_map(|it| it.as_array()).collect();
            match arrays
                .iter()
                .copied()
                .find(|rows| rows.iter().any(|row| row.get(fleet.id).is_some()))
            {
                Some(rows) => rows,
                // Every array is empty: an empty account, whichever of
                // them is the rows.
                None if !arrays.is_empty() && arrays.iter().all(|it| it.is_empty()) => {
                    return Ok(Vec::new())
                }
                None => {
                    return Err(format!(
                        "no field in the listing holds rows carrying {:?}",
                        fleet.id
                    ))
                }
            }
        }
        _ => return Err("the listing is neither an array nor an object".to_string()),
    };
    let read: Vec<Machine> = rows
        .iter()
        .filter_map(|row| {
            Some(Machine {
                id: json_id(row, fleet.id)?,
                name: row
                    .get(fleet.stamp)
                    .and_then(|it| it.as_str())
                    .map(|it| {
                        if fleet.stamp_namespaced {
                            it.rsplit('/').next().unwrap_or(it)
                        } else {
                            it
                        }
                    })
                    .filter(|it| !it.is_empty())
                    .map(str::to_string),
            })
        })
        .collect();
    if read.is_empty() && !rows.is_empty() {
        return Err(format!(
            "none of the {} listed rows carries a readable {:?}",
            rows.len(),
            fleet.id
        ));
    }
    Ok(read)
}

/// What a target is running, and what it said while being asked.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The machines, as [`machines`] read them.
    pub machines: Vec<Machine>,
    /// The platform CLI's own stderr, for the caller to relay under
    /// that CLI's name — this module never writes to a stream.
    pub said: Vec<u8>,
}

/// Ask a target what it is running.
///
/// A read, and the only one here that needs the account's credential
/// without spending anything: the key buys the question, not an
/// answer that costs money.
pub fn list(fleet: &Fleet) -> Result<Listing, ExecuteError> {
    let output = run_output(&fleet.list, None)?;
    let command = fleet.list.join(" ");
    let listed = payload(&String::from_utf8_lossy(&output.stdout), &command)?;
    Ok(Listing {
        machines: machines(&listed, fleet)
            .map_err(|detail| ExecuteError::Unreadable { command, detail })?,
        said: output.stderr,
    })
}

/// Ask a target about **one** machine, by the id it lists it under.
///
/// The read [`Acquired::inspect`] performs, for a caller that never
/// held an [`Acquired`]: the machine may have been created in another
/// process, another day, or by an operator at a terminal, and the
/// identifier is the whole of what is needed to ask about it.
///
/// **Nothing fills the blanks here.** [`Acquired::inspect`] restores
/// what the creation-time description said and this cannot, because
/// there is no creation-time description in reach — so a field the
/// platform states only when it creates a machine (the managed pod
/// service's `machine.gpuTypeId`, which comes back `{}` from every
/// read-back afterwards) is **absent** from what this returns, and a
/// caller reading it for the requirements would find them
/// `NotChecked`. What it is for is [`Infra::connection`], which reads
/// `publicIp` and `portMappings` — fields a read-back always carries,
/// because they are what the platform learned *after* the create.
pub fn inspect(fleet: &Fleet, id: &str) -> Result<serde_json::Value, ExecuteError> {
    run_json(&substitute(&fleet.inspect, id), None)
}

/// An acquisition that cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcquisitionError {
    /// This target has no acquisition wired.
    #[error("{target} cannot acquire a machine here: {reason}")]
    Unsupported {
        /// Which target.
        target: &'static str,
        /// Why not.
        reason: &'static str,
    },

    /// A requirement this target needs in order to create anything.
    #[error("{target} needs {missing} to create a machine")]
    Incomplete {
        /// Which target.
        target: &'static str,
        /// What was not declared.
        missing: &'static str,
    },

    /// The adapter answered that it cannot meet a requirement.
    ///
    /// Rendering a request anyway would produce a machine that is not
    /// what was asked for, and the missing part would be found — if at
    /// all — by whatever failed later. The first version of this code
    /// did exactly that: a memory floor beyond the catalogue dropped the
    /// model selection and returned a request that looked fine
    /// [measured: 2026-08-12, `min_vram_gb: 512` produced a body with
    /// `gpuCount` and no `gpuTypeIds`, exit 0].
    #[error("{target} cannot meet a requirement: {reason}")]
    Unmet {
        /// Which target.
        target: &'static str,
        /// The adapter's own words.
        reason: String,
    },
}

/// The answer's `using`, or the refusal an adapter that builds the
/// request has to make of anything short of `Met`.
///
/// `NotExamined` is refused here as well as `Unmet`, deliberately: on a
/// target that selects the machine, a requirement the adapter could not
/// decide is one it cannot ask for, and a request sent without it would
/// produce a machine that is not what was declared — the failure
/// [`AcquisitionError::Unmet`] records. The container runtime, which
/// builds no request, is where `NotExamined` stays an honest answer.
fn admitted(target: &'static str, answer: Answer) -> Result<Vec<String>, AcquisitionError> {
    match answer {
        Answer::Met { using } => Ok(using),
        Answer::Unmet { reason } => Err(AcquisitionError::Unmet { target, reason }),
        Answer::NotExamined { reason } => Err(AcquisitionError::Unmet {
            target,
            reason: format!(
                "{reason} — this target selects the machine, so a requirement it \
                 cannot decide is one it cannot ask for"
            ),
        }),
    }
}

/// A GPU model, how much memory it carries, and what renting one costs.
///
/// **This table is adapter knowledge, and that is the point.** A managed
/// pod service selects by model name from its own catalogue and has no
/// memory field at all, so somebody has to know which models carry 24 GB
/// — and the only party that should is the one whose catalogue it is. In
/// the vocabulary it would be one vendor's price list embedded in every
/// profile.
struct Gpu {
    /// The name the service's API expects.
    id: &'static str,
    /// Memory per device as the vendor publishes it, in decimal
    /// gigabytes.
    ///
    /// The published figure and not the reported one: a part sold as 48
    /// answers 46068 MiB, and no row here could carry that number
    /// honestly because it moves with ECC mode and driver. This is
    /// matched against a profile's floor, which is written in the same
    /// terms, and converted through
    /// [`lm_provision::machine::gb_to_mib`] on the one path where a
    /// device's own unit is wanted.
    vram_gb: u32,
    /// The published secure-cloud on-demand rate, in US cents per hour
    /// — the ordering key for [`RunPodAdapter::gpu_answer`]'s selection.
    ///
    /// Published rather than live because the REST surface the driver
    /// speaks has no pricing endpoint [measured: 2026-08-30, the
    /// service CLI's command list — pods / billing / templates and
    /// friends, nothing that quotes a GPU type], and a live quote would
    /// mean a second API with its own credential exposure. What the
    /// selection needs from this column is the *ordering* of the
    /// models, which moves far more slowly than the figures themselves;
    /// a stale absolute here mis-sorts nothing until two models cross.
    /// Secure-cloud because the create body sets no `cloudType` and
    /// `SECURE` is the documented default [documented:
    /// docs.runpod.io/api-reference, POST /pods, `cloudType`]. Figures
    /// read 2026-08-30 from runpod.io/pricing.
    usd_cents_hr: u32,
}

/// A subset of the service's catalogue, largest-selling models first.
///
/// **Deliberately partial.** The catalogue runs to about fifty entries
/// [measured: `PodCreateInput.gpuTypeIds`, 49 values] and grows with the
/// service's hardware; carrying all of it here would be a second copy of
/// somebody else's list, going stale on their release schedule rather
/// than this repo's. What is here is enough to select against, and an
/// absent model costs a profile nothing it could not get by naming the
/// model itself through `provider.runpod.gpuTypeIds`.
const RUNPOD_CATALOGUE: &[Gpu] = &[
    Gpu {
        id: "NVIDIA A40",
        vram_gb: 48,
        usd_cents_hr: 44,
    },
    Gpu {
        id: "NVIDIA L40S",
        vram_gb: 48,
        usd_cents_hr: 99,
    },
    Gpu {
        id: "NVIDIA RTX A6000",
        vram_gb: 48,
        usd_cents_hr: 53,
    },
    Gpu {
        id: "NVIDIA A100 80GB PCIe",
        vram_gb: 80,
        usd_cents_hr: 139,
    },
    Gpu {
        id: "NVIDIA H100 PCIe",
        vram_gb: 80,
        usd_cents_hr: 289,
    },
    Gpu {
        id: "NVIDIA GeForce RTX 4090",
        vram_gb: 24,
        usd_cents_hr: 74,
    },
    Gpu {
        id: "NVIDIA RTX A5000",
        vram_gb: 24,
        usd_cents_hr: 27,
    },
    Gpu {
        id: "NVIDIA L4",
        vram_gb: 24,
        usd_cents_hr: 49,
    },
];

/// A managed GPU-pod service: the machine is one API object, and the
/// service owns the network in front of it.
///
/// Its port form is `[port]/[protocol]`, where the protocol is `http` or
/// `tcp` and selects **how the port is exposed** rather than what speaks
/// over it: `http` puts the port behind the service's own HTTPS reverse
/// proxy, `tcp` maps it to a public port on the machine's address
/// [measured: 2026-08-11 — `8188/http` answered on a proxied `https://` URL,
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

    /// The service CLI takes its key from the environment and from
    /// nowhere else: it has no `--api-key` and reads no configuration
    /// file [measured: 2026-08-12, `runpod-cli --help` offers `--base-url`,
    /// `-o`, `--dry-run`, `-v`]. So a resolution order can only exist
    /// out here, and naming the variable is how it gets one.
    fn credentials(&self) -> &'static [&'static str] {
        &["RUNPOD_API_KEY"]
    }

    /// Selecting the models that carry at least the requested memory,
    /// and saying which.
    ///
    /// **Selection is not substitution.** The requirement was a memory
    /// floor; every model returned clears it. That is a scheduler asked
    /// for four CPUs picking a node with at least four and reporting
    /// which — not the thing the refusal rule forbids, which is handing
    /// back *less* than was declared.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        if required.count == 0 {
            return Answer::met();
        }
        let Some(floor) = required.min_vram_gb else {
            // No floor: the service attaches whatever is available, and
            // there is nothing to choose between.
            return Answer::met();
        };
        let mut fits: Vec<&Gpu> = RUNPOD_CATALOGUE
            .iter()
            .filter(|it| it.vram_gb >= floor)
            .collect();
        if fits.is_empty() {
            return Answer::unmet(format!(
                "no catalogued GPU carries {floor} GB; the largest known here is {} GB \
                 (name a model directly with provider.runpod.gpuTypeIds if the \
                 catalogue is behind)",
                RUNPOD_CATALOGUE
                    .iter()
                    .map(|it| it.vram_gb)
                    .max()
                    .unwrap_or(0),
            ));
        }
        // Cheapest first — by the rate column, not by memory. Memory
        // was the old proxy for price and it lies: at a 24 GB floor it
        // put the RTX 4090 (74¢/hr) ahead of the RTX A5000 (27¢/hr),
        // 2.7× the price for the same clearance [measured: 2026-08-30,
        // runpod.io/pricing]. The requirement was a floor, so the
        // cheapest thing that clears it is the one to ask for, and the
        // rest are fallbacks the service can rent when it is short.
        fits.sort_by_key(|it| (it.usd_cents_hr, it.id));
        Answer::met_using(fits.into_iter().map(|it| it.id))
    }

    /// Both levels are settable: the service takes a size for the disk
    /// that is wiped on restart and a size for the volume that is not,
    /// plus where the second one is mounted.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        let mut using = Vec::new();
        if let Some(gb) = required.ephemeral_gb {
            using.push(format!("containerDiskInGb={gb}"));
        }
        if let Some(gb) = required.persistent_gb {
            using.push(format!("volumeInGb={gb}"));
        }
        if let Some(path) = &required.persistent_at {
            using.push(format!("volumeMountPath={path}"));
        }
        Answer::Met { using }
    }

    /// The service's own CLI, which is generated from its OpenAPI
    /// description and already handles authentication from the
    /// environment.
    ///
    /// Driving that rather than speaking the REST API here is the same
    /// judgement the transport layer makes: the useful thing this repo
    /// adds is the requirements, not a second REST client that has to
    /// track somebody else's schema.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError> {
        // Every answer this adapter would give is taken here and handed
        // to the builder, so the builder cannot reach a requirement
        // without going through the answer for it. Asking inside the
        // builder is what let a floor no device clears reach the request
        // as a silent omission.
        let body = runpod_body(
            required,
            provider,
            self.render(required),
            required.gpu.as_ref().map(|it| self.gpu_answer(it)),
            required.disk.as_ref().map(|it| self.disk_answer(it)),
            expires_at,
        )?;

        Ok(Acquisition {
            // The create call describes the machine itself, so there is
            // nothing to discover first.
            discover: None,
            create: vec![
                "runpod-cli".into(),
                "pods".into(),
                "create-pod".into(),
                "-j".into(),
            ],
            body: Some(body),
            created_id_key: "id",
            inspect: runpod_inspect(),
            release: runpod_release(),
        })
    }

    /// The service lists this account's pods, and every pod carries the
    /// `name` the create call set — which is where `runpod_body` writes
    /// the lease.
    fn fleet(&self) -> Option<Fleet> {
        Some(Fleet {
            list: vec![
                "runpod-cli".into(),
                "pods".into(),
                "list-pods".into(),
                // JSON is this CLI's default output; asked for anyway,
                // because a sweeper that depends on a default is one
                // release of somebody else's tool away from parsing a
                // table.
                "-o".into(),
                "json".into(),
            ],
            id: "id",
            stamp: "name",
            stamp_namespaced: false,
            release: runpod_release(),
            inspect: runpod_inspect(),
        })
    }

    /// The key `runpod_body` requires — one name, two readers.
    fn image_key(&self) -> Option<&'static str> {
        Some("runpod.imageName")
    }

    /// Never claimed: this service's boots answered within the base
    /// wait every time they were measured [measured: 2026-08-12 and
    /// 2026-08-30, port 22 within ~2 minutes of create], and its
    /// descriptions carry no field that says "still starting" the way
    /// the marketplace's `actual_status` does — so nothing is read as
    /// one.
    fn still_materializing(&self, _inspected: &serde_json::Value) -> bool {
        false
    }

    /// Read the service's own pod description.
    ///
    /// The `ports` array comes back in the same `[port]/[protocol]` form
    /// it went out in, so what the machine exposes is read with the same
    /// vocabulary the requirement was written in.
    ///
    /// Device memory is the one field that has to be looked up rather
    /// than read: the description names the model
    /// (`machine.gpuTypeId`) and never the size, which is the same
    /// asymmetry that put the catalogue in this adapter in the first
    /// place. A model outside it leaves the memory unobserved — `None`,
    /// not a guess.
    ///
    /// What the catalogue yields is a published figure, and what the
    /// field wants is what the device reports, so it goes through
    /// [`gb_to_mib`] and arrives as the lower bound that function
    /// documents. This is inference from the model's spec rather than a
    /// measurement, and it is bounded so it cannot claim more than the
    /// part is sold as.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState {
        let number = |value: &serde_json::Value| value.as_u64().map(|it| it as u32);
        let text = |value: &serde_json::Value| value.as_str().map(str::to_string);

        let mut exposed = BTreeMap::new();
        let ports = inspected.get("ports").and_then(|it| it.as_array());
        if let Some(ports) = ports {
            for entry in ports.iter().filter_map(|it| it.as_str()) {
                let Some((port, protocol)) = entry.split_once('/') else {
                    continue;
                };
                let Ok(port) = port.parse::<u16>() else {
                    continue;
                };
                let exposure = match protocol {
                    "http" => Exposure::PublicHttp,
                    "tcp" => Exposure::RawTcp,
                    _ => continue,
                };
                exposed.insert(port, exposure);
            }
        }

        let gpu_vram_mib = inspected
            .get("machine")
            .and_then(|it| it.get("gpuTypeId"))
            .and_then(|it| it.as_str())
            .and_then(|model| {
                RUNPOD_CATALOGUE
                    .iter()
                    .find(|it| it.id == model)
                    .map(|it| gb_to_mib(it.vram_gb))
            });

        // `gpuCount` when the description says it; otherwise a CPU
        // machine still gets an observed zero, because the service
        // *does* say so — `cpuFlavorId` is documented for CPU pods
        // only [documented: docs.runpod.io/api-reference, get pod
        // response schema]. Reading that presence keeps "absent means
        // not observed" intact: the zero comes from a field the
        // service wrote, not from a field it left out. Without it a
        // profile asking `gpu.count = 0` came back `NotChecked` on
        // every CPU pod, so `acquire` exited non-zero on machines that
        // were exactly what was asked for [measured: 2026-08-30, pod
        // verification run, verdict NotChecked on a running CPU pod].
        let gpu_count = inspected.get("gpuCount").and_then(number).or_else(|| {
            inspected
                .get("cpuFlavorId")
                .and_then(|it| it.as_str())
                .filter(|it| !it.is_empty())
                .map(|_| 0)
        });

        MachineState {
            exposed,
            // The description carries the field whether or not anything
            // is in it, so an empty list is "nothing exposed" rather
            // than "nobody looked".
            ports_observed: ports.is_some(),
            gpu_count,
            gpu_vram_mib,
            ephemeral_gb: inspected.get("containerDiskInGb").and_then(number),
            persistent_gb: inspected.get("volumeInGb").and_then(number),
            persistent_at: inspected.get("volumeMountPath").and_then(text),
        }
    }

    /// `publicIp` + `portMappings` — the two fields this service uses
    /// to say where a pod landed, and the two fields the first real
    /// usages read out by hand.
    ///
    /// An empty `publicIp` is what a pod reports while it boots
    /// [measured: 2026-08-12 create response], so empty is treated as
    /// absent — a `""` host is not an address anything can dial.
    fn connection(&self, inspected: &serde_json::Value) -> Connection {
        let ip = inspected
            .get("publicIp")
            .and_then(|it| it.as_str())
            .filter(|it| !it.is_empty());
        let mappings = inspected.get("portMappings").and_then(|it| it.as_object());
        let mut endpoints = BTreeMap::new();
        if let (Some(ip), Some(mappings)) = (ip, mappings) {
            for (private, public) in mappings {
                let (Ok(private), Some(public)) = (private.parse::<u16>(), public.as_u64()) else {
                    continue;
                };
                endpoints.insert(private, format!("{ip}:{public}"));
            }
        }
        let ssh = ip.and_then(|host| {
            mappings?
                .get("22")
                .and_then(|it| it.as_u64())
                .map(|port| SshEndpoint {
                    host: host.to_string(),
                    port: port as u16,
                    user: crate::ssh::DEFAULT_SSH_USER.to_string(),
                })
        });
        Connection {
            ssh,
            endpoint: None,
            endpoints,
            read: vec![
                read_text(inspected, "publicIp"),
                read_keys(inspected, "portMappings"),
            ],
        }
    }
}

/// What reads one pod back, `{id}` unsubstituted.
///
/// One spelling, read by both halves, for the reason `runpod_release`
/// gives below: the acquisition records it so a machine can be asked
/// about from what was written down, and the fleet carries it so a
/// machine the platform lists can be asked about with nothing written
/// down at all.
fn runpod_inspect() -> Vec<String> {
    vec![
        "runpod-cli".into(),
        "pods".into(),
        "get-pod".into(),
        "{id}".into(),
    ]
}

/// What destroys one pod, `{id}` unsubstituted.
///
/// One spelling, read by both halves: the acquisition records it so a
/// machine can be given back from what was written down, and the fleet
/// carries it so a machine the platform lists can be given back with
/// nothing written down at all. Two copies would be two commands that
/// could drift, and the one that drifted would be found by a machine
/// that would not die.
fn runpod_release() -> Vec<String> {
    vec![
        "runpod-cli".into(),
        "pods".into(),
        "delete-pod".into(),
        "{id}".into(),
    ]
}

/// The request body for [`RunPodAdapter::acquisition`], built from the
/// requirements *and the adapter's answers to them*.
///
/// The answers arrive as arguments rather than being asked for here. An
/// adapter that reads a requirement without consulting its own answer
/// can build a request that looks well-formed and asks for a machine
/// nobody promised — which is how a memory floor above every catalogued
/// device once produced a body with no model selection in it and an exit
/// status of success. Taking them as parameters also makes the refusal
/// reachable from a test for storage, where this adapter answers `Met`
/// for everything it is asked today.
///
/// `gpu_answer` / `disk_answer` are `None` exactly when the profile
/// declared no such requirement.
fn runpod_body(
    required: &Requirements,
    provider: &BTreeMap<String, String>,
    ports: Vec<String>,
    gpu_answer: Option<Answer>,
    disk_answer: Option<Answer>,
    expires_at: Option<jiff::Timestamp>,
) -> Result<String, AcquisitionError> {
    // The image comes from the provider slot, not from a requirement:
    // an image name is this platform's vocabulary (a bare-VM service
    // has no such field), so the profile writes it under the platform's
    // own key. The key matches the service's field name, as every
    // `runpod.*` key does.
    let image = provider
        .get("runpod.imageName")
        .ok_or(AcquisitionError::Incomplete {
            target: "runpod",
            missing: "provider.runpod.imageName",
        })?;

    let refuse = |answer: Answer| admitted("runpod", answer);

    let mut body = serde_json::Map::new();
    body.insert("imageName".into(), serde_json::json!(image));

    // Only when the profile asked for something. An empty array is a
    // claim that nothing should be exposed, and a profile that declared
    // no ports did not make it — the service's own default applies
    // instead. Absent is not zero here as it is nowhere else in this
    // vocabulary.
    if !ports.is_empty() {
        body.insert("ports".into(), serde_json::json!(ports));
    }

    if let Some(gpu) = &required.gpu {
        body.insert(
            "computeType".into(),
            serde_json::json!(if gpu.count == 0 { "CPU" } else { "GPU" }),
        );
        if gpu.count > 0 {
            body.insert("gpuCount".into(), serde_json::json!(gpu.count));
            // The models that clear the floor, in the order the answer
            // put them: cheapest first, the rest as what the service can
            // fall back to when it is short.
            let selected = gpu_answer.map(refuse).transpose()?.unwrap_or_default();
            if !selected.is_empty() {
                body.insert("gpuTypeIds".into(), serde_json::json!(selected));
            }
        }
    }

    if let Some(disk) = &required.disk {
        disk_answer.map(refuse).transpose()?;
        if let Some(gb) = disk.ephemeral_gb {
            body.insert("containerDiskInGb".into(), serde_json::json!(gb));
        }
        if let Some(gb) = disk.persistent_gb {
            body.insert("volumeInGb".into(), serde_json::json!(gb));
        }
        if let Some(path) = &disk.persistent_at {
            body.insert("volumeMountPath".into(), serde_json::json!(path));
        }
    }

    // Whatever the profile addressed to this target, verbatim and last,
    // so a network volume named there replaces the sizes above the way
    // the service documents it doing.
    for (key, value) in provider {
        if let Some(field) = key.strip_prefix("runpod.") {
            body.insert(field.to_string(), serde_json::json!(value));
        }
    }

    // The lease, on the machine itself — and after the passthrough
    // above rather than before it, which is the one place in this body
    // where the profile does not get the last word. `name` is a free
    // string the service does not require to be unique [documented:
    // docs.runpod.io/api-reference, POST /pods, `name`], so a profile
    // setting `provider.runpod.name` would otherwise take the machine
    // out of the sweeper's reach — it would list as *unknown*, which is
    // reported and never released, and a machine that cannot expire is
    // the accident this whole mechanism exists to remove.
    if let Some(expires_at) = expires_at {
        body.insert("name".into(), serde_json::json!(expiry_stamp(expires_at)));
    }

    Ok(serde_json::Value::Object(body).to_string())
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

    /// None. The daemon is reached over a local socket whose
    /// permissions are the authorisation, so there is no key to arrange
    /// — an empty list is that answer, not an omission.
    fn credentials(&self) -> &'static [&'static str] {
        &[]
    }

    /// A count it can pass on; a memory floor it cannot decide.
    ///
    /// `--gpus` takes a number or device ids — **there is no way to ask
    /// for a size**. Whether the host this lands on carries 24 GB per
    /// device is a property of the host, not of the runtime, so refusing
    /// here would turn away a machine that would have worked and
    /// approving would promise something never looked at.
    ///
    /// So it says it did not examine it, and the question is settled by
    /// observing the machine. That answer is the reason this enum has
    /// four arms instead of two.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        match required.min_vram_gb {
            None => Answer::met(),
            Some(floor) => Answer::not_examined(format!(
                "a container runtime cannot select on device memory, so \
                 {floor} GB per device is a property of the host this runs on"
            )),
        }
    }

    /// It can mount, but it cannot size.
    ///
    /// `-v` puts a volume at a path, so persistence itself is
    /// providable. How large that volume is comes from the host's
    /// filesystem, and the container's own writable layer is likewise
    /// the host's disk — `--storage-opt size=` exists but only on some
    /// storage drivers, so it is not something to promise.
    ///
    /// So a size is not examined and a path is met, which is the same
    /// answer split two ways rather than an awkward middle: the part
    /// that can be provided is, and the part that cannot be decided says
    /// so.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        let mut unsized_levels = Vec::new();
        if required.ephemeral_gb.is_some() {
            unsized_levels.push("the container's writable layer");
        }
        if required.persistent_gb.is_some() {
            unsized_levels.push("a mounted volume");
        }
        if unsized_levels.is_empty() {
            return match &required.persistent_at {
                Some(path) => Answer::met_using([format!("-v {path}")]),
                None => Answer::met(),
            };
        }
        Answer::not_examined(format!(
            "a container runtime cannot request a size for {}; how much there is \
             comes from the host's filesystem",
            unsized_levels.join(" or ")
        ))
    }

    /// Not wired, and said rather than faked.
    ///
    /// `docker run` would create the machine readily enough. Reaching it
    /// afterwards is the missing half: this crate's transports are SSH
    /// and same-host execution, and a container wants `docker exec` —
    /// which spec 08 names as an extension point precisely because it
    /// does not exist yet. An acquisition whose result nothing can be
    /// run against is not an acquisition.
    ///
    /// This adapter earns its place on the vocabulary, which is what it
    /// was added for: it is what proves the requirements are the
    /// workload's words rather than one service's. Execution is a
    /// separate claim, and it is not being made.
    fn acquisition(
        &self,
        _required: &Requirements,
        _provider: &BTreeMap<String, String>,
        _expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError> {
        Err(AcquisitionError::Unsupported {
            target: "container",
            reason: "no transport reaches a container yet (spec 08 names `docker exec` \
                     as an extension point; it is not implemented)",
        })
    }

    /// Nothing to enumerate. This adapter acquires nothing, so a
    /// sweeper asking it what is running would be asking about
    /// containers somebody else started — and answering would put them
    /// in front of a release path.
    fn fleet(&self) -> Option<Fleet> {
        None
    }

    /// No acquisition, so no image to preflight for one.
    fn image_key(&self) -> Option<&'static str> {
        None
    }

    /// Nothing to say: no acquisition means no machine mid-boot.
    fn still_materializing(&self, _inspected: &serde_json::Value) -> bool {
        false
    }

    /// Nothing observed, because nothing was acquired.
    ///
    /// This adapter renders no acquisition, so it is never handed
    /// anything to read. An empty state is the honest answer: every
    /// requirement comes back unexamined rather than met.
    fn read_state(&self, _inspected: &serde_json::Value) -> MachineState {
        MachineState::default()
    }

    /// Empty, for the same reason as [`read_state`](Self::read_state):
    /// no acquisition means nothing to reach. When the `docker exec`
    /// transport lands, this is where the host port bindings project.
    fn connection(&self, _inspected: &serde_json::Value) -> Connection {
        Connection::default()
    }
}

/// A GPU marketplace: the hardware is already listed as *offers* from
/// many hosts, and the create call names an offer rather than
/// describing a machine.
///
/// That inversion is the whole shape of this adapter. The managed pod
/// service takes a description and finds hardware, so its adapter
/// carries a catalogue and builds a request body; here selection
/// happens **before** create, so this adapter carries no catalogue at
/// all — the requirements translate into the marketplace's own filter
/// words (`gpu_ram>=`, `num_gpus>=`), the query sorts by price, and
/// [`Acquisition::discover`]'s first row is the machine. The cheapest
/// thing that clears the floor leads on both targets; this one just
/// asks the marketplace instead of a table.
///
/// **Verified hosts only.** The listings are other people's machines,
/// and the unverified tier is the one the marketplace itself fences off
/// (datacenter verification); the query pins `verified=true` so what a
/// profile lands on is the fenced side. `provider."vast.query"` is the
/// way to say otherwise, as `provider.runpod.gpuTypeIds` is on the
/// other target.
#[derive(Debug, Clone, Copy, Default)]
pub struct VastAdapter;

impl Infra for VastAdapter {
    /// Raw TCP only: an internal port maps to a random external port on
    /// the host's shared public address, read back from the
    /// description. There is no managed HTTPS proxy in front — a
    /// profile that requires `public_http` is refused at admission
    /// rather than handed a port that answers plain TCP
    /// [documented: docs.vast.ai/documentation/instances/connect/networking].
    fn capability(&self) -> Capability {
        Capability {
            target: "vast",
            exposures: &[Exposure::RawTcp],
        }
    }

    /// Docker's own `-p` form, verbatim — the create call forwards
    /// these inside its `--env` argument, which is where this service
    /// takes docker run options.
    fn render(&self, required: &Requirements) -> Vec<String> {
        required
            .ports
            .iter()
            .map(|it| format!("-p {}:{}", it.port, it.port))
            .collect()
    }

    fn provider_namespace(&self) -> &'static str {
        "vast"
    }

    /// None — not because the target is free, but because its CLI holds
    /// its own key: `vastai set api-key` writes a file the CLI reads
    /// back, and it reads no environment variable at all [measured:
    /// 2026-08-30, vast.py resolves `args.api_key` from the key file or
    /// a flag; the only env read is `VAST_URL`]. Authentication is the
    /// delegate's own (spec 06's rule for every tool this repo drives),
    /// so a missing key surfaces as that CLI's error — before anything
    /// is spent, since the first call is the discovery.
    fn credentials(&self) -> &'static [&'static str] {
        &[]
    }

    /// The floor and the count, in the marketplace's own filter words.
    ///
    /// The query unit is decimal gigabytes, same terms the requirement
    /// is written in [documented: docs.vast.ai — `gpu_ram` is GB in CLI
    /// queries, MB in REST responses], so no catalogue and no
    /// conversion stand between them.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        if required.count == 0 {
            return Answer::unmet(
                "this marketplace rents GPU machines; a profile asking for none \
                 has nothing to rent here",
            );
        }
        let mut using = vec![format!("num_gpus>={}", required.count)];
        if let Some(floor) = required.min_vram_gb {
            using.push(format!("gpu_ram>={floor}"));
        }
        Answer::Met { using }
    }

    /// One disk, sized at create, living and dying with the instance.
    ///
    /// A persistent level is refused rather than mapped onto that disk:
    /// calling storage "persisted across restarts" when the platform
    /// has no such distinction would promise exactly what the two-level
    /// vocabulary exists to keep apart.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        if required.persistent_gb.is_some() || required.persistent_at.is_some() {
            return Answer::unmet(
                "an instance here has one disk that lives and dies with it; \
                 there is no separately persisted volume to size or mount",
            );
        }
        match required.ephemeral_gb {
            Some(gb) => Answer::met_using([format!("disk_space>={gb}")]),
            None => Answer::met(),
        }
    }

    /// The service's own CLI, driven the same way as the other target's
    /// and for the same reason: the useful thing this repo adds is the
    /// requirements, not a second REST client.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError> {
        vast_acquisition(
            required,
            provider,
            self.render(required),
            required.gpu.as_ref().map(|it| self.gpu_answer(it)),
            required.disk.as_ref().map(|it| self.disk_answer(it)),
            expires_at,
        )
    }

    /// The marketplace lists this account's instances, and each row
    /// carries the `label` the create call set — the field this
    /// platform gives an operator to write on an instance, and so where
    /// `vast_acquisition` puts the lease.
    ///
    /// The rows name the machine `id`, not the `new_contract` a create
    /// answers with; both are the instance, but only one of them is
    /// what a listing prints.
    fn fleet(&self) -> Option<Fleet> {
        Some(Fleet {
            list: vec![
                "vastai".into(),
                "show".into(),
                "instances".into(),
                "--raw".into(),
            ],
            id: "id",
            stamp: "label",
            stamp_namespaced: false,
            release: vast_release(),
            inspect: vast_inspect(),
        })
    }

    /// The key `vast_acquisition` requires — and the preflight that
    /// matters most on this target: the marketplace accepts a create
    /// naming an image that does not exist and its host retries the
    /// pull forever, on billing [measured: 2026-08-30, instance
    /// 49228600, `manifest unknown` once a minute at `loading`].
    fn image_key(&self) -> Option<&'static str> {
        Some("vast.image")
    }

    /// `actual_status` is the platform's own word for it: `loading`
    /// while the host pulls the image and starts the container —
    /// which for a multi-gigabyte image runs well past the base
    /// reachability wait [measured: 2026-08-30, instance 49227715
    /// still `loading` at 300s] — and `created` before that. Anything
    /// else, including an absent field, makes no claim.
    fn still_materializing(&self, inspected: &serde_json::Value) -> bool {
        matches!(
            inspected.get("actual_status").and_then(|it| it.as_str()),
            Some("loading") | Some("created")
        )
    }

    /// The description names the device and its memory directly —
    /// `gpu_ram` is the figure the device itself reports (a part sold
    /// as 24 GB answers 24564 [documented: docs.vast.ai api-reference,
    /// show-instance example — the same number `nvidia-smi` measured on
    /// a real 4090 here]), so it lands as MiB unconverted and no
    /// catalogue has to know the model.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState {
        // Through `as_f64`, because this response does not commit to
        // integer-typed numbers — `disk_space` arrives as `60.4`, and a
        // `24564.0` read with `as_u64` would come back `None`, turning
        // a satisfied floor into `NotChecked` and a good machine into a
        // refused one (the failure class the CPU-pod zero fixed).
        let number = |value: &serde_json::Value| value.as_f64().map(|it| it as u32);

        // Two shapes in the wild: the docker-style map
        // `{"8188/tcp": [...]}` and a plain array of numbers. Either
        // way every entry is a TCP port on the shared address.
        let mut exposed = BTreeMap::new();
        let ports = inspected.get("ports");
        // Observed only when the field holds one of those shapes: a
        // booting instance writes `"ports": null` before the container
        // runs, and null is nobody having looked yet, not a machine
        // exposing nothing (the other adapter draws the same line at
        // its `as_array`).
        let mut ports_observed = true;
        match ports {
            Some(serde_json::Value::Object(map)) => {
                for key in map.keys() {
                    let port = key.split('/').next().and_then(|it| it.parse::<u16>().ok());
                    if let Some(port) = port {
                        exposed.insert(port, Exposure::RawTcp);
                    }
                }
            }
            Some(serde_json::Value::Array(entries)) => {
                for port in entries.iter().filter_map(|it| it.as_u64()) {
                    exposed.insert(port as u16, Exposure::RawTcp);
                }
            }
            _ => ports_observed = false,
        }

        MachineState {
            exposed,
            ports_observed,
            gpu_count: inspected.get("num_gpus").and_then(number),
            gpu_vram_mib: inspected.get("gpu_ram").and_then(number),
            ephemeral_gb: inspected
                .get("disk_space")
                .and_then(|it| it.as_f64())
                .map(|it| it as u32),
            persistent_gb: None,
            persistent_at: None,
        }
    }

    /// `ssh_host` + `ssh_port` for the session, and the docker-style
    /// port map against `public_ipaddr` for everything else — each
    /// field the service's own [documented: docs.vast.ai api-reference,
    /// show-instance]. SSH goes through the service's own ssh hosts
    /// rather than a mapped port, which is why it is not derived from
    /// the port map the way the other target's is.
    fn connection(&self, inspected: &serde_json::Value) -> Connection {
        let text = |key: &str| {
            inspected
                .get(key)
                .and_then(|it| it.as_str())
                .filter(|it| !it.is_empty())
        };
        let ssh = text("ssh_host").and_then(|host| {
            inspected
                .get("ssh_port")
                .and_then(|it| it.as_u64())
                .map(|port| SshEndpoint {
                    host: host.to_string(),
                    port: port as u16,
                    user: crate::ssh::DEFAULT_SSH_USER.to_string(),
                })
        });

        let mut endpoints = BTreeMap::new();
        if let (Some(ip), Some(map)) = (
            text("public_ipaddr"),
            inspected.get("ports").and_then(|it| it.as_object()),
        ) {
            for (key, bindings) in map {
                let Some(port) = key.split('/').next().and_then(|it| it.parse::<u16>().ok()) else {
                    continue;
                };
                let external = bindings
                    .as_array()
                    .and_then(|it| it.first())
                    .and_then(|it| it.get("HostPort"))
                    .and_then(|it| it.as_str());
                if let Some(external) = external {
                    endpoints.insert(port, format!("{ip}:{external}"));
                }
            }
        }
        Connection {
            ssh,
            endpoint: None,
            endpoints,
            read: vec![
                read_text(inspected, "ssh_host"),
                format!(
                    "ssh_port: {}",
                    match inspected.get("ssh_port").and_then(|it| it.as_u64()) {
                        Some(port) => port.to_string(),
                        None => "absent".to_string(),
                    }
                ),
                read_text(inspected, "public_ipaddr"),
                read_keys(inspected, "ports"),
            ],
        }
    }
}

/// The discovery and create for [`VastAdapter::acquisition`], built
/// from the requirements *and the adapter's answers to them* — the same
/// gate [`runpod_body`] stands behind, for the same reason: a builder
/// that reads a requirement without consulting its own answer can emit
/// a query that quietly dropped one.
fn vast_acquisition(
    required: &Requirements,
    provider: &BTreeMap<String, String>,
    ports: Vec<String>,
    gpu_answer: Option<Answer>,
    disk_answer: Option<Answer>,
    expires_at: Option<jiff::Timestamp>,
) -> Result<Acquisition, AcquisitionError> {
    // The image is the platform's own key, as on every target that
    // takes one (see `runpod_body`).
    let image = provider
        .get("vast.image")
        .ok_or(AcquisitionError::Incomplete {
            target: "vast",
            missing: "provider.vast.image",
        })?;

    let refuse = |answer: Answer| admitted("vast", answer);

    // `rentable=true`: listed and not currently taken. `verified=true`:
    // the fenced tier — see the adapter doc.
    let mut query = vec!["rentable=true".to_string(), "verified=true".to_string()];
    if let Some(answer) = gpu_answer {
        query.extend(refuse(answer)?);
    }
    if let Some(answer) = disk_answer {
        query.extend(refuse(answer)?);
    }
    if let Some(extra) = provider.get("vast.query") {
        query.push(extra.clone());
    }

    let mut create = vec![
        "vastai".to_string(),
        "create".to_string(),
        "instance".to_string(),
        "{offer_id}".to_string(),
        "--image".to_string(),
        image.clone(),
        // Key registration is account-level (`vastai create ssh-key`);
        // `--ssh --direct` is what makes the created instance answer on
        // an SSH endpoint at all.
        "--ssh".to_string(),
        "--direct".to_string(),
    ];
    if let Some(gb) = required.disk.as_ref().and_then(|it| it.ephemeral_gb) {
        create.push("--disk".to_string());
        create.push(gb.to_string());
    }
    if !ports.is_empty() {
        create.push("--env".to_string());
        create.push(ports.join(" "));
    }
    // The lease, on the instance itself: `--label` is the field this
    // platform gives an operator to write on one [documented:
    // docs.vast.ai, `create instance --label LABEL`], and a listing
    // prints it back — which is what lets a sweeper holding only this
    // account's key find the machine and read its expiry off it.
    if let Some(expires_at) = expires_at {
        create.push("--label".to_string());
        create.push(expiry_stamp(expires_at));
    }
    create.push("--raw".to_string());

    Ok(Acquisition {
        discover: Some(vec![
            "vastai".to_string(),
            "search".to_string(),
            "offers".to_string(),
            query.join(" "),
            // Ascending price: taking the first row of this *is* the
            // selection policy.
            "-o".to_string(),
            "dph".to_string(),
            "--raw".to_string(),
        ]),
        create,
        body: None,
        created_id_key: "new_contract",
        inspect: vast_inspect(),
        release: vast_release(),
    })
}

/// What reads one instance back, `{id}` unsubstituted — one spelling
/// for the record and for the listing, as `runpod_inspect` is.
fn vast_inspect() -> Vec<String> {
    vec![
        "vastai".to_string(),
        "show".to_string(),
        "instance".to_string(),
        "{id}".to_string(),
        "--raw".to_string(),
    ]
}

/// What destroys one instance, `{id}` unsubstituted — one spelling for
/// the record and for the listing, as `runpod_release` is.
fn vast_release() -> Vec<String> {
    vec![
        "vastai".to_string(),
        "destroy".to_string(),
        "instance".to_string(),
        "{id}".to_string(),
        // Without this the CLI asks `[y/N]` on a terminal nobody is
        // at, reads EOF as "no", prints `Aborted.` — **and exits
        // zero**, so the driver reported a machine released while
        // it ran on billing [measured: 2026-08-30, instance
        // 49227715 survived its own successful-looking release and
        // was destroyed by hand].
        "--yes".to_string(),
        "--raw".to_string(),
    ]
}

/// The containers collection on the container-rental service's REST
/// surface [documented: docs.deepinfra.com/api-reference/gpu-rentals,
/// read 2026-09-21].
const DEEPINFRA_CONTAINERS: &str = "https://api.deepinfra.com/v1/containers";

/// The variable the service's key is read from.
///
/// `_API_KEY`, as every other platform's is here (`RUNPOD_API_KEY`) and
/// as the service's own dashboard names the thing ("API Keys"), rather
/// than the `DEEPINFRA_API_KEY` its curl examples happen to spell — one
/// shape for the operator's credential file, and the name the routers
/// that consume the resulting endpoint already read (LiteLLM's
/// `deepinfra/` provider takes `DEEPINFRA_API_KEY`) [documented:
/// docs.litellm.ai/docs/providers/deepinfra, read 2026-09-22].
const DEEPINFRA_API_KEY: &str = "DEEPINFRA_API_KEY";

/// The user the service's image creates and its documentation connects
/// as (`ssh ubuntu@<container-ip>`) — not root, which is why the
/// projection below names it rather than [`crate::ssh::DEFAULT_SSH_USER`].
const DEEPINFRA_SSH_USER: &str = "ubuntu";

/// The service's catalogue, in the spelling its `gpu_config` field
/// takes after the count (`8xB200-180GB`).
///
/// One row, because one model is documented [documented:
/// docs.deepinfra.com/gpu-instances/overview, read 2026-09-21] and the
/// rate is the published per-card hour (1× at $3.69, 8× at $29.52 —
/// linear in the count) [read 2026-09-21 from deepinfra.com/gpu-instances].
/// A configuration outside it is named directly with
/// `provider.deepinfra.gpu_config`, as a model outside the pod
/// service's catalogue is named with `gpuTypeIds`.
const DEEPINFRA_CATALOGUE: &[Gpu] = &[Gpu {
    id: "B200-180GB",
    vram_gb: 180,
    usd_cents_hr: 369,
}];

/// A GPU container service that gives the machine an address and puts
/// nothing in front of it: no port mapping, no proxy, no sizeable disk
/// — a container with an IP, reached over SSH as the user its image
/// creates [documented: docs.deepinfra.com/gpu-instances/overview and
/// api-reference/gpu-rentals/*, read 2026-09-21].
///
/// **It exposes nothing, and says so.** The description a container
/// comes back with carries an `ip` and no port at all — the create call
/// takes no port list and the read-back publishes none — so a profile
/// that declares `requires_ports` is refused at admission rather than
/// handed a port nobody mapped. The one address the service states is
/// the container's own and the one port it documents on it is sshd's;
/// everything else on the machine is reached the way a platform's
/// endpoints never cover, through `port-forward`.
///
/// **No CLI to drive.** The service's own CLI (`deepctl`) manages model
/// deployments and has no container verb [documented:
/// github.com/deepinfra/deepctl README — `auth` / `model` / `deploy` /
/// `infer` / `log` / `version`, read 2026-09-21], so this adapter speaks
/// the REST surface through `curl`: the same judgment [`crate::image`]
/// makes, for the same reason — a program already on the host over a
/// second HTTP client tracking somebody else's schema. The credential
/// travels **by name**: `--variable %DEEPINFRA_API_KEY` imports the
/// variable inside curl and `--expand-header` writes it into the header
/// there, so the value is in no argv, no dry-run artifact, and no
/// process listing [measured: 2026-09-21, a local listener saw
/// `Authorization: Bearer <value>` from an argv that named only the
/// variable; curl ≥ 8.3.0, where `--variable` landed].
///
/// **The key rides in the request.** The other two platforms register
/// SSH keys at the account and inject them into every machine; this one
/// takes a cloud-init document on create, and the documented way to
/// reach the container is a public key written into that document under
/// the image's `ubuntu` user. So the profile names the key
/// (`provider."deepinfra.ssh_authorized_key"`, the public line verbatim)
/// and the adapter writes the document the service's own example shows.
/// A profile that writes `provider."deepinfra.cloud_init_user_data"`
/// itself gets its own document sent unchanged instead.
///
/// **Not root.** The session this projects to runs as `ubuntu`, so an
/// apply against it wants `--remote-dir /home/ubuntu`, and a phase that
/// needs root on the machine (system packages) fails there as it would
/// on any non-root session — the image grants passwordless `sudo`, but
/// the provisioner does not call it.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeepInfraAdapter;

impl Infra for DeepInfraAdapter {
    /// No exposure at all: the service maps no port and proxies
    /// nothing, and a machine's own address is not an exposure this
    /// vocabulary can name (the other adapters' `raw_tcp` is a mapping
    /// the platform performs and reports). Saying none is what makes
    /// the refusal of a `requires_ports` profile real.
    fn capability(&self) -> Capability {
        Capability {
            target: "deepinfra",
            exposures: &[],
        }
    }

    /// Nothing to render: the create call takes no port list, and
    /// admission has already refused any profile that declared one.
    fn render(&self, _required: &Requirements) -> Vec<String> {
        Vec::new()
    }

    fn provider_namespace(&self) -> &'static str {
        "deepinfra"
    }

    /// The key, by name. Required
    /// out here because there is no CLI holding its own key: `curl`
    /// reads it from the environment at the adapter's instruction, and
    /// a missing one is found before anything is spent rather than as
    /// a 401 in the middle of a create.
    fn credentials(&self) -> &'static [&'static str] {
        &[DEEPINFRA_API_KEY]
    }

    /// The cheapest catalogued model that clears the floor, in the
    /// service's own `{count}x{model}` spelling. **One configuration,
    /// not a list**: the create call takes a single `gpu_config`, so
    /// unlike the pod service there is no fallback to send alongside.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        if required.count == 0 {
            return Answer::unmet(
                "this service rents GPU containers; a profile asking for none has \
                 nothing to rent here",
            );
        }
        let floor = required.min_vram_gb.unwrap_or(0);
        let cheapest = DEEPINFRA_CATALOGUE
            .iter()
            .filter(|it| it.vram_gb >= floor)
            .min_by_key(|it| (it.usd_cents_hr, it.id));
        match cheapest {
            Some(gpu) => Answer::met_using([format!("{}x{}", required.count, gpu.id)]),
            None => Answer::unmet(format!(
                "no catalogued GPU carries {floor} GB; the largest known here is {} GB \
                 (name a configuration directly with provider.deepinfra.gpu_config if \
                 the catalogue is behind)",
                DEEPINFRA_CATALOGUE
                    .iter()
                    .map(|it| it.vram_gb)
                    .max()
                    .unwrap_or(0),
            )),
        }
    }

    /// One disk that lives and dies with the container, and no way to
    /// size it.
    ///
    /// A persistent level is refused, as on the marketplace and for the
    /// same reason — the service states that all container data is
    /// lost when it is terminated, and calling that "persisted" would
    /// promise exactly what the two-level vocabulary keeps apart. An
    /// ephemeral size is not examined: the create call takes none, so
    /// how much there is comes with the GPU configuration rather than
    /// from a request.
    fn disk_answer(&self, required: &DiskRequirement) -> Answer {
        if required.persistent_gb.is_some() || required.persistent_at.is_some() {
            return Answer::unmet(
                "a container here keeps nothing past its own life (the service states \
                 that all container data is lost when it is terminated), so there is \
                 no persisted volume to size or mount",
            );
        }
        match required.ephemeral_gb {
            Some(gb) => Answer::not_examined(format!(
                "this service takes no disk size; how much a container gets comes with \
                 its GPU configuration, so {gb} GB is a property of the configuration \
                 rather than something to ask for"
            )),
            None => Answer::met(),
        }
    }

    /// One `POST` with the four fields the create call takes, through
    /// `curl` — the body is the argument after `--json`, which is why
    /// `--json` is the last word of the argv: [`acquire`] appends the
    /// body as the final argument.
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError> {
        // Every answer taken here and handed to the builder, for the
        // reason `runpod_body` gives: a builder that reads a
        // requirement without its answer can emit a request that
        // quietly dropped one.
        let body = deepinfra_body(
            provider,
            required.gpu.as_ref().map(|it| self.gpu_answer(it)),
            required.disk.as_ref().map(|it| self.disk_answer(it)),
            expires_at,
        )?;
        let mut create = deepinfra_curl(DEEPINFRA_CONTAINERS);
        create.push("--json".to_string());
        Ok(Acquisition {
            // The create call describes the machine itself.
            discover: None,
            create,
            body: Some(body),
            // The create answers with `container_id`; every read-back
            // and every listed row says `id`. Both are the container.
            created_id_key: "container_id",
            inspect: deepinfra_inspect(),
            release: deepinfra_release(),
        })
    }

    /// The service lists this account's active containers as a bare
    /// array, each row carrying the `name` the create call set — where
    /// `deepinfra_body` writes the lease. `name` is required by the
    /// create call and settable afterwards (`PATCH`), and its length
    /// limit (64) clears the stamp with room.
    fn fleet(&self) -> Option<Fleet> {
        Some(Fleet {
            list: deepinfra_curl(DEEPINFRA_CONTAINERS),
            id: "id",
            stamp: "name",
            stamp_namespaced: false,
            release: deepinfra_release(),
            inspect: deepinfra_inspect(),
        })
    }

    /// None, deliberately, though the create call takes an image. The
    /// service's own images (`di-cont-ubuntu-torch:latest`) are names
    /// on no registry the preflight could ask — a bare name resolves to
    /// Docker Hub's `library/`, which would answer 404 and refuse a
    /// create the service accepts. A brought image could be asked
    /// about, but nothing in the name says which kind it is, and a
    /// preflight that refuses the documented default costs more than
    /// the pull it prevents. The service reports a bad image as
    /// `failed` with a `fail_reason` rather than retrying on billing,
    /// so the marketplace's failure this check exists for does not
    /// arise here.
    fn image_key(&self) -> Option<&'static str> {
        None
    }

    /// `creating` and `starting` are the service's own words for it
    /// [documented: docs.deepinfra.com/gpu-instances/overview, the
    /// state list]; `running`, `failed`, and everything else make no
    /// such claim.
    fn still_materializing(&self, inspected: &serde_json::Value) -> bool {
        matches!(
            inspected.get("state").and_then(|it| it.as_str()),
            Some("creating") | Some("starting")
        )
    }

    /// The description names the configuration (`gpu_config`, in the
    /// `{count}x{model}` form the create took) and nothing about disk
    /// or ports. The count is read off it; the memory is looked up in
    /// the catalogue as the pod service's is, and lands through
    /// [`gb_to_mib`] as the bound that function documents. A
    /// configuration outside the catalogue leaves the memory unobserved.
    ///
    /// Ports are never observed: the service publishes none, and a
    /// profile could not have declared any past admission.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState {
        let parsed = inspected
            .get("gpu_config")
            .and_then(|it| it.as_str())
            .and_then(deepinfra_gpu_config);
        MachineState {
            exposed: BTreeMap::new(),
            ports_observed: false,
            gpu_count: parsed.map(|(count, _)| count),
            gpu_vram_mib: parsed.and_then(|(_, model)| {
                DEEPINFRA_CATALOGUE
                    .iter()
                    .find(|it| it.id == model)
                    .map(|it| gb_to_mib(it.vram_gb))
            }),
            ephemeral_gb: None,
            persistent_gb: None,
            persistent_at: None,
        }
    }

    /// `ip`, port 22, the image's user — **and only once the service
    /// calls the container `running`**. The address is assigned before
    /// sshd is up, and an endpoint reported while the state is still
    /// `starting` would be one nothing can dial yet; absent means not
    /// reachable *yet*, same rule as everywhere else. No endpoints:
    /// nothing is mapped, so there is nothing per port to project.
    ///
    /// The `state` value itself is in what was read, beside the usual
    /// presence-and-shape entries: for an operator refused because
    /// there is no endpoint, `starting` and `failed` are different news,
    /// and the word is the service's enum rather than anything that
    /// identifies a machine.
    fn connection(&self, inspected: &serde_json::Value) -> Connection {
        let state = inspected.get("state").and_then(|it| it.as_str());
        let ip = inspected
            .get("ip")
            .and_then(|it| it.as_str())
            .filter(|it| !it.is_empty());
        let ssh = match (state, ip) {
            (Some("running"), Some(host)) => Some(SshEndpoint {
                host: host.to_string(),
                port: 22,
                user: DEEPINFRA_SSH_USER.to_string(),
            }),
            _ => None,
        };
        Connection {
            ssh,
            endpoint: None,
            endpoints: BTreeMap::new(),
            read: vec![
                read_text(inspected, "ip"),
                format!("state: {}", state.unwrap_or("absent")),
                read_text(inspected, "fail_reason"),
            ],
        }
    }
}

/// `curl` against `url`, authenticated by the token's **name**.
///
/// `-sS`: no progress meter on stderr, errors still spoken there. `-f`:
/// an HTTP error is a non-zero exit with the status on stderr, rather
/// than an error document on stdout that the next step would try to
/// read as a machine. `--variable %NAME` imports the environment
/// variable inside curl and `--expand-header` substitutes it there — the
/// value never appears in this argv, which is what the dry-run prints
/// and what a process listing shows.
fn deepinfra_curl(url: &str) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-sS".to_string(),
        "-f".to_string(),
        "--variable".to_string(),
        format!("%{DEEPINFRA_API_KEY}"),
        "--expand-header".to_string(),
        format!("Authorization: Bearer {{{{{DEEPINFRA_API_KEY}}}}}"),
        url.to_string(),
    ]
}

/// What reads one container back, `{id}` unsubstituted — one spelling
/// for the record and for the listing, as `runpod_inspect` is.
fn deepinfra_inspect() -> Vec<String> {
    deepinfra_curl(&format!("{DEEPINFRA_CONTAINERS}/{{id}}"))
}

/// What destroys one container, `{id}` unsubstituted — one spelling for
/// the record and for the listing, as `runpod_release` is. `DELETE`
/// answers 200 with an empty document; nothing is read from it, and
/// `-f` makes a container that was not there a failed release rather
/// than a silent one.
fn deepinfra_release() -> Vec<String> {
    let mut argv = deepinfra_curl(&format!("{DEEPINFRA_CONTAINERS}/{{id}}"));
    argv.push("-X".to_string());
    argv.push("DELETE".to_string());
    argv
}

/// The count and model in a `gpu_config` (`8xB200-180GB` → `(8,
/// "B200-180GB")`), or `None` for any other shape — which is a
/// configuration this cannot read, not one with zero devices.
fn deepinfra_gpu_config(config: &str) -> Option<(u32, &str)> {
    let (count, model) = config.split_once('x')?;
    Some((count.parse().ok()?, model))
}

/// The cloud-init document the service's own create example shows: the
/// image's user, a shell, passwordless sudo, and the one key. The key is
/// written as a JSON string, which is a valid YAML double-quoted scalar
/// — so a comment field carrying a character YAML would otherwise read
/// (a `#`, a `: `) cannot break the document.
fn deepinfra_cloud_init(key: &str) -> String {
    let quoted = serde_json::Value::String(key.trim().to_string()).to_string();
    format!(
        "#cloud-config\n\
         users:\n  \
           - name: {DEEPINFRA_SSH_USER}\n    \
             shell: /bin/bash\n    \
             sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n    \
             ssh_authorized_keys:\n      \
               - {quoted}\n"
    )
}

/// The request body for [`DeepInfraAdapter::acquisition`], built from
/// the adapter's answers — the same gate `runpod_body` stands behind.
///
/// Four fields, all of which the create call requires: `container_image`
/// from the provider slot, `gpu_config` from the GPU answer (or the
/// slot), `cloud_init_user_data` built from the slot's key (or taken
/// from the slot whole), and `name`, which is the lease.
///
/// `gpu_answer` / `disk_answer` are `None` exactly when the profile
/// declared no such requirement — and with no GPU requirement the body
/// has no `gpu_config` unless the slot names one, which is refused as
/// incomplete rather than sent for the service to refuse.
fn deepinfra_body(
    provider: &BTreeMap<String, String>,
    gpu_answer: Option<Answer>,
    disk_answer: Option<Answer>,
    expires_at: Option<jiff::Timestamp>,
) -> Result<String, AcquisitionError> {
    // The image is the platform's own key, as on every target that
    // takes one (see `runpod_body`), spelled as the API's field is.
    let image = provider
        .get("deepinfra.container_image")
        .ok_or(AcquisitionError::Incomplete {
            target: "deepinfra",
            missing: "provider.deepinfra.container_image",
        })?;

    let mut body = serde_json::Map::new();
    body.insert("container_image".into(), serde_json::json!(image));

    if let Some(answer) = gpu_answer {
        if let Some(config) = admitted("deepinfra", answer)?.into_iter().next() {
            body.insert("gpu_config".into(), serde_json::json!(config));
        }
    }
    if let Some(answer) = disk_answer {
        admitted("deepinfra", answer)?;
    }

    // Whatever the profile addressed to this target, verbatim and after
    // the fields derived above, so the profile gets the last word on
    // `gpu_config` the way it does on every target. The key the
    // cloud-init document is built from is consumed here rather than
    // forwarded: it is this adapter's vocabulary, not a field the
    // service takes.
    for (key, value) in provider {
        if let Some(field) = key.strip_prefix("deepinfra.") {
            if field == "ssh_authorized_key" {
                continue;
            }
            body.insert(field.to_string(), serde_json::json!(value));
        }
    }

    if !body.contains_key("gpu_config") {
        return Err(AcquisitionError::Incomplete {
            target: "deepinfra",
            missing: "requires_gpu (or provider.deepinfra.gpu_config)",
        });
    }
    if !body.contains_key("cloud_init_user_data") {
        let key = provider
            .get("deepinfra.ssh_authorized_key")
            .ok_or(AcquisitionError::Incomplete {
                target: "deepinfra",
                missing: "provider.deepinfra.ssh_authorized_key (or provider.deepinfra.cloud_init_user_data)",
            })?;
        body.insert(
            "cloud_init_user_data".into(),
            serde_json::json!(deepinfra_cloud_init(key)),
        );
    }

    // The lease, last, for the reason `runpod_body` gives — the one
    // field the profile does not get the last word on. `name` is
    // required by the create call, so a rendering with no lease
    // carries none and *cannot be sent*: an unstamped container is
    // refused by the service itself, before it exists.
    if let Some(expires_at) = expires_at {
        body.insert("name".into(), serde_json::json!(expiry_stamp(expires_at)));
    }

    Ok(serde_json::Value::Object(body).to_string())
}

/// The deployments collection on the managed-inference side of the
/// same service [documented: docs.deepinfra.com/api-reference/
/// dedicated-models, read 2026-09-22].
const DEEPINFRA_DEPLOY: &str = "https://api.deepinfra.com/deploy";

/// Where a deployment answers OpenAI-compatible requests [documented:
/// docs.deepinfra.com/private-models/custom-llms, read 2026-09-22].
const DEEPINFRA_OPENAI: &str = "https://api.deepinfra.com/v1/openai";

/// The provider-slot namespace of [`DeepInfraDeployAdapter`], and the
/// key the cloud-init-free half of this service is addressed by.
const DEEPINFRA_DEPLOY_NS: &str = "deepinfra-deploy";

/// The deploy API's `gpu` enum, in its own spelling, with the
/// published custom-LLM hourly rate as the ordering key.
///
/// Partial as the pod service's catalogue is, and for the same reason;
/// the enum also lists `L4-24GB` / `L40S-48GB` / `RTXPRO6000-96GB`,
/// whose rates were not published where the others were [read
/// 2026-09-21 from deepinfra.com/pricing via the provider survey;
/// enum spelling from the deploy-create-llm reference]. A configuration
/// outside this table is named directly with
/// `provider."deepinfra-deploy.gpu"`. The memory a device carries is
/// read off the enum value itself (`-80GB`) rather than from here, so
/// a read-back of an uncatalogued device still observes its memory.
const DEEPINFRA_DEPLOY_CATALOGUE: &[Gpu] = &[
    Gpu {
        id: "A100-80GB",
        vram_gb: 80,
        usd_cents_hr: 89,
    },
    Gpu {
        id: "H100-80GB",
        vram_gb: 80,
        usd_cents_hr: 220,
    },
    Gpu {
        id: "H200-141GB",
        vram_gb: 141,
        usd_cents_hr: 269,
    },
    Gpu {
        id: "B200-180GB",
        vram_gb: 180,
        usd_cents_hr: 369,
    },
    Gpu {
        id: "B300-270GB",
        vram_gb: 270,
        usd_cents_hr: 489,
    },
];

/// The deploy API's `num_gpus` ceiling [documented: deploy-create-llm
/// reference, `num_gpus` 1..8].
const DEEPINFRA_DEPLOY_MAX_GPUS: u32 = 8;

/// A managed LLM deployment: the machine is a **served model**, not a
/// host. The service takes the model's repository, a GPU
/// configuration and a replica range, pulls the weights itself, and
/// answers OpenAI-compatible requests at its own address — nothing of
/// this tool's ever runs on it [documented: docs.deepinfra.com/
/// private-models/custom-llms and api-reference/dedicated-models/*,
/// read 2026-09-22; the API facts below are from that reading].
///
/// **The same verbs, because the same lease.** A deployment is bought
/// with `machine acquire`, listed with `machine list`, given back with
/// `machine release`, and reaped by `machine sweep` exactly as a pod is,
/// because what those verbs manage — a billable thing with an expiry
/// stamped on it, enumerated from the platform's own list — is the
/// same thing here. What differs is what the acquisition *renders*
/// (the profile's `service.start`, carried in [`Requirements::serving`],
/// becomes the request body) and what the machine *projects* (an
/// inference endpoint rather than an SSH endpoint). The pod verbs
/// (`apply`, `logs`, `exec`, `cp`, `port-forward`) have no session to
/// open here and refuse by name.
///
/// **One call from repository to deployment.** `hf.repo` in the create
/// body is a Hugging Face id the service pulls itself; the survey's
/// other candidates need a model import step first (Together) or an
/// operator-side weights upload (Fireworks), which is why this one is
/// the first managed adapter [documented: workspace/drafts/
/// managed-deployment-backend-verify.md §Q1-Q3].
///
/// **The lease is in `model_name`, and the endpoint does not read it.**
/// The service has no label or description field on a deployment;
/// `model_name` is the one operator-written string, and it doubles as
/// the inference model id (`<username>/<model_name>`). Stamping the
/// lease there would put `lmp-exp-…` in every request a router sends —
/// except that the service also accepts `deploy_id:<id>` as the model,
/// "before the model is running" and, by the same reading, after
/// [documented: custom-llms guide]. So the projection names the
/// deployment by id and the stamp stays where the sweeper reads it.
/// The listing returns `model_name` under the account's namespace,
/// which [`Fleet::stamp_namespaced`] tells the reader to step over.
///
/// **Not root, not anything.** There is no user, no remote directory,
/// no port to declare: the capability lists no exposure, so a
/// `requires_ports` profile is refused at admission, and the request
/// carries nothing about ports.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeepInfraDeployAdapter;

impl Infra for DeepInfraDeployAdapter {
    /// No exposure: the service answers at its own address and maps
    /// nothing of the deployment's. A profile that declares a port is
    /// asking for something this cannot hand over.
    fn capability(&self) -> Capability {
        Capability {
            target: DEEPINFRA_DEPLOY_NS,
            exposures: &[],
        }
    }

    /// Nothing: no port list travels in the request.
    fn render(&self, _required: &Requirements) -> Vec<String> {
        Vec::new()
    }

    fn provider_namespace(&self) -> &'static str {
        DEEPINFRA_DEPLOY_NS
    }

    /// The same token as the container half of this service, read by
    /// the same name — one credential file entry covers both.
    fn credentials(&self) -> &'static [&'static str] {
        &[DEEPINFRA_API_KEY]
    }

    /// The cheapest catalogued configuration that clears the floor, in
    /// the deploy API's own spelling. One configuration: the request
    /// takes a single `gpu`.
    fn gpu_answer(&self, required: &GpuRequirement) -> Answer {
        if required.count == 0 {
            return Answer::unmet(
                "this service deploys a model onto GPUs; a profile asking for none \
                 has nothing to deploy onto",
            );
        }
        if required.count > DEEPINFRA_DEPLOY_MAX_GPUS {
            return Answer::unmet(format!(
                "a deployment here takes at most {DEEPINFRA_DEPLOY_MAX_GPUS} GPUs per \
                 instance; {} were asked for",
                required.count
            ));
        }
        let floor = required.min_vram_gb.unwrap_or(0);
        let cheapest = DEEPINFRA_DEPLOY_CATALOGUE
            .iter()
            .filter(|it| it.vram_gb >= floor)
            .min_by_key(|it| (it.usd_cents_hr, it.id));
        match cheapest {
            Some(gpu) => Answer::met_using([gpu.id.to_string()]),
            None => Answer::unmet(format!(
                "no catalogued GPU carries {floor} GB; the largest known here is {} GB \
                 (name a configuration directly with provider.deepinfra-deploy.gpu if \
                 the catalogue is behind)",
                DEEPINFRA_DEPLOY_CATALOGUE
                    .iter()
                    .map(|it| it.vram_gb)
                    .max()
                    .unwrap_or(0),
            )),
        }
    }

    /// No disk at all: the service holds the weights and the
    /// deployment has no filesystem the profile could size or mount.
    /// Any disk declaration is a requirement this target cannot meet.
    fn disk_answer(&self, _required: &DiskRequirement) -> Answer {
        Answer::unmet(
            "a deployment here has no disk the profile could size or mount; the \
             service holds the weights",
        )
    }

    /// One `POST` with the create body built from the profile's
    /// service and the adapter's answers, through `curl`.
    ///
    /// When the profile names a variable for the repository token
    /// (`provider."deepinfra-deploy.hf.token_env"`), the body carries
    /// `{{NAME:json}}` and the argv imports the variable inside curl
    /// (`--variable %NAME`, `--expand-json`): the value is in no argv,
    /// no dry-run and no record, the same way the bearer token travels
    /// [measured: 2026-09-21, a local listener received the expanded
    /// value from an argv that named only the variable].
    fn acquisition(
        &self,
        required: &Requirements,
        provider: &BTreeMap<String, String>,
        expires_at: Option<jiff::Timestamp>,
    ) -> Result<Acquisition, AcquisitionError> {
        let (body, token_env) = deepinfra_deploy_body(
            required,
            provider,
            required.gpu.as_ref().map(|it| self.gpu_answer(it)),
            required.disk.as_ref().map(|it| self.disk_answer(it)),
            expires_at,
        )?;
        let mut create = deepinfra_curl(&format!("{DEEPINFRA_DEPLOY}/llm"));
        match token_env {
            Some(name) => {
                create.push("--variable".to_string());
                create.push(format!("%{name}"));
                create.push("--expand-json".to_string());
            }
            None => create.push("--json".to_string()),
        }
        Ok(Acquisition {
            discover: None,
            create,
            body: Some(body),
            created_id_key: "deploy_id",
            inspect: deepinfra_deploy_inspect(),
            release: deepinfra_deploy_release(),
        })
    }

    /// The service lists this account's deployments, each row carrying
    /// `deploy_id` and the `model_name` the create call set — under the
    /// account's namespace, which is why the stamp is read past the
    /// slash.
    fn fleet(&self) -> Option<Fleet> {
        Some(Fleet {
            list: deepinfra_curl(&format!("{DEEPINFRA_DEPLOY}/list/")),
            id: "deploy_id",
            stamp: "model_name",
            stamp_namespaced: true,
            release: deepinfra_deploy_release(),
            inspect: deepinfra_deploy_inspect(),
        })
    }

    /// The serving image, when the profile names one — a Docker Hub
    /// reference (`vllm/vllm-openai:v0.8.4` in the service's own
    /// example) the registry can be asked about. Absent, the service's
    /// default is used and there is nothing to preflight.
    fn image_key(&self) -> Option<&'static str> {
        Some("deepinfra-deploy.container_image")
    }

    /// `initializing`, `downloading`, `deploying`: the service's own
    /// words for a deployment on its way up [documented: deploy-list
    /// reference, `status`]. `updating` is a running deployment being
    /// changed, and everything else makes no claim.
    fn still_materializing(&self, inspected: &serde_json::Value) -> bool {
        matches!(
            inspected.get("status").and_then(|it| it.as_str()),
            Some("initializing") | Some("downloading") | Some("deploying")
        )
    }

    /// `config.gpu` and `config.num_gpus`, as the description carries
    /// them. The memory is read off the configuration's own spelling
    /// (`H100-80GB` says 80) through [`gb_to_mib`], so an uncatalogued
    /// device is still observed. Ports and disk are never observed:
    /// the service has neither.
    fn read_state(&self, inspected: &serde_json::Value) -> MachineState {
        let config = inspected.get("config");
        MachineState {
            exposed: BTreeMap::new(),
            ports_observed: false,
            gpu_count: config
                .and_then(|it| it.get("num_gpus"))
                .and_then(|it| it.as_u64())
                .map(|it| it as u32),
            gpu_vram_mib: config
                .and_then(|it| it.get("gpu"))
                .and_then(|it| it.as_str())
                .and_then(deepinfra_gpu_vram_gb)
                .map(gb_to_mib),
            ephemeral_gb: None,
            persistent_gb: None,
            persistent_at: None,
        }
    }

    /// The inference endpoint, **once the service calls the deployment
    /// up** (`running`, or the `deployed` the status reference's own
    /// example shows): the OpenAI-compatible base, the deployment named
    /// by id, and the token's name. No SSH: there is no host.
    fn connection(&self, inspected: &serde_json::Value) -> Connection {
        let status = inspected.get("status").and_then(|it| it.as_str());
        let id = inspected
            .get("deploy_id")
            .and_then(|it| it.as_str())
            .filter(|it| !it.is_empty());
        let endpoint = match (status, id) {
            (Some("running") | Some("deployed"), Some(id)) => Some(InferenceEndpoint {
                base_url: DEEPINFRA_OPENAI.to_string(),
                model: format!("deploy_id:{id}"),
                api_key_env: DEEPINFRA_API_KEY.to_string(),
            }),
            _ => None,
        };
        Connection {
            ssh: None,
            endpoint,
            endpoints: BTreeMap::new(),
            read: vec![
                read_text(inspected, "deploy_id"),
                format!("status: {}", status.unwrap_or("absent")),
                read_text(inspected, "fail_reason"),
            ],
        }
    }
}

/// What reads one deployment back, `{id}` unsubstituted — one spelling
/// for the record and for the listing.
fn deepinfra_deploy_inspect() -> Vec<String> {
    deepinfra_curl(&format!("{DEEPINFRA_DEPLOY}/{{id}}"))
}

/// What destroys one deployment, `{id}` unsubstituted — one spelling
/// for the record and for the listing.
fn deepinfra_deploy_release() -> Vec<String> {
    let mut argv = deepinfra_curl(&format!("{DEEPINFRA_DEPLOY}/{{id}}"));
    argv.push("-X".to_string());
    argv.push("DELETE".to_string());
    argv
}

/// The memory a deploy-API configuration name states (`H200-141GB` →
/// 141), or `None` for a spelling that states none (`other`).
fn deepinfra_gpu_vram_gb(config: &str) -> Option<u32> {
    config.rsplit_once('-')?.1.strip_suffix("GB")?.parse().ok()
}

/// A provider-slot value as the JSON scalar it spells.
///
/// The deploy API is typed — `num_gpus` and `settings.min_instances`
/// are integers — while the profile's provider slot is strings, so a
/// passthrough here reads each value as the scalar it spells rather
/// than quoting it: `"0"` becomes `0`, `"true"` becomes `true`, and
/// anything else stays the string it is. Only for this target: the
/// pod service's own API takes strings where the profile writes them.
fn deepinfra_scalar(value: &str) -> serde_json::Value {
    if let Ok(number) = value.parse::<i64>() {
        return serde_json::json!(number);
    }
    match value {
        "true" => serde_json::json!(true),
        "false" => serde_json::json!(false),
        other => serde_json::json!(other),
    }
}

/// The request body for [`DeepInfraDeployAdapter::acquisition`], and
/// the name of the repository-token variable when the profile named
/// one — built from the profile's service *and the adapter's answers*,
/// the same gate `runpod_body` stands behind.
///
/// What the profile wrote becomes the service's own fields: the
/// service's `model` is `hf.repo`, its `dtype` and `extra_args` are the
/// engine's arguments, `requires_gpu` is `gpu` (selected) and
/// `num_gpus`, and the lease is `model_name`. Everything addressed to
/// this target in the provider slot lands after those, verbatim under
/// the field it names — `settings.min_instances` into `settings`,
/// `hf.revision` into `hf`, anything else at the top level — so the
/// profile gets the last word on every field but the lease.
///
/// **Refused by name, not dropped:** a service on another engine, a
/// phase besides the service, a tensor-parallel size that disagrees
/// with the GPU count, a disk. Each is something the profile said and
/// this target cannot do, and a request sent without it would deploy
/// something the profile did not declare.
fn deepinfra_deploy_body(
    required: &Requirements,
    provider: &BTreeMap<String, String>,
    gpu_answer: Option<Answer>,
    disk_answer: Option<Answer>,
    expires_at: Option<jiff::Timestamp>,
) -> Result<(String, Option<String>), AcquisitionError> {
    let serving = required
        .serving
        .as_ref()
        .ok_or(AcquisitionError::Incomplete {
            target: DEEPINFRA_DEPLOY_NS,
            missing: "a service.start phase naming the model to deploy",
        })?;
    let unmet = |reason: String| AcquisitionError::Unmet {
        target: DEEPINFRA_DEPLOY_NS,
        reason,
    };

    if serving.engine != "vllm" {
        return Err(unmet(format!(
            "this service deploys with vLLM; the profile's service `{}` is declared \
             for `{}`",
            serving.name, serving.engine
        )));
    }
    if !serving.others.is_empty() {
        return Err(unmet(format!(
            "this target runs the declared service and nothing else; the profile also \
             declares: {}",
            serving.others.join(", ")
        )));
    }
    let model = serving.model.as_ref().ok_or(AcquisitionError::Incomplete {
        target: DEEPINFRA_DEPLOY_NS,
        missing: "service.start's model (the Hugging Face repository to deploy)",
    })?;
    if let (Some(parallel), Some(gpu)) = (serving.tensor_parallel_size, &required.gpu) {
        if u32::from(parallel) != gpu.count {
            return Err(unmet(format!(
                "the service declares tensor_parallel_size {parallel} but requires_gpu \
                 asks for {} devices; a deployment here gives one instance exactly \
                 num_gpus devices, so the two have to agree",
                gpu.count
            )));
        }
    }

    let mut body = serde_json::Map::new();
    let mut hf = serde_json::Map::new();
    let mut settings = serde_json::Map::new();
    hf.insert("repo".into(), serde_json::json!(model));

    if let Some(answer) = gpu_answer {
        if let Some(config) = admitted(DEEPINFRA_DEPLOY_NS, answer)?.into_iter().next() {
            body.insert("gpu".into(), serde_json::json!(config));
        }
    }
    if let Some(gpu) = &required.gpu {
        body.insert("num_gpus".into(), serde_json::json!(gpu.count));
    }
    if let Some(answer) = disk_answer {
        admitted(DEEPINFRA_DEPLOY_NS, answer)?;
    }

    let mut extra_args: Vec<String> = Vec::new();
    if let Some(dtype) = &serving.dtype {
        extra_args.push("--dtype".to_string());
        extra_args.push(dtype.clone());
    }
    extra_args.extend(serving.extra_args.iter().cloned());
    if !extra_args.is_empty() {
        body.insert("extra_args".into(), serde_json::json!(extra_args));
    }

    // The profile's own words for this target, after the derived
    // fields. The token variable is consumed rather than forwarded: it
    // names where the value is, which is this adapter's vocabulary and
    // not a field the service takes.
    let mut token_env = None;
    for (key, value) in provider {
        let Some(field) = key.strip_prefix("deepinfra-deploy.") else {
            continue;
        };
        match field {
            "hf.token_env" => token_env = Some(value.clone()),
            other => match other.split_once('.') {
                Some(("hf", inner)) => {
                    hf.insert(inner.to_string(), deepinfra_scalar(value));
                }
                Some(("settings", inner)) => {
                    settings.insert(inner.to_string(), deepinfra_scalar(value));
                }
                _ => {
                    body.insert(other.to_string(), deepinfra_scalar(value));
                }
            },
        }
    }
    if let Some(name) = &token_env {
        hf.insert(
            "token".into(),
            serde_json::json!(format!("{{{{{name}:json}}}}")),
        );
    }
    body.insert("hf".into(), serde_json::Value::Object(hf));
    if !settings.is_empty() {
        body.insert("settings".into(), serde_json::Value::Object(settings));
    }

    if !body.contains_key("gpu") {
        return Err(AcquisitionError::Incomplete {
            target: DEEPINFRA_DEPLOY_NS,
            missing: "requires_gpu (or provider.deepinfra-deploy.gpu)",
        });
    }

    // The lease, last, for the reason `runpod_body` gives. `model_name`
    // is required by the create call, so a rendering with no lease
    // carries none and cannot be sent: an unstamped deployment is
    // refused by the service itself.
    if let Some(expires_at) = expires_at {
        body.insert(
            "model_name".into(),
            serde_json::json!(expiry_stamp(expires_at)),
        );
    }

    Ok((serde_json::Value::Object(body).to_string(), token_env))
}

/// A machine that exists because [`acquire`] made it.
///
/// Carries what it takes to give it back, so that a caller holding one
/// of these never has to reconstruct how — the release is not something
/// to work out after the fact.
#[derive(Debug, Clone)]
pub struct Acquired {
    /// The identifier the service gave it.
    pub id: String,
    /// What the service said about it when last inspected.
    pub inspected: serde_json::Value,
    /// What it said at creation, kept because some of it is never said
    /// again — see [`Acquired::inspect`].
    created: serde_json::Value,
    /// How to inspect and destroy it, with `{id}` still in place.
    acquisition: Acquisition,
}

impl Acquired {
    /// Ask the service what this machine is now.
    ///
    /// **What the fresh description leaves blank, the creation-time one
    /// fills.** A managed pod service names the attached GPU model in
    /// its create response and then returns `"machine": {}` from every
    /// read-back afterwards — `get-pod` and `list-pods` both, for a
    /// running pod and for stopped ones [measured: 2026-08-12, pod on an
    /// RTX 4090]. Replacing the description wholesale threw away the
    /// only statement the service ever made about which device this is,
    /// so the memory the profile asked for came back `NotChecked` on
    /// every real machine while passing in tests, whose fixture had been
    /// written from a create response.
    ///
    /// Only blanks are filled: a key the fresh description carries wins,
    /// however stale the other looks. A machine's model cannot change
    /// under it, and a service that stops mentioning something has not
    /// said it went away.
    pub fn inspect(&mut self) -> Result<&serde_json::Value, ExecuteError> {
        let mut fresh = run_json(&substitute(&self.acquisition.inspect, &self.id), None)?;
        fill_blanks(&mut fresh, &self.created);
        self.inspected = fresh;
        Ok(&self.inspected)
    }

    /// Destroy it.
    ///
    /// Takes `self`, so the handle is spent: a machine cannot be
    /// released twice, and one that was released cannot be inspected
    /// afterwards as though it were still there.
    pub fn release(self) -> Result<(), ExecuteError> {
        run(&substitute(&self.acquisition.release, &self.id), None).map(|_| ())
    }
}

/// Something went wrong obtaining or inspecting a machine.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// The command could not be started.
    #[error("could not run `{command}`: {source}")]
    Spawn {
        /// What was being run.
        command: String,
        /// Why it could not start.
        source: std::io::Error,
    },

    /// It ran and failed.
    #[error("`{command}` exited with status {status}: {stderr}")]
    Failed {
        /// What was run.
        command: String,
        /// How it exited.
        status: String,
        /// What it said about it.
        stderr: String,
    },

    /// It succeeded and said something unreadable.
    #[error("`{command}` returned no readable JSON: {detail}")]
    Unreadable {
        /// What was run.
        command: String,
        /// What could not be read.
        detail: String,
    },

    /// The created machine has no identifier, so nothing could release
    /// it.
    ///
    /// Reported rather than tolerated: a machine that exists and cannot
    /// be named is the shape of a bill nobody can stop.
    #[error("`{command}` created something without returning an id: {body}")]
    Anonymous {
        /// What was run.
        command: String,
        /// What came back instead.
        body: String,
    },

    /// A discovery ran and matched nothing, so there is nothing to
    /// create from.
    ///
    /// Not a failure of the command — the query succeeded and the
    /// marketplace simply has no machine like that right now. Said
    /// before anything is spent, with the query in it, because the way
    /// out is loosening the query.
    #[error("`{command}` found no offers to create from")]
    NoCandidates {
        /// The discovery that came back empty.
        command: String,
    },
}

/// Create a machine from a rendered [`Acquisition`].
///
/// **This is the call that spends money.** It is a free function rather
/// than a method on [`Infra`] so that rendering an acquisition and
/// performing one are separate acts in the source as well as in the
/// design: a caller that only wants to show an operator what would
/// happen cannot reach this by accident.
pub fn acquire(mut acquisition: Acquisition) -> Result<Acquired, ExecuteError> {
    if let Some(discover) = &acquisition.discover {
        let found = run_json(discover, None)?;
        // The first row of a query whose argv already sorted and
        // filtered — see `Acquisition::discover` for why the policy
        // lives in the query rather than here.
        let offer = found.as_array().and_then(|it| it.first()).ok_or_else(|| {
            ExecuteError::NoCandidates {
                command: discover.join(" "),
            }
        })?;
        let offer_id = json_id(offer, "id").ok_or_else(|| ExecuteError::Unreadable {
            command: discover.join(" "),
            detail: format!("the first offer has no readable id: {offer}"),
        })?;
        acquisition.create = acquisition
            .create
            .iter()
            .map(|it| it.replace("{offer_id}", &offer_id))
            .collect();
    }
    let created = run_json(&acquisition.create, acquisition.body.as_deref())?;
    let id =
        json_id(&created, acquisition.created_id_key).ok_or_else(|| ExecuteError::Anonymous {
            command: acquisition.create.join(" "),
            body: created.to_string(),
        })?;
    Ok(Acquired {
        id,
        inspected: created.clone(),
        created,
        acquisition,
    })
}

/// The identifier under `key`, in the form every argv wants it.
///
/// A string or a number — one service writes `"id": "abc"` and another
/// writes `"new_contract": 9841205`, and both name a machine.
fn json_id(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key)? {
        serde_json::Value::String(it) => Some(it.clone()),
        serde_json::Value::Number(it) => Some(it.to_string()),
        _ => None,
    }
}

/// Copy over what `fresh` does not say, from what `earlier` did.
///
/// A key is a blank when it is missing, `null`, or an empty object — the
/// third because that is the shape a description takes when a service
/// returns the container of a field without the field
/// [measured: 2026-08-12, `"machine": {}` from `get-pod`]. Objects present on
/// both sides are filled recursively, so one blank key inside a
/// populated object is reached.
///
/// Anything `fresh` states stands. This only restores what nothing
/// contradicted.
fn fill_blanks(fresh: &mut serde_json::Value, earlier: &serde_json::Value) {
    let (Some(fresh), Some(earlier)) = (fresh.as_object_mut(), earlier.as_object()) else {
        return;
    };
    for (key, was) in earlier {
        match fresh.get_mut(key) {
            None => {
                fresh.insert(key.clone(), was.clone());
            }
            Some(now) if now.is_null() => *now = was.clone(),
            Some(now) if now.as_object().is_some_and(|it| it.is_empty()) => *now = was.clone(),
            Some(now) => fill_blanks(now, was),
        }
    }
}

/// `{id}` replaced throughout.
fn substitute(argv: &[String], id: &str) -> Vec<String> {
    argv.iter()
        .map(|it| it.replace("{id}", id))
        .collect::<Vec<_>>()
}

/// Run `argv`, optionally appending `body` as its last argument, and
/// hand back everything it produced.
///
/// A non-zero exit is the error: what a caller does with the streams
/// differs (one wants the stdout parsed, another relays the stderr
/// under the child's name), and what a failure means does not.
fn run_output(argv: &[String], body: Option<&str>) -> Result<std::process::Output, ExecuteError> {
    let Some((program, rest)) = argv.split_first() else {
        return Err(ExecuteError::Unreadable {
            command: String::new(),
            detail: "no command to run".to_string(),
        });
    };
    let mut command = std::process::Command::new(program);
    command.args(rest);
    if let Some(body) = body {
        command.arg(body);
    }
    let rendered = argv.join(" ");
    let output = command.output().map_err(|source| ExecuteError::Spawn {
        command: rendered.clone(),
        source,
    })?;
    if !output.status.success() {
        return Err(ExecuteError::Failed {
            command: rendered,
            status: output
                .status
                .code()
                .map(|it| it.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(output)
}

/// [`run_output`], keeping only what it printed.
fn run(argv: &[String], body: Option<&str>) -> Result<String, ExecuteError> {
    Ok(String::from_utf8_lossy(&run_output(argv, body)?.stdout).into_owned())
}

/// The JSON document in what a CLI printed.
///
/// The CLI prints its own progress before the payload, so the payload
/// is found rather than assumed to start at byte zero — and it may be
/// an array (a discovery's offer list, a fleet listing) as well as an
/// object. Both starts are *tried* rather than the first one taken: a
/// progress line is free to contain a bracket (`[INFO] …`), and
/// stopping there would feed the progress text to the parser. Whichever
/// start yields a document that parses to the end is the payload.
fn payload(stdout: &str, command: &str) -> Result<serde_json::Value, ExecuteError> {
    let mut detail = "no JSON payload in the output".to_string();
    for start in [stdout.find('{'), stdout.find('[')].into_iter().flatten() {
        match serde_json::from_str(&stdout[start..]) {
            Ok(value) => return Ok(value),
            Err(err) => detail = err.to_string(),
        }
    }
    Err(ExecuteError::Unreadable {
        command: command.to_string(),
        detail,
    })
}

/// [`run`], reading the output as JSON.
fn run_json(argv: &[String], body: Option<&str>) -> Result<serde_json::Value, ExecuteError> {
    payload(&run(argv, body)?, &argv.join(" "))
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

    /// **What stage 2 is for.** The same requirement gets three
    /// different *kinds* of answer, and none of them is a lie:
    /// the managed service can choose, so it chooses and says what; the
    /// container runtime has no way to ask, so it says it did not look.
    ///
    /// A two-valued answer would have to call one of those a refusal,
    /// which would turn away a host that carries the memory perfectly
    /// well.
    #[test]
    fn a_memory_floor_is_selected_on_one_target_and_unexamined_on_the_other() {
        let required = GpuRequirement {
            count: 1,
            min_vram_gb: Some(40),
        };

        match RunPodAdapter.gpu_answer(&required) {
            Answer::Met { using } => {
                assert!(
                    using.iter().all(|it| it.contains("A40")
                        || it.contains("L40S")
                        || it.contains("A6000")
                        || it.contains("A100")
                        || it.contains("H100")),
                    "everything chosen clears 40 GB: {using:?}"
                );
                assert!(
                    !using
                        .iter()
                        .any(|it| it.contains("L4\"") || it == "NVIDIA L4"),
                    "a 24 GB device does not clear a 40 GB floor: {using:?}"
                );
            }
            other => panic!("the catalogue carries 40 GB devices: {other:?}"),
        }

        let container = ContainerAdapter.gpu_answer(&required);
        assert!(
            matches!(container, Answer::NotExamined { .. }),
            "a container runtime cannot select on memory: {container:?}"
        );
        assert!(
            !container.blocks(),
            "not examining something is not a refusal — the host may well carry it"
        );
    }

    /// The floor is a floor: the cheapest thing that clears it comes
    /// first, and the rest are what the service can fall back to when it
    /// is short of the first. Cheapest by the rate column — memory is
    /// not a price: a 48 GB A40 rents for less than a 24 GB RTX 4090,
    /// and sorting on memory would have paid the difference.
    #[test]
    fn the_selection_starts_at_the_cheapest_device_that_clears_the_floor() {
        let answer = RunPodAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(24),
        });
        let Answer::Met { using } = answer else {
            panic!("24 GB is well inside the catalogue: {answer:?}");
        };
        assert_eq!(
            using.first().map(String::as_str),
            Some("NVIDIA RTX A5000"),
            "the cheapest device that clears the floor leads: {using:?}"
        );
        // `expect`ed, not compared as options: `None < Some(_)` holds,
        // so a missing model would pass the ordering assertion while
        // testing nothing.
        let position = |id: &str| {
            using
                .iter()
                .position(|it| it == id)
                .unwrap_or_else(|| panic!("{id} missing from the selection: {using:?}"))
        };
        assert!(
            position("NVIDIA A40") < position("NVIDIA GeForce RTX 4090"),
            "a cheaper 48 GB device sorts ahead of a pricier 24 GB one: {using:?}"
        );
    }

    /// A floor nothing carries is refused, and the refusal says both how
    /// far off it is and how to say what the catalogue cannot.
    #[test]
    fn a_floor_beyond_the_catalogue_is_refused_with_a_way_out() {
        let answer = RunPodAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(512),
        });
        let Answer::Unmet { reason } = &answer else {
            panic!("no catalogued device carries 512 GB: {answer:?}");
        };
        assert!(reason.contains("512"), "{reason}");
        assert!(
            reason.contains("provider.runpod.gpuTypeIds"),
            "the refusal points at the slot that can name what the catalogue cannot: {reason}"
        );
        assert!(answer.blocks());
    }

    /// No floor is nothing to choose between, on either target.
    #[test]
    fn a_count_without_a_floor_needs_no_selection() {
        let required = GpuRequirement {
            count: 2,
            min_vram_gb: None,
        };
        assert_eq!(RunPodAdapter.gpu_answer(&required), Answer::met());
        assert_eq!(ContainerAdapter.gpu_answer(&required), Answer::met());
    }

    /// The two storage levels are the supplier's own distinction —
    /// wiped on restart against persisted across one — and the managed
    /// service takes a size for each plus where the second is mounted.
    #[test]
    fn a_managed_service_sizes_both_storage_levels() {
        let answer = RunPodAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: Some(100),
            persistent_gb: Some(50),
            persistent_at: Some("/workspace".into()),
        });
        let Answer::Met { using } = answer else {
            panic!("a managed service sizes both: {answer:?}");
        };
        assert!(
            using.iter().any(|it| it == "containerDiskInGb=100"),
            "{using:?}"
        );
        assert!(using.iter().any(|it| it == "volumeInGb=50"), "{using:?}");
        assert!(
            using.iter().any(|it| it == "volumeMountPath=/workspace"),
            "{using:?}"
        );
    }

    /// **The same split as the accelerator floor, one level down.** A
    /// container runtime can put a volume at a path but cannot say how
    /// large it is — that comes from the host's filesystem. Refusing
    /// would turn away a host with plenty of room.
    #[test]
    fn a_container_mounts_but_does_not_size() {
        let sized = ContainerAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: None,
            persistent_gb: Some(50),
            persistent_at: Some("/workspace".into()),
        });
        assert!(
            matches!(sized, Answer::NotExamined { .. }),
            "a size is the host's business: {sized:?}"
        );
        assert!(!sized.blocks(), "not knowing is not refusing");

        let unsized_request = ContainerAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: None,
            persistent_gb: None,
            persistent_at: Some("/workspace".into()),
        });
        assert_eq!(
            unsized_request,
            Answer::met_using(["-v /workspace".to_string()]),
            "a path with no size is something it can simply do"
        );
    }

    fn full_requirements() -> Requirements {
        Requirements::from_slots(
            &[("8188", "public_http"), ("22", "raw_tcp")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("count", "1"), ("min_vram_gb", "40")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[
                ("ephemeral_gb", "100"),
                ("persistent_gb", "150"),
                ("persistent_at", "/workspace"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        )
        .expect("well-formed fixture")
    }

    /// The provider slot the fixtures pair with [`full_requirements`]:
    /// the image travels here now, under the platform's own key (see
    /// [`runpod_body`]).
    fn image_provider() -> BTreeMap<String, String> {
        [(
            "runpod.imageName",
            "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
        )]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// The whole vocabulary becomes one request, and every part of it is
    /// traceable back to a line the profile wrote.
    #[test]
    fn the_requirements_become_the_services_own_request() {
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &image_provider(), None)
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().expect("create takes a body"))
                .expect("the body is JSON");

        assert_eq!(body["ports"], serde_json::json!(["22/tcp", "8188/http"]));
        assert_eq!(body["computeType"], "GPU");
        assert_eq!(body["gpuCount"], 1);
        assert_eq!(body["containerDiskInGb"], 100);
        assert_eq!(body["volumeInGb"], 150);
        assert_eq!(body["volumeMountPath"], "/workspace");
        assert!(
            body["gpuTypeIds"]
                .as_array()
                .expect("a floor selects models")
                .iter()
                .all(|it| it != "NVIDIA L4"),
            "a 24 GB device does not clear a 40 GB floor: {}",
            body["gpuTypeIds"]
        );
    }

    /// **Every field this emits exists in the service's schema, with the
    /// right type, and every model named is in its enumeration**
    /// [measured: 2026-08-12, checked against the OpenAPI description the
    /// service's own CLI is generated from].
    ///
    /// Pinned here rather than left to a live call, because a live call
    /// costs a machine to find out and this does not. The list is what
    /// the check verified; a field added to the request without being
    /// added here has not been checked against anything.
    #[test]
    fn every_field_emitted_is_one_the_service_defines() {
        const CHECKED: &[&str] = &[
            "computeType",
            "containerDiskInGb",
            "gpuCount",
            "gpuTypeIds",
            "imageName",
            "ports",
            "volumeInGb",
            "volumeMountPath",
        ];
        let provider: BTreeMap<String, String> = [
            ("runpod.imageName", "runpod/pytorch:2.4.0"),
            ("runpod.networkVolumeId", "vol-1"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &provider, None)
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        let emitted: Vec<&String> = body
            .as_object()
            .expect("the body is an object")
            .keys()
            .collect();

        for key in emitted {
            assert!(
                CHECKED.contains(&key.as_str()) || key == "networkVolumeId",
                "{key} is emitted but was never checked against the service's schema"
            );
        }
    }

    /// A profile's provider keys go in verbatim and last, so a network
    /// volume named there replaces the size above it the way the service
    /// documents.
    #[test]
    fn provider_keys_land_in_the_request_unchanged() {
        let provider: BTreeMap<String, String> = [
            ("runpod.imageName", "runpod/pytorch:2.4.0"),
            ("runpod.networkVolumeId", "vol-1"),
            ("container.network", "bridge"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &provider, None)
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();

        assert_eq!(body["networkVolumeId"], "vol-1");
        assert!(
            body.get("container.network").is_none() && body.get("network").is_none(),
            "another target's key is not this target's: {body}"
        );
    }

    /// **The bug this caught.** A memory floor beyond the catalogue used
    /// to drop the model selection and return a request that looked
    /// perfectly well-formed — `gpuCount` present, `gpuTypeIds` absent,
    /// exit 0 — so a machine would have been created without the thing
    /// that was asked for [measured: 2026-08-12, before this arm existed].
    ///
    /// Silently dropping an unsatisfiable requirement is the exact sin
    /// the rest of this module argues against. It got in because the
    /// request was built without consulting the answer.
    #[test]
    fn a_requirement_the_adapter_cannot_meet_stops_the_request() {
        let beyond = Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "1"), ("min_vram_gb", "512")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
        )
        .unwrap();

        let err = RunPodAdapter
            .acquisition(&beyond, &image_provider(), None)
            .expect_err("no catalogued device carries 512 GB");
        let rendered = err.to_string();
        assert!(rendered.contains("512"), "{rendered}");
        assert!(
            rendered.contains("provider.runpod.gpuTypeIds"),
            "the refusal keeps the way out it had: {rendered}"
        );
    }

    /// **The other half of the same bug.** A profile that declares no
    /// ports was sending an explicit empty array, which is a claim that
    /// nothing should be exposed — one the profile never made. Absent is
    /// not zero here as it is nowhere else in this vocabulary; the
    /// service's own default applies instead.
    #[test]
    fn declaring_no_ports_asks_for_nothing_rather_than_for_none() {
        let no_ports =
            Requirements::from_slots(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new()).unwrap();
        let acquisition = RunPodAdapter
            .acquisition(&no_ports, &image_provider(), None)
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert!(
            body.get("ports").is_none(),
            "an undeclared requirement carries no field: {body}"
        );
    }

    /// The same refusal, on the storage axis.
    ///
    /// No profile can reach this through [`RunPodAdapter`]: it answers
    /// `Met` for every storage request it is given today, so the arm is
    /// unreachable from the outside and a test written against the
    /// adapter would pass whether or not the answer were consulted. The
    /// body builder takes the answers as arguments precisely so this can
    /// be asked directly — the fix that has no failing case yet is the
    /// one most likely to be quietly undone.
    #[test]
    fn an_unmet_storage_answer_stops_the_request_too() {
        let disk = Requirements::from_slots(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[("persistent_gb", "4096"), ("persistent_at", "/workspace")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();

        let err = runpod_body(
            &disk,
            &image_provider(),
            Vec::new(),
            None,
            Some(Answer::Unmet {
                reason: "no volume that large".into(),
            }),
            None,
        )
        .expect_err("an answer of Unmet is not a request");
        assert!(err.to_string().contains("no volume that large"));

        // And the same answer as `Met` builds the field it always did,
        // so the guard above is a guard and not a wall.
        let body = runpod_body(
            &disk,
            &image_provider(),
            Vec::new(),
            None,
            Some(Answer::Met { using: Vec::new() }),
            None,
        )
        .unwrap();
        assert!(body.contains("\"volumeInGb\":4096"), "{body}");
    }

    /// A machine with no accelerator is a declaration, and it reaches
    /// the request as one.
    #[test]
    fn zero_accelerators_asks_for_a_machine_without_one() {
        let cpu_only = Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "0")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
        )
        .unwrap();
        let acquisition = RunPodAdapter
            .acquisition(&cpu_only, &image_provider(), None)
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["computeType"], "CPU");
        assert!(body.get("gpuCount").is_none(), "{body}");
        assert!(body.get("gpuTypeIds").is_none(), "{body}");
    }

    /// A machine cannot be created without knowing what to run on it,
    /// and that is said before anything is spent finding out. The
    /// refusal names the provider key, because that is where the image
    /// is written now.
    #[test]
    fn creating_without_an_image_is_refused() {
        let no_image =
            Requirements::from_slots(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new()).unwrap();
        assert_eq!(
            RunPodAdapter.acquisition(&no_image, &BTreeMap::new(), None),
            Err(AcquisitionError::Incomplete {
                target: "runpod",
                missing: "provider.runpod.imageName"
            })
        );
    }

    /// **Every acquisition carries its release.** One worked out later
    /// is one that leaks, and this repo has leaked two machines by hand
    /// for exactly that reason.
    #[test]
    fn an_acquisition_says_how_to_give_the_machine_back() {
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &image_provider(), None)
            .unwrap();
        assert!(acquisition.release.contains(&"delete-pod".to_string()));
        assert!(acquisition.release.contains(&"{id}".to_string()));
        assert!(acquisition.inspect.contains(&"get-pod".to_string()));
    }

    /// Not wired is said, not faked. A `docker run` would create a
    /// machine that no transport here can reach.
    #[test]
    fn a_container_says_it_cannot_acquire_rather_than_pretending() {
        let err = ContainerAdapter
            .acquisition(&full_requirements(), &image_provider(), None)
            .expect_err("no transport reaches a container");
        let rendered = err.to_string();
        assert!(rendered.contains("docker exec"), "{rendered}");
    }

    /// The shape the service returns for a pod, with the fields this
    /// reads and the identifying ones neutralised.
    ///
    /// Taken from real responses rather than invented [measured: 2026-08-11,
    /// four pods created and destroyed while measuring transfers].
    /// A create response, which is the one place the model is named.
    fn created_pod() -> serde_json::Value {
        serde_json::json!({
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
            "gpuCount": 1,
            "containerDiskInGb": 100,
            "volumeInGb": 150,
            "volumeMountPath": "/workspace",
            "ports": ["8188/http", "22/tcp"],
            "machine": {
                "gpuTypeId": "NVIDIA A40",
                "dataCenterId": "EU-SE-1"
            }
        })
    }

    /// A read-back, which is **not** the same shape.
    ///
    /// `machine` comes back empty and the model is gone
    /// [measured: 2026-08-12, `get-pod` and `list-pods` against a running
    /// pod]. This fixture used to carry the create response's `machine`
    /// object, so the catalogue lookup passed here and never once ran on
    /// a real machine.
    fn inspected_pod() -> serde_json::Value {
        serde_json::json!({
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
            "gpuCount": 1,
            "containerDiskInGb": 100,
            "volumeInGb": 150,
            "volumeMountPath": "/workspace",
            "ports": ["8188/http", "22/tcp"],
            "portMappings": { "22": 22016 },
            "publicIp": "203.0.113.10",
            "machine": {}
        })
    }

    /// **A CPU machine's zero accelerators is an observation, not a
    /// gap.** The description of a CPU pod carries no `gpuCount`, but
    /// it does carry `cpuFlavorId` — a field the service documents
    /// for CPU pods only — and that is the service saying what kind
    /// of machine this is. Without this read, `gpu.count = 0` came
    /// back `NotChecked` on every CPU pod and `acquire` refused
    /// machines that were exactly what the profile asked for.
    /// A GPU pod's stated `gpuCount` always wins.
    #[test]
    fn a_cpu_flavor_is_an_observed_zero_gpu_count() {
        let cpu_pod = serde_json::json!({
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "cpuFlavorId": "cpu3c",
            "ports": ["22/tcp"]
        });
        assert_eq!(RunPodAdapter.read_state(&cpu_pod).gpu_count, Some(0));

        let gpu_pod = serde_json::json!({ "id": "pod-id", "gpuCount": 2 });
        assert_eq!(RunPodAdapter.read_state(&gpu_pod).gpu_count, Some(2));

        let unobserved = serde_json::json!({ "id": "pod-id", "cpuFlavorId": "" });
        assert_eq!(
            RunPodAdapter.read_state(&unobserved).gpu_count,
            None,
            "an empty flavor is not a statement; absent stays not observed"
        );
    }

    /// **The address projection reads the two fields the service
    /// writes it in, and a booting pod projects to nothing.** The
    /// empty-`publicIp` shape is the create response's own
    /// [measured: 2026-08-12 fixture below]; treating it as an address
    /// would hand a caller `":16422"` to dial.
    #[test]
    fn connection_projects_public_ip_and_port_mappings_and_boot_is_empty() {
        let described = inspected_pod();
        let connection = RunPodAdapter.connection(&described);
        let ssh = connection.ssh.expect("22 is mapped and the ip is set");
        assert_eq!(ssh.host, "203.0.113.10");
        assert_eq!(ssh.port, 22016);
        assert_eq!(ssh.user, crate::ssh::DEFAULT_SSH_USER);
        assert_eq!(
            connection.endpoints.get(&22),
            Some(&"203.0.113.10:22016".to_string())
        );

        let booting = serde_json::json!({
            "id": "pod-id",
            "publicIp": "",
            "ports": ["22/tcp"]
        });
        let projected = RunPodAdapter.connection(&booting);
        assert_eq!(projected.ssh, None);
        assert!(projected.endpoints.is_empty());
        // What was read is on record, so a refusal can say which field
        // was missing rather than only that the endpoint was.
        assert_eq!(projected.read, ["publicIp: empty", "portMappings: absent"]);
    }

    /// **The loop closes** — over what the service said across both of
    /// its answers, which is what [`Acquired::inspect`] assembles.
    ///
    /// Not over the read-back alone: that one has no model in it, so the
    /// memory requirement comes back `NotChecked` and the verdict with
    /// it. The version of this test that used a create response as
    /// though it were a read-back is why the gap survived to a real
    /// machine.
    #[test]
    fn a_pod_description_reads_back_into_a_judgeable_state() {
        let mut described = inspected_pod();
        fill_blanks(&mut described, &created_pod());

        let state = RunPodAdapter.read_state(&described);
        assert!(state.ports_observed);
        assert_eq!(state.exposed.get(&8188), Some(&Exposure::PublicHttp));
        assert_eq!(state.exposed.get(&22), Some(&Exposure::RawTcp));
        assert_eq!(state.gpu_count, Some(1));
        assert_eq!(state.ephemeral_gb, Some(100));
        assert_eq!(state.persistent_gb, Some(150));
        assert_eq!(state.persistent_at.as_deref(), Some("/workspace"));

        let findings = lm_provision::machine::observe(&full_requirements(), &state);
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Satisfied,
            "{findings:#?}"
        );
    }

    /// Memory is the one field that is looked up rather than read: the
    /// description names the model and never the size, which is the same
    /// asymmetry that put the catalogue in this adapter.
    ///
    /// It arrives in the unit a device reports, and below what a device
    /// reports — the part measured here answers 46068 MiB [measured:
    /// 2026-08-12, `nvidia-smi` on the acquired A40], and the bound this
    /// produces stays under it. A bound that crept above the real figure
    /// would let a floor pass on memory that is not there.
    #[test]
    fn device_memory_comes_from_the_catalogue_and_stays_under_what_the_part_reports() {
        const A40_REPORTS_MIB: u32 = 46068;

        let known = RunPodAdapter.read_state(&created_pod());
        assert_eq!(
            known.gpu_vram_mib,
            Some(45776),
            "an A40 is sold as 48 GB, and that is a floor in the device's unit"
        );
        assert!(
            known.gpu_vram_mib.unwrap() <= A40_REPORTS_MIB,
            "the bound has to stay under the measurement, not over it"
        );

        let mut unknown_model = created_pod();
        unknown_model["machine"]["gpuTypeId"] = serde_json::json!("NVIDIA SOMETHING NEW");
        assert_eq!(
            RunPodAdapter.read_state(&unknown_model).gpu_vram_mib,
            None,
            "a model outside the catalogue leaves the size unobserved, not zero"
        );
    }

    /// **The bug this caught, and the only way it could have been
    /// caught.** The read-back a real service gives has no model in it,
    /// so a description read on its own cannot say how much memory the
    /// machine has — which is what every real run got while the tests
    /// passed against a create response.
    #[test]
    fn a_read_back_alone_cannot_say_what_the_device_is() {
        assert_eq!(
            RunPodAdapter.read_state(&inspected_pod()).gpu_vram_mib,
            None,
            "the service stopped naming the model, so nothing here knows it"
        );

        let mut restored = inspected_pod();
        fill_blanks(&mut restored, &created_pod());
        assert_eq!(
            RunPodAdapter.read_state(&restored).gpu_vram_mib,
            Some(45776),
            "what the service said once is enough, and it said it at creation"
        );
    }

    /// **The plumbing, on what the service actually said.**
    ///
    /// The two strings below are the responses a real pod produced
    /// [measured: 2026-08-12, an RTX 4090 pod created and released], trimmed
    /// to the fields this reads. They go through the same
    /// `acquire` → `inspect` → `read_state` chain a run uses, with the
    /// commands replaced by ones that print them — so what is exercised
    /// is the assembly rather than the network.
    ///
    /// The chain is where the bug was. `fill_blanks` was correct on its
    /// own; nothing called it with the creation-time description,
    /// because `inspect` had replaced that with the read-back.
    #[test]
    fn the_chain_a_run_uses_keeps_the_model_across_a_read_back() {
        let created = r#"{
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
            "gpuCount": 1, "containerDiskInGb": 50, "volumeInGb": 20,
            "volumeMountPath": "/workspace",
            "ports": ["8888/http", "22/tcp"],
            "publicIp": "",
            "machine": {"gpuTypeId": "NVIDIA GeForce RTX 4090", "location": "US"}
        }"#;
        // What get-pod gives back a minute later. Note `machine`.
        let read_back = r#"{
            "id": "pod-id",
            "desiredStatus": "RUNNING",
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04",
            "gpuCount": 1, "containerDiskInGb": 50, "volumeInGb": 20,
            "volumeMountPath": "/workspace",
            "ports": ["8888/http", "22/tcp"],
            "portMappings": {"22": 16422},
            "publicIp": "203.0.113.10",
            "machine": {}
        }"#;

        let mut acquired = acquire(Acquisition {
            discover: None,
            create: vec!["echo".into(), created.into()],
            body: None,
            created_id_key: "id",
            inspect: vec!["echo".into(), read_back.into()],
            release: vec!["true".into()],
        })
        .expect("the create response names an id");
        acquired.inspect().expect("the read-back parses");

        let state = RunPodAdapter.read_state(&acquired.inspected);
        assert_eq!(
            state.gpu_vram_mib,
            Some(22888),
            "the model survived the read-back that stopped naming it"
        );
        assert_eq!(
            acquired.inspected["publicIp"], "203.0.113.10",
            "and the read-back's own words still won: it learned an address"
        );

        let required = Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "1"), ("min_vram_gb", "24")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
        )
        .unwrap();
        let findings = lm_provision::machine::observe(&required, &state);
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Satisfied,
            "this is the verdict a real acquire prints: {findings:#?}"
        );
    }

    /// Filling blanks is not overwriting: the fresh description is the
    /// one that is true, and only what it declines to say is restored.
    #[test]
    fn what_the_fresh_description_says_wins() {
        let mut fresh = serde_json::json!({
            "desiredStatus": "EXITED",
            "volumeInGb": 0,
            "machine": {},
            "portMappings": { "22": 22016 },
        });
        fill_blanks(
            &mut fresh,
            &serde_json::json!({
                "desiredStatus": "RUNNING",
                "volumeInGb": 150,
                "machine": { "gpuTypeId": "NVIDIA A40" },
                "imageName": "runpod/pytorch:2.4.0",
            }),
        );

        assert_eq!(fresh["desiredStatus"], "EXITED", "a stopped pod is stopped");
        assert_eq!(fresh["volumeInGb"], 0, "zero is a statement, not a blank");
        assert_eq!(fresh["machine"]["gpuTypeId"], "NVIDIA A40");
        assert_eq!(fresh["imageName"], "runpod/pytorch:2.4.0");
        assert_eq!(fresh["portMappings"]["22"], 22016);
    }

    /// A description with no ports field is one nobody looked at; a
    /// description with an empty one exposed nothing. Those are
    /// different answers.
    #[test]
    fn an_absent_ports_field_is_not_an_empty_one() {
        let mut without = inspected_pod();
        without.as_object_mut().unwrap().remove("ports");
        assert!(!RunPodAdapter.read_state(&without).ports_observed);

        let mut empty = inspected_pod();
        empty["ports"] = serde_json::json!([]);
        let state = RunPodAdapter.read_state(&empty);
        assert!(state.ports_observed);
        assert!(state.exposed.is_empty());
    }

    /// A machine that came back without what was asked for is caught by
    /// looking, not by the run failing later somewhere else.
    #[test]
    fn a_machine_missing_a_port_is_unsatisfied() {
        let mut missing = inspected_pod();
        missing["ports"] = serde_json::json!(["22/tcp"]);
        let findings = lm_provision::machine::observe(
            &full_requirements(),
            &RunPodAdapter.read_state(&missing),
        );
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Unsatisfied,
            "{findings:#?}"
        );
    }

    /// Keys for another target are reported, not dropped in silence: the
    /// one being ignored may be where the weights live.
    #[test]
    fn keys_for_another_target_are_reported() {
        let provider: BTreeMap<String, String> = [
            ("runpod.imageName", "runpod/pytorch:2.4.0"),
            ("runpod.networkVolumeId", "vol-1"),
            ("container.network", "bridge"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        assert_eq!(
            unexamined(&ContainerAdapter, &provider),
            vec!["runpod.imageName", "runpod.networkVolumeId"]
        );
        assert_eq!(
            unexamined(&RunPodAdapter, &provider),
            vec!["container.network"]
        );
    }

    /// What a marketplace profile asks for: raw TCP (there is no
    /// managed HTTPS proxy to require), one 40 GB device, one sized
    /// disk.
    fn marketplace_requirements() -> Requirements {
        Requirements::from_slots(
            &[("8000", "raw_tcp")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("count", "1"), ("min_vram_gb", "40")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("ephemeral_gb", "60")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .expect("well-formed fixture")
    }

    fn marketplace_provider() -> BTreeMap<String, String> {
        [("vast.image", "pytorch/pytorch:2.4.0")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// **The selection is the query.** Every requirement lands in the
    /// discovery as the marketplace's own filter word, the sort is
    /// ascending price, and the create call takes the winner by
    /// placeholder — so a dry-run shows an operator the whole policy.
    #[test]
    fn a_marketplace_acquisition_discovers_before_it_creates() {
        let acquisition = VastAdapter
            .acquisition(&marketplace_requirements(), &marketplace_provider(), None)
            .expect("an image was declared");

        let discover = acquisition.discover.as_ref().expect("offers come first");
        let query = discover
            .iter()
            .find(|it| it.contains("rentable=true"))
            .expect("the query is one argument");
        for filter in [
            "verified=true",
            "num_gpus>=1",
            "gpu_ram>=40",
            "disk_space>=60",
        ] {
            assert!(query.contains(filter), "{filter} missing from: {query}");
        }
        let sort = discover.iter().position(|it| it == "-o");
        assert!(
            sort.is_some_and(|at| discover.get(at + 1).is_some_and(|it| it == "dph")),
            "ascending price is the selection policy: {discover:?}"
        );

        assert!(acquisition.create.contains(&"{offer_id}".to_string()));
        assert!(acquisition.create.contains(&"--ssh".to_string()));
        assert!(acquisition
            .create
            .contains(&"pytorch/pytorch:2.4.0".to_string()));
        assert!(acquisition.create.contains(&"-p 8000:8000".to_string()));
        assert_eq!(acquisition.created_id_key, "new_contract");
        assert!(acquisition.release.contains(&"destroy".to_string()));
        assert!(acquisition.release.contains(&"{id}".to_string()));
        assert!(
            acquisition.release.contains(&"--yes".to_string()),
            "without --yes the CLI's confirmation prompt reads EOF as \"no\" and exits \
             zero — a release that reports success while the machine runs on billing: \
             {:?}",
            acquisition.release
        );
    }

    /// The same refusal as the pod service's, naming this platform's
    /// own key.
    #[test]
    fn the_marketplace_refuses_to_create_without_an_image_too() {
        assert_eq!(
            VastAdapter.acquisition(&marketplace_requirements(), &BTreeMap::new(), None),
            Err(AcquisitionError::Incomplete {
                target: "vast",
                missing: "provider.vast.image"
            })
        );
    }

    /// A persistent level is refused rather than quietly mapped onto
    /// the one disk an instance has.
    #[test]
    fn a_persistent_level_is_refused_not_mapped() {
        let answer = VastAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: None,
            persistent_gb: Some(50),
            persistent_at: Some("/workspace".into()),
        });
        let Answer::Unmet { reason } = answer else {
            panic!("one disk cannot be a persisted volume: {answer:?}");
        };
        assert!(reason.contains("persisted"), "{reason}");
    }

    /// A machine with no accelerator is not something a GPU marketplace
    /// sells, and that is said rather than searched for.
    #[test]
    fn zero_accelerators_is_refused_on_a_gpu_marketplace() {
        let answer = VastAdapter.gpu_answer(&GpuRequirement {
            count: 0,
            min_vram_gb: None,
        });
        assert!(answer.blocks(), "{answer:?}");
    }

    /// The discovery's first row fills the create call: `{offer_id}`
    /// is substituted, and the numeric `new_contract` the service
    /// answers with becomes the machine's id.
    #[test]
    fn the_discovery_feeds_the_create_call_and_the_numeric_id_is_read() {
        let acquired = acquire(Acquisition {
            discover: Some(vec![
                "echo".into(),
                r#"[{"id": 123, "dph_total": 0.27}, {"id": 456, "dph_total": 0.44}]"#.into(),
            ]),
            create: vec!["echo".into(), r#"{"new_contract": {offer_id}}"#.into()],
            body: None,
            created_id_key: "new_contract",
            inspect: vec!["echo".into(), "{}".into()],
            release: vec!["true".into()],
        })
        .expect("the discovery found offers");
        assert_eq!(
            acquired.id, "123",
            "the first row of the price-sorted query is the machine"
        );
    }

    /// A progress line is free to contain a bracket, and the payload is
    /// still found — stopping at the first `[` fed `[INFO] …` to the
    /// parser and broke the path that had always worked.
    #[test]
    fn a_progress_line_with_a_bracket_does_not_hide_the_payload() {
        let acquired = acquire(Acquisition {
            discover: None,
            create: vec![
                "printf".into(),
                "[INFO] creating pod\\n{\"id\": \"pod-1\"}".into(),
            ],
            body: None,
            created_id_key: "id",
            inspect: vec!["echo".into(), "{}".into()],
            release: vec!["true".into()],
        })
        .expect("the payload follows the progress line");
        assert_eq!(acquired.id, "pod-1");
    }

    /// A query that matches nothing is a marketplace out of stock, said
    /// with the query in it, before anything is spent.
    #[test]
    fn an_empty_discovery_is_out_of_stock_not_a_machine() {
        let err = acquire(Acquisition {
            discover: Some(vec!["echo".into(), "[]".into()]),
            create: vec!["true".into()],
            body: None,
            created_id_key: "new_contract",
            inspect: vec!["true".into()],
            release: vec!["true".into()],
        })
        .expect_err("nothing to create from");
        assert!(matches!(err, ExecuteError::NoCandidates { .. }), "{err:?}");
    }

    /// The description names the device's memory directly — the figure
    /// the device itself reports, so it lands as MiB with no catalogue
    /// in between — and the connection comes from the service's own ssh
    /// fields plus the docker-style port map.
    #[test]
    fn the_marketplace_description_reads_back_without_a_catalogue() {
        let inspected = serde_json::json!({
            "actual_status": "running",
            "ssh_host": "ssh2281.vast.ai",
            "ssh_port": 10882,
            "public_ipaddr": "63.135.50.11",
            "ports": {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "44227"}]},
            "gpu_name": "RTX A5000",
            "num_gpus": 1,
            "gpu_ram": 24564,
            "disk_space": 60.4
        });

        let state = VastAdapter.read_state(&inspected);
        assert_eq!(state.gpu_count, Some(1));
        assert_eq!(state.gpu_vram_mib, Some(24564));
        assert_eq!(state.ephemeral_gb, Some(60));
        assert_eq!(state.exposed.get(&8000), Some(&Exposure::RawTcp));
        assert!(state.ports_observed);

        let connection = VastAdapter.connection(&inspected);
        let ssh = connection.ssh.expect("--ssh --direct was asked for");
        assert_eq!(ssh.host, "ssh2281.vast.ai");
        assert_eq!(ssh.port, 10882);
        assert_eq!(
            connection.endpoints.get(&8000).map(String::as_str),
            Some("63.135.50.11:44227")
        );

        // A booting instance writes `"ports": null` before the
        // container runs — null is nobody having looked yet, not a
        // machine exposing nothing, and reading it as observed
        // condemned a machine that was merely still starting.
        let booting = serde_json::json!({ "ports": null });
        assert!(
            !VastAdapter.read_state(&booting).ports_observed,
            "null is not an observation"
        );
    }

    /// The platform's own word for "not yet" extends the wait; its
    /// silence and its "running" do not.
    #[test]
    fn only_the_platforms_own_loading_claim_extends_the_wait() {
        let loading = serde_json::json!({ "actual_status": "loading" });
        let created = serde_json::json!({ "actual_status": "created" });
        let running = serde_json::json!({ "actual_status": "running" });
        let silent = serde_json::json!({});
        assert!(VastAdapter.still_materializing(&loading));
        assert!(VastAdapter.still_materializing(&created));
        assert!(!VastAdapter.still_materializing(&running));
        assert!(
            !VastAdapter.still_materializing(&silent),
            "absence of a claim is not a claim"
        );
        assert!(
            !RunPodAdapter.still_materializing(&loading),
            "another platform's field is not this platform's word"
        );
    }

    /// No managed HTTPS proxy means a `public_http` requirement is
    /// turned away while the bill is still zero.
    #[test]
    fn a_public_http_requirement_is_refused_at_admission() {
        let required = Requirements::from_slots(
            &[("8188", "public_http")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(lm_provision::machine::admit(&required, &VastAdapter.capability()).is_err());
    }

    fn at(rfc3339: &str) -> jiff::Timestamp {
        rfc3339.parse().expect("a fixed instant")
    }

    /// **The lease survives the round trip through a platform's name
    /// field**, which is the whole basis of reading expiry off the
    /// machine instead of out of a file.
    #[test]
    fn a_lease_written_onto_a_machine_reads_back_as_the_same_instant() {
        let expires_at = at("2026-09-02T06:30:00Z");
        let stamp = expiry_stamp(expires_at);
        assert_eq!(stamp, "lmp-exp-20260902T063000Z");
        assert!(
            !stamp.contains(':'),
            "colon-free: these land in fields each platform constrains its own way"
        );
        assert_eq!(expiry_of(&stamp), Some(expires_at));

        // Sub-second precision is dropped, and only that: the record
        // keeps what the clock gave it, the machine carries the second
        // the lease ends.
        assert_eq!(
            expiry_of(&expiry_stamp(at("2026-09-02T06:30:00.123456789Z"))),
            Some(expires_at)
        );
    }

    /// **Anything else is not a lease.** A machine this cannot read is
    /// reported as unknown and never released, so every string here is
    /// the difference between "leave it alone" and "delete it".
    #[test]
    fn nothing_but_the_stamp_reads_as_a_lease() {
        for not_a_lease in [
            "",
            "comfyui-box",
            "lmp-exp-",
            "lmp-exp-20260902T063000",      // no zone marker
            "lmp-exp-2026-09-02T06:30:00Z", // the separators are the point
            "lmp-exp-20261301T000000Z",     // month 13
            "lmp-exp-20260932T000000Z",     // day 32
            "lmp-exp-2026090aT063000Z",     // not digits
            "lmp-exp-20260902T063000Z-old", // trailing anything
            " lmp-exp-20260902T063000Z",    // leading anything
            "exp-20260902T063000Z",         // another tool's prefix
            "lmp-exp-20260902T0630000Z",    // one digit too many
        ] {
            assert_eq!(
                expiry_of(not_a_lease),
                None,
                "{not_a_lease:?} would be read as a lease"
            );
        }
    }

    /// The lease reaches the machine in each platform's own field: a
    /// `name` in the pod service's request body, a `--label` in the
    /// marketplace's argv.
    #[test]
    fn each_platform_carries_the_lease_in_its_own_field() {
        let expires_at = at("2026-09-02T06:30:00Z");
        let stamp = expiry_stamp(expires_at);

        let pod = RunPodAdapter
            .acquisition(&full_requirements(), &image_provider(), Some(expires_at))
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(pod.body.as_deref().expect("this target takes a body")).unwrap();
        assert_eq!(body["name"], serde_json::json!(stamp));

        let instance = VastAdapter
            .acquisition(
                &marketplace_requirements(),
                &marketplace_provider(),
                Some(expires_at),
            )
            .expect("an image was declared");
        let label = instance
            .create
            .iter()
            .position(|it| it == "--label")
            .expect("the marketplace takes a label");
        assert_eq!(instance.create.get(label + 1), Some(&stamp));

        let container = DeepInfraAdapter
            .acquisition(
                &container_requirements(),
                &container_provider(),
                Some(expires_at),
            )
            .expect("an image and a key were declared");
        let body: serde_json::Value =
            serde_json::from_str(container.body.as_deref().expect("this target takes a body"))
                .unwrap();
        assert_eq!(body["name"], serde_json::json!(stamp));

        // Nothing bought, nothing stamped: a rendering wanted for its
        // release template does not claim a lease. On the container
        // service `name` is required by the create call, so the
        // unstamped rendering is one the service would refuse.
        let unstamped = DeepInfraAdapter
            .acquisition(&container_requirements(), &container_provider(), None)
            .expect("an image and a key were declared");
        let body: serde_json::Value =
            serde_json::from_str(unstamped.body.as_deref().unwrap()).unwrap();
        assert_eq!(body.get("name"), None);

        let deployment = DeepInfraDeployAdapter
            .acquisition(
                &deployment_requirements(),
                &deployment_provider(),
                Some(expires_at),
            )
            .expect("a service and a GPU were declared");
        let body: serde_json::Value =
            serde_json::from_str(deployment.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["model_name"], serde_json::json!(stamp));
        let unstamped = RunPodAdapter
            .acquisition(&full_requirements(), &image_provider(), None)
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(unstamped.body.as_deref().unwrap()).unwrap();
        assert_eq!(body.get("name"), None);
    }

    /// **The profile does not get the last word on this one field.**
    /// A `provider.runpod.name` overwriting the stamp would list the
    /// machine as unknown — reported, never released — and a machine
    /// that cannot expire is the accident this mechanism removes.
    #[test]
    fn a_profile_cannot_name_a_machine_out_of_the_sweepers_reach() {
        let mut provider = image_provider();
        provider.insert("runpod.name".to_string(), "my-box".to_string());
        let expires_at = at("2026-09-02T06:30:00Z");
        let acquisition = RunPodAdapter
            .acquisition(&full_requirements(), &provider, Some(expires_at))
            .expect("an image was declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["name"], serde_json::json!(expiry_stamp(expires_at)));
    }

    /// **One release template and one read-back template, whichever
    /// half of a sweep or a lookup found the machine.** A machine
    /// released from the record and one released from the platform's
    /// own list are released by the same command; a machine asked
    /// about by an id alone is asked with the command the acquisition
    /// would have used. Two copies would be two commands that could
    /// drift, and the drifted release would be found by a machine that
    /// would not die.
    #[test]
    fn the_listing_and_the_acquisition_reach_a_machine_the_same_way() {
        let pod = RunPodAdapter
            .acquisition(&full_requirements(), &image_provider(), None)
            .expect("an image was declared");
        let pods = RunPodAdapter.fleet().expect("this target can be asked");
        assert_eq!(pods.release, pod.release);
        assert_eq!(pods.inspect, pod.inspect);

        let instance = VastAdapter
            .acquisition(&marketplace_requirements(), &marketplace_provider(), None)
            .expect("an image was declared");
        let instances = VastAdapter.fleet().expect("this target can be asked");
        assert_eq!(instances.release, instance.release);
        assert_eq!(instances.inspect, instance.inspect);

        let container = DeepInfraAdapter
            .acquisition(&container_requirements(), &container_provider(), None)
            .expect("an image and a key were declared");
        let containers = DeepInfraAdapter.fleet().expect("this target can be asked");
        assert_eq!(containers.release, container.release);
        assert_eq!(containers.inspect, container.inspect);

        let deployment = DeepInfraDeployAdapter
            .acquisition(&deployment_requirements(), &deployment_provider(), None)
            .expect("a service and a GPU were declared");
        let deployments = DeepInfraDeployAdapter
            .fleet()
            .expect("this target can be asked");
        assert_eq!(deployments.release, deployment.release);
        assert_eq!(deployments.inspect, deployment.inspect);

        // Every template takes the machine's id — as a word of its own
        // on the two CLIs, inside the URL on the REST surface; `substitute`
        // fills either — so a caller holding one identifier can reach
        // any of them.
        for argv in [
            &pods.inspect,
            &instances.inspect,
            &containers.inspect,
            &deployments.inspect,
        ] {
            assert!(
                argv.iter().any(|it| it.contains("{id}")),
                "the read-back is a template an id fills: {argv:?}"
            );
        }

        assert!(
            ContainerAdapter.fleet().is_none(),
            "a target that acquires nothing has no fleet to enumerate"
        );
    }

    /// **One machine, read back by its id and nothing else.** The
    /// identifier substitutes into the fleet's own template and what
    /// the platform printed comes back parsed — which is what lets an
    /// operator who has only the id reach the machine's address.
    #[test]
    fn one_machine_is_read_back_from_its_id_alone() {
        let described = inspect(
            &Fleet {
                list: vec!["true".into()],
                id: "id",
                stamp: "name",
                stamp_namespaced: false,
                release: vec!["true".into()],
                inspect: vec![
                    "printf".into(),
                    r#"{"id": "%s", "publicIp": "203.0.113.9"}"#.into(),
                    "{id}".into(),
                ],
            },
            "pod-7",
        )
        .expect("the stub printed a description");
        assert_eq!(described["id"], serde_json::json!("pod-7"));
        assert_eq!(described["publicIp"], serde_json::json!("203.0.113.9"));
    }

    /// **The rows each platform prints, read into the same two facts.**
    /// One answers with a bare array and one wraps its rows in an
    /// object; one names the machine with a string and one with a
    /// number; the field the stamp rides in is `name` on one and
    /// `label` on the other. What comes out is an id and what it is
    /// called.
    #[test]
    fn both_platforms_listings_read_into_an_id_and_a_name() {
        let pods = RunPodAdapter.fleet().expect("this target can be asked");
        let listed = serde_json::json!({
            "pods": [
                { "id": "pod-a", "name": "lmp-exp-20260902T063000Z" },
                { "id": "pod-b", "name": "" },
                { "id": "pod-c" },
                { "name": "lmp-exp-20260902T063000Z" },
            ]
        });
        assert_eq!(
            machines(&listed, &pods).expect("rows carrying the id key are the fleet"),
            vec![
                Machine {
                    id: "pod-a".to_string(),
                    name: Some("lmp-exp-20260902T063000Z".to_string()),
                },
                Machine {
                    id: "pod-b".to_string(),
                    name: None,
                },
                Machine {
                    id: "pod-c".to_string(),
                    name: None,
                },
            ],
            "an empty name is no name, and a row with no id is nothing that could be released"
        );

        let instances = VastAdapter.fleet().expect("this target can be asked");
        let listed = serde_json::json!([
            { "id": 49227715, "label": "lmp-exp-20260902T063000Z" },
            { "id": 49228600, "label": null },
        ]);
        assert_eq!(
            machines(&listed, &instances).expect("a bare array is the rows"),
            vec![
                Machine {
                    id: "49227715".to_string(),
                    name: Some("lmp-exp-20260902T063000Z".to_string()),
                },
                Machine {
                    id: "49228600".to_string(),
                    name: None,
                },
            ],
            "a numeric id is the machine's name in every argv this drives"
        );
    }

    /// **A listing that cannot be read is an error, never an empty
    /// fleet.** The sweep treats "listed, and absent" as proof a
    /// recorded machine is gone and retires its row — so a shape this
    /// silently read as zero machines would retire the whole record
    /// while everything on it kept billing. Only genuinely empty rows
    /// are an empty account.
    #[test]
    fn a_listing_that_cannot_be_read_is_an_error_not_an_empty_fleet() {
        let pods = RunPodAdapter.fleet().expect("this target can be asked");

        assert_eq!(
            machines(&serde_json::json!({ "pods": [] }), &pods),
            Ok(Vec::new()),
            "an emptied account is a real answer"
        );
        assert_eq!(
            machines(&serde_json::json!({ "errors": [], "pods": [] }), &pods),
            Ok(Vec::new()),
            "and stays one beside an empty sibling array"
        );
        assert_eq!(
            machines(
                &serde_json::json!({
                    "errors": [],
                    "pods": [{ "id": "pod-a", "name": "x" }],
                }),
                &pods
            )
            .expect("the rows are the array whose entries carry the id key")
            .len(),
            1,
            "an empty sibling that sorts first does not shadow the fleet"
        );

        for unreadable in [
            serde_json::json!({ "error": "unauthorized" }),
            serde_json::json!("unauthorized"),
            // Rows exist but none carries the id key: a shape change,
            // not an empty account.
            serde_json::json!({ "pods": [{ "podId": "pod-a" }] }),
            serde_json::json!([{ "podId": "pod-a" }]),
        ] {
            assert!(
                machines(&unreadable, &pods).is_err(),
                "{unreadable} would have been read as an empty fleet"
            );
        }
    }

    /// The listing goes through a real process: what the platform CLI
    /// printed is parsed, and what it said on the way back is handed to
    /// the caller to relay rather than written to a stream from here.
    #[test]
    fn a_listing_reads_the_clis_output_and_hands_back_what_it_said() {
        let listing = list(&Fleet {
            list: vec![
                "sh".into(),
                "-c".into(),
                "echo 'fetching...' >&2; echo '[{\"id\": 7, \"label\": \
                 \"lmp-exp-20260902T063000Z\"}]'"
                    .into(),
            ],
            id: "id",
            stamp: "label",
            stamp_namespaced: false,
            release: vec!["true".into()],
            inspect: vec!["true".into()],
        })
        .expect("the stub printed a list");
        assert_eq!(
            listing.machines,
            vec![Machine {
                id: "7".to_string(),
                name: Some("lmp-exp-20260902T063000Z".to_string()),
            }]
        );
        assert_eq!(String::from_utf8_lossy(&listing.said).trim(), "fetching...");
    }

    // ---- The container-rental service ----

    /// A profile for the container-rental service: a GPU and nothing
    /// mapped — the service exposes no port, so none is declared.
    fn container_requirements() -> Requirements {
        Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "2"), ("min_vram_gb", "80")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
        )
        .expect("well-formed fixture")
    }

    /// The image and the key, under the service's own field name and
    /// this adapter's one word of vocabulary.
    fn container_provider() -> BTreeMap<String, String> {
        [
            ("deepinfra.container_image", "di-cont-ubuntu-torch:latest"),
            (
                "deepinfra.ssh_authorized_key",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly operator@host",
            ),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// **The four fields the create call takes, and nothing else** —
    /// each traceable to a line the profile wrote or to the lease: the
    /// image from the slot, the configuration from the GPU answer in
    /// the service's `{count}x{model}` spelling, the cloud-init
    /// document from the key, and the stamp as `name`.
    #[test]
    fn the_container_request_is_the_four_fields_the_service_defines() {
        let expires_at = at("2026-09-02T06:30:00Z");
        let acquisition = DeepInfraAdapter
            .acquisition(
                &container_requirements(),
                &container_provider(),
                Some(expires_at),
            )
            .expect("an image and a key were declared");
        let body: serde_json::Value = serde_json::from_str(
            acquisition
                .body
                .as_deref()
                .expect("this target takes a body"),
        )
        .unwrap();
        let fields: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            vec!["cloud_init_user_data", "container_image", "gpu_config", "name"],
            "every field emitted is one the create call defines, and every one it requires is there"
        );
        assert_eq!(body["container_image"], "di-cont-ubuntu-torch:latest");
        assert_eq!(body["gpu_config"], "2xB200-180GB");
        assert_eq!(body["name"], serde_json::json!(expiry_stamp(expires_at)));

        let cloud_init = body["cloud_init_user_data"].as_str().unwrap();
        assert!(cloud_init.starts_with("#cloud-config\n"), "{cloud_init}");
        assert!(cloud_init.contains("- name: ubuntu\n"), "{cloud_init}");
        assert!(
            cloud_init.contains("- \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly operator@host\""),
            "the key is the one line the profile gave, quoted so nothing in it reads as YAML: {cloud_init}"
        );

        // The body is the argument after `--json`, which `acquire`
        // appends last — so `--json` has to be the last word here.
        assert_eq!(
            acquisition.create.last().map(String::as_str),
            Some("--json")
        );
        assert_eq!(acquisition.create[0], "curl");
        assert!(
            acquisition.discover.is_none(),
            "the create call selects by itself"
        );
        assert_eq!(acquisition.created_id_key, "container_id");
    }

    /// **The credential travels by name.** The argv names the variable
    /// twice — once to import it into curl, once to place it in the
    /// header — and nowhere carries a value; the adapter declares the
    /// same name so it is required before anything is spent.
    #[test]
    fn the_container_service_is_authenticated_without_a_value_in_the_argv() {
        assert_eq!(DeepInfraAdapter.credentials(), &["DEEPINFRA_API_KEY"]);
        let fleet = DeepInfraAdapter.fleet().expect("this target can be asked");
        for argv in [&fleet.list, &fleet.inspect, &fleet.release] {
            assert!(argv.contains(&"%DEEPINFRA_API_KEY".to_string()), "{argv:?}");
            assert!(
                argv.contains(&"Authorization: Bearer {{DEEPINFRA_API_KEY}}".to_string()),
                "{argv:?}"
            );
            assert!(
                !argv
                    .iter()
                    .any(|it| it.starts_with("Authorization: Bearer ") && !it.contains("{{")),
                "no argument carries a literal bearer value: {argv:?}"
            );
        }
        assert!(
            fleet.release.windows(2).any(|it| it == ["-X", "DELETE"]),
            "the release is the DELETE: {:?}",
            fleet.release
        );
        assert!(
            !fleet.list.iter().any(|it| it == "-X"),
            "the listing is the plain GET: {:?}",
            fleet.list
        );
    }

    /// Each of the two things the create call cannot do without is
    /// refused by name when absent — and the profile's own cloud-init
    /// document stands in for the key when it writes one.
    #[test]
    fn the_container_service_refuses_without_an_image_or_a_key() {
        let mut no_image = container_provider();
        no_image.remove("deepinfra.container_image");
        assert_eq!(
            DeepInfraAdapter.acquisition(&container_requirements(), &no_image, None),
            Err(AcquisitionError::Incomplete {
                target: "deepinfra",
                missing: "provider.deepinfra.container_image",
            })
        );

        let mut no_key = container_provider();
        no_key.remove("deepinfra.ssh_authorized_key");
        let refusal = DeepInfraAdapter
            .acquisition(&container_requirements(), &no_key, None)
            .expect_err("nothing could reach the container");
        assert!(
            refusal
                .to_string()
                .contains("provider.deepinfra.ssh_authorized_key"),
            "{refusal}"
        );

        no_key.insert(
            "deepinfra.cloud_init_user_data".to_string(),
            "#cloud-config\nusers: []\n".to_string(),
        );
        let own_document = DeepInfraAdapter
            .acquisition(&container_requirements(), &no_key, None)
            .expect("a document of the profile's own is enough");
        let body: serde_json::Value =
            serde_json::from_str(own_document.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["cloud_init_user_data"], "#cloud-config\nusers: []\n");

        // No GPU requirement and no configuration named: the service
        // requires one, and the refusal says so rather than sending a
        // request the service would refuse.
        let no_gpu = Requirements::from_slots(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new())
            .expect("an empty declaration is well-formed");
        assert_eq!(
            DeepInfraAdapter.acquisition(&no_gpu, &container_provider(), None),
            Err(AcquisitionError::Incomplete {
                target: "deepinfra",
                missing: "requires_gpu (or provider.deepinfra.gpu_config)",
            })
        );
    }

    /// The profile's own `gpu_config` replaces the selected one, and the
    /// key is consumed rather than forwarded as a field the service
    /// would not know.
    #[test]
    fn a_named_configuration_wins_and_the_key_is_not_forwarded() {
        let mut provider = container_provider();
        provider.insert(
            "deepinfra.gpu_config".to_string(),
            "4xB200-180GB".to_string(),
        );
        let acquisition = DeepInfraAdapter
            .acquisition(&container_requirements(), &provider, None)
            .expect("an image and a key were declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["gpu_config"], "4xB200-180GB");
        assert!(body.get("ssh_authorized_key").is_none(), "{body}");
    }

    /// A floor the one catalogued model clears is met in the service's
    /// spelling; one it does not is refused with the way out; a profile
    /// asking for no GPU has nothing to rent here.
    #[test]
    fn the_container_service_selects_one_configuration_or_says_why_not() {
        let fits = DeepInfraAdapter.gpu_answer(&GpuRequirement {
            count: 8,
            min_vram_gb: Some(180),
        });
        assert_eq!(
            fits,
            Answer::Met {
                using: vec!["8xB200-180GB".to_string()]
            }
        );

        let beyond = DeepInfraAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(200),
        });
        match beyond {
            Answer::Unmet { reason } => {
                assert!(reason.contains("200 GB"), "{reason}");
                assert!(reason.contains("provider.deepinfra.gpu_config"), "{reason}");
            }
            other => panic!("nothing catalogued carries 200 GB: {other:?}"),
        }

        assert!(DeepInfraAdapter
            .gpu_answer(&GpuRequirement {
                count: 0,
                min_vram_gb: None
            })
            .blocks());
    }

    /// A persistent level is refused, as on the marketplace; an
    /// ephemeral size is not examined — and, because this target builds
    /// the request, that becomes a refusal at the body.
    #[test]
    fn the_container_service_takes_no_disk_size() {
        assert!(DeepInfraAdapter
            .disk_answer(&DiskRequirement {
                ephemeral_gb: None,
                persistent_gb: Some(80),
                persistent_at: None,
            })
            .blocks());
        let sized = DeepInfraAdapter.disk_answer(&DiskRequirement {
            ephemeral_gb: Some(60),
            persistent_gb: None,
            persistent_at: None,
        });
        assert!(matches!(sized, Answer::NotExamined { .. }), "{sized:?}");

        let with_disk = Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "1")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("ephemeral_gb", "60")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();
        let refusal = DeepInfraAdapter
            .acquisition(&with_disk, &container_provider(), None)
            .expect_err("a size nothing can ask for is not sent");
        assert!(
            matches!(
                refusal,
                AcquisitionError::Unmet {
                    target: "deepinfra",
                    ..
                }
            ),
            "{refusal}"
        );
    }

    /// **The refusal of a port declaration is real.** The service maps
    /// nothing, so the capability lists no exposure, and admission
    /// turns a `requires_ports` profile away by name.
    #[test]
    fn a_port_declaration_is_refused_at_admission_on_the_container_service() {
        let capability = DeepInfraAdapter.capability();
        assert!(capability.exposures.is_empty());
        let refusal = lm_provision::machine::admit(&required(&[("8000", "raw_tcp")]), &capability)
            .expect_err("nothing here maps a port");
        let rendered = refusal.to_string();
        assert!(rendered.contains("deepinfra"), "{rendered}");
        assert!(rendered.contains("8000"), "{rendered}");
        assert!(rendered.contains("no exposure at all"), "{rendered}");
        assert!(
            DeepInfraAdapter
                .render(&required(&[("8000", "raw_tcp")]))
                .is_empty(),
            "and there is nothing to render for one"
        );
    }

    /// **The address is reported only once the service calls the
    /// container running**, and the state is in what was read — so the
    /// operator refused for want of an endpoint learns whether the
    /// machine is still coming up or has failed.
    #[test]
    fn the_container_address_is_reachable_only_once_running() {
        let starting = serde_json::json!({
            "id": "c-1", "name": "lmp-exp-20260902T063000Z", "state": "starting",
            "ip": "203.0.113.20", "gpu_config": "2xB200-180GB", "fail_reason": null
        });
        let connection = DeepInfraAdapter.connection(&starting);
        assert!(
            connection.ssh.is_none(),
            "an address sshd is not yet behind is not one to dial"
        );
        assert!(
            connection.read.contains(&"state: starting".to_string()),
            "{:?}",
            connection.read
        );
        assert!(
            connection.read.contains(&"ip: present".to_string()),
            "{:?}",
            connection.read
        );
        assert!(DeepInfraAdapter.still_materializing(&starting));

        let mut running = starting.clone();
        running["state"] = serde_json::json!("running");
        let connection = DeepInfraAdapter.connection(&running);
        let ssh = connection.ssh.expect("running, with an address");
        assert_eq!(ssh.host, "203.0.113.20");
        assert_eq!(ssh.port, 22);
        assert_eq!(ssh.user, "ubuntu", "the image's user, not root");
        assert!(
            connection.endpoints.is_empty(),
            "nothing is mapped, so nothing per port is projected"
        );
        assert!(!DeepInfraAdapter.still_materializing(&running));

        let mut failed = starting.clone();
        failed["state"] = serde_json::json!("failed");
        failed["fail_reason"] = serde_json::json!("image pull failed");
        let connection = DeepInfraAdapter.connection(&failed);
        assert!(connection.ssh.is_none());
        assert!(
            connection.read.contains(&"state: failed".to_string()),
            "{:?}",
            connection.read
        );
        assert!(
            connection
                .read
                .contains(&"fail_reason: present".to_string()),
            "{:?}",
            connection.read
        );
        assert!(
            !DeepInfraAdapter.still_materializing(&failed),
            "a failure is not a machine still coming up"
        );

        let created = serde_json::json!({ "container_id": "c-1" });
        assert!(DeepInfraAdapter.connection(&created).ssh.is_none());
        assert!(
            !DeepInfraAdapter.still_materializing(&created),
            "absence of a claim is not a claim"
        );
    }

    /// The configuration reads back into a count and a catalogued
    /// memory; ports are never observed; a configuration this cannot
    /// read leaves both unobserved rather than zero.
    #[test]
    fn the_container_description_reads_back_into_a_judgeable_state() {
        let described = serde_json::json!({
            "id": "c-1", "state": "running", "ip": "203.0.113.20", "gpu_config": "2xB200-180GB"
        });
        let state = DeepInfraAdapter.read_state(&described);
        assert_eq!(state.gpu_count, Some(2));
        assert_eq!(state.gpu_vram_mib, Some(gb_to_mib(180)));
        assert!(!state.ports_observed);
        assert_eq!(state.ephemeral_gb, None);

        let findings = lm_provision::machine::observe(&container_requirements(), &state);
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Satisfied,
            "{findings:#?}"
        );

        let unreadable =
            DeepInfraAdapter.read_state(&serde_json::json!({ "gpu_config": "B200-180GB" }));
        assert_eq!(unreadable.gpu_count, None);
        assert_eq!(unreadable.gpu_vram_mib, None);
    }

    /// The listing is a bare array under `id` and `name`, read into
    /// the same two facts as the other platforms'.
    #[test]
    fn the_container_listing_reads_into_an_id_and_a_name() {
        let containers = DeepInfraAdapter.fleet().expect("this target can be asked");
        let listed = serde_json::json!([
            { "id": "c-a", "name": "lmp-exp-20260902T063000Z", "state": "running" },
            { "id": "c-b", "name": "scratch", "state": "creating" },
        ]);
        assert_eq!(
            machines(&listed, &containers).expect("a bare array is the rows"),
            vec![
                Machine {
                    id: "c-a".to_string(),
                    name: Some("lmp-exp-20260902T063000Z".to_string()),
                },
                Machine {
                    id: "c-b".to_string(),
                    name: Some("scratch".to_string()),
                },
            ]
        );
    }

    /// The image is not preflighted here, and the reason is stated: the
    /// service's own image names are on no registry the check could
    /// ask, and a refusal of the documented default would cost more
    /// than the pull it prevents.
    #[test]
    fn the_container_service_names_no_image_to_preflight() {
        assert_eq!(DeepInfraAdapter.image_key(), None);
        assert_eq!(DeepInfraAdapter.provider_namespace(), "deepinfra");
        assert!(adapter_named("deepinfra").is_ok());
        let refusal = adapter_named("deepinfra-serverless")
            .err()
            .expect("no such platform");
        assert!(
            refusal.contains("deepinfra"),
            "the way out names every wired platform: {refusal}"
        );
    }

    // ---- The managed deployment ----

    fn serving() -> lm_provision::machine::Serving {
        lm_provision::machine::Serving {
            name: "llm".to_string(),
            engine: "vllm".to_string(),
            model: Some("Qwen/Qwen3-8B".to_string()),
            dtype: Some("bfloat16".to_string()),
            tensor_parallel_size: Some(2),
            extra_args: vec!["--max-model-len".to_string(), "32768".to_string()],
            others: Vec::new(),
        }
    }

    /// A profile for the managed deployment: two GPUs of at least 80 GB,
    /// no ports, no disk, one vLLM service.
    fn deployment_requirements() -> Requirements {
        Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "2"), ("min_vram_gb", "80")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &BTreeMap::new(),
        )
        .expect("well-formed fixture")
        .with_serving(Some(serving()))
    }

    fn deployment_provider() -> BTreeMap<String, String> {
        [
            ("deepinfra-deploy.settings.min_instances", "0"),
            ("deepinfra-deploy.settings.max_instances", "1"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// **The profile's service becomes the service's own request.** The
    /// model is `hf.repo`, dtype and extra args are the engine's
    /// arguments, the GPU answer and count are `gpu` / `num_gpus`, the
    /// slot's `settings.*` land nested and typed, and the lease is
    /// `model_name`.
    #[test]
    fn the_deployment_request_is_built_from_the_service_and_the_answers() {
        let expires_at = at("2026-09-02T06:30:00Z");
        let acquisition = DeepInfraDeployAdapter
            .acquisition(
                &deployment_requirements(),
                &deployment_provider(),
                Some(expires_at),
            )
            .expect("a service and a GPU were declared");
        let body: serde_json::Value = serde_json::from_str(
            acquisition
                .body
                .as_deref()
                .expect("this target takes a body"),
        )
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "gpu": "A100-80GB",
                "num_gpus": 2,
                "extra_args": ["--dtype", "bfloat16", "--max-model-len", "32768"],
                "hf": { "repo": "Qwen/Qwen3-8B" },
                "settings": { "min_instances": 0, "max_instances": 1 },
                "model_name": expiry_stamp(expires_at),
            })
        );
        assert_eq!(acquisition.created_id_key, "deploy_id");
        assert_eq!(
            acquisition.create.last().map(String::as_str),
            Some("--json")
        );
        assert!(
            acquisition
                .create
                .contains(&format!("{DEEPINFRA_DEPLOY}/llm")),
            "{:?}",
            acquisition.create
        );
        assert!(acquisition.discover.is_none());
    }

    /// **The repository token travels by name.** Naming the variable
    /// puts a placeholder in the body and the import in the argv; the
    /// value is in neither.
    #[test]
    fn a_repository_token_is_a_placeholder_in_the_body_and_a_name_in_the_argv() {
        let mut provider = deployment_provider();
        provider.insert(
            "deepinfra-deploy.hf.token_env".to_string(),
            "HF_TOKEN".to_string(),
        );
        provider.insert(
            "deepinfra-deploy.hf.revision".to_string(),
            "main".to_string(),
        );
        let acquisition = DeepInfraDeployAdapter
            .acquisition(&deployment_requirements(), &provider, None)
            .expect("a service and a GPU were declared");
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["hf"],
            serde_json::json!({ "repo": "Qwen/Qwen3-8B", "revision": "main", "token": "{{HF_TOKEN:json}}" })
        );
        assert!(
            body.get("hf.token_env").is_none(),
            "consumed, not forwarded: {body}"
        );
        assert!(
            acquisition
                .create
                .windows(2)
                .any(|it| it == ["--variable", "%HF_TOKEN"]),
            "{:?}",
            acquisition.create
        );
        assert_eq!(
            acquisition.create.last().map(String::as_str),
            Some("--expand-json")
        );
        assert!(
            !acquisition.create.iter().any(|it| it.contains("hf_")),
            "no argument carries a token value: {:?}",
            acquisition.create
        );
        assert_eq!(
            body.get("model_name"),
            None,
            "no lease, no name: the service refuses it"
        );
    }

    /// **Refused by name, not dropped.** Each thing the profile said
    /// that this target cannot do stops the request and says which.
    #[test]
    fn a_deployment_refuses_what_it_cannot_run_by_name() {
        let refusal = |required: Requirements| {
            DeepInfraDeployAdapter
                .acquisition(&required, &deployment_provider(), None)
                .expect_err("something the target cannot do")
                .to_string()
        };

        let no_service = deployment_requirements().with_serving(None);
        assert!(refusal(no_service).contains("service.start"));

        let mut other_engine = serving();
        other_engine.engine = "ollama".to_string();
        let rendered = refusal(deployment_requirements().with_serving(Some(other_engine)));
        assert!(
            rendered.contains("vLLM") && rendered.contains("ollama"),
            "{rendered}"
        );

        let mut with_others = serving();
        with_others.others = vec!["system.apt".to_string(), "sh.exec".to_string()];
        let rendered = refusal(deployment_requirements().with_serving(Some(with_others)));
        assert!(rendered.contains("system.apt, sh.exec"), "{rendered}");

        let mut no_model = serving();
        no_model.model = None;
        assert!(refusal(deployment_requirements().with_serving(Some(no_model))).contains("model"));

        let mut disagreeing = serving();
        disagreeing.tensor_parallel_size = Some(4);
        let rendered = refusal(deployment_requirements().with_serving(Some(disagreeing)));
        assert!(
            rendered.contains("tensor_parallel_size 4") && rendered.contains("2 devices"),
            "{rendered}"
        );

        let with_disk = Requirements::from_slots(
            &BTreeMap::new(),
            &[("count", "2")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            &[("ephemeral_gb", "60")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap()
        .with_serving(Some(serving()));
        assert!(refusal(with_disk).contains("no disk"));

        let capability = DeepInfraDeployAdapter.capability();
        assert!(capability.exposures.is_empty());
        assert!(
            lm_provision::machine::admit(&required(&[("8000", "raw_tcp")]), &capability).is_err(),
            "a port declaration is refused at admission"
        );
    }

    /// The count is bounded by the API, the floor selects the cheapest
    /// configuration, and the way out names the slot key.
    #[test]
    fn a_deployment_selects_one_configuration_within_the_apis_bounds() {
        assert_eq!(
            DeepInfraDeployAdapter.gpu_answer(&GpuRequirement {
                count: 1,
                min_vram_gb: Some(100),
            }),
            Answer::Met {
                using: vec!["H200-141GB".to_string()]
            }
        );
        assert!(DeepInfraDeployAdapter
            .gpu_answer(&GpuRequirement {
                count: 9,
                min_vram_gb: None
            })
            .blocks());
        match DeepInfraDeployAdapter.gpu_answer(&GpuRequirement {
            count: 1,
            min_vram_gb: Some(300),
        }) {
            Answer::Unmet { reason } => {
                assert!(reason.contains("provider.deepinfra-deploy.gpu"), "{reason}")
            }
            other => panic!("nothing catalogued carries 300 GB: {other:?}"),
        }
        let mut provider = deployment_provider();
        provider.insert(
            "deepinfra-deploy.gpu".to_string(),
            "RTXPRO6000-96GB".to_string(),
        );
        let acquisition = DeepInfraDeployAdapter
            .acquisition(&deployment_requirements(), &provider, None)
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(acquisition.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["gpu"], "RTXPRO6000-96GB",
            "the profile gets the last word"
        );
    }

    /// **The endpoint is projected only once the service calls the
    /// deployment up, and it names the deployment by id** — so the
    /// lease in `model_name` never reaches a request.
    #[test]
    fn the_deployment_projects_an_endpoint_and_no_ssh() {
        let deploying = serde_json::json!({
            "deploy_id": "dep-1", "model_name": "me/lmp-exp-20260902T063000Z",
            "status": "deploying", "fail_reason": null,
            "config": { "gpu": "H100-80GB", "num_gpus": 2 }
        });
        let connection = DeepInfraDeployAdapter.connection(&deploying);
        assert!(connection.ssh.is_none() && connection.endpoint.is_none());
        assert!(
            connection.read.contains(&"status: deploying".to_string()),
            "{:?}",
            connection.read
        );
        assert!(DeepInfraDeployAdapter.still_materializing(&deploying));

        let mut running = deploying.clone();
        running["status"] = serde_json::json!("running");
        let connection = DeepInfraDeployAdapter.connection(&running);
        let endpoint = connection.endpoint.as_ref().expect("running");
        assert_eq!(endpoint.base_url, "https://api.deepinfra.com/v1/openai");
        assert_eq!(endpoint.model, "deploy_id:dep-1");
        assert_eq!(endpoint.api_key_env, "DEEPINFRA_API_KEY");
        assert!(connection.ssh.is_none(), "there is no host");
        assert!(!DeepInfraDeployAdapter.still_materializing(&running));
        let artifact = serde_json::to_value(&connection).unwrap();
        assert_eq!(
            artifact,
            serde_json::json!({ "endpoint": {
                "base_url": "https://api.deepinfra.com/v1/openai",
                "model": "deploy_id:dep-1",
                "api_key_env": "DEEPINFRA_API_KEY",
            }}),
            "what a caller reads: the endpoint, and nothing that is not there"
        );

        let mut failed = deploying.clone();
        failed["status"] = serde_json::json!("failed");
        failed["fail_reason"] = serde_json::json!("out of quota");
        let connection = DeepInfraDeployAdapter.connection(&failed);
        assert!(connection.endpoint.is_none());
        assert!(!DeepInfraDeployAdapter.still_materializing(&failed));
        assert!(
            connection
                .read
                .contains(&"fail_reason: present".to_string()),
            "{:?}",
            connection.read
        );

        let state = DeepInfraDeployAdapter.read_state(&running);
        assert_eq!(state.gpu_count, Some(2));
        assert_eq!(state.gpu_vram_mib, Some(gb_to_mib(80)));
        assert!(!state.ports_observed);
        let findings = lm_provision::machine::observe(&deployment_requirements(), &state);
        assert_eq!(
            lm_provision::machine::verdict(&findings),
            lm_provision::machine::Outcome::Satisfied,
            "{findings:#?}"
        );
        let uncatalogued = DeepInfraDeployAdapter.read_state(&serde_json::json!({
            "config": { "gpu": "RTXPRO6000-96GB", "num_gpus": 1 }
        }));
        assert_eq!(
            uncatalogued.gpu_vram_mib,
            Some(gb_to_mib(96)),
            "the memory is read off the configuration's own spelling"
        );
        assert_eq!(deepinfra_gpu_vram_gb("other"), None);
    }

    /// **The stamp is read past the account's namespace.** The listing
    /// says `<username>/<model_name>`; the lease is what the create
    /// call wrote, which is the part after the slash.
    #[test]
    fn the_deployment_listing_reads_the_stamp_past_the_namespace() {
        let fleet = DeepInfraDeployAdapter
            .fleet()
            .expect("this target can be asked");
        assert!(fleet.stamp_namespaced);
        let listed = serde_json::json!([
            { "deploy_id": "dep-a", "model_name": "me/lmp-exp-20260902T063000Z", "status": "running" },
            { "deploy_id": "dep-b", "model_name": "me/scratch", "status": "stopped" },
            { "deploy_id": "dep-c", "model_name": "lmp-exp-20260902T063000Z", "status": "running" },
        ]);
        let listed = machines(&listed, &fleet).expect("a bare array is the rows");
        assert_eq!(
            listed
                .iter()
                .map(|it| (it.id.as_str(), it.name.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("dep-a", Some("lmp-exp-20260902T063000Z")),
                ("dep-b", Some("scratch")),
                ("dep-c", Some("lmp-exp-20260902T063000Z")),
            ]
        );
        assert!(expiry_of(listed[0].name.as_deref().unwrap()).is_some());

        // The pod service's names are read whole: a slash in one of
        // them is the operator's, not a namespace.
        let pods = RunPodAdapter.fleet().unwrap();
        assert!(!pods.stamp_namespaced);
        let listed = serde_json::json!({ "pods": [{ "id": "p", "name": "team/box" }] });
        assert_eq!(
            machines(&listed, &pods).unwrap()[0].name.as_deref(),
            Some("team/box")
        );

        assert_eq!(fleet.id, "deploy_id");
        assert!(
            fleet.list.contains(&format!("{DEEPINFRA_DEPLOY}/list/")),
            "{:?}",
            fleet.list
        );
        assert!(fleet.release.windows(2).any(|it| it == ["-X", "DELETE"]));
        assert_eq!(DeepInfraDeployAdapter.credentials(), &["DEEPINFRA_API_KEY"]);
        assert_eq!(
            DeepInfraDeployAdapter.image_key(),
            Some("deepinfra-deploy.container_image")
        );
        assert!(adapter_named("deepinfra-deploy").is_ok());
    }
}
