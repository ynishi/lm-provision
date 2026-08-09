//! The Assert model: what an Assert answers, how answers compose, and
//! how an Assert is evaluated (design.md §3, plan 段 A).
//!
//! An Assert is an *expression*, not a closed list of cases. Evaluating
//! one reads the host, so it can fail; "did not evaluate" and "could not
//! evaluate" are different things and are not folded together. Hence the
//! four-valued [`AssertOutcome`].
//!
//! **The model does not decide what any particular Assert means.**
//! "What does a finished `ModelFile` / `Service` / `Checkout` look like"
//! is a separate design question, answered per entity. The model half
//! of this module is the type, the value range, the composition, the
//! evaluator and the three basic predicates; the entity half —
//! [`Done`] and its implementors [`ModelFile`] and [`Checkout`] — sits
//! at the bottom of the file and is what the lifecycle layer actually
//! consumes.
//!
//! ## Scope boundary
//!
//! The model was `pub(crate)` while nothing consumed it. It is public
//! now because entities have been wired end to end: `models` derives a
//! `done` from [`ModelFile`] and `comfyui.install` / `custom_nodes`
//! from [`Checkout`], the lifecycle layer evaluates each before running
//! the step it guards, and [`crate::canonical::encode_assert`] gives
//! them deterministic bytes.
//!
//! **Nothing here is author-visible yet.** A profile cannot write a
//! `done:` of its own — every `done` is derived from the phase kind —
//! so no `ProfileNode` carries an `Assert` and no profile's hash moves.
//! The author-facing form is settled once three entities exist, so that
//! it is not shaped by this one (design §5).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::exec::ExecMode;

// ---------------------------------------------------------------------
// (1) The value range
// ---------------------------------------------------------------------

/// What an Assert answers.
///
/// `CheckFailed` is **not** an `Err`: a failure on the observed side is
/// one of the answers an Assert can give, and the caller has to handle
/// it. A skip decision treats it like `Unsatisfied`, but a report must
/// keep them apart — that is the whole reason the variant exists.
///
/// The boundary against a `Result::Err` (`crate::exec::ExecError`) is
/// "observed side or host-process side", and the test is **whether it
/// could be detected**: EACCES, corrupt content, a subprocess killed by
/// the OOM killer, a non-zero exit, a fired timeout — all detected, all
/// answers. Allocation failure, runtime collapse and internal
/// inconsistency cannot be answered at all and stay `Err`. Routing an
/// observed-side failure into `Err` is equally forbidden: doing that
/// erases the distinction between `NotChecked` and `CheckFailed`.
///
/// `NotChecked` is the *policy* answer ("this mode does not evaluate
/// this predicate"). It is not called `Skipped` because a step's "skip"
/// points the other way (skip = the condition already holds).
///
/// **The range is four. A fifth variant is not added.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertOutcome {
    /// The condition holds.
    Satisfied,
    /// The condition does not hold.
    Unsatisfied,
    /// Deliberately not evaluated (e.g. a whole-file read under
    /// [`ExecMode::DryRun`]).
    NotChecked,
    /// Evaluation was attempted and failed on the observed side.
    CheckFailed(CheckError),
}

/// Why an evaluation failed on the observed side.
///
/// A **value type**: a category plus a detail string. Wrapping a
/// [`std::io::Error`] would make answers incomparable, and "the same
/// host state gives the same answer" could then not be written as a
/// test. A single free-form string is equally rejected — that is the
/// granularity this model exists to get away from.
///
/// **The detail string must be a function of the observation alone** —
/// no clock, no attempt counter, no random value, no pointer. Equality
/// includes the detail, so anything variable breaks reproducibility;
/// and it breaks it *in production only*, since a fixed-response
/// observer in tests stays green.
///
/// Deliberately not named `Reason`: `crate::exec::report::StepReport`
/// already has a free-form `reason` field in this same module tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckError {
    category: CheckErrorCategory,
    detail: String,
}

impl CheckError {
    /// Build a failure answer from a category and its detail.
    pub fn new(category: CheckErrorCategory, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
        }
    }

    /// The coarse classification.
    pub fn category(&self) -> CheckErrorCategory {
        self.category
    }

    /// The observation-derived detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// The coarse classification carried by a [`CheckError`].
///
/// **The set is still one variant, now on evidence rather than on a
/// deferral.** The two file observations
/// ([`crate::exec::observe::LocalObserve`]) split their outcomes three
/// ways — present, absent, and *anything else* — and only the third
/// reaches a `CheckError`. Whether the file was unreadable, on a
/// broken mount, or blocked by permissions changes the detail string,
/// not what the caller does about it: the skip decision treats them
/// alike and the report prints the detail. A second category earns its
/// place when a caller would branch on it.
//
// The note this replaces expected command exit codes to be what split
// the enum, on the grounds that a command observed across a transport
// could fail to come back at all — a different answer from "the
// observed side said no". [`Assert::GitTreeAt`] added command exit
// codes and did not split it, for two reasons. The observation is local
// (the provisioner runs on the pod it asks about), so "did not come
// back" is not a case that arises here; and, more to the point, the
// rule above still holds — the skip decision treats "git is not
// installed" and "git exited 128" exactly alike, and the report prints
// the detail either way. There is still no caller that would branch.
// Mount state and HTTP status remain open on the same test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckErrorCategory {
    /// The observation could not be carried out at all (the observed
    /// side refused or broke).
    Unobservable,
}

/// The image of `Not` on [`AssertOutcome`].
///
/// | input | image |
/// |---|---|
/// | `Satisfied` | `Unsatisfied` |
/// | `Unsatisfied` | `Satisfied` |
/// | `NotChecked` | `NotChecked` |
/// | `CheckFailed(e)` | `CheckFailed(e)` |
///
/// An involution. `Assert` has no `Not` variant in this stage — only
/// the mapping on the value range is decided here, because leaving the
/// image open would force the range or the fold table back open later.
#[allow(dead_code)] // No `Not` variant exists yet; the image is fixed, not used.
pub(crate) fn not(outcome: AssertOutcome) -> AssertOutcome {
    match outcome {
        AssertOutcome::Satisfied => AssertOutcome::Unsatisfied,
        AssertOutcome::Unsatisfied => AssertOutcome::Satisfied,
        AssertOutcome::NotChecked => AssertOutcome::NotChecked,
        AssertOutcome::CheckFailed(e) => AssertOutcome::CheckFailed(e),
    }
}

// ---------------------------------------------------------------------
// (2) The expression — and the non-empty list it composes over
// ---------------------------------------------------------------------

/// A list that cannot be empty, isolated so that every future change to
/// its surface shows up in one module's diff.
///
/// The fields are private to this module, so the only way to build one
/// is [`NonEmpty::new`], which requires a head.
mod nonempty {
    /// A head plus a (possibly empty) tail.
    ///
    /// The head is boxed. That is a representation detail, not part of
    /// the surface: it is what lets `Assert` hold a `NonEmpty<Assert>`
    /// and `AssertNode` a `NonEmpty<AssertNode>` directly, since an
    /// inline head would make both types infinitely sized. Keeping the
    /// indirection here rather than at the two use sites keeps their
    /// declarations reading as the plain recursive shapes they are.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NonEmpty<T> {
        head: Box<T>,
        tail: Vec<T>,
    }

    impl<T> NonEmpty<T> {
        /// The only constructor. A head is mandatory, so an empty value
        /// cannot be expressed.
        pub fn new(head: T, tail: Vec<T>) -> Self {
            Self {
                head: Box::new(head),
                tail,
            }
        }

        /// The first element, unconditionally.
        ///
        /// This exists so that no caller has to write
        /// `iter().next().expect(..)` — a panic path on the inside of a
        /// type whose whole point is that the empty case is gone.
        pub fn head(&self) -> &T {
            &self.head
        }

        /// Head first, then the tail in order.
        pub fn iter(&self) -> impl Iterator<Item = &T> {
            std::iter::once(self.head()).chain(self.tail.iter())
        }

        /// A count-preserving transform.
        ///
        /// Without it the evaluator could not turn a `NonEmpty<Assert>`
        /// into a `NonEmpty<AssertOutcome>` and would need a panic path
        /// to rebuild one.
        pub fn map<U>(&self, f: impl Fn(&T) -> U) -> NonEmpty<U> {
            NonEmpty {
                head: Box::new(f(self.head())),
                tail: self.tail.iter().map(f).collect(),
            }
        }
    }

    // Nothing that drops elements is provided — no `retain`, `filter`,
    // `pop`, `remove` or `truncate`. Blocking only the constructor is
    // not enough: with an element-dropping operation, an "all children
    // are tautologies" conjunction can be reduced back to an empty one.
    //
    // `Debug` / `PartialEq` / `Eq` are derived above; they observe
    // elements rather than remove them, so they do not widen the
    // surface this comment guards.
}

pub use nonempty::NonEmpty;

/// A condition about the host, as an expression.
///
/// `All []` is excluded by the type: an empty conjunction folds to the
/// unit element `Satisfied`, which would slip a tautological subterm
/// into the fold. What the type removes is the *expression* "empty
/// conjunction", not "unconditional skip" — a tautological basic
/// predicate still expresses that — so this is not a safety claim.
///
/// `Not` / `ForEach` / `Any` are not here. They arrive when a kind
/// needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assert {
    /// There is a file at `path`.
    ///
    /// **What that means is deliberately not settled here** — whether a
    /// symlink is followed, how a directory counts, and so on are
    /// answered by the [`Observe`] implementation, i.e. by the stage
    /// that writes the observation.
    FileExists {
        /// The observed path.
        path: PathBuf,
    },

    /// The file at `path` has content digest `expected_sha256`
    /// (lowercase hex, see [`crate::digest::hex_sha256`]).
    ///
    /// Same boundary as [`Assert::FileExists`]: how the content is read
    /// is the observation's business, not the model's.
    FileDigest {
        /// The observed path.
        path: PathBuf,
        /// The digest the content must have.
        expected_sha256: String,
    },

    /// The git repository at `dir` holds `git_ref`'s content.
    ///
    /// Observed by running [`git_tree_at_argv`] and reading its exit
    /// status: `0` is `Satisfied`, `1` is `Unsatisfied`, anything else
    /// is a [`CheckError`] (git's own convention — `--quiet` implies
    /// `--exit-code`, and a broken repository or an unknown ref exits
    /// `128`).
    ///
    /// ## Why this runs in a dry run too
    ///
    /// The two file predicates split on cost: existence is cheap and is
    /// evaluated in both modes, a digest reads the whole file and is
    /// not. A command predicate raises a second question, because the
    /// precedents §3.7 cites both answer it the other way — Chef's
    /// why-run suppresses shell-command guards, and Ansible's `command`
    /// module evaluates `creates` / `removes` in check mode but does not
    /// run the command. Neither is being cautious about *cost*; they are
    /// being cautious about **side effects**, which a command generally
    /// has and a read never does.
    ///
    /// This predicate is evaluated in both modes anyway, and the reason
    /// is that it is not a general command:
    ///
    /// - **The command is fixed by the predicate.** A profile cannot
    ///   write an `Assert` at all yet — every `done` is derived from a
    ///   phase kind — and even when it can, this variant carries a
    ///   repository and a ref, not an argv. The only command it can ever
    ///   fire is [`git_tree_at_argv`]'s, which is a `git diff` under
    ///   `--no-optional-locks`: a read, and a read that is denied even
    ///   the index-refresh lock git would otherwise be free to take.
    /// - **It is cheap** — the axis §3.7 does use. Resolving two refs
    ///   and comparing two trees is a small local read, on the same
    ///   order as the `stat` behind [`Assert::FileExists`].
    ///
    /// So the answer a dry run gives is the answer a real run gives, and
    /// `plan` can say "this will clone" instead of "undecided". Had this
    /// returned [`AssertOutcome::NotChecked`] instead, a `Checkout`
    /// would have been *less* answerable in a dry run than a
    /// [`ModelFile`] — which can at least decide an absent destination —
    /// and the plan output would have gone backwards as entities were
    /// added.
    ///
    /// **The obligation this creates** lands on the stage that lets an
    /// author write a `done` of their own: an authored condition that
    /// could name an arbitrary command would break the first bullet, and
    /// that stage has to decide the question again rather than inherit
    /// this answer.
    ///
    /// ## What "holds `git_ref`" means
    ///
    /// The comparison is `<git_ref>` against `HEAD`, both as commits, so
    /// what is compared is **the content two commits name**, not the
    /// commit identity and not the working tree:
    ///
    /// - a **dirty** work tree is still finished. It has to be: `git
    ///   clone` / `git checkout` will not clean local modifications, so a
    ///   condition that counted them would name something the step
    ///   cannot achieve, and the step would run — and fail — on every
    ///   apply. A completion condition an action cannot reach is not a
    ///   completion condition.
    /// - a **branch**, a **tag** and a **sha** are judged alike, because
    ///   the ref is resolved in the same local repository the step
    ///   produced. Neither the step nor this predicate fetches, so a
    ///   branch that has moved upstream is not a difference either of
    ///   them can see, and reporting one would be an answer about a
    ///   remote that nothing in this phase consults.
    GitTreeAt {
        /// The work tree observed.
        dir: PathBuf,
        /// The ref — branch, tag or commit — its content must match.
        git_ref: String,
    },

    /// Conjunction. Child order is the order the author wrote.
    All(NonEmpty<Assert>),
}

/// The command [`Assert::GitTreeAt`] fires.
///
/// **A template, not an argument.** Everything variable in it is a
/// repository path and a ref; the verb, the flags and their order are
/// fixed here, which is what makes "this predicate has no side effects"
/// a property of the code rather than a promise about the caller.
///
/// - `--no-optional-locks` is git's own answer to "a tool is inspecting
///   this repository and must not write to it": it suppresses the
///   optional index refresh, which is the one write a plain `git diff`
///   might otherwise perform.
/// - `--quiet` implies `--exit-code`, so the answer arrives as the exit
///   status and no output has to be parsed.
/// - Two revisions are compared, rather than one revision against the
///   work tree, so local modifications do not enter the answer (see
///   [`Assert::GitTreeAt`]).
/// - The trailing `--` keeps a ref that looks like a path from being
///   read as a pathspec.
fn git_tree_at_argv(dir: &Path, git_ref: &str) -> Vec<String> {
    vec![
        "git".to_string(),
        "--no-optional-locks".to_string(),
        "-C".to_string(),
        dir.to_string_lossy().into_owned(),
        "diff".to_string(),
        "--quiet".to_string(),
        git_ref.to_string(),
        "HEAD".to_string(),
        "--".to_string(),
    ]
}

// ---------------------------------------------------------------------
// (3) The fold
// ---------------------------------------------------------------------

/// Fold the children of an [`Assert::All`] into one answer.
///
/// | # | children | result |
/// |---|---|---|
/// | 1 | any `Unsatisfied` | `Unsatisfied` |
/// | 2 | all `Satisfied` | `Satisfied` |
/// | 3 | no `Unsatisfied`, some `CheckFailed` | `CheckFailed` |
/// | 4 | otherwise, some `NotChecked` | `NotChecked` |
///
/// Once `Unsatisfied` is established a `CheckFailed` may be ignored;
/// conversely `Satisfied` requires every child to be `Satisfied`.
///
/// **Row 3 keeps the first `CheckError` in child order.** Without that
/// rule two different folds both satisfy the four rows while disagreeing
/// on the answer, and "the same host state gives the same answer" stops
/// being true. The rule presumes child order is preserved — neither the
/// evaluator nor this fold reorders.
///
/// Kept a pure function on outcomes, separate from evaluation, so rows
/// 1 and 3 can be tested from inside the crate rather than by
/// manufacturing an EACCES on the host (`chmod 000` is a no-op for root
/// and is unreliable in CI containers).
pub(crate) fn fold_all(children: &NonEmpty<AssertOutcome>) -> AssertOutcome {
    let mut saw_unsatisfied = false;
    let mut saw_not_checked = false;
    let mut first_failure: Option<&CheckError> = None;

    for child in children.iter() {
        match child {
            AssertOutcome::Satisfied => {}
            AssertOutcome::Unsatisfied => saw_unsatisfied = true,
            AssertOutcome::NotChecked => saw_not_checked = true,
            AssertOutcome::CheckFailed(error) => {
                if first_failure.is_none() {
                    first_failure = Some(error);
                }
            }
        }
    }

    if saw_unsatisfied {
        return AssertOutcome::Unsatisfied; // row 1
    }
    if let Some(error) = first_failure {
        return AssertOutcome::CheckFailed(error.clone()); // row 3 + tie-break
    }
    if saw_not_checked {
        return AssertOutcome::NotChecked; // row 4
    }
    AssertOutcome::Satisfied // row 2
}

// ---------------------------------------------------------------------
// (4) The result tree
// ---------------------------------------------------------------------

/// The id of **one execution of one Assert**.
///
/// An Assert is an expression, so every subterm is itself an Assert and
/// gets its own id: an `All` is evaluated and produces an answer too, so
/// there is something to record about it (what it folded, into what).
///
/// The substance of an execution — when, what was looked at, what came
/// back — is not carried in the tree. It lives on the step's execution
/// record and is joined by this id. The tree is shape and answers; the
/// record is the execution itself. Without the id the tree cannot be
/// matched against anything external, and "which one, when, how did it
/// fail" is unrecoverable.
///
/// Ids are per execution, not per step: nothing short-circuits, so N
/// leaves means N observations and N separate records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssertExecutionId(u64);

/// Process-wide source of [`AssertExecutionId`]s.
//
// 段 B で決める: where numbering is issued from, and how it is aligned
// with the persistence of the execution record. The model only fixes
// that every node has an id.
static NEXT_ASSERT_EXECUTION_ID: AtomicU64 = AtomicU64::new(1);

impl AssertExecutionId {
    fn next() -> Self {
        Self(NEXT_ASSERT_EXECUTION_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// What an evaluation returns: the answer of every subterm, in place.
///
/// A single [`AssertOutcome`] is not enough. The fold gives
/// `Unsatisfied` absolute priority, so a `CheckFailed` sitting in the
/// same conjunction disappears from the top value — and a report that
/// has to show what broke then cannot be built at all. The outcome is
/// taken as a projection of this tree instead.
///
/// `children` is a [`NonEmpty`], not a `Vec`: with a `Vec`, "a leaf" and
/// "a conjunction with no children" would be the very same value, which
/// rebuilds on the result side exactly the empty conjunction the
/// expression side removed by typing.
#[derive(Debug, PartialEq, Eq)]
pub enum AssertNode {
    /// A basic predicate's execution.
    Leaf {
        /// This execution's id.
        id: AssertExecutionId,
        /// What it answered.
        outcome: AssertOutcome,
    },
    /// A conjunction's execution.
    All {
        /// This execution's id.
        id: AssertExecutionId,
        /// The folded answer.
        outcome: AssertOutcome,
        /// The children's executions, in the order the author wrote.
        children: NonEmpty<AssertNode>,
    },
}

impl AssertNode {
    /// The projection down to a single answer.
    pub fn outcome(&self) -> &AssertOutcome {
        match self {
            AssertNode::Leaf { outcome, .. } | AssertNode::All { outcome, .. } => outcome,
        }
    }

    /// True iff this execution answered [`AssertOutcome::Satisfied`] —
    /// the one outcome that lets a caller skip the work.
    ///
    /// Named as a question rather than exposed as a comparison so that
    /// the safe direction is the easy one to write: everything that is
    /// not `Satisfied` (including `NotChecked` and `CheckFailed`) means
    /// "do the work", and a caller writing `!= Unsatisfied` by hand
    /// would get that backwards.
    pub fn is_satisfied(&self) -> bool {
        matches!(self.outcome(), AssertOutcome::Satisfied)
    }
}

// ---------------------------------------------------------------------
// (5) The observation channel
// ---------------------------------------------------------------------

/// What an observation of a file's content digest found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestReading {
    /// There is no file to read.
    Absent,
    /// There is one, with this lowercase-hex SHA-256.
    Present(String),
}

/// The route a predicate takes to look at the host.
///
/// Injected so a test can supply any answer, success or failure,
/// without arranging the real thing on the host.
///
/// **A `trait`, and swapped by generics.** A parameter (the shape
/// `crate::exec::lifecycle::probe_liveness` uses for its `proc_root`)
/// does not scale here: later stages add command exit codes, command
/// output and mount state, so per-observation parameters would grow one
/// argument per predicate and the evaluator would end up knowing all of
/// them. With one trait the evaluator only knows `O: Observe`. Dispatch
/// stays static, so no `async_trait` and no `dyn` is involved.
///
/// The `Err` side is [`CheckError`] — the *answer* type — not
/// `crate::exec::ExecError`. A failed observation is mapped straight to
/// [`AssertOutcome::CheckFailed`]; nothing here escapes into the
/// host-process error channel.
///
/// **What these observations mean is not settled here**: whether a
/// symlink is followed, how a directory is treated, whether content is
/// read in one go or in chunks. Those belong to the design of the
/// individual Asserts. This stage only fixes that the answers come back
/// in a form the model can receive.
///
/// ## Why the futures are `Send`
///
/// The methods are written as RPITIT with an explicit `+ Send` rather
/// than as `async fn`, which is the shape an `async fn` in a trait
/// cannot promise.
///
/// **This bound was deliberately left out when the model was written**,
/// and the reason it recorded was that nothing required it: dispatch is
/// static, and the future was awaited on the thread that created it —
/// `block_in_place` + `Handle::block_on` at the synchronous `Op::apply`
/// seam. Adding it would have constrained every implementor for a
/// capability no caller had asked for. The case that was expected to
/// ask for it was moving an observation onto `tokio::spawn` to abandon
/// one that never returns, and the design routes that to a driver on
/// the far side of a transport instead (§3.2d) — so the bound was
/// deferred rather than overlooked.
///
/// **A different caller asked.** Evaluating an Assert now happens inside
/// a host effect resolver, because a lifecycle step is a dsl-kit `Call`
/// node ([`crate::exec::steps`]) rather than a loop inside one
/// `Op::apply`. dsl-kit's `AsyncEffectResolver::resolve` requires the
/// future it returns to be `Send`
/// (`dsl-kit-core-0.11.0/src/drive.rs:75-81`), and a future that awaits
/// [`eval`] is only `Send` if these observations are. Without the bound
/// an Assert simply cannot be evaluated on the `Call` route at all — in
/// real mode as much as in a dry run.
///
/// So the bound is here on evidence, not on speculation: it is the
/// price of the Assert model being usable from where the effects
/// actually run. Nothing else moved with it — the value range, the fold
/// table, the result tree, the leaf contract and the entity trait are
/// unchanged.
pub trait Observe {
    /// Whether a file is at `path`.
    fn file_exists(&self, path: &Path) -> impl Future<Output = Result<bool, CheckError>> + Send;

    /// The content digest of the file at `path`, lowercase hex (see
    /// [`crate::digest::hex_sha256`] for the rendering contract).
    fn file_digest(
        &self,
        path: &Path,
    ) -> impl Future<Output = Result<DigestReading, CheckError>> + Send;

    /// Run `argv` and report the status it exited with.
    ///
    /// `Ok(code)` means the command ran to completion; the code is the
    /// process's, and what it *means* belongs to the predicate that
    /// composed the argv (git's `1` is not curl's). `Err` is reserved
    /// for "it could not be run at all" — a missing binary is detected,
    /// so it is an answer, not a host-process error.
    ///
    /// **The channel is general; the expressions on it are not.** This
    /// method takes any argv because an observation channel that took a
    /// closed set of commands would have to be widened for every
    /// predicate. What may reach it is decided one level up, by
    /// [`Assert`] having no variant that carries an author's argv — see
    /// [`Assert::GitTreeAt`] for why that distinction is what lets a
    /// command be observed during a dry run.
    fn command_status(
        &self,
        argv: &[String],
    ) -> impl Future<Output = Result<i32, CheckError>> + Send;
}

// ---------------------------------------------------------------------
// (6) The evaluator
// ---------------------------------------------------------------------

/// Evaluate `assert` against the host `obs` reaches, under `mode`.
///
/// **Async**, and not because timeouts would otherwise be impossible —
/// this crate already does timeouts twice over while staying
/// synchronous. It is async because later stages observe a remote pod,
/// where observations that never return are a certainty. A `stat()` on
/// a hard-mounted NFS path can enter D state, where not even SIGKILL
/// helps; the only move left is for the caller to give up on the wait
/// and answer `CheckFailed`. Async is the shape that lets the caller
/// write that wrapper.
///
/// For the same reason observations belong on the far side of a driver
/// (a separate process, or remote) rather than on an in-process
/// `spawn_blocking`, whose tasks ignore `abort` and hold a pool slot
/// indefinitely.
///
/// **Nothing short-circuits: every child is evaluated.** Stopping at
/// fold row 1 would leave unevaluated branches needing a value, and
/// `NotChecked` would then mean both "policy said no" and "the answer
/// was already settled".
///
/// **That was left to be reconsidered once a predicate ran a command,
/// and it has been.** [`Assert::GitTreeAt`] does spawn a process, so
/// full evaluation is no longer free — a conjunction whose first child
/// already answered `Unsatisfied` still pays for a `git` invocation. It
/// stays anyway, for two reasons. The command is a read (the variant's
/// doc argues that at length), so short-circuiting would still be
/// *observationally* indistinguishable and the difference remains cost
/// alone. And the cost is one local process per leaf, against a step
/// that clones a repository — while what short-circuiting would buy is
/// paid for in the report, where the skipped branch is exactly the one
/// an operator needs to see. A predicate that changed the host would
/// reopen this properly; a predicate that merely takes longer to read
/// does not.
///
/// `mode` is [`crate::exec::ExecMode`], the same type the rest of the
/// execution layer branches on — a second mode type would split one
/// concept in two and force conversions at the step wiring. **The
/// composition carries no mode-specific rule**: each basic predicate
/// answers `NotChecked` for itself and [`fold_all`] folds as usual.
///
/// `O: Sync` (with the `Send` futures [`Observe`] requires) is what
/// makes the returned future `Send`, which is what lets an evaluation
/// happen inside a host effect resolver — see [`Observe`]'s
/// §Why the futures are `Send`.
pub async fn eval<O: Observe + Sync>(assert: &Assert, mode: ExecMode, obs: &O) -> AssertNode {
    match assert {
        Assert::FileExists { path } => {
            // Existence is a cheap observation, so it is evaluated in
            // both modes.
            let outcome = match obs.file_exists(path).await {
                Ok(true) => AssertOutcome::Satisfied,
                Ok(false) => AssertOutcome::Unsatisfied,
                Err(error) => AssertOutcome::CheckFailed(error),
            };
            AssertNode::Leaf {
                id: AssertExecutionId::next(),
                outcome,
            }
        }

        Assert::FileDigest {
            path,
            expected_sha256,
        } => {
            // A digest reads the whole content, so a dry run does not
            // take it. Answering `NotChecked` rather than guessing is
            // what the leaf contract requires: `Satisfied` under
            // `DryRun` may only be returned when `Real` would certainly
            // say `Satisfied` too.
            let outcome = match mode {
                ExecMode::DryRun => AssertOutcome::NotChecked,
                ExecMode::Real => match obs.file_digest(path).await {
                    Ok(DigestReading::Absent) => AssertOutcome::Unsatisfied,
                    Ok(DigestReading::Present(found)) => {
                        if &found == expected_sha256 {
                            AssertOutcome::Satisfied
                        } else {
                            AssertOutcome::Unsatisfied
                        }
                    }
                    Err(error) => AssertOutcome::CheckFailed(error),
                },
            };
            AssertNode::Leaf {
                id: AssertExecutionId::next(),
                outcome,
            }
        }

        Assert::GitTreeAt { dir, git_ref } => {
            // Evaluated in both modes: the command is the predicate's
            // own, is read-only by construction, and costs about what a
            // `stat` does (see the variant's doc for the whole
            // argument). `mode` therefore does not appear here.
            let argv = git_tree_at_argv(dir, git_ref);
            let outcome = match obs.command_status(&argv).await {
                Ok(0) => AssertOutcome::Satisfied,
                Ok(1) => AssertOutcome::Unsatisfied,
                // Anything else is git failing to answer rather than
                // answering "no": no repository there, an unknown ref, a
                // signal (which `sh_exec` reports as `-1`). The skip
                // decision treats it like `Unsatisfied` — the work runs
                // — but the report has to be able to tell them apart,
                // which is the whole reason this variant exists.
                Ok(code) => AssertOutcome::CheckFailed(CheckError::new(
                    CheckErrorCategory::Unobservable,
                    format!("git exited {code}"),
                )),
                Err(error) => AssertOutcome::CheckFailed(error),
            };
            AssertNode::Leaf {
                id: AssertExecutionId::next(),
                outcome,
            }
        }

        Assert::All(children) => {
            // Head first, then the tail, so child order is the order
            // the author wrote (which is what the fold's tie-break
            // rests on).
            let head = eval_boxed(children.head(), mode, obs).await;
            let mut tail = Vec::new();
            for child in children.iter().skip(1) {
                tail.push(eval_boxed(child, mode, obs).await);
            }
            let children = NonEmpty::new(head, tail);
            let outcome = fold_all(&children.map(|node| node.outcome().clone()));
            AssertNode::All {
                id: AssertExecutionId::next(),
                outcome,
                children,
            }
        }
    }
}

/// Boxed indirection for the recursive call in [`eval`].
///
/// A directly recursive `async fn` has an infinitely sized future, so
/// the recursion has to go through a pointer. This boxes the *future*
/// only; `Observe` is still resolved statically through `O`, so no
/// `dyn` enters the observation path.
///
/// The box carries `+ Send`, which is the one place the whole
/// evaluation's `Send`-ness is actually decided: a `dyn Future` erases
/// auto traits, so an unannotated box would make [`eval`] non-`Send`
/// however `Send` its parts were.
fn eval_boxed<'a, O: Observe + Sync>(
    assert: &'a Assert,
    mode: ExecMode,
    obs: &'a O,
) -> Pin<Box<dyn Future<Output = AssertNode> + Send + 'a>> {
    Box::pin(eval(assert, mode, obs))
}

// ---------------------------------------------------------------------
// (7) Rendering — what a report and a dry-run trace print
// ---------------------------------------------------------------------

impl AssertOutcome {
    /// The one-word spelling used in traces and report notes.
    ///
    /// A `CheckFailed` carries its detail: the whole reason the variant
    /// exists is that a report must show what broke, and a bare
    /// `check-failed` would be the `(skipped due to not_if)` granularity
    /// this model was built to get away from (design §3.2b).
    pub fn label(&self) -> String {
        match self {
            AssertOutcome::Satisfied => "satisfied".to_string(),
            AssertOutcome::Unsatisfied => "unsatisfied".to_string(),
            AssertOutcome::NotChecked => "not-checked".to_string(),
            AssertOutcome::CheckFailed(error) => {
                format!("check-failed({:?}: {})", error.category(), error.detail())
            }
        }
    }
}

/// The condition itself, with no answers: `exists(/p) and sha256(/p)=…`.
///
/// Used where there is nothing to evaluate — the dry-run trace, which
/// states what *would* decide the skip.
pub fn describe(assert: &Assert) -> String {
    let mut out = String::new();
    write_assert(assert, None, &mut out);
    out
}

/// The condition annotated with what each subterm answered.
///
/// This is what a skipped step reports. Printing only the top answer
/// would hide exactly what the fold hides — a `CheckFailed` sitting
/// under an `Unsatisfied` sibling — which is why the evaluator returns
/// a tree in the first place (design §3.2b').
pub fn describe_execution(assert: &Assert, node: &AssertNode) -> String {
    let mut out = String::new();
    write_assert(assert, Some(node), &mut out);
    out
}

/// Render `assert`, annotating each subterm with the matching node's
/// answer when one is supplied.
///
/// The two trees have the same shape by construction ([`eval`] builds
/// the node from the expression), so the zip always lines up. A
/// mismatch would mean the caller paired an expression with a foreign
/// execution; rather than panic on that, the annotation is dropped for
/// the offending subterm and the expression still prints.
fn write_assert(assert: &Assert, node: Option<&AssertNode>, out: &mut String) {
    match assert {
        Assert::FileExists { path } => {
            out.push_str(&format!("exists({})", path.display()));
        }
        Assert::FileDigest {
            path,
            expected_sha256,
        } => {
            out.push_str(&format!("sha256({})={expected_sha256}", path.display()));
        }
        Assert::GitTreeAt { dir, git_ref } => {
            out.push_str(&format!("git_tree({})={git_ref}", dir.display()));
        }
        Assert::All(children) => {
            let child_nodes = match node {
                Some(AssertNode::All { children, .. }) => Some(children),
                _ => None,
            };
            out.push_str("all[");
            for (index, child) in children.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let child_node = child_nodes.and_then(|nodes| nodes.iter().nth(index));
                write_assert(child, child_node, out);
            }
            out.push(']');
        }
    }
    if let Some(node) = node {
        out.push('=');
        out.push_str(&node.outcome().label());
    }
}

// ---------------------------------------------------------------------
// (8) Entities — what a finished thing looks like
// ---------------------------------------------------------------------

/// A host-side thing that knows what its own completion looks like.
///
/// Implementors are built from a phase payload, and the lifecycle layer
/// asks for the `done` rather than assembling an `Assert` at each call
/// site — so "what does a finished X look like" is answered once per
/// kind of thing, not once per kind of phase (design §3.4: the payoff
/// is the conjunctions that recur across kinds).
///
/// **The signature held for the second entity.** [`Checkout`] was
/// predicted to fit — needing a new [`Assert`] variant, not a new
/// signature — and it does: `fn done(&self) -> Assert`, infallible,
/// with the repository and the ref as constructor input exactly as
/// `sha256` is for [`ModelFile`]. What did *not* hold was where the
/// condition was kept: it used to sit on one `Step` variant, and a
/// second entity is what turned that into
/// [`crate::exec::lifecycle::PlannedStep`].
///
/// **`Service`** (段 4: pid alive ∧ cmdline matches ∧ 2xx, shared by
/// `comfyui.restart` and `service.start`) is expected to fit too: the
/// launch argv it compares against is constructor input like the two
/// above, and the poll that waits for it is the step's execution
/// strategy rather than part of the condition (design §3.2c).
///
/// The signature is deliberately infallible (`-> Assert`, not
/// `-> Result<Assert, _>`). A payload too underspecified to say what
/// finished means — `service.start` on an unrecognised platform — has
/// no entity constructed for it at all; the absence lives at the
/// construction site, where it can be seen, rather than inside a
/// method that would have to invent an error for it.
pub trait Done {
    /// What has to hold for this thing to be finished.
    fn done(&self) -> Assert;
}

/// One file a `models` phase downloads.
///
/// Its identity is the destination path plus, when the profile declares
/// one, the content digest (design §3.6: a content-addressed file can
/// put the digest *in* its identity, so "present but different" is a
/// different thing rather than the same thing in a different state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelFile {
    dst: PathBuf,
    sha256: Option<String>,
}

impl ModelFile {
    /// A model file at `dst`, optionally identified by content.
    ///
    /// `sha256` is the profile's declared digest, lowercase hex; `None`
    /// is a profile that named no digest, not a digest that is unknown
    /// yet.
    pub fn new(dst: impl Into<PathBuf>, sha256: Option<String>) -> Self {
        Self {
            dst: dst.into(),
            sha256: sha256.map(|hex| hex.to_ascii_lowercase()),
        }
    }
}

impl Done for ModelFile {
    /// Present, and — when the profile declared a digest — holding that
    /// content.
    ///
    /// **Without a digest this is a single predicate, not a
    /// one-element conjunction.** `All` is for composing; wrapping a
    /// lone predicate in it would add a subterm that says nothing, and
    /// the model does not require every `done` to be a conjunction
    /// (`NonEmpty` means "not empty", not "at least two").
    ///
    /// With a digest, the existence conjunct is *not* redundant even
    /// though [`Assert::FileDigest`] already answers `Unsatisfied` for
    /// an absent file. It is what makes a dry run informative: the
    /// digest is not read under [`ExecMode::DryRun`], so on its own the
    /// answer would be `NotChecked` whatever the host looks like,
    /// whereas the conjunction still answers `Unsatisfied` — "this will
    /// transfer" — when the file is simply not there.
    ///
    /// Existence is deliberately the weaker half: a half-written file
    /// from an interrupted download exists. A profile that declares a
    /// digest is protected from that; one that does not has asked for
    /// existence and gets it (design §3.3: an entity type does not fix
    /// its own assert).
    fn done(&self) -> Assert {
        let exists = Assert::FileExists {
            path: self.dst.clone(),
        };
        match &self.sha256 {
            None => exists,
            Some(expected_sha256) => Assert::All(NonEmpty::new(
                exists,
                vec![Assert::FileDigest {
                    path: self.dst.clone(),
                    expected_sha256: expected_sha256.clone(),
                }],
            )),
        }
    }
}

/// One git working copy a phase puts on the pod.
///
/// Shared by `comfyui.install` (which clones and checks out in a single
/// composed step) and `custom_nodes` (which clones and, when the entry
/// names a `ref`, checks out in a second one) — the recurrence design
/// §3.4 gives as the reason for an entity to exist at all.
///
/// Its identity is the destination directory plus, when the profile
/// names one, the ref its content must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    dir: PathBuf,
    git_ref: Option<String>,
}

impl Checkout {
    /// A working copy at `dir`, optionally pinned to `git_ref`.
    ///
    /// `None` is a profile that named no ref — a `custom_nodes` entry
    /// that only clones — not a ref that is unknown yet.
    pub fn new(dir: impl Into<PathBuf>, git_ref: Option<String>) -> Self {
        Self {
            dir: dir.into(),
            git_ref,
        }
    }
}

impl Done for Checkout {
    /// A repository is there and — when the profile named a ref — holds
    /// that ref's content.
    ///
    /// **The weak half is `<dir>/.git`, not `<dir>`.** Design §3.3 says
    /// existence alone does not finish a checkout, and this is where
    /// that is paid: a directory can exist without being a clone (the
    /// operator made it, an earlier tool wrote into it), and answering
    /// "finished" for one would skip the clone and leave every step
    /// after it working against an empty tree. Asking for the
    /// repository's own directory is the same cost and a true statement.
    /// It is still the weaker half, and honestly so: an interrupted
    /// clone can leave a `.git` behind, and a profile that named no ref
    /// has asked for "there is a clone here" and gets exactly that.
    ///
    /// **With a ref, the conjunction is load-bearing** — for a different
    /// reason than [`ModelFile`]'s. There the second conjunct goes
    /// `NotChecked` in a dry run, so the first is what keeps the answer
    /// decidable. Here [`Assert::GitTreeAt`] answers in both modes, but
    /// on a pod where nothing has been cloned yet it answers
    /// `CheckFailed` — git cannot find a repository to compare in. On
    /// its own that is "undecided"; conjoined with the existence of
    /// `.git`, fold row 1 makes the answer `Unsatisfied`, which is the
    /// difference between a plan that says "this will clone" and a plan
    /// that says it could not tell. The tree keeps git's failure
    /// underneath either way (design §3.2b'), so nothing is hidden by
    /// deciding.
    ///
    /// The order is existence first, which is also the order a reader
    /// wants: is there a clone, and is it the right one.
    fn done(&self) -> Assert {
        let cloned = Assert::FileExists {
            path: self.dir.join(".git"),
        };
        match &self.git_ref {
            None => cloned,
            Some(git_ref) => Assert::All(NonEmpty::new(
                cloned,
                vec![Assert::GitTreeAt {
                    dir: self.dir.clone(),
                    git_ref: git_ref.clone(),
                }],
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // -----------------------------------------------------------------
    // A fixed-response host
    // -----------------------------------------------------------------

    /// The state a path can be in, from an observation's point of view.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostFile {
        /// Nothing there.
        Absent,
        /// There, and the observation succeeds; carries the content.
        Readable(&'static str),
        /// There or not — the observation itself fails (EACCES and the
        /// like).
        Unobservable,
    }

    /// How a command ends, from an observation's point of view.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostCommand {
        /// It ran and exited with this status.
        Exits(i32),
        /// It could not be started at all (the binary is not there).
        Unrunnable,
    }

    /// Answers observations from a fixed table, so a whole evaluation is
    /// reproducible without touching the real filesystem — or spawning
    /// anything.
    struct FakeHost {
        files: BTreeMap<PathBuf, HostFile>,
        commands: BTreeMap<Vec<String>, HostCommand>,
    }

    impl FakeHost {
        fn new(entries: &[(&str, HostFile)]) -> Self {
            Self {
                files: entries
                    .iter()
                    .map(|(path, state)| (PathBuf::from(path), *state))
                    .collect(),
                commands: BTreeMap::new(),
            }
        }

        /// Fix what `argv` does. A command this is not called for is
        /// [`HostCommand::Unrunnable`] — a test that did not say what a
        /// command does gets the answer that says so, rather than a
        /// silent success.
        fn running(mut self, argv: Vec<String>, reply: HostCommand) -> Self {
            self.commands.insert(argv, reply);
            self
        }

        fn at(&self, path: &Path) -> HostFile {
            self.files.get(path).copied().unwrap_or(HostFile::Absent)
        }
    }

    /// A detail string derived only from the observation — no clock, no
    /// counter — as [`CheckError`] requires.
    const UNOBSERVABLE_DETAIL: &str = "the path could not be observed";

    fn unobservable() -> CheckError {
        CheckError::new(CheckErrorCategory::Unobservable, UNOBSERVABLE_DETAIL)
    }

    /// What a command that could not be started answers with.
    const UNRUNNABLE_DETAIL: &str = "the command could not be started";

    fn unrunnable() -> CheckError {
        CheckError::new(CheckErrorCategory::Unobservable, UNRUNNABLE_DETAIL)
    }

    impl Observe for FakeHost {
        async fn file_exists(&self, path: &Path) -> Result<bool, CheckError> {
            match self.at(path) {
                HostFile::Absent => Ok(false),
                HostFile::Readable(_) => Ok(true),
                HostFile::Unobservable => Err(unobservable()),
            }
        }

        async fn file_digest(&self, path: &Path) -> Result<DigestReading, CheckError> {
            match self.at(path) {
                HostFile::Absent => Ok(DigestReading::Absent),
                HostFile::Readable(content) => Ok(DigestReading::Present(
                    // The crate's single content-digest implementation.
                    crate::digest::hex_sha256(content.as_bytes()),
                )),
                HostFile::Unobservable => Err(unobservable()),
            }
        }

        async fn command_status(&self, argv: &[String]) -> Result<i32, CheckError> {
            match self
                .commands
                .get(argv)
                .copied()
                .unwrap_or(HostCommand::Unrunnable)
            {
                HostCommand::Exits(code) => Ok(code),
                HostCommand::Unrunnable => Err(unrunnable()),
            }
        }
    }

    fn exists(path: &str) -> Assert {
        Assert::FileExists {
            path: PathBuf::from(path),
        }
    }

    fn digest_of(content: &str) -> String {
        crate::digest::hex_sha256(content.as_bytes())
    }

    fn digest(path: &str, expected: &str) -> Assert {
        Assert::FileDigest {
            path: PathBuf::from(path),
            expected_sha256: expected.to_string(),
        }
    }

    fn failed(detail: &str) -> AssertOutcome {
        AssertOutcome::CheckFailed(CheckError::new(CheckErrorCategory::Unobservable, detail))
    }

    // -----------------------------------------------------------------
    // The fold table: 4 rows plus row 3's tie-break
    // -----------------------------------------------------------------

    #[test]
    fn fold_row1_one_unsatisfied_child_wins_over_a_check_failure() {
        let children = NonEmpty::new(
            failed("first"),
            vec![AssertOutcome::Unsatisfied, AssertOutcome::Satisfied],
        );
        assert_eq!(fold_all(&children), AssertOutcome::Unsatisfied);
    }

    #[test]
    fn fold_row2_all_satisfied_children_give_satisfied() {
        let children = NonEmpty::new(
            AssertOutcome::Satisfied,
            vec![AssertOutcome::Satisfied, AssertOutcome::Satisfied],
        );
        assert_eq!(fold_all(&children), AssertOutcome::Satisfied);
    }

    #[test]
    fn fold_row3_a_check_failure_without_any_unsatisfied_gives_check_failed() {
        let children = NonEmpty::new(
            AssertOutcome::Satisfied,
            vec![failed("only"), AssertOutcome::NotChecked],
        );
        assert_eq!(fold_all(&children), failed("only"));
    }

    #[test]
    fn fold_row3_tie_break_keeps_the_first_check_error_in_child_order() {
        let children = NonEmpty::new(
            AssertOutcome::NotChecked,
            vec![failed("first"), failed("second")],
        );
        assert_eq!(
            fold_all(&children),
            failed("first"),
            "the earliest child's CheckError is the one that survives",
        );
    }

    #[test]
    fn fold_row4_not_checked_survives_when_nothing_stronger_is_present() {
        let children = NonEmpty::new(
            AssertOutcome::Satisfied,
            vec![AssertOutcome::NotChecked, AssertOutcome::Satisfied],
        );
        assert_eq!(fold_all(&children), AssertOutcome::NotChecked);
    }

    // -----------------------------------------------------------------
    // Reproducibility
    // -----------------------------------------------------------------

    /// The tree with the ids removed.
    #[derive(Debug, PartialEq, Eq)]
    enum Shape {
        Leaf(AssertOutcome),
        All(AssertOutcome, Vec<Shape>),
    }

    fn shape(node: &AssertNode) -> Shape {
        match node {
            AssertNode::Leaf { outcome, .. } => Shape::Leaf(outcome.clone()),
            AssertNode::All {
                outcome, children, ..
            } => Shape::All(outcome.clone(), children.iter().map(shape).collect()),
        }
    }

    fn ids(node: &AssertNode, out: &mut Vec<AssertExecutionId>) {
        match node {
            AssertNode::Leaf { id, .. } => out.push(*id),
            AssertNode::All { id, children, .. } => {
                out.push(*id);
                for child in children.iter() {
                    ids(child, out);
                }
            }
        }
    }

    fn id_list(node: &AssertNode) -> Vec<AssertExecutionId> {
        let mut out = Vec::new();
        ids(node, &mut out);
        out
    }

    /// Evaluating the same Assert twice **against a host held fixed for
    /// the duration** gives the same answer, `CheckError` details
    /// included. The premise cannot be read off the return value, so the
    /// host is pinned here by handing the evaluator a fixed-response
    /// observer. A host that changes between the two evaluations (a
    /// race) is out of scope.
    ///
    /// What is compared is the outcome projection and the id-stripped
    /// shape. Comparing whole trees would always fail, because ids are
    /// per execution — and that red would say nothing about the
    /// implementation.
    #[tokio::test]
    async fn the_same_assert_twice_on_a_fixed_host_gives_the_same_answer() {
        let host = FakeHost::new(&[
            ("/present", HostFile::Readable("payload")),
            ("/blocked", HostFile::Unobservable),
        ]);
        let assert = Assert::All(NonEmpty::new(
            exists("/present"),
            vec![
                digest("/present", &digest_of("payload")),
                exists("/blocked"),
                exists("/missing"),
            ],
        ));

        let first = eval(&assert, ExecMode::Real, &host).await;
        let second = eval(&assert, ExecMode::Real, &host).await;

        assert_eq!(first.outcome(), second.outcome());
        assert_eq!(shape(&first), shape(&second));
        assert_ne!(
            id_list(&first),
            id_list(&second),
            "ids are per execution, which is why whole-tree equality is not the assertion",
        );
    }

    // -----------------------------------------------------------------
    // The leaf contract
    // -----------------------------------------------------------------

    /// Every leaf that answers `Satisfied` under `DryRun` answers
    /// `Satisfied` under `Real` too.
    ///
    /// The enumeration is over **leaves only**, literally:
    ///
    /// | predicate | observations | modes |
    /// |---|---|---|
    /// | file exists | absent / present (observable) / unobservable | `Real`, `DryRun` |
    /// | file digest | absent / present matching / present differing / unobservable | `Real`, `DryRun` |
    /// | git tree at | exit 0 / exit 1 / exit 128 / could not be started | `Real`, `DryRun` |
    ///
    /// = 3×2 + 4×2 + 4×2 = **22 combinations**. It is not written as
    /// "3 predicates × 4 observations × 2 modes": the existence
    /// predicate has no matching/differing distinction, so that product
    /// would double-count and the count would depend on how it was
    /// written.
    ///
    /// **The third row is what this stage adds, and it is why the
    /// enumeration is the Done Criteria rather than a nicety.** The
    /// command predicate answers *identically* in both modes — it does
    /// not merely avoid returning `Satisfied` in a dry run, it returns
    /// the same thing a real run would — so the contract holds by the
    /// strongest available margin. The four observations are git's own
    /// documented exit shapes for `diff --quiet` (`0` no difference,
    /// `1` difference, other = git failed) plus the binary being
    /// missing, which is an answer rather than an error (design §3.2b).
    ///
    /// Composition is *not* covered here — the contract is a property of
    /// leaves, and a version of this that enumerated `All` up to depth 2
    /// would be red. Composition is looked at separately below.
    ///
    /// `proptest` / `quickcheck` are not in the workspace, so this is an
    /// enumeration rather than a universally quantified statement.
    #[tokio::test]
    async fn every_leaf_satisfies_the_dry_run_contract() {
        let matching = "content that matches";
        let expected = digest_of(matching);
        let file = |state| FakeHost::new(&[("/target", state)]);
        let repo =
            |reply| FakeHost::new(&[]).running(git_tree_at_argv(Path::new("/repo"), "v1"), reply);
        let at_v1 = || Assert::GitTreeAt {
            dir: PathBuf::from("/repo"),
            git_ref: "v1".to_string(),
        };

        // (label, host, assert, expected DryRun answer, expected Real answer)
        let cases: Vec<(&str, FakeHost, Assert, AssertOutcome, AssertOutcome)> = vec![
            // file exists — 3 observations.
            (
                "exists / absent",
                file(HostFile::Absent),
                exists("/target"),
                AssertOutcome::Unsatisfied,
                AssertOutcome::Unsatisfied,
            ),
            (
                "exists / present",
                file(HostFile::Readable(matching)),
                exists("/target"),
                AssertOutcome::Satisfied,
                AssertOutcome::Satisfied,
            ),
            (
                "exists / unobservable",
                file(HostFile::Unobservable),
                exists("/target"),
                failed(UNOBSERVABLE_DETAIL),
                failed(UNOBSERVABLE_DETAIL),
            ),
            // file digest — 4 observations.
            (
                "digest / absent",
                file(HostFile::Absent),
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Unsatisfied,
            ),
            (
                "digest / present matching",
                file(HostFile::Readable(matching)),
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Satisfied,
            ),
            (
                "digest / present differing",
                file(HostFile::Readable("content that does not match")),
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Unsatisfied,
            ),
            (
                "digest / unobservable",
                file(HostFile::Unobservable),
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                failed(UNOBSERVABLE_DETAIL),
            ),
            // git tree at — 4 observations, answering the same in both
            // modes.
            (
                "git tree / exit 0 (no difference)",
                repo(HostCommand::Exits(0)),
                at_v1(),
                AssertOutcome::Satisfied,
                AssertOutcome::Satisfied,
            ),
            (
                "git tree / exit 1 (difference)",
                repo(HostCommand::Exits(1)),
                at_v1(),
                AssertOutcome::Unsatisfied,
                AssertOutcome::Unsatisfied,
            ),
            (
                "git tree / exit 128 (no repository, or unknown ref)",
                repo(HostCommand::Exits(128)),
                at_v1(),
                failed("git exited 128"),
                failed("git exited 128"),
            ),
            (
                "git tree / git could not be started",
                repo(HostCommand::Unrunnable),
                at_v1(),
                failed(UNRUNNABLE_DETAIL),
                failed(UNRUNNABLE_DETAIL),
            ),
        ];

        for (label, host, assert, want_dry, want_real) in cases {
            let dry = eval(&assert, ExecMode::DryRun, &host).await;
            let real = eval(&assert, ExecMode::Real, &host).await;
            assert_eq!(dry.outcome(), &want_dry, "{label} under DryRun");
            assert_eq!(real.outcome(), &want_real, "{label} under Real");
            if want_dry == AssertOutcome::Satisfied {
                assert_eq!(
                    real.outcome(),
                    &AssertOutcome::Satisfied,
                    "{label}: DryRun answered Satisfied, so Real must too",
                );
            }
        }
    }

    /// If every leaf keeps the contract, the one-sided property survives
    /// composition: `All` (to depth 2) and the `Not` image.
    ///
    /// This is stated **on `AssertOutcome`**, not by building `Assert`
    /// values: this stage has no `Not` variant, so `Not(All)` and
    /// `All(Not, _)` are not expressible as expressions, and trying to
    /// build them would contradict the expression type.
    ///
    /// The starting set is the `(DryRun, Real)` pairs the two leaves can
    /// actually produce, read off the enumeration above. The first level
    /// closes them under `not` and under `All` of one, two and three
    /// children; the second level closes that result under `not` and
    /// under `All` of one and two children.
    #[test]
    fn the_one_sided_contract_survives_fold_and_not_to_depth_two() {
        /// A leaf's or a composition's `(DryRun, Real)` answers.
        type Pair = (AssertOutcome, AssertOutcome);

        let failure = failed(UNOBSERVABLE_DETAIL);
        let leaves: Vec<Pair> = vec![
            // exists / absent
            (AssertOutcome::Unsatisfied, AssertOutcome::Unsatisfied),
            // exists / present
            (AssertOutcome::Satisfied, AssertOutcome::Satisfied),
            // exists / unobservable
            (failure.clone(), failure.clone()),
            // digest / absent and digest / present differing
            (AssertOutcome::NotChecked, AssertOutcome::Unsatisfied),
            // digest / present matching
            (AssertOutcome::NotChecked, AssertOutcome::Satisfied),
            // digest / unobservable
            (AssertOutcome::NotChecked, failure.clone()),
        ];

        /// Fold one conjunction's children on both sides at once.
        fn folded(children: &[&Pair]) -> Option<Pair> {
            let (head, tail) = children.split_first()?;
            let dry = fold_all(&NonEmpty::new(
                head.0.clone(),
                tail.iter().map(|child| child.0.clone()).collect(),
            ));
            let real = fold_all(&NonEmpty::new(
                head.1.clone(),
                tail.iter().map(|child| child.1.clone()).collect(),
            ));
            Some((dry, real))
        }

        fn compose(pairs: &[Pair], max_arity: usize) -> Vec<Pair> {
            let mut out = Vec::new();
            for a in pairs {
                out.push((not(a.0.clone()), not(a.1.clone())));
                out.extend(folded(&[a]));
                if max_arity < 2 {
                    continue;
                }
                for b in pairs {
                    out.extend(folded(&[a, b]));
                    if max_arity < 3 {
                        continue;
                    }
                    for c in pairs {
                        out.extend(folded(&[a, b, c]));
                    }
                }
            }
            out
        }

        let depth1 = compose(&leaves, 3);
        let mut reachable = leaves.clone();
        reachable.extend(depth1.iter().cloned());
        let depth2 = compose(&reachable, 2);

        for (dry, real) in leaves.iter().chain(depth1.iter()).chain(depth2.iter()) {
            if dry == &AssertOutcome::Satisfied {
                assert_eq!(
                    real,
                    &AssertOutcome::Satisfied,
                    "a composition answered Satisfied under DryRun but {real:?} under Real",
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // What the model can express
    // -----------------------------------------------------------------

    /// Form 1: a basic predicate is an Assert on its own — no connective
    /// needed, and no wrapping `All` in the result tree either.
    #[tokio::test]
    async fn a_basic_predicate_is_an_assert_by_itself() {
        let host = FakeHost::new(&[("/target", HostFile::Readable("x"))]);
        let node = eval(&exists("/target"), ExecMode::Real, &host).await;
        assert_eq!(node.outcome(), &AssertOutcome::Satisfied);
        assert!(
            matches!(node, AssertNode::Leaf { .. }),
            "a bare predicate must not be wrapped in a conjunction",
        );
    }

    /// Form 2: a two-predicate conjunction where `DryRun` drops one side
    /// to `NotChecked`.
    ///
    /// **The host state matters and is fixed on purpose.** The file the
    /// existence predicate looks at is present and observable: if it
    /// were absent the top would be `Unsatisfied`, and if it were
    /// unobservable the top would be `CheckFailed`. `NotChecked` only
    /// surfaces when that side is present and observable.
    ///
    /// The condition binds **only** the existence side. The digest side
    /// is not observed under `DryRun` at all, so the top stays
    /// `NotChecked` whatever state that file is in — which is checked
    /// here by sweeping it, and doubles as the test that `DryRun` really
    /// does not observe. Pinning both sides to "present and observable"
    /// would leave exactly one combination and pick the weakest possible
    /// witness for "both outcomes survive in the tree".
    #[tokio::test]
    async fn a_dry_run_conjunction_reports_not_checked_and_keeps_both_outcomes() {
        for digest_side in [
            HostFile::Absent,
            HostFile::Readable("whatever"),
            HostFile::Readable("something else"),
            HostFile::Unobservable,
        ] {
            let host = FakeHost::new(&[
                ("/observable", HostFile::Readable("present and readable")),
                ("/swept", digest_side),
            ]);
            let assert = Assert::All(NonEmpty::new(
                exists("/observable"),
                vec![digest("/swept", &digest_of("whatever"))],
            ));

            let node = eval(&assert, ExecMode::DryRun, &host).await;

            assert_eq!(
                node.outcome(),
                &AssertOutcome::NotChecked,
                "digest side {digest_side:?} must not change the answer",
            );
            assert_eq!(
                shape(&node),
                Shape::All(
                    AssertOutcome::NotChecked,
                    vec![
                        Shape::Leaf(AssertOutcome::Satisfied),
                        Shape::Leaf(AssertOutcome::NotChecked),
                    ],
                ),
                "both children's outcomes stay in the tree",
            );
        }
    }

    // -----------------------------------------------------------------
    // The tree carries what the projection loses
    // -----------------------------------------------------------------

    /// The witness: `All [exists(/a), exists(/b)]` with `/a` absent and
    /// `/b` unobservable. The top projects to `Unsatisfied`, yet the
    /// `CheckFailed` is still in the tree — which is the whole reason
    /// the evaluator returns a tree rather than one value.
    #[tokio::test]
    async fn a_check_failure_hidden_by_the_projection_is_still_in_the_tree() {
        let host = FakeHost::new(&[("/a", HostFile::Absent), ("/b", HostFile::Unobservable)]);
        let assert = Assert::All(NonEmpty::new(exists("/a"), vec![exists("/b")]));

        let node = eval(&assert, ExecMode::Real, &host).await;

        assert_eq!(node.outcome(), &AssertOutcome::Unsatisfied);
        assert_eq!(
            shape(&node),
            Shape::All(
                AssertOutcome::Unsatisfied,
                vec![
                    Shape::Leaf(AssertOutcome::Unsatisfied),
                    Shape::Leaf(failed(UNOBSERVABLE_DETAIL)),
                ],
            ),
            "the CheckFailed the projection drops must survive in the tree",
        );
    }

    // -----------------------------------------------------------------
    // The Not image
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // The one entity: ModelFile
    // -----------------------------------------------------------------

    /// A profile that declared no digest gets a bare predicate — no
    /// conjunction wrapping one child.
    #[test]
    fn a_model_file_without_a_digest_is_a_single_predicate() {
        let done = ModelFile::new("/models/checkpoints/a.safetensors", None).done();
        assert_eq!(
            done,
            Assert::FileExists {
                path: PathBuf::from("/models/checkpoints/a.safetensors"),
            },
            "existence alone is the whole condition, not All[existence]",
        );
        assert!(
            !matches!(done, Assert::All(_)),
            "a lone predicate must not be wrapped in a conjunction",
        );
    }

    /// With a digest the condition is existence ∧ content, in that
    /// order — the order the fold's tie-break and the trace both read.
    #[test]
    fn a_model_file_with_a_digest_conjoins_existence_and_content() {
        let done = ModelFile::new("/models/loras/b.safetensors", Some("ABCDEF".to_string())).done();
        assert_eq!(
            done,
            Assert::All(NonEmpty::new(
                Assert::FileExists {
                    path: PathBuf::from("/models/loras/b.safetensors"),
                },
                vec![Assert::FileDigest {
                    path: PathBuf::from("/models/loras/b.safetensors"),
                    // Declared uppercase, compared lowercase: the
                    // rendering contract is lowercase hex, and a
                    // profile spelling it the other way must not fail
                    // forever against a digest that can never match.
                    expected_sha256: "abcdef".to_string(),
                }],
            )),
        );
    }

    /// The reason the existence conjunct is not redundant: a dry run
    /// does not read the digest, so on the digest alone every answer
    /// would be `NotChecked`. The conjunction still says `Unsatisfied`
    /// — "this will transfer" — for a file that is simply absent.
    #[tokio::test]
    async fn a_dry_run_still_decides_a_model_file_that_is_not_there() {
        let done = ModelFile::new("/target", Some(digest_of("weights"))).done();

        let absent = FakeHost::new(&[("/target", HostFile::Absent)]);
        assert_eq!(
            eval(&done, ExecMode::DryRun, &absent).await.outcome(),
            &AssertOutcome::Unsatisfied,
            "an absent file is decided in a dry run: the transfer will happen",
        );

        let present = FakeHost::new(&[("/target", HostFile::Readable("weights"))]);
        assert_eq!(
            eval(&done, ExecMode::DryRun, &present).await.outcome(),
            &AssertOutcome::NotChecked,
            "a present file is undecided in a dry run: the digest was not read",
        );
    }

    // -----------------------------------------------------------------
    // The second entity: Checkout
    // -----------------------------------------------------------------

    fn checkout_host(dir: &str, git_ref: &str, state: HostFile, reply: HostCommand) -> FakeHost {
        FakeHost::new(&[(&format!("{dir}/.git"), state)])
            .running(git_tree_at_argv(Path::new(dir), git_ref), reply)
    }

    /// A profile that named no ref asks for a repository and gets one —
    /// a bare predicate, no conjunction around it.
    ///
    /// **The subject is `<dir>/.git`, not `<dir>`.** A directory that
    /// exists without being a clone is a real state of a pod, and
    /// answering "finished" for it would skip the clone and leave every
    /// later step working against an empty tree (design §3.3:
    /// "`Checkout` は存在だけでは足りない").
    #[test]
    fn a_checkout_without_a_ref_asks_for_the_repository_alone() {
        let done = Checkout::new("/workspace/ComfyUI", None).done();
        assert_eq!(
            done,
            Assert::FileExists {
                path: PathBuf::from("/workspace/ComfyUI/.git"),
            },
        );
        assert!(
            !matches!(done, Assert::All(_)),
            "a lone predicate must not be wrapped in a conjunction",
        );
    }

    /// With a ref the condition is repository ∧ ref, in that order.
    #[test]
    fn a_checkout_with_a_ref_conjoins_the_repository_and_the_ref() {
        let done = Checkout::new("/nodes/impact", Some("v2".to_string())).done();
        assert_eq!(
            done,
            Assert::All(NonEmpty::new(
                Assert::FileExists {
                    path: PathBuf::from("/nodes/impact/.git"),
                },
                vec![Assert::GitTreeAt {
                    dir: PathBuf::from("/nodes/impact"),
                    git_ref: "v2".to_string(),
                }],
            )),
        );
    }

    /// **Why the conjunction is load-bearing**, and it is not the same
    /// reason as [`ModelFile`]'s.
    ///
    /// On a pod where nothing has been cloned, `git` has no repository
    /// to compare in and exits 128 — `CheckFailed`, i.e. "undecided" on
    /// its own. The existence conjunct answers `Unsatisfied`, and fold
    /// row 1 makes the whole condition `Unsatisfied`: **this will
    /// clone**, which is what a plan has to be able to say. The tree
    /// still carries git's failure underneath, so deciding hides
    /// nothing (design §3.2b').
    ///
    /// Both modes, because the command predicate does not change its
    /// answer between them — the dry run is as decided as the real run.
    #[tokio::test]
    async fn a_checkout_on_a_pod_with_no_clone_is_decided_rather_than_undecided() {
        let done = Checkout::new("/workspace/ComfyUI", Some("v0.1.0".to_string())).done();
        let host = checkout_host(
            "/workspace/ComfyUI",
            "v0.1.0",
            HostFile::Absent,
            HostCommand::Exits(128),
        );

        for mode in [ExecMode::DryRun, ExecMode::Real] {
            let node = eval(&done, mode, &host).await;
            assert_eq!(
                node.outcome(),
                &AssertOutcome::Unsatisfied,
                "{mode:?}: an absent repository is decided, not undecided",
            );
            assert_eq!(
                shape(&node),
                Shape::All(
                    AssertOutcome::Unsatisfied,
                    vec![
                        Shape::Leaf(AssertOutcome::Unsatisfied),
                        Shape::Leaf(failed("git exited 128")),
                    ],
                ),
                "{mode:?}: git's failure survives in the tree",
            );
        }
    }

    /// The three answers a cloned repository can give, in both modes:
    /// at the ref, at a different one, and unreadable.
    #[tokio::test]
    async fn a_cloned_repository_answers_on_the_ref() {
        let done = Checkout::new("/repo", Some("v1".to_string())).done();
        let cases = [
            (HostCommand::Exits(0), AssertOutcome::Satisfied),
            (HostCommand::Exits(1), AssertOutcome::Unsatisfied),
            (HostCommand::Exits(128), failed("git exited 128")),
            (HostCommand::Unrunnable, failed(UNRUNNABLE_DETAIL)),
        ];
        for (reply, want) in cases {
            let host = checkout_host("/repo", "v1", HostFile::Readable("gitdir"), reply);
            for mode in [ExecMode::DryRun, ExecMode::Real] {
                assert_eq!(
                    eval(&done, mode, &host).await.outcome(),
                    &want,
                    "{reply:?} under {mode:?}",
                );
            }
        }
    }

    /// The command is a template of the two fields, and read-only by
    /// construction: nothing an entity supplies can change the verb or
    /// the flags. That is the property the dry-run decision rests on
    /// ([`Assert::GitTreeAt`]), so it is pinned rather than left to be
    /// read off the source.
    #[test]
    fn the_command_the_predicate_fires_is_a_read_only_template() {
        assert_eq!(
            git_tree_at_argv(Path::new("/workspace/ComfyUI"), "v0.1.0"),
            vec![
                "git".to_string(),
                "--no-optional-locks".to_string(),
                "-C".to_string(),
                "/workspace/ComfyUI".to_string(),
                "diff".to_string(),
                "--quiet".to_string(),
                "v0.1.0".to_string(),
                "HEAD".to_string(),
                "--".to_string(),
            ],
        );
    }

    /// A branch, a tag and a commit compose the same command, so they
    /// are judged the same way: the ref is resolved in the local
    /// repository the step produced, and neither the step nor this
    /// predicate fetches.
    #[test]
    fn a_branch_a_tag_and_a_sha_are_all_just_the_ref() {
        let dir = Path::new("/repo");
        for git_ref in ["main", "v1.2.3", "9660479"] {
            let argv = git_tree_at_argv(dir, git_ref);
            assert_eq!(argv[6], git_ref, "the ref reaches the command verbatim");
            assert_eq!(argv[7], "HEAD");
        }
    }

    // -----------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------

    #[test]
    fn describe_prints_the_condition_without_answers() {
        let done = ModelFile::new("/w/a.bin", Some("abc".to_string())).done();
        assert_eq!(
            describe(&done),
            "all[exists(/w/a.bin), sha256(/w/a.bin)=abc]"
        );
    }

    /// The annotated form carries every subterm's answer, including one
    /// the top-level projection drops.
    #[tokio::test]
    async fn describe_execution_keeps_an_answer_the_projection_hides() {
        let host = FakeHost::new(&[("/a", HostFile::Absent), ("/b", HostFile::Unobservable)]);
        let assert = Assert::All(NonEmpty::new(exists("/a"), vec![exists("/b")]));

        let node = eval(&assert, ExecMode::Real, &host).await;
        let rendered = describe_execution(&assert, &node);

        assert_eq!(
            rendered,
            format!(
                "all[exists(/a)=unsatisfied, exists(/b)=check-failed(Unobservable: \
                 {UNOBSERVABLE_DETAIL})]=unsatisfied"
            ),
            "the check failure the top answer drops is still printed",
        );
    }

    #[test]
    fn not_swaps_satisfied_and_unsatisfied_and_fixes_the_other_two() {
        assert_eq!(not(AssertOutcome::Satisfied), AssertOutcome::Unsatisfied);
        assert_eq!(not(AssertOutcome::Unsatisfied), AssertOutcome::Satisfied);
        assert_eq!(not(AssertOutcome::NotChecked), AssertOutcome::NotChecked);
        let failure = failed(UNOBSERVABLE_DETAIL);
        assert_eq!(not(failure.clone()), failure.clone());
        // An involution.
        for outcome in [
            AssertOutcome::Satisfied,
            AssertOutcome::Unsatisfied,
            AssertOutcome::NotChecked,
            failure,
        ] {
            assert_eq!(not(not(outcome.clone())), outcome);
        }
    }
}
