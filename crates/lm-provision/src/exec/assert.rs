//! The Assert model: what an Assert answers, how answers compose, and
//! how an Assert is evaluated (design.md §3, plan 段 A).
//!
//! An Assert is an *expression*, not a closed list of cases. Evaluating
//! one reads the host, so it can fail; "did not evaluate" and "could not
//! evaluate" are different things and are not folded together. Hence the
//! four-valued [`AssertOutcome`].
//!
//! **This module does not decide what any particular Assert means.**
//! "What does a finished `ModelFile` / `Service` / `Checkout` look like"
//! is a separate design question, handled per entity in later stages.
//! What lives here is only the type, the value range, the composition,
//! the evaluator, and the two basic predicates needed to show that the
//! composition works at all.
//!
//! ## Scope boundary
//!
//! Everything here is `pub(crate)` — the item *and* the module path (see
//! [`crate::exec`]). Nothing reaches the AST, the canonical encoding,
//! validation or the plan artifact, so a profile's public surface and
//! its hash are unaffected. Assert becomes author-visible in a later
//! stage.
//!
//! Because no caller exists yet, the items below carry item-level
//! `#[allow(dead_code)]`. That is deliberate: a module-level blanket
//! allow would let a stale one survive unnoticed once callers arrive,
//! whereas item-level allows go stale one by one and keep the incentive
//! to remove them.

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
#[allow(dead_code)]
pub(crate) enum AssertOutcome {
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
#[allow(dead_code)]
pub(crate) struct CheckError {
    category: CheckErrorCategory,
    detail: String,
}

#[allow(dead_code)]
impl CheckError {
    /// Build a failure answer from a category and its detail.
    pub(crate) fn new(category: CheckErrorCategory, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
        }
    }

    /// The coarse classification.
    pub(crate) fn category(&self) -> CheckErrorCategory {
        self.category
    }

    /// The observation-derived detail.
    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

/// The coarse classification carried by a [`CheckError`].
///
/// **The set is deliberately open here.** This stage contains no code
/// that inspects an errno — the only [`Observe`] implementations it has
/// are fixed-response ones used by tests — so closing the set now would
/// mean the stage that actually writes the observations inherits a
/// guess. What this stage fixes is the *shape*: a category plus a
/// detail. The category set and the errno mapping close where the
/// observations are implemented.
//
// 段 B/C で決める: which categories exist, and which errno / transport
// failure lands in which one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum CheckErrorCategory {
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
#[allow(dead_code)]
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
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct NonEmpty<T> {
        head: Box<T>,
        tail: Vec<T>,
    }

    impl<T> NonEmpty<T> {
        /// The only constructor. A head is mandatory, so an empty value
        /// cannot be expressed.
        pub(crate) fn new(head: T, tail: Vec<T>) -> Self {
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
        pub(crate) fn head(&self) -> &T {
            &self.head
        }

        /// Head first, then the tail in order.
        pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
            std::iter::once(self.head()).chain(self.tail.iter())
        }

        /// A count-preserving transform.
        ///
        /// Without it the evaluator could not turn a `NonEmpty<Assert>`
        /// into a `NonEmpty<AssertOutcome>` and would need a panic path
        /// to rebuild one.
        pub(crate) fn map<U>(&self, f: impl Fn(&T) -> U) -> NonEmpty<U> {
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

pub(crate) use nonempty::NonEmpty;

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
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum Assert {
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
    /// (lowercase hex, see [`crate::canonical::hex_sha256`]).
    ///
    /// Same boundary as [`Assert::FileExists`]: how the content is read
    /// is the observation's business, not the model's.
    FileDigest {
        /// The observed path.
        path: PathBuf,
        /// The digest the content must have.
        expected_sha256: String,
    },

    /// Conjunction. Child order is the order the author wrote.
    All(NonEmpty<Assert>),
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) struct AssertExecutionId(u64);

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
#[allow(dead_code)]
pub(crate) enum AssertNode {
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

#[allow(dead_code)]
impl AssertNode {
    /// The projection down to a single answer.
    pub(crate) fn outcome(&self) -> &AssertOutcome {
        match self {
            AssertNode::Leaf { outcome, .. } | AssertNode::All { outcome, .. } => outcome,
        }
    }
}

// ---------------------------------------------------------------------
// (5) The observation channel
// ---------------------------------------------------------------------

/// What an observation of a file's content digest found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum DigestReading {
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
/// them. With one trait the evaluator only knows `O: Observe`. Methods
/// are `async fn` in trait (RPITIT) and dispatch stays static, so no
/// `async_trait` and no `dyn` is involved.
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
#[allow(dead_code)]
pub(crate) trait Observe {
    /// Whether a file is at `path`.
    async fn file_exists(&self, path: &Path) -> Result<bool, CheckError>;

    /// The content digest of the file at `path`, lowercase hex (see
    /// [`crate::canonical::hex_sha256`] for the rendering contract).
    async fn file_digest(&self, path: &Path) -> Result<DigestReading, CheckError>;
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
/// was already settled". This stage's two predicates are side-effect
/// free reads, so full evaluation and short-circuiting are
/// indistinguishable apart from cost; that gets revisited when a
/// predicate with side effects (running a command) arrives.
///
/// `mode` is [`crate::exec::ExecMode`], the same type the rest of the
/// execution layer branches on — a second mode type would split one
/// concept in two and force conversions at the step wiring. **The
/// composition carries no mode-specific rule**: each basic predicate
/// answers `NotChecked` for itself and [`fold_all`] folds as usual.
#[allow(dead_code)]
pub(crate) async fn eval<O: Observe>(assert: &Assert, mode: ExecMode, obs: &O) -> AssertNode {
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
fn eval_boxed<'a, O: Observe>(
    assert: &'a Assert,
    mode: ExecMode,
    obs: &'a O,
) -> Pin<Box<dyn Future<Output = AssertNode> + 'a>> {
    Box::pin(eval(assert, mode, obs))
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

    /// Answers observations from a fixed table, so a whole evaluation is
    /// reproducible without touching the real filesystem.
    struct FakeHost {
        files: BTreeMap<PathBuf, HostFile>,
    }

    impl FakeHost {
        fn new(entries: &[(&str, HostFile)]) -> Self {
            Self {
                files: entries
                    .iter()
                    .map(|(path, state)| (PathBuf::from(path), *state))
                    .collect(),
            }
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
                    // The crate's single hex-rendering implementation.
                    crate::canonical::hex_sha256(content.as_bytes()),
                )),
                HostFile::Unobservable => Err(unobservable()),
            }
        }
    }

    fn exists(path: &str) -> Assert {
        Assert::FileExists {
            path: PathBuf::from(path),
        }
    }

    fn digest_of(content: &str) -> String {
        crate::canonical::hex_sha256(content.as_bytes())
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
    /// | predicate | host states | modes |
    /// |---|---|---|
    /// | file exists | absent / present (observable) / unobservable | `Real`, `DryRun` |
    /// | file digest | absent / present matching / present differing / unobservable | `Real`, `DryRun` |
    ///
    /// = 3×2 + 4×2 = **14 combinations**. It is not written as
    /// "2 predicates × 4 host states × 2 modes": the existence predicate
    /// has no matching/differing distinction, so that product would
    /// double-count and the count would depend on how it was written.
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

        // (host state, assert, expected DryRun answer, expected Real answer)
        let cases: Vec<(&str, Assert, AssertOutcome, AssertOutcome)> = vec![
            // file exists — 3 host states.
            (
                "exists / absent",
                exists("/target"),
                AssertOutcome::Unsatisfied,
                AssertOutcome::Unsatisfied,
            ),
            (
                "exists / present",
                exists("/target"),
                AssertOutcome::Satisfied,
                AssertOutcome::Satisfied,
            ),
            (
                "exists / unobservable",
                exists("/target"),
                failed(UNOBSERVABLE_DETAIL),
                failed(UNOBSERVABLE_DETAIL),
            ),
            // file digest — 4 host states.
            (
                "digest / absent",
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Unsatisfied,
            ),
            (
                "digest / present matching",
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Satisfied,
            ),
            (
                "digest / present differing",
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                AssertOutcome::Unsatisfied,
            ),
            (
                "digest / unobservable",
                digest("/target", &expected),
                AssertOutcome::NotChecked,
                failed(UNOBSERVABLE_DETAIL),
            ),
        ];
        let hosts = [
            HostFile::Absent,
            HostFile::Readable(matching),
            HostFile::Unobservable,
            HostFile::Absent,
            HostFile::Readable(matching),
            HostFile::Readable("content that does not match"),
            HostFile::Unobservable,
        ];

        for ((label, assert, want_dry, want_real), state) in cases.into_iter().zip(hosts) {
            let host = FakeHost::new(&[("/target", state)]);
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
