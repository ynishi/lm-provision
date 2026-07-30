//! dsl-kit-core adapters for [`super::ProfileNode`]: the [`ProfileValue`]
//! result type, the [`ProfileSemantics`] semantics adapter, and the
//! [`ProfileAst`] type alias the [`super::engine`] constructors return.

use dsl_kit::{DslExec as DslExecTrait, DslSemantics, LoopDecision, NodeId, OwnedDerivedAst};

use super::ProfileNode;

/// Execution value type for provision phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileValue {
    /// Unit result indicating successful execution of a phase step.
    Success(String),
}

impl From<()> for ProfileValue {
    fn from(_: ()) -> Self {
        ProfileValue::Success("ok".into())
    }
}

/// Literal env value nodes ([`ProfileNode::EnvLiteral`] /
/// [`ProfileNode::EnvSecret`]) carry a `String` `LitValue`; the engine
/// converts it into a [`ProfileValue`] when it evaluates the leaf. The
/// value is inert (exec-time env injection is deferred, spec 02
/// §Dispatch routing), so the string is wrapped as a success marker.
impl From<String> for ProfileValue {
    fn from(value: String) -> Self {
        ProfileValue::Success(value)
    }
}

/// Semantics adapter for provisioning AST execution under dsl-kit-core.
#[derive(Debug, Clone, Copy)]
pub struct ProfileSemantics;

impl DslSemantics for ProfileSemantics {
    type Value = ProfileValue;
    type Delta = ();
    type EffectError = std::convert::Infallible;
    type Cursor = ();

    fn unit_value(&self) -> ProfileValue {
        ProfileValue::Success("ok".into())
    }

    fn continue_loop(
        &self,
        _node: NodeId,
        _last: &ProfileValue,
        _iteration: usize,
    ) -> LoopDecision {
        LoopDecision::Break
    }
}

/// Owned AST projection: the engine borrows nothing, so hosts can hold
/// program and engine together without `Box::leak`.
pub type ProfileAst = OwnedDerivedAst<<ProfileNode as DslExecTrait>::LitValue, ProfileSemantics>;
