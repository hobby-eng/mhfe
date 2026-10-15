//! Synthetic component outcomes shared by terminal rendering and startup failure controls.

/// A failed public cipher case, without relying on the reporting code's formatter.
pub(crate) fn failed_cipher_case() -> mhfe::self_check::ComponentOutcome {
    use mhfe::self_check::{CaseKind, ComponentOutcome, FailureDetail, KnownAnswerDifference};
    ComponentOutcome::Failed(FailureDetail::Case {
        kind: CaseKind::Vector,
        number: 4,
        total: 10,
        cause: Box::new(KnownAnswerDifference::GivesAnotherContainer.into()),
    })
}
