//! Typed rekey sequencing, confirmation and setting refusals.
use crate::ErrorCode;
use std::fmt;

/// A rekey's own refusal. Underlying cipher/wallet failures stay separately typed in the aggregate
/// returned by the orchestration methods; this enum never hides an aggregate or free-text reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RekeyError {
    /// The recovered or confirmed state belongs to other source credentials.
    OriginMismatch,
    /// The rehearsal's fingerprint needs the wallet's BIP39 passphrase.
    RehearsalNeedsPassphrase,
    /// The wallet is stated to have no BIP39 passphrase.
    WalletHasNoPassphrase,
    /// This refusal does not allow another confirmation.
    NoFurtherConfirmation,
    /// The owner cannot confirm this phrase: an address or the fingerprint does.
    OwnerCannotConfirm,
    /// Only the owner's confirmation states a length.
    OnlyOwnerStatesLength,
    /// The recovery must run at the old container's settings.
    OldSettingsRequired,
    /// The owner has not confirmed the recovered phrase yet; seal it only after their explicit yes (ConfirmedPhrase::confirmed_by_owner).
    OwnerHasNotConfirmed,
    /// The wallet's BIP39 passphrase is stated otherwise than the reference shows.
    PassphraseContradiction,
    /// The reference must be compared with the wallet's BIP39 passphrase, which it has.
    ReferenceNeedsPassphrase,
    /// Say whether the wallet has a BIP39 passphrase.
    PassphraseStatementRequired,
    /// A rekey is not confirmed by that reference kind.
    UnsupportedConfirmation,
    /// A rekey step out of its order.
    StepOutOfOrder,
    /// An owner's answer without a phrase.
    OwnerAnswerWithoutPhrase,
    /// A confirmed rekey lacks its phrase or new password.
    MissingSealingInputs,
    /// A rekey confirms without its recovery.
    ConfirmationWithoutRecovery,
    /// The owner selected a reading outside those offered, or has not selected among several.
    OwnerLength {
        /// The supported reading lengths from the retained recovery/refusal.
        offered: Vec<usize>,
        /// The stated length, or none when a choice is still needed.
        selected: Option<usize>,
    },
    /// Password and work settings would reproduce the old container unchanged.
    Unchanged,
    /// The owner explicitly rejected the recovered phrase.
    OwnerRejected,
}
impl RekeyError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Unchanged => ErrorCode::NewPasswordSameAsOld,
            Self::OwnerRejected => ErrorCode::NotConfirmedByOwner,
            Self::OwnerAnswerWithoutPhrase
            | Self::MissingSealingInputs
            | Self::ConfirmationWithoutRecovery => ErrorCode::InternalError,
            Self::RehearsalNeedsPassphrase
            | Self::OriginMismatch
            | Self::WalletHasNoPassphrase
            | Self::NoFurtherConfirmation
            | Self::OwnerCannotConfirm
            | Self::OnlyOwnerStatesLength
            | Self::OldSettingsRequired
            | Self::OwnerHasNotConfirmed
            | Self::PassphraseContradiction
            | Self::ReferenceNeedsPassphrase
            | Self::PassphraseStatementRequired
            | Self::UnsupportedConfirmation
            | Self::StepOutOfOrder
            | Self::OwnerLength { .. } => ErrorCode::InvalidRequest,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for RekeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OriginMismatch => f.write_str("invalid request: the recovered state belongs to different source credentials"),
            Self::RehearsalNeedsPassphrase => f.write_str("invalid request: the rehearsal's fingerprint needs the wallet's BIP39 passphrase"),
            Self::WalletHasNoPassphrase => f.write_str("invalid request: the wallet is stated to have no BIP39 passphrase"),
            Self::NoFurtherConfirmation => f.write_str("invalid request: this refusal does not allow another confirmation"),
            Self::OwnerCannotConfirm => f.write_str("invalid request: the owner cannot confirm this phrase: an address or the fingerprint does"),
            Self::OnlyOwnerStatesLength => f.write_str("invalid request: only the owner's confirmation states a length"),
            Self::OldSettingsRequired => f.write_str("invalid request: the recovery must run at the old container's settings"),
            Self::OwnerHasNotConfirmed => f.write_str("invalid request: the owner has not confirmed the recovered phrase yet; seal it only after their explicit yes (ConfirmedPhrase::confirmed_by_owner)"),
            Self::PassphraseContradiction => f.write_str("invalid request: the wallet's BIP39 passphrase is stated otherwise than the reference shows"),
            Self::ReferenceNeedsPassphrase => f.write_str("invalid request: the reference must be compared with the wallet's BIP39 passphrase, which it has"),
            Self::PassphraseStatementRequired => f.write_str("invalid request: say whether the wallet has a BIP39 passphrase"),
            Self::UnsupportedConfirmation => f.write_str("invalid request: a rekey is not confirmed by that reference kind"),
            Self::StepOutOfOrder => f.write_str("invalid request: a rekey step out of its order"),
            Self::OwnerAnswerWithoutPhrase => f.write_str("internal error: an owner's answer without a phrase"),
            Self::MissingSealingInputs => f.write_str("internal error: a confirmed rekey lacks its phrase or new password"),
            Self::ConfirmationWithoutRecovery => f.write_str("internal error: a rekey confirms without its recovery"),
            Self::OwnerLength { offered, selected } => {
                write!(f, "invalid request: the owner confirms a reading of {offered:?} words here")?;
                match selected {
                    Some(words) => write!(f, ", not {words}"),
                    None => f.write_str("; choose one of those lengths"),
                }
            }
            Self::Unchanged => f.write_str("the new password and settings are the same as the old ones, so the container would not change"),
            Self::OwnerRejected => f.write_str("the recovered phrase is not yours: the password, PIM, memory level, word count or container is wrong. Nothing was encrypted again"),
        }
    }
}
impl std::error::Error for RekeyError {}

impl crate::ErrorIdentity for RekeyError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
