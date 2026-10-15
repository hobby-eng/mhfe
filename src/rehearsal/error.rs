//! Reference-comparison and follow-up refusals, independent of the cryptographic engine.
use super::PassphraseReferences;
use crate::ErrorCode;
use std::fmt;

/// A comparison or its confirmation cannot use the supplied reference or metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RehearsalError {
    /// The caller supplied a passphrase to a reference that does not use one.
    UnusedPassphrase(PassphraseReferences),
    /// Length detection did not request the attempted follow-up.
    DetectionNotRequested,
    /// The follow-up reference cannot disambiguate that detection result.
    DetectionReference,
    /// The script supplied address metadata beside a non-address reference.
    AddressMetadata,
    /// The recovery needs a wallet reference or the owner's confirmation before re-encryption.
    ReferenceRequired,
    /// The supplied wallet reference does not match the recovery.
    ReferenceMismatch,
}
impl RehearsalError {
    /// The stable typed refusal code.
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::ReferenceRequired => ErrorCode::ReferenceRequired,
            Self::ReferenceMismatch => ErrorCode::ReferenceMismatch,
            Self::UnusedPassphrase(_)
            | Self::DetectionNotRequested
            | Self::DetectionReference
            | Self::AddressMetadata => ErrorCode::InvalidRequest,
        }
    }
    /// The machine-readable identifier.
    pub const fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl fmt::Display for RehearsalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedPassphrase(references) => write!(f, "invalid request: a BIP39 passphrase belongs only to {}", references.names()),
            Self::DetectionNotRequested => f.write_str("invalid request: detection did not ask for another length or a wallet reference"),
            Self::DetectionReference => f.write_str("invalid request: a follow-up after detection needs a stated short length, an address or a fingerprint"),
            Self::AddressMetadata => f.write_str("invalid request: --coin and --path belong to an address reference"),
            Self::ReferenceRequired => f.write_str("the built-in check alone does not confirm this recovery: a 24-word original seed phrase, a same-length container and a detected length need a receiving address or the master key fingerprint of the wallet, or the owner's comparison with the backup, before the phrase is encrypted again"),
            Self::ReferenceMismatch => f.write_str("the recovered phrase does not match the address or fingerprint: the password, PIM, memory level, container, word count or BIP39 passphrase is wrong; nothing was encrypted again"),
        }
    }
}
impl std::error::Error for RehearsalError {}

impl crate::ErrorIdentity for RehearsalError {
    fn error_code(&self) -> crate::ErrorCode {
        self.error_code()
    }
}
