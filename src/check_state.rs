//! Shared recovery-check states, independent of the wallet, cipher and self-check runner.

/// Whether a recovery's supplied reference confirms it, leaves it unverified, or contradicts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckState {
    /// One reading is verified by the reference.
    Matches,
    /// The available evidence does not verify one reading.
    NotVerified,
    /// The reference contradicts the recovery.
    DoesNotMatch,
}

impl CheckState {
    /// The stable browser result identifier.
    pub fn id(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::NotVerified => "notVerified",
            Self::DoesNotMatch => "doesNotMatch",
        }
    }

    /// The result in the specification's words, which scripts read.
    pub fn text(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::NotVerified => "not verified",
            Self::DoesNotMatch => "does not match",
        }
    }
}

/// One of the original seed phrase's own checks that a recovery passed, as a front end lists it
/// beside the result ([`crate::CheckEvidence::own_checks_passed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PassedCheck {
    /// The built-in check of the one verified reading, of this many words.
    BuiltInCheck(usize),
    /// The built-in checks of several lengths, of which at most one is the phrase's.
    BuiltInChecks(Vec<usize>),
    /// The 16-bit phrase + passphrase check of the 24-word reading.
    WalletCheck,
}
