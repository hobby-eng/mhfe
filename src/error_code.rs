//! Stable machine identifiers. Module errors own their reasons and messages; this vocabulary
//! lets bindings name a refusal without manufacturing an error value.

macro_rules! error_codes {
    ($($name:ident => $code:literal;)+) => {
        /// A stable error identifier shared by native and browser callers.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ErrorCode {
            $(#[doc = concat!("The stable `", $code, "` code.")] $name,)+
        }

        impl ErrorCode {
            /// Every stable code in declaration order, without constructing an error.
            pub const ALL: &'static [Self] = &[$(Self::$name,)+];

            /// Reads a stable identifier; an unknown spelling stays unknown.
            pub fn from_name(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|code| code.as_str() == name)
            }

            /// The identifier sent to scripts and browser callers.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$name => $code,)+ }
            }
        }
    };
}

error_codes! {
    InvalidPhrase => "INVALID_PHRASE";
    InvalidContainer => "INVALID_CONTAINER";
    InvalidWordCount => "INVALID_WORD_COUNT";
    SameLengthNeedsShortPhrase => "SAME_LENGTH_NEEDS_SHORT_PHRASE";
    LengthChoiceNotApplicable => "LENGTH_CHOICE_NOT_APPLICABLE";
    NoBuiltInCheck => "NO_BUILT_IN_CHECK";
    NoWalletCheck => "NO_WALLET_CHECK";
    NoHiddenWallets => "NO_HIDDEN_WALLETS";
    ReferenceRequired => "REFERENCE_REQUIRED";
    ReferenceMismatch => "REFERENCE_MISMATCH";
    HiddenWalletPassesCheck => "HIDDEN_WALLET_PASSES_CHECK";
    InvalidRepairWords => "INVALID_REPAIR_WORDS";
    InvalidWordWish => "INVALID_WORD_WISH";
    RepairNotPossible => "REPAIR_NOT_POSSIBLE";
    TooManyMissingWords => "TOO_MANY_MISSING_WORDS";
    SeveralCandidatesMatch => "SEVERAL_CANDIDATES_MATCH";
    InvalidPim => "INVALID_PIM";
    InvalidMemoryLevel => "INVALID_MEMORY_LEVEL";
    EmptyPassword => "EMPTY_PASSWORD";
    PasswordTooLong => "PASSWORD_TOO_LONG";
    InvalidPasswordUtf8 => "INVALID_PASSWORD_UTF8";
    ControlCharacterInPassword => "CONTROL_CHARACTER_IN_PASSWORD";
    UnassignedCharacter => "UNASSIGNED_CHARACTER";
    VerifierMismatch => "VERIFIER_MISMATCH";
    AmbiguousLength => "AMBIGUOUS_LENGTH";
    LengthDiffers => "LENGTH_DIFFERS";
    FixedPoint => "FIXED_POINT";
    VerificationFailed => "VERIFICATION_FAILED";
    Cancelled => "CANCELLED";
    InvalidAddress => "INVALID_ADDRESS";
    InvalidDerivationPath => "INVALID_DERIVATION_PATH";
    InvalidFingerprint => "INVALID_FINGERPRINT";
    InvalidPassphrase => "INVALID_PASSPHRASE";
    PassphraseTooLong => "PASSPHRASE_TOO_LONG";
    NotEnoughMemory => "NOT_ENOUGH_MEMORY";
    MemoryAllocationFailed => "MEMORY_ALLOCATION_FAILED";
    MemoryProtectionFailed => "MEMORY_PROTECTION_FAILED";
    MemoryLevelNotSupportedHere => "MEMORY_LEVEL_NOT_SUPPORTED_HERE";
    Argon2Failed => "ARGON2_FAILED";
    InvalidRequest => "INVALID_REQUEST";
    InvalidPasswordSize => "INVALID_PASSWORD_SIZE";
    InvalidDiceRolls => "INVALID_DICE_ROLLS";
    PasswordRepairNotOffered => "PASSWORD_REPAIR_NOT_OFFERED";
    WalletCheckNeedsPassphrase => "WALLET_CHECK_NEEDS_PASSPHRASE";
    RandomFailed => "RANDOM_FAILED";
    PasswordsDiffer => "PASSWORDS_DIFFER";
    PassphrasesDiffer => "PASSPHRASES_DIFFER";
    PasswordAlreadyUsed => "PASSWORD_ALREADY_USED";
    NewPasswordSameAsOld => "NEW_PASSWORD_SAME_AS_OLD";
    NotConfirmedByOwner => "NOT_CONFIRMED_BY_OWNER";
    InvalidCoin => "INVALID_COIN";
    SelfCheckFailed => "SELF_CHECK_FAILED";
    InternalError => "INTERNAL_ERROR";
}

/// The narrow boundary needed by diagnostic comparisons: no crate-wide error dependency,
/// underlying message, or secret-bearing value needs to be retained by the checker.
pub trait ErrorIdentity {
    /// The stable typed identifier.
    fn error_code(&self) -> ErrorCode;
    /// The machine-readable spelling of the identifier.
    fn code(&self) -> &'static str {
        self.error_code().as_str()
    }
}
impl ErrorIdentity for ErrorCode {
    fn error_code(&self) -> ErrorCode {
        *self
    }
}
impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
