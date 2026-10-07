//! Everything that can stop an MHFE operation, with messages written for the person using it.
//!
//! No message ever contains a seed phrase, a password or any part of them.

use std::fmt;

const GIB: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MhfeError {
    /// The original seed phrase is not a valid English BIP39 phrase.
    InvalidPhrase(String),
    /// The container is not a valid English BIP39 phrase of 12, 15, 18, 21 or 24 words.
    InvalidContainer(String),
    /// A phrase length other than 12, 15, 18, 21 or 24 words was selected.
    InvalidWordCount(usize),
    /// A same-length container was asked for a 24-word original, which has none: its container
    /// always has 24 words.
    SameLengthNeedsShortPhrase,
    /// A length was chosen for a same-length container, which keeps the length of its original.
    LengthChoiceNotApplicable {
        container_words: usize,
    },
    /// The built-in check was asked for a same-length container, which has none.
    NoBuiltInCheck {
        container_words: usize,
    },
    /// The wallet check was asked for a same-length container, whose phrase is never one drawn to
    /// pass it ([`crate::ContainerFacts::offers_wallet_check`]).
    NoWalletCheck {
        container_words: usize,
    },
    /// A recovery to re-encrypt has no built-in check, a 24-word original or a same-length
    /// container, and no address or fingerprint was given to confirm it.
    ReferenceRequired,
    /// The phrase recovered to re-encrypt does not match the address or fingerprint given.
    ReferenceMismatch,
    /// The wallet a password opens on a container passes the check of a 12- to 21-word phrase, or
    /// the wallet check of a new phrase, so it cannot serve as a hidden wallet (rule I29).
    HiddenWalletPassesCheck,
    /// Repair words that are not 2, 4, 6 or 8 English BIP39 words.
    InvalidRepairWords(String),
    /// No repair within the bound of the repair words passes the BIP39 checksum: more damage than
    /// they repair, or a card of another plate, as far as the decoder can tell.
    RepairNotPossible {
        repair_words: usize,
    },
    InvalidPim(u32),
    InvalidMemoryLevel(u32),
    EmptyPassword,
    /// The normalized password is longer than 1024 bytes; the value is its length.
    PasswordTooLong(usize),
    InvalidPasswordUtf8,
    /// The password contains a control character (General_Category Cc), U+2028 or U+2029, which
    /// the specification forbids.
    ControlCharacterInPassword,
    /// The password contains a code point that Unicode 17.0.0 does not assign.
    UnassignedCharacter,
    /// A short length was selected, but the check value inside the container does not match.
    VerifierMismatch,
    /// The container would equal the original phrase (see the specification, step 4 of
    /// "Creating a container"). This practically means a broken Argon2 engine.
    FixedPoint,
    /// The new container did not turn back into the original when it was checked (step 6 of
    /// "Creating a container"): a memory error or another fault. Nothing was produced.
    VerificationFailed,
    /// The user stopped the operation.
    Cancelled,
    /// A reference address for the rehearsal check cannot be used.
    InvalidAddress(String),
    InvalidDerivationPath(String),
    InvalidFingerprint(String),
    /// The BIP39 passphrase given as bytes is not UTF-8 text.
    InvalidPassphrase,
    /// The computer reports less free memory than the memory level needs.
    NotEnoughMemory {
        needed_bytes: u64,
        available_bytes: u64,
    },
    /// The operating system refused to reserve the Argon2 memory.
    MemoryAllocation {
        bytes: u64,
    },
    /// The memory level needs more memory than this environment can address, for example a
    /// browser, where WebAssembly is limited to 4 GiB.
    MemoryLevelNotSupportedHere {
        level: u32,
        highest_supported: u32,
    },
    /// Argon2 itself reported an error; the text comes from the reference implementation.
    Argon2(String),
    /// A call that the API does not take, such as an unknown choice or a step out of its order;
    /// the text says which. The browser bindings report it for what a page passed them.
    InvalidRequest(String),
    /// A generated password of this size is not offered: 1 to 32 words or 1 to 64 characters.
    InvalidPasswordSize(String),
    /// Dice digits for a word are not five digits from 1 to 6; the value names the word.
    InvalidDiceRolls(usize),
    /// A password review choice that the review did not offer, such as a repair at a place
    /// without one.
    PasswordRepairNotOffered,
    /// The wallet check of a new phrase needs a BIP39 passphrase: without one, anyone who sees the
    /// phrase can test it.
    WalletCheckNeedsPassphrase,
    /// The random source failed or gave bytes that cannot be random; nothing was drawn.
    RandomFailed(String),
    /// A password typed twice differs from its repetition.
    PasswordsDiffer,
    /// A password already used in this session, compared after Unicode normalization.
    PasswordAlreadyUsed,
    /// A rekey whose owner has not confirmed that the wallets of other passwords are safe: the new
    /// container changes them.
    OtherWalletsNotConfirmed,
    /// A rekey whose new password and settings would give the same container as the old ones.
    NewPasswordSameAsOld,
    /// The recovered phrase was shown to its owner, who said it is not theirs.
    NotConfirmedByOwner,
    /// The coin of an address is not one the check knows.
    InvalidCoin(String),
    /// A part of the program gave another answer than its known answer in a self-check
    /// ([`crate::self_check`]): nothing that part computes can be trusted on this computer. The
    /// component is its label, such as "Repair words (MHFE-REPAIR-1)", and the detail says which
    /// case differs, never with a secret, a vector's text or a coin's name.
    SelfCheckFailed {
        component: String,
        detail: String,
    },
    Internal(String),
}

impl fmt::Display for MhfeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhrase(reason) => {
                write!(
                    f,
                    "the seed phrase is not a valid English BIP39 phrase: {reason}"
                )
            }
            Self::InvalidContainer(reason) => write!(
                f,
                "the container is not a valid English BIP39 phrase: {reason}"
            ),
            Self::InvalidWordCount(words) => write!(
                f,
                "the original phrase length must be 12, 15, 18, 21 or 24 words, not {words}"
            ),
            Self::SameLengthNeedsShortPhrase => write!(
                f,
                "a 24-word phrase has no same-length container: its container always has 24 \
                 words. Encrypt it without choosing the same length"
            ),
            Self::LengthChoiceNotApplicable { container_words } => write!(
                f,
                "a container of {container_words} words keeps the length of its original, so no \
                 length is chosen for it; choosing a length applies only to 24-word containers"
            ),
            Self::NoBuiltInCheck { container_words } => write!(
                f,
                "a container of {container_words} words has no built-in check; compare it with a \
                 receiving address or the master key fingerprint of the wallet instead"
            ),
            Self::NoWalletCheck { container_words } => write!(
                f,
                "a container of {container_words} words holds a phrase of its own length, which \
                 has no wallet check; compare it with a receiving address or the master key \
                 fingerprint of the wallet instead"
            ),
            Self::ReferenceRequired => write!(
                f,
                "a 24-word original or a same-length container has no built-in check, so a \
                 receiving address or the master key fingerprint of the wallet must confirm the \
                 recovery before it is encrypted again"
            ),
            Self::ReferenceMismatch => write!(
                f,
                "the recovered phrase does not match the address or fingerprint: the password, \
                 PIM, memory level, container, word count or BIP39 passphrase is wrong; nothing \
                 was encrypted again"
            ),
            Self::HiddenWalletPassesCheck => write!(
                f,
                "with this password the container gives a phrase that passes a check: the \
                 built-in check of a shorter phrase, as the container's own password of a 12- to \
                 21-word phrase does, or the wallet check of a new phrase, by chance once in 65,536; \
                 recovery would take it for a verified or main wallet, so choose another password"
            ),
            Self::InvalidRepairWords(reason) => {
                write!(f, "the repair words cannot be used: {reason}")
            }
            Self::RepairNotPossible { repair_words } => write!(
                f,
                "the plate cannot be repaired with {repair_words} repair words: more words are \
                 damaged than they can repair (each repairs one unreadable word, two repair one \
                 wrong word), or the card belongs to another plate"
            ),
            Self::InvalidPim(pim) => {
                write!(
                    f,
                    "the PIM must be a whole number from 0 to 1023, not {pim}"
                )
            }
            Self::InvalidMemoryLevel(level) => write!(
                f,
                "the memory level must be a whole number from 0 to 21, not {level}"
            ),
            Self::EmptyPassword => write!(f, "the password is empty"),
            Self::PasswordTooLong(bytes) => write!(
                f,
                "the password is too long: {bytes} bytes after Unicode normalization, \
                 but at most 1024 are allowed"
            ),
            Self::InvalidPasswordUtf8 => write!(f, "the password is not valid UTF-8 text"),
            Self::ControlCharacterInPassword => write!(
                f,
                "the password contains a control character, such as a tab, NUL or line break, \
                 or a line or paragraph separator (U+2028, U+2029); a password may not contain \
                 them, so that every program takes it as typed"
            ),
            Self::UnassignedCharacter => write!(
                f,
                "the password contains a character that Unicode 17.0.0 does not define; \
                 use only defined characters so that every future version reads the \
                 password the same way"
            ),
            Self::VerifierMismatch => write!(
                f,
                "the recovered phrase does not pass its check: the password, PIM, memory \
                 level, container or selected length is wrong"
            ),
            Self::FixedPoint => write!(
                f,
                "the container would be identical to the original phrase, which should \
                 never happen; nothing was produced. Choose a different password, PIM or \
                 memory level, and report this if it happens again"
            ),
            Self::VerificationFailed => write!(
                f,
                "the new container did not turn back into the original phrase when it was \
                 checked, which points to a memory error or another fault; it was discarded. \
                 Run the encryption again, and have the computer's memory tested if it happens \
                 again"
            ),
            Self::Cancelled => write!(f, "the operation was cancelled"),
            Self::InvalidAddress(reason) => {
                write!(f, "the address cannot be used for the check: {reason}")
            }
            Self::InvalidDerivationPath(reason) => write!(f, "invalid derivation path: {reason}"),
            Self::InvalidFingerprint(reason) => {
                write!(f, "invalid master key fingerprint: {reason}")
            }
            Self::InvalidPassphrase => write!(f, "the BIP39 passphrase is not valid UTF-8 text"),
            Self::NotEnoughMemory {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "this memory level needs {} of memory, but only {} is available; close \
                 other programs or choose a lower memory level",
                gib_text(*needed_bytes),
                gib_text(*available_bytes)
            ),
            Self::MemoryAllocation { bytes } => write!(
                f,
                "the computer could not reserve {} of memory for Argon2",
                gib_text(*bytes)
            ),
            Self::MemoryLevelNotSupportedHere {
                level,
                highest_supported,
            } => write!(
                f,
                "memory level {level} needs more memory than this environment can use; the \
                 highest supported level here is {highest_supported}. Use the command-line \
                 tool on a 64-bit system for higher levels"
            ),
            Self::Argon2(message) => write!(f, "Argon2 failed: {message}"),
            Self::InvalidRequest(reason) => write!(f, "invalid request: {reason}"),
            Self::InvalidPasswordSize(reason) => write!(f, "{reason}"),
            Self::InvalidDiceRolls(word) => write!(
                f,
                "the dice digits for word {word} must be exactly five digits, each from 1 to 6"
            ),
            Self::PasswordRepairNotOffered => {
                write!(f, "the review of this password did not offer that choice")
            }
            Self::WalletCheckNeedsPassphrase => write!(
                f,
                "the wallet check needs a BIP39 passphrase; without one it would let anyone \
                 who sees the phrase test it"
            ),
            Self::RandomFailed(reason) => write!(f, "the random generator failed: {reason}"),
            Self::PasswordsDiffer => write!(f, "the password and its repetition differ"),
            Self::PasswordAlreadyUsed => write!(
                f,
                "this password was already used here; a hidden wallet needs a password of its own"
            ),
            Self::OtherWalletsNotConfirmed => write!(
                f,
                "the wallets that other passwords open on this container change with the new \
                 one; move their funds first and confirm that"
            ),
            Self::NewPasswordSameAsOld => write!(
                f,
                "the new password and settings are the same as the old ones, so the container \
                 would not change"
            ),
            Self::NotConfirmedByOwner => write!(
                f,
                "the recovered phrase is not yours: the password, PIM, memory level or container \
                 is wrong. Nothing was changed"
            ),
            Self::InvalidCoin(reason) => write!(f, "unknown coin {reason}"),
            Self::SelfCheckFailed { component, detail } => write!(
                f,
                "the self-test failed: {component}: {detail}. Do not use this program on this \
                 computer"
            ),
            Self::Internal(message) => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for MhfeError {}

impl MhfeError {
    /// Stable machine-readable code for the browser API and for scripts.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPhrase(_) => "INVALID_PHRASE",
            Self::InvalidContainer(_) => "INVALID_CONTAINER",
            Self::InvalidWordCount(_) => "INVALID_WORD_COUNT",
            Self::SameLengthNeedsShortPhrase => "SAME_LENGTH_NEEDS_SHORT_PHRASE",
            Self::LengthChoiceNotApplicable { .. } => "LENGTH_CHOICE_NOT_APPLICABLE",
            Self::NoBuiltInCheck { .. } => "NO_BUILT_IN_CHECK",
            Self::NoWalletCheck { .. } => "NO_WALLET_CHECK",
            Self::ReferenceRequired => "REFERENCE_REQUIRED",
            Self::ReferenceMismatch => "REFERENCE_MISMATCH",
            Self::HiddenWalletPassesCheck => "HIDDEN_WALLET_PASSES_CHECK",
            Self::InvalidRepairWords(_) => "INVALID_REPAIR_WORDS",
            Self::RepairNotPossible { .. } => "REPAIR_NOT_POSSIBLE",
            Self::InvalidPim(_) => "INVALID_PIM",
            Self::InvalidMemoryLevel(_) => "INVALID_MEMORY_LEVEL",
            Self::EmptyPassword => "EMPTY_PASSWORD",
            Self::PasswordTooLong(_) => "PASSWORD_TOO_LONG",
            Self::InvalidPasswordUtf8 => "INVALID_PASSWORD_UTF8",
            Self::ControlCharacterInPassword => "CONTROL_CHARACTER_IN_PASSWORD",
            Self::UnassignedCharacter => "UNASSIGNED_CHARACTER",
            Self::VerifierMismatch => "VERIFIER_MISMATCH",
            Self::FixedPoint => "FIXED_POINT",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::InvalidAddress(_) => "INVALID_ADDRESS",
            Self::InvalidDerivationPath(_) => "INVALID_DERIVATION_PATH",
            Self::InvalidFingerprint(_) => "INVALID_FINGERPRINT",
            Self::InvalidPassphrase => "INVALID_PASSPHRASE",
            Self::NotEnoughMemory { .. } => "NOT_ENOUGH_MEMORY",
            Self::MemoryAllocation { .. } => "MEMORY_ALLOCATION_FAILED",
            Self::MemoryLevelNotSupportedHere { .. } => "MEMORY_LEVEL_NOT_SUPPORTED_HERE",
            Self::Argon2(_) => "ARGON2_FAILED",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::InvalidPasswordSize(_) => "INVALID_PASSWORD_SIZE",
            Self::InvalidDiceRolls(_) => "INVALID_DICE_ROLLS",
            Self::PasswordRepairNotOffered => "PASSWORD_REPAIR_NOT_OFFERED",
            Self::WalletCheckNeedsPassphrase => "WALLET_CHECK_NEEDS_PASSPHRASE",
            Self::RandomFailed(_) => "RANDOM_FAILED",
            Self::PasswordsDiffer => "PASSWORDS_DIFFER",
            Self::PasswordAlreadyUsed => "PASSWORD_ALREADY_USED",
            Self::OtherWalletsNotConfirmed => "OTHER_WALLETS_NOT_CONFIRMED",
            Self::NewPasswordSameAsOld => "NEW_PASSWORD_SAME_AS_OLD",
            Self::NotConfirmedByOwner => "NOT_CONFIRMED_BY_OWNER",
            Self::InvalidCoin(_) => "INVALID_COIN",
            Self::SelfCheckFailed { .. } => "SELF_CHECK_FAILED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

/// Formats a byte count in GiB, with one decimal unless it is whole, using integers only.
fn gib_text(bytes: u64) -> String {
    if bytes.is_multiple_of(GIB) {
        return format!("{} GiB", bytes / GIB);
    }
    let tenths = bytes / (GIB / 10);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_messages_use_readable_gib_values() {
        let error = MhfeError::NotEnoughMemory {
            needed_bytes: 2 * GIB,
            available_bytes: GIB + GIB / 2,
        };
        assert_eq!(
            error.to_string(),
            "this memory level needs 2 GiB of memory, but only 1.5 GiB is available; \
             close other programs or choose a lower memory level"
        );
        assert_eq!(gib_text(3 * GIB), "3 GiB");
        assert_eq!(gib_text(GIB / 10 - 1), "0.0 GiB");
    }

    /// The two codes that only the browser bindings used to write out themselves.
    #[test]
    fn requests_and_passphrases_have_codes_of_their_own() {
        let request = MhfeError::InvalidRequest("unknown reference kind seed".to_owned());
        assert_eq!(request.code(), "INVALID_REQUEST");
        assert_eq!(
            request.to_string(),
            "invalid request: unknown reference kind seed"
        );
        assert_eq!(MhfeError::InvalidPassphrase.code(), "INVALID_PASSPHRASE");
        assert_eq!(
            MhfeError::InvalidPassphrase.to_string(),
            "the BIP39 passphrase is not valid UTF-8 text"
        );
    }
}
