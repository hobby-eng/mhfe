//! Everything that can stop an MHFE operation, with messages written for the person using it.
//!
//! No message ever contains a seed phrase, a password or any part of them.

use std::fmt;

use crate::suite::Settings;

/// Why an MHFE operation stopped. Each variant has a stable code ([`MhfeError::code`]) and one
/// message, written by its `Display`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MhfeError {
    /// The original seed phrase is not a valid English BIP39 phrase.
    InvalidPhrase(String),
    /// The container is not a valid English BIP39 phrase of 12, 15, 18, 21 or 24 words.
    InvalidContainer(String),
    /// A phrase length other than 12, 15, 18, 21 or 24 words was selected.
    InvalidWordCount(usize),
    /// A built-in check asked for at a length that has none: only a 12- to 21-word original of a
    /// 24-word container carries one.
    NoBuiltInCheckAtLength(usize),
    /// The wallet check asked for of a phrase that is not 24 words long: only a new 24-word phrase
    /// is drawn with it.
    NoWalletCheckAtLength(usize),
    /// A same-length container was asked for a 24-word original, which has none: its container
    /// always has 24 words.
    SameLengthNeedsShortPhrase,
    /// A length was chosen for a same-length container, which keeps the length of its original.
    LengthChoiceNotApplicable {
        /// The number of words of the container.
        container_words: usize,
    },
    /// The built-in check was asked for a same-length container, which has none.
    NoBuiltInCheck {
        /// The number of words of the container.
        container_words: usize,
    },
    /// The wallet check was asked for a same-length container, whose phrase is never one drawn to
    /// pass it ([`crate::ContainerFacts::offers_wallet_check`]).
    NoWalletCheck {
        /// The number of words of the container.
        container_words: usize,
    },
    /// Hidden wallets were asked of a same-length container, which opens none
    /// ([`crate::ContainerFacts::opens_hidden_wallets`]).
    NoHiddenWallets {
        /// The number of words of the container.
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
    /// Words wished for in a new phrase that cannot be used; the reason never names a word.
    InvalidWordWish(String),
    /// No repair within the bound of the repair words passes the BIP39 checksum: more damage than
    /// they repair, or a card of another container phrase, as far as the decoder can tell.
    RepairNotPossible {
        /// The number of repair words given.
        repair_words: usize,
    },
    /// More words are missing from a container phrase than a search without its repair words
    /// looks for: each further word multiplies the candidates by about the size of the word list.
    TooManyMissingWords {
        /// The number of missing words.
        missing: usize,
        /// The most missing words the search looks for.
        limit: usize,
    },
    /// More than one candidate container of a search for missing words matches its reference,
    /// which therefore cannot tell them apart: none is taken (AUD-024-FUN001).
    SeveralCandidatesMatch {
        /// The number of candidates that match.
        matches: usize,
    },
    /// A PIM above [`crate::MAX_PIM`], of the settings that the message names.
    InvalidPim {
        /// The PIM given.
        pim: u32,
        /// Whose PIM it is: the container's, or the new one of a rekey.
        settings: Settings,
    },
    /// A memory level above [`crate::MAX_MEMORY_LEVEL`], of the settings that the message names.
    InvalidMemoryLevel {
        /// The memory level given.
        level: u32,
        /// Whose memory level it is: the container's, or the new one of a rekey.
        settings: Settings,
    },
    /// The password is empty.
    EmptyPassword,
    /// The normalized password is longer than [`crate::MAX_PASSWORD_BYTES`]; the value is its
    /// length in bytes.
    PasswordTooLong(usize),
    /// The password given as bytes is not UTF-8 text.
    InvalidPasswordUtf8,
    /// The password contains a control character (General_Category Cc), U+2028 or U+2029, which
    /// the specification forbids.
    ControlCharacterInPassword,
    /// The password contains a code point that Unicode 17.0.0 does not assign.
    UnassignedCharacter,
    /// No built-in check passes where a short length was stated or needed: a wrong password,
    /// setting or container, or a 24-word original.
    VerifierMismatch,
    /// Detection found several short lengths whose built-in check passes, by accident about once
    /// in four billion containers, where one phrase is needed: the length must be stated, one of
    /// `readings`, the lengths it can be read as in ascending order, 24 words last.
    AmbiguousLength {
        /// The lengths in words the container can be read as, ascending, 24 last.
        readings: Vec<usize>,
    },
    /// A phrase to be encrypted again whose built-in check finds another length, `found`, than the
    /// one stated, `stated`: the check takes precedence, but a receiving address or the master key
    /// fingerprint of the wallet must confirm the phrase before a rekey seals it, since a stated
    /// length is usually right (the specification's re-encryption rules). Where 24 words were
    /// stated, only they tell the readings apart.
    LengthDiffers {
        /// The length in words that was stated.
        stated: usize,
        /// The length in words whose built-in check passes.
        found: usize,
    },
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
    /// A derivation path for the rehearsal check cannot be used; the text says why.
    InvalidDerivationPath(String),
    /// A master key fingerprint for the rehearsal check cannot be used; the text says why.
    InvalidFingerprint(String),
    /// The BIP39 passphrase given as bytes is not UTF-8 text.
    InvalidPassphrase,
    /// The BIP39 passphrase is longer than [`crate::wallet::MAX_PASSPHRASE_BYTES`]; the value is
    /// its length in bytes (AUD-024-API019).
    PassphraseTooLong(usize),
    /// The computer reports less free memory than the memory level needs.
    NotEnoughMemory {
        /// The memory the level needs, in bytes.
        needed_bytes: u64,
        /// The free memory the computer reports, in bytes.
        available_bytes: u64,
    },
    /// The operating system refused to reserve the Argon2 memory.
    MemoryAllocation {
        /// The memory asked for, in bytes.
        bytes: u64,
    },
    /// The memory level needs more memory than this environment can address, for example a
    /// browser, where WebAssembly is limited to 4 GiB.
    MemoryLevelNotSupportedHere {
        /// The memory level asked for.
        level: u32,
        /// The highest memory level this environment can use.
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
    /// A new wallet's BIP39 passphrase typed twice differs from its repetition.
    PassphrasesDiffer,
    /// A password already used in this session, compared after Unicode normalization.
    PasswordAlreadyUsed,
    /// A rekey whose new password and settings would give the same container as the old ones.
    NewPasswordSameAsOld,
    /// The recovered phrase was shown to its owner, who said it is not theirs.
    NotConfirmedByOwner,
    /// The coin of an address is not one the check knows.
    InvalidCoin,
    /// A part of the program gave another answer than its known answer in a self-check
    /// ([`crate::self_check`]): nothing that part computes can be trusted on this computer. The
    /// component is its label, such as "Repair words (MHFE-REPAIR-1)", and the detail says which
    /// case differs, never with a secret, a vector's text or a coin's name.
    SelfCheckFailed {
        /// The label of the part that failed.
        component: String,
        /// Which case gave another answer.
        detail: String,
    },
    /// A fault of the program itself, such as an invariant that did not hold; the text says which.
    Internal(String),
}

/// A name the program itself knows, quoted for a message: in double quotes, with every control
/// character escaped, such as `\u{1b}`, so that a terminal shows it instead of carrying it out
/// (AUD-015-SEC002). Text a person typed is never repeated in a message: a seed phrase pasted into
/// the wrong field, such as the fingerprint, would be shown and kept in a log (AUD-016-SEC001).
pub(crate) fn quoted(text: &str) -> String {
    format!("{text:?}")
}

impl fmt::Display for MhfeError {
    #[expect(
        clippy::too_many_lines,
        reason = "one match over every variant: the one place the messages are written (CORE-23)"
    )]
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
                "the original seed phrase must have {} words, not {words}",
                crate::phrase::word_counts_text()
            ),
            Self::SameLengthNeedsShortPhrase => write!(
                f,
                "a 24-word phrase has no same-length container: its container always has 24 \
                 words. Encrypt it without choosing the same length"
            ),
            Self::LengthChoiceNotApplicable { container_words } => write!(
                f,
                "a container of {container_words} words keeps the length of its original seed \
                 phrase, so no length is chosen for it; choosing a length applies only to 24-word \
                 containers"
            ),
            Self::NoBuiltInCheckAtLength(words) => write!(
                f,
                "a {words}-word original seed phrase has no built-in check (only {} words have \
                 one); compare it with a receiving address or the master key fingerprint of the \
                 wallet instead",
                crate::phrase::counts_text(&crate::BUILT_IN_CHECK_WORD_COUNTS)
            ),
            Self::NoWalletCheckAtLength(words) => write!(
                f,
                "a {words}-word phrase has no wallet check: only a 24-word phrase is drawn with one"
            ),
            Self::NoBuiltInCheck { container_words } => write!(
                f,
                "a container of {container_words} words has no built-in check; compare it with a \
                 receiving address or the master key fingerprint of the wallet instead"
            ),
            Self::NoHiddenWallets { container_words } => write!(
                f,
                "a container of {container_words} words opens no hidden wallets: they are opened \
                 on a 24-word container only, for now"
            ),
            Self::NoWalletCheck { container_words } => write!(
                f,
                "a container of {container_words} words holds a phrase of its own length, which \
                 has no wallet check; compare it with a receiving address or the master key \
                 fingerprint of the wallet instead"
            ),
            Self::ReferenceRequired => write!(
                f,
                "the built-in check alone does not confirm this recovery: a 24-word original seed \
                 phrase, a same-length container and a detected length need a receiving address \
                 or the master key fingerprint of the wallet, or the owner's comparison with the \
                 backup, before the phrase is encrypted again"
            ),
            Self::ReferenceMismatch => write!(
                f,
                "the recovered phrase does not match the address or fingerprint: the password, \
                 PIM, memory level, container, word count or BIP39 passphrase is wrong; nothing \
                 was encrypted again"
            ),
            Self::HiddenWalletPassesCheck => write!(
                f,
                "with this password the container gives a phrase that passes a check: the built-in \
                 check of a shorter phrase, as the container's own password of a 12- to 21-word \
                 phrase does, or the wallet check of a new phrase, by chance once in {}; \
                 recovery would take it for a verified or main wallet, so choose another password",
                crate::phrase::grouped(crate::wallet_check::WALLET_CHECK_ODDS)
            ),
            Self::InvalidWordWish(reason) => {
                write!(f, "the wishes for the new phrase cannot be used: {reason}")
            }
            Self::InvalidRepairWords(reason) => {
                write!(f, "the repair words cannot be used: {reason}")
            }
            Self::RepairNotPossible { repair_words } => write!(
                f,
                "the container phrase cannot be repaired with {repair_words} repair words: more \
                 words are damaged than they can repair (each repairs one unreadable word, two \
                 repair one wrong word), or the card belongs to another container phrase"
            ),
            Self::TooManyMissingWords { missing, limit } => write!(
                f,
                "{missing} words of the container phrase are missing, but this search finds at \
                 most {limit}: each further word multiplies the candidates by about {}; only \
                 the repair words repair more",
                crate::phrase::grouped(crate::phrase::LIST_SIZE)
            ),
            Self::SeveralCandidatesMatch { matches } => write!(
                f,
                "{matches} candidate container phrases match the reference, which cannot tell \
                 them apart, so none is taken: search again with a receiving address of the same \
                 wallet, which tells them apart"
            ),
            Self::InvalidPim { pim, settings } => write!(
                f,
                "{settings} PIM must be a whole number from 0 to {}, not {pim}",
                crate::MAX_PIM
            ),
            Self::InvalidMemoryLevel { level, settings } => write!(
                f,
                "{settings} memory level must be a whole number from 0 to {}, not {level}",
                crate::MAX_MEMORY_LEVEL
            ),
            Self::EmptyPassword => write!(f, "the password is empty"),
            Self::PasswordTooLong(bytes) => write!(
                f,
                "the password is too long: {bytes} bytes after Unicode normalization, \
                 but at most {} are allowed",
                crate::MAX_PASSWORD_BYTES
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
                "the recovered phrase passes no built-in check: the password, PIM, memory level \
                 or container is probably wrong, or the original seed phrase has 24 words"
            ),
            Self::AmbiguousLength { readings } => {
                // The 24-word reading, last, has no check to pass.
                let passing = &readings[..readings.len().saturating_sub(1)];
                write!(
                    f,
                    "the built-in check passes for {} words by accident: a receiving address or \
                     the master key fingerprint of the wallet tells the readings apart",
                    passing
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" and ")
                )
            }
            Self::LengthDiffers { stated, found } => write!(
                f,
                "the built-in check finds a {found}-word original seed phrase, not the {stated} \
                 words stated: confirm it with a receiving address or the master key fingerprint \
                 of the wallet"
            ),
            Self::FixedPoint => write!(
                f,
                "the container would be identical to the original seed phrase, which should \
                 never happen; nothing was produced. Choose a different password, PIM or \
                 memory level, and report this if it happens again"
            ),
            Self::VerificationFailed => write!(
                f,
                "the new container did not turn back into the original seed phrase when it was \
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
            Self::PassphraseTooLong(bytes) => write!(
                f,
                "the BIP39 passphrase is too long: {bytes} bytes, but at most {} are allowed",
                crate::wallet::MAX_PASSPHRASE_BYTES
            ),
            Self::NotEnoughMemory {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "this memory level needs {} of memory, but only {} is available; close \
                 other programs or choose a lower memory level",
                crate::suite::memory_text(*needed_bytes),
                crate::suite::memory_text(*available_bytes)
            ),
            Self::MemoryAllocation { bytes } => write!(
                f,
                "the computer could not reserve {} of memory for Argon2",
                crate::suite::memory_text(*bytes)
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
            Self::PassphrasesDiffer => write!(f, "the passphrase and its repetition differ"),
            Self::PasswordAlreadyUsed => write!(
                f,
                "this password was already used here; a hidden wallet needs a password of its own"
            ),
            Self::NewPasswordSameAsOld => write!(
                f,
                "the new password and settings are the same as the old ones, so the container \
                 would not change"
            ),
            Self::NotConfirmedByOwner => write!(
                f,
                "the recovered phrase is not yours: the password, PIM, memory level, word count or \
                 container is wrong. Nothing was encrypted again"
            ),
            Self::InvalidCoin => {
                let known: Vec<_> = crate::wallet::Coin::ALL
                    .iter()
                    .map(|coin| coin.id())
                    .collect();
                write!(f, "unknown coin; the coins are {}", known.join(", "))
            }
            Self::SelfCheckFailed { component, detail } => f.write_str(
                &crate::self_check::failure_message("the self-test failed", component, detail),
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
            Self::InvalidWordCount(_)
            | Self::NoBuiltInCheckAtLength(_)
            | Self::NoWalletCheckAtLength(_) => "INVALID_WORD_COUNT",
            Self::SameLengthNeedsShortPhrase => "SAME_LENGTH_NEEDS_SHORT_PHRASE",
            Self::LengthChoiceNotApplicable { .. } => "LENGTH_CHOICE_NOT_APPLICABLE",
            Self::NoBuiltInCheck { .. } => "NO_BUILT_IN_CHECK",
            Self::NoWalletCheck { .. } => "NO_WALLET_CHECK",
            Self::NoHiddenWallets { .. } => "NO_HIDDEN_WALLETS",
            Self::ReferenceRequired => "REFERENCE_REQUIRED",
            Self::ReferenceMismatch => "REFERENCE_MISMATCH",
            Self::HiddenWalletPassesCheck => "HIDDEN_WALLET_PASSES_CHECK",
            Self::InvalidRepairWords(_) => "INVALID_REPAIR_WORDS",
            Self::InvalidWordWish(_) => "INVALID_WORD_WISH",
            Self::RepairNotPossible { .. } => "REPAIR_NOT_POSSIBLE",
            Self::TooManyMissingWords { .. } => "TOO_MANY_MISSING_WORDS",
            Self::SeveralCandidatesMatch { .. } => "SEVERAL_CANDIDATES_MATCH",
            Self::InvalidPim { .. } => "INVALID_PIM",
            Self::InvalidMemoryLevel { .. } => "INVALID_MEMORY_LEVEL",
            Self::EmptyPassword => "EMPTY_PASSWORD",
            Self::PasswordTooLong(_) => "PASSWORD_TOO_LONG",
            Self::InvalidPasswordUtf8 => "INVALID_PASSWORD_UTF8",
            Self::ControlCharacterInPassword => "CONTROL_CHARACTER_IN_PASSWORD",
            Self::UnassignedCharacter => "UNASSIGNED_CHARACTER",
            Self::VerifierMismatch => "VERIFIER_MISMATCH",
            Self::AmbiguousLength { .. } => "AMBIGUOUS_LENGTH",
            Self::LengthDiffers { .. } => "LENGTH_DIFFERS",
            Self::FixedPoint => "FIXED_POINT",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::InvalidAddress(_) => "INVALID_ADDRESS",
            Self::InvalidDerivationPath(_) => "INVALID_DERIVATION_PATH",
            Self::InvalidFingerprint(_) => "INVALID_FINGERPRINT",
            Self::InvalidPassphrase => "INVALID_PASSPHRASE",
            Self::PassphraseTooLong(_) => "PASSPHRASE_TOO_LONG",
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
            Self::PassphrasesDiffer => "PASSPHRASES_DIFFER",
            Self::PasswordAlreadyUsed => "PASSWORD_ALREADY_USED",
            Self::NewPasswordSameAsOld => "NEW_PASSWORD_SAME_AS_OLD",
            Self::NotConfirmedByOwner => "NOT_CONFIRMED_BY_OWNER",
            Self::InvalidCoin => "INVALID_COIN",
            Self::SelfCheckFailed { .. } => "SELF_CHECK_FAILED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    /// A quoted name carries no control character a terminal would carry out (AUD-015-SEC002):
    /// C0, DEL and C1 are escaped, printable text stays as it is.
    #[test]
    fn quoted_text_holds_no_control_character() {
        let typed = "ab\u{1b}]0;TITLE\u{7}\u{1b}[2J\u{7f}\u{9b}cd é";
        let shown = quoted(typed);
        assert!(!shown.chars().any(char::is_control), "{shown}");
        assert_eq!(shown, r#""ab\u{1b}]0;TITLE\u{7}\u{1b}[2J\u{7f}\u{9b}cd é""#);
    }

    /// A refusal of a public field never repeats what was typed: a seed phrase pasted there by
    /// mistake stays out of the message (AUD-016-SEC001), and so does a control sequence.
    #[test]
    fn a_refused_public_field_does_not_repeat_the_text() {
        const PASTED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon about";
        for typed in [PASTED, "ab\u{1b}]0;TITLE\u{7}cd"] {
            for refusal in [
                crate::wallet::parse_fingerprint(typed).unwrap_err(),
                typed.parse::<crate::wallet::Coin>().unwrap_err(),
                typed.parse::<crate::wallet::DerivationPath>().unwrap_err(),
            ] {
                let message = refusal.to_string();
                assert!(!message.contains("abandon"), "{message}");
                assert!(!message.chars().any(char::is_control), "{message}");
            }
        }
    }

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
    }

    #[test]
    fn an_unknown_coin_is_one_sentence_without_the_typed_value() {
        assert_eq!(MhfeError::InvalidCoin.code(), "INVALID_COIN");
        assert_eq!(
            MhfeError::InvalidCoin.to_string(),
            "unknown coin; the coins are bitcoin, bitcoin-cash, cosmos, dash, dogecoin, ethereum, \
             ethereum-classic, injective, litecoin, tron, xrp, zcash"
        );
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
