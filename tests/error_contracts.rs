//! Stable error identity across independent owners and the application boundary. These controls
//! construct refusals only; they run no KDF and use no private wallet data.
use mhfe::engine::{Argon2Failure, EngineError};
use mhfe::new_password::{NewPasswordError, PasswordKind};
use mhfe::random::RandomError;
use mhfe::repair::RepairError;
use mhfe::search::SearchError;
use mhfe::self_check::{FailureDetail, KnownAnswerDifference, SelfCheckError};
use mhfe::wallet::{AddressIssue, PathIssue, WalletError};
use mhfe::wallet_check::WalletCheckError;
use mhfe::word_wishes::{WishError, WishWord};
use mhfe::{
    CipherError, ErrorCode, HiddenError, MhfeError, PasswordError, PhraseError, PhraseIssue,
    RehearsalError, Settings, SettingsError,
};
use std::collections::BTreeSet;
use std::error::Error;

macro_rules! case {
    ($error:expr, $code:literal) => {
        (MhfeError::from($error), $code)
    };
}

/// One independently named representative of each pre-migration public code.
fn cipher_and_password_refusals() -> Vec<(MhfeError, &'static str)> {
    vec![
        case!(
            PhraseError::Original(PhraseIssue::UnknownWord(2)),
            "INVALID_PHRASE"
        ),
        case!(
            PhraseError::Container(PhraseIssue::Checksum),
            "INVALID_CONTAINER"
        ),
        case!(
            mhfe::FormatError::InvalidWordCount(13),
            "INVALID_WORD_COUNT"
        ),
        case!(
            mhfe::FormatError::SameLengthNeedsShortPhrase,
            "SAME_LENGTH_NEEDS_SHORT_PHRASE"
        ),
        case!(
            mhfe::FormatError::LengthChoiceNotApplicable {
                container_words: 15
            },
            "LENGTH_CHOICE_NOT_APPLICABLE"
        ),
        case!(
            mhfe::FormatError::NoBuiltInCheck {
                container_words: 15
            },
            "NO_BUILT_IN_CHECK"
        ),
        case!(
            mhfe::FormatError::NoWalletCheck {
                container_words: 15
            },
            "NO_WALLET_CHECK"
        ),
        case!(
            mhfe::FormatError::NoHiddenWallets {
                container_words: 15
            },
            "NO_HIDDEN_WALLETS"
        ),
        case!(RehearsalError::ReferenceRequired, "REFERENCE_REQUIRED"),
        case!(RehearsalError::ReferenceMismatch, "REFERENCE_MISMATCH"),
        case!(HiddenError::PassesCheck, "HIDDEN_WALLET_PASSES_CHECK"),
        case!(
            RepairError::WordCount {
                count: 3,
                unreadable_hint: true
            },
            "INVALID_REPAIR_WORDS"
        ),
        case!(
            WishError::UnknownWord(WishWord::Chosen(1)),
            "INVALID_WORD_WISH"
        ),
        case!(
            RepairError::NotPossible { repair_words: 4 },
            "REPAIR_NOT_POSSIBLE"
        ),
        case!(
            SearchError::TooManyMissing {
                missing: 3,
                limit: 2
            },
            "TOO_MANY_MISSING_WORDS"
        ),
        case!(
            SearchError::SeveralMatches { matches: 2 },
            "SEVERAL_CANDIDATES_MATCH"
        ),
        case!(
            SettingsError::InvalidPim {
                pim: 1024,
                settings: Settings::Current
            },
            "INVALID_PIM"
        ),
        case!(
            SettingsError::InvalidMemoryLevel {
                level: 22,
                settings: Settings::Current
            },
            "INVALID_MEMORY_LEVEL"
        ),
        case!(PasswordError::EmptyPassword, "EMPTY_PASSWORD"),
        case!(PasswordError::PasswordTooLong(1025), "PASSWORD_TOO_LONG"),
        case!(PasswordError::InvalidPasswordUtf8, "INVALID_PASSWORD_UTF8"),
        case!(
            PasswordError::ControlCharacterInPassword,
            "CONTROL_CHARACTER_IN_PASSWORD"
        ),
        case!(PasswordError::UnassignedCharacter, "UNASSIGNED_CHARACTER"),
        case!(mhfe::FormatError::VerifierMismatch, "VERIFIER_MISMATCH"),
        case!(
            CipherError::AmbiguousLength {
                readings: vec![12, 21, 24]
            },
            "AMBIGUOUS_LENGTH"
        ),
        case!(
            CipherError::LengthDiffers {
                stated: 15,
                found: 12
            },
            "LENGTH_DIFFERS"
        ),
        case!(CipherError::FixedPoint, "FIXED_POINT"),
        case!(CipherError::VerificationFailed, "VERIFICATION_FAILED"),
    ]
}

/// Process, wallet and orchestration refusals, independent of cipher message construction.
fn application_refusals() -> Vec<(MhfeError, &'static str)> {
    vec![
        case!(mhfe::CancelledError, "CANCELLED"),
        case!(
            WalletError::Address {
                issue: AddressIssue::Malformed,
                assumed_coin: None
            },
            "INVALID_ADDRESS"
        ),
        case!(
            WalletError::Path(PathIssue::Malformed),
            "INVALID_DERIVATION_PATH"
        ),
        case!(WalletError::Fingerprint, "INVALID_FINGERPRINT"),
        case!(WalletError::InvalidPassphrase, "INVALID_PASSPHRASE"),
        case!(WalletError::PassphraseTooLong(1025), "PASSPHRASE_TOO_LONG"),
        case!(
            EngineError::NotEnoughMemory {
                needed_bytes: 2 << 30,
                available_bytes: 1 << 30
            },
            "NOT_ENOUGH_MEMORY"
        ),
        case!(
            EngineError::MemoryAllocation { bytes: 2 << 30 },
            "MEMORY_ALLOCATION_FAILED"
        ),
        case!(
            SettingsError::MemoryLevelNotSupportedHere {
                level: 1,
                highest_supported: 0
            },
            "MEMORY_LEVEL_NOT_SUPPORTED_HERE"
        ),
        case!(
            EngineError::Argon2(Argon2Failure::UnwrittenKey),
            "ARGON2_FAILED"
        ),
        case!(
            mhfe::request::RequestError::UnknownReferenceKind,
            "INVALID_REQUEST"
        ),
        case!(
            NewPasswordError::Size {
                kind: PasswordKind::Words,
                count: 0
            },
            "INVALID_PASSWORD_SIZE"
        ),
        case!(
            mhfe::eff::EffError::InvalidDiceRolls(2),
            "INVALID_DICE_ROLLS"
        ),
        case!(
            mhfe::check_word::ReviewError::NotOffered,
            "PASSWORD_REPAIR_NOT_OFFERED"
        ),
        case!(
            WalletCheckError::NeedsPassphrase,
            "WALLET_CHECK_NEEDS_PASSPHRASE"
        ),
        case!(RandomError::Page, "RANDOM_FAILED"),
        case!(PasswordError::PasswordsDiffer, "PASSWORDS_DIFFER"),
        case!(WalletCheckError::PassphrasesDiffer, "PASSPHRASES_DIFFER"),
        case!(HiddenError::PasswordAlreadyUsed, "PASSWORD_ALREADY_USED"),
        case!(
            mhfe::rekey::RekeyError::Unchanged,
            "NEW_PASSWORD_SAME_AS_OLD"
        ),
        case!(
            mhfe::rekey::RekeyError::OwnerRejected,
            "NOT_CONFIRMED_BY_OWNER"
        ),
        case!(WalletError::InvalidCoin, "INVALID_COIN"),
        case!(
            SelfCheckError::Failed {
                component: "Public control",
                detail: KnownAnswerDifference::GivesAnotherContainer.into()
            },
            "SELF_CHECK_FAILED"
        ),
        case!(mhfe::output::OutputError::Json, "INTERNAL_ERROR"),
    ]
}

fn refusals() -> Vec<(MhfeError, &'static str)> {
    let mut cases = cipher_and_password_refusals();
    cases.extend(application_refusals());
    cases
}

#[test]
fn every_stable_code_survives_conversion_and_has_an_owned_source() {
    let mut seen = BTreeSet::new();
    for (error, expected) in refusals() {
        assert_eq!(error.code(), expected);
        assert_eq!(error.error_code().as_str(), expected);
        assert_eq!(ErrorCode::from_name(expected), Some(error.error_code()));
        assert!(seen.insert(expected), "duplicate coverage of {expected}");
        let message = error.to_string();
        assert!(!message.is_empty(), "{expected}");
        assert!(
            !message.chars().any(char::is_control),
            "{expected}: {message}"
        );
        assert!(
            !message.starts_with(expected),
            "the binding alone prefixes a code"
        );
        assert_eq!(error.source().unwrap().to_string(), message, "{expected}");
    }
    assert_eq!(seen.len(), 52);
    assert_eq!(
        seen,
        ErrorCode::ALL.iter().map(|code| code.as_str()).collect()
    );
    for unknown in [
        "",
        "INVALID_PASSWORD",
        "invalid_phrase",
        "synthetic-secret-marker",
    ] {
        assert_eq!(ErrorCode::from_name(unknown), None);
    }
}

#[test]
fn cancellation_is_preserved_through_each_composed_owner() {
    let errors: [MhfeError; 8] = [
        RandomError::Cancelled.into(),
        WalletError::Cancelled.into(),
        WalletCheckError::Cancelled.into(),
        NewPasswordError::Cancelled.into(),
        CipherError::Cancelled.into(),
        HiddenError::Cipher(CipherError::Cancelled).into(),
        mhfe::self_test::SelfTestError::Cancelled.into(),
        mhfe::CancelledError.into(),
    ];
    for error in errors {
        assert_eq!(error, MhfeError::Cancelled);
        assert_eq!(error.code(), "CANCELLED");
        assert_eq!(error.to_string(), "the operation was cancelled");
    }
}

#[test]
fn lower_level_causes_have_one_aggregate_classification() {
    let format = mhfe::FormatError::VerifierMismatch;
    assert_eq!(
        MhfeError::from(format.clone()),
        MhfeError::from(CipherError::from(format))
    );
    for passphrase in [
        mhfe::PassphraseError::InvalidUtf8,
        mhfe::PassphraseError::TooLong(1025),
    ] {
        let shared = MhfeError::from(passphrase);
        assert_eq!(shared, MhfeError::from(WalletError::from(passphrase)));
        let checked = MhfeError::from(WalletCheckError::Passphrase(passphrase));
        assert_eq!(checked.code(), shared.code());
        assert_eq!(checked.to_string(), shared.to_string());
    }
}

#[test]
fn failure_details_retain_public_identity_and_exact_diagnostic_without_input_text() {
    let detail = FailureDetail::Case {
        kind: mhfe::self_check::CaseKind::Vector,
        number: 4,
        total: 10,
        cause: Box::new(FailureDetail::RefusalCode {
            actual: ErrorCode::InvalidPhrase,
            expected: ErrorCode::InvalidContainer,
        }),
    };
    assert_eq!(
        detail.to_string(),
        "vector 4 of 10 is refused with INVALID_PHRASE instead of INVALID_CONTAINER"
    );
    let error = SelfCheckError::Failed {
        component: "Public control",
        detail,
    };
    assert_eq!(error.code(), "SELF_CHECK_FAILED");
    assert_eq!(
        error.source().unwrap().to_string(),
        "vector 4 of 10 is refused with INVALID_PHRASE instead of INVALID_CONTAINER"
    );
    assert!(
        std::mem::size_of::<MhfeError>() <= 128,
        "typed failure metadata must not inflate every operation's Result"
    );
}
