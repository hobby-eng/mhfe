//! Structured failure details of known-answer checks. No compared value or arbitrary reason
//! text is retained: differences, case identities, ordinals and stable codes are typed fields.
use crate::{engine::Argon2Failure, ErrorCode};
use std::fmt;

macro_rules! diagnostic_names {
    ($name:ident, $doc:literal, { $($(#[$meta:meta])* $variant:ident => $text:literal;)+ }) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($(#[$meta])* #[doc = $text] $variant,)+ }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $($(#[$meta])* Self::$variant => $text,)+ })
            }
        }
    };
}

diagnostic_names! { KnownAnswerDifference, "The specific guarantee a known-answer comparison did not satisfy.", {
    NfkdMakesARefusedCharacter => "NFKD makes a refused character";
    TabCompletesAnotherWord => "Tab completes another word";
    ABuiltInVectorIsMissing => "a built-in vector is missing";
    ABuiltInWordIsNotInTheList => "a built-in word is not in the list";
    TheBuiltInCasesAreOfAnotherSuite => "the built-in cases are of another suite";
    IsRefused => "is refused";
    FindsNoPhrase => "finds no phrase";
    ADrawGivesAnotherPhrase => "a draw gives another phrase";
    ADrawIsBiased => "a draw is biased";
    AFingerprintThatDiffersIsReportedAsMatching => "a fingerprint that differs is reported as matching";
    AMasterKeyFingerprintDiffers => "a master key fingerprint differs";
    AMatchingAddressIsReportedAsNotMatching => "a matching address is reported as not matching";
    AMatchingFingerprintIsReportedAsNotMatching => "a matching fingerprint is reported as not matching";
    AWordLeftOutIsNotRestored => "a word left out is not restored";
    AnotherNumberOfCharactersIsRefused => "another number of characters is refused";
    CrashDumpsOrProcessMemoryAccessAreStillAllowed => "crash dumps or process memory access are still allowed";
    TheRunningPartIsNotNamed => "the running part is not named";
    TerminalEchoStayedOn => "the terminal did not turn its echo off";
    Differs => "differs";
    DoesNotFitItsCheckWord => "does not fit its check word";
    DoesNotOfferThe24WordReadingBesideTheCheckedOne => "does not offer the 24-word reading beside the checked one";
    DoesNotTakeTheLengthItsCheckFindsOverAStatedOne => "does not take the length its check finds over a stated one";
    FailsWhereItMustPass => "fails where it must pass";
    FiltersAWordAtThisPositionWrongly => "filters a word at this position wrongly";
    FindsAWordThatIsNotThere => "finds a word that is not there";
    FindsAnotherContainer => "finds another container";
    FindsTheAddressElsewhere => "finds the address elsewhere";
    GivesAContainerOfAnotherSuite => "gives a container of another suite";
    GivesAnotherCheckIndex => "gives another check index";
    GivesAnotherContainer => "gives another container";
    GivesAnotherContainerPhrase => "gives another container phrase";
    GivesAnotherDigest => "gives another digest";
    GivesAnotherEntropy => "gives another entropy";
    GivesAnotherEstimate => "gives another estimate";
    GivesAnotherFingerprint => "gives another fingerprint";
    GivesAnotherHint => "gives another hint";
    GivesAnotherKey => "gives another key";
    GivesAnotherLength => "gives another length";
    GivesAnotherMask => "gives another mask";
    GivesAnotherMaskInput => "gives another mask input";
    GivesAnotherMasterKey => "gives another master key";
    GivesAnotherPassword => "gives another password";
    GivesAnotherPhrase => "gives another phrase";
    GivesAnotherPublicKey => "gives another public key";
    GivesAnotherSalt => "gives another salt";
    GivesAnotherSaltInput => "gives another salt input";
    GivesAnotherSuite => "gives another suite";
    GivesAnotherTag => "gives another tag";
    GivesOtherBytes => "gives other bytes";
    GivesOtherLengths => "gives other lengths";
    GivesOtherMemoryOrPasses => "gives other memory or passes";
    GivesOtherRepairWords => "gives other repair words";
    GivesOtherWords => "gives other words";
    GivesSeveralReadingsWhereItsCheckFoundOne => "gives several readings where its check found one";
    HasAnotherFilterOutcome => "has another filter outcome";
    HasDifferentBip39WordGeometry => "has different BIP39 word geometry";
    IsAccepted => "is accepted";
    IsReadAsAnotherKind => "is read as another kind";
    IsReadAsOtherWords => "is read as other words";
    IsStatedOtherwise => "is stated otherwise";
    LeavesAnotherNumber => "leaves another number";
    ListsOtherWords => "lists other words";
    NeedsAnotherConfirmation => "needs another confirmation";
    OffersOtherContainers => "offers other containers";
    OffersOtherReadingsBeside24StatedWords => "offers other readings beside 24 stated words";
    OffersOtherWallets => "offers other wallets";
    PacksAnotherState => "packs another state";
    PassesWhereItMustFail => "passes where it must fail";
    Reads24StatedWordsOtherwiseThanTheLengthRulesSay => "reads 24 stated words otherwise than the length rules say";
    ReadsDifferentWordBits => "reads different word bits";
    RecoversAnotherPhrase => "recovers another phrase";
    RecoversAnotherPhraseAtAStatedLength => "recovers another phrase at a stated length";
    RecoversAnotherPhraseWithItsSuiteSelected => "recovers another phrase with its suite selected";
    RepairsOtherWords => "repairs other words";
    SealsAnotherContainer => "seals another container";
    SetsDifferentEntropyBits => "sets different entropy bits";
    ShowsAnotherContainerBeforeItsCheck => "shows another container before its check";
    SixWordsThatDoNotFitAreAccepted => "six words that do not fit are accepted";
    TakesAnotherDraw => "takes another draw";
    TakesAnotherWalletSFingerprint => "takes another wallet's fingerprint";
    TellsOtherChecks => "tells other checks";
    TheEffListDiffersFromTheVendoredFile => "the EFF list differs from the vendored file";
    TheEffListIsReadWrongly => "the EFF list is read wrongly";
    TheEnglishListDiffersFromEnglishTxt => "the English list differs from english.txt";
    TheBuiltInCasesAreDamaged => "the built-in cases are damaged";
    TheBuiltInCheckConfirmedStated15Words => "the built-in check confirmed 15 stated words";
    TheBuiltInCheckIsReportedAsNotMatching => "the built-in check is reported as not matching";
    TheChecksumSSha256GivesAnotherDigest => "the checksum's SHA-256 gives another digest";
    TheMasterKeyFingerprintDiffers => "the master key fingerprint differs";
    TheNormalizationTablesAreNotUnicode1700 => "the normalization tables are not Unicode 17.0.0";
    TheOwnerIsNotLeftTheStatedLengthAfterTheRefusal => "the owner is not left the stated length after the refusal";
    TheOwnerSConfirmationStepDiffers => "the owner's confirmation step differs";
    ThePageSArgon2BuildGivesAnotherTag => "the page's Argon2 build gives another tag";
    ThePublishedContainerGivesAnotherWallet => "the published container gives another wallet";
    ThePublishedPasswordGivesOtherBytes => "the published password gives other bytes";
    TheReplacementRehearsalDiffers => "the replacement rehearsal differs";
    TheSealedContainerDiffersFromThePublishedOne => "the sealed container differs from the published one";
    TheSourceCheckRefusesAWorkingSource => "the source check refuses a working source";
    TheSourceGivesBytesThatCannotBeRandom => "the source gives bytes that cannot be random";
    TheSourceSBytesAreNotSpreadAsRandomBytesAre => "the source's bytes are not spread as random bytes are";
    TheSpreadTestAcceptsANarrowSource => "the spread test accepts a narrow source";
    TheVerifierIsWrittenInAnotherByteOrder => "the verifier is written in another byte order";
}}

diagnostic_names! { CaseKind, "A kind of public check case, without its input or vector name.", {
    Address => "address";
    Candidates => "candidates";
    Card => "card";
    Case => "case";
    Completion => "completion";
    Container => "container";
    DamagedAddress => "damaged address";
    DecoySearch => "decoy search";
    Draw => "draw";
    EntropySize => "entropy size";
    LengthDetectionCase => "length detection case";
    LengthRule => "length rule";
    OldContainer => "old container";
    Original => "original";
    Password => "password";
    PhraseCase => "phrase case";
    Reading => "reading";
    Refusal => "refusal";
    RefusedText => "refused text";
    Rekey => "rekey";
    Repair => "repair";
    Replacement => "replacement";
    Search => "search";
    Seed => "seed";
    SettingsCase => "settings case";
    Suite4Refusal => "suite 4 refusal";
    TestVector => "test vector";
    TestVectorSeed => "test vector seed";
    Vector => "vector";
    WrongSearch => "wrong search";
}}

diagnostic_names! { CheckContext, "The fixed context of a refusal control.", {
    Stated15Words => "15 stated words";
    ACheckWithoutAPassphrase => "a check without a passphrase";
    AFingerprintThatIsNotHexadecimal => "a fingerprint that is not hexadecimal";
    APasswordUsedTwice => "a password used twice";
    AReadingThatPassesACheck => "a reading that passes a check";
    ASecondChosenWord => "a second chosen word";
    ASecondWordNeverToUse => "a second word never to use";
    ASourceOfZeros => "a source of zeros";
    AStuckSource => "a stuck source";
    AWrongChecksum => "a wrong checksum";
    AZeroSourceWithAChosenWord => "a zero source with a chosen word";
    AnExcludedEntropyWord => "an excluded entropy word";
    AnExcludedChecksumWord => "an excluded checksum word";
    AnAbsentAnywhereWord => "an absent anywhere word";
    ARepeatedAnywhereWord => "a repeated anywhere word";
    AnAnywhereWordAtTheLastPosition => "an anywhere word at the last position";
    AWrongFinalWord => "a wrong final word";
    TheCorrectFinalWord => "the correct final word";
    AWrongInteriorWord => "a wrong interior word";
    TheSamePasswordAndSettings => "the same password and settings";
    AFingerprintThatDoesNotMatch => "a fingerprint that does not match";
    ADetectedLengthWithTheBuiltInCheckAlone => "a detected length with the built-in check alone";
    AStatedLengthTheBuiltInCheckContradicts => "a stated length the built-in check contradicts";
}}

diagnostic_names! { DigestAlgorithm, "The fixed digest or MAC algorithm under comparison.", {
    Sha256 => "SHA-256";
    Sha512 => "SHA-512";
    HmacSha256 => "HMAC-SHA-256";
    HmacSha512 => "HMAC-SHA-512";
    Blake2b256 => "BLAKE2b-256";
    Ripemd160 => "RIPEMD-160";
    Keccak256 => "Keccak-256";
    #[cfg(test)] Nothing => "Nothing";
}}

/// A deliberately broken scripted byte source used by the randomness guards' controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusedSource {
    /// It returns without filling the output.
    Untouched,
    /// It fills with one repeating byte.
    Stuck,
}
impl fmt::Display for RefusedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Untouched => "a source that fills nothing",
            Self::Stuck => "a stuck source",
        })
    }
}

/// The published input used by a small Argon2 known-answer check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgonVector {
    /// The reference vector of RFC 9106.
    Rfc9106,
    /// MHFE's small-cost public vector.
    OneMib,
}
impl fmt::Display for ArgonVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rfc9106 => "the RFC 9106 vector",
            Self::OneMib => "the 1 MiB vector",
        })
    }
}

/// The public kind of reference in a length-rule control, without its passphrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthReference {
    /// The built-in check at this public word count.
    BuiltInCheck(usize),
    /// The recovered length is detected.
    Detected,
    /// The wallet check is used.
    WalletCheck,
}
impl fmt::Display for LengthReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltInCheck(words) => write!(f, "the built-in check of {words} words"),
            Self::Detected => f.write_str("the length detected"),
            Self::WalletCheck => f.write_str("the wallet check"),
        }
    }
}

/// The public states compared by a length-rule control. No recovered phrase or reference value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LengthEvidence {
    /// The reference comparison's state.
    outcome: crate::CheckState,
    /// The one verified length, when any.
    built_in_check: Option<usize>,
    /// Every short length whose check passed.
    matching_lengths: Vec<usize>,
    /// The result of the wallet check, when attempted.
    wallet_check: Option<bool>,
    /// The checks the result lists as passed.
    passed: Vec<crate::PassedCheck>,
    /// Whether a further length or wallet reference is required.
    asks_length: bool,
}

impl LengthEvidence {
    /// Only the public states of a comparison, including the checks its diagnostic lists.
    pub fn from_check(evidence: &crate::CheckEvidence, passed: Vec<crate::PassedCheck>) -> Self {
        Self {
            outcome: evidence.outcome().state(),
            built_in_check: evidence.built_in_check(),
            matching_lengths: evidence.matching_lengths().to_vec(),
            wallet_check: evidence.wallet_check(),
            passed,
            asks_length: evidence.asks_length(),
        }
    }
}
impl fmt::Display for LengthEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, verified length ", self.outcome.text())?;
        match self.built_in_check {
            Some(words) => write!(f, "{words}")?,
            None => f.write_str("none")?,
        }
        write!(
            f,
            ", lengths {:?}, wallet check {:?}, passed {:?}, asks length {}",
            self.matching_lengths, self.wallet_check, self.passed, self.asks_length
        )
    }
}

/// A failed comparison, including only public case metadata and a closed diagnostic reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureDetail {
    /// A fixed known-answer difference.
    Difference(KnownAnswerDifference),
    /// A case's place in its public list, followed by its typed failure.
    Case {
        /// The kind of case, without a vector's text or name.
        kind: CaseKind,
        /// One-based ordinal.
        number: usize,
        /// Total cases in the list.
        total: usize,
        /// The failed check inside that case.
        cause: Box<Self>,
    },
    /// A refusal control's fixed context, followed by its failed check.
    Context {
        /// The control's identity, without input values.
        context: CheckContext,
        /// The failed check.
        cause: Box<Self>,
    },
    /// A public word-bit control's position and optional public list index.
    Position {
        /// One-based public fixture position.
        position: usize,
        /// Public fixture word index, never a user's chosen word.
        public_index: Option<u16>,
        /// The comparison that failed.
        cause: Box<Self>,
    },
    /// Complete actual and expected state of a public length-rule case.
    LengthRule {
        /// The kind of reference, without its value or passphrase.
        reference: LengthReference,
        /// The returned evidence.
        actual: Box<LengthEvidence>,
        /// The evidence required by the case.
        expected: Box<LengthEvidence>,
    },
    /// The operation stopped with this stable code, without its possibly sensitive text.
    Stopped(ErrorCode),
    /// A refusal used a different code from the fixture's valid code.
    RefusalCode {
        /// The actual stable code.
        actual: ErrorCode,
        /// The fixture's expected stable code.
        expected: ErrorCode,
    },
    /// A negative case was incorrectly accepted.
    Accepted {
        /// The refusal the case should have given.
        expected: ErrorCode,
    },
    /// A corrupted fixture names a code outside the closed vocabulary.
    UnknownExpectedCode,
    /// A damaged fixture was refused with this code where a length-rule refusal was expected.
    Refused(ErrorCode),
    /// A fixed digest/MAC algorithm gave a different known digest.
    Digest(DigestAlgorithm),
    /// The randomness guard accepted a scripted source it must reject.
    AcceptedSource(RefusedSource),
    /// Argon2 itself could not run, with only a closed engine reason.
    Argon2(Argon2Failure),
    /// A non-Argon2 refusal prevented its known-answer check, recorded by code only.
    Argon2Stopped(ErrorCode),
    /// A native core gave a wrong tag for a public small vector.
    NativeTag {
        /// The selected compiled core.
        core: crate::engine::ArgonCore,
        /// The fixed public input kind.
        vector: ArgonVector,
    },
    /// A core gave a wrong tag at one of the larger check sizes.
    TagAtSize {
        /// The native core, or none for the browser reference build.
        core: Option<crate::engine::ArgonCore>,
        /// Public memory cost in MiB.
        mebibytes: u64,
        /// Whether the four-lane core ran on one thread.
        one_thread: bool,
    },
    /// A native core left its work area unwiped.
    Unwiped {
        /// The selected compiled core.
        core: crate::engine::ArgonCore,
        /// Public memory cost in MiB when the larger-size check names it.
        mebibytes: Option<u64>,
    },
    /// A test-only synthetic detail for controls of the reporting harness, never in a program.
    #[cfg(test)]
    TestMessage(String),
}
impl From<KnownAnswerDifference> for FailureDetail {
    fn from(reason: KnownAnswerDifference) -> Self {
        Self::Difference(reason)
    }
}
#[cfg(test)]
impl From<String> for FailureDetail {
    fn from(text: String) -> Self {
        Self::TestMessage(text)
    }
}
impl fmt::Display for FailureDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Difference(reason) => reason.fmt(f),
            Self::Case {
                kind,
                number,
                total,
                cause,
            } => write!(f, "{kind} {number} of {total} {cause}"),
            Self::Context { context, cause } => write!(f, "{context} {cause}"),
            Self::Position {
                position,
                public_index,
                cause,
            } => {
                write!(f, "position {position}")?;
                if let Some(number) = public_index {
                    write!(f, ", public index {number}")?;
                }
                write!(f, " {cause}")
            }
            Self::LengthRule {
                reference,
                actual,
                expected,
            } => write!(f, "with {reference} gives \"{actual}\", not \"{expected}\""),
            Self::Stopped(code) => write!(f, "stops with {code}"),
            Self::RefusalCode { actual, expected } => {
                write!(f, "is refused with {actual} instead of {expected}")
            }
            Self::Accepted { expected } => {
                write!(f, "is accepted instead of refused with {expected}")
            }
            Self::UnknownExpectedCode => {
                f.write_str("the built-in case names an unknown error code")
            }
            Self::Refused(code) => write!(f, "is refused with {code}"),
            Self::Digest(algorithm) => write!(f, "{algorithm} gives another digest"),
            Self::AcceptedSource(source) => write!(f, "the source check accepts {source}"),
            Self::Argon2(reason) => write!(f, "Argon2id could not run: {reason}"),
            Self::Argon2Stopped(code) => write!(f, "Argon2id could not run: {code}"),
            Self::NativeTag { core, vector } => write!(f, "{core} gives another tag for {vector}"),
            Self::TagAtSize {
                core,
                mebibytes,
                one_thread,
            } => {
                match core {
                    Some(core) => write!(f, "{core} ")?,
                    None => f.write_str("the page's Argon2 build ")?,
                }
                write!(f, "gives another tag at {mebibytes} MiB")?;
                if *one_thread {
                    f.write_str(" on one thread")?;
                }
                Ok(())
            }
            Self::Unwiped { core, mebibytes } => {
                write!(f, "{core} leaves its memory unwiped")?;
                if let Some(mebibytes) = mebibytes {
                    write!(f, " at {mebibytes} MiB")?;
                }
                Ok(())
            }
            #[cfg(test)]
            Self::TestMessage(text) => f.write_str(text),
        }
    }
}
impl std::error::Error for FailureDetail {}
impl crate::ErrorIdentity for FailureDetail {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::SelfCheckFailed
    }
}
