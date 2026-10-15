//! Known answers of the cipher: the self-checks `cipher-hashes`, `cipher-rounds` and `formats`.
//!
//! `cipher-rounds` replays the published vectors through the operations the front ends call,
//! [`Encryption::run`], [`Mhfe::decrypt`] and [`Mhfe::decrypt_as`], with [`PublishedRoundKeys`] in
//! place of Argon2: an engine that computes nothing and answers only the salts a published vector
//! records, with the key it records. Everything around Argon2 runs as in a real operation: the
//! phrase parsing, the packing, the BLAKE2b salts with their settings, the HMAC masks, the twelve
//! rounds in both directions, the container encoding, the encryption's own check, the length
//! detection and the NFKD of the password. A salt the vector does not record means the pipeline
//! asked for a round it should not have, and fails the check. Argon2 itself has its own check.
//!
//! [`PublishedRoundKeys`] cannot encrypt anything but a published vector, so it is no reduced-cost
//! engine: a release build may hold it.

use super::RecoveredPhrase;
use crate::detection::LengthDetection;
use crate::engine::{Argon2Engine, KEY_BYTES};
use crate::feistel::{round_mask, round_message, round_salt, Geometry};
use crate::operation::Encryption;
use crate::packing::{self, STATE_WORDS};
use crate::self_check::{
    damaged, expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, DigestCase,
    Findings, Tier, DAMAGED,
};
use crate::validation_fixtures::{self as fixtures, Fixture};
use crate::vectors::inputs::TEST_PASSWORD;
use crate::{
    ContainerFacts, Mhfe, Password, PhraseLength, Recovery, Suite, WordCount, WorkFactor,
    SAME_LENGTH_SUITE_ID, SUITE_ID,
};

const ANOTHER_SUITE: crate::self_check::KnownAnswerDifference =
    crate::self_check::KnownAnswerDifference::TheBuiltInCasesAreOfAnotherSuite;

mod published;

pub(crate) use published::{
    published, published_in, published_table, PublishedReading, PublishedRound, PublishedRoundKeys,
    PublishedVector,
};

use crate::self_check::digests::{digest, hmac};

/// RFC 4231 test case 6: a key longer than the block, which HMAC hashes first.
const LONG_KEY: [u8; 131] = [0xaa; 131];

/// The hashes of the cipher's rounds as the rounds use them: SHA-256 for the packing's verifier,
/// HMAC-SHA-256 for the masks and BLAKE2b with a 32-byte output for the salts.
const CIPHER_DIGESTS: [DigestCase; 5] = [
    // FIPS 180-4, example "abc" (one block).
    DigestCase::new(
        crate::self_check::DigestAlgorithm::Sha256,
        digest::<sha2::Sha256>,
        b"",
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    // FIPS 180-4, the 448-bit message, which needs a second block for its padding.
    DigestCase::new(
        crate::self_check::DigestAlgorithm::Sha256,
        digest::<sha2::Sha256>,
        b"",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    // RFC 4231, test case 2.
    DigestCase::new(
        crate::self_check::DigestAlgorithm::HmacSha256,
        hmac::<sha2::Sha256>,
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    // RFC 4231, test case 6.
    DigestCase::new(
        crate::self_check::DigestAlgorithm::HmacSha256,
        hmac::<sha2::Sha256>,
        &LONG_KEY,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
    // BLAKE2b with the output length 32 in its parameter block (RFC 7693), computed with Python's
    // hashlib.blake2b(digest_size=32), whose reference code first gave RFC 7693 Appendix A's
    // BLAKE2b-512("abc"). A BLAKE2b-512 cut to 32 bytes would give ba80a53f... instead.
    DigestCase::new(
        crate::self_check::DigestAlgorithm::Blake2b256,
        digest::<blake2::Blake2b<blake2::digest::consts::U32>>,
        b"",
        b"abc",
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    ),
];

/// The `cipher-hashes` check: the CPU-dispatched SHA-256, HMAC-SHA-256 and BLAKE2b-256 against
/// their published values. Microseconds.
pub(crate) struct CipherHashesCheck {
    cases: &'static [DigestCase],
}

impl CipherHashesCheck {
    pub(crate) fn new() -> Self {
        Self {
            cases: &CIPHER_DIGESTS,
        }
    }
}

impl ComponentCheck for CipherHashesCheck {
    fn id(&self) -> &'static str {
        "cipher-hashes"
    }

    fn label(&self) -> &'static str {
        "Cipher hashes"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        DigestCase::outcome(self.cases)
    }
}

/// The repair words that the encryption of zero-12 makes with four words: MHFE-REPAIR-1's public
/// vector (the specification's vectors/profiles/README.md), computed by an independent Python
/// implementation.
const ZERO_12_REPAIR_WORDS: (&str, usize, &str) = (
    "zero-12",
    crate::repair::known_answers::ZERO_12_CARD.0,
    crate::repair::known_answers::ZERO_12_CARD.1,
);

/// The `cipher-rounds` check: every vector of the tier through encryption, its check and
/// recovery, then the refusals, and suite 4's round message, salt and mask for each entropy size.
pub(crate) struct CipherRoundsCheck {
    vectors: &'static [PublishedVector],
    refusals: &'static [Refusal],
}

impl CipherRoundsCheck {
    pub(crate) fn new() -> Self {
        Self {
            vectors: published_table(),
            refusals: &REFUSALS,
        }
    }

    /// Encrypts `vector` and recovers it, and compares each result with the published one.
    fn replay(&self, vector: &PublishedVector) -> Result<(), crate::self_check::FailureDetail> {
        let password = vector.password()?;
        let mut mhfe = vector.mhfe(self.vectors)?;
        let suite = vector.suite();
        let repair_words = (vector.name == ZERO_12_REPAIR_WORDS.0).then_some(ZERO_12_REPAIR_WORDS);
        let encryption = Encryption::new(
            vector.phrase,
            suite,
            repair_words.map(|(_, count, _)| count),
        )
        .map_err(stopped)?;
        let mut shown = false;
        let sealed = encryption
            .run(
                &mut mhfe,
                vector.phrase,
                &password,
                &mut |_, _, _| Ok(()),
                &mut |words| {
                    shown = words == vector.container;
                    Ok(())
                },
            )
            .map_err(stopped)?;
        expect(
            sealed.container() == vector.container,
            crate::self_check::KnownAnswerDifference::GivesAnotherContainer,
        )?;
        expect(
            shown,
            crate::self_check::KnownAnswerDifference::ShowsAnotherContainerBeforeItsCheck,
        )?;
        expect(
            sealed.suite() == suite,
            crate::self_check::KnownAnswerDifference::GivesAContainerOfAnotherSuite,
        )?;
        if let Some((_, _, words)) = repair_words {
            expect(
                sealed.repair_words() == Some(words),
                crate::self_check::KnownAnswerDifference::GivesOtherRepairWords,
            )?;
        }

        let detected = mhfe
            .decrypt(
                vector.container,
                &password,
                PhraseLength::Detect,
                &mut |_, _| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            same_readings(&detected, vector.recovery),
            crate::self_check::KnownAnswerDifference::RecoversAnotherPhrase,
        )?;
        let selected = mhfe
            .decrypt_as(
                vector.container,
                &password,
                Some(suite),
                PhraseLength::Detect,
                &mut |_, _| Ok(()),
            )
            .map_err(stopped)?;
        expect(
            same_readings(&selected, vector.recovery),
            crate::self_check::KnownAnswerDifference::RecoversAnotherPhraseWithItsSuiteSelected,
        )?;
        // A 24-word container read at a stated length gives that reading alone where its check
        // passes; 24 words stated beside a check that passes give every reading, the checked ones
        // first (the length rules of recovery).
        if !vector.same_length {
            for reading in vector.recovery {
                let expected = if reading.words == STATE_WORDS && vector.recovery.len() > 1 {
                    vector.recovery
                } else {
                    std::slice::from_ref(reading)
                };
                let words = WordCount::new(reading.words).map_err(stopped)?;
                let chosen = mhfe
                    .decrypt(
                        vector.container,
                        &password,
                        PhraseLength::Words(words),
                        &mut |_, _| Ok(()),
                    )
                    .map_err(stopped)?;
                expect(
                    same_readings(&chosen, expected),
                    crate::self_check::KnownAnswerDifference::RecoversAnotherPhraseAtAStatedLength,
                )?;
            }
        }
        Ok(())
    }

    /// The length rules of recovery, which a stated length meets (AUD-015-FUN001): a built-in
    /// check that passes takes precedence over the length stated.
    fn length_rules(&self, findings: &mut Findings) {
        /// One case, given the table of round keys to replay with.
        type Case = fn(&'static [PublishedVector]) -> Result<(), crate::self_check::FailureDetail>;
        let cases: [Case; 2] = [
            // zero-12's container with 15 words stated: the 12-word check passes and gives the
            // published reading, which says that 15 were stated.
            |table| {
                let vector = published_in(table, "zero-12")?;
                let recovery = vector.recovery_at(table, 15)?.map_err(stopped)?;
                let Recovery::Phrase(reading) = &recovery else {
                    return Err(crate::self_check::FailureDetail::from(crate::self_check::KnownAnswerDifference::GivesSeveralReadingsWhereItsCheckFoundOne));
                };
                expect(
                    same_readings(&recovery, vector.recovery) && reading.stated_words() == Some(15), crate::self_check::KnownAnswerDifference::DoesNotTakeTheLengthItsCheckFindsOverAStatedOne,
                )
            },
            // zero-12's container with 24 words stated: the 12-word reading first, which says
            // that 24 were stated, and the unverified 24-word reading after it.
            |table| {
                let vector = published_in(table, "zero-12")?;
                let Recovery::Ambiguous(readings) =
                    vector.recovery_at(table, STATE_WORDS)?.map_err(stopped)?
                else {
                    return Err(
                        crate::self_check::FailureDetail::from(crate::self_check::KnownAnswerDifference::DoesNotOfferThe24WordReadingBesideTheCheckedOne)
                    );
                };
                let [checked, read_as_24] = &readings[..] else {
                    return Err(crate::self_check::FailureDetail::from(crate::self_check::KnownAnswerDifference::OffersOtherReadingsBeside24StatedWords));
                };
                let [published] = vector.recovery else {
                    return Err(damaged());
                };
                expect(
                    same_reading(checked, published)
                        && checked.stated_words() == Some(STATE_WORDS)
                        && (read_as_24.words, read_as_24.verified) == (STATE_WORDS, false), crate::self_check::KnownAnswerDifference::Reads24StatedWordsOtherwiseThanTheLengthRulesSay,
                )
            },
        ];
        let table = self.vectors;
        findings.each(crate::self_check::CaseKind::LengthRule, &cases, |case| {
            case(table)
        });
    }

    /// Refusals the cipher must give: a short length whose verifier does not match, a container
    /// changed before its check, and a round at settings no vector has.
    fn refusals(&self, findings: &mut Findings) {
        let table = self.vectors;
        findings.each(
            crate::self_check::CaseKind::Refusal,
            self.refusals,
            |refusal| refusal.run(table),
        );
    }
}

/// A case the cipher must refuse, with the error code it must refuse it with. The cases are data
/// of [`CipherRoundsCheck`], so that a test can give one that is wrongly accepted.
#[derive(Clone, Copy)]
enum Refusal {
    /// The container of `vector` recovered with `words` stated.
    ReadAs {
        vector: &'static str,
        words: usize,
        code: &'static str,
    },
    /// The new container of `vector` with its words replaced by the container of `other`, checked
    /// as the encryption checks its own result.
    Swapped {
        vector: &'static str,
        other: &'static str,
        code: &'static str,
    },
    /// The container of `vector` recovered at the PIM `pim`.
    AtPim {
        vector: &'static str,
        pim: u32,
        code: &'static str,
    },
}

const REFUSALS: [Refusal; 3] = [
    // zero-24's container read as 12 words: no short length's check passes, so the stated one
    // fails too.
    Refusal::ReadAs {
        vector: "zero-24",
        words: 12,
        code: "VERIFIER_MISMATCH",
    },
    // zero-12's new container with its words replaced by zero-24's container, which has the same
    // password and settings: the check recovers another state and refuses it.
    Refusal::Swapped {
        vector: "zero-12",
        other: "zero-24",
        code: "VERIFICATION_FAILED",
    },
    // zero-12's container at PIM 1: the settings reach the salt, so no recorded round matches and
    // the engine refuses the first call.
    Refusal::AtPim {
        vector: "zero-12",
        pim: 1,
        code: "INTERNAL_ERROR",
    },
];

impl Refusal {
    /// `Ok` when the case is refused with its code, its rounds answered by `table`.
    fn run(
        &self,
        table: &'static [PublishedVector],
    ) -> Result<(), crate::self_check::FailureDetail> {
        match *self {
            Self::ReadAs {
                vector,
                words,
                code,
            } => {
                let result = published_in(table, vector)?.recovery_at(table, words)?;
                expect_refusal(result.map(|_| ()), code)
            }
            Self::Swapped {
                vector,
                other,
                code,
            } => {
                let vector = published_in(table, vector)?;
                let other = published_in(table, other)?;
                let password = vector.password()?;
                let mut mhfe = vector.mhfe(table)?;
                let mut new = mhfe
                    .encrypt_unchecked(vector.phrase, &password, vector.suite(), &mut |_, _| Ok(()))
                    .map_err(stopped)?;
                new.words = zeroize::Zeroizing::new(other.container.to_owned());
                expect_refusal(
                    mhfe.check_new_container(&new, &password, &mut |_, _| Ok(())),
                    code,
                )
            }
            Self::AtPim { vector, pim, code } => {
                let vector = published_in(table, vector)?;
                let work = WorkFactor::new(pim, vector.memory_level).map_err(stopped)?;
                let mut mhfe = Mhfe::with_engine(work, PublishedRoundKeys::of(table));
                let result = mhfe.decrypt(
                    vector.container,
                    &vector.password()?,
                    PhraseLength::Detect,
                    &mut |_, _| Ok(()),
                );
                expect_refusal(result.map(|_| ()), code)
            }
        }
    }
}

/// Whether a recovery gives exactly the published readings, in order.
pub(crate) fn same_readings(recovery: &Recovery, published: &[PublishedReading]) -> bool {
    let readings = match recovery {
        Recovery::Phrase(phrase) => std::slice::from_ref(phrase),
        Recovery::Ambiguous(candidates) => candidates.as_slice(),
    };
    readings.len() == published.len()
        && readings
            .iter()
            .zip(published)
            .all(|(reading, expected)| same_reading(reading, expected))
}

/// Whether one reading is the published one: its length, its check and its phrase.
fn same_reading(reading: &RecoveredPhrase, expected: &PublishedReading) -> bool {
    reading.words == expected.words
        && reading.verified == expected.verified
        && *reading.phrase == *expected.phrase
}

/// Suite 4's round message, salt and mask for each entropy size, with a stand-in key: the
/// `ent_separation` cases of the suite 4 validation fixture.
fn entropy_separation(fixture: &Fixture, findings: &mut Findings) {
    let cases = match fixture.cases("ent_separation") {
        Ok(cases) => cases,
        Err(damaged) => return findings.one(|| Err(damaged)),
    };
    findings.each(crate::self_check::CaseKind::EntropySize, cases, |case| {
        let entropy_bytes =
            usize::try_from(fixtures::number(case, "entropy_bits")? / 8).map_err(|_| damaged())?;
        let geometry = Geometry::same_length(entropy_bytes).map_err(stopped)?;
        let work = WorkFactor::new(
            fixtures::number_u32(case, "pim")?,
            fixtures::number_u32(case, "memory_level")?,
        )
        .map_err(stopped)?;
        let half = fixtures::bytes(case, "half_hex")?;
        let message = round_message(geometry, work, fixtures::number_u32(case, "round")?, &half);
        expect(
            [geometry.ds_salt(), &message].concat() == fixtures::bytes(case, "salt_input_hex")?,
            crate::self_check::KnownAnswerDifference::GivesAnotherSaltInput,
        )?;
        expect(
            round_salt(geometry, &message)[..] == fixtures::bytes(case, "salt_hex")?[..],
            crate::self_check::KnownAnswerDifference::GivesAnotherSalt,
        )?;
        expect(
            [geometry.ds_mask(), &message].concat() == fixtures::bytes(case, "mask_input_hex")?,
            crate::self_check::KnownAnswerDifference::GivesAnotherMaskInput,
        )?;
        let key: [u8; KEY_BYTES] = fixtures::bytes(case, "key_hex")?
            .try_into()
            .map_err(|_| damaged())?;
        expect(
            round_mask(geometry, &key, &message) == fixtures::bytes(case, "mask_hex")?,
            crate::self_check::KnownAnswerDifference::GivesAnotherMask,
        )
    });
}

impl ComponentCheck for CipherRoundsCheck {
    fn id(&self) -> &'static str {
        "cipher-rounds"
    }

    fn label(&self) -> &'static str {
        "Cipher rounds"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let vectors: Vec<&PublishedVector> = self
            .vectors
            .iter()
            .filter(|vector| tier == Tier::Full || vector.startup)
            .collect();
        let mut findings = Findings::new();
        findings.each(crate::self_check::CaseKind::Vector, &vectors, |vector| {
            self.replay(vector)
        });
        self.length_rules(&mut findings);
        self.refusals(&mut findings);
        match Fixture::read(crate::validation_fixtures::SUITE_4) {
            Ok(fixture) => {
                findings.one(|| {
                    expect(
                        fixture.text("suite_id")? == SAME_LENGTH_SUITE_ID,
                        ANOTHER_SUITE,
                    )
                });
                entropy_separation(&fixture, &mut findings);
            }
            Err(damaged) => findings.one(|| Err(damaged)),
        }
        findings.outcome()
    }
}

/// The `formats` check: the settings, the length detection, the verifier's byte order and the
/// refusals of bad phrases and containers before any Argon2 work, from the validation fixtures.
/// Startup runs the suite 3 fixture; the full self-test adds the 63 refusals of suite 4. The
/// refusals run with an engine that answers nothing, so an input that reaches Argon2 fails with
/// another error code instead of being refused first.
pub(crate) struct FormatsCheck {
    suite_3: &'static str,
    suite_4: &'static str,
}

impl FormatsCheck {
    pub(crate) fn new() -> Self {
        Self {
            suite_3: crate::validation_fixtures::SUITE_3,
            suite_4: crate::validation_fixtures::SUITE_4,
        }
    }

    /// The suite 3 fixture; the phrase cases run with `engine`, which must not be reached.
    fn suite_3(
        &self,
        findings: &mut Findings,
        engine: impl Argon2Engine,
    ) -> Result<(), crate::self_check::FailureDetail> {
        let fixture = Fixture::read(self.suite_3)?;
        expect(fixture.text("suite_id")? == SUITE_ID, ANOTHER_SUITE)?;
        findings.each(
            crate::self_check::CaseKind::SettingsCase,
            fixture.cases("settings")?,
            |case| {
                let result = WorkFactor::new(
                    fixtures::number_u32(case, "pim")?,
                    fixtures::number_u32(case, "memory_level")?,
                );
                match case.get("expected_error") {
                    Some(_) => expect_refusal(result, fixtures::text(case, "expected_error")?),
                    None => {
                        let work = result.map_err(stopped)?;
                        expect(
                            u64::from(work.memory_kib())
                                == fixtures::number(case, "expected_memory_kib")?
                                && u64::from(work.passes())
                                    == fixtures::number(case, "expected_passes")?,
                            crate::self_check::KnownAnswerDifference::GivesOtherMemoryOrPasses,
                        )
                    }
                }
            },
        );
        findings.each(
            crate::self_check::CaseKind::LengthDetectionCase,
            fixture.cases("length_detection")?,
            |case| {
                let state: packing::State = fixtures::bytes(case, "state_hex")?
                    .try_into()
                    .map_err(|_| damaged())?;
                if case.get("entropy_hex").is_some() {
                    let packed =
                        packing::pack(&fixtures::bytes(case, "entropy_hex")?).map_err(stopped)?;
                    expect(
                        *packed == state,
                        crate::self_check::KnownAnswerDifference::PacksAnotherState,
                    )?;
                }
                expect(
                    LengthDetection::of(&state).short_lengths()
                        == fixtures::numbers(case, "matching_short_lengths")?,
                    crate::self_check::KnownAnswerDifference::Differs,
                )
            },
        );
        findings.one(|| {
            let case = fixture.case("verifier_serialization")?;
            let entropy = fixtures::bytes(case, "entropy_hex")?;
            let state = packing::pack(&entropy).map_err(stopped)?;
            // The verifier follows the entropy.
            expect(
                state[..] == fixtures::bytes(case, "state_hex")?[..]
                    && state[entropy.len()..] == fixtures::bytes(case, "verifier_hex")?[..],
                crate::self_check::KnownAnswerDifference::TheVerifierIsWrittenInAnotherByteOrder,
            )
        });
        let (password, mut mhfe) = Self::with_public_password(engine)?;
        findings.each(
            crate::self_check::CaseKind::PhraseCase,
            fixture.cases("phrases")?,
            |case| {
                let expected = fixtures::text(case, "expected_error")?;
                let result = match fixtures::text(case, "operation")? {
                    "encrypt" => mhfe
                        .encrypt(
                            fixtures::text(case, "phrase")?,
                            &password,
                            Suite::TwentyFourWords,
                            &mut |_, _| Ok(()),
                        )
                        .map(|_| ()),
                    "decrypt" => {
                        let length = match case.get("words") {
                            Some(_) => usize::try_from(fixtures::number(case, "words")?)
                                .map_err(|_| damaged())
                                .map(WordCount::new)?
                                .map(PhraseLength::Words),
                            None => Ok(PhraseLength::Detect),
                        };
                        let container = fixtures::text(case, "container")?;
                        length
                            .map_err(crate::CipherError::from)
                            .and_then(|length| {
                                mhfe.decrypt_as(
                                    container,
                                    &password,
                                    Some(Suite::TwentyFourWords),
                                    length,
                                    &mut |_, _| Ok(()),
                                )
                            })
                            .map(|_| ())
                    }
                    _ => return Err(damaged()),
                };
                expect_refusal(result, expected)
            },
        );
        Ok(())
    }

    fn with_public_password<T: Argon2Engine>(
        engine: T,
    ) -> Result<(Password, Mhfe<T>), crate::self_check::FailureDetail> {
        Ok((
            Password::new(TEST_PASSWORD).map_err(stopped)?,
            Mhfe::with_engine(WorkFactor::default(), engine),
        ))
    }

    /// The refusals of the suite 4 fixture, with `engine`, which must not be reached.
    fn suite_4(
        &self,
        findings: &mut Findings,
        engine: impl Argon2Engine,
    ) -> Result<(), crate::self_check::FailureDetail> {
        let fixture = Fixture::read(self.suite_4)?;
        let (password, mut mhfe) = Self::with_public_password(engine)?;
        findings.each(
            crate::self_check::CaseKind::Suite4Refusal,
            fixture.cases("refusals")?,
            |case| {
                expect(fixtures::text(case, "expected")? == "rejected", DAMAGED)?;
                let text = fixtures::text(case, "text")?;
                let result = match fixtures::text(case, "operation")? {
                    "encrypt-same-length" => mhfe
                        .encrypt(text, &password, Suite::SameLength, &mut |_, _| Ok(()))
                        .map(|_| ()),
                    "decrypt" => {
                        // A container that does not read would be refused with the same error code as
                        // one of a length the suite does not have: only a readable one can count.
                        ContainerFacts::read(text).map_err(|_| damaged())?;
                        let length = match case.get("words") {
                            Some(_) => {
                                let words = usize::try_from(fixtures::number(case, "words")?)
                                    .map_err(|_| damaged())?;
                                PhraseLength::Words(WordCount::new(words).map_err(stopped)?)
                            }
                            None => PhraseLength::Detect,
                        };
                        let suite = match case.get("suite") {
                            None => None,
                            Some(_) => Some(
                                Suite::of_number(fixtures::number(case, "suite")?)
                                    .ok_or_else(damaged)?,
                            ),
                        };
                        mhfe.decrypt_as(text, &password, suite, length, &mut |_, _| Ok(()))
                            .map(|_| ())
                    }
                    _ => return Err(damaged()),
                };
                match result {
                    Err(error) if crate::CipherError::is_length_refusal(&error) => Ok(()),
                    Err(error) => Err(crate::self_check::FailureDetail::Refused(
                        error.error_code(),
                    )),
                    Ok(()) => Err(crate::self_check::FailureDetail::from(
                        crate::self_check::KnownAnswerDifference::IsAccepted,
                    )),
                }
            },
        );
        Ok(())
    }
}

impl ComponentCheck for FormatsCheck {
    fn id(&self) -> &'static str {
        "formats"
    }

    fn label(&self) -> &'static str {
        "Formats"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        if let Err(damaged) = self.suite_3(&mut findings, PublishedRoundKeys::none()) {
            findings.one(|| Err(damaged));
        }
        if tier == Tier::Full {
            if let Err(damaged) = self.suite_4(&mut findings, PublishedRoundKeys::none()) {
                findings.one(|| Err(damaged));
            }
        }
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::SALT_BYTES;
    use crate::mhfe::published_rounds::PUBLISHED;

    fn leaked(vectors: Vec<PublishedVector>) -> &'static [PublishedVector] {
        Box::leak(vectors.into_boxed_slice())
    }

    #[test]
    fn the_cipher_checks_pass() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(CipherHashesCheck::new().run(tier), ComponentOutcome::Passed);
            assert_eq!(CipherRoundsCheck::new().run(tier), ComponentOutcome::Passed);
            assert_eq!(FormatsCheck::new().run(tier), ComponentOutcome::Passed);
        }
    }

    #[test]
    fn a_wrong_hash_or_digest_fails() {
        fn sha512_cut(_: &[u8], message: &[u8]) -> Vec<u8> {
            use sha2::Digest;
            sha2::Sha512::digest(message)[..32].to_vec()
        }
        let mut cases = CIPHER_DIGESTS;
        cases[4] = cases[4].with_function(sha512_cut);
        let mut check = CipherHashesCheck {
            cases: Box::leak(Box::new(cases)),
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "BLAKE2b-256 gives another digest".to_owned()
        );
        let mut cases = CIPHER_DIGESTS;
        cases[3] = cases[3]
            .with_expected("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f55");
        let mut check = CipherHashesCheck {
            cases: Box::leak(Box::new(cases)),
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "HMAC-SHA-256 gives another digest".to_owned()
        );
    }

    /// The place of a vector in its tier, counted from 1, as a failure names it.
    fn startup_place(name: &str) -> usize {
        PUBLISHED
            .iter()
            .filter(|vector| vector.startup)
            .position(|vector| vector.name == name)
            .unwrap()
            + 1
    }

    #[test]
    fn a_corrupted_container_or_round_key_fails() {
        let mut vectors = PUBLISHED.to_vec();
        let index = vectors.iter().position(|v| v.name == "nonzero-15").unwrap();
        vectors[index].container = vectors[index].container.replacen("a", "b", 1).leak();
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
            refusals: &REFUSALS,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            format!(
                "vector {} of 10 gives another container",
                startup_place("nonzero-15")
            )
        );

        // A wrong key in the last round is a wrong Argon2 output that changes only the
        // container; in an earlier round it changes the next round's salt, which no vector
        // records, so the replay stops there.
        for (round, what) in [
            (11, "gives another container"),
            (7, "stops with INTERNAL_ERROR"),
        ] {
            let mut vectors = PUBLISHED.to_vec();
            let index = vectors
                .iter()
                .position(|v| v.name == "same-length-zero-18")
                .unwrap();
            vectors[index].rounds[round].key[0] ^= 1;
            let mut check = CipherRoundsCheck {
                vectors: leaked(vectors),
                refusals: &REFUSALS,
            };
            crate::self_check::assert_failed!(
                check.run(Tier::Startup),
                format!(
                    "vector {} of 10 {what}",
                    startup_place("same-length-zero-18")
                )
            );
        }
    }

    #[test]
    fn a_wrong_password_encoding_or_recovery_fails() {
        // The recorded NFKD bytes changed: the pipeline's encoding no longer finds its rounds.
        let mut vectors = PUBLISHED.to_vec();
        let index = vectors
            .iter()
            .position(|v| v.name == "unicode-password")
            .unwrap();
        vectors[index].password_nfkd =
            b"Caf\xc3\xa9 fi PA\xcc\x8a1 \xf0\x9f\x94\x90 \xd0\xb8\xcc\x86";
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
            refusals: &REFUSALS,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            format!(
                "vector {} of 10 stops with INTERNAL_ERROR",
                startup_place("unicode-password")
            )
        );

        // The ambiguous vector must list both short readings and the 24-word one.
        let mut vectors = PUBLISHED.to_vec();
        let index = vectors
            .iter()
            .position(|v| v.name == "ambiguous-12-21")
            .unwrap();
        let recovery = vectors[index].recovery;
        vectors[index].recovery = &recovery[..2];
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
            refusals: &REFUSALS,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            format!(
                "vector {} of 10 recovers another phrase",
                startup_place("ambiguous-12-21")
            )
        );
    }

    #[test]
    fn the_full_tier_replays_every_vector() {
        let mut vectors = PUBLISHED.to_vec();
        let index = vectors.iter().position(|v| v.name == "zero-21").unwrap();
        assert!(!vectors[index].startup);
        vectors[index].rounds[11].key[31] ^= 0x10;
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
            refusals: &REFUSALS,
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        crate::self_check::assert_failed!(
            check.run(Tier::Full),
            format!("vector {} of 27 gives another container", index + 1)
        );
    }

    #[test]
    fn the_engine_answers_only_recorded_rounds() {
        let mut keys = PublishedRoundKeys::of(published_table());
        let zero_12 = published("zero-12").unwrap();
        let mut key = [0u8; KEY_BYTES];
        keys.derive(zero_12.password_nfkd, &zero_12.rounds[3].salt, &mut key)
            .unwrap();
        assert_eq!(key, zero_12.rounds[3].key);
        // The right salt with another password, and an unknown salt, are refused.
        assert_eq!(
            keys.derive(
                crate::test_support::WRONG_PASSWORD.as_bytes(),
                &zero_12.rounds[3].salt,
                &mut key
            )
            .unwrap_err()
            .code(),
            "INTERNAL_ERROR"
        );
        assert!(keys
            .derive(zero_12.password_nfkd, &[0u8; SALT_BYTES], &mut key)
            .is_err());
        assert!(PublishedRoundKeys::none()
            .derive(zero_12.password_nfkd, &zero_12.rounds[3].salt, &mut key)
            .is_err());
    }

    /// The engine cannot encrypt a phrase that is not a published vector's, even with a published
    /// password and settings: its first salt is not recorded.
    #[test]
    fn an_arbitrary_phrase_cannot_be_encrypted() {
        let zero_12 = published("zero-12").unwrap();
        let mut mhfe = zero_12.mhfe(published_table()).unwrap();
        let other = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let result = mhfe.encrypt(
            other,
            &zero_12.password().unwrap(),
            Suite::TwentyFourWords,
            &mut |_, _| Ok(()),
        );
        assert_eq!(result.unwrap_err().code(), "INTERNAL_ERROR");
    }

    /// The outcome of `refusal` alone, its rounds answered by the published table.
    fn refusal_alone(refusal: Refusal) -> ComponentOutcome {
        let check = CipherRoundsCheck {
            vectors: published_table(),
            refusals: Box::leak(Box::new([refusal])),
        };
        let mut findings = Findings::new();
        check.refusals(&mut findings);
        findings.outcome()
    }

    #[test]
    fn each_refusal_passes_alone() {
        for refusal in REFUSALS {
            assert_eq!(refusal_alone(refusal), ComponentOutcome::Passed);
        }
    }

    #[test]
    fn a_refusal_that_is_accepted_fails() {
        let accepted = |code: &str| {
            let detail = crate::self_check::FailureDetail::Case {
                kind: crate::self_check::CaseKind::Refusal,
                number: 1,
                total: 1,
                cause: Box::new(crate::self_check::FailureDetail::Accepted {
                    expected: crate::ErrorCode::from_name(code).unwrap(),
                }),
            };
            assert_eq!(
                detail.to_string(),
                format!("refusal 1 of 1 is accepted instead of refused with {code}")
            );
            ComponentOutcome::Failed(detail)
        };
        // zero-12's own container at its own length, its own container in place of another, and
        // its own PIM: each is accepted, so each refusal must fail.
        assert_eq!(
            refusal_alone(Refusal::ReadAs {
                vector: "zero-12",
                words: 12,
                code: "VERIFIER_MISMATCH",
            }),
            accepted("VERIFIER_MISMATCH")
        );
        assert_eq!(
            refusal_alone(Refusal::Swapped {
                vector: "zero-12",
                other: "zero-12",
                code: "VERIFICATION_FAILED",
            }),
            accepted("VERIFICATION_FAILED")
        );
        let zero_12 = published("zero-12").unwrap();
        assert_eq!(
            refusal_alone(Refusal::AtPim {
                vector: "zero-12",
                pim: zero_12.pim,
                code: "INTERNAL_ERROR",
            }),
            accepted("INTERNAL_ERROR")
        );
    }

    #[test]
    fn a_refusal_with_another_code_fails() {
        for (index, refusal) in REFUSALS.into_iter().enumerate() {
            let (changed, code) = match refusal {
                Refusal::ReadAs {
                    vector,
                    words,
                    code,
                } => (
                    Refusal::ReadAs {
                        vector,
                        words,
                        code: "LENGTH_DIFFERS",
                    },
                    code,
                ),
                Refusal::Swapped {
                    vector,
                    other,
                    code,
                } => (
                    Refusal::Swapped {
                        vector,
                        other,
                        code: "LENGTH_DIFFERS",
                    },
                    code,
                ),
                Refusal::AtPim { vector, pim, code } => (
                    Refusal::AtPim {
                        vector,
                        pim,
                        code: "LENGTH_DIFFERS",
                    },
                    code,
                ),
            };
            crate::self_check::assert_failed!(
                refusal_alone(changed),
                format!("refusal 1 of 1 is refused with {code} instead of LENGTH_DIFFERS"),
                "refusal {}",
                index + 1
            );
        }
    }

    #[test]
    fn a_missing_vector_fails_the_refusals() {
        let vectors: Vec<PublishedVector> = PUBLISHED
            .iter()
            .filter(|vector| vector.name != "zero-24")
            .copied()
            .collect();
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
            refusals: &REFUSALS,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "refusal 1 of 3 a built-in vector is missing".to_owned()
        );
    }

    /// Asserts that the formats check fails at startup with `detail` once `from` in the suite 3
    /// fixture is changed to `to`.
    fn suite_3_changed_fails(from: &str, to: &str, detail: &str) {
        let changed = crate::validation_fixtures::SUITE_3.replacen(from, to, 1);
        assert_ne!(changed, crate::validation_fixtures::SUITE_3);
        let mut check = FormatsCheck {
            suite_3: changed.leak(),
            suite_4: crate::validation_fixtures::SUITE_4,
        };
        crate::self_check::assert_failed!(check.run(Tier::Startup), detail.to_owned());
    }

    #[test]
    fn a_damaged_fixture_or_a_wrong_expectation_fails_the_formats() {
        let mut check = FormatsCheck {
            suite_3: "{",
            suite_4: crate::validation_fixtures::SUITE_4,
        };
        crate::self_check::assert_failed!(check.run(Tier::Startup), damaged());
        suite_3_changed_fails(
            "        15\n      ]",
            "        15,\n        21\n      ]",
            "length detection case 2 of 8 differs",
        );
        // A refusal that the fixture names otherwise.
        let changed = crate::validation_fixtures::SUITE_3.replacen(
            "\"expected_error\": \"INVALID_PIM\"",
            "\"expected_error\": \"INVALID_MEMORY_LEVEL\"",
            1,
        );
        let mut check = FormatsCheck {
            suite_3: changed.leak(),
            suite_4: crate::validation_fixtures::SUITE_4,
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "settings case 4 of 5 is refused with INVALID_PIM instead of INVALID_MEMORY_LEVEL"
                .to_owned()
        );
    }

    #[test]
    fn the_suite_4_refusals_run_in_the_full_tier() {
        // A refusal case changed into a container the suite takes: accepted only if Argon2 ran,
        // which the engine of the check refuses, so it fails with another code.
        let fixture = crate::validation_fixtures::SUITE_4;
        let refusals = fixture.find("\"refusals\"").unwrap();
        let changed = format!(
            "{}{}",
            &fixture[..refusals],
            fixture[refusals..].replacen("\"words\": 12", "\"words\": 15", 1)
        );
        assert_ne!(changed, fixture);
        let mut check = FormatsCheck {
            suite_3: crate::validation_fixtures::SUITE_3,
            suite_4: changed.leak(),
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        crate::self_check::assert_failed!(
            check.run(Tier::Full),
            "suite 4 refusal 2 of 63 is refused with INTERNAL_ERROR".to_owned()
        );
    }

    /// The format checks with an engine that panics if Argon2 is reached, as the unit tests run
    /// them: every refusal of both fixtures must come first.
    #[test]
    fn the_formats_refuse_before_argon2() {
        use crate::test_support::NoArgon2Calls;
        let check = FormatsCheck::new();
        let mut findings = Findings::new();
        check.suite_3(&mut findings, NoArgon2Calls).unwrap();
        check.suite_4(&mut findings, NoArgon2Calls).unwrap();
        assert_eq!(findings.outcome(), ComponentOutcome::Passed);
    }

    #[test]
    fn a_wrong_verifier_or_mask_input_fails() {
        suite_3_changed_fails(
            "\"verifier_hex\": \"dc27f8e8\"",
            "\"verifier_hex\": \"dc27f8e9\"",
            "the verifier is written in another byte order",
        );

        let fixture = Fixture::read(crate::validation_fixtures::SUITE_4).unwrap();
        let mask_input = fixtures::text(
            &fixture.cases("ent_separation").unwrap()[1],
            "mask_input_hex",
        )
        .unwrap()
        .to_owned();
        let mut wrong = mask_input.clone();
        wrong.replace_range(
            wrong.len() - 1..,
            if wrong.ends_with('0') { "1" } else { "0" },
        );
        let changed = crate::validation_fixtures::SUITE_4.replacen(&mask_input, &wrong, 1);
        assert_ne!(changed, crate::validation_fixtures::SUITE_4);
        let mut findings = Findings::new();
        entropy_separation(&Fixture::read(&changed).unwrap(), &mut findings);
        crate::self_check::assert_failed!(
            findings.outcome(),
            "entropy size 2 of 4 gives another mask input".to_owned()
        );
    }
}
