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

use super::published_rounds::PUBLISHED;
use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::feistel::{round_mask, round_message, round_salt, Geometry};
use crate::operation::Encryption;
use crate::packing;
use crate::self_check::{
    digest_outcome, expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, DigestCase,
    Findings, Tier,
};
use crate::validation_fixtures::{self as fixtures, Fixture};
use crate::{
    Mhfe, MhfeError, Password, PhraseLength, Recovery, Suite, WordCount, WorkFactor,
    SAME_LENGTH_SUITE_ID, SUITE_ID,
};

/// One published vector as the checks replay it.
#[derive(Clone, Copy)]
pub(crate) struct PublishedVector {
    /// The file name of the vector, for the unit tests; a self-check names it only by its place.
    pub(crate) name: &'static str,
    /// Suite 4: the container keeps the length of its original.
    pub(crate) same_length: bool,
    /// Replayed at every start; the others in the full self-test only.
    pub(crate) startup: bool,
    pub(crate) phrase: &'static str,
    pub(crate) password: &'static str,
    /// The password after NFKD, as the vector records it: the bytes Argon2 receives.
    pub(crate) password_nfkd: &'static [u8],
    pub(crate) pim: u32,
    pub(crate) memory_level: u32,
    pub(crate) container: &'static str,
    /// What a recovery with automatic detection gives, in order.
    pub(crate) recovery: &'static [PublishedReading],
    /// The salt and the Argon2id key of rounds 0 to 11 of the encryption.
    pub(crate) rounds: [PublishedRound; crate::ROUNDS as usize],
}

#[derive(Clone, Copy)]
pub(crate) struct PublishedReading {
    pub(crate) words: usize,
    pub(crate) verified: bool,
    pub(crate) phrase: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) struct PublishedRound {
    pub(crate) salt: [u8; SALT_BYTES],
    pub(crate) key: [u8; KEY_BYTES],
}

impl PublishedVector {
    pub(crate) fn suite(&self) -> Suite {
        if self.same_length {
            Suite::SameLength
        } else {
            Suite::TwentyFourWords
        }
    }

    pub(crate) fn work(&self) -> Result<WorkFactor, String> {
        WorkFactor::new(self.pim, self.memory_level).map_err(stopped)
    }

    /// The password through the library's own encoding, which must give the recorded bytes for
    /// the round keys to be found.
    pub(crate) fn password(&self) -> Result<Password, String> {
        Password::new(self.password).map_err(stopped)
    }

    /// An `Mhfe` at the vector's settings that answers the rounds of `table`.
    pub(crate) fn mhfe(
        &self,
        table: &'static [PublishedVector],
    ) -> Result<Mhfe<PublishedRoundKeys>, String> {
        Ok(Mhfe::with_engine(
            self.work()?,
            PublishedRoundKeys::of(table),
        ))
    }
}

/// The published vector named `name`.
pub(crate) fn published(name: &str) -> Result<&'static PublishedVector, String> {
    PUBLISHED
        .iter()
        .find(|vector| vector.name == name)
        .ok_or_else(|| "a built-in vector is missing".to_owned())
}

/// The whole table of published vectors.
pub(crate) fn published_table() -> &'static [PublishedVector] {
    &PUBLISHED
}

/// An engine that answers only the rounds of published vectors, with the keys they record. It
/// computes no Argon2: the salt and the password after NFKD must be a recorded pair, and anything
/// else is refused with [`MhfeError::Internal`].
pub(crate) struct PublishedRoundKeys {
    vectors: &'static [PublishedVector],
}

impl PublishedRoundKeys {
    pub(crate) fn of(vectors: &'static [PublishedVector]) -> Self {
        Self { vectors }
    }

    /// An engine that answers nothing: any Argon2 call fails, for the refusals that must come
    /// before the first one.
    pub(crate) fn none() -> Self {
        Self { vectors: &[] }
    }
}

impl Argon2Engine for PublishedRoundKeys {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), MhfeError> {
        let round = self
            .vectors
            .iter()
            .filter(|vector| vector.password_nfkd == password)
            .flat_map(|vector| vector.rounds.iter())
            .find(|round| round.salt == *salt)
            .ok_or_else(|| {
                MhfeError::Internal("no published round has this password and salt".to_owned())
            })?;
        key.copy_from_slice(&round.key);
        Ok(())
    }
}

fn sha256(_: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(message).to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::{KeyInit, Mac};
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn blake2b_256(_: &[u8], message: &[u8]) -> Vec<u8> {
    use blake2::Digest;
    blake2::Blake2b::<blake2::digest::consts::U32>::digest(message).to_vec()
}

/// RFC 4231 test case 6: a key longer than the block, which HMAC hashes first.
const LONG_KEY: [u8; 131] = [0xaa; 131];

/// The hashes of the cipher's rounds as the rounds use them: SHA-256 for the packing's verifier,
/// HMAC-SHA-256 for the masks and BLAKE2b with a 32-byte output for the salts.
const CIPHER_DIGESTS: [DigestCase; 5] = [
    // FIPS 180-4, example "abc" (one block).
    DigestCase {
        algorithm: "SHA-256",
        function: sha256,
        key: b"",
        message: b"abc",
        expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    // FIPS 180-4, the 448-bit message, which needs a second block for its padding.
    DigestCase {
        algorithm: "SHA-256",
        function: sha256,
        key: b"",
        message: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
    // RFC 4231, test case 2.
    DigestCase {
        algorithm: "HMAC-SHA-256",
        function: hmac_sha256,
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    // RFC 4231, test case 6.
    DigestCase {
        algorithm: "HMAC-SHA-256",
        function: hmac_sha256,
        key: &LONG_KEY,
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    // BLAKE2b with the output length 32 in its parameter block (RFC 7693), computed with Python's
    // hashlib.blake2b(digest_size=32), whose reference code first gave RFC 7693 Appendix A's
    // BLAKE2b-512("abc"). A BLAKE2b-512 cut to 32 bytes would give ba80a53f... instead.
    DigestCase {
        algorithm: "BLAKE2b-256",
        function: blake2b_256,
        key: b"",
        message: b"abc",
        expected: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    },
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
        digest_outcome(self.cases)
    }
}

/// The repair words that the encryption of zero-12 makes with four words: MHFE-REPAIR-1's public
/// vector (the specification's vectors/profiles/README.md), computed by an independent Python
/// implementation.
const ZERO_12_REPAIR_WORDS: (&str, usize, &str) = ("zero-12", 4, "shaft pupil patient jewel");

/// The `cipher-rounds` check: every vector of the tier through encryption, its check and
/// recovery, then the refusals, and suite 4's round message, salt and mask for each entropy size.
pub(crate) struct CipherRoundsCheck {
    vectors: &'static [PublishedVector],
}

impl CipherRoundsCheck {
    pub(crate) fn new() -> Self {
        Self {
            vectors: published_table(),
        }
    }

    /// Encrypts `vector` and recovers it, and compares each result with the published one.
    fn replay(&self, vector: &PublishedVector) -> Result<(), String> {
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
            "gives another container",
        )?;
        expect(shown, "shows another container before its check")?;
        expect(
            sealed.suite() == suite,
            "gives a container of another suite",
        )?;
        if let Some((_, _, words)) = repair_words {
            expect(
                sealed.repair_words() == Some(words),
                "gives other repair words",
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
            "recovers another phrase",
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
            "recovers another phrase with its suite selected",
        )?;
        // A 24-word container read at a stated length gives that reading alone.
        if !vector.same_length {
            for reading in vector.recovery {
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
                    same_readings(&chosen, std::slice::from_ref(reading)),
                    "recovers another phrase at a stated length",
                )?;
            }
        }
        Ok(())
    }

    /// Refusals the cipher must give: a short length whose verifier does not match, a container
    /// changed before its check, and a round at settings no vector has.
    fn refusals(&self, findings: &mut Findings) {
        /// One refusal, given the table of round keys to replay with.
        type Refusal = fn(&'static [PublishedVector]) -> Result<(), String>;
        let checks: [Refusal; 3] = [
            // zero-12's container read as 15 words: the verifier of that length does not match.
            |table| {
                let vector = find(table, "zero-12")?;
                let words = WordCount::new(15).map_err(stopped)?;
                let result = vector.mhfe(table)?.decrypt(
                    vector.container,
                    &vector.password()?,
                    PhraseLength::Words(words),
                    &mut |_, _| Ok(()),
                );
                expect_refusal(result.map(|_| ()), "VERIFIER_MISMATCH")
            },
            // zero-12's new container with its words replaced by zero-24's container, which has
            // the same password and settings: the check recovers another state and refuses it.
            |table| {
                let vector = find(table, "zero-12")?;
                let other = find(table, "zero-24")?;
                let password = vector.password()?;
                let mut mhfe = vector.mhfe(table)?;
                let mut new = mhfe
                    .encrypt_unchecked(
                        vector.phrase,
                        &password,
                        Suite::TwentyFourWords,
                        &mut |_, _| Ok(()),
                    )
                    .map_err(stopped)?;
                new.words = zeroize::Zeroizing::new(other.container.to_owned());
                expect_refusal(
                    mhfe.check_new_container(&new, &password, &mut |_, _| Ok(())),
                    "VERIFICATION_FAILED",
                )
            },
            // zero-12's container at PIM 1: the settings reach the salt, so no recorded round
            // matches and the engine refuses the first call.
            |table| {
                let vector = find(table, "zero-12")?;
                let work = WorkFactor::new(1, vector.memory_level).map_err(stopped)?;
                let mut mhfe = Mhfe::with_engine(work, PublishedRoundKeys::of(table));
                let result = mhfe.decrypt(
                    vector.container,
                    &vector.password()?,
                    PhraseLength::Detect,
                    &mut |_, _| Ok(()),
                );
                expect_refusal(result.map(|_| ()), "INTERNAL_ERROR")
            },
        ];
        let table = self.vectors;
        findings.each("refusal", &checks, |check| check(table));
    }
}

/// The vector named `name` in `table`.
fn find(table: &'static [PublishedVector], name: &str) -> Result<&'static PublishedVector, String> {
    table
        .iter()
        .find(|vector| vector.name == name)
        .ok_or_else(|| "a built-in vector is missing".to_owned())
}

/// Whether a recovery gives exactly the published readings, in order.
pub(crate) fn same_readings(recovery: &Recovery, published: &[PublishedReading]) -> bool {
    let readings = match recovery {
        Recovery::Phrase(phrase) => std::slice::from_ref(phrase),
        Recovery::Ambiguous(candidates) => candidates.as_slice(),
    };
    readings.len() == published.len()
        && readings.iter().zip(published).all(|(reading, expected)| {
            reading.words == expected.words
                && reading.verified == expected.verified
                && *reading.phrase == *expected.phrase
        })
}

/// Suite 4's round message, salt and mask for each entropy size, with a stand-in key: the
/// `ent_separation` cases of the suite 4 validation fixture.
fn entropy_separation(fixture: &Fixture, findings: &mut Findings) {
    let cases = match fixture.cases("ent_separation") {
        Ok(cases) => cases,
        Err(damaged) => return findings.one(|| Err(damaged)),
    };
    findings.each("entropy size", cases, |case| {
        let entropy_bytes = usize::try_from(fixtures::number(case, "entropy_bits")? / 8)
            .map_err(|_| "the built-in cases are damaged".to_owned())?;
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
            "gives another salt input",
        )?;
        expect(
            round_salt(geometry, &message)[..] == fixtures::bytes(case, "salt_hex")?[..],
            "gives another salt",
        )?;
        let key: [u8; KEY_BYTES] = fixtures::bytes(case, "key_hex")?
            .try_into()
            .map_err(|_| "the built-in cases are damaged".to_owned())?;
        expect(
            round_mask(geometry, &key, &message) == fixtures::bytes(case, "mask_hex")?,
            "gives another mask",
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
        findings.each("vector", &vectors, |vector| self.replay(vector));
        self.refusals(&mut findings);
        match Fixture::read(crate::validation_fixtures::SUITE_4) {
            Ok(fixture) => {
                findings.one(|| {
                    expect(
                        fixture.text("suite_id")? == SAME_LENGTH_SUITE_ID,
                        "the built-in cases are of another suite",
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

    fn suite_3(&self, findings: &mut Findings) -> Result<(), String> {
        let fixture = Fixture::read(self.suite_3)?;
        expect(
            fixture.text("suite_id")? == SUITE_ID,
            "the built-in cases are of another suite",
        )?;
        findings.each("settings case", fixture.cases("settings")?, |case| {
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
                        "gives other memory or passes",
                    )
                }
            }
        });
        findings.each(
            "length detection case",
            fixture.cases("length_detection")?,
            |case| {
                let state: packing::State = fixtures::bytes(case, "state_hex")?
                    .try_into()
                    .map_err(|_| "the built-in cases are damaged".to_owned())?;
                if case.get("entropy_hex").is_some() {
                    let packed =
                        packing::pack(&fixtures::bytes(case, "entropy_hex")?).map_err(stopped)?;
                    expect(*packed == state, "packs another state")?;
                }
                expect(
                    packing::matching_short_lengths(&state)
                        == fixtures::numbers(case, "matching_short_lengths")?,
                    "differs",
                )
            },
        );
        findings.one(|| {
            let case = fixture.case("verifier_serialization")?;
            let state = packing::pack(&fixtures::bytes(case, "entropy_hex")?).map_err(stopped)?;
            expect(
                state[..] == fixtures::bytes(case, "state_hex")?[..],
                "the verifier is written in another byte order",
            )
        });
        let password = Password::new("public test password").map_err(stopped)?;
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), PublishedRoundKeys::none());
        findings.each("phrase case", fixture.cases("phrases")?, |case| {
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
                            .map_err(|_| "the built-in cases are damaged".to_owned())
                            .map(WordCount::new)?
                            .map(PhraseLength::Words),
                        None => Ok(PhraseLength::Detect),
                    };
                    let container = fixtures::text(case, "container")?;
                    length
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
                _ => return Err("the built-in cases are damaged".to_owned()),
            };
            expect_refusal(result, expected)
        });
        Ok(())
    }

    fn suite_4(&self, findings: &mut Findings) -> Result<(), String> {
        let fixture = Fixture::read(self.suite_4)?;
        let password = Password::new("public test password").map_err(stopped)?;
        let mut mhfe = Mhfe::with_engine(WorkFactor::default(), PublishedRoundKeys::none());
        findings.each("suite 4 refusal", fixture.cases("refusals")?, |case| {
            expect(
                fixtures::text(case, "expected")? == "rejected",
                "the built-in cases are damaged",
            )?;
            let text = fixtures::text(case, "text")?;
            let result = match fixtures::text(case, "operation")? {
                "encrypt-same-length" => mhfe
                    .encrypt(text, &password, Suite::SameLength, &mut |_, _| Ok(()))
                    .map(|_| ()),
                "decrypt" => {
                    let length = match case.get("words") {
                        Some(_) => {
                            let words = usize::try_from(fixtures::number(case, "words")?)
                                .map_err(|_| "the built-in cases are damaged".to_owned())?;
                            PhraseLength::Words(WordCount::new(words).map_err(stopped)?)
                        }
                        None => PhraseLength::Detect,
                    };
                    let suite = match case.get("suite").map(|_| fixtures::number(case, "suite")) {
                        None => None,
                        Some(Ok(3)) => Some(Suite::TwentyFourWords),
                        Some(Ok(4)) => Some(Suite::SameLength),
                        Some(_) => return Err("the built-in cases are damaged".to_owned()),
                    };
                    mhfe.decrypt_as(text, &password, suite, length, &mut |_, _| Ok(()))
                        .map(|_| ())
                }
                _ => return Err("the built-in cases are damaged".to_owned()),
            };
            match result {
                Err(
                    MhfeError::SameLengthNeedsShortPhrase
                    | MhfeError::LengthChoiceNotApplicable { .. }
                    | MhfeError::InvalidContainer(_),
                ) => Ok(()),
                Err(error) => Err(format!("is refused with {}", error.code())),
                Ok(()) => Err("is accepted".to_owned()),
            }
        });
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
        if let Err(damaged) = self.suite_3(&mut findings) {
            findings.one(|| Err(damaged));
        }
        if tier == Tier::Full {
            if let Err(damaged) = self.suite_4(&mut findings) {
                findings.one(|| Err(damaged));
            }
        }
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn leaked(vectors: Vec<PublishedVector>) -> &'static [PublishedVector] {
        Box::leak(vectors.into_boxed_slice())
    }

    /// Every value of the generated table against the fixtures it was generated from.
    #[test]
    fn published_round_table_equals_the_fixtures() {
        /// A published vector file, read when the test is compiled.
        macro_rules! fixture {
            ($folder:literal, $name:literal) => {
                include_str!(concat!(
                    "../../tests/fixtures/",
                    $folder,
                    "/",
                    $name,
                    ".json"
                ))
            };
        }
        let files: [(&str, &str, bool); 27] = [
            (
                "ambiguous-12-21",
                fixture!("suite3-vectors", "ambiguous-12-21"),
                false,
            ),
            (
                "nonzero-12",
                fixture!("suite3-vectors", "nonzero-12"),
                false,
            ),
            (
                "nonzero-15",
                fixture!("suite3-vectors", "nonzero-15"),
                false,
            ),
            (
                "nonzero-18",
                fixture!("suite3-vectors", "nonzero-18"),
                false,
            ),
            (
                "nonzero-21",
                fixture!("suite3-vectors", "nonzero-21"),
                false,
            ),
            (
                "nonzero-24",
                fixture!("suite3-vectors", "nonzero-24"),
                false,
            ),
            (
                "spaces-password",
                fixture!("suite3-vectors", "spaces-password"),
                false,
            ),
            (
                "unicode-password",
                fixture!("suite3-vectors", "unicode-password"),
                false,
            ),
            (
                "zero-12-memory-level-1",
                fixture!("suite3-vectors", "zero-12-memory-level-1"),
                false,
            ),
            (
                "zero-12-pim-1-memory-level-1",
                fixture!("suite3-vectors", "zero-12-pim-1-memory-level-1"),
                false,
            ),
            (
                "zero-12-pim-1",
                fixture!("suite3-vectors", "zero-12-pim-1"),
                false,
            ),
            ("zero-12", fixture!("suite3-vectors", "zero-12"), false),
            ("zero-15", fixture!("suite3-vectors", "zero-15"), false),
            ("zero-18", fixture!("suite3-vectors", "zero-18"), false),
            ("zero-21", fixture!("suite3-vectors", "zero-21"), false),
            (
                "zero-24-pim-1-memory-level-1",
                fixture!("suite3-vectors", "zero-24-pim-1-memory-level-1"),
                false,
            ),
            ("zero-24", fixture!("suite3-vectors", "zero-24"), false),
            (
                "same-length-nonzero-12",
                fixture!("suite4-vectors", "same-length-nonzero-12"),
                true,
            ),
            (
                "same-length-nonzero-21",
                fixture!("suite4-vectors", "same-length-nonzero-21"),
                true,
            ),
            (
                "same-length-unicode-password",
                fixture!("suite4-vectors", "same-length-unicode-password"),
                true,
            ),
            (
                "same-length-zero-12-memory-level-1",
                fixture!("suite4-vectors", "same-length-zero-12-memory-level-1"),
                true,
            ),
            (
                "same-length-zero-12-pim-1-memory-level-1",
                fixture!("suite4-vectors", "same-length-zero-12-pim-1-memory-level-1"),
                true,
            ),
            (
                "same-length-zero-12-pim-1",
                fixture!("suite4-vectors", "same-length-zero-12-pim-1"),
                true,
            ),
            (
                "same-length-zero-12",
                fixture!("suite4-vectors", "same-length-zero-12"),
                true,
            ),
            (
                "same-length-zero-15",
                fixture!("suite4-vectors", "same-length-zero-15"),
                true,
            ),
            (
                "same-length-zero-18",
                fixture!("suite4-vectors", "same-length-zero-18"),
                true,
            ),
            (
                "same-length-zero-21",
                fixture!("suite4-vectors", "same-length-zero-21"),
                true,
            ),
        ];
        assert_eq!(PUBLISHED.len(), files.len());
        for (name, json, same_length) in files {
            let fixture: Value = serde_json::from_str(json).unwrap();
            let vector = published(name).unwrap();
            assert_eq!(fixture["name"], name);
            assert_eq!(vector.same_length, same_length, "{name}");
            let inputs = &fixture["inputs"];
            assert_eq!(vector.phrase, inputs["phrase"], "{name}");
            assert_eq!(vector.password, inputs["password"], "{name}");
            assert_eq!(
                hex::encode(vector.password_nfkd),
                inputs["password_nfkd_utf8_hex"],
                "{name}"
            );
            assert_eq!(u64::from(vector.pim), inputs["pim"], "{name}");
            assert_eq!(
                u64::from(vector.memory_level),
                inputs["memory_level"],
                "{name}"
            );
            assert_eq!(vector.container, fixture["container"], "{name}");
            let recovery = match &fixture["recovery"] {
                Value::Array(readings) => readings.clone(),
                reading => vec![reading.clone()],
            };
            assert_eq!(vector.recovery.len(), recovery.len(), "{name}");
            for (reading, expected) in vector.recovery.iter().zip(&recovery) {
                assert_eq!(reading.words as u64, expected["words"], "{name}");
                assert_eq!(reading.verified, expected["verified"], "{name}");
                assert_eq!(reading.phrase, expected["phrase"], "{name}");
            }
            let encryption = fixture["encryption"]["rounds"].as_array().unwrap();
            assert_eq!(encryption.len(), 12);
            for (round, expected) in vector.rounds.iter().zip(encryption) {
                assert_eq!(hex::encode(round.salt), expected["salt_hex"], "{name}");
                assert_eq!(hex::encode(round.key), expected["argon2_key_hex"], "{name}");
            }
            // A recovery runs the same rounds backwards: its salts are the encryption's.
            for entry in fixture["decryption"]["rounds"].as_array().unwrap() {
                let salt = entry["salt_hex"].as_str().unwrap();
                assert!(
                    vector
                        .rounds
                        .iter()
                        .any(|round| hex::encode(round.salt) == salt),
                    "{name}: a recovery salt is not an encryption salt"
                );
            }
        }
        let startup: Vec<&str> = PUBLISHED
            .iter()
            .filter(|vector| vector.startup)
            .map(|vector| vector.name)
            .collect();
        assert_eq!(startup.len(), 10);
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
        cases[4].function = sha512_cut;
        let mut check = CipherHashesCheck {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("BLAKE2b-256 gives another digest".to_owned())
        );
        let mut cases = CIPHER_DIGESTS;
        cases[3].expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f55";
        let mut check = CipherHashesCheck {
            cases: Box::leak(Box::new(cases)),
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("HMAC-SHA-256 gives another digest".to_owned())
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
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(format!(
                "vector {} of 10 gives another container",
                startup_place("nonzero-15")
            ))
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
            };
            assert_eq!(
                check.run(Tier::Startup),
                ComponentOutcome::Failed(format!(
                    "vector {} of 10 {what}",
                    startup_place("same-length-zero-18")
                ))
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
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(format!(
                "vector {} of 10 stops with INTERNAL_ERROR",
                startup_place("unicode-password")
            ))
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
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(format!(
                "vector {} of 10 recovers another phrase",
                startup_place("ambiguous-12-21")
            ))
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
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        assert_eq!(
            check.run(Tier::Full),
            ComponentOutcome::Failed(format!(
                "vector {} of 27 gives another container",
                index + 1
            ))
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
            keys.derive(b"public test passwore", &zero_12.rounds[3].salt, &mut key)
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

    #[test]
    fn a_refusal_that_is_accepted_fails() {
        // Without zero-24 in the table, the changed container's check cannot run its rounds and
        // stops with another error than VERIFICATION_FAILED.
        let vectors: Vec<PublishedVector> = PUBLISHED
            .iter()
            .filter(|vector| vector.name != "zero-24")
            .copied()
            .collect();
        let mut check = CipherRoundsCheck {
            vectors: leaked(vectors),
        };
        let outcome = check.run(Tier::Startup);
        assert!(outcome.is_failure(), "{outcome:?}");
    }

    #[test]
    fn a_damaged_fixture_or_a_wrong_expectation_fails_the_formats() {
        let mut check = FormatsCheck {
            suite_3: "{",
            suite_4: crate::validation_fixtures::SUITE_4,
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("the built-in cases are damaged".to_owned())
        );
        let changed = crate::validation_fixtures::SUITE_3.replacen(
            "        15\n      ]",
            "        15,\n        21\n      ]",
            1,
        );
        assert_ne!(changed, crate::validation_fixtures::SUITE_3);
        let mut check = FormatsCheck {
            suite_3: changed.leak(),
            suite_4: crate::validation_fixtures::SUITE_4,
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("length detection case 2 of 8 differs".to_owned())
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
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed(
                "settings case 4 of 5 is refused with INVALID_PIM instead of INVALID_MEMORY_LEVEL"
                    .to_owned()
            )
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
        assert_eq!(
            check.run(Tier::Full),
            ComponentOutcome::Failed(
                "suite 4 refusal 2 of 63 is refused with INTERNAL_ERROR".to_owned()
            )
        );
    }
}
