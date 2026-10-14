//! The published vectors as the checks replay them, and [`PublishedRoundKeys`], the engine that
//! answers their rounds in place of Argon2. The table itself is generated: published_rounds.rs.

use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::mhfe::published_rounds::PUBLISHED;
use crate::self_check::stopped;
use crate::{Mhfe, MhfeError, Password, PhraseLength, Recovery, Suite, WordCount, WorkFactor};

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

    /// The recovery of the vector's container with `words` stated, its rounds answered by
    /// `table`: its own result, inside the refusal of damaged built-in cases.
    pub(crate) fn recovery_at(
        &self,
        table: &'static [PublishedVector],
        words: usize,
    ) -> Result<Result<Recovery, MhfeError>, String> {
        let words = WordCount::new(words).map_err(stopped)?;
        Ok(self.mhfe(table)?.decrypt(
            self.container,
            &self.password()?,
            PhraseLength::Words(words),
            &mut |_, _| Ok(()),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The published vector files of `folder`, read when the test is compiled, each with its name
    /// and whether it is a same-length vector.
    macro_rules! fixtures {
        ($folder:literal, $same_length:literal, [$($name:literal),+ $(,)?]) => {
            [$((
                $name,
                include_str!(concat!("../../../tests/fixtures/", $folder, "/", $name, ".json")),
                $same_length,
            )),+]
        };
    }

    /// The suite 3 vectors, in the order of their file names.
    const SUITE_3_FILES: [(&str, &str, bool); 17] = fixtures!(
        "suite3-vectors",
        false,
        [
            "ambiguous-12-21",
            "nonzero-12",
            "nonzero-15",
            "nonzero-18",
            "nonzero-21",
            "nonzero-24",
            "spaces-password",
            "unicode-password",
            "zero-12-memory-level-1",
            "zero-12-pim-1-memory-level-1",
            "zero-12-pim-1",
            "zero-12",
            "zero-15",
            "zero-18",
            "zero-21",
            "zero-24-pim-1-memory-level-1",
            "zero-24",
        ]
    );

    /// The suite 4 vectors, in the order of their file names.
    const SUITE_4_FILES: [(&str, &str, bool); 10] = fixtures!(
        "suite4-vectors",
        true,
        [
            "same-length-nonzero-12",
            "same-length-nonzero-21",
            "same-length-unicode-password",
            "same-length-zero-12-memory-level-1",
            "same-length-zero-12-pim-1-memory-level-1",
            "same-length-zero-12-pim-1",
            "same-length-zero-12",
            "same-length-zero-15",
            "same-length-zero-18",
            "same-length-zero-21",
        ]
    );

    /// Every value of the generated table against the fixtures it was generated from.
    #[test]
    fn published_round_table_equals_the_fixtures() {
        assert_eq!(PUBLISHED.len(), SUITE_3_FILES.len() + SUITE_4_FILES.len());
        for &(name, json, same_length) in SUITE_3_FILES.iter().chain(&SUITE_4_FILES) {
            assert_vector_equals_fixture(name, json, same_length);
        }
        let startup: Vec<&str> = PUBLISHED
            .iter()
            .filter(|vector| vector.startup)
            .map(|vector| vector.name)
            .collect();
        assert_eq!(startup.len(), 10);
    }

    /// Every value of the published vector `name` against its fixture, `json`.
    fn assert_vector_equals_fixture(name: &str, json: &str, same_length: bool) {
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
}
