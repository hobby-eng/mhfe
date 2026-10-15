//! Known answers of the BIP39 word list: the self-check `bip39-words`.
//!
//! The English list of 2,048 words, the checksum, the conversion between entropy and words both
//! ways, the refusal of a wrong checksum and the completion of four-letter prefixes, which every
//! phrase and container a person types passes through.

use bip39::Language;
use sha2::Digest;

use crate::self_check::{
    damaged, expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

/// SHA-256 of english.txt of BIP-0039 (the words, each followed by a line feed), recomputed with
/// Python's hashlib from the list of the bip39 3.0.0 crate.
const ENGLISH_LIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

/// The English entropy and phrase of a BIP-0039 test vector.
#[derive(Clone, Copy)]
pub(crate) struct TrezorVector {
    pub(crate) entropy: &'static str,
    pub(crate) phrase: &'static str,
}

/// The 24 English test vectors of BIP-0039 (trezor/python-mnemonic vectors.json, as the bip39
/// 3.0.0 crate's tests give them), reproduced with Python's hashlib. Their seeds with the
/// passphrase "TREZOR" are in the wallet's check (src/wallet/known_answers.rs), in this order.
pub(crate) const TREZOR_ENGLISH: [TrezorVector; 24] = [
    TrezorVector {
        entropy: "00000000000000000000000000000000",
        phrase: crate::vectors::inputs::ZERO_12,
    },
    TrezorVector {
        entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    },
    TrezorVector {
        entropy: "80808080808080808080808080808080",
        phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    },
    TrezorVector {
        entropy: "ffffffffffffffffffffffffffffffff",
        phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    },
    TrezorVector {
        entropy: "000000000000000000000000000000000000000000000000",
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    },
    TrezorVector {
        entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
    },
    TrezorVector {
        entropy: "808080808080808080808080808080808080808080808080",
        phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
    },
    TrezorVector {
        entropy: "ffffffffffffffffffffffffffffffffffffffffffffffff",
        phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
    },
    TrezorVector {
        entropy: "0000000000000000000000000000000000000000000000000000000000000000",
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    },
    TrezorVector {
        entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    },
    TrezorVector {
        entropy: "8080808080808080808080808080808080808080808080808080808080808080",
        phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    },
    TrezorVector {
        entropy: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    },
    TrezorVector {
        entropy: "9e885d952ad362caeb4efe34a8e91bd2",
        phrase: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    },
    TrezorVector {
        entropy: "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        phrase: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
    },
    TrezorVector {
        entropy: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        phrase: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    },
    TrezorVector {
        entropy: "c0ba5a8e914111210f2bd131f3d5e08d",
        phrase: "scheme spot photo card baby mountain device kick cradle pact join borrow",
    },
    TrezorVector {
        entropy: "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        phrase: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
    },
    TrezorVector {
        entropy: "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        phrase: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    },
    TrezorVector {
        entropy: "23db8160a31d3e0dca3688ed941adbf3",
        phrase: "cat swing flag economy stadium alone churn speed unique patch report train",
    },
    TrezorVector {
        entropy: "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        phrase: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
    },
    TrezorVector {
        entropy: "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        phrase: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    },
    TrezorVector {
        entropy: "f30f8c1da665478f49b001d94c5fc452",
        phrase: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    },
    TrezorVector {
        entropy: "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        phrase: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
    },
    TrezorVector {
        entropy: "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        phrase: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    },
];

/// The startup vectors: the first, the 7f and 80 patterns of 12 words, and the ff pattern of 24.
const STARTUP_VECTORS: [usize; 4] = [0, 1, 2, 11];

/// Completions of typed prefixes: an exact three-letter word that begins others stays itself,
/// four letters name one word, and letters that begin no word name none.
const COMPLETIONS: [(&str, Option<&str>); 5] = [
    ("aban", Some("abandon")),
    ("act", Some("act")),
    ("actr", Some("actress")),
    ("zzzz", None),
    ("ab", None),
];

/// The `bip39-words` check.
pub(crate) struct WordListCheck {
    list_sha256: &'static str,
    vectors: &'static [TrezorVector],
}

impl WordListCheck {
    pub(crate) fn new() -> Self {
        Self {
            list_sha256: ENGLISH_LIST_SHA256,
            vectors: &TREZOR_ENGLISH,
        }
    }

    fn vector(vector: &TrezorVector) -> Result<(), crate::self_check::FailureDetail> {
        let entropy = hex::decode(vector.entropy).map_err(|_| damaged())?;
        let phrase = crate::Phrase::from_entropy(&entropy).map_err(stopped)?;
        expect(
            phrase.words() == vector.phrase,
            crate::self_check::KnownAnswerDifference::GivesOtherWords,
        )?;
        let read = crate::Phrase::read(vector.phrase).map_err(|_| {
            crate::self_check::FailureDetail::from(
                crate::self_check::KnownAnswerDifference::IsRefused,
            )
        })?;
        let parsed = super::parse(read.words()).map_err(stopped)?;
        expect(
            parsed.to_entropy() == entropy,
            crate::self_check::KnownAnswerDifference::GivesAnotherEntropy,
        )
    }
}

impl ComponentCheck for WordListCheck {
    fn id(&self) -> &'static str {
        "bip39-words"
    }

    fn label(&self) -> &'static str {
        "BIP39 words"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.one(|| {
            let mut text =
                String::with_capacity(usize::from(super::LIST_SIZE) * (super::LONGEST_WORD + 1));
            for word in Language::English.word_list() {
                text.push_str(word);
                text.push('\n');
            }
            expect(
                hex::encode(sha2::Sha256::digest(text.as_bytes())) == self.list_sha256,
                crate::self_check::KnownAnswerDifference::TheEnglishListDiffersFromEnglishTxt,
            )
        });
        // bitcoin_hashes computes the BIP39 checksum; FIPS 180-4's SHA-256("abc").
        findings.one(|| {
            use bitcoin_hashes::{sha256, Hash};
            expect(
                hex::encode(sha256::Hash::hash(b"abc").to_byte_array())
                    == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                crate::self_check::KnownAnswerDifference::TheChecksumSSha256GivesAnotherDigest,
            )
        });
        let vectors: Vec<TrezorVector> = match tier {
            Tier::Startup => STARTUP_VECTORS
                .iter()
                .filter_map(|&index| self.vectors.get(index).copied())
                .collect(),
            Tier::Full => self.vectors.to_vec(),
        };
        findings.each(
            crate::self_check::CaseKind::TestVector,
            &vectors,
            Self::vector,
        );
        // The first vector with its last word changed fails its checksum: "abandon" 12 times.
        findings.one(|| {
            let wrong = ["abandon"; 12].join(" ");
            expect_refusal(crate::Phrase::read(&wrong), "INVALID_PHRASE").map_err(|what| {
                crate::self_check::FailureDetail::Context {
                    context: crate::self_check::CheckContext::AWrongChecksum,
                    cause: Box::new(what),
                }
            })
        });
        findings.each(
            crate::self_check::CaseKind::Completion,
            &COMPLETIONS,
            |&(typed, expected)| {
                expect(
                    super::complete_word(typed) == expected,
                    crate::self_check::KnownAnswerDifference::Differs,
                )
            },
        );
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};
    use bip39::Mnemonic;

    #[test]
    fn the_word_list_passes_at_both_tiers() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(WordListCheck::new().run(tier), ComponentOutcome::Passed);
        }
        // The vectors parse back with the crate's own parser too.
        for vector in TREZOR_ENGLISH {
            let parsed = Mnemonic::parse_in(Language::English, vector.phrase).unwrap();
            assert_eq!(hex::encode(parsed.to_entropy()), vector.entropy);
        }
    }

    #[test]
    fn a_corrupted_list_digest_or_vector_fails() {
        let mut check = WordListCheck::new();
        check.list_sha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbdb";
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "the English list differs from english.txt".to_owned()
        );
        let mut vectors = TREZOR_ENGLISH;
        // The ff pattern of 24 words with its last word changed.
        vectors[11].phrase =
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                              zoo zoo zoo zoo zoo wrong";
        fails_with(
            WordListCheck {
                vectors: leak(vectors),
                ..WordListCheck::new()
            },
            "test vector 4 of 4 gives other words",
        );
        // A vector outside the startup set fails only the full self-test.
        let mut vectors = TREZOR_ENGLISH;
        vectors[23].entropy = "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90420";
        let mut check = WordListCheck {
            vectors: Box::leak(Box::new(vectors)),
            ..WordListCheck::new()
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        crate::self_check::assert_failed!(
            check.run(Tier::Full),
            "test vector 24 of 24 gives other words".to_owned()
        );
    }
}
