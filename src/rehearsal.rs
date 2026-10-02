//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! only "matches" or "does not match". No part of the recovered phrase leaves this module, and a
//! wrong password gives no hint of how close it was.

use zeroize::Zeroizing;

use crate::engine::Argon2Engine;
use crate::mhfe::{phrase_from_entropy, suite_3_state};
use crate::packing::{self, State};
use crate::suite::Suite;
use crate::wallet::{self, BitcoinAddress, DerivationPath, SearchLimits};
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount};

/// What the recovered phrase is compared with.
pub enum Reference<'a> {
    /// The built-in check value of a 12-, 15-, 18- or 21-word original in a 24-word container.
    /// It confirms that the recovery is consistent, not that it gives the same wallet, and it says
    /// nothing about a BIP39 passphrase. A 24-word original and a same-length container have no
    /// such check and are refused.
    BuiltInCheck { words: WordCount },
    /// A receiving address of the wallet, the strong check. The address is searched on the
    /// standard paths of its type within `limits`, or only at `path` when given.
    Address {
        address: &'a BitcoinAddress,
        passphrase: &'a str,
        path: Option<&'a DerivationPath>,
        limits: SearchLimits,
    },
    /// The BIP32 master key fingerprint: quick, but only 32 bits, so a weaker check.
    Fingerprint {
        fingerprint: [u8; 4],
        passphrase: &'a str,
    },
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Runs a full recovery and compares it with `reference`. Returns only whether it matches.
    pub fn check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<bool, MhfeError> {
        if let Reference::BuiltInCheck { words } = reference {
            // Refused before any Argon2 work, from the word count alone.
            let container_words = container.split_whitespace().count();
            if Suite::of_container(container_words) == Ok(Suite::SameLength) {
                return Err(MhfeError::NoBuiltInCheck { container_words });
            }
            if !packing::SHORT_WORD_COUNTS.contains(&words.get()) {
                return Err(MhfeError::InvalidWordCount(words.get()));
            }
        }
        let (suite, x) = self.recover_state(container, password, None, on_progress)?;
        if suite == Suite::SameLength {
            // The container's own length is the only reading.
            return phrase_matches(&phrase_from_entropy(&x)?, reference);
        }
        let x = suite_3_state(&x)?;
        match reference {
            Reference::BuiltInCheck { words } => Ok(packing::unpack(&x, words.get()).is_ok()),
            Reference::Address { .. } | Reference::Fingerprint { .. } => {
                // Every reading of X is compared: each short length that passes its check and
                // the 24-word reading, so that no accidental match hides the real phrase.
                for words in packing::matching_short_lengths(&x).into_iter().chain([24]) {
                    let phrase = read_phrase(&x, words)?;
                    if phrase_matches(&phrase, reference)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

fn read_phrase(x: &State, words: usize) -> Result<Zeroizing<String>, MhfeError> {
    let entropy = packing::unpack(x, words)?;
    phrase_from_entropy(&entropy)
}

fn phrase_matches(phrase: &str, reference: &Reference<'_>) -> Result<bool, MhfeError> {
    match reference {
        Reference::BuiltInCheck { .. } => Ok(false),
        Reference::Address {
            address,
            passphrase,
            path,
            limits,
        } => Ok(wallet::find_address(phrase, passphrase, address, *path, *limits)?.is_some()),
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => Ok(wallet::master_fingerprint(phrase, passphrase)? == *fingerprint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Argon2Cost, NativeEngine};
    use crate::WorkFactor;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn reduced() -> Mhfe<NativeEngine> {
        let cost = Argon2Cost {
            memory_kib: 256,
            passes: 1,
        };
        Mhfe::with_engine(
            WorkFactor::default(),
            NativeEngine::reduced_for_tests(cost).unwrap(),
        )
    }

    #[test]
    fn every_reference_matches_the_right_password_only() {
        let password = Password::new("public test password").unwrap();
        let wrong = Password::new("public test passwore").unwrap();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();

        let address: BitcoinAddress = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            .parse()
            .unwrap();
        let references = [
            Reference::BuiltInCheck {
                words: WordCount::new(12).unwrap(),
            },
            Reference::Address {
                address: &address,
                passphrase: "",
                path: None,
                limits: SearchLimits::default(),
            },
            Reference::Fingerprint {
                fingerprint: [0x73, 0xc5, 0xda, 0x0a],
                passphrase: "",
            },
        ];
        for reference in &references {
            assert!(mhfe
                .check(&container, &password, reference, &mut |_, _| Ok(()))
                .unwrap());
            assert!(!mhfe
                .check(&container, &wrong, reference, &mut |_, _| Ok(()))
                .unwrap());
        }

        // The right password with a wrong BIP39 passphrase is a different wallet.
        let with_passphrase = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "TREZOR",
        };
        assert!(!mhfe
            .check(&container, &password, &with_passphrase, &mut |_, _| Ok(()))
            .unwrap());
    }

    #[test]
    fn a_24_word_original_is_checked_against_the_wallet() {
        let password = Password::new("public test password").unwrap();
        let mut mhfe = reduced();
        let original = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal winner thank year wave sausage worth title";
        let container = mhfe
            .encrypt(original, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let fingerprint = wallet::master_fingerprint(original, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        assert!(mhfe
            .check(&container, &password, &reference, &mut |_, _| Ok(()))
            .unwrap());
        assert_eq!(
            mhfe.check(
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(24).unwrap()
                },
                &mut |_, _| Ok(())
            )
            .err(),
            Some(MhfeError::InvalidWordCount(24))
        );
    }

    #[test]
    fn a_same_length_container_is_checked_against_the_wallet_only() {
        let password = Password::new("public test password").unwrap();
        let wrong = Password::new("public test passwore").unwrap();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::SameLength, &mut |_, _| Ok(()))
            .unwrap();
        assert_eq!(container.split(' ').count(), 12);
        let reference = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "",
        };
        assert!(mhfe
            .check(&container, &password, &reference, &mut |_, _| Ok(()))
            .unwrap());
        assert!(!mhfe
            .check(&container, &wrong, &reference, &mut |_, _| Ok(()))
            .unwrap());
        assert_eq!(
            mhfe.check(
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(12).unwrap()
                },
                &mut |_, _| Ok(())
            )
            .err(),
            Some(MhfeError::NoBuiltInCheck {
                container_words: 12
            })
        );
    }
}
