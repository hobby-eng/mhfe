//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! "matches" or "does not match", and on a match with an address the path where it was found.
//! No part of the recovered phrase leaves the check, and a wrong password gives no hint of how
//! close it was. The re-encryption guard uses the same comparison: a phrase recovered to be
//! encrypted again comes out only once it is confirmed.

use zeroize::Zeroizing;

use crate::engine::Argon2Engine;
use crate::mhfe::{phrase_from_entropy, suite_3_state, PhraseLength, RecoveredPhrase, Recovery};
use crate::packing::{self, State};
use crate::suite::Suite;
use crate::wallet::{self, Address, DerivationPath, SearchLimits};
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount};

/// What a rehearsal found. A match on a receiving address names the path where the address was
/// found, which tells the person which account and address of the wallet it is; it is not part of
/// the phrase and is given only on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Matches { path: Option<DerivationPath> },
    DoesNotMatch,
}

impl CheckOutcome {
    pub fn matches(&self) -> bool {
        matches!(self, Self::Matches { .. })
    }

    /// The path of a matched address; `None` for any other outcome.
    pub fn path(&self) -> Option<&DerivationPath> {
        match self {
            Self::Matches { path } => path.as_ref(),
            Self::DoesNotMatch => None,
        }
    }

    fn of(matches: bool) -> Self {
        if matches {
            Self::Matches { path: None }
        } else {
            Self::DoesNotMatch
        }
    }
}

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
        address: &'a Address,
        passphrase: &'a str,
        path: Option<&'a DerivationPath>,
        limits: SearchLimits,
    },
    /// The BIP32 master key fingerprint: quick, but only 32 bits, so a weaker check.
    Fingerprint {
        fingerprint: [u8; 4],
        passphrase: &'a str,
    },
    /// The wallet check of a phrase that `mhfe new` made with one (a draft, [`crate::wallet_check`]),
    /// with its BIP39 `passphrase`, which may not be empty. It tells a right password and
    /// passphrase from wrong ones with 16 bits, not which wallet it is, so it never confirms a
    /// recovery to encrypt again.
    WalletCheck { passphrase: &'a str },
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Runs a full recovery and compares it with `reference`. Returns whether it matches, and for
    /// an address the path where it was found.
    pub fn check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
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
            return compare(&phrase_from_entropy(&x)?, reference);
        }
        let x = suite_3_state(&x)?;
        match reference {
            Reference::BuiltInCheck { words } => {
                Ok(CheckOutcome::of(packing::unpack(&x, words.get()).is_ok()))
            }
            Reference::Address { .. }
            | Reference::Fingerprint { .. }
            | Reference::WalletCheck { .. } => {
                // Every reading of X is compared: each short length that passes its check and
                // the 24-word reading, so that no accidental match hides the real phrase.
                for words in packing::matching_short_lengths(&x).into_iter().chain([24]) {
                    let phrase = read_phrase(&x, words)?;
                    let outcome = compare(&phrase, reference)?;
                    if outcome.matches() {
                        return Ok(outcome);
                    }
                }
                Ok(CheckOutcome::DoesNotMatch)
            }
        }
    }
}

/// How a phrase recovered to be encrypted again is confirmed (the re-encryption guard).
pub enum Confirmation<'a> {
    /// Its built-in check at the stated length: a 12- to 21-word original of a 24-word container
    /// only.
    BuiltInCheck,
    /// A receiving address or the fingerprint of the wallet, compared as the rehearsal check
    /// compares them.
    Wallet(&'a Reference<'a>),
    /// The owner compares the phrase with their backup and confirms it. The library cannot tell:
    /// the caller must show the phrase and go on only if the owner confirms it.
    Owner,
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Recovers the phrase of `container` to encrypt it again under a new password or settings,
    /// and gives it only once it is confirmed (the re-encryption guard), as `confirmation` says:
    /// a 12- to 21-word original of a 24-word container passes its built-in check at the length
    /// `words` the owner states in every case, and a 24-word original or a same-length container,
    /// which have none, need a wallet reference or the owner. Encrypting the phrase again under the
    /// old password and comparing proves nothing, as that gives the same container for every
    /// password, so it is not a confirmation. Everything is checked before the first Argon2 call.
    pub fn recover_confirmed(
        &mut self,
        container: &str,
        password: &Password,
        words: WordCount,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        let container_words = container.split_whitespace().count();
        let same_length = Suite::of_container(container_words) == Ok(Suite::SameLength);
        if same_length && words.get() != container_words {
            return Err(MhfeError::LengthChoiceNotApplicable { container_words });
        }
        let has_check = !same_length && packing::SHORT_WORD_COUNTS.contains(&words.get());
        let reference = match confirmation {
            // The built-in check is the stated length's own, not a reference of the wallet.
            // A wallet check has 16 bits: too few to seal a phrase on its own.
            Confirmation::Wallet(
                Reference::BuiltInCheck { .. } | Reference::WalletCheck { .. },
            )
            | Confirmation::BuiltInCheck
                if !has_check =>
            {
                return Err(MhfeError::ReferenceRequired)
            }
            Confirmation::Wallet(
                Reference::BuiltInCheck { .. } | Reference::WalletCheck { .. },
            )
            | Confirmation::BuiltInCheck => None,
            Confirmation::Wallet(reference) => Some(reference),
            Confirmation::Owner => None,
        };
        let length = if same_length {
            PhraseLength::Detect
        } else {
            PhraseLength::Words(words)
        };
        // A stated length gives one reading, which for a short length has passed its check.
        let Recovery::Phrase(phrase) = self.decrypt(container, password, length, on_progress)?
        else {
            return Err(MhfeError::Internal(
                "a stated length gave several readings".to_owned(),
            ));
        };
        if has_check && !phrase.verified {
            return Err(MhfeError::VerifierMismatch);
        }
        if let Some(reference) = reference {
            if !compare(&phrase.phrase, reference)?.matches() {
                return Err(MhfeError::ReferenceMismatch);
            }
        }
        Ok(phrase)
    }
}

fn read_phrase(x: &State, words: usize) -> Result<Zeroizing<String>, MhfeError> {
    let entropy = packing::unpack(x, words)?;
    phrase_from_entropy(&entropy)
}

fn compare(phrase: &str, reference: &Reference<'_>) -> Result<CheckOutcome, MhfeError> {
    match reference {
        Reference::BuiltInCheck { .. } => Ok(CheckOutcome::DoesNotMatch),
        Reference::Address {
            address,
            passphrase,
            path,
            limits,
        } => Ok(
            match wallet::find_address(phrase, passphrase, address, *path, *limits)? {
                Some(found) => CheckOutcome::Matches { path: Some(found) },
                None => CheckOutcome::DoesNotMatch,
            },
        ),
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => Ok(CheckOutcome::of(
            wallet::master_fingerprint(phrase, passphrase)? == *fingerprint,
        )),
        Reference::WalletCheck { passphrase } => Ok(CheckOutcome::of(wallet_check::phrase_passes(
            phrase, passphrase,
        )?)),
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

    /// The re-encryption guard: a phrase comes out only once confirmed.
    #[test]
    fn a_recovery_to_encrypt_again_needs_a_confirmation() {
        let password = Password::new("public test password").unwrap();
        let wrong = Password::new("public test passwore").unwrap();
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let twelve = WordCount::new(12).unwrap();
        let twenty_four = WordCount::new(24).unwrap();

        // A 12-word original in a 24-word container: its built-in check at the stated length.
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::BuiltInCheck,
                none,
            )
            .unwrap();
        assert_eq!(*phrase.phrase, ABANDON);
        assert!(matches!(
            mhfe.recover_confirmed(&container, &wrong, twelve, Confirmation::BuiltInCheck, none),
            Err(MhfeError::VerifierMismatch)
        ));

        // A 24-word original has no check: refused without a reference, before any Argon2 call.
        const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon art";
        let container = mhfe
            .encrypt(ART, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let mut rounds = 0;
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::BuiltInCheck,
                &mut |_, _| {
                    rounds += 1;
                    Ok(())
                }
            ),
            Err(MhfeError::ReferenceRequired)
        ));
        assert_eq!(rounds, 0);
        let fingerprint = wallet::master_fingerprint(ART, "").unwrap();
        let right = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&right),
                none,
            )
            .unwrap();
        assert_eq!(*phrase.phrase, ART);
        // The wrong password gives another valid phrase, which the reference refuses.
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &wrong,
                twenty_four,
                Confirmation::Wallet(&right),
                none
            ),
            Err(MhfeError::ReferenceMismatch)
        ));
        let other_passphrase = Reference::Fingerprint {
            fingerprint,
            passphrase: "TREZOR",
        };
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&other_passphrase),
                none
            ),
            Err(MhfeError::ReferenceMismatch)
        ));

        // The owner may confirm a 24-word original instead: the phrase comes out for showing.
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Owner,
                none,
            )
            .unwrap();
        assert_eq!(*phrase.phrase, ART);

        // A same-length container: its own length, and a reference.
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::SameLength, none)
            .unwrap();
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::BuiltInCheck,
                none
            ),
            Err(MhfeError::ReferenceRequired)
        ));
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                twenty_four,
                Confirmation::Wallet(&right),
                none
            ),
            Err(MhfeError::LengthChoiceNotApplicable {
                container_words: 12
            })
        ));
        let abandon = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "",
        };
        let phrase = mhfe
            .recover_confirmed(
                &container,
                &password,
                twelve,
                Confirmation::Wallet(&abandon),
                none,
            )
            .unwrap();
        assert_eq!(*phrase.phrase, ABANDON);
    }

    #[test]
    fn a_wallet_check_matches_a_phrase_made_with_it_and_never_confirms_a_rekey() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = Password::new("public test password").unwrap();
        let wrong = Password::new("public test passwore").unwrap();
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&76_562u64.to_be_bytes());
        let phrase = phrase_from_entropy(&entropy).unwrap();
        let container = mhfe
            .encrypt(&phrase, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let reference = Reference::WalletCheck {
            passphrase: "TREZOR",
        };
        assert!(mhfe
            .check(&container, &password, &reference, none)
            .unwrap()
            .matches());
        assert!(!mhfe
            .check(&container, &wrong, &reference, none)
            .unwrap()
            .matches());
        let other = Reference::WalletCheck {
            passphrase: "trezor",
        };
        assert!(!mhfe
            .check(&container, &password, &other, none)
            .unwrap()
            .matches());
        assert!(matches!(
            mhfe.check(
                &container,
                &password,
                &Reference::WalletCheck { passphrase: "" },
                none
            ),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        assert!(matches!(
            mhfe.recover_confirmed(
                &container,
                &password,
                WordCount::new(24).unwrap(),
                Confirmation::Wallet(&reference),
                none
            ),
            Err(MhfeError::ReferenceRequired)
        ));
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

        let address = Address::parse(
            wallet::Coin::Bitcoin,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        )
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
                .unwrap()
                .matches());
            assert!(!mhfe
                .check(&container, &wrong, reference, &mut |_, _| Ok(()))
                .unwrap()
                .matches());
        }

        // A matched address names its path: the first native SegWit receiving address.
        let found = mhfe
            .check(&container, &password, &references[1], &mut |_, _| Ok(()))
            .unwrap();
        assert_eq!(
            found.path().map(ToString::to_string).as_deref(),
            Some("m/84'/0'/0'/0/0")
        );

        // The right password with a wrong BIP39 passphrase is a different wallet.
        let with_passphrase = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "TREZOR",
        };
        assert!(!mhfe
            .check(&container, &password, &with_passphrase, &mut |_, _| Ok(()))
            .unwrap()
            .matches());
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
            .unwrap()
            .matches());
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
            .unwrap()
            .matches());
        assert!(!mhfe
            .check(&container, &wrong, &reference, &mut |_, _| Ok(()))
            .unwrap()
            .matches());
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
