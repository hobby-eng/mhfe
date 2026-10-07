//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! "matches" or "does not match", and on a match with an address the path where it was found.
//! No part of the recovered phrase leaves the check, and a wrong password gives no hint of how
//! close it was. The re-encryption guard uses the same comparison: a phrase recovered to be
//! encrypted again comes out only once it is confirmed.

use crate::container::{ConfirmationNeeded, ContainerFacts};
use crate::engine::Argon2Engine;
use crate::memory::{LockedBytes, LockedText};
use crate::mhfe::{suite_3_state, PhraseLength, RecoveredPhrase, Recovery};
use crate::operation::{RoundCounter, Stage, StageCallback};
use crate::packing::{self, State};
use crate::phrase::locked_phrase_from_entropy;
use crate::suite::{Suite, ROUNDS};
use crate::wallet::{self, Address, DerivationPath, SearchLimits};
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

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
    /// The wallet check of a 24-word phrase drawn to pass it, as `mhfe new` does on request (the
    /// draft profile MHFE-WALLET-CHECK-SEED-1, [`crate::wallet_check`]), with its BIP39
    /// `passphrase`, which may not be empty (`WALLET_CHECK_NEEDS_PASSPHRASE`). Only the 24-word
    /// reading of the recovery is compared, as the profile defines the check for it alone
    /// ([`crate::wallet_check::verify_entropy`]). It tells a right password and passphrase from
    /// wrong ones with 16 bits, not which wallet it is, so it never confirms a recovery to encrypt
    /// again.
    WalletCheck { passphrase: &'a str },
}

impl Reference<'_> {
    /// The BIP39 passphrase the recovery is compared with; none for the built-in check, which
    /// says nothing about one.
    pub fn passphrase(&self) -> Option<&str> {
        match self {
            Self::BuiltInCheck { .. } => None,
            Self::Address { passphrase, .. }
            | Self::Fingerprint { passphrase, .. }
            | Self::WalletCheck { passphrase } => Some(passphrase),
        }
    }
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
        let (suite, x) = self.recover_to_check(container, password, reference, on_progress)?;
        compare_state(suite, &x, reference)
    }

    /// [`Mhfe::check`], reporting its two stages: the twelve rounds of the recovery as
    /// [`Stage::Recover`], then [`Stage::Compare`] once more at round 12 of 12, before the
    /// recovery is compared with `reference`, which for an address can take seconds.
    pub fn check_in_stages(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: StageCallback<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        let rounds = RoundCounter::starting_after(0, ROUNDS);
        let (suite, x) =
            self.recover_to_check(container, password, reference, &mut |round, _| {
                rounds.report(Stage::Recover, round, on_progress)
            })?;
        rounds.report(Stage::Compare, ROUNDS, on_progress)?;
        compare_state(suite, &x, reference)
    }

    /// The first part of a check: refuses a built-in check or a wallet check that cannot be, from
    /// the word counts and the passphrase alone and before any Argon2 work, then recovers the
    /// suite and the state `X` of `container`.
    fn recover_to_check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(Suite, LockedBytes), MhfeError> {
        let container_words = container.split_whitespace().count();
        let same_length = Suite::of_container(container_words) == Ok(Suite::SameLength);
        match reference {
            Reference::BuiltInCheck { .. } if same_length => {
                return Err(MhfeError::NoBuiltInCheck { container_words });
            }
            Reference::BuiltInCheck { words }
                if !packing::SHORT_WORD_COUNTS.contains(&words.get()) =>
            {
                return Err(MhfeError::InvalidWordCount(words.get()));
            }
            Reference::WalletCheck { .. } if same_length => {
                return Err(MhfeError::NoWalletCheck { container_words });
            }
            // The wallet check's own rule, the one every front end gets: it needs a passphrase.
            Reference::WalletCheck { passphrase } => wallet_check::require_passphrase(passphrase)?,
            _ => {}
        }
        self.recover_state(container, password, None, on_progress)
    }
}

/// The second part of a check: compares the state `x` recovered from a container of `suite` with
/// `reference`.
fn compare_state(
    suite: Suite,
    x: &[u8],
    reference: &Reference<'_>,
) -> Result<CheckOutcome, MhfeError> {
    if suite == Suite::SameLength {
        // The container's own length is the only reading.
        return compare(&locked_phrase_from_entropy(x)?, reference);
    }
    let x = suite_3_state(x)?;
    match reference {
        Reference::BuiltInCheck { words } => {
            Ok(CheckOutcome::of(packing::unpack(x, words.get()).is_ok()))
        }
        // The profile defines the wallet check for the 24-word reading alone, whose entropy is X
        // itself: a shorter reading would be a construction it does not define, and a match of
        // its own about once in 65,536 (AUD-010).
        Reference::WalletCheck { passphrase } => Ok(CheckOutcome::of(
            wallet_check::verify_entropy(x, passphrase)?,
        )),
        Reference::Address { .. } | Reference::Fingerprint { .. } => {
            // Every reading of X is compared: each short length that passes its check and the
            // 24-word reading, so that no accidental match hides the real phrase.
            for words in packing::matching_short_lengths(x).into_iter().chain([24]) {
                let phrase = read_phrase(x, words)?;
                let outcome = compare(&phrase, reference)?;
                if outcome.matches() {
                    return Ok(outcome);
                }
            }
            Ok(CheckOutcome::DoesNotMatch)
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
        self.recover_confirmed_reporting(
            container,
            password,
            words,
            confirmation,
            on_progress,
            &mut || Ok(()),
        )
    }

    /// [`Mhfe::recover_confirmed`], calling `before_compare` once the recovery's rounds are done
    /// and before a wallet reference is compared, which for an address can take seconds.
    pub(crate) fn recover_confirmed_reporting(
        &mut self,
        container: &str,
        password: &Password,
        words: WordCount,
        confirmation: Confirmation<'_>,
        on_progress: ProgressCallback<'_>,
        before_compare: &mut dyn FnMut() -> Result<(), MhfeError>,
    ) -> Result<RecoveredPhrase, MhfeError> {
        let facts = ContainerFacts::read(container)?;
        let has_check = facts.confirmation_needed(words)? == ConfirmationNeeded::BuiltInCheck;
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
        let length = match facts.suite() {
            // Its own length, which confirmation_needed has made sure of, is the only reading.
            Suite::SameLength => PhraseLength::Detect,
            Suite::TwentyFourWords => PhraseLength::Words(words),
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
            before_compare()?;
            if !compare(&phrase.phrase, reference)?.matches() {
                return Err(MhfeError::ReferenceMismatch);
            }
        }
        Ok(phrase)
    }
}

/// The reading of `x` as `words` words, in locked memory, as a recovered phrase is held while it
/// is compared: an address search can take seconds.
fn read_phrase(x: &State, words: usize) -> Result<LockedText, MhfeError> {
    locked_phrase_from_entropy(packing::unpack(x, words)?)
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
        Reference::WalletCheck { passphrase } => {
            Ok(CheckOutcome::of(wallet_check::verify(phrase, passphrase)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Argon2Cost, NativeEngine};
    use crate::{phrase_from_entropy, WorkFactor};

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
        // Without a passphrase the check is not offered: refused before any Argon2 work, as the
        // browser and wallet_check::verify refuse it (AUD-010).
        let mut rounds = 0;
        assert_eq!(
            mhfe.check(
                &container,
                &password,
                &Reference::WalletCheck { passphrase: "" },
                &mut |_, _| {
                    rounds += 1;
                    Ok(())
                }
            ),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(rounds, 0);
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

    /// A public passphrase with which the 12-word test phrase passes the wallet check's criterion
    /// as 12 words, under BE32(128), which the profile does not define; its 24-word reading fails
    /// (AUD-010, harness crypto-core/short_reading_wallet_check.py).
    const SHORT_READING_PASSPHRASE: &str = "aud010 public probe 11656";

    /// The wallet check compares only the 24-word reading of a recovery: a 12-word original whose
    /// own reading passes the criterion with a passphrase does not make a match (AUD-010).
    #[test]
    fn a_wallet_check_compares_the_24_word_reading_only() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = Password::new("public test password").unwrap();
        assert!(wallet_check::phrase_passes(ABANDON, SHORT_READING_PASSPHRASE).unwrap());
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        // The recovery reads as the 12-word phrase, which the built-in check confirms.
        let built_in = Reference::BuiltInCheck {
            words: WordCount::new(12).unwrap(),
        };
        assert!(mhfe
            .check(&container, &password, &built_in, none)
            .unwrap()
            .matches());
        let reference = Reference::WalletCheck {
            passphrase: SHORT_READING_PASSPHRASE,
        };
        assert_eq!(
            mhfe.check(&container, &password, &reference, none),
            Ok(CheckOutcome::DoesNotMatch)
        );
        assert_eq!(
            mhfe.check_in_stages(&container, &password, &reference, &mut |_, _, _| Ok(())),
            Ok(CheckOutcome::DoesNotMatch)
        );
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

    /// The twelve rounds of the recovery, then the comparison, which can be stopped as well.
    #[test]
    fn a_check_in_stages_reports_its_recovery_and_its_comparison() {
        let password = Password::new("public test password").unwrap();
        let mut mhfe = reduced();
        let container = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let reference = Reference::Fingerprint {
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
            passphrase: "",
        };
        let mut reports = Vec::new();
        let outcome = mhfe
            .check_in_stages(
                &container,
                &password,
                &reference,
                &mut |stage, round, rounds| {
                    reports.push((stage, round, rounds));
                    Ok(())
                },
            )
            .unwrap();
        assert!(outcome.matches());
        let mut expected: Vec<(Stage, u32, u32)> =
            (1..=12).map(|round| (Stage::Recover, round, 12)).collect();
        expected.push((Stage::Compare, 12, 12));
        assert_eq!(reports, expected);

        let stopped =
            mhfe.check_in_stages(&container, &password, &reference, &mut |stage, _, _| {
                if stage == Stage::Compare {
                    Err(MhfeError::Cancelled)
                } else {
                    Ok(())
                }
            });
        assert_eq!(stopped.err(), Some(MhfeError::Cancelled));
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
        assert_eq!(
            mhfe.check(
                &container,
                &password,
                &Reference::WalletCheck {
                    passphrase: "TREZOR"
                },
                &mut |_, _| Ok(())
            )
            .err(),
            Some(MhfeError::NoWalletCheck {
                container_words: 12
            })
        );
    }
}
