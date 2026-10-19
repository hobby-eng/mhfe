//! The rehearsal check (specification: "Application requirements"): a full recovery that answers
//! "matches", "does not match" or "not verified", and on a match with an address the path where it
//! was found.
//! No part of the recovered phrase leaves the check, and a wrong password gives no hint of how
//! close it was. The re-encryption guard uses the same comparison: a phrase recovered to be
//! encrypted again comes out only once it is confirmed.

mod error;
pub use crate::check_state::PassedCheck;
use crate::CheckState;
pub use error::RehearsalError;

use crate::wallet::Fingerprint;

use crate::detection::{LengthDetection, Readings};
use crate::engine::Argon2Engine;
use crate::memory::LockedBytes;
use crate::mhfe::{read_as, read_same_length, suite_3_state, PhraseLength};
use crate::operation::{RoundCounter, Stage, StageCallback};
use crate::packing::{State, STATE_WORDS};
use crate::suite::{Suite, ROUNDS};
use crate::wallet::{self, Address, DerivationPath, SearchLimits};
use crate::wallet_check;
use crate::{Mhfe, MhfeError, Password, ProgressCallback, WordCount};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;
mod reencryption;
pub(crate) use reencryption::RekeyOrigin;

pub use reencryption::{Confirmation, RecoveredForRekey};

/// What a rehearsal found, under the length rules of recovery (specification: "Rehearsal
/// check"). A match on a receiving address names the path where the address was found, which
/// tells the person which account and address of the wallet it is; it is not part of the phrase
/// and is given only on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Exactly one verified reading, at the stated length or at the detected one that takes
    /// precedence over it, or a wallet reference that matches.
    Matches {
        /// Where the matching receiving address was found; `None` for any other reference.
        path: Option<DerivationPath>,
    },
    /// Only readings that nothing verifies: a 24-word reading without a wallet reference, which
    /// a pass of the 16-bit wallet check does not change, or several lengths that match with none
    /// of them stated, which [`CheckEvidence::matching_lengths`] lists.
    NotVerified,
    /// No reading (a stated short length that nothing matches, or a lone 24-word reading that fails
    /// the wallet check it was drawn to pass), or a reference that the recovery does not match.
    DoesNotMatch,
}

impl CheckEvidence {
    /// Whether detection left no verified length, so that the next comparison must use a stated
    /// short length, an address or the fingerprint, rather than detection or the wallet check.
    pub fn asks_length(&self) -> bool {
        self.asks_length
    }

    /// The outcome compared with the supplied reference.
    pub fn outcome(&self) -> &CheckOutcome {
        &self.outcome
    }

    /// The one short reading whose built-in check passed, where length rules chose one.
    pub fn built_in_check(&self) -> Option<usize> {
        self.built_in_check
    }

    /// The lengths whose built-in checks passed, in ascending order.
    pub fn matching_lengths(&self) -> &[usize] {
        &self.matching_lengths
    }

    /// Whether the eligible 24-word reading passed its wallet check.
    pub fn wallet_check(&self) -> Option<bool> {
        self.wallet_check
    }

    /// The original seed phrase's own checks that passed, in the order a front end lists them:
    /// the built-in check of the verified reading or those of the several lengths that pass, then
    /// the 16-bit check, only where it passes. A phrase drawn without it can pass by chance.
    pub fn own_checks_passed(&self) -> Vec<PassedCheck> {
        let mut passed = Vec::new();
        match (self.built_in_check, &self.matching_lengths[..]) {
            (Some(words), _) => passed.push(PassedCheck::BuiltInCheck(words)),
            (None, []) => {}
            (None, lengths) => passed.push(PassedCheck::BuiltInChecks(lengths.to_vec())),
        }
        if self.wallet_check == Some(true) {
            passed.push(PassedCheck::WalletCheck);
        }
        passed
    }
}

impl CheckOutcome {
    /// Whether the outcome is [`CheckOutcome::Matches`].
    pub fn matches(&self) -> bool {
        matches!(self, Self::Matches { .. })
    }

    /// The path of a matched address; `None` for any other outcome.
    pub fn path(&self) -> Option<&DerivationPath> {
        match self {
            Self::Matches { path } => path.as_ref(),
            Self::NotVerified | Self::DoesNotMatch => None,
        }
    }

    /// The result as the browser package names it: "matches", "notVerified" or "doesNotMatch".
    pub fn id(&self) -> &'static str {
        self.state().id()
    }

    /// The result in the specification's words, which scripts read.
    pub fn text(&self) -> &'static str {
        self.state().text()
    }

    pub(crate) fn state(&self) -> CheckState {
        match self {
            Self::Matches { .. } => CheckState::Matches,
            Self::NotVerified => CheckState::NotVerified,
            Self::DoesNotMatch => CheckState::DoesNotMatch,
        }
    }

    /// The outcome of the length rules of recovery for a `stated` length or none: exactly one
    /// verified reading matches, a 24-word reading alone or several readings are not verified, and
    /// no reading does not match.
    fn of_length_rules(detection: &LengthDetection<'_>, stated: Option<usize>) -> Self {
        match detection.under_length_rules(stated) {
            Readings::NoReading => Self::DoesNotMatch,
            _ if detection.verified_length(stated).is_some() => Self::Matches { path: None },
            Readings::One(_) | Readings::Several(_) => Self::NotVerified,
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

/// What a check found, its reference's outcome first, and what the same recovery shows beside it:
/// a front end lists every check that passed.
///
/// Only a recovery builds this evidence; a caller cannot alter its outcome:
///
/// ```compile_fail
/// fn forge(evidence: &mut mhfe::rehearsal::CheckEvidence) {
///     evidence.outcome = mhfe::rehearsal::CheckOutcome::Matches { path: None };
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckEvidence {
    asks_length: bool,
    /// How the recovery compared with the reference.
    outcome: CheckOutcome,
    /// The length of the one verified reading the length rules give: the stated length where its
    /// built-in check passes, else the one short length whose check passes. `None` where no
    /// short length passes, where several do and none of them was stated, and for a same-length
    /// container, which has no built-in check.
    built_in_check: Option<usize>,
    /// Every 12- to 21-word length whose built-in check passes, in ascending order: one for a
    /// short original's own length is included, and other lengths can pass by chance, including
    /// a shorter reading of a 24-word original or a wrong-password state. Empty for a same-length
    /// container.
    matching_lengths: Vec<usize>,
    /// Whether the 24-word reading passes the phrase + passphrase check of `mhfe new` (the 16-bit
    /// wallet check) with the reference's passphrase, or the empty one where it has none, where
    /// that reading comes out: no short length's check passes, several do, or the reference
    /// matched the 24-word reading. `None` for the built-in check, for a same-length container,
    /// and when exactly one short length passes and the reference did not match the 24-word
    /// reading. A phrase drawn without that check can pass by chance; a failure matters only
    /// when the owner knows it was drawn with the check.
    wallet_check: Option<bool>,
}

/// What the recovered phrase is compared with.
pub enum Reference<'a> {
    /// The built-in check value of a 12-, 15-, 18- or 21-word original in a 24-word container,
    /// `words` the length the person states, under the length rules of recovery: a check that
    /// passes at another short length takes precedence and matches, and
    /// [`CheckEvidence::built_in_check`] names that length; several other lengths that pass are
    /// not verified, and none gives "does not match". It confirms that the recovery is consistent,
    /// not that it gives the same wallet, and it says nothing about a BIP39 passphrase. A 24-word
    /// original and a same-length container have no such check and are refused.
    BuiltInCheck {
        /// The length the person states.
        words: WordCount,
    },
    /// A receiving address of the wallet, the strong check. The address is searched on the
    /// standard paths of its type within `limits`, or only at `path` when given.
    Address {
        /// The receiving address.
        address: &'a Address,
        /// The wallet's BIP39 passphrase; empty for none.
        passphrase: &'a str,
        /// The one path to look at, in place of the standard paths.
        path: Option<&'a DerivationPath>,
        /// How many accounts and addresses of the standard paths are searched.
        limits: SearchLimits,
    },
    /// The BIP32 master key fingerprint: quick, but only 32 bits, so a weaker check.
    Fingerprint {
        /// The four bytes of the fingerprint.
        fingerprint: Fingerprint,
        /// The wallet's BIP39 passphrase; empty for none.
        passphrase: &'a str,
    },
    /// The wallet check of a 24-word phrase drawn to pass it, as `mhfe new` does on request (the
    /// draft profile MHFE-WALLET-CHECK-SEED-1, [`crate::wallet_check`]), with its BIP39
    /// `passphrase`, which may not be empty (`WALLET_CHECK_NEEDS_PASSPHRASE`). The length rules of
    /// recovery come first: a 12- to 21-word reading whose built-in check passes takes precedence
    /// and matches, as without a reference (AUD-024-FUN010). Where they leave the 24-word reading
    /// alone, it is compared, as the profile defines the check for it alone
    /// ([`crate::wallet_check::WalletCheck::verify_entropy`]). It tells a right password and passphrase from
    /// wrong ones with 16 bits, not which wallet it is: a pass leaves the reading not verified (the
    /// specification's recovery rules), and a failure of a phrase the person says was drawn with
    /// the check does not match. It never confirms a recovery to encrypt again.
    WalletCheck {
        /// The BIP39 passphrase the phrase was drawn with.
        passphrase: &'a str,
    },
    /// The original seed phrase's own checks, its length detected (`detection`): the built-in
    /// check of whichever 12- to 21-word length passes it, or else, with a BIP39 `passphrase`,
    /// which may not be empty, the phrase + passphrase check of the 24-word reading, which a check
    /// reports beside a "not verified" 24-word reading and a search for missing words takes as a
    /// pass. Like those checks it tells a right password from a wrong one, not which wallet it is.
    /// A same-length container has neither and is refused.
    OwnChecks {
        /// The BIP39 passphrase for the check of the 24-word reading, if the wallet has one.
        passphrase: Option<&'a str>,
    },
}

/// A reference as a front end reads it, owning what [`Reference`] borrows except the BIP39
/// passphrase, which the front end holds apart, in locked memory, and gives with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTarget {
    /// A receiving address, searched on the standard paths of its type, or only at `path`.
    Address {
        /// The receiving address.
        address: Address,
        /// The one path to look at, in place of the standard paths.
        path: Option<DerivationPath>,
    },
    /// The BIP32 master key fingerprint.
    Fingerprint(Fingerprint),
    /// The built-in check at a stated length, or with the length detected the phrase's own
    /// checks.
    Length(PhraseLength),
    /// The phrase + passphrase check.
    WalletCheck,
}

impl ReferenceTarget {
    /// The reference to compare with, with `passphrase` the BIP39 passphrase it is compared
    /// with: the wallet's for an address or a fingerprint, the original seed phrase's for its own
    /// checks, empty for none.
    pub fn with<'a>(&'a self, passphrase: &'a str) -> Reference<'a> {
        match self {
            Self::Address { address, path } => Reference::Address {
                address,
                passphrase,
                path: path.as_ref(),
                limits: SearchLimits::default(),
            },
            Self::Fingerprint(fingerprint) => Reference::Fingerprint {
                fingerprint: *fingerprint,
                passphrase,
            },
            Self::Length(PhraseLength::Words(words)) => Reference::BuiltInCheck { words: *words },
            Self::Length(PhraseLength::Detect) => Reference::own_checks(passphrase),
            Self::WalletCheck => Reference::WalletCheck { passphrase },
        }
    }

    /// Refuses a BIP39 passphrase that is not empty beside a stated length, the built-in check,
    /// which takes none: [`ReferenceTarget::with`] would drop it (AUD-024-API017).
    pub fn refuse_unused(&self, passphrase: &str) -> Result<(), RehearsalError> {
        match self {
            Self::Length(PhraseLength::Words(_)) => {
                PassphraseReferences::Check.refuse_unused(passphrase)
            }
            _ => Ok(()),
        }
    }
}

/// The references that take a BIP39 passphrase in an operation, which a refusal of an unused one
/// names: a rehearsal check's wallet check takes one too, while a rekey is confirmed only by the
/// wallet's address or fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseReferences {
    /// The references of a rehearsal check.
    Check,
    /// The confirmations of a rekey.
    Rekey,
}

impl PassphraseReferences {
    /// Refuses a BIP39 `passphrase` that is not empty where the comparison takes none: the built-in
    /// check, and the owner's comparison with the backup in a rekey. Dropped without a word, it would
    /// let a person believe the wallet with that passphrase was compared (`INVALID_REQUEST`, naming
    /// the `references` that take one).
    pub fn refuse_unused(self, passphrase: &str) -> Result<(), RehearsalError> {
        if passphrase.is_empty() {
            Ok(())
        } else {
            Err(RehearsalError::UnusedPassphrase(self))
        }
    }

    /// The references, as a message names them.
    fn names(self) -> &'static str {
        match self {
            Self::Check => "an address, a fingerprint or the wallet check",
            Self::Rekey => "an address or a fingerprint",
        }
    }
}

impl<'a> Reference<'a> {
    /// The BIP39 passphrase the recovery is compared with; none for the built-in check, which
    /// says nothing about one.
    pub fn passphrase(&self) -> Option<&str> {
        match self {
            Self::BuiltInCheck { .. } => None,
            Self::Address { passphrase, .. }
            | Self::Fingerprint { passphrase, .. }
            | Self::WalletCheck { passphrase } => Some(passphrase),
            Self::OwnChecks { passphrase } => *passphrase,
        }
    }

    /// The length of the original seed phrase the person states: the built-in check's; `None`
    /// for every other reference, with which the length rules detect it.
    fn stated_words(&self) -> Option<usize> {
        match self {
            Self::BuiltInCheck { words } => Some(words.get()),
            _ => None,
        }
    }

    /// The BIP39 passphrase the recovery is compared with when one is given, not empty: what shows
    /// that the wallet has one.
    pub fn given_passphrase(&self) -> Option<&str> {
        self.passphrase().filter(|text| !text.is_empty())
    }

    /// The phrase's own checks with the BIP39 passphrase of the original seed phrase as typed:
    /// empty for none, which leaves the built-in check alone.
    pub fn own_checks(passphrase: &'a str) -> Self {
        Self::OwnChecks {
            passphrase: (!passphrase.is_empty()).then_some(passphrase),
        }
    }

    /// Whether it identifies the wallet, a receiving address or the master key fingerprint,
    /// rather than the phrase's own checks, which tell a right password from a wrong one but not
    /// which wallet it is. Only such a reference confirms a phrase without a built-in check to
    /// encrypt it again, and tells apart the candidates of a search, several of which may pass a
    /// check of the phrase. A wallet check has 16 bits: too few to seal a phrase on its own.
    pub fn identifies_wallet(&self) -> bool {
        matches!(self, Self::Address { .. } | Self::Fingerprint { .. })
    }
}

impl<E: Argon2Engine> Mhfe<E> {
    /// Runs a full recovery and compares it with `reference`. Returns the outcome, and on a match
    /// with an address the path where it was found.
    pub fn check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        let recovered = self.recover_for_check(container, password, reference, on_progress)?;
        Ok(recovered.compare(reference)?.outcome)
    }

    /// Recovers `container` for a check against `reference` and any reference after it, such as
    /// an address once detection found no length ([`RecoveredForCheck`]). A `reference` the
    /// container cannot be checked with is refused first, before any Argon2 work.
    pub fn recover_for_check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<RecoveredForCheck, MhfeError> {
        let (suite, state) = self.recover_to_check(container, password, reference, on_progress)?;
        Ok(RecoveredForCheck {
            container_words: container.split_whitespace().count(),
            suite,
            state,
        })
    }

    /// [`Mhfe::recover_for_check`], reporting its two stages: the twelve rounds of the recovery as
    /// [`Stage::Recover`], then [`Stage::Compare`] once more at round 12 of 12, before the
    /// recovery is compared, which for an address can take seconds.
    pub fn recover_for_check_in_stages(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: StageCallback<'_>,
    ) -> Result<RecoveredForCheck, MhfeError> {
        let rounds = RoundCounter::starting_after(0, ROUNDS);
        let recovered =
            self.recover_for_check(container, password, reference, &mut |round, _| {
                rounds.report(Stage::Recover, round, on_progress)
            })?;
        rounds.report(Stage::Compare, ROUNDS, on_progress)?;
        Ok(recovered)
    }

    /// The first part of a check: refuses a reference the container cannot be checked with, before
    /// any Argon2 work, then recovers the suite and the state `X` of `container`.
    fn recover_to_check(
        &mut self,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: ProgressCallback<'_>,
    ) -> Result<(Suite, LockedBytes), MhfeError> {
        refuse_impossible(container.split_whitespace().count(), reference)?;
        self.recover_state(container, password, None, on_progress)
            .map_err(Into::into)
    }
}

/// A container recovered for a check: its suite and state `X` in locked memory, which a front end
/// compares with one reference after another without the rounds again, such as an address once
/// detection found no length the built-in check passes. No part of the phrase comes out of it,
/// only whether a reference matches, and the state is wiped when it is dropped.
pub struct RecoveredForCheck {
    container_words: usize,
    suite: Suite,
    state: LockedBytes,
}

impl RecoveredForCheck {
    /// Compares the recovery with `reference`, refusing one the container cannot be checked with,
    /// as [`Mhfe::check`] refuses it, with what the recovery shows beside it ([`CheckEvidence`]).
    pub fn compare(&self, reference: &Reference<'_>) -> Result<CheckEvidence, MhfeError> {
        refuse_impossible(self.container_words, reference)?;
        evidence_of(self.suite, &self.state, reference)
    }

    /// The comparison after detection asked for a length. Detection and the 16-bit wallet
    /// check cannot answer that question again; a short stated length uses its built-in check,
    /// and a wallet address or fingerprint may identify any reading. No Argon2 rounds repeat.
    pub fn compare_after_detection(
        &self,
        reference: &Reference<'_>,
    ) -> Result<CheckEvidence, MhfeError> {
        if !self
            .compare(&Reference::OwnChecks { passphrase: None })?
            .asks_length()
        {
            return Err(MhfeError::Rehearsal(RehearsalError::DetectionNotRequested));
        }
        if !matches!(
            reference,
            Reference::BuiltInCheck { .. }
                | Reference::Address { .. }
                | Reference::Fingerprint { .. }
        ) {
            return Err(MhfeError::Rehearsal(RehearsalError::DetectionReference));
        }
        self.compare(reference)
    }

    /// Whether any of the original seed phrase's own checks passes, its length detected: the
    /// built-in check of a short length, or with `passphrase` the 16-bit phrase + passphrase check
    /// of the 24-word reading, which a check reports only beside "not verified" but which a search
    /// for missing words takes, since a wrong candidate passes it about once in 65,536.
    pub(crate) fn passes_own_checks(&self, passphrase: Option<&str>) -> Result<bool, MhfeError> {
        refuse_impossible(self.container_words, &Reference::OwnChecks { passphrase })?;
        LengthDetection::of(suite_3_state(&self.state)?)
            .passes_own_checks(passphrase)
            .map_err(Into::into)
    }
}

/// Refuses a built-in check, a wallet check or the phrase's own checks that a container of
/// `container_words` words cannot have, from the word counts and the passphrase alone.
pub(crate) fn refuse_impossible(
    container_words: usize,
    reference: &Reference<'_>,
) -> Result<(), MhfeError> {
    // A passphrase too long for any seed, before any work (AUD-024-API019).
    if let Some(passphrase) = reference.passphrase() {
        crate::wallet::require_passphrase_size(passphrase)?;
    }
    // A count no container has is refused where the container is read, after this.
    let Ok(suite) = Suite::of_container(container_words) else {
        return Ok(());
    };
    let built_in_lengths = suite.built_in_check_lengths();
    match reference {
        Reference::BuiltInCheck { .. } | Reference::OwnChecks { .. }
            if built_in_lengths.is_empty() =>
        {
            return Err(MhfeError::Format(crate::FormatError::NoBuiltInCheck {
                container_words,
            }));
        }
        Reference::BuiltInCheck { words } if !built_in_lengths.contains(&words.get()) => {
            return Err(MhfeError::Format(
                crate::FormatError::NoBuiltInCheckAtLength(words.get()),
            ));
        }
        // The wallet check's own rule, the one every front end gets: it needs a passphrase.
        Reference::WalletCheck { passphrase } => {
            require_wallet_check(suite, container_words)?;
            wallet_check::WalletCheck::new(passphrase).require_passphrase()?;
        }
        Reference::OwnChecks {
            passphrase: Some(passphrase),
        } => wallet_check::WalletCheck::new(passphrase).require_passphrase()?,
        _ => {}
    }
    Ok(())
}

/// Whether this container suite can use the wallet check, before a passphrase is asked for.
pub(crate) fn require_wallet_check(suite: Suite, container_words: usize) -> Result<(), MhfeError> {
    if suite.holds_full_state() {
        Ok(())
    } else {
        Err(MhfeError::Format(crate::FormatError::NoWalletCheck {
            container_words,
        }))
    }
}

/// The reference's outcome and the checks of the original seed phrase itself, from the state `x`
/// recovered from a container of `suite`.
fn evidence_of(
    suite: Suite,
    x: &[u8],
    reference: &Reference<'_>,
) -> Result<CheckEvidence, MhfeError> {
    if suite == Suite::SameLength {
        // The container's own length is the only reading, and it has no check of its own.
        return Ok(CheckEvidence {
            asks_length: false,
            outcome: compare(read_same_length(x)?.phrase(), reference)?,
            built_in_check: None,
            matching_lengths: Vec::new(),
            wallet_check: None,
        });
    }
    let x = suite_3_state(x)?;
    let detection = LengthDetection::of(x);
    let (outcome, matched_words) = compare_state(x, &detection, reference)?;
    // The 16-bit wallet check on the 24-word reading, with the passphrase compared or the empty
    // one, wherever that reading comes out: no short length passes, several do, or a reference
    // matched the 24-word reading beside one that passes (AUD-017). A built-in check states a
    // short length, and no passphrase.
    let reads_24_words = detection.short_lengths().len() != 1 || matched_words == Some(STATE_WORDS);
    let wallet_check = match reference {
        Reference::BuiltInCheck { .. } => None,
        _ if !reads_24_words => None,
        other => Some(detection.source_check(other.passphrase().unwrap_or(""))?),
    };
    Ok(CheckEvidence {
        asks_length: matches!(reference, Reference::OwnChecks { .. })
            && outcome == CheckOutcome::NotVerified,
        outcome,
        built_in_check: detection.verified_length(reference.stated_words()),
        matching_lengths: detection.short_lengths().to_vec(),
        wallet_check,
    })
}

/// The second part of a check: compares the recovered state `x` of a 24-word container, which
/// `detection` has read, with `reference`, with the length of the reading that an address or the
/// fingerprint matched.
fn compare_state(
    x: &State,
    detection: &LengthDetection<'_>,
    reference: &Reference<'_>,
) -> Result<(CheckOutcome, Option<usize>), MhfeError> {
    match reference {
        // The length rules of recovery: a short length whose check passes takes precedence over
        // the stated one, which the evidence then names (AUD-015-FUN001), and several that pass
        // with none of them stated are not verified (AUD-023-FUN002).
        Reference::BuiltInCheck { .. } | Reference::OwnChecks { .. } => Ok((
            CheckOutcome::of_length_rules(detection, reference.stated_words()),
            None,
        )),
        // The length rules of recovery first: a short length whose built-in check passes is a
        // verified reading that takes precedence (AUD-024-FUN010). Where they leave the 24-word
        // reading alone, the owner says it was drawn to pass the check, which leaves no reading
        // where it fails; a pass is 16 bits, not the wallet's identity, and the reading stays
        // not verified.
        Reference::WalletCheck { passphrase } => Ok((
            match detection.under_length_rules(None) {
                Readings::One(STATE_WORDS) if detection.passes_wallet_check(passphrase)? => {
                    CheckOutcome::NotVerified
                }
                Readings::One(STATE_WORDS) => CheckOutcome::DoesNotMatch,
                _ => CheckOutcome::of_length_rules(detection, None),
            },
            None,
        )),
        Reference::Address { .. } | Reference::Fingerprint { .. } => {
            // Every reading the detection gives is compared, whatever length the person has.
            for words in detection.readings() {
                // Held in locked memory while it is compared: an address search can take seconds.
                let reading = read_as(x, words)?;
                let outcome = compare(reading.phrase(), reference)?;
                if outcome.matches() {
                    return Ok((outcome, Some(words)));
                }
            }
            Ok((CheckOutcome::DoesNotMatch, None))
        }
    }
}

pub(crate) fn compare(phrase: &str, reference: &Reference<'_>) -> Result<CheckOutcome, MhfeError> {
    compare_until(phrase, reference, &|| false)
}

/// [`compare`] that an address search ends with [`MhfeError::Cancelled`] once `stopped` says so,
/// between the addresses it derives.
pub(crate) fn compare_until(
    phrase: &str,
    reference: &Reference<'_>,
    stopped: &dyn Fn() -> bool,
) -> Result<CheckOutcome, MhfeError> {
    match reference {
        Reference::BuiltInCheck { .. } => Ok(CheckOutcome::DoesNotMatch),
        Reference::Address {
            address,
            passphrase,
            path,
            limits,
        } => Ok(
            match address.find_until(phrase, passphrase, *path, *limits, stopped)? {
                Some(found) => CheckOutcome::Matches { path: Some(found) },
                None => CheckOutcome::DoesNotMatch,
            },
        ),
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => Ok(CheckOutcome::of(
            wallet::Fingerprint::of(phrase, passphrase)? == *fingerprint,
        )),
        Reference::WalletCheck { passphrase } => Ok(CheckOutcome::of(
            wallet_check::WalletCheck::new(passphrase).verify(phrase)?,
        )),
        // The phrase's own checks are read from the recovered state, never from one reading.
        Reference::OwnChecks { .. } => Ok(CheckOutcome::DoesNotMatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phrase::phrase_from_entropy;
    use crate::test_support::{
        container_of, counted, reduced, test_password, wrong_password, ABANDON_12 as ABANDON,
        ABANDON_12_FINGERPRINT, ABANDON_24, AMBIGUOUS_12_21, EMPTY_COUNTER, TREZOR_COUNTER,
    };

    /// A check of `container` against `reference` with no progress to report.
    fn check<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        password: &Password,
        reference: &Reference<'_>,
    ) -> Result<CheckOutcome, MhfeError> {
        mhfe.check(container, password, reference, &mut |_, _| Ok(()))
    }

    /// What a check of `container` against `reference` shows, with no progress to report.
    fn evidence_for<E: Argon2Engine>(
        mhfe: &mut Mhfe<E>,
        container: &str,
        reference: &Reference<'_>,
    ) -> CheckEvidence {
        mhfe.recover_for_check(container, &test_password(), reference, &mut |_, _| Ok(()))
            .unwrap()
            .compare(reference)
            .unwrap()
    }

    #[test]
    fn an_empty_passphrase_wallet_check_stays_in_rehearsal_evidence() {
        let mut mhfe = reduced();
        let phrase = phrase_from_entropy(&counted(EMPTY_COUNTER)).unwrap();
        let container = container_of(&mut mhfe, &phrase, Suite::TwentyFourWords);
        let evidence = evidence_for(
            &mut mhfe,
            &container,
            &Reference::OwnChecks { passphrase: None },
        );
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(evidence.wallet_check, Some(true));
        assert_eq!(evidence.own_checks_passed(), [PassedCheck::WalletCheck]);
        let reference = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(&phrase, "").unwrap(),
            passphrase: "",
        };
        let matched = evidence_for(&mut mhfe, &container, &reference);
        assert!(matched.outcome.matches());
        assert_eq!(matched.wallet_check, Some(true));
        assert_eq!(matched.own_checks_passed(), [PassedCheck::WalletCheck]);
    }

    /// A check tells beside its reference the original seed phrase's own checks: the built-in
    /// check of a 12-word original, and for a 24-word one the 16-bit wallet check with the
    /// reference's passphrase or none. This fixture fails; another unchecked phrase can pass by chance.
    #[test]
    fn a_check_lists_the_checks_of_the_phrase_itself() {
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let fingerprint = wallet::Fingerprint::of(ABANDON, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let evidence = evidence_for(&mut mhfe, &container, &reference);
        assert!(evidence.outcome.matches());
        assert_eq!(evidence.built_in_check, Some(12));
        assert_eq!(evidence.wallet_check, None);
        let with_passphrase = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(ABANDON, "TREZOR").unwrap(),
            passphrase: "TREZOR",
        };
        let evidence = evidence_for(&mut mhfe, &container, &with_passphrase);
        assert!(evidence.outcome.matches());
        // A 12-word phrase: the 24-word reading does not come out, so it is not checked.
        assert_eq!(evidence.wallet_check, None);
        // This unchecked public fixture fails with either passphrase; other phrases can pass by chance.
        let phrase = crate::phrase::phrase_from_entropy(&[7u8; 32]).unwrap();
        let container = container_of(&mut mhfe, &phrase, Suite::TwentyFourWords);
        let reference = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(&phrase, "").unwrap(),
            passphrase: "",
        };
        let evidence = evidence_for(&mut mhfe, &container, &reference);
        assert!(evidence.outcome.matches());
        assert_eq!(evidence.built_in_check, None);
        assert_eq!(evidence.wallet_check, Some(false));
    }

    /// A wallet check that passes leaves a phrase drawn with it not verified, with the 16-bit
    /// pass among the evidence; one that fails does not match (AUD-023-FUN002).
    #[test]
    fn a_wallet_check_leaves_a_phrase_made_with_it_not_verified_and_never_confirms_a_rekey() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        // The public vector of the wallet check: 24 zero bytes and 76,562, with "TREZOR".
        let entropy = counted(TREZOR_COUNTER);
        let phrase = phrase_from_entropy(&entropy).unwrap();
        let container = mhfe
            .encrypt(&phrase, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let reference = Reference::WalletCheck {
            passphrase: "TREZOR",
        };
        let evidence = evidence_for(&mut mhfe, &container, &reference);
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(evidence.wallet_check, Some(true));
        assert_eq!(
            mhfe.check(&container, &wrong, &reference, none),
            Ok(CheckOutcome::DoesNotMatch)
        );
        let other = Reference::WalletCheck {
            passphrase: "trezor",
        };
        assert_eq!(
            mhfe.check(&container, &password, &other, none),
            Ok(CheckOutcome::DoesNotMatch)
        );
        // Without a passphrase the check is not offered: refused before any Argon2 work, as the
        // browser and WalletCheck::verify refuse it (AUD-010).
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
            Err(MhfeError::WalletCheck(
                crate::wallet_check::WalletCheckError::NeedsPassphrase
            ))
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
            Err(MhfeError::Rehearsal(
                crate::RehearsalError::ReferenceRequired
            ))
        ));
    }

    /// The phrase's own checks with its length detected, under the length rules of recovery: a
    /// 12-word original matches by its built-in check with or without a passphrase; a 24-word
    /// reading, of a right password or a wrong one, is not verified, and a pass of the 16-bit check
    /// is evidence beside it, which a search for missing words takes. An empty passphrase and a
    /// same-length container are refused before any Argon2 work (AUD-023-FUN002).
    #[test]
    fn the_own_checks_detect_the_length() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        let wrong = wrong_password();
        let own = |passphrase| Reference::OwnChecks { passphrase };
        let short = mhfe
            .encrypt(ABANDON, &password, Suite::TwentyFourWords, none)
            .unwrap();
        for passphrase in [None, Some("TREZOR")] {
            let evidence = evidence_for(&mut mhfe, &short, &own(passphrase));
            assert!(evidence.outcome.matches());
            assert_eq!(evidence.built_in_check, Some(12));
            assert_eq!(evidence.matching_lengths, [12]);
        }
        assert_eq!(
            mhfe.check(&short, &wrong, &own(None), none),
            Ok(CheckOutcome::NotVerified)
        );
        let drawn = phrase_from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        let full = mhfe
            .encrypt(&drawn, &password, Suite::TwentyFourWords, none)
            .unwrap();
        let recovered = mhfe
            .recover_for_check(&full, &password, &own(Some("TREZOR")), none)
            .unwrap();
        let evidence = recovered.compare(&own(Some("TREZOR"))).unwrap();
        assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
        assert_eq!(
            (
                evidence.built_in_check,
                evidence.matching_lengths.as_slice(),
                evidence.wallet_check
            ),
            (None, &[][..], Some(true))
        );
        assert!(recovered.passes_own_checks(Some("TREZOR")).unwrap());
        for passphrase in [None, Some("trezor")] {
            assert_eq!(
                recovered.compare(&own(passphrase)).unwrap().outcome,
                CheckOutcome::NotVerified
            );
            assert!(!recovered.passes_own_checks(passphrase).unwrap());
        }
        assert_eq!(
            mhfe.check(&full, &password, &own(Some("")), none),
            Err(MhfeError::WalletCheck(
                crate::wallet_check::WalletCheckError::NeedsPassphrase
            ))
        );
        let same_length = mhfe
            .encrypt(ABANDON, &password, Suite::SameLength, none)
            .unwrap();
        assert_eq!(
            mhfe.check(&same_length, &password, &own(None), none),
            Err(MhfeError::Format(crate::FormatError::NoBuiltInCheck {
                container_words: 12
            }))
        );
    }

    /// The published ambiguous-12-21 phrase passes the built-in checks of 12 and 21 words: with
    /// no length stated, or a short length stated that does not pass, the check is not verified
    /// and names both; a stated length among them matches; a wallet reference compares every
    /// reading and matches. A stated short length that nothing passes does not match
    /// (AUD-023-FUN002).
    #[test]
    fn several_matching_lengths_are_reported_and_not_verified() {
        let mut mhfe = reduced();
        let ambiguous = container_of(&mut mhfe, AMBIGUOUS_12_21, Suite::TwentyFourWords);
        let built_in = |words| Reference::BuiltInCheck {
            words: WordCount::new(words).unwrap(),
        };
        let recovered = mhfe
            .recover_for_check(
                &ambiguous,
                &test_password(),
                &Reference::own_checks(""),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        for reference in [Reference::own_checks(""), built_in(15), built_in(18)] {
            let evidence = recovered.compare(&reference).unwrap();
            assert_eq!(evidence.outcome, CheckOutcome::NotVerified);
            assert_eq!(evidence.built_in_check, None);
            assert_eq!(evidence.matching_lengths, [12, 21]);
        }
        for words in [12, 21] {
            let evidence = recovered.compare(&built_in(words)).unwrap();
            assert!(evidence.outcome.matches());
            assert_eq!(evidence.built_in_check, Some(words));
            assert_eq!(evidence.matching_lengths, [12, 21]);
        }
        let fingerprint = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(AMBIGUOUS_12_21, "").unwrap(),
            passphrase: "",
        };
        assert!(recovered.compare(&fingerprint).unwrap().outcome.matches());
        // A 24-word original has no built-in check: a stated short length does not match.
        let art = container_of(&mut mhfe, ABANDON_24, Suite::TwentyFourWords);
        let evidence = evidence_for(&mut mhfe, &art, &built_in(12));
        assert_eq!(evidence.outcome, CheckOutcome::DoesNotMatch);
        assert!(evidence.matching_lengths.is_empty());
    }

    /// The checks a front end lists beside the result: the verified reading's built-in check or
    /// those of several lengths, then the 16-bit check only where it passes (AUD-023-ARC016).
    #[test]
    fn the_passed_own_checks_are_listed_in_order() {
        let evidence = |built_in_check, matching_lengths: &[usize], wallet_check| CheckEvidence {
            asks_length: false,
            outcome: CheckOutcome::NotVerified,
            built_in_check,
            matching_lengths: matching_lengths.to_vec(),
            wallet_check,
        };
        assert_eq!(
            evidence(Some(12), &[12], None).own_checks_passed(),
            [PassedCheck::BuiltInCheck(12)]
        );
        assert_eq!(
            evidence(None, &[12, 21], Some(true)).own_checks_passed(),
            [
                PassedCheck::BuiltInChecks(vec![12, 21]),
                PassedCheck::WalletCheck
            ]
        );
        assert!(evidence(None, &[], Some(false))
            .own_checks_passed()
            .is_empty());
    }

    /// A front end's reference gives the library's, with the passphrase it is given; the own
    /// checks take an empty passphrase as none.
    #[test]
    fn a_reference_target_gives_its_reference() {
        let fingerprint = ReferenceTarget::Fingerprint(ABANDON_12_FINGERPRINT.into());
        assert!(matches!(
            fingerprint.with("TREZOR"),
            Reference::Fingerprint {
                fingerprint,
                passphrase: "TREZOR"
            } if fingerprint.bytes() == ABANDON_12_FINGERPRINT
        ));
        let twelve = ReferenceTarget::Length(PhraseLength::Words(WordCount::new(12).unwrap()));
        assert!(matches!(twelve.with(""), Reference::BuiltInCheck { words } if words.get() == 12));
        let detected = ReferenceTarget::Length(PhraseLength::Detect);
        assert!(matches!(
            detected.with(""),
            Reference::OwnChecks { passphrase: None }
        ));
        assert!(matches!(
            detected.with("TREZOR"),
            Reference::OwnChecks {
                passphrase: Some("TREZOR")
            }
        ));
        assert!(matches!(
            ReferenceTarget::WalletCheck.with("TREZOR"),
            Reference::WalletCheck {
                passphrase: "TREZOR"
            }
        ));
        assert!(fingerprint.with("").identifies_wallet());
        assert!(!detected.with("").identifies_wallet());
    }

    /// One recovery compared with one reference after another: a 24-word phrase that detection
    /// finds no length for is then compared with its fingerprint, without the rounds again, and a
    /// reference the container cannot be checked with is refused as a check refuses it.
    #[test]
    fn a_recovery_is_compared_again_without_its_rounds() {
        let mut mhfe = reduced();
        let password = test_password();
        let phrase = phrase_from_entropy(&[7u8; 32]).unwrap();
        let container = mhfe
            .encrypt(&phrase, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let own = Reference::OwnChecks { passphrase: None };
        let mut rounds = 0;
        let recovered = mhfe
            .recover_for_check(&container, &password, &own, &mut |_, _| {
                rounds += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(rounds, ROUNDS);
        assert!(!recovered.compare(&own).unwrap().outcome.matches());
        assert!(recovered.compare(&own).unwrap().asks_length());
        for forbidden in [
            Reference::OwnChecks { passphrase: None },
            Reference::WalletCheck {
                passphrase: "TREZOR",
            },
        ] {
            assert_eq!(
                recovered.compare_after_detection(&forbidden),
                Err(MhfeError::Rehearsal(RehearsalError::DetectionReference))
            );
        }
        for words in crate::BUILT_IN_CHECK_WORD_COUNTS {
            let stated = Reference::BuiltInCheck {
                words: WordCount::new(words).unwrap(),
            };
            assert_eq!(
                recovered
                    .compare_after_detection(&stated)
                    .unwrap()
                    .outcome(),
                &CheckOutcome::DoesNotMatch
            );
        }
        let fingerprint = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(&phrase, "").unwrap(),
            passphrase: "",
        };
        assert!(recovered.compare(&fingerprint).unwrap().outcome.matches());
        let follow_up = recovered.compare_after_detection(&fingerprint).unwrap();
        assert!(follow_up.outcome().matches());
        assert!(!follow_up.asks_length());
        let address = Address::parse(
            crate::wallet::Coin::Bitcoin,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        )
        .unwrap();
        let address = Reference::Address {
            address: &address,
            passphrase: "",
            path: None,
            limits: SearchLimits::first_account(1).unwrap(),
        };
        assert_eq!(
            recovered
                .compare_after_detection(&address)
                .unwrap()
                .outcome(),
            &CheckOutcome::DoesNotMatch
        );
        assert_eq!(
            recovered.compare(&Reference::WalletCheck { passphrase: "" }),
            Err(MhfeError::WalletCheck(
                crate::wallet_check::WalletCheckError::NeedsPassphrase
            ))
        );
    }

    /// A public passphrase with which the 12-word test phrase passes the wallet check's criterion
    /// as 12 words, under BE32(128), which the profile does not define; its 24-word reading fails
    /// (AUD-010, harness crypto-core/short_reading_wallet_check.py).
    const SHORT_READING_PASSPHRASE: &str = "aud010 public probe 11656";

    /// The wallet check follows the length rules of recovery: a 12-word original, verified by its
    /// built-in check, matches with the right password, whether or not its reading passes the
    /// criterion (AUD-024-FUN010), and a wrong password, which leaves the 24-word reading alone,
    /// does not match. The criterion is compared with the 24-word reading only (AUD-010).
    #[test]
    fn a_wallet_check_follows_the_length_rules() {
        let none = &mut |_, _| Ok(());
        let mut mhfe = reduced();
        let password = test_password();
        assert!(wallet_check::WalletCheck::new(SHORT_READING_PASSPHRASE)
            .phrase_passes(ABANDON)
            .unwrap());
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
        for passphrase in [SHORT_READING_PASSPHRASE, "TREZOR"] {
            let reference = Reference::WalletCheck { passphrase };
            assert_eq!(
                mhfe.check(&container, &password, &reference, none),
                Ok(CheckOutcome::Matches { path: None })
            );
            let staged = mhfe
                .recover_for_check_in_stages(&container, &password, &reference, &mut |_, _, _| {
                    Ok(())
                })
                .unwrap();
            let evidence = staged.compare(&reference).unwrap();
            assert_eq!(evidence.outcome, CheckOutcome::Matches { path: None });
            // The 16-bit check belongs to the 24-word reading, which the rules do not give.
            assert_eq!(
                (evidence.built_in_check, evidence.wallet_check),
                (Some(12), None)
            );
            assert_eq!(
                mhfe.check(&container, &wrong_password(), &reference, none),
                Ok(CheckOutcome::DoesNotMatch)
            );
        }
    }

    #[test]
    fn every_reference_matches_the_right_password_only() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);

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
                fingerprint: Fingerprint::from_bytes(ABANDON_12_FINGERPRINT),
                passphrase: "",
            },
        ];
        for reference in &references {
            assert!(check(&mut mhfe, &container, &password, reference)
                .unwrap()
                .matches());
            assert!(!check(&mut mhfe, &container, &wrong, reference)
                .unwrap()
                .matches());
        }

        // A matched address names its path: the first native SegWit receiving address.
        let found = check(&mut mhfe, &container, &password, &references[1]).unwrap();
        assert_eq!(
            found.path().map(ToString::to_string).as_deref(),
            Some("m/84'/0'/0'/0/0")
        );

        // The right password with a wrong BIP39 passphrase is a different wallet.
        let with_passphrase = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes(ABANDON_12_FINGERPRINT),
            passphrase: "TREZOR",
        };
        assert!(!check(&mut mhfe, &container, &password, &with_passphrase)
            .unwrap()
            .matches());
    }

    /// The twelve rounds of the recovery, then the comparison, which can be stopped as well.
    #[test]
    fn a_recovery_in_stages_reports_its_rounds_and_its_comparison() {
        let password = test_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::TwentyFourWords);
        let reference = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes(ABANDON_12_FINGERPRINT),
            passphrase: "",
        };
        let mut reports = Vec::new();
        let recovered = mhfe
            .recover_for_check_in_stages(
                &container,
                &password,
                &reference,
                &mut |stage, round, rounds| {
                    reports.push((stage, round, rounds));
                    Ok(())
                },
            )
            .unwrap();
        assert!(recovered.compare(&reference).unwrap().outcome.matches());
        let mut expected: Vec<(Stage, u32, u32)> =
            (1..=12).map(|round| (Stage::Recover, round, 12)).collect();
        expected.push((Stage::Compare, 12, 12));
        assert_eq!(reports, expected);

        let stopped = mhfe.recover_for_check_in_stages(
            &container,
            &password,
            &reference,
            &mut |stage, _, _| {
                if stage == Stage::Compare {
                    Err(crate::CancelledError)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(stopped, Err(MhfeError::Cancelled)));
    }

    #[test]
    fn a_24_word_original_is_checked_against_the_wallet() {
        let password = test_password();
        let mut mhfe = reduced();
        let original = "legal winner thank year wave sausage worth useful legal winner thank year \
                        wave sausage worth useful legal winner thank year wave sausage worth title";
        let container = mhfe
            .encrypt(original, &password, Suite::TwentyFourWords, &mut |_, _| {
                Ok(())
            })
            .unwrap();
        let fingerprint = wallet::Fingerprint::of(original, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        assert!(check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(24).unwrap()
                }
            )
            .err(),
            Some(MhfeError::Format(
                crate::FormatError::NoBuiltInCheckAtLength(24)
            ))
        );
    }

    #[test]
    fn a_same_length_container_is_checked_against_the_wallet_only() {
        let password = test_password();
        let wrong = wrong_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, ABANDON, Suite::SameLength);
        assert_eq!(container.split(' ').count(), 12);
        let reference = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes(ABANDON_12_FINGERPRINT),
            passphrase: "",
        };
        assert!(check(&mut mhfe, &container, &password, &reference)
            .unwrap()
            .matches());
        assert!(!check(&mut mhfe, &container, &wrong, &reference)
            .unwrap()
            .matches());
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::BuiltInCheck {
                    words: WordCount::new(12).unwrap()
                }
            )
            .err(),
            Some(MhfeError::Format(crate::FormatError::NoBuiltInCheck {
                container_words: 12
            }))
        );
        assert_eq!(
            check(
                &mut mhfe,
                &container,
                &password,
                &Reference::WalletCheck {
                    passphrase: "TREZOR"
                }
            )
            .err(),
            Some(MhfeError::Format(crate::FormatError::NoWalletCheck {
                container_words: 12
            }))
        );
    }

    #[test]
    fn an_unused_passphrase_is_refused_naming_the_references_that_take_one() {
        assert_eq!(
            PassphraseReferences::Check.refuse_unused("TREZOR"),
            Err(RehearsalError::UnusedPassphrase(
                PassphraseReferences::Check
            ))
        );
        assert_eq!(
            PassphraseReferences::Rekey.refuse_unused("TREZOR"),
            Err(RehearsalError::UnusedPassphrase(
                PassphraseReferences::Rekey
            ))
        );
    }

    #[test]
    fn an_empty_passphrase_is_no_passphrase_and_passes() {
        assert_eq!(PassphraseReferences::Check.refuse_unused(""), Ok(()));
        assert_eq!(PassphraseReferences::Rekey.refuse_unused(""), Ok(()));
    }

    /// A stated length takes no passphrase, and a reference that takes one keeps it
    /// (AUD-024-API017).
    #[test]
    fn a_stated_length_refuses_a_passphrase() {
        let twelve = ReferenceTarget::Length(PhraseLength::Words(WordCount::new(12).unwrap()));
        assert!(matches!(
            twelve.refuse_unused("TREZOR"),
            Err(RehearsalError::UnusedPassphrase(_))
        ));
        assert!(twelve.refuse_unused("").is_ok());
        for target in [
            ReferenceTarget::Length(PhraseLength::Detect),
            ReferenceTarget::WalletCheck,
            ReferenceTarget::Fingerprint(Fingerprint::from_bytes([0; 4])),
        ] {
            assert!(target.refuse_unused("TREZOR").is_ok());
        }
    }
}
