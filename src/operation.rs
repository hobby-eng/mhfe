//! Long operations and how they report their progress. A long operation runs one or more `Mhfe`
//! calls of twelve Argon2 rounds each. Before every round it reports the stage the round belongs
//! to and the round's number in the whole operation, so that a front end can show a bar for each
//! stage and stop the operation between any two rounds.

use crate::engine::Argon2Engine;
use crate::mhfe::{Mhfe, NewContainer};
use crate::repair::{self, repair_words};
use crate::{check_phrase, MhfeError, OriginalFacts, Password, Suite, WorkFactor};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// What a long operation is doing when it reports a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Recovering a phrase, or a hidden wallet, from a container: twelve rounds.
    Recover,
    /// Encrypting a phrase into a new container: twelve rounds.
    Encrypt,
    /// Checking a new container: twelve rounds that recover it again and compare the result with
    /// the original, before anything relies on it.
    Check,
    /// Comparing a recovered phrase with a reference of the wallet. It follows the rounds of a
    /// recovery and may take seconds: an address is searched for among thousands.
    Compare,
}

impl Stage {
    /// The stage's name in the browser API: "recover", "encrypt", "check" or "compare".
    pub fn name(self) -> &'static str {
        match self {
            Self::Recover => "recover",
            Self::Encrypt => "encrypt",
            Self::Check => "check",
            Self::Compare => "compare",
        }
    }
}

/// Called before each round of a long operation with its stage, the number of the round about to
/// start in the whole operation and the number of rounds of the whole operation: 12 for a
/// recovery and 24 for an encryption with its check, while an operation of several such calls
/// counts all their rounds, such as 36 for a recovery followed by an encryption.
/// [`Stage::Compare`] follows the last round of a recovery and repeats that round's number.
/// Returning an error, such as [`MhfeError::Cancelled`], stops the operation before that round or
/// comparison, as a [`ProgressCallback`](crate::ProgressCallback) does.
pub type StageCallback<'a> = &'a mut dyn FnMut(Stage, u32, u32) -> Result<(), MhfeError>;

/// Numbers the rounds that one `Mhfe` call reports as rounds of the whole operation it is a part
/// of. A call counts its own rounds from 1: of 12, or of 24 for an encryption with its check. A
/// call that starts after round `done` of the operation has the rounds from `done + 1` on, of
/// `total`.
pub(crate) struct RoundCounter {
    done: u32,
    total: u32,
}

impl RoundCounter {
    /// For the call that starts after round `done` of an operation of `total` rounds.
    pub(crate) fn starting_after(done: u32, total: u32) -> Self {
        Self { done, total }
    }

    /// Reports `round` of the call, in `stage`, as a round of the whole operation.
    pub(crate) fn report(
        &self,
        stage: Stage,
        round: u32,
        on_progress: StageCallback<'_>,
    ) -> Result<(), MhfeError> {
        on_progress(stage, self.done + round, self.total)
    }
}

/// What is known of the wallet's BIP39 passphrase when a container is made. MHFE encrypts the
/// phrase alone, so a wallet with a passphrase still needs it, and [`Keep`] names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletPassphrase {
    /// The wallet has one, such as the passphrase typed for a new phrase.
    Present,
    /// The wallet has none.
    Absent,
    /// Not known, as where a front end does not ask: [`Keep`] then names any passphrase the
    /// wallet may have.
    Unknown,
}

impl From<bool> for WalletPassphrase {
    /// Whether the wallet is known to have a passphrase.
    fn from(has_one: bool) -> Self {
        if has_one {
            Self::Present
        } else {
            Self::Absent
        }
    }
}

impl From<Option<bool>> for WalletPassphrase {
    /// An answer whether the wallet has a passphrase, or none: [`WalletPassphrase::Unknown`].
    fn from(answer: Option<bool>) -> Self {
        answer.map_or(Self::Unknown, Self::from)
    }
}

/// What the owner keeps of a new container. Only what is needed to open it: its words and the
/// password, the BIP39 passphrase of a wallet that has one or may have one, the repair words if
/// made, a setting changed from its default, and the word count when automatic detection would
/// misread the phrase (AUD-003-DOC002). With the defaults and a wallet known to have no
/// passphrase, 24 words and the password are all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keep {
    items: Vec<KeepItem>,
}

/// One thing to keep, in the order [`Keep`] lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepItem {
    /// The container's words, this many.
    ContainerWords(usize),
    Password,
    /// The wallet's BIP39 passphrase, which belongs to the wallet whether checked or not.
    Passphrase,
    /// Any BIP39 passphrase of the wallet, where it is not known whether it has one; in the place
    /// of [`KeepItem::Passphrase`].
    PassphraseIfAny,
    /// The repair words, kept apart from the container phrase.
    RepairWords,
    Pim(u32),
    MemoryLevel(u32),
    /// The original phrase's word count, to choose at recovery.
    WordCount(usize),
}

impl Keep {
    /// The list for a container of `container_words` made at `work`, for a wallet with, without or
    /// perhaps with a BIP39 `passphrase`; `word_count_to_note` is the original's length when
    /// automatic detection would also accept another one.
    pub fn new(
        work: WorkFactor,
        container_words: usize,
        passphrase: WalletPassphrase,
        repair_words: bool,
        word_count_to_note: Option<usize>,
    ) -> Self {
        let mut items = vec![
            KeepItem::ContainerWords(container_words),
            KeepItem::Password,
        ];
        match passphrase {
            WalletPassphrase::Present => items.push(KeepItem::Passphrase),
            WalletPassphrase::Unknown => items.push(KeepItem::PassphraseIfAny),
            WalletPassphrase::Absent => {}
        }
        if repair_words {
            items.push(KeepItem::RepairWords);
        }
        if work.pim() != 0 {
            items.push(KeepItem::Pim(work.pim()));
        }
        if work.memory_level() != 0 {
            items.push(KeepItem::MemoryLevel(work.memory_level()));
        }
        items.extend(word_count_to_note.map(KeepItem::WordCount));
        Self { items }
    }

    pub fn items(&self) -> &[KeepItem] {
        &self.items
    }
}

/// An encryption with its check (creation steps 1 to 6 of the specification), and the repair words
/// of the new container phrase. Everything that can be refused is refused when it is made, before
/// any Argon2 work.
pub struct Encryption {
    suite: Suite,
    repair_word_count: Option<usize>,
}

impl Encryption {
    /// An encryption of `original` into a container of `suite`, with `repair_word_count` repair
    /// words if given.
    pub fn new(
        original: &str,
        suite: Suite,
        repair_word_count: Option<usize>,
    ) -> Result<Self, MhfeError> {
        let words = check_phrase(original)?;
        suite.require_original(words)?;
        if let Some(count) = repair_word_count {
            repair::require_count(count)?;
        }
        Ok(Self {
            suite,
            repair_word_count,
        })
    }

    /// Encrypts `original` (rounds 1 to 12, [`Stage::Encrypt`]), makes the repair words, gives the
    /// container to `on_unverified` so that a person can write it down while the check runs, and
    /// checks it (rounds 13 to 24, [`Stage::Check`]). The repair words come out only with the
    /// checked result: a card is made only for a container whose check passed.
    pub fn run<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        original: &str,
        password: &Password,
        progress: StageCallback,
        on_unverified: &mut dyn FnMut(&str) -> Result<(), MhfeError>,
    ) -> Result<Sealed, MhfeError> {
        let original_words = check_phrase(original)?;
        let other_lengths = OriginalFacts::read(original)?
            .other_lengths_in(self.suite)
            .to_vec();
        let container =
            mhfe.encrypt_unchecked(original, password, self.suite, &mut |round, rounds| {
                progress(Stage::Encrypt, round, rounds)
            })?;
        let repair_words = self
            .repair_word_count
            .map(|count| repair_words(&container.words, count))
            .transpose()?;
        on_unverified(&container.words)?;
        mhfe.check_new_container(&container, password, &mut |round, rounds| {
            progress(Stage::Check, round, rounds)
        })?;
        Ok(Sealed {
            container,
            original_words,
            other_lengths,
            repair_words,
        })
    }
}

/// A new container whose check has passed, with its repair words if made.
pub struct Sealed {
    container: NewContainer,
    original_words: usize,
    other_lengths: Vec<usize>,
    repair_words: Option<String>,
}

impl Sealed {
    /// The container's words.
    pub fn container(&self) -> &str {
        &self.container.words
    }

    pub fn suite(&self) -> Suite {
        self.container.suite
    }

    pub fn container_words(&self) -> usize {
        self.container.words.split(' ').count()
    }

    /// The repair words, made only once the check has passed.
    pub fn repair_words(&self) -> Option<&str> {
        self.repair_words.as_deref()
    }

    /// Whether a recovery of this container checks the phrase on its own: a 12- to 21-word phrase
    /// in a 24-word container carries a built-in check; a 24-word phrase and a same-length
    /// container do not.
    pub fn built_in_check(&self) -> bool {
        self.container
            .suite
            .built_in_check_lengths()
            .contains(&self.original_words)
    }

    /// The other lengths that automatic detection would also accept, almost always none: when not,
    /// the owner notes the word count and chooses it at recovery.
    pub fn other_lengths(&self) -> &[usize] {
        &self.other_lengths
    }

    /// What the owner keeps, for a container made at `work`, with what is known of the wallet's
    /// BIP39 `passphrase`.
    pub fn keep(&self, work: WorkFactor, passphrase: WalletPassphrase) -> Keep {
        Keep::new(
            work,
            self.container_words(),
            passphrase,
            self.repair_words.is_some(),
            (!self.other_lengths.is_empty()).then_some(self.original_words),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_have_the_names_of_the_browser_api() {
        let stages = [Stage::Recover, Stage::Encrypt, Stage::Check, Stage::Compare];
        let names: Vec<&str> = stages.into_iter().map(Stage::name).collect();
        assert_eq!(names, ["recover", "encrypt", "check", "compare"]);
    }

    /// A recovery, rounds 1 to 12 of 36 and its comparison, then an encryption with its check,
    /// whose own rounds 1 to 24 become rounds 13 to 36, as for a new password.
    #[test]
    fn the_calls_of_an_operation_are_numbered_as_one_sequence() {
        let mut reports = Vec::new();
        let mut on_progress = |stage: Stage, round: u32, rounds: u32| -> Result<(), MhfeError> {
            reports.push((stage, round, rounds));
            Ok(())
        };
        let recovery = RoundCounter::starting_after(0, 36);
        recovery
            .report(Stage::Recover, 1, &mut on_progress)
            .unwrap();
        recovery
            .report(Stage::Recover, 12, &mut on_progress)
            .unwrap();
        recovery
            .report(Stage::Compare, 12, &mut on_progress)
            .unwrap();
        let encryption = RoundCounter::starting_after(12, 36);
        encryption
            .report(Stage::Encrypt, 1, &mut on_progress)
            .unwrap();
        encryption
            .report(Stage::Check, 13, &mut on_progress)
            .unwrap();
        encryption
            .report(Stage::Check, 24, &mut on_progress)
            .unwrap();
        assert_eq!(
            reports,
            [
                (Stage::Recover, 1, 36),
                (Stage::Recover, 12, 36),
                (Stage::Compare, 12, 36),
                (Stage::Encrypt, 13, 36),
                (Stage::Check, 25, 36),
                (Stage::Check, 36, 36),
            ]
        );
    }

    /// The wallet's passphrase is named as far as it is known, always after the container's words
    /// and the password and before the repair words, the settings and the word count.
    #[test]
    fn the_passphrase_is_kept_as_far_as_it_is_known() {
        let work = WorkFactor::new(3, 1).unwrap();
        let listed = |passphrase| {
            Keep::new(work, 24, passphrase, true, Some(15))
                .items()
                .to_vec()
        };
        let around = |passphrase: &[KeepItem]| {
            let mut items = vec![KeepItem::ContainerWords(24), KeepItem::Password];
            items.extend_from_slice(passphrase);
            items.extend([
                KeepItem::RepairWords,
                KeepItem::Pim(3),
                KeepItem::MemoryLevel(1),
                KeepItem::WordCount(15),
            ]);
            items
        };
        assert_eq!(
            listed(WalletPassphrase::Present),
            around(&[KeepItem::Passphrase])
        );
        assert_eq!(listed(WalletPassphrase::Absent), around(&[]));
        assert_eq!(
            listed(WalletPassphrase::Unknown),
            around(&[KeepItem::PassphraseIfAny])
        );
        // With the defaults, a wallet not known to be without one still names it.
        assert_eq!(
            Keep::new(
                WorkFactor::default(),
                12,
                WalletPassphrase::Unknown,
                false,
                None
            )
            .items(),
            [
                KeepItem::ContainerWords(12),
                KeepItem::Password,
                KeepItem::PassphraseIfAny
            ]
        );
    }

    #[test]
    fn an_answer_or_none_tells_what_is_known_of_the_passphrase() {
        assert_eq!(WalletPassphrase::from(true), WalletPassphrase::Present);
        assert_eq!(WalletPassphrase::from(false), WalletPassphrase::Absent);
        assert_eq!(
            WalletPassphrase::from(Some(true)),
            WalletPassphrase::Present
        );
        assert_eq!(
            WalletPassphrase::from(Some(false)),
            WalletPassphrase::Absent
        );
        assert_eq!(WalletPassphrase::from(None), WalletPassphrase::Unknown);
    }

    #[test]
    fn an_error_from_the_callback_is_passed_on() {
        let counter = RoundCounter::starting_after(0, 12);
        let mut stop = |_: Stage, _: u32, _: u32| Err(MhfeError::Cancelled);
        assert_eq!(
            counter.report(Stage::Recover, 1, &mut stop),
            Err(MhfeError::Cancelled)
        );
    }
}
