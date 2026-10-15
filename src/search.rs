//! The search for words missing from a container phrase when its repair words are lost. Every
//! word the BIP39 checksum allows in place of each missing one makes a candidate container, and
//! each candidate is compared with what the owner knows of a wallet:
//!
//! - of the decoy wallet, the container itself typed into a wallet: its master key fingerprint,
//!   which MHFE shows under every container it makes, or one of its receiving addresses. Each
//!   candidate is compared as it is, without the password and without Argon2, so that even two
//!   missing words of 24 are found in a few minutes at most;
//! - of the owner's wallet, the original seed phrase: its fingerprint or an address. Each
//!   candidate is recovered with the password first, a full recovery with Argon2, one to two
//!   minutes at the default settings, so that only one missing word is searched: about 8
//!   candidates in 24 words, 128 in 12; two would take weeks.
//!
//! The words typed are read as for a repair: `?` or a word outside the BIP39 list marks a missing
//! word, and the first four letters of a word are enough. A candidate that matches proves only
//! what the reference proves among all the candidates: an address strongly; a fingerprint, a
//! 32-bit check, is shared by another of the 262,144 candidates of two missing words of 12 about
//! once in 16,384 searches. The search with the decoy wallet therefore compares every candidate
//! and refuses a reference that more than one matches (`SEVERAL_CANDIDATES_MATCH`); an address
//! tells them apart.

mod error;
pub use error::SearchError;

#[cfg(test)]
use crate::wallet::Fingerprint;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::engine::Argon2Engine;
use crate::packing::{self, STATE_BYTES};
use crate::phrase::{self, LIST_SIZE, WORD_BITS, WORD_COUNTS};
use crate::rehearsal::{self, CheckOutcome, Reference};
use crate::repair::ContainerReading;
use crate::wallet::{DerivationPath, SearchLimits};
use crate::{Mhfe, MhfeError, Password, Suite};

#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub(crate) mod known_answers;

/// The most missing words a search with the decoy wallet looks for: two make about 16,384
/// candidates of 24 words, each compared in a few milliseconds.
pub const MAX_MISSING_FOR_DECOY: usize = 2;
/// How many receiving and change addresses of the first account a search with the decoy wallet
/// covers for two missing words, unless told otherwise: the gap of unused addresses a wallet
/// leaves before it stops looking (BIP44).
pub const DECOY_SCAN_GAP: u32 = 20;

/// Hears how far a search that compares candidates has come: `(done, count)`; an error stops it.
pub type CandidateProgress<'a> =
    &'a mut dyn FnMut(usize, usize) -> Result<(), crate::CancelledError>;
/// Hears every round of a search that recovers each candidate: `(candidate, count, round,
/// rounds)`; an error stops it.
pub type RecoveryProgress<'a> =
    &'a mut dyn FnMut(usize, usize, u32, u32) -> Result<(), crate::CancelledError>;
/// Compares candidate `index` with the reference, from any of the threads that share them; the
/// second argument says when the search was stopped, which a long address search asks between its
/// addresses.
type CandidateCompare<'a> =
    &'a (dyn Fn(usize, &dyn Fn() -> bool) -> Result<CheckOutcome, MhfeError> + Sync);
/// The most missing words a search with the owner's wallet looks for: each candidate takes a full
/// recovery, so one word, about 8 candidates of 24 words, takes minutes and two would take weeks.
pub const MAX_MISSING_FOR_WALLET: usize = 1;

/// A container phrase with missing words and every candidate container the BIP39 checksum allows.
pub struct ContainerSearch {
    /// The numbers of the words typed; a missing word holds 0 until a candidate fills it.
    words: Vec<u16>,
    /// The positions of the missing words, from 0.
    missing: Vec<usize>,
    /// The numbers of the missing words of every candidate, in the order of `missing`.
    candidates: Vec<Vec<u16>>,
}

/// A candidate that matched the reference.
///
/// The result's words are read-only outside its producer:
///
/// ```compile_fail
/// fn corrupt(found: &mut mhfe::search::Found) { found.words.clear(); }
/// ```
#[derive(Debug)]
pub struct Found {
    /// The container phrase, every word in full, one space apart.
    container: Zeroizing<String>,
    /// Each missing word as found, with its position from 1.
    words: Vec<(usize, &'static str)>,
    /// For an address, the path where it was found.
    path: Option<DerivationPath>,
}

impl Found {
    /// The candidate container that matched the reference.
    pub fn container(&self) -> &str {
        &self.container
    }

    /// Each missing word found, with its position from one.
    pub fn words(&self) -> &[(usize, &'static str)] {
        &self.words
    }

    /// The matched address's derivation path, or none for another kind of reference.
    pub fn path(&self) -> Option<&DerivationPath> {
        self.path.as_ref()
    }
}

impl ContainerSearch {
    /// Reads `written` as a repair reads it and lists the candidates. Words must be marked
    /// missing (`INVALID_REQUEST` otherwise), at most [`MAX_MISSING_FOR_DECOY`] of them
    /// (`TOO_MANY_MISSING_WORDS`).
    pub fn new(written: &str) -> Result<Self, SearchError> {
        // `?` or a word outside the BIP39 list marks a missing word, as for a repair
        // (AUD-024-API013).
        let unreadable = match ContainerReading::read(written) {
            ContainerReading::Marked { unreadable } => unreadable,
            ContainerReading::WrongLength(count) => {
                return Err(crate::repair::RepairError::ContainerLength(count).into())
            }
            ContainerReading::NotAContainer => {
                let (_, outside) = phrase::word_numbers(written);
                if outside.is_empty() {
                    return Err(SearchError::WrongWord);
                }
                outside.iter().map(|position| position + 1).collect()
            }
            ContainerReading::Container => return Err(SearchError::NoMissingWord),
        };
        if unreadable.len() > MAX_MISSING_FOR_DECOY {
            return Err(SearchError::TooManyMissing {
                missing: unreadable.len(),
                limit: MAX_MISSING_FOR_DECOY,
            });
        }
        // The unreadable words stand as 0, read as the repair reads them.
        let (words, missing) = phrase::word_numbers(written);
        debug_assert!(missing.iter().map(|position| position + 1).eq(unreadable));
        debug_assert!(WORD_COUNTS.contains(&words.len()));
        let candidates = candidates(&words, &missing);
        Ok(Self {
            words,
            missing,
            candidates,
        })
    }

    /// The positions of the missing words, from 1.
    pub fn missing(&self) -> Vec<usize> {
        self.missing.iter().map(|position| position + 1).collect()
    }

    /// How many candidate containers pass the BIP39 checksum.
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// Where [`ContainerSearch::search_decoy`] looks for an address without a path. The usual
    /// 2,000 addresses take under a second a candidate, hours for the 16,384 of two missing
    /// words, so that for two it looks in the first account only, among its first `scan_gap`
    /// receiving and as many change addresses: [`DECOY_SCAN_GAP`] by default, the gap of unused
    /// addresses a wallet leaves, more for an address further on, at a cost that grows with it.
    /// One missing word keeps the usual search. A front end states the scope before the work.
    pub fn decoy_address_limits(
        &self,
        scan_gap: u32,
    ) -> Result<SearchLimits, crate::wallet::WalletError> {
        if !self.offers_wallet_search() {
            SearchLimits::first_account(scan_gap)
        } else {
            Ok(SearchLimits::default())
        }
    }

    /// Compares every candidate, as the decoy wallet, with `reference`: an address, searched
    /// within [`ContainerSearch::decoy_address_limits`] of `scan_gap` unless its path is given,
    /// or a fingerprint, with the passphrase it names: none for the container typed into a
    /// wallet as it is, the usual case, or the one the person says is used with the container
    /// phrase. Every candidate is compared, natively on the processor's cores, in a WebAssembly
    /// build in turn: a reference that more than one candidate matches cannot tell them apart and
    /// is refused (`SEVERAL_CANDIDATES_MATCH`) rather than one of them taken. `on_progress(done,
    /// count)` hears how far the comparison has come and stops the search with its error, such
    /// as a cancel.
    pub fn search_decoy(
        &self,
        reference: &Reference<'_>,
        scan_gap: u32,
        on_progress: CandidateProgress<'_>,
    ) -> Result<Option<Found>, MhfeError> {
        require_wallet_reference(reference)?;
        let limits = self.decoy_address_limits(scan_gap)?;
        let compared = decoy_reference(reference, limits);
        let compare = |index: usize, stopped: &dyn Fn() -> bool| {
            rehearsal::compare_until(&self.container(&self.candidates[index]), &compared, stopped)
        };
        let matched = only_match(compare_candidates(self.count(), &compare, on_progress)?)?;
        Ok(matched.map(|(index, outcome)| {
            let missing = &self.candidates[index];
            self.found(self.container(missing), missing, outcome.path().cloned())
        }))
    }

    /// Recovers every candidate with `password`, a full recovery each, until one matches
    /// `reference` as [`Mhfe::check`] compares it, an address or a fingerprint of the wallet, or
    /// passes the original seed phrase's own checks ([`ContainerSearch::search_own_checks`]). Only
    /// [`MAX_MISSING_FOR_WALLET`] missing word is searched (`TOO_MANY_MISSING_WORDS`), and a
    /// reference that cannot tell the candidates apart is refused, both before any work.
    /// `on_progress(candidate, count, round, rounds)` hears of every round and stops the search
    /// with its error.
    pub fn search_wallet<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        password: &Password,
        reference: &Reference<'_>,
        on_progress: RecoveryProgress<'_>,
    ) -> Result<Option<Found>, MhfeError> {
        self.require_one_missing()?;
        match reference {
            // The phrase's own checks with its length detected, refused as a check refuses them.
            Reference::OwnChecks { .. } => {
                rehearsal::refuse_impossible(self.words.len(), reference)?
            }
            _ => require_wallet_reference(reference)?,
        }
        let count = self.count();
        for (index, missing) in self.candidates.iter().enumerate() {
            let container = self.container(missing);
            let recovered =
                mhfe.recover_for_check(&container, password, reference, &mut |round, rounds| {
                    on_progress(index + 1, count, round, rounds)
                })?;
            let found = match reference {
                Reference::OwnChecks { passphrase } => {
                    recovered.passes_own_checks(*passphrase)?.then_some(None)
                }
                _ => {
                    let outcome = recovered.compare(reference)?.outcome().clone();
                    outcome.matches().then(|| outcome.path().cloned())
                }
            };
            if let Some(path) = found {
                return Ok(Some(self.found(container, missing, path)));
            }
        }
        Ok(None)
    }

    /// Whether the original seed phrase's wallet can tell the candidates apart: with one missing
    /// word, as each candidate costs a full recovery.
    pub fn offers_wallet_search(&self) -> bool {
        self.missing.len() <= MAX_MISSING_FOR_WALLET
    }

    /// Whether the original seed phrase's own checks can, as its wallet can, in a container that
    /// carries them: a 24-word one, with the built-in check of a shorter original seed phrase or
    /// a phrase drawn with the phrase + passphrase check.
    pub fn offers_own_checks(&self) -> bool {
        self.offers_wallet_search() && self.carries_own_checks()
    }

    fn carries_own_checks(&self) -> bool {
        Suite::of_container(self.words.len())
            .is_ok_and(|suite| !suite.built_in_check_lengths().is_empty())
    }

    fn require_one_missing(&self) -> Result<(), MhfeError> {
        if !self.offers_wallet_search() {
            return Err(MhfeError::Search(SearchError::TooManyMissing {
                missing: self.missing.len(),
                limit: MAX_MISSING_FOR_WALLET,
            }));
        }
        Ok(())
    }

    /// Recovers every candidate with `password` and takes the one whose recovery passes a check
    /// of the original seed phrase itself, with no fingerprint or address: the built-in check of
    /// a 12- to 21-word original seed phrase, and with its BIP39 `passphrase` also the phrase +
    /// passphrase check of a 24-word one that `mhfe new` drew to pass it (16 bits, so a wrong
    /// candidate passes about once in 65,536). A 24-word original seed phrase without that check
    /// has neither, so that none of its candidates passes. A same-length container has no check
    /// of its own (`NO_BUILT_IN_CHECK`), and an empty passphrase none to compare
    /// (`WALLET_CHECK_NEEDS_PASSPHRASE`). One missing word only (`TOO_MANY_MISSING_WORDS`).
    /// `on_progress` as for [`ContainerSearch::search_wallet`].
    pub fn search_own_checks<E: Argon2Engine>(
        &self,
        mhfe: &mut Mhfe<E>,
        password: &Password,
        passphrase: Option<&str>,
        on_progress: RecoveryProgress<'_>,
    ) -> Result<Option<Found>, MhfeError> {
        let reference = Reference::OwnChecks { passphrase };
        self.search_wallet(mhfe, password, &reference, on_progress)
    }

    /// The candidate container with `missing` in the places of the missing words.
    fn container(&self, missing: &[u16]) -> Zeroizing<String> {
        let mut numbers = self.words.clone();
        for (&position, &number) in self.missing.iter().zip(missing) {
            numbers[position] = number;
        }
        Zeroizing::new(phrase::words_of(&numbers))
    }

    fn found(
        &self,
        container: Zeroizing<String>,
        missing: &[u16],
        path: Option<DerivationPath>,
    ) -> Found {
        Found {
            container,
            words: self
                .missing
                .iter()
                .zip(missing)
                .map(|(&position, &number)| (position + 1, phrase::word(number)))
                .collect(),
            path,
        }
    }
}

/// Compares every candidate `0..count` with `compare` and gives each that matches, with its
/// outcome, by index: a search does not stop at a first match, which another candidate could
/// share (AUD-024-FUN001). Natively the candidates are shared among the processor's cores, each
/// worker taking the next one left, while this thread reports how far they have come; where the
/// system starts no worker, and in a WebAssembly build, which has no threads here, they are
/// compared in turn.
#[cfg(not(target_arch = "wasm32"))]
fn compare_candidates(
    count: usize,
    compare: CandidateCompare<'_>,
    on_progress: CandidateProgress<'_>,
) -> Result<Vec<(usize, CheckOutcome)>, MhfeError> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    let workers = std::thread::available_parallelism()
        .map_or(1, |cores| cores.get())
        .min(count.max(1));
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    // The workers that have ended, which wake this thread at once when the last one does.
    let finished = Mutex::new(0);
    let all_finished = Condvar::new();
    // After an error or a cancel, ends the taking of candidates and the comparisons under way.
    let abort = AtomicBool::new(false);
    let matched: Mutex<Vec<(usize, CheckOutcome)>> = Mutex::new(Vec::new());
    let failure: Mutex<Option<MhfeError>> = Mutex::new(None);
    // Keeps the error and ends every comparison, those under way too.
    let abort_with = |error| {
        *failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
        abort.store(true, Ordering::Relaxed);
    };
    let work = || {
        while !abort.load(Ordering::Relaxed) {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= count {
                break;
            }
            match compare(index, &|| abort.load(Ordering::Relaxed)) {
                Ok(outcome) if outcome.matches() => matched
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((index, outcome)),
                Ok(_) => {}
                // A comparison abandoned after an abort: the abort's error stands.
                Err(_) if abort.load(Ordering::Relaxed) => {}
                Err(error) => abort_with(error),
            }
            done.fetch_add(1, Ordering::Relaxed);
        }
        *finished.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        all_finished.notify_one();
    };
    let started = std::thread::scope(|scope| {
        let started = crate::workers::start_scoped(scope, workers, &work);
        // This thread tells how far the comparison has come at every interval, and ends as soon as
        // the last worker started does, without waiting out an interval (AUD-023-DOC002); an error
        // from it stops the workers. After an abort it is not asked again while the workers end.
        let interval = Duration::from_millis(PROGRESS_INTERVAL_MS);
        // With no worker started there is nothing to wait for: the candidates are compared in
        // turn below.
        loop {
            if started == 0 {
                break;
            }
            let ended = finished.lock().unwrap_or_else(|e| e.into_inner());
            let (ended, _) = all_finished
                .wait_timeout_while(ended, interval, |ended| *ended < started)
                .unwrap_or_else(|e| e.into_inner());
            if *ended >= started {
                break;
            }
            // The workers that end meanwhile need the lock.
            drop(ended);
            if abort.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(error) = on_progress(done.load(Ordering::Relaxed).min(count), count) {
                abort_with(error.into());
            }
        }
        started
    });
    if started == 0 {
        return compare_in_turn(count, compare, on_progress);
    }
    if let Some(error) = failure.into_inner().unwrap_or_else(|e| e.into_inner()) {
        return Err(error);
    }
    on_progress(count, count)?;
    let mut matched = matched.into_inner().unwrap_or_else(|e| e.into_inner());
    matched.sort_by_key(|(index, _)| *index);
    Ok(matched)
}

/// How often the thread that waits for the workers reports the progress, in milliseconds.
#[cfg(not(target_arch = "wasm32"))]
const PROGRESS_INTERVAL_MS: u64 = 100;

#[cfg(target_arch = "wasm32")]
fn compare_candidates(
    count: usize,
    compare: CandidateCompare<'_>,
    on_progress: CandidateProgress<'_>,
) -> Result<Vec<(usize, CheckOutcome)>, MhfeError> {
    compare_in_turn(count, compare, on_progress)
}

/// Compares every candidate in turn on the calling thread, reporting after each one, and gives
/// each that matches, by index.
fn compare_in_turn(
    count: usize,
    compare: CandidateCompare<'_>,
    on_progress: CandidateProgress<'_>,
) -> Result<Vec<(usize, CheckOutcome)>, MhfeError> {
    let mut matched = Vec::new();
    for index in 0..count {
        let outcome = compare(index, &|| false)?;
        on_progress(index + 1, count)?;
        if outcome.matches() {
            matched.push((index, outcome));
        }
    }
    Ok(matched)
}

/// The one candidate that matched, or none; a reference that more than one candidate matches
/// cannot tell them apart, so that none is taken (AUD-024-FUN001).
fn only_match(
    matched: Vec<(usize, CheckOutcome)>,
) -> Result<Option<(usize, CheckOutcome)>, MhfeError> {
    if matched.len() > 1 {
        return Err(MhfeError::Search(SearchError::SeveralMatches {
            matches: matched.len(),
        }));
    }
    Ok(matched.into_iter().next())
}

/// `reference` as the decoy search compares it: an address without a path within `limits`.
fn decoy_reference<'a>(reference: &Reference<'a>, limits: SearchLimits) -> Reference<'a> {
    match *reference {
        Reference::Address {
            address,
            passphrase,
            path: None,
            ..
        } => Reference::Address {
            address,
            passphrase,
            path: None,
            limits,
        },
        Reference::Address {
            address,
            passphrase,
            path,
            limits,
        } => Reference::Address {
            address,
            passphrase,
            path,
            limits,
        },
        Reference::Fingerprint {
            fingerprint,
            passphrase,
        } => Reference::Fingerprint {
            fingerprint,
            passphrase,
        },
        Reference::BuiltInCheck { words } => Reference::BuiltInCheck { words },
        Reference::WalletCheck { passphrase } => Reference::WalletCheck { passphrase },
        Reference::OwnChecks { passphrase } => Reference::OwnChecks { passphrase },
    }
}

/// A search compares with a wallet: an address or a fingerprint. The built-in check and the
/// wallet check say nothing of which container is the right one among several that pass them.
fn require_wallet_reference(reference: &Reference<'_>) -> Result<(), MhfeError> {
    if !reference.identifies_wallet() {
        return Err(MhfeError::Search(SearchError::WalletReferenceRequired));
    }
    Ok(())
}

/// The numbers of the missing words of every candidate that passes the BIP39 checksum, in the
/// order of the list, the first missing word slowest.
fn candidates(words: &[u16], missing: &[usize]) -> Vec<Vec<u16>> {
    // The bits of the words typed are packed once; each candidate adds only its missing words'.
    let mut known = words.to_vec();
    for &position in missing {
        known[position] = 0;
    }
    let base = pack(&known);
    let mut found = Vec::new();
    let mut values = vec![0_u16; missing.len()];
    loop {
        let mut bits = base;
        for (&position, &value) in missing.iter().zip(&values) {
            set_word(&mut bits, position, value);
        }
        if passes_checksum(&bits, words.len()) {
            found.push(values.clone());
        }
        // The next combination, the last missing word fastest.
        let mut place = values.len();
        loop {
            if place == 0 {
                return found;
            }
            place -= 1;
            values[place] += 1;
            if values[place] < LIST_SIZE {
                break;
            }
            values[place] = 0;
        }
    }
}

/// The bits of up to 24 words of 11 bits: 33 bytes, 32 of entropy and one of checksum.
type WordBits = [u8; STATE_BYTES + 1];

fn pack(numbers: &[u16]) -> WordBits {
    let mut bits = [0_u8; STATE_BYTES + 1];
    for (index, &number) in numbers.iter().enumerate() {
        set_word(&mut bits, index, number);
    }
    bits
}

/// Writes the 11 bits of word `index`.
fn set_word(bits: &mut WordBits, index: usize, number: u16) {
    phrase::write_bits(bits, index * WORD_BITS, WORD_BITS, number);
}

/// Whether `words` words packed in `bits` pass the BIP39 checksum: the first
/// [`packing::checksum_bits`] bits of the SHA-256 of the entropy, which the last word carries after
/// the entropy's last bits.
fn passes_checksum(bits: &WordBits, words: usize) -> bool {
    let entropy_bytes = packing::entropy_of_words(words);
    let hash = Sha256::digest(&bits[..entropy_bytes]);
    let shift = 8 - packing::checksum_bits(words);
    hash[0] >> shift == bits[entropy_bytes] >> shift
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{container_of, reduced, test_password, zero_12_container, LEGAL_12};
    use crate::wallet;
    use crate::Suite;

    /// One instant comparison ends before a progress interval; a fixed sleep in the waiting
    /// loop must fail in debug builds too. A median tolerates occasional scheduler delays.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn instant_comparisons_end_before_one_progress_interval() {
        use std::time::{Duration, Instant};
        let mut times = Vec::new();
        for _ in 0..10 {
            let mut progress = Vec::new();
            let started = Instant::now();
            let found = compare_candidates(
                1,
                &|_, _| Ok(CheckOutcome::DoesNotMatch),
                &mut |done, total| {
                    progress.push((done, total));
                    Ok(())
                },
            )
            .unwrap();
            times.push(started.elapsed());
            assert!(found.is_empty());
            assert_eq!(
                progress,
                [(1, 1)],
                "instant work reports only its completion"
            );
        }
        times.sort_unstable();
        assert!(
            times[times.len() / 2] < Duration::from_millis(PROGRESS_INTERVAL_MS),
            "instant comparison median {:?} includes a whole progress interval",
            times[times.len() / 2],
        );
    }

    fn with(container: &str, changes: &[(usize, &'static str)]) -> String {
        let mut words: Vec<&str> = container.split(' ').collect();
        for &(position, word) in changes {
            words[position - 1] = word;
        }
        words.join(" ")
    }

    /// The checksum test agrees with the BIP39 library on every word in one place.
    #[test]
    fn the_checksum_agrees_with_the_bip39_library() {
        let container = zero_12_container();
        let list = bip39::Language::English.word_list();
        for place in [1, 13, 24] {
            for word in list.iter().step_by(7) {
                let typed = with(&container, &[(place, word)]);
                let (numbers, _) = phrase::word_numbers(&typed);
                assert_eq!(
                    passes_checksum(&pack(&numbers), numbers.len()),
                    phrase::parse_container(&typed).is_ok(),
                    "{place} {word}"
                );
            }
        }
    }

    /// One missing word of 24 leaves the 8 candidates of the last word's checksum, or about as
    /// many elsewhere; the real container is always among them.
    #[test]
    fn the_candidates_pass_the_checksum_and_hold_the_container() {
        let container = zero_12_container();
        let last = ContainerSearch::new(&with(&container, &[(24, "?")])).unwrap();
        assert_eq!(last.missing(), [24]);
        assert_eq!(last.count(), 8, "2048 words, 8 checksum bits");
        let early = ContainerSearch::new(&with(&container, &[(3, "?")])).unwrap();
        for search in [&last, &early] {
            let listed: Vec<Zeroizing<String>> = search
                .candidates
                .iter()
                .map(|missing| search.container(missing))
                .collect();
            assert!(listed.iter().any(|candidate| **candidate == container));
            assert!(listed
                .iter()
                .all(|candidate| phrase::parse_container(candidate).is_ok()));
        }
    }

    /// The decoy wallet's fingerprint finds the container among the candidates of a missing word,
    /// without the password; with a passphrase the decoy has not, or the fingerprint of another
    /// wallet, it finds nothing.
    #[test]
    fn the_decoy_fingerprint_finds_the_missing_word() {
        let container = zero_12_container();
        let fingerprint = wallet::Fingerprint::of(&container, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let one = ContainerSearch::new(&with(&container, &[(24, "?")])).unwrap();
        let mut compared = 0;
        let found = decoy_found(&one, &reference, &mut |done, _| {
            compared = done;
            Ok(())
        });
        assert_eq!(found_words(&found, &container), [24]);
        // Every candidate is compared, not only those before the match (AUD-024-FUN001).
        assert_eq!(compared, one.count());
        let with_passphrase = Reference::Fingerprint {
            fingerprint,
            passphrase: "TREZOR",
        };
        assert!(one
            .search_decoy(&with_passphrase, DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .unwrap()
            .is_none());
        let other = Reference::Fingerprint {
            fingerprint: Fingerprint::from_bytes([0, 0, 0, 0]),
            passphrase: "",
        };
        assert!(one
            .search_decoy(&other, DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .unwrap()
            .is_none());
    }

    /// Two missing words: the decoy wallet's fingerprint finds both among about 16,384
    /// candidates, every one of them compared.
    #[test]
    #[ignore = "compares all 16,384 candidates: about a minute and a half in a debug build"]
    fn full_size_decoy_search_finds_two_missing_words() {
        let container = zero_12_container();
        let reference = Reference::Fingerprint {
            fingerprint: wallet::Fingerprint::of(&container, "").unwrap(),
            passphrase: "",
        };
        let search = ContainerSearch::new(&with(&container, &[(15, "?"), (21, "?")])).unwrap();
        assert!(search.count() > 8 * 2048 / 2, "about 16,384 candidates");
        let found = decoy_found(&search, &reference, &mut |_, _| Ok(()));
        assert_eq!(found_words(&found, &container), [15, 21]);
    }

    /// What the decoy search finds with `reference`, which must match one candidate.
    fn decoy_found(
        search: &ContainerSearch,
        reference: &Reference<'_>,
        on_progress: CandidateProgress<'_>,
    ) -> Found {
        search
            .search_decoy(reference, DECOY_SCAN_GAP, on_progress)
            .unwrap()
            .unwrap()
    }

    /// The positions of the words found, each checked against `container`, which must be the one
    /// found.
    fn found_words(found: &Found, container: &str) -> Vec<usize> {
        assert_eq!(*found.container, container);
        let words: Vec<&str> = container.split(' ').collect();
        for &(position, word) in &found.words {
            assert_eq!(word, words[position - 1]);
        }
        found.words.iter().map(|&(position, _)| position).collect()
    }

    /// Two candidates of "abandon" ten times and two missing words share the fingerprint
    /// a30a4e0f: "able ghost" comes first, "best student" later. The search finds both and takes
    /// neither, where it used to take the first (AUD-024-FUN001).
    #[test]
    #[ignore = "compares all 262,144 candidates: minutes in a debug build"]
    fn full_size_decoy_search_refuses_a_fingerprint_two_candidates_share() {
        let abandon = "abandon ".repeat(10);
        let first = format!("{abandon}able ghost");
        let later = format!("{abandon}best student");
        let fingerprint = wallet::Fingerprint::of(&first, "").unwrap();
        assert_eq!(fingerprint.bytes(), [0xa3, 0x0a, 0x4e, 0x0f]);
        assert_eq!(wallet::Fingerprint::of(&later, "").unwrap(), fingerprint);
        let search = ContainerSearch::new(&format!("{abandon}? ?")).unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let refused = search.search_decoy(&reference, DECOY_SCAN_GAP, &mut |_, _| Ok(()));
        match refused {
            Err(MhfeError::Search(SearchError::SeveralMatches { matches })) => {
                assert!(matches >= 2)
            }
            other => panic!("not refused: {other:?}"),
        }
    }

    /// A comparison that matches the candidates of `matching`, with a path in each outcome to tell
    /// them apart.
    fn matching_at(
        matching: &'static [usize],
    ) -> impl Fn(usize, &dyn Fn() -> bool) -> Result<CheckOutcome, MhfeError> + Sync {
        move |index, _| {
            Ok(if matching.contains(&index) {
                CheckOutcome::Matches { path: None }
            } else {
                CheckOutcome::DoesNotMatch
            })
        }
    }

    /// Every candidate that matches is found, in the order of the candidates, on the workers and
    /// in turn alike; the comparison goes on after a first match (AUD-024-FUN001).
    #[test]
    fn every_matching_candidate_is_found_in_order() {
        let compare = matching_at(&[1, 3, 4]);
        let mut last = 0;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let found = compare_candidates(6, &compare, &mut |done, _| {
                last = done;
                Ok(())
            })
            .unwrap();
            let indexes: Vec<usize> = found.iter().map(|(index, _)| *index).collect();
            assert_eq!(indexes, [1, 3, 4]);
            assert_eq!(last, 6);
        }
        let in_turn = compare_in_turn(6, &compare, &mut |_, _| Ok(())).unwrap();
        let indexes: Vec<usize> = in_turn.iter().map(|(index, _)| *index).collect();
        assert_eq!(indexes, [1, 3, 4]);
        // A progress error ends the comparison in turn too.
        let stopped = compare_in_turn(6, &compare, &mut |_, _| Err(crate::CancelledError));
        assert_eq!(stopped.err(), Some(MhfeError::Cancelled));
    }

    /// One match is taken, none is none, and several are refused with their number.
    #[test]
    fn only_one_match_is_taken() {
        let matched = |indexes: &[usize]| {
            indexes
                .iter()
                .map(|&index| (index, CheckOutcome::Matches { path: None }))
                .collect::<Vec<_>>()
        };
        assert_eq!(only_match(matched(&[])).unwrap(), None);
        assert_eq!(
            only_match(matched(&[2])).unwrap().map(|(index, _)| index),
            Some(2)
        );
        assert_eq!(
            only_match(matched(&[2, 5])).err(),
            Some(MhfeError::Search(SearchError::SeveralMatches {
                matches: 2
            }))
        );
        assert_eq!(
            only_match(matched(&[2, 5])).err().unwrap().code(),
            "SEVERAL_CANDIDATES_MATCH"
        );
    }

    /// Without any reference, the built-in check of a 12-word original seed phrase finds the
    /// missing word; a same-length container, which has no such check, is refused.
    #[test]
    fn the_own_checks_find_the_missing_word_of_a_short_original() {
        let original = LEGAL_12;
        let password = test_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, original, Suite::TwentyFourWords);
        let search = ContainerSearch::new(&with(&container, &[(9, "?")])).unwrap();
        let found = search
            .search_own_checks(&mut mhfe, &password, None, &mut |_, _, _, _| Ok(()))
            .unwrap()
            .unwrap();
        assert_eq!(found.container.as_str(), container.as_str());
        let same_length = mhfe
            .encrypt(original, &password, Suite::SameLength, &mut |_, _| Ok(()))
            .unwrap();
        let short = ContainerSearch::new(&with(&same_length, &[(1, "?")])).unwrap();
        let refused = short.search_own_checks(&mut mhfe, &password, None, &mut |_, _, _, _| Ok(()));
        assert_eq!(refused.err().unwrap().code(), "NO_BUILT_IN_CHECK");
    }

    /// Two missing words search an address of the decoy in the first account, as far as the gap.
    #[test]
    fn the_decoy_address_scope_narrows_for_two_missing_words() {
        let container = zero_12_container();
        let one = ContainerSearch::new(&with(&container, &[(24, "?")])).unwrap();
        let two = ContainerSearch::new(&with(&container, &[(15, "?"), (21, "?")])).unwrap();
        assert!(one.offers_wallet_search());
        assert!(!two.offers_wallet_search());
        assert_eq!(
            one.decoy_address_limits(50).unwrap(),
            SearchLimits::default()
        );
        assert_eq!(
            two.decoy_address_limits(DECOY_SCAN_GAP).unwrap(),
            SearchLimits::new(1, DECOY_SCAN_GAP).unwrap()
        );
        assert!(two.decoy_address_limits(0).is_err());
    }

    #[test]
    fn a_search_needs_marked_words_and_not_too_many() {
        let container = zero_12_container();
        let code = |result: Result<ContainerSearch, SearchError>| result.err().unwrap().code();
        assert_eq!(code(ContainerSearch::new(&container)), "INVALID_REQUEST");
        assert_eq!(
            code(ContainerSearch::new(&with(
                &container,
                &[(1, "?"), (2, "?"), (3, "?")]
            ))),
            "TOO_MANY_MISSING_WORDS"
        );
        let search = ContainerSearch::new(&with(&container, &[(1, "?")])).unwrap();
        let built_in = Reference::BuiltInCheck {
            words: crate::WordCount::new(12).unwrap(),
        };
        let refused = search.search_decoy(&built_in, DECOY_SCAN_GAP, &mut |_, _| Ok(()));
        assert_eq!(refused.err().unwrap().code(), "INVALID_REQUEST");
        // Read as a repair reads it (AUD-024-API013): a word outside the list is missing, a
        // wrong length is said as such, and a checksum that fails names a wrong word.
        let outside = ContainerSearch::new(&with(&container, &[(5, "zzzz")])).unwrap();
        assert_eq!(outside.missing(), [5]);
        let short = format!(
            "{} ?",
            container.split(' ').take(10).collect::<Vec<_>>().join(" ")
        );
        let wrong_length = ContainerSearch::new(&short).err().unwrap();
        assert_eq!(wrong_length.code(), "INVALID_CONTAINER");
        assert!(
            wrong_length.to_string().contains("it has 11 words"),
            "{wrong_length}"
        );
        let first = container.split(' ').next().unwrap();
        let other = if first == "zoo" { "abandon" } else { "zoo" };
        let wrong_word = ContainerSearch::new(&with(&container, &[(1, other)]))
            .err()
            .unwrap();
        assert!(
            wrong_word
                .to_string()
                .contains("a word is wrong, not missing"),
            "{wrong_word}"
        );
    }

    /// With the owner's wallet, each candidate is recovered first: the fingerprint of the
    /// original seed phrase finds the container; two missing words are refused before any work.
    #[test]
    fn the_wallet_fingerprint_finds_the_missing_word_after_recoveries() {
        let original = LEGAL_12;
        let password = test_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, original, Suite::TwentyFourWords);
        let fingerprint = wallet::Fingerprint::of(original, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        let search = ContainerSearch::new(&with(&container, &[(24, "?")])).unwrap();
        let mut rounds = 0;
        let found = search
            .search_wallet(&mut mhfe, &password, &reference, &mut |_, count, _, _| {
                assert_eq!(count, 8);
                rounds += 1;
                Ok(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(found.container.as_str(), container.as_str());
        assert!(rounds >= 12, "at least one full recovery");
        let two = ContainerSearch::new(&with(&container, &[(1, "?"), (24, "?")])).unwrap();
        let refused = two.search_wallet(&mut mhfe, &password, &reference, &mut |_, _, _, _| {
            panic!("no round before the refusal")
        });
        assert_eq!(refused.err().unwrap().code(), "TOO_MANY_MISSING_WORDS");
    }

    /// A cancel ends the comparisons under way, not only the taking of new candidates: a long
    /// address search is left between its addresses, and the progress is not asked again
    /// (AUD-016-API001).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_cancel_ends_the_comparisons_under_way() {
        use std::time::{Duration, Instant};
        // A comparison that would run for a minute unless it is stopped.
        let compare = |_: usize, stopped: &dyn Fn() -> bool| {
            let end = Instant::now() + Duration::from_secs(60);
            while Instant::now() < end {
                if stopped() {
                    return Err(MhfeError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(CheckOutcome::DoesNotMatch)
        };
        let mut asked = 0;
        let began = Instant::now();
        let result = compare_candidates(4, &compare, &mut |_, _| {
            asked += 1;
            Err(crate::CancelledError)
        });
        assert_eq!(result.err(), Some(MhfeError::Cancelled));
        assert_eq!(asked, 1);
        assert!(began.elapsed() < Duration::from_secs(10));
    }
}
