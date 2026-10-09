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
//! what the reference proves: an address strongly, a fingerprint with 32 bits.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::engine::Argon2Engine;
use crate::packing;
use crate::phrase::{self, LIST_SIZE, WORD_BITS, WORD_COUNTS};
use crate::rehearsal::{self, CheckOutcome, Reference};
use crate::repair::ContainerReading;
use crate::wallet::SearchLimits;
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
pub type CandidateProgress<'a> = &'a mut dyn FnMut(usize, usize) -> Result<(), MhfeError>;
/// Hears every round of a search that recovers each candidate: `(candidate, count, round,
/// rounds)`; an error stops it.
pub type RecoveryProgress<'a> = &'a mut dyn FnMut(usize, usize, u32, u32) -> Result<(), MhfeError>;
/// Compares candidate `index` with the reference, from any of the threads that share them.
/// Compares one candidate; the second argument says when the search was stopped, which a long
/// address search asks between its addresses.
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
#[derive(Debug)]
pub struct Found {
    /// The container phrase, every word in full, one space apart.
    pub container: Zeroizing<String>,
    /// Each missing word as found, with its position from 1.
    pub words: Vec<(usize, &'static str)>,
    /// What the comparison found: for an address, the path where it was found.
    pub outcome: CheckOutcome,
}

impl ContainerSearch {
    /// Reads `written` as a repair reads it and lists the candidates. Words must be marked
    /// missing (`INVALID_REQUEST` otherwise), at most [`MAX_MISSING_FOR_DECOY`] of them
    /// (`TOO_MANY_MISSING_WORDS`).
    pub fn new(written: &str) -> Result<Self, MhfeError> {
        let ContainerReading::Marked { unreadable } = ContainerReading::read(written) else {
            return Err(MhfeError::InvalidRequest(
                "no word of the container phrase is marked missing: type ? in its place".to_owned(),
            ));
        };
        if unreadable.len() > MAX_MISSING_FOR_DECOY {
            return Err(MhfeError::TooManyMissingWords {
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
    pub fn decoy_address_limits(&self, scan_gap: u32) -> Result<SearchLimits, MhfeError> {
        if self.missing.len() > MAX_MISSING_FOR_WALLET {
            SearchLimits::first_account(scan_gap)
        } else {
            Ok(SearchLimits::default())
        }
    }

    /// Compares every candidate, as the decoy wallet, with `reference`: an address, searched
    /// within [`ContainerSearch::decoy_address_limits`] of `scan_gap` unless its path is given,
    /// or a fingerprint, with the passphrase it names: none for the container typed into a
    /// wallet as it is, the usual case, or the one the person says is used with the container
    /// phrase. Natively the candidates are shared among the processor's cores, and the first
    /// match stops them all; a WebAssembly build compares them in turn. `on_progress(done,
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
        let matched = compare_candidates(self.count(), &compare, on_progress)?;
        Ok(matched.map(|(index, outcome)| {
            let missing = &self.candidates[index];
            self.found(self.container(missing), missing, outcome)
        }))
    }

    /// Recovers every candidate with `password`, a full recovery each, until one matches
    /// `reference` as [`Mhfe::check`] compares it: an address or a fingerprint of the wallet, or
    /// the original seed phrase's own checks ([`ContainerSearch::search_own_checks`]). Only
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
            let outcome = mhfe.check(&container, password, reference, &mut |round, rounds| {
                on_progress(index + 1, count, round, rounds)
            })?;
            if outcome.matches() {
                return Ok(Some(self.found(container, missing, outcome)));
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
            return Err(MhfeError::TooManyMissingWords {
                missing: self.missing.len(),
                limit: MAX_MISSING_FOR_WALLET,
            });
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

    fn found(&self, container: Zeroizing<String>, missing: &[u16], outcome: CheckOutcome) -> Found {
        Found {
            container,
            words: self
                .missing
                .iter()
                .zip(missing)
                .map(|(&position, &number)| (position + 1, phrase::word(number)))
                .collect(),
            outcome,
        }
    }
}

/// Compares candidates `0..count` with `compare` and gives the first that matches with its
/// outcome. Natively the candidates are shared among the processor's cores, each taking the next
/// one left, while this thread reports how far they have come; a WebAssembly build, which has no
/// threads here, compares them in turn.
#[cfg(not(target_arch = "wasm32"))]
fn compare_candidates(
    count: usize,
    compare: CandidateCompare<'_>,
    on_progress: CandidateProgress<'_>,
) -> Result<Option<(usize, CheckOutcome)>, MhfeError> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    let workers = std::thread::available_parallelism()
        .map_or(1, |cores| cores.get())
        .min(count.max(1));
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);
    // `stop` ends the taking of candidates after a match, while the comparisons under way finish,
    // so that the lowest match wins; `abort`, after an error or a cancel, ends those too.
    let stop = AtomicBool::new(false);
    let abort = AtomicBool::new(false);
    // The match with the lowest index, so that the result does not depend on the threads' order.
    let matched: Mutex<Option<(usize, CheckOutcome)>> = Mutex::new(None);
    let failure: Mutex<Option<MhfeError>> = Mutex::new(None);
    // Keeps the error and ends every comparison, those under way too.
    let abort_with = |error| {
        *failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
        abort.store(true, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
    };
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    match compare(index, &|| abort.load(Ordering::Relaxed)) {
                        Ok(outcome) if outcome.matches() => {
                            let mut best = matched.lock().unwrap_or_else(|e| e.into_inner());
                            if best.as_ref().is_none_or(|(found, _)| index < *found) {
                                *best = Some((index, outcome));
                            }
                            stop.store(true, Ordering::Relaxed);
                        }
                        Ok(_) => {}
                        // A comparison abandoned after an abort: the abort's error stands.
                        Err(_) if abort.load(Ordering::Relaxed) => {}
                        Err(error) => abort_with(error),
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
                finished.fetch_add(1, Ordering::Release);
            });
        }
        // This thread tells how far the comparison has come; an error from it stops the workers.
        // After an abort it is not asked again while the workers end.
        while finished.load(Ordering::Acquire) < workers {
            std::thread::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS));
            if abort.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(error) = on_progress(done.load(Ordering::Relaxed).min(count), count) {
                abort_with(error);
            }
        }
    });
    if let Some(error) = failure.into_inner().unwrap_or_else(|e| e.into_inner()) {
        return Err(error);
    }
    let matched = matched.into_inner().unwrap_or_else(|e| e.into_inner());
    if matched.is_none() {
        on_progress(count, count)?;
    }
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
) -> Result<Option<(usize, CheckOutcome)>, MhfeError> {
    for index in 0..count {
        let outcome = compare(index, &|| false)?;
        on_progress(index + 1, count)?;
        if outcome.matches() {
            return Ok(Some((index, outcome)));
        }
    }
    Ok(None)
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
        return Err(MhfeError::InvalidRequest(
            "a search compares with a receiving address or a master key fingerprint".to_owned(),
        ));
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
type WordBits = [u8; 33];

fn pack(numbers: &[u16]) -> WordBits {
    let mut bits = [0_u8; 33];
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

    /// The decoy wallet's fingerprint finds the container among the candidates, also with two
    /// missing words, without the password; a fingerprint of another wallet finds nothing.
    #[test]
    fn the_decoy_fingerprint_finds_the_missing_words() {
        let container = zero_12_container();
        let fingerprint = wallet::master_fingerprint(&container, "").unwrap();
        let reference = Reference::Fingerprint {
            fingerprint,
            passphrase: "",
        };
        // Words 15 and 21, "also" and "ahead", come early in the list, where a debug build of the
        // tests reaches them in seconds.
        let search = ContainerSearch::new(&with(&container, &[(15, "?"), (21, "?")])).unwrap();
        assert!(search.count() > 8 * 2048 / 2, "about 16,384 candidates");
        let mut compared = 0;
        let found = search
            .search_decoy(&reference, DECOY_SCAN_GAP, &mut |done, _| {
                compared = done;
                Ok(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(*found.container, container);
        let words: Vec<&str> = container.split(' ').collect();
        assert_eq!(found.words, [(15, words[14]), (21, words[20])]);
        assert!(compared <= search.count());
        // The decoy is compared with the passphrase given only: with one it has not, the decoy
        // wallet of the container typed as it is does not match.
        let with_passphrase = Reference::Fingerprint {
            fingerprint,
            passphrase: "TREZOR",
        };
        let one = ContainerSearch::new(&with(&container, &[(24, "?")])).unwrap();
        assert!(one
            .search_decoy(&with_passphrase, DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .unwrap()
            .is_none());
        let other = Reference::Fingerprint {
            fingerprint: [0, 0, 0, 0],
            passphrase: "",
        };
        assert!(one
            .search_decoy(&other, DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .unwrap()
            .is_none());
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
        let code = |result: Result<ContainerSearch, MhfeError>| result.err().unwrap().code();
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
    }

    /// With the owner's wallet, each candidate is recovered first: the fingerprint of the
    /// original seed phrase finds the container; two missing words are refused before any work.
    #[test]
    fn the_wallet_fingerprint_finds_the_missing_word_after_recoveries() {
        let original = LEGAL_12;
        let password = test_password();
        let mut mhfe = reduced();
        let container = container_of(&mut mhfe, original, Suite::TwentyFourWords);
        let fingerprint = wallet::master_fingerprint(original, "").unwrap();
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
            Err(MhfeError::Cancelled)
        });
        assert_eq!(result.err(), Some(MhfeError::Cancelled));
        assert_eq!(asked, 1);
        assert!(began.elapsed() < Duration::from_secs(10));
    }
}
