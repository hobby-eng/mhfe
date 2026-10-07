//! The wallet check of a new seed phrase: the DRAFT profile MHFE-WALLET-CHECK-SEED-1, which the
//! specification defines as an optional source profile ("Optional source profile: a recovery check
//! for new 24-word phrases"), a creation mode the owner chooses. It is still experimental.
//!
//! A new phrase is drawn at random until its check passes. The check, byte for byte: the SHA-256
//! digest of
//!
//! - the ASCII tag `MHFE-WALLET-CHECK-SEED-1`, 24 bytes, with no terminating NUL;
//! - `BE32(ENT)`, the entropy's length in bits as a 4-byte big-endian number, 256 for 24 words;
//! - the raw 64-byte BIP39 seed: PBKDF2-HMAC-SHA512 with 2,048 iterations of the canonical English
//!   phrase of the entropy (its words in lower case, one space apart), with the salt "mnemonic"
//!   followed by the BIP39 passphrase in NFKD;
//!
//! starts with 16 zero bits: its first two bytes are zero.
//!
//! The check is defined for a 24-word phrase, whose entropy has 256 bits, and this library offers
//! it only with a BIP39 passphrase that is not empty, as the specification allows: one rule for
//! every front end, owned by [`require_passphrase`] and [`verify_entropy`]. A new phrase is drawn
//! with it only with a passphrase ([`PhraseDraw::with_check`]), and a recovery is checked against
//! it only as 24 words and with a passphrase ([`verify`], and the rehearsal's
//! `Reference::WalletCheck`), never as a shorter reading. Without a passphrase the seed would be a
//! function of the phrase alone, and anyone who saw the phrase could test the check. [`passes`]
//! computes the criterion itself for any passphrase, the empty one included: a recovery reports a
//! pass without a passphrase for a phrase that another program made in that form, and a hidden
//! wallet may pass neither form.
//!
//! A pass is statistical evidence, not proof. A random phrase with a given passphrase passes once
//! in about 65,536, so a wrong MHFE password or passphrase slips through at that rate, and a
//! passphrase that passes with a given phrase is found after about 65,536 tries by anyone who
//! searches for one. With a passphrase that is not empty, a guess of the MHFE password can be
//! tested only together with a guess of the passphrase. Drawing the phrase this way leaves about
//! 240 of its 256 bits of entropy for a given passphrase. The specification's deniability results
//! assume a uniformly random phrase; they do not by themselves cover a phrase drawn to pass the
//! check. The check never identifies the wallet: only an address or the fingerprint does that.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use bip39::{Language, Mnemonic};

use crate::memory::LockedText;
use crate::phrase::{self, locked_phrase_from_entropy};
use crate::random::{check_source, RandomSource};
use crate::{wallet, MhfeError};

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;
// The draw on several threads at once, for a native program; a page runs its draws in workers.
#[cfg(not(target_arch = "wasm32"))]
mod threads;

/// The bits the check fixes: 16, so that a wrong password passes once in 65,536, at a cost of 16
/// of the 256 bits of a 24-word phrase. A new phrase takes about 65,536 BIP39 seeds to find.
pub const WALLET_CHECK_BITS: u32 = 16;
/// The domain tag, which keeps the check apart from every other hash of the seed. Draft.
const DOMAIN: &[u8] = b"MHFE-WALLET-CHECK-SEED-1";
/// The entropy of a new 24-word phrase: 256 bits.
pub const NEW_ENTROPY_BYTES: usize = 32;

/// Whether `entropy` passes the criterion of the wallet check with `passphrase`, which may be empty
/// here; of any length BIP39 takes. A program that checks a recovery uses [`verify`] or
/// [`verify_entropy`], which hold the profile's rule.
pub fn passes(entropy: &[u8], passphrase: &str) -> Result<bool, MhfeError> {
    Ok(digest_passes(&*digest(entropy, passphrase)?))
}

/// The digest `T` of `entropy` with `passphrase`: the tagged SHA-256 of its BIP39 seed.
fn digest(entropy: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; 32]>, MhfeError> {
    let bits = u32::try_from(entropy.len() * 8).unwrap_or(u32::MAX);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|error| MhfeError::Internal(error.to_string()))?;
    let seed = wallet::bip39_seed(&mnemonic, passphrase);
    Ok(tagged_digest(bits, &seed[..]))
}

/// Whether a seed phrase passes the criterion of the wallet check with `passphrase`, as
/// [`passes`] does: of any length and with any passphrase.
pub fn phrase_passes(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    let mnemonic = phrase::parse(text).map_err(MhfeError::InvalidPhrase)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    passes(&entropy, passphrase)
}

/// Whether a digest `T` starts with [`WALLET_CHECK_BITS`] zero bits: the criterion of the check.
fn digest_passes(digest: &[u8; 32]) -> bool {
    let zero_bytes = (WALLET_CHECK_BITS / 8) as usize;
    digest[..zero_bytes].iter().all(|&byte| byte == 0)
}

/// `T = SHA-256(DOMAIN || BE32(bits) || seed)`, the digest the check reads; its self-check
/// compares all of it with the published vectors, not only its first bits.
fn tagged_digest(bits: u32, seed: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bits.to_be_bytes())
            .chain_update(seed)
            .finalize()
            .into(),
    )
}

/// Draws between two reports to the caller, which can show progress or stop the draw then.
pub const DRAW_REPORT_INTERVAL: u64 = 1024;
/// Words of a phrase the wallet check is offered for: new phrases have 24.
const CHECKED_WORDS: usize = 24;

/// The rule of the passphrase, for every front end: the wallet check is offered only with a BIP39
/// passphrase that is not empty (`WALLET_CHECK_NEEDS_PASSPHRASE` otherwise), for a new phrase as
/// for a recovery. A front end can ask this before anything else, as the rehearsal does before any
/// Argon2 work.
pub fn require_passphrase(passphrase: &str) -> Result<(), MhfeError> {
    if passphrase.is_empty() {
        return Err(MhfeError::WalletCheckNeedsPassphrase);
    }
    Ok(())
}

/// Whether a recovered 24-word phrase passes the wallet check with the passphrase the owner gives.
/// An empty passphrase is refused ([`require_passphrase`]), and so is a phrase of another length.
pub fn verify(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    require_passphrase(passphrase)?;
    let mnemonic = phrase::parse(text).map_err(MhfeError::InvalidPhrase)?;
    if mnemonic.word_count() != CHECKED_WORDS {
        return Err(MhfeError::InvalidWordCount(mnemonic.word_count()));
    }
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    verify_entropy(&entropy, passphrase)
}

/// [`verify`] for the entropy of the 24-word phrase, 256 bits, as the rehearsal reads it from a
/// recovered state: the profile's `BE32(256)` and nothing shorter. An empty passphrase is refused
/// ([`require_passphrase`]), and so is entropy of another length, by the words it would have.
pub fn verify_entropy(entropy: &[u8], passphrase: &str) -> Result<bool, MhfeError> {
    require_passphrase(passphrase)?;
    if entropy.len() != NEW_ENTROPY_BYTES {
        // Three words for every four bytes of entropy (BIP39).
        return Err(MhfeError::InvalidWordCount(entropy.len() / 4 * 3));
    }
    passes(entropy, passphrase)
}

/// How a new 24-word phrase is drawn: at random, or with the wallet check until it passes with a
/// BIP39 passphrase.
pub struct PhraseDraw {
    passphrase: Option<LockedText>,
}

impl PhraseDraw {
    /// One random phrase, without the check.
    pub fn unchecked() -> Self {
        Self { passphrase: None }
    }

    /// Phrases drawn until one passes the wallet check with `passphrase`, about 65,536 BIP39
    /// seeds. The check needs a passphrase ([`require_passphrase`]): without one, anyone who sees
    /// the phrase could test it.
    pub fn with_check(passphrase: &str) -> Result<Self, MhfeError> {
        require_passphrase(passphrase)?;
        Ok(Self {
            passphrase: Some(LockedText::copy_of(passphrase)),
        })
    }

    pub fn is_checked(&self) -> bool {
        self.passphrase.is_some()
    }

    /// Up to `count` draws from `source`: the first entropy that passes, or `None`. Several
    /// threads or workers may call it at once; taking the first entropy found by any of them
    /// leaves every passing entropy equally likely. An entropy of zeros, which a random source
    /// never gives in practice, means the source filled nothing and is refused.
    pub fn try_draws(
        &self,
        source: &mut dyn RandomSource,
        count: u64,
    ) -> Result<Option<Zeroizing<[u8; NEW_ENTROPY_BYTES]>>, MhfeError> {
        let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
        for _ in 0..count {
            source.fill(&mut entropy[..])?;
            if entropy.iter().all(|&byte| byte == 0) {
                return Err(MhfeError::RandomFailed(
                    "it gave an entropy of zeros".to_owned(),
                ));
            }
            let found = match &self.passphrase {
                None => true,
                Some(passphrase) => passes(&entropy[..], passphrase)?,
            };
            if found {
                return Ok(Some(entropy));
            }
        }
        Ok(None)
    }

    /// Draws until a phrase is found. The source is probed first ([`check_source`]), so that a
    /// source that fills nothing or repeats itself is refused before anything is drawn. `on_draws`
    /// hears the number of draws so far every [`DRAW_REPORT_INTERVAL`] draws; an error it returns
    /// stops the draw. The phrase found is read back before it is given out.
    pub fn draw(
        &self,
        source: &mut dyn RandomSource,
        on_draws: &mut dyn FnMut(u64) -> Result<(), MhfeError>,
    ) -> Result<NewPhrase, MhfeError> {
        check_source(source)?;
        let mut draws = 0;
        loop {
            if let Some(entropy) = self.try_draws(source, DRAW_REPORT_INTERVAL)? {
                return self.give_out(&entropy);
            }
            draws += DRAW_REPORT_INTERVAL;
            on_draws(draws)?;
        }
    }

    /// [`PhraseDraw::draw`] on every processor core at once, natively: one thread per core, each
    /// with its own source from `new_source`, which it probes ([`check_source`]) before its first
    /// draw. The first passing entropy any thread finds is taken, which leaves every passing
    /// entropy equally likely, and the others stop at their next draw. An error of any thread, a
    /// source that cannot be random among them, ends the draw with that error. `on_draws` hears
    /// the number of draws of all threads every [`DRAW_REPORT_INTERVAL`] draws, from whichever
    /// thread reaches it; an error it returns stops the draw. The phrase found is read back before
    /// it is given out. A draw without the check takes one entropy on the calling thread, as
    /// [`PhraseDraw::draw`] does.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn draw_on_every_core<S, F>(
        &self,
        new_source: F,
        on_draws: &mut (dyn FnMut(u64) -> Result<(), MhfeError> + Send),
    ) -> Result<NewPhrase, MhfeError>
    where
        S: RandomSource,
        F: Fn() -> S + Sync,
    {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        self.draw_on_threads(cores, &new_source, on_draws)
    }

    /// [`PhraseDraw::draw_on_every_core`] on `threads` threads.
    #[cfg(not(target_arch = "wasm32"))]
    fn draw_on_threads<S, F>(
        &self,
        threads: usize,
        new_source: &F,
        on_draws: &mut (dyn FnMut(u64) -> Result<(), MhfeError> + Send),
    ) -> Result<NewPhrase, MhfeError>
    where
        S: RandomSource,
        F: Fn() -> S + Sync,
    {
        if !self.is_checked() || threads <= 1 {
            return self.draw(&mut new_source(), on_draws);
        }
        let entropy = threads::ThreadedDraw::new(self, on_draws).run(threads, new_source)?;
        self.give_out(&entropy)
    }

    /// The phrase of a drawn `entropy`, read back before it is given out.
    fn give_out(&self, entropy: &[u8; NEW_ENTROPY_BYTES]) -> Result<NewPhrase, MhfeError> {
        // Written at its final size into a buffer locked first: Mnemonic::to_string would leave
        // growing copies of the first words in freed memory (AUD-008-SEC002).
        let phrase = locked_phrase_from_entropy(&entropy[..])?;
        self.read_back(&phrase, &entropy[..])?;
        Ok(NewPhrase {
            phrase,
            checked: self.is_checked(),
        })
    }

    /// Reads a new phrase as a person's program will read it: it must give back the entropy it
    /// was written from and, when drawn with the check, pass the check again. A fault between the
    /// drawing and the writing would otherwise give a phrase that is not the one drawn, or one
    /// whose check fails at the first recovery.
    fn read_back(&self, phrase: &str, entropy: &[u8]) -> Result<(), MhfeError> {
        let read = phrase::parse(phrase)
            .map_err(|_| MhfeError::Internal("a new phrase does not read back".to_owned()))?;
        let read = Zeroizing::new(read.to_entropy());
        if *read != entropy {
            return Err(MhfeError::Internal(
                "a new phrase reads back as another entropy".to_owned(),
            ));
        }
        if let Some(passphrase) = &self.passphrase {
            if !passes(&read, passphrase)? {
                return Err(MhfeError::Internal(
                    "a new phrase does not pass its wallet check when read back".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// A new phrase, kept out of swap and wiped when dropped.
pub struct NewPhrase {
    phrase: LockedText,
    checked: bool,
}

impl NewPhrase {
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Whether it was drawn to pass the wallet check.
    pub fn checked(&self) -> bool {
        self.checked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entropies of 32 bytes with `counter` in the last eight, as a deterministic stand-in for a
    /// random generator.
    fn counted(counter: u64) -> [u8; 32] {
        let mut entropy = [0u8; 32];
        entropy[24..].copy_from_slice(&counter.to_be_bytes());
        entropy
    }

    /// The first counter whose phrase passes with the public test passphrase "TREZOR": entropy of
    /// 24 zero bytes and 76,562, "abandon" 21 times, "above proof fatigue". Found once with the
    /// release build, about 65,536 BIP39 seeds, and confirmed by an independent computation.
    const TREZOR_COUNTER: u64 = 76_562;

    /// The first counter whose phrase passes with an empty passphrase: 24 zero bytes and 98,918,
    /// "abandon" 21 times, "absorb another spoil". Found with an independent Python computation
    /// (digest 0000ede7…), which also confirmed that it fails with "TREZOR" (8d2b97fb…).
    const EMPTY_COUNTER: u64 = 98_918;

    #[test]
    fn about_one_seed_in_65536_passes() {
        // The criterion alone, over counted 64-byte seeds: fast, unlike a BIP39 seed each.
        const TRIES: u64 = 1 << 20;
        let passing = (0..TRIES)
            .filter(|&counter| {
                let mut seed = [0u8; 64];
                seed[56..].copy_from_slice(&counter.to_be_bytes());
                digest_passes(&tagged_digest(256, &seed))
            })
            .count();
        // 16 expected; far outside 4 to 40 would mean the criterion is not uniform.
        assert!((4..=40).contains(&passing), "{passing}");
    }

    #[test]
    fn the_check_binds_the_passphrase() {
        let entropy = counted(TREZOR_COUNTER);
        assert!(passes(&entropy, "TREZOR").unwrap());
        assert!(!passes(&entropy, "trezor").unwrap());
        // Without the passphrase it is another seed, which fails: 0 leading zero bits.
        assert!(!passes(&entropy, "").unwrap());
        let phrase = crate::phrase::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(phrase_passes(&phrase, "TREZOR").unwrap());
    }

    #[test]
    fn a_wallet_without_a_passphrase_has_its_check_too() {
        let entropy = counted(EMPTY_COUNTER);
        assert!(passes(&entropy, "").unwrap());
        assert!(!passes(&entropy, "TREZOR").unwrap());
        let phrase = crate::phrase::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon absorb another spoil"));
        assert!(phrase_passes(&phrase, "").unwrap());
    }

    #[test]
    fn a_new_phrase_passes_and_an_unchecked_one_takes_the_first_draw() {
        // The counter starts just before the known passing one, so the search is short: the two
        // probes of the source take the next two counters, and the first draw the passing one.
        let counter = std::cell::Cell::new(TREZOR_COUNTER - 3);
        let mut fill = |bytes: &mut [u8]| {
            counter.set(counter.get() + 1);
            bytes.copy_from_slice(&counted(counter.get()));
            Ok(())
        };
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let checked = draw.draw(&mut fill, &mut |_| Ok(())).unwrap();
        assert_eq!(counter.get(), TREZOR_COUNTER);
        assert!(checked.checked());
        assert!(verify(checked.phrase(), "TREZOR").unwrap());
        // Written into a buffer locked first, as a recovered phrase is.
        assert_eq!(checked.phrase.is_locked(), cfg!(unix));
        let unchecked = PhraseDraw::unchecked()
            .draw(&mut fill, &mut |_| Ok(()))
            .unwrap();
        // Two probes of the source, then the one draw.
        assert_eq!(counter.get(), TREZOR_COUNTER + 3);
        assert_eq!(unchecked.phrase().split(' ').count(), 24);
        assert!(!unchecked.checked());
    }

    #[test]
    fn the_check_needs_a_passphrase_and_24_words() {
        assert!(matches!(
            PhraseDraw::with_check(""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        assert!(matches!(
            verify(twelve, "TREZOR"),
            Err(MhfeError::InvalidWordCount(12))
        ));
        let phrase = crate::phrase::phrase_from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        assert!(matches!(
            verify(&phrase, ""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        // The same rule for the entropy a recovery reads, which the rehearsal checks.
        let entropy = counted(TREZOR_COUNTER);
        assert_eq!(verify_entropy(&entropy, "TREZOR"), Ok(true));
        assert_eq!(verify_entropy(&entropy, "trezor"), Ok(false));
        assert_eq!(
            verify_entropy(&entropy, ""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(
            verify_entropy(&entropy[..16], "TREZOR"),
            Err(MhfeError::InvalidWordCount(12))
        );
        assert_eq!(
            require_passphrase(""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(require_passphrase("TREZOR"), Ok(()));
    }

    /// The criterion alone takes a phrase of any length, as a recovery's report without a
    /// passphrase does; the check does not (AUD-010): a public passphrase with which the 12-word
    /// test phrase passes the criterion is refused by `verify`.
    #[test]
    fn only_the_criterion_takes_a_short_phrase() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        let passphrase = "aud010 public probe 11656";
        assert_eq!(phrase_passes(twelve, passphrase), Ok(true));
        assert_eq!(
            verify(twelve, passphrase),
            Err(MhfeError::InvalidWordCount(12))
        );
    }

    #[test]
    fn a_draw_stops_when_told_and_refuses_a_source_of_zeros() {
        // Counters from 1: the first that passes with "TREZOR" is 76,562, far beyond these.
        let next = std::cell::Cell::new(0u64);
        let mut never = |bytes: &mut [u8]| {
            next.set(next.get() + 1);
            bytes.copy_from_slice(&counted(next.get()));
            Ok(())
        };
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let stopped = draw.draw(&mut never, &mut |draws| {
            assert_eq!(draws, DRAW_REPORT_INTERVAL);
            Err(MhfeError::Cancelled)
        });
        assert!(matches!(stopped, Err(MhfeError::Cancelled)));
        let mut zeros = |_: &mut [u8]| Ok(());
        assert!(matches!(
            PhraseDraw::unchecked().try_draws(&mut zeros, 1),
            Err(MhfeError::RandomFailed(_))
        ));
        // draw probes the source first: a stuck one is refused before any draw.
        let mut stuck = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        assert!(matches!(
            PhraseDraw::unchecked().draw(&mut stuck, &mut |_| Ok(())),
            Err(MhfeError::RandomFailed(_))
        ));
    }

    /// A stand-in for the system's generator on one thread: the [`counted`] entropies after
    /// `next`.
    #[cfg(not(target_arch = "wasm32"))]
    struct Counting {
        next: u64,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl RandomSource for Counting {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
            self.next += 1;
            bytes.copy_from_slice(&counted(self.next));
            Ok(())
        }
    }

    /// Sources for the threads of a draw, one per call: the first counts after `first`, each
    /// other one from 1, where none passes with "TREZOR" before [`TREZOR_COUNTER`]. Whichever
    /// thread finds a passing entropy first, it is the one of [`TREZOR_COUNTER`].
    #[cfg(not(target_arch = "wasm32"))]
    fn thread_sources(first: u64) -> impl Fn() -> Counting + Sync {
        let made = std::sync::atomic::AtomicUsize::new(0);
        move || Counting {
            next: if made.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                first
            } else {
                0
            },
        }
    }

    /// The draw on several threads gives the phrase the draw on one gives, read back and checked,
    /// whether on every core or on four threads.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_draw_on_several_threads_finds_the_passing_phrase() {
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let expected = crate::phrase::phrase_from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        // The first source's two probes take the two counters before the passing one.
        let first = TREZOR_COUNTER - 3;
        let found = draw
            .draw_on_every_core(thread_sources(first), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(found.phrase(), &*expected);
        assert!(found.checked());
        let found = draw
            .draw_on_threads(4, &thread_sources(first), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(found.phrase(), &*expected);
        assert!(verify(found.phrase(), "TREZOR").unwrap());
        // A draw without the check takes one entropy on the calling thread, after the probes.
        let unchecked = PhraseDraw::unchecked()
            .draw_on_threads(4, &thread_sources(10), &mut |_| Ok(()))
            .unwrap();
        let thirteenth = crate::phrase::phrase_from_entropy(&counted(13)).unwrap();
        assert_eq!(unchecked.phrase(), &*thirteenth);
        assert!(!unchecked.checked());
    }

    /// Every thread probes its own source: one that fills nothing ends the draw with
    /// RANDOM_FAILED, and the callback can stop it, hearing the count of all threads.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_draw_on_several_threads_refuses_a_bad_source_and_stops_when_told() {
        /// The first source fills nothing; the others count from 1.
        enum OneBad {
            Zeros,
            Counting(Counting),
        }
        impl RandomSource for OneBad {
            fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
                match self {
                    Self::Zeros => {
                        bytes.fill(0);
                        Ok(())
                    }
                    Self::Counting(counting) => counting.fill(bytes),
                }
            }
        }
        let draw = PhraseDraw::with_check("TREZOR").unwrap();
        let made = std::sync::atomic::AtomicUsize::new(0);
        let one_bad = || {
            if made.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                OneBad::Zeros
            } else {
                OneBad::Counting(Counting { next: 0 })
            }
        };
        assert!(matches!(
            draw.draw_on_threads(4, &one_bad, &mut |_| Ok(())),
            Err(MhfeError::RandomFailed(_))
        ));
        let mut heard = Vec::new();
        let stopped = draw.draw_on_threads(4, &thread_sources(0), &mut |draws| {
            heard.push(draws);
            Err(MhfeError::Cancelled)
        });
        assert!(matches!(stopped, Err(MhfeError::Cancelled)));
        assert_eq!(heard, [DRAW_REPORT_INTERVAL]);
    }

    /// A phrase is read back before it is given out: one that gives back another entropy, or
    /// fails its check, is refused.
    #[test]
    fn a_new_phrase_is_read_back() {
        let entropy = counted(TREZOR_COUNTER);
        let phrase = crate::phrase::phrase_from_entropy(&entropy).unwrap();
        let checked = PhraseDraw::with_check("TREZOR").unwrap();
        assert_eq!(checked.read_back(&phrase, &entropy), Ok(()));
        let other = counted(TREZOR_COUNTER + 1);
        assert!(checked.read_back(&phrase, &other).is_err());
        let other_phrase = crate::phrase::phrase_from_entropy(&other).unwrap();
        assert_eq!(
            checked.read_back(&other_phrase, &other).unwrap_err().code(),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            PhraseDraw::unchecked().read_back(&other_phrase, &other),
            Ok(())
        );
    }
}
