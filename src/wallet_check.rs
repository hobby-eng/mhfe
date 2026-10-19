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
//! every front end, owned by [`WalletCheck::require_passphrase`] and [`WalletCheck::verify_entropy`]. A new phrase is drawn
//! with it only with a passphrase ([`PhraseDraw::with_check`]), and a recovery is checked against
//! it only as 24 words and with a passphrase ([`WalletCheck::verify`], and the rehearsal's
//! `Reference::WalletCheck`), never as a shorter reading. Without a passphrase the seed would be a
//! function of the phrase alone, and anyone who saw the phrase could test the check. [`WalletCheck::passes`]
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

use crate::memory::LockedText;
use crate::phrase::{self, locked_phrase_from_entropy};
use crate::random::{RandomError, RandomSampler, RandomSource};
use crate::word_wishes::{WishOdds, WordWishes};
mod error;
pub use error::{DrawReadback, WalletCheckError};

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
/// One in this many wrong passwords passes the check, and a new phrase takes about as many draws:
/// 2^[`WALLET_CHECK_BITS`], 65,536.
pub const WALLET_CHECK_ODDS: u64 = 1 << WALLET_CHECK_BITS;
/// The domain tag, which keeps the check apart from every other hash of the seed. Draft.
const DOMAIN: &[u8] = b"MHFE-WALLET-CHECK-SEED-1";
/// The entropy of a new 24-word phrase: 256 bits, the whole state of a container.
pub const NEW_ENTROPY_BYTES: usize = crate::packing::STATE_BYTES;
/// [`NEW_ENTROPY_BYTES`] in bits.
pub const NEW_ENTROPY_BITS: usize = NEW_ENTROPY_BYTES * u8::BITS as usize;

/// The wallet-check criterion with one BIP39 passphrase, borrowed without another secret copy.
///
/// Constructing it does no work. Criterion methods accept an empty passphrase and any BIP39
/// length; verification methods first require a nonempty passphrase and a 24-word phrase.
/// Every seed derivation checks the library's passphrase-size bound.
pub struct WalletCheck<'a> {
    passphrase: &'a str,
}

impl<'a> WalletCheck<'a> {
    /// Chooses the passphrase of this check; an empty string means the wallet without one.
    pub const fn new(passphrase: &'a str) -> Self {
        Self { passphrase }
    }

    /// Whether `entropy` passes the criterion of the wallet check with `passphrase`, which may be empty
    /// here; of any length BIP39 takes. A program that checks a recovery uses [`WalletCheck::verify`] or
    /// [`WalletCheck::verify_entropy`], which hold the profile's rule.
    pub fn passes(&self, entropy: &[u8]) -> Result<bool, WalletCheckError> {
        Ok(digest_passes(&*digest(entropy, self.passphrase)?))
    }

    /// Whether a seed phrase passes the criterion of the wallet check with `passphrase`, as
    /// [`WalletCheck::passes`] does: of any length and with any passphrase.
    pub fn phrase_passes(&self, text: &str) -> Result<bool, WalletCheckError> {
        let mnemonic = phrase::parse(text).map_err(WalletCheckError::from)?;
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        self.passes(&entropy)
    }

    /// The rule of the passphrase, for every front end: the wallet check is offered only with a BIP39
    /// passphrase that is not empty (`WALLET_CHECK_NEEDS_PASSPHRASE` otherwise), for a new phrase as
    /// for a recovery. A front end can ask this before anything else, as the rehearsal does before any
    /// Argon2 work.
    pub fn require_passphrase(&self) -> Result<(), WalletCheckError> {
        if self.passphrase.is_empty() {
            return Err(WalletCheckError::NeedsPassphrase);
        }
        Ok(())
    }

    /// The rule of a new wallet's passphrase, typed twice: the repetition must be exactly the same text
    /// (`PASSPHRASES_DIFFER` otherwise). An empty passphrase, none, is typed once and needs none.
    /// The original text must fit the shared BIP39 byte limit before normalization or drawing
    /// (`PASSPHRASE_TOO_LONG` otherwise), including when no wallet check is requested.
    pub fn require_same_passphrase(&self, repeat: &str) -> Result<(), WalletCheckError> {
        crate::bip39_seed::require_size(self.passphrase)?;
        if !self.passphrase.is_empty() && repeat != self.passphrase {
            return Err(WalletCheckError::PassphrasesDiffer);
        }
        Ok(())
    }

    /// Whether a recovered 24-word phrase passes the wallet check with the passphrase the owner gives.
    ///
    /// An empty passphrase is refused ([`WalletCheck::require_passphrase`]), and so is a phrase of another length.
    pub fn verify(&self, text: &str) -> Result<bool, WalletCheckError> {
        self.require_passphrase()?;
        let mnemonic = phrase::parse(text).map_err(WalletCheckError::from)?;
        if mnemonic.word_count() != crate::packing::STATE_WORDS {
            return Err(WalletCheckError::WordCount(mnemonic.word_count()));
        }
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        self.verify_entropy(&entropy)
    }

    /// [`WalletCheck::verify`] for the entropy of the 24-word phrase, 256 bits, as the rehearsal reads it from a
    /// recovered state: the profile's `BE32(256)` and nothing shorter. An empty passphrase is refused
    /// ([`WalletCheck::require_passphrase`]), and so is entropy of another length, by the words it would have.
    pub fn verify_entropy(&self, entropy: &[u8]) -> Result<bool, WalletCheckError> {
        self.require_passphrase()?;
        if entropy.len() != NEW_ENTROPY_BYTES {
            return Err(WalletCheckError::WordCount(
                crate::packing::words_of_entropy(entropy.len()),
            ));
        }
        self.passes(entropy)
    }
}

/// The digest `T` of `entropy` with `passphrase`: the tagged SHA-256 of its BIP39 seed.
fn digest(entropy: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; 32]>, WalletCheckError> {
    let mnemonic = phrase::mnemonic_of(entropy)?;
    // The shared guard bounds this multiplication to a valid BIP39 entropy.
    let bits = (entropy.len() * u8::BITS as usize) as u32;
    let seed = crate::bip39_seed::derive(&mnemonic, passphrase)?;
    Ok(tagged_digest(bits, &seed[..]))
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
/// Hears the number of draws so far, from whichever thread reaches the next report; an error it
/// returns stops the draw.
#[cfg(not(target_arch = "wasm32"))]
pub type SharedDrawReport<'a> = &'a mut (dyn FnMut(u64) -> Result<(), WalletCheckError> + Send);

/// How a new 24-word phrase is drawn: at random, or with the wallet check until it passes with a
/// BIP39 passphrase.
pub struct PhraseDraw {
    passphrase: Option<LockedText>,
    /// The words the phrase must hold and avoid; none by default.
    wishes: WordWishes,
}

impl PhraseDraw {
    /// One random phrase, without the check.
    pub fn unchecked() -> Self {
        Self {
            passphrase: None,
            wishes: WordWishes::none(),
        }
    }

    /// Phrases drawn until one passes the wallet check with `passphrase`, about 65,536 BIP39
    /// seeds. The check needs a passphrase ([`WalletCheck::require_passphrase`]): without one, anyone who sees
    /// the phrase could test it.
    pub fn with_check(passphrase: &str) -> Result<Self, WalletCheckError> {
        WalletCheck::new(passphrase).require_passphrase()?;
        crate::bip39_seed::require_size(passphrase)?;
        Ok(Self {
            passphrase: Some(LockedText::copy_of(passphrase)),
            wishes: WordWishes::none(),
        })
    }

    /// The same draw for a phrase that also meets `wishes`. Their limits keep it quick and leave
    /// it enough random bits ([`crate::word_wishes`]); [`PhraseDraw::odds`] says how many.
    pub fn with_wishes(self, wishes: WordWishes) -> Self {
        Self { wishes, ..self }
    }

    /// Whether the phrase is drawn with the wallet check.
    pub fn is_checked(&self) -> bool {
        self.passphrase.is_some()
    }

    /// The bits the check takes from the phrase's randomness: [`WALLET_CHECK_BITS`], or 0.
    pub fn check_bits(&self) -> u32 {
        if self.is_checked() {
            WALLET_CHECK_BITS
        } else {
            0
        }
    }

    /// What the phrase keeps of its randomness and how many draws it is expected to take, for a
    /// front end to say before it draws.
    pub fn odds(&self) -> WishOdds {
        self.wishes.odds(self.check_bits())
    }

    /// Up to `count` draws from `source`: the first entropy that passes, or `None`. Several
    /// threads or workers may call it at once; taking the first entropy found by any of them
    /// leaves every passing entropy equally likely. An entropy that a random source never gives
    /// in practice is refused: one of a single byte value, zeros among them, as from a source that
    /// fills nothing or is stuck, or one equal to the entropy drawn before it (AUD-024-SEC014).
    /// The preceding entropy is retained within this call; [`PhraseDraw::draw`] also retains it
    /// across its progress batches. Separate `try_draws` calls start independent histories.
    pub fn try_draws(
        &self,
        source: &mut dyn RandomSource,
        count: u64,
    ) -> Result<Option<Zeroizing<[u8; NEW_ENTROPY_BYTES]>>, WalletCheckError> {
        self.draws_after(source, count, &mut Zeroizing::new([0u8; NEW_ENTROPY_BYTES]))
    }

    /// [`PhraseDraw::try_draws`] after the entropy `previous`, which it compares the first draw
    /// with, and where it leaves the last entropy it drew, as the source gave it.
    pub(crate) fn draws_after(
        &self,
        source: &mut dyn RandomSource,
        count: u64,
        previous: &mut [u8; NEW_ENTROPY_BYTES],
    ) -> Result<Option<Zeroizing<[u8; NEW_ENTROPY_BYTES]>>, WalletCheckError> {
        let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
        for _ in 0..count {
            source.fill(&mut entropy[..])?;
            if entropy.iter().all(|&byte| byte == entropy[0]) || *entropy == *previous {
                return Err(RandomError::UnusableEntropy.into());
            }
            previous.copy_from_slice(&entropy[..]);
            // The chosen words' bits are set after the source's bytes are judged, and a phrase
            // that misses a wish is drawn again, before the check's costly seed.
            self.wishes.apply(&mut entropy);
            if !self.wishes.met_by(&entropy) {
                continue;
            }
            let found = match &self.passphrase {
                None => true,
                Some(passphrase) => WalletCheck::new(passphrase).passes(&entropy[..])?,
            };
            if found {
                return Ok(Some(entropy));
            }
        }
        Ok(None)
    }

    /// Draws until a phrase is found. The source is probed first ([`RandomSampler::check_source`]), so that a
    /// source that fills nothing or repeats itself is refused before anything is drawn. `on_draws`
    /// hears the number of draws so far every [`DRAW_REPORT_INTERVAL`] draws; an error it returns
    /// stops the draw. The phrase found is read back before it is given out.
    pub fn draw(
        &self,
        source: &mut dyn RandomSource,
        on_draws: &mut dyn FnMut(u64) -> Result<(), WalletCheckError>,
    ) -> Result<NewPhrase, WalletCheckError> {
        RandomSampler::new(source).check_source()?;
        let mut draws = 0;
        let mut previous = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
        loop {
            if let Some(entropy) = self.draws_after(source, DRAW_REPORT_INTERVAL, &mut previous)? {
                return self.give_out(&entropy);
            }
            draws += DRAW_REPORT_INTERVAL;
            on_draws(draws)?;
        }
    }

    /// [`PhraseDraw::draw`] on every processor core at once, natively: one thread per core, each
    /// with its own source from `new_source`, which it probes ([`RandomSampler::check_source`]) before its first
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
        on_draws: SharedDrawReport<'_>,
    ) -> Result<NewPhrase, WalletCheckError>
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
        on_draws: SharedDrawReport<'_>,
    ) -> Result<NewPhrase, WalletCheckError>
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
    fn give_out(&self, entropy: &[u8; NEW_ENTROPY_BYTES]) -> Result<NewPhrase, WalletCheckError> {
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
    fn read_back(&self, phrase: &str, entropy: &[u8]) -> Result<(), WalletCheckError> {
        let read = phrase::parse(phrase)
            .map_err(|_| WalletCheckError::Readback(DrawReadback::Unreadable))?;
        let read = Zeroizing::new(read.to_entropy());
        if *read != entropy {
            return Err(WalletCheckError::Readback(DrawReadback::Entropy));
        }
        let words: &[u8; NEW_ENTROPY_BYTES] = (&read[..])
            .try_into()
            .map_err(|_| WalletCheckError::Readback(DrawReadback::Length))?;
        if !self.wishes.met_by(words) {
            return Err(WalletCheckError::Readback(DrawReadback::Wishes));
        }
        if let Some(passphrase) = &self.passphrase {
            if !WalletCheck::new(passphrase).passes(&read)? {
                return Err(WalletCheckError::Readback(DrawReadback::WalletCheck));
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
    /// The 24 words, one space apart.
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
    use crate::test_support::{counted, EMPTY_COUNTER, TREZOR_COUNTER};

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
        assert!(WalletCheck::new("TREZOR").passes(&entropy).unwrap());
        assert!(!WalletCheck::new("trezor").passes(&entropy).unwrap());
        // Without the passphrase it is another seed, which fails: 0 leading zero bits.
        assert!(!WalletCheck::new("").passes(&entropy).unwrap());
        let phrase = crate::phrase::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(WalletCheck::new("TREZOR").phrase_passes(&phrase).unwrap());
    }

    #[test]
    fn a_wallet_without_a_passphrase_has_its_check_too() {
        let entropy = counted(EMPTY_COUNTER);
        assert!(WalletCheck::new("").passes(&entropy).unwrap());
        assert!(!WalletCheck::new("TREZOR").passes(&entropy).unwrap());
        let phrase = crate::phrase::phrase_from_entropy(&entropy).unwrap();
        assert!(phrase.ends_with("abandon absorb another spoil"));
        assert!(WalletCheck::new("").phrase_passes(&phrase).unwrap());
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
        assert!(WalletCheck::new("TREZOR").verify(checked.phrase()).unwrap());
        // Written into a buffer locked first, as a recovered phrase is.
        assert_eq!(checked.phrase.is_locked(), cfg!(any(unix, windows)));
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
            Err(WalletCheckError::NeedsPassphrase)
        ));
        let twelve = crate::test_support::ABANDON_12;
        assert!(matches!(
            WalletCheck::new("TREZOR").verify(twelve),
            Err(WalletCheckError::WordCount(12))
        ));
        let phrase = crate::phrase::phrase_from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        assert!(matches!(
            WalletCheck::new("").verify(&phrase),
            Err(WalletCheckError::NeedsPassphrase)
        ));
        // The same rule for the entropy a recovery reads, which the rehearsal checks.
        let entropy = counted(TREZOR_COUNTER);
        assert_eq!(
            WalletCheck::new("TREZOR").verify_entropy(&entropy),
            Ok(true)
        );
        assert_eq!(
            WalletCheck::new("trezor").verify_entropy(&entropy),
            Ok(false)
        );
        assert_eq!(
            WalletCheck::new("").verify_entropy(&entropy),
            Err(WalletCheckError::NeedsPassphrase)
        );
        assert_eq!(
            WalletCheck::new("TREZOR").verify_entropy(&entropy[..16]),
            Err(WalletCheckError::WordCount(12))
        );
        assert_eq!(
            WalletCheck::new("").require_passphrase(),
            Err(WalletCheckError::NeedsPassphrase)
        );
        assert_eq!(WalletCheck::new("TREZOR").require_passphrase(), Ok(()));
    }

    /// The library's messages write the odds out, as "65,536"; they must stay the check's.
    #[test]
    fn messages_give_the_odds_of_the_check() {
        assert_eq!(WALLET_CHECK_ODDS, 65_536);
        assert!(crate::MhfeError::Hidden(crate::HiddenError::PassesCheck)
            .to_string()
            .contains("once in 65,536"));
    }

    #[test]
    fn a_new_passphrase_must_be_repeated_exactly() {
        assert_eq!(
            WalletCheck::new("TREZOR").require_same_passphrase("TREZOR"),
            Ok(())
        );
        assert_eq!(WalletCheck::new("").require_same_passphrase(""), Ok(()));
        assert_eq!(
            WalletCheck::new("").require_same_passphrase("unused"),
            Ok(())
        );
        for repeat in ["trezor", "TREZOR ", ""] {
            assert_eq!(
                WalletCheck::new("TREZOR").require_same_passphrase(repeat),
                Err(WalletCheckError::PassphrasesDiffer)
            );
        }
    }

    #[test]
    fn a_repeated_new_passphrase_is_bounded_as_typed() {
        use unicode_normalization::UnicodeNormalization;
        let expanding = format!("{}a", "\u{FDFA}".repeat(341));
        assert_eq!(expanding.len(), 1024);
        assert!(expanding.nfkd().map(char::len_utf8).sum::<usize>() > 1024);
        for valid in ["a".repeat(1024), expanding] {
            assert_eq!(
                WalletCheck::new(&valid).require_same_passphrase(&valid),
                Ok(())
            );
        }
        let contracting = format!("{}aa", "\u{FF21}".repeat(341));
        assert_eq!(contracting.len(), 1025);
        assert!(contracting.nfkd().map(char::len_utf8).sum::<usize>() < 1024);
        for over in ["a".repeat(1025), contracting] {
            for repeat in [&*over, "different"] {
                assert_eq!(
                    WalletCheck::new(&over).require_same_passphrase(repeat),
                    Err(WalletCheckError::Passphrase(
                        crate::PassphraseError::TooLong(1025)
                    ))
                );
            }
            assert_eq!(
                WalletCheck::new("in-bound").require_same_passphrase(&over),
                Err(WalletCheckError::PassphrasesDiffer)
            );
        }
    }

    /// The criterion alone takes a phrase of any length, as a recovery's report without a
    /// passphrase does; the check does not (AUD-010): a public passphrase with which the 12-word
    /// test phrase passes the criterion is refused by `verify`.
    #[test]
    fn only_the_criterion_takes_a_short_phrase() {
        let twelve = crate::test_support::ABANDON_12;
        let passphrase = "aud010 public probe 11656";
        assert_eq!(WalletCheck::new(passphrase).phrase_passes(twelve), Ok(true));
        assert_eq!(
            WalletCheck::new(passphrase).verify(twelve),
            Err(WalletCheckError::WordCount(12))
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
            Err(WalletCheckError::Cancelled)
        });
        assert!(matches!(stopped, Err(WalletCheckError::Cancelled)));
        let mut zeros = |_: &mut [u8]| Ok(());
        assert!(matches!(
            PhraseDraw::unchecked().try_draws(&mut zeros, 1),
            Err(WalletCheckError::Random(_))
        ));
        // draw probes the source first: a stuck one is refused before any draw.
        let mut stuck = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        assert!(matches!(
            PhraseDraw::unchecked().draw(&mut stuck, &mut |_| Ok(())),
            Err(WalletCheckError::Random(_))
        ));
    }

    /// A source that gets stuck after its probes, on one byte or on one block, gives no phrase
    /// but RANDOM_FAILED, on one thread and on several (AUD-024-SEC014).
    #[test]
    fn a_source_stuck_after_its_probes_gives_no_phrase() {
        let stuck_after_probes = |block: [u8; NEW_ENTROPY_BYTES]| {
            let mut fills = 0u64;
            move |bytes: &mut [u8]| {
                fills += 1;
                if fills <= 2 {
                    bytes.copy_from_slice(&counted(fills));
                } else {
                    bytes.copy_from_slice(&block);
                }
                Ok(())
            }
        };
        let mut block = counted(TREZOR_COUNTER - 1);
        block[0] = 0x5a;
        for stuck in [[0xff; NEW_ENTROPY_BYTES], [0x5a; NEW_ENTROPY_BYTES], block] {
            for draw in [
                PhraseDraw::unchecked(),
                PhraseDraw::with_check("TREZOR").unwrap(),
            ] {
                let drawn = draw.draw(&mut stuck_after_probes(stuck), &mut |_| Ok(()));
                // An unchecked draw takes the first block; only a repeated one is refused.
                if stuck == block && !draw.is_checked() {
                    assert!(drawn.is_ok());
                    continue;
                }
                assert!(
                    matches!(drawn, Err(WalletCheckError::Random(_))),
                    "{stuck:?}"
                );
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let threaded =
                        draw.draw_on_threads(4, &|| stuck_after_probes(stuck), &mut |_| Ok(()));
                    assert!(
                        matches!(threaded, Err(WalletCheckError::Random(_))),
                        "{stuck:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_repeated_entropy_across_progress_batches_is_refused() {
        let draw = PhraseDraw::unchecked().with_wishes(WordWishes::new(&[], &["abandon"]).unwrap());
        // Every counter has a leading "abandon", so none meets the exclusion and no seed runs.
        let mut script = Vec::new();
        for counter in 1..=DRAW_REPORT_INTERVAL {
            script.extend_from_slice(&counted(counter));
        }
        script.extend_from_slice(&counted(DRAW_REPORT_INTERVAL));
        let mut source = crate::random::ScriptedSource::after_probes(&script);
        let mut reports = Vec::new();
        let result = draw.draw(&mut source, &mut |draws| {
            reports.push(draws);
            Ok(())
        });
        assert!(
            matches!(
                result,
                Err(WalletCheckError::Random(RandomError::UnusableEntropy))
            ),
            "the previous source entropy must survive a progress report"
        );
        assert_eq!(reports, [DRAW_REPORT_INTERVAL]);
    }

    /// A stand-in for the system's generator on one thread: the [`counted`] entropies after
    /// `next`.
    #[cfg(not(target_arch = "wasm32"))]
    struct Counting {
        next: u64,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl RandomSource for Counting {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
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
        assert!(WalletCheck::new("TREZOR").verify(found.phrase()).unwrap());
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
            fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
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
            Err(WalletCheckError::Random(_))
        ));
        let mut heard = Vec::new();
        let stopped = draw.draw_on_threads(4, &thread_sources(0), &mut |draws| {
            heard.push(draws);
            Err(WalletCheckError::Cancelled)
        });
        assert!(matches!(stopped, Err(WalletCheckError::Cancelled)));
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
