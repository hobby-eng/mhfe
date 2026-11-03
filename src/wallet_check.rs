//! The wallet check of a new seed phrase: the DRAFT profile MHFE-WALLET-CHECK-SEED-1, which the
//! specification defines as an optional source profile ("Optional source profile: a recovery check
//! for new 24-word phrases"), a creation mode the owner chooses. It is still experimental.
//!
//! A new phrase is drawn at random until its check passes. The draw and the check itself, on the
//! BIP39 seed of the phrase and a passphrase, are the core's: [`mhfe_core::wallet_check`] gives
//! them byte for byte.
//!
//! The check is defined for a 24-word phrase, whose entropy has 256 bits, and this library offers
//! it only with a BIP39 passphrase that is not empty, as the specification allows: one rule for
//! every front end, owned by [`require_passphrase`] and [`verify`]. A new phrase is drawn with it
//! only with a passphrase ([`PhraseDraw::with_check`]), and a recovery is checked against it only
//! as 24 words and with a passphrase ([`verify`], and the rehearsal's `Reference::WalletCheck`),
//! never as a shorter reading. Without a passphrase the seed would be a function of the phrase
//! alone, and anyone who saw the phrase could test the check. [`phrase_passes`] computes the
//! criterion itself for any passphrase, the empty one included: a recovery reports a pass without a
//! passphrase for a phrase that another program made in that form, and a hidden wallet may pass
//! neither form.
//!
//! A pass is statistical evidence, not proof. A random phrase with a given passphrase passes once
//! in about 65,536, so a wrong MHFE password or passphrase slips through at that rate, and a
//! passphrase that passes with a given phrase is found after about 65,536 tries by anyone who
//! searches for one. With a passphrase that is not empty, a guess of the MHFE password can be
//! tested only together with a guess of the passphrase. Drawing the phrase this way leaves about
//! 240 of its 256 bits of entropy for a given passphrase. The specification's deniability results
//! assume a uniformly random phrase; they do not by themselves cover a phrase drawn to pass the
//! check. The check never identifies the wallet: only an address or the fingerprint does that.

use std::ops::ControlFlow;

use mhfe_core::wallet_check::Seed;
use mhfe_core::Phrase;
use zeroize::Zeroizing;

use crate::memory::LockedText;
use crate::random::{check_source, RandomSource};
use crate::word_wishes::{WishOdds, WordWishes};
use crate::{read_phrase, MhfeError};

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) mod known_answers;

/// The bits the check fixes: 16, so that a wrong password passes once in 65,536, at a cost of 16
/// of the 256 bits of a 24-word phrase. A new phrase takes about 65,536 BIP39 seeds to find. A
/// deliberate copy of `CHECK_BITS` in the core's src/wallet_check.rs, which keeps it private, for
/// what the front ends say of the check: a change goes to both.
pub const WALLET_CHECK_BITS: u32 = 16;
/// One in this many wrong passwords passes the check, and a new phrase takes about as many draws:
/// 2^[`WALLET_CHECK_BITS`], 65,536.
pub const WALLET_CHECK_ODDS: u64 = 1 << WALLET_CHECK_BITS;
/// The entropy of a new 24-word phrase: 256 bits, the whole state of a container.
pub const NEW_ENTROPY_BYTES: usize = crate::packing::STATE_BYTES;

/// Whether a seed phrase passes the criterion of the wallet check with `passphrase`, which may be
/// empty here. The profile defines it for 24 words alone, so a phrase of another length does not
/// pass. A program that checks a recovery uses [`verify`], which holds the profile's rule.
pub fn phrase_passes(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    Ok(meets_criterion(&read_phrase(text)?, passphrase))
}

/// The criterion itself. The core has no answer below 24 words, which is no pass.
fn meets_criterion(phrase: &Phrase, passphrase: &str) -> bool {
    Seed::derive(phrase, passphrase).passes() == Some(true)
}

/// Draws between two reports to the caller, which can show progress or stop the draw then.
pub const DRAW_REPORT_INTERVAL: u64 = 1024;
/// How many times the expected number of draws a draw may take before it stops: a working
/// generator needs more with a probability of about e^-64, so reaching it means a broken one.
pub const DRAW_LIMIT_FACTOR: f64 = 64.0;

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

/// The rule of a new wallet's passphrase, typed twice: the repetition must be exactly the same text
/// (`PASSPHRASES_DIFFER` otherwise), so a repetition alone is no empty passphrase.
pub fn require_same_passphrase(passphrase: &str, repeat: &str) -> Result<(), MhfeError> {
    if repeat != passphrase {
        return Err(MhfeError::PassphrasesDiffer);
    }
    Ok(())
}

/// Whether a recovered 24-word phrase passes the wallet check with the passphrase the owner gives.
/// An empty passphrase is refused ([`require_passphrase`]), and so is a phrase of another length.
pub fn verify(text: &str, passphrase: &str) -> Result<bool, MhfeError> {
    require_passphrase(passphrase)?;
    let phrase = read_phrase(text)?;
    if phrase.words() != crate::packing::STATE_WORDS {
        return Err(MhfeError::NoWalletCheckAtLength(phrase.words()));
    }
    Ok(meets_criterion(&phrase, passphrase))
}

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
    /// seeds. The check needs a passphrase ([`require_passphrase`]): without one, anyone who sees
    /// the phrase could test it.
    pub fn with_check(passphrase: &str) -> Result<Self, MhfeError> {
        require_passphrase(passphrase)?;
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

    /// The most draws this draw takes: [`DRAW_LIMIT_FACTOR`] times the expected number.
    pub fn draw_limit(&self) -> u64 {
        (self.odds().expected_draws * DRAW_LIMIT_FACTOR).ceil() as u64
    }

    /// One draw from `source` into `entropy`, and whether its phrase meets the wishes. The source
    /// was probed before the first draw ([`check_source`]).
    fn one_draw(
        &self,
        source: &mut dyn RandomSource,
        entropy: &mut [u8; NEW_ENTROPY_BYTES],
    ) -> Result<bool, MhfeError> {
        source.fill(&mut entropy[..])?;
        // The chosen words' bits are set after the source's bytes, and a phrase that misses a
        // wish is drawn again, before the check's costly seed.
        self.wishes.apply(entropy);
        Ok(self.wishes.met_by(entropy))
    }

    /// Up to `count` draws from `source`, without the wallet check, which only the core's draw
    /// makes: the first phrase that meets the wishes, or `None`.
    pub(crate) fn try_draws(
        &self,
        source: &mut dyn RandomSource,
        count: u64,
    ) -> Result<Option<Phrase>, MhfeError> {
        let mut entropy = Zeroizing::new([0u8; NEW_ENTROPY_BYTES]);
        for _ in 0..count {
            if self.one_draw(source, &mut entropy)? {
                return Ok(Some(Phrase::from_entropy(&entropy[..])?));
            }
        }
        Ok(None)
    }

    /// Draws until a phrase is found, at most [`PhraseDraw::draw_limit`] times, after which it
    /// refuses the generator with [`MhfeError::RandomFailed`]. The source is probed first
    /// ([`check_source`]), so that a source that fills nothing or repeats itself is refused before
    /// anything is drawn. `on_draws` hears the number of draws so far every
    /// [`DRAW_REPORT_INTERVAL`] draws, and its `Break` stops the draw.
    pub fn draw(
        &self,
        source: &mut dyn RandomSource,
        on_draws: &mut dyn FnMut(u64) -> crate::Outcome,
    ) -> crate::Outcome<NewPhrase> {
        check_source(source)?;
        let phrase = proceed!(match &self.passphrase {
            Some(passphrase) => self.checked_phrase(passphrase, source, on_draws),
            None => self.unchecked_phrase(source, on_draws),
        });
        Ok(ControlFlow::Continue(NewPhrase {
            phrase,
            checked: self.is_checked(),
        }))
    }

    /// The first phrase that meets the wishes. The core's draw always checks, so this one stays
    /// here.
    fn unchecked_phrase(
        &self,
        source: &mut dyn RandomSource,
        on_draws: &mut dyn FnMut(u64) -> crate::Outcome,
    ) -> crate::Outcome<Phrase> {
        let limit = self.draw_limit();
        let mut draws = 0;
        loop {
            let count = DRAW_REPORT_INTERVAL.min(limit - draws);
            if let Some(phrase) = self.try_draws(source, count)? {
                return Ok(ControlFlow::Continue(phrase));
            }
            draws += count;
            if draws == limit {
                return Err(no_phrase_within(limit));
            }
            proceed!(on_draws(draws));
        }
    }

    /// The phrase of the core's draw, whose trials run one after another, as the specification's
    /// proof requires: `source` fills each, and a draw that misses a wish is drawn again before the
    /// core sees it, though it counts for `on_draws`.
    fn checked_phrase(
        &self,
        passphrase: &str,
        source: &mut dyn RandomSource,
        on_draws: &mut dyn FnMut(u64) -> crate::Outcome,
    ) -> crate::Outcome<Phrase> {
        let limit = self.draw_limit();
        let mut draws = 0u64;
        let mut counted = |entropy: &mut [u8; NEW_ENTROPY_BYTES]| -> crate::Outcome<bool> {
            if draws == limit {
                return Err(no_phrase_within(limit));
            }
            let met = self.one_draw(source, entropy)?;
            draws += 1;
            if draws.is_multiple_of(DRAW_REPORT_INTERVAL) {
                proceed!(on_draws(draws));
            }
            Ok(ControlFlow::Continue(met))
        };
        // `Break` carries no error, so the error that stops the draw waits here.
        let mut stopped = None;
        let drawn = mhfe_core::wallet_check::draw(passphrase, &mut |entropy| loop {
            match counted(entropy) {
                Ok(ControlFlow::Continue(true)) => return ControlFlow::Continue(()),
                Ok(ControlFlow::Continue(false)) => {}
                Ok(ControlFlow::Break(())) => return ControlFlow::Break(()),
                Err(error) => {
                    stopped = Some(error);
                    return ControlFlow::Break(());
                }
            }
        });
        stopped.map_or(Ok(drawn?), Err)
    }
}

/// The refusal of a generator that gave no phrase in `limit` draws.
fn no_phrase_within(limit: u64) -> MhfeError {
    MhfeError::RandomFailed(format!(
        "it gave no phrase that meets the conditions in {limit} draws"
    ))
}

/// A new phrase, kept out of swap and wiped when dropped.
pub struct NewPhrase {
    phrase: Phrase,
    checked: bool,
}

impl NewPhrase {
    /// The 24 words, one space apart.
    pub fn phrase(&self) -> &str {
        self.phrase.as_str()
    }

    /// Whether it was drawn to pass the wallet check.
    pub fn checked(&self) -> bool {
        self.checked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::word_wishes::Place;
    use crate::Unstopped as _;

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
    fn the_check_binds_the_passphrase() {
        let phrase = Phrase::from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        let phrase = phrase.as_str();
        assert!(phrase.ends_with("abandon above proof fatigue"));
        assert!(phrase_passes(phrase, "TREZOR").unwrap());
        assert!(!phrase_passes(phrase, "trezor").unwrap());
        // Without the passphrase it is another seed, which fails: 0 leading zero bits.
        assert!(!phrase_passes(phrase, "").unwrap());
    }

    #[test]
    fn a_wallet_without_a_passphrase_has_its_check_too() {
        let phrase = Phrase::from_entropy(&counted(EMPTY_COUNTER)).unwrap();
        let phrase = phrase.as_str();
        assert!(phrase.ends_with("abandon absorb another spoil"));
        assert!(phrase_passes(phrase, "").unwrap());
        assert!(!phrase_passes(phrase, "TREZOR").unwrap());
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
        let checked = draw
            .draw(&mut fill, &mut |_| crate::GO_ON)
            .unstopped()
            .unwrap();
        assert_eq!(counter.get(), TREZOR_COUNTER);
        assert!(checked.checked());
        assert!(verify(checked.phrase(), "TREZOR").unwrap());
        let unchecked = PhraseDraw::unchecked()
            .draw(&mut fill, &mut |_| crate::GO_ON)
            .unstopped()
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
            Err(MhfeError::NoWalletCheckAtLength(12))
        ));
        let phrase = Phrase::from_entropy(&counted(TREZOR_COUNTER)).unwrap();
        assert!(matches!(
            verify(phrase.as_str(), ""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        ));
        assert_eq!(
            require_passphrase(""),
            Err(MhfeError::WalletCheckNeedsPassphrase)
        );
        assert_eq!(require_passphrase("TREZOR"), Ok(()));
    }

    /// The library's messages write the odds out, as "65,536"; they must stay the check's.
    #[test]
    fn messages_give_the_odds_of_the_check() {
        assert_eq!(WALLET_CHECK_ODDS, 65_536);
        assert!(MhfeError::HiddenWalletPassesCheck
            .to_string()
            .contains("once in 65,536"));
    }

    #[test]
    fn a_new_passphrase_must_be_repeated_exactly() {
        assert_eq!(require_same_passphrase("TREZOR", "TREZOR"), Ok(()));
        assert_eq!(require_same_passphrase("", ""), Ok(()));
        for repeat in ["trezor", "TREZOR ", ""] {
            assert_eq!(
                require_same_passphrase("TREZOR", repeat),
                Err(MhfeError::PassphrasesDiffer)
            );
        }
        assert_eq!(
            require_same_passphrase("", "TREZOR"),
            Err(MhfeError::PassphrasesDiffer)
        );
    }

    /// A short phrase has no check (AUD-010): a public passphrase with which the 12-word test
    /// phrase would pass under BE32(128), which the profile does not define, does not pass, and
    /// `verify` refuses the length.
    #[test]
    fn a_short_phrase_has_no_check() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        let passphrase = "aud010 public probe 11656";
        assert_eq!(phrase_passes(twelve, passphrase), Ok(false));
        assert_eq!(
            verify(twelve, passphrase),
            Err(MhfeError::NoWalletCheckAtLength(12))
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
            Ok(ControlFlow::Break(()))
        });
        assert!(matches!(stopped, Ok(ControlFlow::Break(()))));
        // draw probes the source first: a stuck one is refused before any draw.
        let mut stuck = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        assert!(matches!(
            PhraseDraw::unchecked().draw(&mut stuck, &mut |_| crate::GO_ON),
            Err(MhfeError::RandomFailed(_))
        ));
    }

    /// A source of the counters from 1, which `next` counts; each phrase of them holds "abandon".
    fn counting_source(
        next: &std::cell::Cell<u64>,
    ) -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> + '_ {
        |bytes: &mut [u8]| {
            next.set(next.get() + 1);
            bytes.copy_from_slice(&counted(next.get()));
            Ok(())
        }
    }

    /// A generator whose phrases never meet the wishes is refused after exactly the draw limit.
    #[test]
    fn a_draw_stops_at_its_limit() {
        // Every phrase of these counters holds "abandon", the word never to use.
        let next = std::cell::Cell::new(0u64);
        let mut counting = counting_source(&next);
        check_source(&mut counting).unwrap();
        let probes = next.get();
        next.set(0);
        let draw = PhraseDraw::unchecked().with_wishes(WordWishes::new(&[], &["abandon"]).unwrap());
        let limit = draw.draw_limit();
        assert_eq!(limit, 65, "64 times the expected 1.01 draws");
        let refused = draw.draw(&mut counting, &mut |_| crate::GO_ON);
        assert!(matches!(refused, Err(MhfeError::RandomFailed(_))));
        assert_eq!(next.get(), probes + limit);
    }

    /// The core's draw stops only with `Cancelled`: what stopped it comes out as it was. A draw
    /// that misses a wish counts, but never reaches the check.
    #[test]
    fn a_checked_draw_keeps_its_errors_and_counts_a_missed_wish() {
        // Every phrase of these counters holds "abandon", so that no seed is computed here.
        let next = std::cell::Cell::new(0u64);
        let mut counting = counting_source(&next);
        let never = WordWishes::new(&[], &["abandon"]).unwrap();
        let draw = PhraseDraw::with_check("TREZOR").unwrap().with_wishes(never);
        let told = MhfeError::Internal("told to stop".to_owned());
        let mut heard = Vec::new();
        let stopped = draw.draw(&mut counting, &mut |draws| {
            heard.push(draws);
            if heard.len() == 2 {
                return Err(told.clone());
            }
            crate::GO_ON
        });
        assert_eq!(stopped.err(), Some(told));
        assert_eq!(heard, [DRAW_REPORT_INTERVAL, 2 * DRAW_REPORT_INTERVAL]);

        /// The two probes, the phrase that passes the check, then a failure with an error of its
        /// own.
        fn ending() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
            let mut next = TREZOR_COUNTER - 3;
            move |bytes| {
                next += 1;
                if next > TREZOR_COUNTER {
                    return Err(MhfeError::RandomFailed("it ended".to_owned()));
                }
                bytes.copy_from_slice(&counted(next));
                Ok(())
            }
        }
        let drawn = |wishes| {
            PhraseDraw::with_check("TREZOR")
                .unwrap()
                .with_wishes(wishes)
                .draw(&mut ending(), &mut |_| crate::GO_ON)
                .unstopped()
        };
        let holds = WordWishes::new(&[(Place::Anywhere, "proof")], &["zoo"]).unwrap();
        assert!(drawn(holds).unwrap().phrase().ends_with("proof fatigue"));
        // That phrase holds this word, so it must not be given out, and the source then fails.
        let never = WordWishes::new(&[], &["fatigue"]).unwrap();
        assert!(matches!(drawn(never), Err(MhfeError::RandomFailed(_))));
    }
}
