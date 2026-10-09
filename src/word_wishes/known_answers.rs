//! Known answers of the chosen-word draw: the self-check `word-wishes`.
//!
//! The phrases were drawn by the multi-chain Deriver's generator
//! (packages/crypto-core/src/bip39-chosen-words.ts, generateMnemonicWithChosenWords), an
//! implementation independent of this one, from the same byte stream: xorshift32 (Marsaglia, 2003)
//! from 0x2545f491, one byte from each step, 32 bytes a draw. The stream is repeatable and never
//! used for a real phrase. Two of them are also among the Deriver's own known answers
//! (CHOSEN_WORDS_KNOWN_ANSWERS), which a third, whole-integer implementation computed. Each case
//! also states which draw of the stream it takes, so that the refusals before it are exercised.
//!
//! The check also sets and reads a word at every position, finds the filtered words at every
//! position, and must refuse a second chosen word, a second word never to use and a source of
//! zeros.

use super::{Place, WordWishes};
use crate::packing::{STATE_BYTES, STATE_WORDS};
use crate::phrase;
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};
use crate::wallet_check::PhraseDraw;
use crate::MhfeError;

/// The start of the byte stream; any non-zero value works.
const SEED: u32 = 0x2545_f491;
/// Draws a case may take: thirty times the most it needs, a fixed last word's 256.
const MOST_DRAWS: u64 = 30 * 256;

/// The extremes and each independent bit of the published BIP39 11-bit word index.
const BIT_INDICES: [u16; 13] = [0, 2047, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// A request, the phrase the independent implementation drew for it, and the draw of the stream,
/// from 1, that gives it: the draws before it are refused by the wishes.
struct WishCase {
    chosen: &'static [(Place, &'static str)],
    never_use: &'static [&'static str],
    phrase: &'static str,
    draw: u64,
}

const CASES: [WishCase; 6] = [
    // The first draw meets the wishes at once.
    WishCase {
        chosen: &[(Place::At(1), "happy")],
        never_use: &["abandon"],
        phrase: "happy frost answer furnace coyote december rather close country sea quality \
                 place vital mule into enemy swift slice soft tail tired tomato master upgrade",
        draw: 1,
    },
    // The first draw holds "frost" second, the word never to use, and is refused (also one of
    // the Deriver's known answers).
    WishCase {
        chosen: &[(Place::At(1), "happy")],
        never_use: &["frost"],
        phrase: "happy buyer glide special riot dynamic guard shrimp pole zebra nice wood bacon \
                 swing live exercise nest fence beach license that caution cricket oven",
        draw: 2,
    },
    // A word across three bytes, bits 22 to 32.
    WishCase {
        chosen: &[(Place::At(3), "primary")],
        never_use: &[],
        phrase: "deny frost primary furnace coyote december rather close country sea quality \
                 place vital mule into enemy swift slice soft tail tired tomato master wise",
        draw: 1,
    },
    // A fixed last word of all ones and a word never to use: its 8 checksum bits must come out of
    // the hash (also one of the Deriver's known answers).
    WishCase {
        chosen: &[(Place::At(24), "zoo")],
        never_use: &["abandon"],
        phrase: "unique film envelope lazy jelly tennis flame flash melody news kangaroo health \
                 wife sure sort invest laugh friend clock reform border put october zoo",
        draw: 770,
    },
    // A fixed last word of mixed bits, 10101010101: its 3 entropy bits 101 and 8 checksum bits
    // 01010101 catch a split at the wrong bit, which a word of all ones hides.
    WishCase {
        chosen: &[(Place::At(24), "primary")],
        never_use: &[],
        phrase: "practice screen reflect crumble tape regular author shoe amused broom shaft \
                 family letter crowd caught replace picnic soccer output sphere actress company \
                 rabbit primary",
        draw: 10,
    },
    // A word anywhere, which the first draws lack.
    WishCase {
        chosen: &[(Place::Anywhere, "zoo")],
        never_use: &[],
        phrase: "exclude master napkin ordinary movie tide kick display trade bone cluster exit \
                 act kick leave legal zoo opera play cloth common feel coconut flash",
        draw: 192,
    },
];

/// The byte stream of the cases.
fn xorshift32() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    let mut state = SEED;
    move |bytes: &mut [u8]| {
        for byte in bytes.iter_mut() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        Ok(())
    }
}

/// The `word-wishes` check.
pub(crate) struct WordWishesCheck {
    cases: &'static [WishCase],
}

impl WordWishesCheck {
    pub(crate) fn new() -> Self {
        Self { cases: &CASES }
    }

    fn case(case: &WishCase) -> Result<(), String> {
        let wishes = WordWishes::new(case.chosen, case.never_use).map_err(stopped)?;
        let draw = PhraseDraw::unchecked().with_wishes(wishes);
        // The draw's own loop, as a new phrase takes it; each draw fills the entropy once.
        let mut draws = 0;
        let mut stream = xorshift32();
        let mut counted = |bytes: &mut [u8]| {
            draws += 1;
            stream(bytes)
        };
        let entropy = draw
            .try_draws(&mut counted, MOST_DRAWS)
            .map_err(stopped)?
            .ok_or_else(|| "finds no phrase".to_owned())?;
        let phrase = crate::phrase::phrase_from_entropy(&entropy[..]).map_err(stopped)?;
        expect(*phrase == *case.phrase, "gives another phrase")?;
        expect(draws == case.draw, "takes another draw")
    }

    // Independent BIP39 oracle: a 24-bit window replaces the full field at once, unlike
    // apply's bit-by-bit masks. The 32-byte buffer keeps the final 3 of 11 word bits; a
    // 33-byte entropy/checksum buffer keeps all 11. This duplication is an independent oracle.
    fn expected_bits<const N: usize>(before: &[u8; N], position: usize, number: u16) -> [u8; N] {
        let mut expected = *before;
        let start = (position - 1) * 11;
        let width = 11.min(N * 8 - start);
        let byte = start / 8;
        let shift = 24 - start % 8 - width;
        let mask = ((1u32 << width) - 1) << shift;
        let mut window = 0u32;
        for offset in 0..3 {
            window = window << 8 | u32::from(*before.get(byte + offset).unwrap_or(&0));
        }
        let value = number >> (11 - width);
        window = (window & !mask) | (u32::from(value) << shift);
        for offset in 0..3 {
            if let Some(destination) = expected.get_mut(byte + offset) {
                *destination = (window >> (16 - offset * 8)) as u8;
            }
        }
        expected
    }

    fn bit_case(
        before: &[u8; STATE_BYTES],
        position: usize,
        number: u16,
        expected: &[u8; STATE_BYTES],
    ) -> Result<(), String> {
        let wishes = WordWishes::new(&[(Place::At(position), phrase::word(number))], &[])
            .map_err(stopped)?;
        let mut actual = *before;
        wishes.apply(&mut actual);
        expect(actual == *expected, "sets different entropy bits")
    }

    fn read_case(bits: &[u8], position: usize, number: u16) -> Result<(), String> {
        expect(
            phrase::number_at(bits, position - 1) == number,
            "reads different word bits",
        )
    }

    fn fixed_word_bits() -> Result<(), String> {
        expect(
            (
                STATE_BYTES,
                STATE_WORDS,
                phrase::WORD_BITS,
                super::CHECKSUM_BITS,
            ) == (32, 24, 11, 8),
            "has different BIP39 word geometry",
        )?;
        for position in 1..=STATE_WORDS {
            for number in BIT_INDICES {
                for before in [[0; STATE_BYTES], [0xff; STATE_BYTES]] {
                    let expected = Self::expected_bits(&before, position, number);
                    Self::bit_case(&before, position, number, &expected).map_err(|what| {
                        format!("position {position}, public index {number} {what}")
                    })?;
                    let reference =
                        Self::expected_bits(&[before[0]; STATE_BYTES + 1], position, number);
                    Self::read_case(&reference, position, number).map_err(|what| {
                        format!("position {position}, public index {number} {what}")
                    })?;
                }
            }
        }
        Ok(())
    }

    /// The filters at every position: a word never to use, a word anywhere and a fixed word are
    /// each found wherever they stand, and nowhere else. In the entropy of ones every word but the
    /// last reads "zoo"; the oracle puts "abandon" at each position in turn. The last position is
    /// filtered through its checksum in [`WordWishesCheck::filter_cases`].
    fn filters_at_every_position() -> Result<(), String> {
        let ones = [0xff; STATE_BYTES];
        let wishes =
            |chosen: &[(Place, &str)], never_use: &[&str]| WordWishes::new(chosen, never_use);
        let never = wishes(&[], &["abandon"]).map_err(stopped)?;
        let anywhere = wishes(&[(Place::Anywhere, "abandon")], &[]).map_err(stopped)?;
        expect(
            never.met_by(&ones) && !anywhere.met_by(&ones),
            "finds a word that is not there",
        )?;
        for position in 1..STATE_WORDS {
            let entropy = Self::expected_bits(&ones, position, 0);
            // The next position, the first after the last but one.
            let elsewhere = position % (STATE_WORDS - 1) + 1;
            let here = wishes(&[(Place::At(position), "abandon")], &[]).map_err(stopped)?;
            let there = wishes(&[(Place::At(elsewhere), "abandon")], &[]).map_err(stopped)?;
            let outcomes = (
                never.met_by(&entropy),
                anywhere.met_by(&entropy),
                here.met_by(&entropy),
                there.met_by(&entropy),
            );
            expect(
                outcomes == (false, true, true, false),
                "filters a word at this position wrongly",
            )
            .map_err(|what| format!("position {position} {what}"))?;
        }
        Ok(())
    }

    fn filter_cases() -> Result<(), String> {
        // Published BIP39 256-bit zero-entropy vector: 23 abandon words, then art. These
        // direct predicates deliberately bypass try_draws' separate raw-zero source refusal.
        let entropy = [0; STATE_BYTES];
        let case = |chosen: &[(Place, &str)], never_use: &[&str], expected, label| {
            let wishes = WordWishes::new(chosen, never_use).map_err(stopped)?;
            expect(
                wishes.met_by(&entropy) == expected,
                "has another filter outcome",
            )
            .map_err(|what| format!("{label} {what}"))
        };
        case(&[], &["abandon"], false, "an excluded entropy word")?;
        case(&[], &["art"], false, "an excluded checksum word")?;
        case(
            &[(Place::Anywhere, "zoo")],
            &[],
            false,
            "an absent anywhere word",
        )?;
        case(
            &[(Place::Anywhere, "abandon")],
            &[],
            true,
            "a repeated anywhere word",
        )?;
        // "art" stands only last: an anywhere word is looked for there too.
        case(
            &[(Place::Anywhere, "art")],
            &[],
            true,
            "an anywhere word at the last position",
        )?;
        case(
            &[(Place::At(24), "abandon")],
            &[],
            false,
            "a wrong final word",
        )?;
        case(
            &[(Place::At(24), "art")],
            &[],
            true,
            "the correct final word",
        )?;
        case(
            &[(Place::At(2), "zoo")],
            &[],
            false,
            "a wrong interior word",
        )
    }
}

impl ComponentCheck for WordWishesCheck {
    fn id(&self) -> &'static str {
        "word-wishes"
    }

    fn label(&self) -> &'static str {
        "Chosen word of a new phrase"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("case", self.cases, Self::case);
        findings.one(Self::fixed_word_bits);
        findings.one(Self::filter_cases);
        findings.one(Self::filters_at_every_position);
        findings.one(|| {
            let wishes = WordWishes::new(&[(Place::At(1), "happy")], &[]).map_err(stopped)?;
            let draw = PhraseDraw::unchecked().with_wishes(wishes);
            let mut zero_source = |bytes: &mut [u8]| {
                bytes.fill(0);
                Ok(())
            };
            // A chosen nonzero word must not hide a host that provided no random entropy.
            expect_refusal(draw.try_draws(&mut zero_source, 1), "RANDOM_FAILED")
                .map_err(|what| format!("a zero source with a chosen word {what}"))
        });
        findings.one(|| {
            expect_refusal(
                WordWishes::new(&[(Place::At(1), "happy"), (Place::At(5), "zoo")], &[]),
                "INVALID_WORD_WISH",
            )
            .map_err(|what| format!("a second chosen word {what}"))
        });
        findings.one(|| {
            expect_refusal(
                WordWishes::new(&[], &["abandon", "zoo"]),
                "INVALID_WORD_WISH",
            )
            .map_err(|what| format!("a second word never to use {what}"))
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};

    #[test]
    fn the_cases_pass() {
        assert_eq!(
            WordWishesCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_damaged_case_fails() {
        let damaged = [WishCase {
            phrase: "abandon",
            ..CASES[0]
        }];
        fails_with(
            WordWishesCheck {
                cases: leak(damaged),
            },
            "case 1 of 1 gives another phrase",
        );
    }

    #[test]
    fn a_case_taken_from_another_draw_fails() {
        let damaged = [WishCase {
            draw: 1,
            ..CASES[1]
        }];
        fails_with(
            WordWishesCheck {
                cases: leak(damaged),
            },
            "case 1 of 1 takes another draw",
        );
    }

    #[test]
    fn a_wrong_bit_oracle_answer_is_refused() {
        let before = [0x5a; STATE_BYTES];
        let position = 2;
        let number = 512;
        let mut expected = WordWishesCheck::expected_bits(&before, position, number);
        assert!(WordWishesCheck::bit_case(&before, position, number, &expected).is_ok());
        // A neighboring bit and a chosen-word bit must each make the same startup check fail.
        expected[0] ^= 1;
        assert_eq!(
            WordWishesCheck::bit_case(&before, position, number, &expected),
            Err("sets different entropy bits".to_owned())
        );
        expected[0] ^= 1;
        expected[1] ^= 0x08;
        assert_eq!(
            WordWishesCheck::bit_case(&before, position, number, &expected),
            Err("sets different entropy bits".to_owned())
        );
    }

    #[test]
    fn a_damaged_reader_fixture_is_refused() {
        let position = 2;
        let number = 512;
        let mut reference =
            WordWishesCheck::expected_bits(&[0x5a; STATE_BYTES + 1], position, number);
        assert!(WordWishesCheck::read_case(&reference, position, number).is_ok());
        reference[1] ^= 0x08;
        assert_eq!(
            WordWishesCheck::read_case(&reference, position, number),
            Err("reads different word bits".to_owned())
        );
    }
}
