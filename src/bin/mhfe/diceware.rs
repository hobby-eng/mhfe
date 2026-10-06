//! `mhfe password`: a password of random words from the EFF large wordlist, or of random
//! characters, and the count of dice words in a password, which the strength estimate uses.

use std::io::IsTerminal;

use anstream::{eprintln, println};
use clap::Args;
use zeroize::{Zeroize, Zeroizing};

use crate::check_word;
use crate::exit::{Failure, SUCCESS};
use crate::flow::{self, Flow};
use crate::style::{self, STRONG};
use crate::terminal::{self, Input};

/// The EFF large wordlist, unchanged: "11111<TAB>abacus" to "66666<TAB>zoom", one per line.
/// Provenance and licence: vendor/eff-large-wordlist.md.
const EFF_LIST: &str = include_str!("../../../vendor/eff-large-wordlist/eff_large_wordlist.txt");
/// 6^5: one word for every roll of five dice.
const LIST_SIZE: usize = 7776;
/// Recommended minimum; fewer words get a warning.
const RECOMMENDED_WORDS: usize = 4;
const DEFAULT_WORDS: usize = 5;
const MOST_WORDS: usize = 32;
/// The longest word of the EFF large list has nine letters.
const LONGEST_WORD: usize = 9;
/// log2(7776) = 12.925 bits per word, in thousandths, to print the strength without floats.
pub const MILLIBITS_PER_WORD: usize = 12_925;

/// The characters of a character password: digits, capital and small letters without those
/// easily confused when read back from paper (0 and O, 1, l and I).
const CHARACTERS: &[u8; 57] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// log2(57) = 5.833 bits per character, in thousandths.
const MILLIBITS_PER_CHARACTER: usize = 5_833;
/// Twelve characters, about 70 bits: fewer get a warning. The strength estimate of `mhfe encrypt`
/// counts a random letter as 4.7 bits rather than 5.8, so twelve also pass there. The default, 16
/// characters, gives about 93.3 bits.
const RECOMMENDED_CHARACTERS: usize = 12;
const MOST_CHARACTERS: usize = 64;

#[derive(Args)]
pub struct Options {
    /// Number of words, 1 to 32 (default 5; fewer than 4 are weak)
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_WORDS,
        hide_default_value = true,
        long_help = words_help()
    )]
    words: usize,

    /// Roll real dice instead of using the computer's randomness
    #[arg(long, long_help = dice_help())]
    dice: bool,

    /// Five words and a check word that repairs one mistyped word
    #[arg(long, conflicts_with_all = ["words", "chars"], long_help = check_word_help())]
    check_word: bool,

    /// Random characters instead of words, N of them (default 16)
    #[arg(
        long,
        value_name = "N",
        num_args = 0..=1,
        // --chars alone means sixteen characters.
        default_missing_value = "16",
        conflicts_with_all = ["words", "dice"],
        long_help = chars_help()
    )]
    chars: Option<usize>,
}

fn words_help() -> String {
    style::option_help(&[
        "Number of words, 1 to 32 (default 5; fewer than 4 are weak).",
        "Each word adds about 12.9 bits: four words give about 51.7 bits, five about 64.6, six \
         about 77.5. Fewer than four get a warning.",
    ])
}

fn check_word_help() -> String {
    style::option_help(&[
        "Five words and a check word that repairs one mistyped word.",
        "The sixth word is computed from the five before it (MHFE-PASSWORD-CHECK-1). When the \
         password is typed, it restores one word that is missing or misspelt and notices one \
         wrong word, before the long wait. It adds no strength: the password keeps about 64.6 \
         bits, and the check word must stay as secret as the rest.",
    ])
}

fn chars_help() -> String {
    style::option_help(&[
        "Random characters instead of words, N of them, 1 to 64 (default 16).",
        "Digits and letters without those easily confused, such as 0 and O or 1 and l: 57 \
         characters, about 5.8 bits each. Sixteen give about 93.3 bits, but words are easier to \
         type correctly years later.",
    ])
}

fn dice_help() -> String {
    style::option_help(&[
        "Roll real dice instead of using the computer's randomness.",
        "For each word, roll five dice and type the five numbers, 1 to 6, at a hidden prompt. \
         The computer's random generator is then not used at all.",
    ])
}

/// The top of `mhfe password --help`.
pub fn about() -> String {
    style::command_about(&[
        "Make a strong password of words or random characters",
        "Each word is drawn from the EFF large word list of 7,776 words, the same list that \
         five dice select from. Every word is equally likely.",
    ])
}

/// The end of `mhfe password -h` and `--help`.
pub fn help() -> String {
    let examples = style::help_section(
        "Examples:",
        &[
            ("mhfe password", "Five random words, about 64.6 bits"),
            ("mhfe password --words 6", "Six words, about 77.5 bits"),
            (
                "mhfe password --dice",
                "Roll real dice instead of using the computer",
            ),
            ("mhfe password --dice --words 6", "Six words from real dice"),
            (
                "mhfe password --check-word",
                "Five words and a check word, about 64.6 bits",
            ),
            (
                "mhfe password --chars",
                "Sixteen random characters, about 93.3 bits",
            ),
        ],
    );
    let note = style::help_note("The password is shown once and never stored.");
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    if let Some(count) = options.chars {
        return run_characters(count);
    }
    if !(1..=MOST_WORDS).contains(&options.words) {
        return Err(Failure::invalid_input(format!(
            "Choose between 1 and {MOST_WORDS} words."
        )));
    }
    let mut input = Input::new(false);
    // At a terminal the password has a step of its own, cleared once it is written down; the
    // summary says only how strong it is.
    let flow = Flow::start(&input, TITLE);
    style::title(TITLE);
    eprintln!();
    if options.words < RECOMMENDED_WORDS {
        style::warn(
            &format!("Fewer than {RECOMMENDED_WORDS} words is weak."),
            "Four words give about 51.7 bits, five about 64.6.",
        );
        eprintln!();
    }

    let words = eff_words();
    if options.dice {
        // The rolls are typed on a step of their own.
        flow::step();
    }
    let drawn_words = if options.check_word {
        check_word::DRAWN_WORDS
    } else {
        options.words
    };
    let all_words = drawn_words + usize::from(options.check_word);
    // Built in place at its final size, so no reallocation leaves a copy of the password.
    let mut password = Zeroizing::new(String::with_capacity(all_words * (LONGEST_WORD + 1)));
    // The indexes the check word is computed from, wiped when done.
    let mut drawn = Zeroizing::new([0; check_word::DRAWN_WORDS]);
    for number in 1..=drawn_words {
        let index = if options.dice {
            index_from_dice(&mut input, number)?
        } else {
            random_index()?
        };
        if number > 1 {
            password.push(' ');
        }
        password.push_str(words[index]);
        if let Some(slot) = drawn.get_mut(number - 1) {
            *slot = index;
        }
    }
    let strength = strength_text(drawn_words * MILLIBITS_PER_WORD);
    if !options.check_word {
        return show(
            &password,
            &format!("{drawn_words} words from the EFF list, about {strength} bits."),
            &[],
            flow,
        );
    }
    password.push(' ');
    password.push_str(words[check_word::check_index(&drawn)]);
    show(
        &password,
        &format!("5 words from the EFF list and a check word, about {strength} bits."),
        &["The last word is the check word; it adds no strength and is just as secret."],
        flow,
    )
}

/// The title of `mhfe password`.
const TITLE: &str = "Make a password";

/// Shows a new password with how strong it is and `notes` about it. At a terminal it is set apart
/// and in bold for writing down, on a step of its own that is cleared when the person is done; a
/// script gets the bare password.
fn show(password: &str, strength: &str, notes: &[&str], flow: Flow) -> Result<i32, Failure> {
    flow::step();
    if std::io::stdout().is_terminal() {
        println!("  {STRONG}{password}{STRONG:#}");
        eprintln!();
    } else {
        println!("{password}");
    }
    style::ok(strength);
    for note in notes {
        style::hint(note);
    }
    style::hint("Shown only once and not stored: write it down, apart from the container.");
    if flow::is_active() {
        terminal::wait_to_leave()?;
    }
    flow.finish();
    Ok(SUCCESS)
}

/// `mhfe password --chars N`: N characters drawn evenly from [`CHARACTERS`].
fn run_characters(count: usize) -> Result<i32, Failure> {
    if !(1..=MOST_CHARACTERS).contains(&count) {
        return Err(Failure::invalid_input(format!(
            "Choose between 1 and {MOST_CHARACTERS} characters."
        )));
    }
    let input = Input::new(false);
    let flow = Flow::start(&input, TITLE);
    style::title(TITLE);
    eprintln!();
    if count < RECOMMENDED_CHARACTERS {
        style::warn(
            &format!("Fewer than {RECOMMENDED_CHARACTERS} characters is weak."),
            "Twelve characters give about 70.0 bits, sixteen about 93.3.",
        );
        eprintln!();
    }
    // Built in place at its final size, so no reallocation leaves a copy of the password.
    let mut password = Zeroizing::new(String::with_capacity(count));
    for _ in 0..count {
        password.push(char::from(CHARACTERS[random_character()?]));
    }
    show(
        &password,
        &format!(
            "{count} random characters, about {} bits.",
            strength_text(count * MILLIBITS_PER_CHARACTER)
        ),
        &[],
        flow,
    )
}

/// An unbiased index below 57 from the operating system's random generator. A random byte gives
/// 256 values; only the first 228 = 4 x 57 are used, and a byte above them is drawn again.
fn random_character() -> Result<usize, Failure> {
    const ACCEPTED: u8 = 4 * CHARACTERS.len() as u8;
    loop {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).map_err(|error| {
            Failure::internal(format!("The system random generator failed: {error}"))
        })?;
        let value = byte[0];
        byte.zeroize();
        if value < ACCEPTED {
            return Ok(usize::from(value) % CHARACTERS.len());
        }
    }
}

/// The 7,776 words in dice order.
pub fn eff_words() -> Vec<&'static str> {
    let words: Vec<&'static str> = EFF_LIST
        .lines()
        .map(|line| {
            line.split('\t')
                .nth(1)
                .expect("each line holds dice digits and a word")
        })
        .collect();
    assert_eq!(
        words.len(),
        LIST_SIZE,
        "the vendored EFF list is incomplete"
    );
    words
}

/// An unbiased index below 7,776 from the operating system's random generator. Two random bytes
/// give 65,536 values; only the first 62,208 = 8 x 7,776 are used, so every index is equally
/// likely, and a value above them is drawn again.
fn random_index() -> Result<usize, Failure> {
    const ACCEPTED: u16 = 8 * LIST_SIZE as u16;
    loop {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes).map_err(|error| {
            Failure::internal(format!("The system random generator failed: {error}"))
        })?;
        let value = u16::from_be_bytes(bytes);
        bytes.zeroize();
        if value < ACCEPTED {
            return Ok(usize::from(value) % LIST_SIZE);
        }
    }
}

/// Reads five dice digits for one word, hidden, and returns the word's index.
fn index_from_dice(input: &mut Input, number: usize) -> Result<usize, Failure> {
    loop {
        let typed = input.secret(&format!(
            "Word {number}: roll five dice and type the five digits"
        ))?;
        match index_of_rolls(&typed) {
            Some(index) => return Ok(index),
            None => {
                style::retry("Type exactly five digits, each from 1 to 6, for example 35142.");
            }
        }
    }
}

/// Five dice digits read as a number in base 6, the order of the EFF list.
fn index_of_rolls(rolls: &str) -> Option<usize> {
    let digits = rolls.trim().as_bytes();
    if digits.len() != 5 || !digits.iter().all(|digit| (b'1'..=b'6').contains(digit)) {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0, |index, digit| index * 6 + usize::from(digit - b'1')),
    )
}

/// How many different EFF list words a password has if it consists only of such words, in any
/// ASCII letter case, else 0. A repeated word counts once: "abacus abacus abacus abacus" is one
/// dice word, about 12.9 bits, not four (AUD-005-FUN001). Used to warn about passwords weaker than
/// four different dice words. The words are compared in place, so no copy of the password is made;
/// the list positions found, which reveal the password, are wiped.
pub fn different_dice_words(password: &str) -> usize {
    let words = eff_words();
    // Reserved for every token up front, so the list never grows and leaves no unwiped copy.
    let mut found = Zeroizing::new(Vec::with_capacity(password.split_whitespace().count()));
    for token in password.split_whitespace() {
        match words
            .iter()
            .position(|word| word.eq_ignore_ascii_case(token))
        {
            Some(index) => found.push(index),
            None => return 0,
        }
    }
    found.sort_unstable();
    found.dedup();
    found.len()
}

/// "64.6" for 64,625 millibits, five words: the strength in bits, rounded to one decimal.
fn strength_text(millibits: usize) -> String {
    let tenths = (millibits + 50) / 100;
    format!("{}.{}", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_vendored_list_is_the_published_file() {
        let digest = Sha256::digest(EFF_LIST.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let words = eff_words();
        assert_eq!(words[0], "abacus");
        assert_eq!(words[LIST_SIZE - 1], "zoom");
    }

    #[test]
    fn dice_digits_select_the_listed_word() {
        let words = eff_words();
        for line in EFF_LIST.lines().step_by(97) {
            let (rolls, word) = line.split_once('\t').unwrap();
            assert_eq!(words[index_of_rolls(rolls).unwrap()], word);
        }
        assert_eq!(index_of_rolls("11111"), Some(0));
        assert_eq!(index_of_rolls("66666"), Some(LIST_SIZE - 1));
        for invalid in ["1111", "111111", "11117", "01111", "abcde"] {
            assert_eq!(index_of_rolls(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn random_indexes_stay_in_range() {
        for _ in 0..1000 {
            assert!(random_index().unwrap() < LIST_SIZE);
        }
    }

    #[test]
    fn recognises_passwords_made_of_dice_words() {
        assert_eq!(different_dice_words("abacus zoom yearbook zipfile"), 4);
        assert_eq!(different_dice_words("Abacus  ZOOM"), 2);
        assert_eq!(different_dice_words("abacus zoom Tr0ub4dor"), 0);
        assert_eq!(different_dice_words(""), 0);
    }

    /// AUD-005-FUN001: a repeated word adds nothing, in any letter case.
    #[test]
    fn a_repeated_dice_word_counts_once() {
        assert_eq!(different_dice_words("abacus abacus abacus abacus"), 1);
        assert_eq!(different_dice_words("abacus ABACUS Abacus zoom"), 2);
        assert_eq!(different_dice_words("abacus zoom abacus zoom yearbook"), 3);
        assert_eq!(
            different_dice_words("abacus zoom yearbook zipfile abacus"),
            4
        );
        // Only ASCII letters change case; any other letter makes it a word outside the list.
        assert_eq!(different_dice_words("abacus zo\u{d3}m"), 0);
    }

    #[test]
    fn strength_is_about_12_9_bits_per_word_and_5_8_per_character() {
        assert_eq!(strength_text(4 * MILLIBITS_PER_WORD), "51.7");
        assert_eq!(strength_text(5 * MILLIBITS_PER_WORD), "64.6");
        assert_eq!(strength_text(12 * MILLIBITS_PER_CHARACTER), "70.0");
        assert_eq!(strength_text(16 * MILLIBITS_PER_CHARACTER), "93.3");
    }

    #[test]
    fn characters_leave_out_those_easily_confused() {
        let mut sorted = CHARACTERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CHARACTERS.len(), "no character twice");
        for confused in b"0O1lI" {
            assert!(!CHARACTERS.contains(confused), "{}", char::from(*confused));
        }
        assert!(CHARACTERS.iter().all(u8::is_ascii_alphanumeric));
        for _ in 0..1000 {
            assert!(random_character().unwrap() < CHARACTERS.len());
        }
    }
}
