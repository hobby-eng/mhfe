//! `mhfe password`: a password of random words from the EFF large wordlist, and the check that
//! warns when a chosen password is weaker than four different such words.

use std::io::IsTerminal;

use anstream::{eprintln, println};
use clap::Args;
use zeroize::{Zeroize, Zeroizing};

use crate::exit::{Failure, SUCCESS};
use crate::style::{self, STRONG};
use crate::terminal::Input;

/// The EFF large wordlist, unchanged: "11111<TAB>abacus" to "66666<TAB>zoom", one per line.
/// Provenance and licence: vendor/eff-large-wordlist.md.
const EFF_LIST: &str = include_str!("../../../vendor/eff-large-wordlist/eff_large_wordlist.txt");
/// 6^5: one word for every roll of five dice.
const LIST_SIZE: usize = 7776;
/// Recommended minimum; fewer words get a warning.
pub const RECOMMENDED_WORDS: usize = 4;
const DEFAULT_WORDS: usize = 5;
const MOST_WORDS: usize = 32;
/// The longest word of the EFF large list has nine letters.
const LONGEST_WORD: usize = 9;
/// log2(7776) = 12.925 bits per word, in thousandths, to print the strength without floats.
const MILLIBITS_PER_WORD: usize = 12_925;

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
}

fn words_help() -> String {
    style::option_help(&[
        "Number of words, 1 to 32 (default 5; fewer than 4 are weak).",
        "Each word adds about 12.9 bits: four words give about 51.7 bits, five about 64.6, six \
         about 77.5. Fewer than four get a warning.",
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
        "Make a strong password of random dice words",
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
        ],
    );
    let note = style::help_note("The password is shown once and never stored.");
    format!("{examples}\n{note}")
}

pub fn run(options: Options) -> Result<i32, Failure> {
    if !(1..=MOST_WORDS).contains(&options.words) {
        return Err(Failure::invalid_input(format!(
            "Choose between 1 and {MOST_WORDS} words."
        )));
    }
    style::title("Make a password");
    eprintln!();
    if options.words < RECOMMENDED_WORDS {
        style::warn(
            &format!("Fewer than {RECOMMENDED_WORDS} words is weak."),
            "Four words give about 51.7 bits, five about 64.6.",
        );
        eprintln!();
    }

    let words = eff_words();
    let mut input = Input::new(false);
    // Built in place at its final size, so no reallocation leaves a copy of the password.
    let mut password = Zeroizing::new(String::with_capacity(options.words * (LONGEST_WORD + 1)));
    for number in 1..=options.words {
        let index = if options.dice {
            index_from_dice(&mut input, number)?
        } else {
            random_index()?
        };
        if number > 1 {
            password.push(' ');
        }
        password.push_str(words[index]);
    }

    if std::io::stdout().is_terminal() {
        // Set apart and in bold for writing down; a script gets the bare password.
        println!("  {STRONG}{}{STRONG:#}", *password);
        eprintln!();
    } else {
        println!("{}", *password);
    }
    style::ok(format!(
        "{} words from the EFF list, about {} bits.",
        options.words,
        strength_text(options.words)
    ));
    style::hint(
        "The password is shown only this once and is not stored. Write it down and keep it \
         apart from the container.",
    );
    Ok(SUCCESS)
}

/// The 7,776 words in dice order.
fn eff_words() -> Vec<&'static str> {
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
            "Word {number}: roll five dice and type the five digits (hidden): "
        ))?;
        match index_of_rolls(&typed) {
            Some(index) => return Ok(index),
            None => style::retry("Type exactly five digits, each from 1 to 6, for example 35142."),
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

/// "64.6" for five words: the strength in bits with one decimal.
fn strength_text(words: usize) -> String {
    let tenths = words * MILLIBITS_PER_WORD / 100;
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
    fn strength_is_about_12_9_bits_per_word() {
        assert_eq!(strength_text(4), "51.7");
        assert_eq!(strength_text(5), "64.6");
    }
}
