//! The choice of container for a 12- to 21-word phrase: 24 words, the default, or the same length
//! as the phrase (specification: "Choosing the suite" in suite 4). The same length is used only
//! when the person chooses it, and its consequences are shown before and after the choice.

use anstream::eprintln;
use mhfe::Suite;

use crate::choice::{self, Answer, Help, Question};
use crate::exit::Failure;
use crate::style::{self, paint, GOOD, MUTED, STRONG, WARNING};

/// Where the README explains the choice. The question shows only this link; ? compares both
/// answers on request ([`explain`]).
const README_LENGTH: &str = "https://github.com/hobby-eng/mhfe#24-words-or-the-same-length";

/// A 24-word container has an 8-bit BIP39 checksum.
const TWENTY_FOUR_WORD_CHECKSUM_BITS: u32 = 8;

/// The BIP39 checksum of a phrase of `words` words has `words / 3` bits: 4 for 12 words, 7 for 21.
fn checksum_bits(words: usize) -> u32 {
    words as u32 / 3
}

/// "about once in 16": how often a word replaced at random still passes the checksum.
fn passes_wrongly(bits: u32) -> u32 {
    1 << bits
}

/// Asks a person at a terminal which container to make. Enter alone keeps 24 words.
pub fn choose(words: usize) -> Result<Suite, Failure> {
    let suites = [Suite::TwentyFourWords, Suite::SameLength];
    let answers = [
        Answer::new("24 words (recommended)", ""),
        Answer::new(format!("{words} words, the same length as yours"), ""),
    ];
    let text = format!("Your phrase has {words} words. How long should the encrypted phrase be?");
    let question = Question {
        text: &text,
        explanation: &[],
        more: &[README_LENGTH],
        record: Some("Container"),
    };
    let chosen = choice::choose(
        &question,
        &answers,
        Some(Help {
            hint: "? explains both",
            show: &|| explain(words),
        }),
    )?;
    let Some(index) = chosen else {
        return Err(mhfe::MhfeError::Cancelled.into());
    };
    if suites[index] == Suite::SameLength {
        show_consequences(words);
    }
    Ok(suites[index])
}

/// What each choice gives and costs, shown when the person presses ?.
pub fn explain(words: usize) {
    let bits = checksum_bits(words);
    let short = passes_wrongly(bits);
    let long = passes_wrongly(TWENTY_FOUR_WORD_CHECKSUM_BITS);
    let good = |text: String| eprintln!("  {} {text}", paint(GOOD, "✓"));
    let bad = |text: String| eprintln!("  {} {text}", paint(WARNING, "!"));

    eprintln!("{}", paint(STRONG, "24 words (recommended)"));
    good("Recovery checks the password and tells you if it is wrong.".into());
    good("Every encrypted phrase has 24 words, so it does not show how long yours is.".into());
    good(format!(
        "A word copied wrongly is caught {} times in {long}.",
        long - 1
    ));
    bad("The backup is longer than your phrase.".into());
    eprintln!();
    eprintln!(
        "{}",
        paint(STRONG, format!("{words} words, the same length as yours"))
    );
    good("The backup is as long as your phrase and looks like any other phrase.".into());
    good("Every password opens some valid wallet, which can serve as a decoy.".into());
    bad("Recovery cannot check the password: a wrong one opens another wallet.".into());
    eprintln!(
        "    {}",
        paint(
            MUTED,
            "Before you rely on it, check it with mhfe check against your wallet's"
        )
    );
    eprintln!(
        "    {}",
        paint(MUTED, "fingerprint or a known receiving address.")
    );
    bad(format!("It shows that your phrase has {words} words."));
    bad(format!(
        "A word copied wrongly is caught only {} times in {short}.",
        short - 1
    ));
    eprintln!();
    style::hint(
        "The fingerprint is the 8-character code that wallets such as Sparrow and Electrum show \
         for a wallet. It changes with a BIP39 passphrase.",
    );
}

/// The consequences of a same-length container, which the person must see once it is chosen.
pub fn show_consequences(words: usize) {
    let bits = checksum_bits(words);
    // Set apart from the summary above and below it.
    eprintln!();
    style::warn(
        "A wrong password will not be detected.",
        &format!(
            "It opens another, empty wallet of {words} words. The container also shows that your \
             phrase has {words} words, and a word copied wrongly still passes its {bits}-bit \
             checksum about once in {}.",
            passes_wrongly(bits)
        ),
    );
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shorter_container_has_a_weaker_checksum() {
        let odds: Vec<u32> = [12, 15, 18, 21, 24]
            .into_iter()
            .map(|words| passes_wrongly(checksum_bits(words)))
            .collect();
        assert_eq!(odds, [16, 32, 64, 128, 256]);
        assert_eq!(checksum_bits(24), TWENTY_FOUR_WORD_CHECKSUM_BITS);
    }
}
