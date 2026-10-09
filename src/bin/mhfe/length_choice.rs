//! The choice of container for a 12- to 21-word phrase: 24 words, the default, or the same length
//! as the phrase (specification: "Choosing the suite" in suite 4). The same length is used only
//! when the person chooses it, and its consequences are shown before and after the choice.

use anstream::eprintln;
use mhfe::{ContainerChoice, OriginalFacts, Suite};

use crate::choice::{self, Answer, Help, Question};
use crate::exit::Failure;
use crate::readme;
use crate::style::{self, paint, MUTED, STRONG};

/// Asks a person at a terminal which container to make for a 12- to 21-word phrase. Enter alone
/// keeps 24 words.
pub fn choose(original: &OriginalFacts) -> Result<Suite, Failure> {
    let words = original.word_count();
    // The recommended 24 words first, then the phrase's own length.
    let choices = original.container_choices();
    let answers: Vec<Answer> = choices
        .iter()
        .map(|&choice| Answer::new(label(choice), ""))
        .collect();
    let text = format!("Your phrase has {words} words. How long should the encrypted phrase be?");
    let question = Question {
        text: &text,
        explanation: &[],
        // The README explains the choice; ? compares both answers on request ([`explain`]).
        more: Some(readme::CONTAINER_LENGTH),
        record: Some("Container"),
    };
    let chosen = choice::choose(
        &question,
        &answers,
        Some(Help {
            hint: "? explains both",
            show: &|| explain(&choices),
        }),
    )?;
    let Some(index) = chosen else {
        return Err(mhfe::MhfeError::Cancelled.into());
    };
    let suite = choices[index].suite();
    if suite == Suite::SameLength {
        show_consequences(words);
    }
    Ok(suite)
}

/// The answer that offers `choice`: "24 words (recommended)", or "12 words, the same length as
/// yours".
fn label(choice: ContainerChoice) -> String {
    match choice.suite() {
        Suite::TwentyFourWords => format!("{} words (recommended)", choice.word_count()),
        Suite::SameLength => format!("{} words, the same length as yours", choice.word_count()),
    }
}

/// What each choice gives and costs, shown when the person presses ?.
pub fn explain(choices: &[ContainerChoice]) {
    for &choice in choices {
        eprintln!("{}", paint(STRONG, label(choice)));
        match choice.suite() {
            Suite::TwentyFourWords => explain_24_words(choice),
            Suite::SameLength => explain_same_length(choice),
        }
        eprintln!();
    }
    style::hint(
        "The fingerprint is the 8-character code that wallets such as Sparrow and Electrum show \
         for a wallet. It changes with a BIP39 passphrase.",
    );
}

/// How often the container's checksum catches a word copied wrongly: "255 times in 256".
fn caught(choice: ContainerChoice) -> String {
    let one_in = choice.wrong_word_passes_one_in();
    format!("{} times in {one_in}", one_in - 1)
}

fn explain_24_words(choice: ContainerChoice) {
    style::gives("Recovery checks the password and tells you if it is wrong.");
    style::gives("Every encrypted phrase has 24 words, so it does not show how long yours is.");
    style::gives(&format!(
        "A word copied wrongly is caught {}.",
        caught(choice)
    ));
    style::costs("The backup is longer than your phrase.");
}

fn explain_same_length(choice: ContainerChoice) {
    style::gives("The backup is as long as your phrase and looks like any other phrase.");
    style::gives("Every password opens some valid wallet, which can serve as a decoy.");
    style::costs("Recovery cannot check the password: a wrong one opens another wallet.");
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
    style::costs(&format!(
        "It shows that your phrase has {} words.",
        choice.word_count()
    ));
    style::costs(&format!(
        "A word copied wrongly is caught only {}.",
        caught(choice)
    ));
}

/// The consequences of a same-length container, which the person must see once it is chosen.
pub fn show_consequences(words: usize) {
    // Set apart from the summary above and below it.
    eprintln!();
    style::warn(
        &format!("A wrong password will not be detected: it opens another {words}-word wallet."),
        "",
    );
    style::more(readme::CONTAINER_LENGTH);
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The answers and the odds read as they did when the numbers were the command's own.
    #[test]
    fn the_answers_and_the_odds_read_as_before() {
        let original = OriginalFacts::read(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        )
        .unwrap();
        let choices = original.container_choices();
        let labels: Vec<String> = choices.iter().map(|&choice| label(choice)).collect();
        assert_eq!(
            labels,
            [
                "24 words (recommended)",
                "12 words, the same length as yours"
            ]
        );
        let odds: Vec<String> = choices.iter().map(|&choice| caught(choice)).collect();
        assert_eq!(odds, ["255 times in 256", "15 times in 16"]);
    }
}
