//! The choice of container for a 12- to 21-word phrase: 24 words, the default, or the same length
//! as the phrase (specification: "Choosing the suite" in suite 4). The same length is used only
//! when the person chooses it, and its consequences are shown before and after the choice.

use anstream::eprintln;
use mhfe::Suite;

use crate::exit::Failure;
use crate::hidden_input::{self, Key};
use crate::menu::{redraw_from, write_control};
use crate::style::{self, paint, ACCENT, GOOD, MUTED, STRONG, WARNING};

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
    let options = [
        (
            Suite::TwentyFourWords,
            "24 words (recommended)".to_owned(),
            "a wrong password is reported",
        ),
        (
            Suite::SameLength,
            format!("{words} words, the same length as yours"),
            "a wrong password opens another wallet",
        ),
    ];
    eprintln!();
    eprintln!(
        "{}",
        paint(
            STRONG,
            format!("Your phrase has {words} words. How long should the encrypted phrase be?")
        )
    );
    let mut selected = 0;
    let chosen = hidden_input::with_keys(|next_key| {
        eprintln!();
        let mut drawn_lines = draw(&options, selected);
        loop {
            match next_key()? {
                Key::Up | Key::Down => selected = 1 - selected,
                Key::Enter => return Ok(Some(selected)),
                Key::Digit(number @ 1..=2) => return Ok(Some(usize::from(number) - 1)),
                Key::Help => {
                    // The explanation stays on the screen, and the menu is drawn again below it.
                    eprintln!();
                    explain(words);
                    eprintln!();
                    drawn_lines = draw(&options, selected);
                    continue;
                }
                Key::Quit => return Ok(None),
                Key::Digit(_) | Key::Other => continue,
            }
            write_control(&redraw_from(drawn_lines))?;
            drawn_lines = draw(&options, selected);
        }
    })?;
    let Some(index) = chosen else {
        return Err(mhfe::MhfeError::Cancelled.into());
    };
    let suite = options[index].0;
    eprintln!();
    style::ok(format!("Container: {}.", options[index].1));
    if suite == Suite::SameLength {
        show_consequences(words);
    }
    Ok(suite)
}

/// Draws the two options and returns how many lines they took. The highlighted one has a cyan
/// marker and a bold label, so that it stands out also without colours.
fn draw(options: &[(Suite, String, &str); 2], selected: usize) -> usize {
    let label_width = options
        .iter()
        .map(|(_, label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    for (index, (_, label, note)) in options.iter().enumerate() {
        let number = paint(MUTED, index + 1);
        let padding = " ".repeat(label_width - label.chars().count());
        let (marker, label) = if index == selected {
            (paint(ACCENT, "›"), paint(STRONG, label))
        } else {
            (" ".to_owned(), label.clone())
        };
        eprintln!(
            "{marker} {number}  {label}{padding}  {}",
            paint(MUTED, note)
        );
    }
    eprintln!();
    style::hint("↑ ↓ choose · Enter confirms · ? explains both · q quits");
    options.len() + 2
}

/// What each choice gives and costs, shown when the person presses ?.
pub fn explain(words: usize) {
    let bits = checksum_bits(words);
    let short = passes_wrongly(bits);
    let long = passes_wrongly(TWENTY_FOUR_WORD_CHECKSUM_BITS);
    let good = |text: String| eprintln!("  {} {text}", paint(GOOD, "✓"));
    let bad = |text: String| eprintln!("  {} {text}", paint(WARNING, "!"));

    eprintln!("{}", paint(STRONG, "24 words (recommended)"));
    good("A wrong password is reported as wrong; it never opens another wallet.".into());
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
    bad("A wrong password is not reported: it opens another, empty wallet.".into());
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
    style::warn(
        "A wrong password will not be detected.",
        &format!(
            "It opens another, empty wallet of {words} words. The container also shows that your \
             phrase has {words} words, and a word copied wrongly still passes its {bits}-bit \
             checksum about once in {}.",
            passes_wrongly(bits)
        ),
    );
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
