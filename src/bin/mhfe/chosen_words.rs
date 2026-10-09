//! The word a person chooses for the new phrase of `mhfe new`, at a position or anywhere, and a
//! word never to use, with what they cost. The rules, the limits and the cost are the library's
//! (mhfe::word_wishes); this module asks and tells.

use clap::Args;
use mhfe::wallet_check::PhraseDraw;
use mhfe::word_hints::WordList;
use mhfe::word_wishes::{
    Place, Randomness, WishOdds, WordWishes, MAX_CHOSEN_WORDS, MAX_NEVER_USE_WORDS, PHRASE_WORDS,
    RECOMMENDED_RANDOM_BITS,
};
use zeroize::Zeroizing;

use crate::choice::{self, Answer, Question};
use crate::exit::{self, Failure};
use crate::flow;
use crate::readme;
use crate::settings::Operation;
use crate::style;
use crate::terminal::{Input, PrivateScreen};

// The questions below ask for one word of each kind, the library's limits (the owner's,
// 2026-10-08); more typed at once go to the library, which refuses them.
const _: () = assert!(MAX_CHOSEN_WORDS == 1 && MAX_NEVER_USE_WORDS == 1);

/// `--never-use` of `mhfe new`.
#[derive(Args)]
pub struct NeverUseOption {
    /// A word the new phrase must not hold
    #[arg(long = "never-use", value_name = "WORD", long_help = never_use_help())]
    never_use: Option<String>,
}

fn never_use_help() -> String {
    style::option_help(&[
        "A word the new phrase must not hold.",
        "It costs a little of the phrase's randomness; mhfe new states what is left before it \
         draws. When it is not given, mhfe new asks for it after the chosen word.",
    ])
}

impl NeverUseOption {
    /// Refuses, before any question, a word the library would refuse whatever word is chosen: a
    /// word not on the list, or more than it takes. Asking for a chosen word again could never
    /// mend it (AUD-015-UI002).
    pub fn check(&self) -> Result<(), Failure> {
        if let Some(words) = self.words() {
            let never: Vec<&str> = words.iter().map(String::as_str).collect();
            WordWishes::new(&[], &never)?;
        }
        Ok(())
    }

    /// The words given, if any: one, or more for the library to refuse.
    fn words(&self) -> Option<Vec<String>> {
        self.never_use.as_deref().map(split_words)
    }
}

/// Words separated by commas or spaces.
fn split_words(text: &str) -> Vec<String> {
    text.split(|character: char| character == ',' || character.is_whitespace())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Asks for the wishes of the new phrase until the library takes them for `draw`, and says what
/// they cost: none when the person wants every word at random.
pub fn ask(
    input: &mut Input,
    draw: PhraseDraw,
    option: &NeverUseOption,
) -> Result<PhraseDraw, Failure> {
    let given = option.words();
    loop {
        let wants_words = ask_whether(input)?;
        if !wants_words && given.is_none() {
            // The wallet check alone costs 16 bits, which is said too.
            tell(draw.odds());
            choice::record(RECORD, "no words, every word at random");
            return Ok(draw);
        }
        let chosen = if wants_words {
            read_chosen(input)?
        } else {
            Vec::new()
        };
        let never_use = match &given {
            Some(words) => words.clone(),
            None if wants_words => read_never_use(input)?,
            None => Vec::new(),
        };
        let pairs: Vec<(Place, &str)> = chosen
            .iter()
            .map(|(place, word)| (*place, word.as_str()))
            .collect();
        let never: Vec<&str> = never_use.iter().map(String::as_str).collect();
        match WordWishes::new(&pairs, &never) {
            Ok(wishes) => {
                let draw = draw.with_wishes(wishes);
                tell(draw.odds());
                record(chosen.len(), never_use.len(), draw.odds());
                return Ok(draw);
            }
            Err(error) if input.can_ask_again() => {
                style::retry_next(exit::refused(&error, "Choose again."));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Whether the person wants to choose a word.
fn ask_whether(input: &mut Input) -> Result<bool, Failure> {
    let answers = [
        Answer::new(
            "Every word at random",
            "the phrase keeps all its randomness",
        ),
        Answer::new("Choose one word", "not recommended: see More"),
    ];
    let question = Question {
        text: "Do you want to choose a word of the new phrase?",
        explanation: &[],
        more: Some(readme::NEW),
        record: None,
    };
    Ok(input.choose(&question, &answers)? == 1)
}

/// The chosen word with its place, typed hidden on a private screen as part of the secret phrase:
/// none for Enter alone.
fn read_chosen(input: &mut Input) -> Result<Vec<(Place, Zeroizing<String>)>, Failure> {
    let _screen = PrivateScreen::enter(input, Operation::New.title());
    let word = input.secret_words("Chosen word, or Enter for none", WordList::Bip39)?;
    if word.is_empty() {
        return Ok(Vec::new());
    }
    let place = read_place(input)?;
    Ok(vec![(place, Zeroizing::new(word.to_string()))])
}

/// The place of the chosen word: a position in the phrase, or Enter for anywhere. The library
/// refuses a position outside it.
fn read_place(input: &mut Input) -> Result<Place, Failure> {
    loop {
        let typed = input.visible(&format!(
            "Its position, 1 to {PHRASE_WORDS}, or Enter for anywhere: "
        ))?;
        let typed = typed.trim();
        if typed.is_empty() {
            return Ok(Place::Anywhere);
        }
        match typed.parse::<usize>() {
            Ok(position) => return Ok(Place::At(position)),
            Err(_) => {
                style::retry(format!(
                    "Type a number from 1 to {PHRASE_WORDS}, or Enter alone for anywhere."
                ));
            }
        }
    }
}

/// The word never to use, typed visibly on a step of its own: it is not part of the phrase.
fn read_never_use(input: &mut Input) -> Result<Vec<String>, Failure> {
    flow::step();
    let typed = input.visible_words("Word never to use, or Enter for none: ", WordList::Bip39)?;
    Ok(split_words(&typed))
}

/// Says what the wishes leave of the phrase's randomness, as the library rates it, and what chosen
/// words give away.
pub fn tell(odds: WishOdds) {
    if odds.recognisable {
        style::warn(
            "If someone learns or guesses your chosen word, it lets them rule out almost every \
             wrong password and tell this wallet from a decoy.",
            "Never tell anyone your chosen word. Choose no word for a wallet you would protect with \
             a decoy.",
        );
    }
    let bits = odds.random_bits.floor();
    match odds.randomness {
        Randomness::Full => {}
        Randomness::Ample => style::warn(
            &format!(
                "The phrase keeps about {bits} of its 256 random bits: still far more than enough."
            ),
            "",
        ),
        Randomness::NotRecommended => style::warn(
            &format!(
                "Not recommended: the phrase keeps about {bits} of its 256 random bits, fewer than \
                 {RECOMMENDED_RANDOM_BITS}."
            ),
            // Only where it helps: a word anywhere already keeps the most (AUD-015-UI003).
            if odds.fixed_position {
                "A word anywhere in the phrase keeps more than one at a fixed position."
            } else {
                ""
            },
        ),
    }
}

/// The label of the wishes in the summary.
const RECORD: &str = "Chosen";

/// Records the wishes in the summary without naming a word.
fn record(chosen: usize, never_use: usize, odds: WishOdds) {
    let words = if chosen == 1 { "word" } else { "words" };
    choice::record(
        RECORD,
        &format!(
            "{chosen} {words}, {never_use} never to use; about {} random bits",
            odds.random_bits.floor()
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_use_words_are_split_at_commas_and_spaces() {
        assert_eq!(
            split_words("abandon, zoo  happy,,"),
            ["abandon", "zoo", "happy"]
        );
        assert!(split_words(" , ").is_empty());
    }
}
