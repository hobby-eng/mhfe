//! `mhfe repair` and `mhfe repair-words`: repair words for a container plate (mhfe::repair, the
//! optional profile MHFE-REPAIR-1 of the specification). A few extra words, kept on a card apart
//! from the plate, repair it when words rust away, are scratched or were copied wrongly, without
//! the password and without Argon2.

use anstream::{eprintln, println};
use clap::Args;
use mhfe::memory::LockedText;
use mhfe::repair::{self, Repaired, REPAIR_WORD_COUNTS};
use mhfe::WORD_COUNTS;

use crate::choice::{self, Answer, Question};
use crate::exit::{capitalize, Failure, SUCCESS};
use crate::flow::Flow;
use crate::readme;
use crate::style::{self, paint, ACCENT, HEADING, MUTED, STRONG};
use crate::terminal::{self, Input, PrivateScreen, Wallet};

#[derive(Args)]
pub struct RepairOptions {
    /// Read the answers from standard input (for scripts)
    #[arg(long, long_help = repair_stdin_help())]
    stdin: bool,
}

#[derive(Args)]
pub struct WordsOptions {
    /// Number of repair words: 2, 4, 6 or 8
    #[arg(long, value_name = "N", long_help = count_help())]
    count: Option<usize>,

    /// Read the container from standard input (for scripts)
    #[arg(long, requires = "count", long_help = words_stdin_help())]
    stdin: bool,
}

fn repair_stdin_help() -> String {
    style::option_help(&[
        "Read the answers from standard input (for scripts).",
        "Input: the plate, then the repair words, one line each, with ? for a word that cannot \
         be read. Output: the repaired container on one line, or nothing when there is nothing \
         to repair.",
    ])
}

fn count_help() -> String {
    style::option_help(&[
        "Number of repair words: 2, 4, 6 or 8.",
        "Asked at a terminal when not given; a script must give it.",
    ])
}

fn words_stdin_help() -> String {
    style::option_help(&[
        "Read the container from standard input (for scripts); needs --count.",
        "Input: the container on one line. Output: the repair words on one line.",
    ])
}

/// The end of `mhfe repair -h` and `--help`.
pub fn repair_help() -> String {
    style::help_section(
        "Examples:",
        &[
            (
                "mhfe repair",
                "Type the plate and the card; ? for a word that cannot be read",
            ),
            (
                "your-program | mhfe repair --stdin",
                "A script: the plate and the card from another program, the repaired container \
                 out",
            ),
        ],
    )
}

/// The end of `mhfe repair-words -h` and `--help`.
pub fn words_help() -> String {
    style::help_section(
        "Examples:",
        &[
            ("mhfe repair-words", "Choose how many repair words to make"),
            (
                "mhfe repair-words --count 4",
                "Four repair words, the recommended number",
            ),
            (
                "your-program | mhfe repair-words --stdin --count 4",
                "A script: the container from another program, the four words out",
            ),
        ],
    )
}

/// The top of `mhfe repair --help`.
pub fn repair_about() -> String {
    style::command_about(&[
        "Repair a plate with its repair words",
        "Repairs the words of a container plate that cannot be read or were copied wrongly, from \
         the repair words kept on a card, without the password. Type ? for a word that cannot be \
         read. Each repair word repairs one unreadable word; two repair one wrong word.",
    ])
}

/// The top of `mhfe repair-words --help`.
pub fn words_about() -> String {
    style::command_about(&[
        "Make repair words for a plate",
        "Makes 2, 4, 6 or 8 repair words for a container, to keep on a card apart from the \
         plate. mhfe repair then repairs the plate with them, without the password.",
    ])
}

const REPAIR_TITLE: &str = "Repair a plate";
const WORDS_TITLE: &str = "Make repair words";

pub fn run_repair(options: RepairOptions) -> Result<i32, Failure> {
    let mut input = Input::new(options.stdin);
    // At a terminal every step on a screen of its own, the summary at the end.
    let flow = Flow::start(&input, REPAIR_TITLE);
    style::title(REPAIR_TITLE);
    let (plate, card) = read_damaged(&mut input)?;
    let repaired = repair::repair(&plate, &card)?;
    drop((plate, card));
    if repaired.plate_words.is_empty() && repaired.card_words.is_empty() {
        flow.finish();
        style::ok("The plate and its repair words agree: nothing to repair.");
        return Ok(SUCCESS);
    }
    // The repaired container is shown privately, as a container always is.
    let screen = PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(REPAIR_TITLE);
    }
    eprintln!();
    eprintln!(
        "{}",
        paint(
            HEADING,
            format!(
                "Repaired container, {} words",
                repaired.container.split(' ').count()
            )
        )
    );
    terminal::print_phrase(&repaired.container, Wallet::Container, &input);
    eprintln!();
    style::ok(what_was_repaired(&repaired));
    print_changes(&repaired);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    drop(screen);
    flow.finish();
    style::fact_wrapped(
        "Next",
        &format!(
            "write the repaired words on the plate; rehearse with {}",
            paint(ACCENT, "mhfe check")
        ),
    );
    style::more(readme::REPAIR);
    Ok(SUCCESS)
}

pub fn run_words(options: WordsOptions) -> Result<i32, Failure> {
    if let Some(count) = options.count {
        if !REPAIR_WORD_COUNTS.contains(&count) {
            return Err(Failure::invalid_input(format!(
                "A card has 2, 4, 6 or 8 repair words, not {count}."
            )));
        }
    }
    let mut input = Input::new(options.stdin);
    let flow = Flow::start(&input, WORDS_TITLE);
    style::title(WORDS_TITLE);
    let container = terminal::read_container(&mut input, WORDS_TITLE)?;
    let count = match options.count {
        Some(count) => count,
        // Without --count a script is refused by clap, so the person at a terminal is asked.
        None => ask_count(&mut input, false)?.unwrap_or(repair::RECOMMENDED_REPAIR_WORDS),
    };
    let words = repair::repair_words(container.words(), count)?;
    let screen = PrivateScreen::enter_to_show(&input);
    if screen.is_active() {
        style::title(WORDS_TITLE);
    }
    print_card(&words, &input);
    if screen.is_active() {
        terminal::wait_to_leave()?;
    }
    drop(screen);
    flow.finish();
    style::fact_wrapped("Keep", "the repair words on a card, apart from the plate");
    style::more(readme::REPAIR);
    Ok(SUCCESS)
}

/// Asks how many repair words a plate gets, the recommended four first; with `offer_none`, as when
/// a container is made, "none" too, which gives `None`.
pub fn ask_count(input: &mut Input, offer_none: bool) -> Result<Option<usize>, Failure> {
    // The counts in the order of the answers below.
    const COUNTS: [usize; 4] = [repair::RECOMMENDED_REPAIR_WORDS, 2, 6, 8];
    let mut answers = vec![
        Answer::new(
            "4 repair words (recommended)",
            "4 unreadable or 2 wrong words",
        ),
        Answer::new("2 repair words", "2 unreadable or 1 wrong word"),
        Answer::new("6 repair words", "6 unreadable or 3 wrong words"),
        Answer::new("8 repair words", "8 unreadable or 4 wrong words"),
    ];
    if offer_none {
        answers.push(Answer::new("No repair words", "nothing to keep apart"));
    }
    let question = Question {
        text: "Repair words for the plate?",
        explanation: &["They fix unreadable or miscopied plate words without the password."],
        more: Some(readme::REPAIR),
        record: Some("Repair"),
    };
    let chosen = input.choose(&question, &answers)?;
    Ok(COUNTS.get(chosen).copied())
}

/// At a terminal, asks whether a new container gets repair words; a script, whose answers come in
/// a documented order, gets none.
pub fn ask_when_creating(input: &mut Input) -> Result<Option<usize>, Failure> {
    if input.is_script() || !choice::can_run() {
        return Ok(None);
    }
    ask_count(input, true)
}

/// The repair card as it is written down: the profile's name, then the words numbered as "1/4",
/// as the specification advises, so that the card tells how many words it has. A script gets the
/// bare words.
pub fn print_card(words: &str, input: &Input) {
    if input.is_script() {
        println!("{words}");
        return;
    }
    let count = words.split(' ').count();
    eprintln!();
    eprintln!(
        "{} {}",
        paint(HEADING, "Repair card"),
        paint(STRONG, repair::PROFILE)
    );
    for row in words
        .split(' ')
        .enumerate()
        .collect::<Vec<_>>()
        .chunks(CARD_WORDS_PER_ROW)
    {
        let cells: Vec<String> = row
            .iter()
            .map(|(index, word)| {
                format!(
                    "{} {}",
                    paint(MUTED, format!("{:>3}/{count}", index + 1)),
                    paint(STRONG, format!("{word:<8}"))
                )
            })
            .collect();
        println!(" {}", cells.join("  "));
    }
    style::hint("Write it on a card as shown, and keep the card apart from the plate.");
}

/// Repair words a row of the card, as the words of a phrase are shown.
const CARD_WORDS_PER_ROW: usize = 4;

/// Each repaired word with what was read there, so that no repair is silent.
fn print_changes(repaired: &Repaired) {
    for change in &repaired.changes {
        let place = if change.on_card { "card" } else { "word" };
        let read = change.read.as_deref().unwrap_or("unreadable");
        eprintln!(
            "  {} {} → {}",
            paint(MUTED, format!("{place} {:>2}", change.position)),
            paint(MUTED, format!("{read:<10}")),
            paint(STRONG, &change.word)
        );
    }
}

/// Reads the plate and the card on a private screen, `?` for a word that cannot be read, again
/// until each has a length it can have.
fn read_damaged(input: &mut Input) -> Result<(LockedText, LockedText), Failure> {
    let screen = PrivateScreen::enter(input, REPAIR_TITLE);
    if screen.is_active() {
        eprintln!();
        style::hint("Type ? for a word you cannot read; four letters of a word are enough.");
    }
    // A container has 24 words, or 12 to 21 if it has the length of its original.
    let plate = read_words(
        input,
        "Plate",
        &WORD_COUNTS,
        "A plate has 12, 15, 18, 21 or 24",
        |typed| typed.split_whitespace().count(),
    )?;
    // A card may be typed as written, with the profile's name and its numbers.
    let card = read_words(
        input,
        "Repair words",
        &REPAIR_WORD_COUNTS,
        "A card has 2, 4, 6 or 8",
        |typed| repair::card_text(typed).split_whitespace().count(),
    )?;
    drop(screen);
    choice::record(
        "Plate",
        &format!("{} words", plate.split_whitespace().count()),
    );
    choice::record(
        "Card",
        &format!(
            "{} repair words",
            repair::card_text(&card).split_whitespace().count()
        ),
    );
    Ok((plate, card))
}

/// One line of words whose count, by `count_of`, is one of `counts`; `what` begins the message for
/// another count.
fn read_words(
    input: &mut Input,
    prompt: &str,
    counts: &[usize],
    what: &str,
    count_of: fn(&str) -> usize,
) -> Result<LockedText, Failure> {
    loop {
        let typed = input.visible(&format!("{prompt}: "))?;
        let count = count_of(&typed);
        if counts.contains(&count) {
            return Ok(typed);
        }
        let message = format!("{what} words, not {count}; type ? for a word you cannot read.");
        if !input.can_ask_again() {
            return Err(Failure::invalid_input(capitalize(&message)));
        }
        style::retry(message);
    }
}

/// "Repaired words 3 and 17 of the plate and word 2 of the card."
fn what_was_repaired(repaired: &Repaired) -> String {
    let list = |positions: &[usize]| -> String {
        let numbers: Vec<String> = positions.iter().map(ToString::to_string).collect();
        match numbers.split_last() {
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
            None => String::new(),
        }
    };
    let part = |positions: &[usize], of: &str| -> Option<String> {
        match positions.len() {
            0 => None,
            1 => Some(format!("word {} of the {of}", list(positions))),
            _ => Some(format!("words {} of the {of}", list(positions))),
        }
    };
    let parts: Vec<String> = [
        part(&repaired.plate_words, "plate"),
        part(&repaired.card_words, "card"),
    ]
    .into_iter()
    .flatten()
    .collect();
    format!("Repaired {}.", parts.join(" and "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repaired_words_are_listed_plainly() {
        let repaired = |plate: Vec<usize>, card: Vec<usize>| Repaired {
            container: String::new(),
            plate_words: plate,
            card_words: card,
            changes: Vec::new(),
        };
        assert_eq!(
            what_was_repaired(&repaired(vec![3], vec![])),
            "Repaired word 3 of the plate."
        );
        assert_eq!(
            what_was_repaired(&repaired(vec![3, 9, 17], vec![2])),
            "Repaired words 3, 9 and 17 of the plate and word 2 of the card."
        );
    }

    #[test]
    fn the_question_fits_the_screen() {
        assert!(
            "They fix unreadable or miscopied plate words without the password.".len() + 2
                <= choice::LINE_WIDTH
        );
    }
}
