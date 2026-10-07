//! Questions answered from a short list with the arrow keys, laid out as in MnemoCode
//! (src/cli/terminal-choice.ts there), so that a screen of questions never runs together:
//!
//! - a blank line, then the question in bold;
//! - its explanation, if any: short lines written by hand, indented two spaces, in the normal
//!   colour, with a blank line between two topics, and where to read more last, in grey under
//!   "More:";
//! - a blank line, one line per answer as "› 1  Label  grey note", a blank line and the grey key
//!   hint.
//!
//! ↑ and ↓ move, Enter selects, a digit selects at once and Escape, or q, cancels. Once answered,
//! the whole block is erased and one line records the answer, a grey label and the answer in cyan,
//! like the facts of a summary, so that the answers build a short summary.
//!
//! The block is redrawn by moving the cursor up, so it needs a terminal ([`can_run`]); a script,
//! or a terminal that cannot do this, is asked with numbered lines instead (`Input::choose` in
//! terminal.rs).

use std::io::{self, IsTerminal, Write};

use anstream::eprintln;

use crate::exit::Failure;
use crate::flow::{self, Kind};
use crate::hidden_input::{self, Key};
use crate::style::{self, paint, ACCENT, MUTED, STRONG};
use crate::terminal;

/// The width that a line of a list must not exceed: the list redraws itself by moving the cursor
/// up line by line, which a line wrapped by the terminal would upset. As style.rs: 78 columns.
pub const LINE_WIDTH: usize = 78;

/// The indent of an explanation.
const TEXT_INDENT: &str = "  ";

/// A question with what explains it.
pub struct Question<'a> {
    pub text: &'a str,
    /// Short lines, each written to fit LINE_WIDTH with its indent; "" separates two topics.
    pub explanation: &'a [&'a str],
    /// The README section that explains the question, linked on one grey line.
    pub more: Option<&'a str>,
    /// The grey label of the line that records the answer, at most 10 characters; `None` when
    /// what the program shows next states the answer anyway.
    pub record: Option<&'a str>,
}

impl<'a> Question<'a> {
    /// A question without an explanation.
    pub fn new(text: &'a str, record: &'a str) -> Self {
        Self {
            text,
            explanation: &[],
            more: None,
            record: Some(record),
        }
    }
}

/// One answer of a question: a label and a grey note beside it, which may be empty.
pub struct Answer {
    pub label: String,
    pub note: String,
}

impl Answer {
    pub fn new(label: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            note: note.into(),
        }
    }
}

/// An explanation shown when the person presses ?, and the words that offer it in the hint
/// line, such as "? explains both".
pub struct Help<'a> {
    pub hint: &'a str,
    pub show: &'a dyn Fn(),
}

/// Whether a list can be shown: it reads single keys from a terminal and draws on one.
pub fn can_run() -> bool {
    io::stdin().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

/// Asks `question` and returns the index of the chosen answer, or `None` when the person pressed
/// Escape or q; the block is then erased without a record. The first answer is highlighted at the
/// start, so that Enter alone chooses it. In a command shown one step at a time the question is a
/// step of its own.
pub fn choose(
    question: &Question,
    answers: &[Answer],
    help: Option<Help>,
) -> Result<Option<usize>, Failure> {
    flow::step();
    choose_here(question, answers, help)
}

/// [`choose`] below what the screen shows already, for a question about it, such as whether a
/// phrase shown matches the owner's record.
pub fn choose_here(
    question: &Question,
    answers: &[Answer],
    help: Option<Help>,
) -> Result<Option<usize>, Failure> {
    run_list(question, answers, help, Some(0))
}

/// [`choose`] with no answer highlighted at the start, for a question whose answer must be the
/// person's own: Enter selects nothing until an arrow key has highlighted an answer, and a digit
/// chooses at once. `help` is shown on ?, as in [`choose`].
pub fn choose_without_default(
    question: &Question,
    answers: &[Answer],
    help: Option<Help>,
) -> Result<Option<usize>, Failure> {
    flow::step();
    run_list(question, answers, help, None)
}

/// The list of [`choose_here`], starting with `start` highlighted, or none.
fn run_list(
    question: &Question,
    answers: &[Answer],
    help: Option<Help>,
    start: Option<usize>,
) -> Result<Option<usize>, Failure> {
    let help_hint = help.as_ref().map(|help| help.hint);
    let last = answers.len() - 1;
    // The terminal reads single keys before the list appears, as a hidden prompt does, so that a
    // key pressed as soon as the list shows is read as a key and never echoed.
    hidden_input::with_keys(|next_key| {
        let mut selected = start;
        let mut drawn = draw(question, answers, selected, help_hint);
        let selected = loop {
            match (next_key()?, selected) {
                (Key::Up, Some(index)) => selected = Some(index.checked_sub(1).unwrap_or(last)),
                (Key::Up, None) => selected = Some(last),
                (Key::Down, Some(index)) => selected = Some((index + 1) % answers.len()),
                (Key::Down, None) => selected = Some(0),
                (Key::Enter, Some(index)) => break index,
                (Key::Enter, None) => continue,
                (Key::Digit(number), _) if usize::from(number) <= answers.len() => {
                    break usize::from(number) - 1;
                }
                (Key::Help, _) => {
                    let Some(help) = &help else { continue };
                    // The explanation takes the place of the block, which is drawn again below it.
                    write_control(&redraw_from(drawn.rows()))?;
                    eprintln!();
                    (help.show)();
                    drawn = draw(question, answers, selected, help_hint);
                    continue;
                }
                (Key::Quit, _) => {
                    write_control(&redraw_from(drawn.rows()))?;
                    return Ok(None);
                }
                (Key::Digit(_) | Key::Other, _) => continue,
            }
            write_control(&redraw_from(drawn.rows()))?;
            drawn = draw(question, answers, selected, help_hint);
        };
        write_control(&redraw_from(drawn.rows()))?;
        if let Some(label) = question.record {
            record(label, &answers[selected].label);
        }
        Ok(Some(selected))
    })
}

/// The line that records an answer: a grey label and the answer in cyan, as a fact of a summary.
pub fn record(label: &str, answer: &str) {
    style::fact_as(Kind::Record, label, paint(ACCENT, answer));
}

/// The visible widths of logical lines, without retaining their text, and the width of the
/// terminal they were drawn at. Keeping only widths avoids a second copy of any sensitive labels
/// and leaves the phrase above a confirmation visible.
struct DrawnRows {
    widths: Vec<usize>,
    drawn_at: usize,
}

impl DrawnRows {
    fn new() -> Self {
        Self {
            widths: Vec::new(),
            drawn_at: current_columns(),
        }
    }

    fn line(&mut self, text: &str) {
        eprintln!("{text}");
        self.widths.push(style::visible_width(text));
    }

    fn extend(&mut self, other: Self) {
        self.widths.extend(other.widths);
    }

    /// The rows the lines take now. A terminal rewraps the lines of its main screen when it is
    /// resized, so there they take the rows of the new width; the alternate screen, which holds
    /// the steps of a command and its private screens, is not rewrapped by VTE or Alacritty, so
    /// there they keep the rows they were drawn in.
    fn rows(&self) -> usize {
        let now = current_columns();
        if now == self.drawn_at || terminal::on_alternate_screen() {
            self.rows_at(self.drawn_at)
        } else {
            self.rows_at(now)
        }
    }

    fn rows_at(&self, columns: usize) -> usize {
        self.widths
            .iter()
            .map(|width| width.div_ceil(columns.max(1)).max(1))
            .sum()
    }
}

/// The width of the terminal now; when it cannot be read, the usual 80 columns.
fn current_columns() -> usize {
    hidden_input::columns().unwrap_or(80).max(1)
}

/// Draws the question block and retains only its line widths for later redraws.
fn draw(
    question: &Question,
    answers: &[Answer],
    selected: Option<usize>,
    help_hint: Option<&str>,
) -> DrawnRows {
    let mut lines = draw_question_rows(question);
    let entries: Vec<(&str, &str)> = answers
        .iter()
        .map(|answer| (answer.label.as_str(), answer.note.as_str()))
        .collect();
    lines.extend(draw_entry_rows(&entries, selected));
    lines.line("");
    for line in style::wrap(
        &hint(answers.len(), help_hint, selected.is_some()),
        style::TEXT_WIDTH,
    ) {
        lines.line(&paint(MUTED, line));
    }
    lines
}

/// Draws a blank line, the question in bold and its explanation, and returns how many lines they
/// took. A list or a prompt follows; after an explanation, a blank line separates it.
pub fn draw_question(question: &Question) -> usize {
    draw_question_rows(question).rows()
}

fn draw_question_rows(question: &Question) -> DrawnRows {
    let mut lines = DrawnRows::new();
    let text = paint(STRONG, question.text);
    lines.line("");
    lines.line(&text);
    for line in question.explanation {
        if line.is_empty() {
            lines.line("");
        } else {
            let line = format!("{TEXT_INDENT}{line}");
            lines.line(&line);
        }
    }
    if let Some(place) = question.more {
        // Without an explanation the link follows the question directly, as part of it.
        if !question.explanation.is_empty() {
            lines.line("");
        }
        lines.line(&style::more_line(place));
    }
    if !question.explanation.is_empty() || question.more.is_some() {
        lines.line("");
    }
    lines
}

/// Whether every line of an explanation fits the width of a list with its indent.
#[cfg(test)]
pub fn fits(explanation: &[&str]) -> bool {
    explanation
        .iter()
        .all(|line| TEXT_INDENT.len() + line.chars().count() <= LINE_WIDTH)
}

/// The keys of a list: "↑ ↓ choose · Enter selects · 1 or 2 at once · Esc cancels", with the help
/// before Esc. q cancels too but is not offered: a keyboard layout may have no q. Only the first
/// nine answers have a digit key. With no answer `marked` yet, Enter selects nothing, so the hint
/// says it waits for one.
fn hint(answers: usize, help_hint: Option<&str>, marked: bool) -> String {
    let numbers = match answers {
        2 => "1 or 2".to_owned(),
        _ => format!("1 to {}", answers.min(DIGIT_KEYS)),
    };
    let help = help_hint
        .map(|hint| format!(" · {hint}"))
        .unwrap_or_default();
    let enter = if marked {
        "Enter selects"
    } else {
        "Enter selects once one is marked"
    };
    let line = format!("↑ ↓ choose · {enter} · {numbers} at once{help} · Esc cancels");
    if line.chars().count() <= LINE_WIDTH {
        return line;
    }
    // Too long for one line, as with no answer marked and an explanation behind ?: the keys that
    // move and explain first, then how to choose and how to leave, each part whole on its line.
    format!("↑ ↓ choose · {numbers} at once{help}\n{enter} · Esc cancels")
}

/// Answers that a digit key chooses at once: 1 to 9. Further answers are reached with the arrows
/// and show no number.
pub(crate) const DIGIT_KEYS: usize = 9;

/// Draws one line per entry, a label and a grey note, and returns how many rows they took, a line
/// wider than a narrow terminal taking more than one. The
/// highlighted entry has a cyan marker and a bold label, so that it stands out also without
/// colours. The notes line up after the longest label and are shortened to fit the width.
pub fn draw_entries(entries: &[(&str, &str)], selected: usize) -> usize {
    draw_entry_rows(entries, Some(selected)).rows()
}

/// The entries with `selected` highlighted, or none.
fn draw_entry_rows(entries: &[(&str, &str)], selected: Option<usize>) -> DrawnRows {
    let label_width = entries
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let mut rows = DrawnRows::new();
    for (index, (label, note)) in entries.iter().enumerate() {
        let number = if index < DIGIT_KEYS {
            paint(MUTED, index + 1)
        } else {
            " ".to_owned()
        };
        let (marker, shown_label) = if Some(index) == selected {
            (paint(ACCENT, "›"), paint(STRONG, label))
        } else {
            (" ".to_owned(), (*label).to_owned())
        };
        // Marker, number and the gaps: "› 1  " and two spaces before the note.
        let note_room = LINE_WIDTH.saturating_sub(5 + label_width + 2);
        let note = shortened(note, note_room);
        let line = if note.is_empty() {
            format!("{marker} {number}  {shown_label}")
        } else {
            // Padded by hand: the width of a painted label would count its colour codes.
            let padding = " ".repeat(label_width - label.chars().count());
            format!(
                "{marker} {number}  {shown_label}{padding}  {}",
                paint(MUTED, note)
            )
        };
        rows.line(&line);
    }
    rows
}

/// `text` cut to `room` characters with "…" at the end, so that a long note cannot wrap the line.
pub fn shortened(text: &str, room: usize) -> String {
    if text.chars().count() <= room {
        return text.to_owned();
    }
    let kept: String = text.chars().take(room.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Moves the cursor up `lines_above` lines to the start of the line, then clears to the end of
/// the screen (VT100 "cursor up" and "erase in display").
pub fn redraw_from(lines_above: usize) -> String {
    format!("\x1b[{lines_above}A\r\x1b[J")
}

/// Writes a cursor-control sequence as it is: anstream would remove it when NO_COLOR is set.
pub fn write_control(sequence: &str) -> Result<(), Failure> {
    let mut terminal = io::stderr();
    terminal.write_all(sequence.as_bytes())?;
    terminal.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_line_widths_recount_rows_after_a_resize() {
        let drawn = DrawnRows {
            widths: vec![0, 54, 78, 40, 39],
            drawn_at: 80,
        };
        assert_eq!(drawn.rows_at(80), 5);
        assert_eq!(drawn.rows_at(60), 6);
        assert_eq!(drawn.rows_at(40), 7);
        assert_eq!(drawn.rows_at(80), 5);
    }

    #[test]
    fn the_hint_names_the_numbers_and_the_help() {
        assert_eq!(
            hint(2, None, true),
            "↑ ↓ choose · Enter selects · 1 or 2 at once · Esc cancels"
        );
        assert_eq!(
            hint(4, Some("? explains both"), true),
            "↑ ↓ choose · Enter selects · 1 to 4 at once · ? explains both · Esc cancels"
        );
        assert!(hint(9, Some("? explains both"), true).chars().count() <= LINE_WIDTH);
        assert_eq!(
            hint(12, None, true),
            "↑ ↓ choose · Enter selects · 1 to 9 at once · Esc cancels"
        );
        // A list with no answer marked yet: Enter waits for one.
        assert_eq!(
            hint(2, None, false),
            "↑ ↓ choose · Enter selects once one is marked · 1 or 2 at once · Esc cancels"
        );
        // With an explanation too, it takes two lines, Enter and Esc together on the second.
        assert_eq!(
            hint(2, Some("? explains both"), false),
            "↑ ↓ choose · 1 or 2 at once · ? explains both\n\
             Enter selects once one is marked · Esc cancels"
        );
        for answers in [2, 4, 12] {
            for help in [None, Some("? explains both")] {
                for marked in [true, false] {
                    let text = hint(answers, help, marked);
                    assert!(
                        text.lines().all(|line| line.chars().count() <= LINE_WIDTH),
                        "{text}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_long_note_is_shortened() {
        assert_eq!(
            shortened("mhfe serve tool.html", 40),
            "mhfe serve tool.html"
        );
        assert_eq!(
            shortened("mhfe serve a-very-long-name.html", 15),
            "mhfe serve a-v…"
        );
    }
}
