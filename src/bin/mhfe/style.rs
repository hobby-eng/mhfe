//! Colours and layout of everything the tool shows.
//!
//! Text is written through `anstream`, which drops the colour codes when the output is not a
//! terminal, when `NO_COLOR` is set, or when the terminal cannot show colours, and enables them
//! in the Windows console. Only the standard sixteen terminal colours are used, so every colour
//! scheme shows them. Results for scripts never carry colour.

use std::fmt::{Display, Write};

use anstream::{eprint, eprintln};
use anstyle::{AnsiColor, Style};
use zeroize::Zeroizing;

use crate::flow::{self, Kind};
use crate::hidden_input;

/// Titles, section headings and the words `mhfe` and its commands.
pub const HEADING: Style = AnsiColor::Cyan.on_default().bold();
/// Command names and the progress bar.
pub const ACCENT: Style = AnsiColor::Cyan.on_default();
/// Questions and the words of a phrase.
pub const STRONG: Style = Style::new().bold();
/// Labels, numbers, hints and anything secondary. Bright black is the grey of most schemes;
/// "dim" text is too faint in some terminals.
pub const MUTED: Style = AnsiColor::BrightBlack.on_default();
pub const GOOD: Style = AnsiColor::Green.on_default().bold();
pub const WARNING: Style = AnsiColor::Yellow.on_default().bold();
pub const BAD: Style = AnsiColor::Red.on_default().bold();

/// `text` in `style`. For public text only: the result is an ordinary string, which is not
/// wiped. Secret words are painted by [`boxed_words`].
pub fn paint(style: Style, text: impl Display) -> String {
    format!("{style}{text}{style:#}")
}

/// The first lines of a command: its name and what it does. A command shown one step at a time
/// heads every step and its summary itself (flow.rs).
pub fn title(what: &str) -> usize {
    if flow::is_active() {
        return 0;
    }
    write_title(what)
}

/// Writes the title line at once, after a blank line; returns the rows they took.
pub fn write_title(what: &str) -> usize {
    let line = format!(
        "{} {} {}",
        paint(HEADING, "MHFE"),
        paint(MUTED, "·"),
        paint(STRONG, what)
    );
    eprintln!();
    eprintln!("{line}");
    1 + rows(&line)
}

/// How many rows of the terminal on standard error `line` takes, written on a line of its own: a
/// line wider than the terminal wraps onto further rows, which a redraw that moves the cursor up
/// must count, also in a narrow window (AUD-008-UI001). A line that fills its last row exactly
/// takes no more: the cursor moves on only with the next character.
pub fn rows(line: &str) -> usize {
    // When the width cannot be read, the usual 80 columns.
    let columns = hidden_input::columns().unwrap_or(80).max(1);
    visible_width(line).div_ceil(columns).max(1)
}

/// One line of a summary table: a grey label and its value.
pub fn fact(label: &str, value: impl Display) {
    fact_as(Kind::Fact, label, value);
}

/// A line of a summary table of `kind`: in a command shown one step at a time it waits for the
/// summary at the end.
pub fn fact_as(kind: Kind, label: &str, value: impl Display) {
    let line = fact_line(label, value);
    if !flow::keep(kind, std::slice::from_ref(&line)) {
        eprintln!("{line}");
    }
}

/// [`fact`] that is shown at the top of the next step too, so that it is read before the work it
/// describes starts.
pub fn fact_before_work(label: &str, value: impl Display) {
    let line = fact_line(label, value);
    if !flow::keep_next(Kind::Fact, std::slice::from_ref(&line)) {
        eprintln!("{line}");
    }
}

fn fact_line(label: &str, value: impl Display) -> String {
    format!("  {} {value}", paint(MUTED, format!("{label:<10}")))
}

/// Something that went right, after a green tick. It is shown at once, on the step it belongs to,
/// and kept for the summary too.
pub fn ok(text: impl Display) {
    let line = format!("{} {text}", paint(GOOD, "✓"));
    eprintln!("{line}");
    flow::keep_shown(Kind::Result, &[line]);
}

/// Advice that can be read and passed over, in grey, wrapped to the text width. Returns the lines
/// it took, for a step that erases itself once answered (terminal::Step).
pub fn hint(text: &str) -> usize {
    let lines = wrap(text, TEXT_WIDTH);
    for line in &lines {
        eprintln!("{}", paint(MUTED, line));
    }
    lines.iter().map(|line| rows(line)).sum()
}

/// A grey line that links to the README section explaining what a screen only names; returns
/// the lines it took on the screen. In a command shown one step at a time it goes with the
/// summary line or warning before it.
pub fn more(place: &str) -> usize {
    let line = more_line(place);
    if !flow::keep_link(line.clone()) {
        return 0;
    }
    eprintln!("{line}");
    1
}

/// [`more`] written at once, as part of a question or another step.
pub fn more_here(place: &str) -> usize {
    let line = more_line(place);
    eprintln!("{line}");
    rows(&line)
}

fn more_line(place: &str) -> String {
    format!("  {}", paint(MUTED, format!("More: {place}")))
}

/// A warning: a yellow headline after "!", then `body` wrapped, every line marked with "!". In a
/// command shown one step at a time it is kept for the summary and shown at the top of the next
/// step, so that it is read before the person goes on.
pub fn warn(headline: &str, body: &str) {
    let lines = marked(WARNING, "!", headline, body);
    if !flow::keep_notice(&lines) {
        write_lines(&lines);
    }
}

/// A warning about the screen it is on, such as the wait to clear it, never kept for a summary.
pub fn warn_here(headline: &str, body: &str) {
    write_lines(&marked(WARNING, "!", headline, body));
}

/// A warning shown at once, next to what it is about, and kept for the summary too, such as the
/// status of a recovered phrase.
pub fn warn_now(headline: &str, body: &str) {
    let lines = marked(WARNING, "!", headline, body);
    write_lines(&lines);
    flow::keep_shown(Kind::Notice, &lines);
}

/// A mistake in an answer that can be typed again: the message wrapped, every line after a yellow
/// "!". Returns the lines it took, as `hint` does.
pub fn retry(text: impl Display) -> usize {
    let lines = retry_lines(text);
    write_lines(&lines);
    lines.iter().map(|line| rows(line)).sum()
}

/// [`retry`] for an answer that is asked again on a step of its own: in a command shown one step
/// at a time the message heads that step, and is kept nowhere.
pub fn retry_next(text: impl Display) {
    let lines = retry_lines(text);
    if !flow::show_at_next_step(&lines) {
        write_lines(&lines);
    }
}

fn retry_lines(text: impl Display) -> Vec<String> {
    // Two columns go to the mark and its space.
    wrap(&text.to_string(), TEXT_WIDTH - 2)
        .iter()
        .map(|line| format!("{} {line}", paint(WARNING, "!")))
        .collect()
}

/// An error message after a red "✗ Error:".
pub fn error(text: &str) {
    eprintln!("{} {text}", paint(BAD, "✗ Error:"));
}

/// An error or a failed check: a red headline after "✗", then `body` wrapped, every line
/// marked in red. It is shown at once and kept for the summary too.
pub fn alarm(headline: &str, body: &str) {
    let lines = marked(BAD, "✗", headline, body);
    write_lines(&lines);
    flow::keep_shown(Kind::Notice, &lines);
}

/// The lines of a warning or alarm: `headline` after `mark`, then `body`, both wrapped and every
/// line marked in `style`.
fn marked(style: Style, mark: &str, headline: &str, body: &str) -> Vec<String> {
    // Two columns go to the mark and its space.
    let mut lines: Vec<String> = wrap(headline, TEXT_WIDTH - 2)
        .iter()
        .map(|line| format!("{} {}", paint(style, mark), paint(style, line)))
        .collect();
    for line in wrap(body, TEXT_WIDTH - 2) {
        lines.push(format!("{} {line}", paint(style, "!")));
    }
    lines
}

fn write_lines(lines: &[String]) {
    for line in lines {
        eprintln!("{line}");
    }
}

/// Longest line of running text, so that messages read well in an 80-column terminal.
const TEXT_WIDTH: usize = 78;

/// Breaks `text` into lines of at most `width` visible characters at spaces; a line break in
/// `text` is kept. Colour codes do not count towards the width.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut line_width = 0;
        for word in paragraph.split(' ').filter(|word| !word.is_empty()) {
            let word_width = visible_width(word);
            if line_width > 0 && line_width + 1 + word_width > width {
                lines.push(std::mem::take(&mut line));
                line_width = 0;
            }
            if line_width > 0 {
                line.push(' ');
                line_width += 1;
            }
            line.push_str(word);
            line_width += word_width;
        }
        lines.push(line);
    }
    if text.is_empty() {
        lines.clear();
    }
    lines
}

/// Characters a terminal shows for `text`, without colour codes such as "\u{1b}[1m".
fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut in_code = false;
    for character in text.chars() {
        match character {
            '\u{1b}' => in_code = true,
            'm' if in_code => in_code = false,
            _ if in_code => {}
            _ => width += 1,
        }
    }
    width
}

/// Writes a question: its words in bold, a closing note such as "(hidden):" or "[1]:" in grey.
pub fn prompt(text: &str) {
    let (question, note) = text.split_at(note_start(text));
    eprint!("{}{}", paint(STRONG, question), paint(MUTED, note));
}

/// Where the grey note of a question begins: at " (" or " [", or at the end.
fn note_start(text: &str) -> usize {
    [" (", " ["]
        .iter()
        .filter_map(|opening| text.find(opening))
        .min()
        .unwrap_or(text.len())
}

/// Words per row when a phrase is shown for writing down.
const WORDS_PER_ROW: usize = 4;
/// One cell: a number right-aligned in three places, ". ", and a word of up to eight letters,
/// the longest in the English BIP39 list.
const CELL_WIDTH: usize = 3 + 2 + 8;
/// Spaces between two cells of a row.
const CELL_GAP: usize = 3;
/// Characters inside the frame: four cells, three gaps and one space on either side.
const INNER_WIDTH: usize = WORDS_PER_ROW * CELL_WIDTH + (WORDS_PER_ROW - 1) * CELL_GAP + 2;

/// A phrase in a frame, numbered, four words to a row, the numbers grey and the words bold.
/// The lines are wiped when dropped, because the words may be secret.
pub fn boxed_words(phrase: &str) -> Vec<Zeroizing<String>> {
    let border = "─".repeat(INNER_WIDTH);
    let mut lines = vec![Zeroizing::new(paint(MUTED, format!("┌{border}┐")))];
    let words: Vec<&str> = phrase.split(' ').collect();
    for (row, chunk) in words.chunks(WORDS_PER_ROW).enumerate() {
        // Reserved generously so that writing never reallocates and leaves a copy behind.
        let mut line = Zeroizing::new(String::with_capacity(512));
        let mut visible = 1;
        line.push_str(&paint(MUTED, "│"));
        line.push(' ');
        for (column, word) in chunk.iter().enumerate() {
            if column > 0 {
                line.push_str(&" ".repeat(CELL_GAP));
                visible += CELL_GAP;
            }
            let number = row * WORDS_PER_ROW + column + 1;
            // Writing into a String cannot fail.
            let _ = write!(
                line,
                "{MUTED}{number:>3}.{MUTED:#} {STRONG}{word:<8}{STRONG:#}"
            );
            visible += CELL_WIDTH;
        }
        line.push_str(&" ".repeat(INNER_WIDTH - visible));
        line.push_str(&paint(MUTED, "│"));
        lines.push(line);
    }
    lines.push(Zeroizing::new(paint(MUTED, format!("└{border}┘"))));
    lines
}

/// Cells of a progress bar: two for each of the 12 rounds of a stage.
pub const BAR_CELLS: u32 = 24;

/// "████████░░░░" with `done` of `total` rounds filled.
pub fn bar(done: u32, total: u32) -> String {
    let filled = (done * BAR_CELLS / total.max(1)).min(BAR_CELLS) as usize;
    let empty = BAR_CELLS as usize - filled;
    format!(
        "{}{}",
        paint(ACCENT, "█".repeat(filled)),
        paint(MUTED, "░".repeat(empty))
    )
}

/// A section at the end of a help text: a heading and rows of a command or answer with its
/// explanation, the first column in the accent colour, the second wrapped within the help width.
/// When one first column is longer than [`HELP_COLUMN_LIMIT`], such as a full example command,
/// every row is stacked instead: the command on its own line, its explanation indented below it,
/// and a blank line between rows.
pub fn help_section(heading: &str, rows: &[(&str, &str)]) -> String {
    let mut text = format!("{}\n", paint(HEADING, heading));
    if rows.iter().any(|(left, _)| left.len() > HELP_COLUMN_LIMIT) {
        for (index, (left, right)) in rows.iter().enumerate() {
            if index > 0 {
                text.push('\n');
            }
            text.push_str(&format!("  {}\n", paint(ACCENT, left)));
            let indent = " ".repeat(HELP_STACKED_INDENT);
            for line in wrap(right, HELP_WIDTH - HELP_STACKED_INDENT) {
                text.push_str(&format!("{indent}{line}\n"));
            }
        }
        return text;
    }
    let width = rows.iter().map(|(left, _)| left.len()).max().unwrap_or(0);
    // Two spaces of indent and two between the columns.
    let right_width = HELP_WIDTH.saturating_sub(width + 4).max(20);
    for (left, right) in rows {
        for (index, line) in wrap(right, right_width).iter().enumerate() {
            let left = if index == 0 { *left } else { "" };
            let left = paint(ACCENT, format!("{left:<width$}"));
            text.push_str(&format!("  {left}  {line}\n"));
        }
    }
    text
}

/// Widest first column of a help section that still leaves the explanation 44 columns.
const HELP_COLUMN_LIMIT: usize = 32;
/// Indent of the explanation below a command in a stacked section.
const HELP_STACKED_INDENT: usize = 6;

/// Width of the help texts: they read well in an 80-column terminal and stay the same in a
/// wider one.
pub const HELP_WIDTH: usize = 80;

/// Indent at which clap prints the explanation of an option in `--help`.
const OPTION_HELP_INDENT: usize = 10;

/// The explanation of an option in `--help`: paragraphs broken into lines by hand, because clap
/// is built without its optional wrapping feature. clap indents every line itself.
pub fn option_help(paragraphs: &[&str]) -> String {
    help_paragraphs(paragraphs, HELP_WIDTH - OPTION_HELP_INDENT)
}

/// What a command does, for the top of its `--help`: the one-line summary, then paragraphs.
pub fn command_about(paragraphs: &[&str]) -> String {
    help_paragraphs(paragraphs, HELP_WIDTH)
}

fn help_paragraphs(paragraphs: &[&str], width: usize) -> String {
    paragraphs
        .iter()
        .map(|paragraph| wrap(paragraph, width).join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// A closing paragraph of a help text, in grey, wrapped to the help width.
pub fn help_note(text: &str) -> String {
    wrap(text, HELP_WIDTH)
        .iter()
        .map(|line| format!("{}\n", paint(MUTED, line)))
        .collect()
}

/// The colours of `mhfe --help`, matching the rest of the tool.
pub fn help_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(HEADING)
        .usage(HEADING)
        .literal(ACCENT)
        .placeholder(MUTED)
        .valid(GOOD)
        .invalid(BAD)
        .error(BAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of a line without its colour codes.
    fn plain(line: &str) -> String {
        let mut text = String::new();
        let mut in_code = false;
        for character in line.chars() {
            match character {
                '\u{1b}' => in_code = true,
                'm' if in_code => in_code = false,
                _ if in_code => {}
                _ => text.push(character),
            }
        }
        text
    }

    #[test]
    fn every_line_of_the_frame_has_the_same_width() {
        let phrase = "abandon ability able about above absent absorb abstract absurd abuse access \
                      accident";
        let lines = boxed_words(phrase);
        assert_eq!(lines.len(), 5);
        let widths: Vec<usize> = lines
            .iter()
            .map(|line| plain(line).chars().count())
            .collect();
        assert!(
            widths.iter().all(|width| *width == INNER_WIDTH + 2),
            "{widths:?}"
        );
        assert_eq!(
            plain(&lines[1]),
            "│   1. abandon      2. ability      3. able         4. about    │"
        );
    }

    #[test]
    fn the_bar_fills_in_proportion() {
        assert_eq!(plain(&bar(0, 24)), "░".repeat(24));
        assert_eq!(
            plain(&bar(6, 12)),
            format!("{}{}", "█".repeat(12), "░".repeat(12))
        );
        assert_eq!(plain(&bar(24, 24)), "█".repeat(24));
    }

    #[test]
    fn text_wraps_at_spaces_and_ignores_colour_codes() {
        let text = format!("one two {} four five", paint(BAD, "three"));
        assert_eq!(
            wrap(&text, 13)
                .iter()
                .map(|line| plain(line))
                .collect::<Vec<_>>(),
            ["one two three", "four five"]
        );
        assert_eq!(wrap("a\nb", 10), ["a", "b"]);
        assert!(wrap("", 10).is_empty());
    }

    #[test]
    fn a_long_example_stacks_the_whole_section() {
        let long = "mhfe check --address --path \"m/84'/0'/0'/0/5\"";
        let text = help_section("Examples:", &[("mhfe check", "Short"), (long, "Long")]);
        let lines: Vec<String> = text.lines().map(plain).collect();
        assert_eq!(
            lines,
            [
                "Examples:".to_string(),
                "  mhfe check".to_string(),
                "      Short".to_string(),
                String::new(),
                format!("  {long}"),
                "      Long".to_string(),
            ]
        );
        let short = help_section("Examples:", &[("mhfe check", "Short")]);
        assert_eq!(plain(short.lines().nth(1).unwrap()), "  mhfe check  Short");
    }

    #[test]
    fn a_prompt_note_is_split_off() {
        assert_eq!(note_start("Password (hidden): "), 8);
        assert_eq!(note_start("Choice [1]: "), 6);
        assert_eq!(note_start("Choice: "), 8);
    }
}
