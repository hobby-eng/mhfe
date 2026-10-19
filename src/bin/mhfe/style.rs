//! Colours and layout of everything the tool shows.
//!
//! Text is written through `anstream`, which drops the colour codes when the output is not a
//! terminal, when `NO_COLOR` is set, or when the terminal cannot show colours, and enables them
//! in the Windows console. Only the standard sixteen terminal colours are used, so every colour
//! scheme shows them. Results for scripts never carry colour.
//! TERM=dumb always disables colour, except an explicit nonempty CLICOLOR_FORCE without NO_COLOR.

use std::fmt::{Display, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anstyle::{AnsiColor, Style};
use zeroize::Zeroizing;

use crate::exit::{capitalize, Failure};
use crate::flow::{self, Kind};
use crate::hidden_input;

/// Apply CORE-38 before clap renders help or usage; CI and CLICOLOR cannot override TERM=dumb.
pub(crate) fn configure_colours() {
    if plain_dumb_terminal(
        std::env::var("TERM").ok().as_deref(),
        std::env::var("NO_COLOR").ok().as_deref(),
        std::env::var("CLICOLOR_FORCE").ok().as_deref(),
    ) {
        anstream::ColorChoice::Never.write_global();
    }
}

/// NO_COLOR takes precedence, then explicit forced colour, then a dumb terminal's limitation.
fn plain_dumb_terminal(term: Option<&str>, no_colour: Option<&str>, forced: Option<&str>) -> bool {
    no_colour.is_some_and(|value| !value.is_empty())
        || (term == Some("dumb") && !forced.is_some_and(|value| !value.is_empty()))
}

/// Writes `line` and a line break to standard output, the result of a command, and flushes it. An
/// error, a closed pipe or a full disk included, is the failure "Input or output failed" (exit 1),
/// never a panic, so that a result that did not arrive is not reported as success
/// (AUD-023-FUN001). Every result goes through here; messages go to standard error.
pub(crate) fn out(line: impl Display) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut stdout = anstream::stdout().lock();
    writeln!(stdout, "{line}")?;
    stdout.flush()?;
    Ok(())
}

/// Titles, section headings and the words `mhfe` and its commands.
pub(crate) const HEADING: Style = AnsiColor::Cyan.on_default().bold();
/// Command names and the progress bar.
pub(crate) const ACCENT: Style = AnsiColor::Cyan.on_default();
/// Questions and the words of a phrase.
pub(crate) const STRONG: Style = Style::new().bold();
/// Labels, numbers, hints and anything secondary. Bright black is the grey of most schemes;
/// "dim" text is too faint in some terminals.
pub(crate) const MUTED: Style = AnsiColor::BrightBlack.on_default();
pub(crate) const GOOD: Style = AnsiColor::Green.on_default().bold();
pub(crate) const WARNING: Style = AnsiColor::Yellow.on_default().bold();
/// Every help screen's final safety line, shared with the Python launcher by its parity test.
pub(crate) const SAFETY_LINE: &str =
    "Experimental: not independently reviewed; do not use it to protect real funds.";

/// End every command's short and long help with the shared note and yellow safety line.
pub(crate) fn help_ending(text: impl Display) -> String {
    format!(
        "{text}\n{}\n{}",
        help_note("Use MHFE on a trusted computer without a network connection."),
        paint(WARNING, SAFETY_LINE)
    )
}
pub(crate) const BAD: Style = AnsiColor::Red.on_default().bold();

/// Items of running text as English lists them: "a", "a and b", "a, b and c".
pub(crate) fn and_list<T: AsRef<str>>(items: &[T]) -> String {
    list(items, "and")
}

/// Choices of running text as English lists them: "a", "a or b", "a, b or c".
pub(crate) fn or_list<T: AsRef<str>>(items: &[T]) -> String {
    list(items, "or")
}

fn list<T: AsRef<str>>(items: &[T], conjunction: &str) -> String {
    match items {
        [] => String::new(),
        [only] => only.as_ref().to_owned(),
        [rest @ .., last] => {
            let rest: Vec<&str> = rest.iter().map(AsRef::as_ref).collect();
            format!("{} {conjunction} {}", rest.join(", "), last.as_ref())
        }
    }
}

/// `text` in `style`. For public text only: the result is an ordinary string, which is not
/// wiped. Secret words are painted by [`boxed_words`].
pub(crate) fn paint(style: Style, text: impl Display) -> String {
    format!("{style}{text}{style:#}")
}

/// The first lines of a command: its name and what it does. A command shown one step at a time
/// heads every step and its summary itself (flow.rs).
pub(crate) fn title(what: &str) -> usize {
    if flow::is_active() {
        return 0;
    }
    write_title(what)
}

/// Writes the title line at once, after a blank line; returns the rows they took.
pub(crate) fn write_title(what: &str) -> usize {
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
pub(crate) fn rows(line: &str) -> usize {
    rows_of_cells(visible_width(line), hidden_input::columns_or_default())
}

/// The rows that `cells` cells take on a terminal `columns` wide, written on a line of their own:
/// one at least, and a line that fills its last row exactly takes no more. The one row rule of
/// every redraw (AUD-023-ARC014).
pub(crate) fn rows_of_cells(cells: usize, columns: usize) -> usize {
    cells.div_ceil(columns.max(1)).max(1)
}

/// One line of a summary table: a grey label and its value.
pub(crate) fn fact(label: &str, value: impl Display) {
    fact_as(Kind::Fact, label, value);
}

/// A line of a summary table of `kind`: in a command shown one step at a time it waits for the
/// summary at the end.
pub(crate) fn fact_as(kind: Kind, label: &str, value: impl Display) {
    // Wrapped under its column, so that a long value never passes the text width (AUD-023-UI007).
    let lines = fact_lines(label, &value.to_string());
    if !flow::keep(kind, &lines) {
        write_lines(&lines);
    }
}

/// [`fact`] that is shown at the top of the next step too, so that it is read before the work it
/// describes starts.
pub(crate) fn fact_before_work(label: &str, value: impl Display) {
    let lines = fact_lines(label, &value.to_string());
    if !flow::keep_next(Kind::Fact, &lines) {
        write_lines(&lines);
    }
}

fn fact_line(label: &str, value: impl Display) -> String {
    format!(
        "  {} {value}",
        paint(MUTED, format!("{label:<FACT_LABEL_WIDTH$}"))
    )
}

/// The width a fact's label is padded to; its value starts one column after it.
const FACT_LABEL_WIDTH: usize = 10;

/// The lines of [`fact`]: the first beside the label, the others under the value.
pub(crate) fn fact_lines(label: &str, value: &str) -> Vec<String> {
    // Two columns of indent, the label and the one space after it.
    let value_column = 2 + FACT_LABEL_WIDTH + 1;
    wrap(value, TEXT_WIDTH - value_column)
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                fact_line(label, line)
            } else {
                format!("{}{line}", " ".repeat(value_column))
            }
        })
        .collect()
}

/// Something that went right, after a green tick. It is shown at once, on the step it belongs to,
/// and kept for the summary too.
pub(crate) fn ok(text: impl Display) {
    let lines = ok_lines(&text.to_string());
    write_lines(&lines);
    flow::keep_shown(Kind::Result, &lines);
}

/// The lines of [`ok`]: wrapped to the text width, the tick on the first and the others indented
/// under its text (AUD-023-UI007).
fn ok_lines(text: &str) -> Vec<String> {
    wrap(text, TEXT_WIDTH - 2)
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("{} {line}", paint(GOOD, TICK))
            } else {
                format!("  {line}")
            }
        })
        .collect()
}

/// The green tick of something that went right or that a choice gives.
pub(crate) const TICK: &str = "✓";

/// The note beside openly shown master key fingerprints (DOC-05).
pub(crate) const FINGERPRINT_NOTE: &str = "They do not reveal the phrase.";

/// Keeps the note beside a fingerprint recorded in the summary's facts.
pub(crate) fn fingerprint_fact() {
    fact("Fingerprints", FINGERPRINT_NOTE);
}

/// A line of what a choice gives, indented under its name: a green tick, then `text`.
pub(crate) fn gives(text: &str) {
    write_lines(&choice_lines(GOOD, TICK, text));
}

/// A line of what a choice costs, indented under its name: a yellow "!", then `text`.
pub(crate) fn costs(text: &str) {
    write_lines(&choice_lines(WARNING, "!", text));
}

/// Choice facts keep their indent and colour only their mark, wrapping under the text.
fn choice_lines(style: Style, mark: &str, text: &str) -> Vec<String> {
    wrap(text, TEXT_WIDTH - 4)
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("  {} {line}", paint(style, mark))
            } else {
                format!("    {line}")
            }
        })
        .collect()
}

/// Advice that can be read and passed over, in grey, wrapped to the text width. Returns the lines
/// it took, for a step that erases itself once answered (terminal::Step).
pub(crate) fn hint(text: &str) -> usize {
    let lines = wrap(text, TEXT_WIDTH);
    for line in &lines {
        eprintln!("{}", paint(MUTED, line));
    }
    lines.iter().map(|line| rows(line)).sum()
}

/// A grey line that links to the README section explaining what a screen only names; returns
/// the lines it took on the screen. In a command shown one step at a time it goes with the
/// summary line or warning before it.
pub(crate) fn more(place: &str) -> usize {
    let line = more_line(place);
    if !flow::keep_link(line.clone()) {
        return 0;
    }
    eprintln!("{line}");
    1
}

/// A link line, also used by choice lists that retain only its visible width for redraws.
pub(crate) fn more_line(place: &str) -> String {
    format!("  {}", paint(MUTED, format!("More: {place}")))
}

/// A warning: a yellow headline after "!", then `body` wrapped, every line marked with "!". In a
/// command shown one step at a time it is kept for the summary and shown at the top of the next
/// step, so that it is read before the person goes on.
pub(crate) fn warn(headline: &str, body: &str) {
    let lines = marked(WARNING, "!", headline, body);
    if !flow::keep_notice(&lines) {
        write_lines(&lines);
    }
}

/// A warning about the screen it is on, such as the wait to clear it, never kept for a summary.
pub(crate) fn warn_here(headline: &str, body: &str) {
    write_lines(&marked(WARNING, "!", headline, body));
}

/// A warning shown at once, next to what it is about, and kept for the summary too, such as the
/// status of a recovered phrase.
pub(crate) fn warn_now(headline: &str, body: &str) {
    let lines = marked(WARNING, "!", headline, body);
    write_lines(&lines);
    flow::keep_shown(Kind::Notice, &lines);
}

/// A mistake in an answer that can be typed again: the message wrapped, every line after a yellow
/// "!". Returns the lines it took, as `hint` does.
pub(crate) fn retry(text: impl Display) -> usize {
    let lines = retry_lines(text);
    write_lines(&lines);
    lines.iter().map(|line| rows(line)).sum()
}

/// [`retry`] for an answer that is asked again on a step of its own: in a command shown one step
/// at a time the message heads that step, and is kept nowhere.
pub(crate) fn retry_next(text: impl Display) {
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

const ERROR_MARK: &str = "✗ Error:";

/// An error message after a red "✗ Error:", wrapped to the text width, every further line indented
/// under the first, so that a long message, such as a check at start that failed, reads well in
/// an 80-column terminal.
pub(crate) fn error_wrapped(text: &str) {
    write_lines(&error_lines(text));
}

/// A usage error of the command line, from the plain text clap writes for it ("error: ...", the
/// arguments it lists below that, a tip, the usage, a pointer to --help), shown as mhfe shows an
/// error: the message, with the listed arguments joined into it, after one red "✗ Error:", then
/// every other line of clap's in grey.
pub(crate) fn usage_error(clap_text: &str) {
    write_lines(&usage_error_lines(clap_text));
}

fn usage_error_lines(clap_text: &str) -> Vec<String> {
    // clap repeats a mistyped argument as it was given, which may hold control characters: they
    // are escaped on every line, as every other message escapes them (AUD-018).
    let clap_text: Vec<String> = clap_text.split('\n').map(escaped).collect();
    let clap_text = clap_text.join("\n");
    let mut blocks = clap_text.trim().split("\n\n");
    let mut message = blocks.next().unwrap_or_default().lines();
    let first = message.next().unwrap_or_default();
    let first = first.strip_prefix("error: ").unwrap_or(first);
    // Such as the required arguments that were not given, one per indented line.
    let listed: Vec<&str> = message
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let text = if listed.is_empty() {
        first.to_owned()
    } else {
        format!("{first} {}", listed.join(", "))
    };
    let mut lines = error_lines(&capitalize(&text));
    for line in blocks.flat_map(str::lines).map(str::trim) {
        if !line.is_empty() {
            lines.extend(
                wrap(&capitalize(line), TEXT_WIDTH)
                    .into_iter()
                    .map(|line| paint(MUTED, line)),
            );
        }
    }
    lines
}

/// [`error_lines`] for the tests of other modules, which check how a message is shown.
#[cfg(test)]
pub(crate) fn error_lines_for_test(text: &str) -> Vec<String> {
    error_lines(text)
}

fn error_lines(text: &str) -> Vec<String> {
    // The mark and its space.
    let indent = ERROR_MARK.chars().count() + 1;
    wrap(text, TEXT_WIDTH - indent)
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("{} {line}", paint(BAD, ERROR_MARK))
            } else {
                format!("{}{line}", " ".repeat(indent))
            }
        })
        .collect()
}

/// A row of a report table, such as one part of `mhfe self-test`: the grey label padded to
/// `label_width`, then `value` in `style`, wrapped to the text width under its own column.
pub(crate) fn report_row(
    label: &str,
    label_width: usize,
    style: Style,
    value: &str,
) -> Vec<String> {
    // Two columns of indent and two between label and value; the value keeps at least
    // REPORT_VALUE_MIN columns, also beside a label that is too long for the table.
    let value_column = 2 + label_width + 2;
    let value_width = TEXT_WIDTH
        .saturating_sub(value_column)
        .max(REPORT_VALUE_MIN);
    wrap(value, value_width)
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let lead = if index == 0 {
                format!("  {}  ", paint(MUTED, format!("{label:<label_width$}")))
            } else {
                " ".repeat(value_column)
            };
            format!("{lead}{}", paint(style, line))
        })
        .collect()
}

/// The narrowest value column of a report table.
const REPORT_VALUE_MIN: usize = 24;

/// An error or a failed check: a red headline after "✗", then `body` wrapped, every line
/// marked in red. It is shown at once and kept for the summary too.
pub(crate) fn alarm(headline: &str, body: &str) {
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

/// Whether a message could not be written to standard error.
static MESSAGE_FAILED: AtomicBool = AtomicBool::new(false);

/// Writes a message to standard error, with colours as the terminal takes them, as anstream's
/// `eprint!` does, but without its panic on a failed write: a failure other than a closed pipe is
/// remembered for the exit code ([`message_failed`], AUD-024-FUN009). A test writes where the test
/// harness collects its output.
pub(crate) fn write_message(arguments: std::fmt::Arguments<'_>) {
    if cfg!(test) {
        std::eprint!("{arguments}");
        return;
    }
    let mut stream = anstream::stderr();
    if let Err(error) = std::io::Write::write_fmt(&mut stream, arguments) {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            MESSAGE_FAILED.store(true, Ordering::Relaxed);
        }
    }
}

/// Whether a message could not be written to standard error, as on a full disk.
pub(crate) fn message_failed() -> bool {
    MESSAGE_FAILED.load(Ordering::Relaxed)
}

fn write_lines(lines: &[String]) {
    for line in lines {
        eprintln!("{line}");
    }
}

/// Longest line of running text, so that messages read well in an 80-column terminal, and of a
/// list, which redraws itself by moving the cursor up line by line, as a line the terminal wrapped
/// would upset.
pub(crate) const TEXT_WIDTH: usize = 78;

/// Breaks `text` into lines of at most `width` visible characters at spaces; a line break in
/// `text` is kept. Colour codes do not count towards the width.
// Deliberate copy in the standalone Python launcher: shared ASCII/ANSI display cases
// are compared by its parity tests; Python documents its Unicode width approximation.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
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
// Deliberate copy in the standalone Python launcher: shared ASCII/ANSI display cases
// are compared by its parity tests; Python documents its Unicode width approximation.
pub(crate) fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut in_code = false;
    for character in text.chars() {
        match character {
            '\u{1b}' => in_code = true,
            'm' if in_code => in_code = false,
            _ if in_code => {}
            // Cells, as the terminal shows them: a wide character takes two.
            _ => width += crate::typed_line::char_cells(character),
        }
    }
    width
}

/// Writes a question: its words in bold, a closing note such as "(hidden):" or "[1]:" in grey.
pub(crate) fn prompt(text: &str) {
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
pub(crate) const WORDS_PER_ROW: usize = 4;
/// One cell: a number right-aligned in three places, ". ", and a word of up to eight letters,
/// the longest in the English BIP39 list.
const CELL_WIDTH: usize = 3 + 2 + 8;
/// Spaces between two cells of a row.
const CELL_GAP: usize = 3;
/// Characters inside the frame: four cells, three gaps and one space on either side.
const INNER_WIDTH: usize = WORDS_PER_ROW * CELL_WIDTH + (WORDS_PER_ROW - 1) * CELL_GAP + 2;
/// A complete four-word row with BIP39 words, numbering, borders and ANSI style escapes fits here.
pub(crate) const WORD_ROW_BYTES: usize = 512;

/// A phrase in a frame, numbered, four words to a row, the numbers grey and the words bold.
///
/// The lines are wiped when dropped, because the words may be secret.
pub(crate) fn boxed_words(phrase: &str) -> Vec<Zeroizing<String>> {
    let border = "─".repeat(INNER_WIDTH);
    let word_count = phrase.split(' ').count();
    let mut lines = Vec::with_capacity(word_count.div_ceil(WORDS_PER_ROW) + 2);
    lines.push(Zeroizing::new(paint(MUTED, format!("┌{border}┐"))));
    let mut words = phrase.split(' ').peekable();
    let mut shown = 0;
    while words.peek().is_some() {
        // Reserved generously so that writing never reallocates and leaves a copy behind.
        let mut line = Zeroizing::new(String::with_capacity(WORD_ROW_BYTES));
        let mut visible = 1;
        line.push_str(&paint(MUTED, "│"));
        line.push(' ');
        for (column, word) in words.by_ref().take(WORDS_PER_ROW).enumerate() {
            if column > 0 {
                line.push_str(&" ".repeat(CELL_GAP));
                visible += CELL_GAP;
            }
            shown += 1;
            let number = shown;
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
pub(crate) const BAR_CELLS: u32 = 24;

/// "████████░░░░" with `done` of `total` rounds filled.
pub(crate) fn bar(done: u32, total: u32) -> String {
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
pub(crate) fn help_section(heading: &str, rows: &[(&str, &str)]) -> String {
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
pub(crate) const HELP_WIDTH: usize = hidden_input::DEFAULT_COLUMNS;

/// Indent at which clap prints the explanation of an option in `--help`.
const OPTION_HELP_INDENT: usize = 10;

/// The explanation of an option in `--help`: paragraphs broken into lines by hand, because clap
/// is built without its optional wrapping feature. clap indents every line itself.
pub(crate) fn option_help(paragraphs: &[&str]) -> String {
    help_paragraphs(paragraphs, HELP_WIDTH - OPTION_HELP_INDENT)
}

/// A count as a word, as in "Five dice words": the words up to twenty, digits above, so that a
/// label follows its constant (AUD-023-ARC007). `capital` starts it with a capital.
pub(crate) fn number_word(count: usize, capital: bool) -> String {
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    match WORDS.get(count) {
        Some(word) if capital => capitalize(word),
        Some(word) => (*word).to_owned(),
        None => count.to_string(),
    }
}

/// The short help of every `--stdin` that reads the answers of a command.
pub(crate) const STDIN_HELP: &str = "Read the answers from standard input";

/// The long help of such a `--stdin`: [`STDIN_HELP`], with `condition` after it where the option
/// needs another, then `paragraphs`.
pub(crate) fn stdin_help(condition: Option<&str>, paragraphs: &[&str]) -> String {
    let first = match condition {
        Some(condition) => format!("{STDIN_HELP}; {condition}."),
        None => format!("{STDIN_HELP}."),
    };
    option_help(&[&[first.as_str()], paragraphs].concat())
}

/// What a command does, for the top of its `--help`: the one-line summary, then paragraphs.
pub(crate) fn command_about(paragraphs: &[&str]) -> String {
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
pub(crate) fn help_note(text: &str) -> String {
    wrap(text, HELP_WIDTH)
        .iter()
        .map(|line| format!("{}\n", paint(MUTED, line)))
        .collect()
}

/// The end of a command's help: its examples, then a grey note.
pub(crate) fn examples_with_note(rows: &[(&str, &str)], note: &str) -> String {
    let examples = help_section("Examples:", rows);
    format!("{examples}\n{}", help_note(note))
}

/// The colours of `mhfe --help`, matching the rest of the tool.
pub(crate) fn help_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(HEADING)
        .usage(HEADING)
        .literal(ACCENT)
        .placeholder(MUTED)
        .valid(GOOD)
        .invalid(BAD)
        .error(BAD)
}

/// A path as a message shows it, every control character escaped, such as `\u{1b}`, so that a
/// terminal shows a folder or file name instead of carrying it out (AUD-015-SEC002): a name may
/// hold any character but `/`.
pub(crate) fn shown_path(path: &Path) -> String {
    escaped(&path.to_string_lossy())
}

/// `text` with every control character escaped, as [`shown_path`] shows a path.
// Deliberate copy in the standalone Python launcher: shared ASCII/ANSI display cases
// are compared by its parity tests; Python documents its Unicode width approximation.
pub(crate) fn escaped(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                character.escape_unicode().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}

/// The text of a line without its colour codes, as the tests read what the tool wrote.
#[cfg(test)]
pub(crate) fn plain(line: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumb_terminals_stay_plain_unless_colour_is_explicitly_forced() {
        for forced in [None, Some("")] {
            assert!(plain_dumb_terminal(Some("dumb"), None, forced));
        }
        assert!(!plain_dumb_terminal(Some("dumb"), None, Some("1")));
        assert!(!plain_dumb_terminal(Some("dumb"), None, Some("0")));
        assert!(plain_dumb_terminal(Some("dumb"), Some("1"), Some("1")));
        assert!(!plain_dumb_terminal(Some("xterm"), None, None));
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

    /// A long error is one "✗ Error:" line, wrapped within the text width under its first line.
    #[test]
    fn a_long_error_wraps_under_its_mark() {
        let text =
            "Self-test at start failed: Password check word (MHFE-PASSWORD-CHECK-1): the EFF \
                    list differs from the vendored file. Do not use this program on this computer.";
        let lines: Vec<String> = error_lines(text).iter().map(|line| plain(line)).collect();
        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("✗ Error: Self-test at start failed:"));
        assert_eq!(lines.iter().filter(|line| line.contains("✗")).count(), 1);
        for line in &lines {
            assert!(line.chars().count() <= TEXT_WIDTH, "{line}");
        }
        for line in &lines[1..] {
            assert!(line.starts_with("         ") && !line.starts_with("          "));
        }
        assert_eq!(
            lines
                .join(" ")
                .split_whitespace()
                .skip(2)
                .collect::<Vec<_>>()
                .join(" "),
            text
        );
        assert_eq!(
            error_lines("Short."),
            [format!("{} Short.", paint(BAD, ERROR_MARK))]
        );
    }

    /// A usage error from clap reads as every other error: one "✗ Error:" line with the listed
    /// arguments joined into it, then clap's tip, usage and pointer to --help in grey (AUD-010).
    #[test]
    fn a_usage_error_reads_as_an_error_of_the_tool() {
        let unknown = "error: unexpected argument '--stdn' found\n\n  tip: a similar argument \
                       exists: '--stdin'\n\nUsage: mhfe encrypt --stdin\n\nFor more \
                       information, try '--help'.\n";
        let lines = usage_error_lines(unknown);
        assert_eq!(
            lines,
            [
                format!(
                    "{} Unexpected argument '--stdn' found",
                    paint(BAD, ERROR_MARK)
                ),
                paint(MUTED, "Tip: a similar argument exists: '--stdin'"),
                paint(MUTED, "Usage: mhfe encrypt --stdin"),
                paint(MUTED, "For more information, try '--help'."),
            ]
        );
        let missing = "error: the following required arguments were not provided:\n  <FILE>\n\n\
                       Usage: mhfe serve <FILE>\n\nFor more information, try '--help'.\n";
        assert_eq!(
            plain(&usage_error_lines(missing)[0]),
            "✗ Error: The following required arguments were not provided: <FILE>"
        );
        for line in usage_error_lines(missing) {
            assert!(visible_width(&line) <= TEXT_WIDTH, "{line}");
        }
        // A mistyped argument with control characters, C1 and a carriage return among them, is
        // shown escaped: nothing in the message is carried out by the terminal (AUD-018).
        let typed = "error: unexpected argument '--x\u{1b}]52;c;QUFB\u{7}\u{9b}2J\r' found\n";
        let lines = usage_error_lines(typed);
        assert!(plain(&lines[0]).contains("--x\\u{1b}]52;c;QUFB\\u{7}\\u{9b}2J\\u{d}"));
        for line in &lines {
            assert!(!plain(line).chars().any(char::is_control), "{line:?}");
        }
    }

    #[test]
    fn a_report_row_wraps_its_value_under_its_column() {
        let rows = report_row(
            "Label",
            8,
            GOOD,
            "one two three four five six seven eight nine",
        );
        let lines: Vec<String> = rows.iter().map(|line| plain(line)).collect();
        assert_eq!(lines[0].find("one"), Some(12));
        assert!(lines.iter().all(|line| line.chars().count() <= TEXT_WIDTH));
        let short = report_row("Core dumps", 12, GOOD, "off");
        assert_eq!(plain(&short[0]), "  Core dumps    off");
        assert_eq!(short.len(), 1);
        // A wrapped value continues in the value column.
        let long = report_row("Label", 50, BAD, &"word ".repeat(10));
        assert!(long.len() > 1);
        assert_eq!(plain(&long[1]).find("word"), Some(54));
    }

    #[test]
    fn a_prompt_note_is_split_off() {
        assert_eq!(note_start("Password (hidden): "), 8);
        assert_eq!(note_start("Choice [1]: "), 6);
        assert_eq!(note_start("Choice: "), 8);
    }

    /// A result and a record with a long text, such as the repair summary of eight repair words
    /// and six unreadable words, wrap within the text width (AUD-023-UI007).
    #[test]
    fn long_results_and_records_wrap_to_the_text_width() {
        let summary =
            "Repaired words 10, 12, 14, 16, 18 and 20 of the container phrase and words 1, \
                       3, 5 and 7 of the card.";
        let lines = ok_lines(summary);
        assert!(lines.len() > 1);
        let records = fact_lines("Repaired", &paint(ACCENT, summary));
        for line in lines.iter().chain(&records) {
            assert!(visible_width(line) <= TEXT_WIDTH, "{line}");
        }
    }

    /// One row rule for every redraw: an exact fill takes its rows and no more, a wrap one more,
    /// an empty line one, and a wide character two cells (AUD-023-ARC014).
    #[test]
    fn rows_count_cells_as_the_terminal_does() {
        assert_eq!(rows_of_cells(80, 80), 1);
        assert_eq!(rows_of_cells(81, 80), 2);
        assert_eq!(rows_of_cells(0, 80), 1);
        assert_eq!(rows_of_cells(5, 0), 5);
        assert_eq!(visible_width("界界"), 4);
        assert_eq!(visible_width(&paint(GOOD, "ok")), 2);
        assert_eq!(rows_of_cells(visible_width(&"界".repeat(40)), 79), 2);
    }
}
