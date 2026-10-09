//! What the person sees of a line while typing it on a screen that carries out control sequences:
//! the characters as typed, except control characters, and below them a hint for the word being
//! typed (mhfe::word_hints): from two letters the words of the list that begin with them, after one
//! letter how many there are. The cursor stays where the next character goes, also on the further
//! rows of a long line, so every change redraws only what follows it.
//!
//! A character takes the cells a terminal gives it: two for a wide East Asian character, none for
//! a combining mark, one otherwise (AUD-016-UI001), as glibc's wcwidth and GLib count them
//! (scripts/generate-cell-widths.py says which terminals may differ). The line begins right after
//! its prompt, which begins a row of its own.

use std::io::{self, Write};

use mhfe::word_hints::{Hint, WordList};

use anstyle::Style;
use zeroize::Zeroizing;

use crate::cell_widths;
use crate::style::{paint, MUTED, WARNING};

/// Rows of words at most below the line; the rest is counted on a row of its own.
const HINT_ROWS: usize = 3;
/// Columns between two words of a hint.
const WORD_GAP: usize = 2;
/// Narrower terminals get no hints, which would not fit beside their indent.
const NARROWEST_FOR_HINTS: usize = 24;
/// The indent of a hint row, as for the hints of a step.
const INDENT: &str = "  ";

/// Where a line is written: its characters and the control sequences as they are, and the text of
/// a hint through `text`, which leaves out the colours where the terminal shows none.
pub struct LineScreen<'a> {
    controls: &'a mut dyn Write,
    text: &'a mut dyn Write,
    /// The columns of the prompt before the line.
    start: usize,
    columns: usize,
    /// The cells the shown characters take so far, a cell skipped before a wide character at the
    /// end of a row included.
    shown: usize,
    /// The cells each shown character moved the cursor, so that a removal goes back as far. Wiped
    /// when dropped: the widths tell something of a password's characters.
    advances: Zeroizing<Vec<u8>>,
    /// Whether the prompt filled its row exactly: a terminal then keeps the cursor at the end of
    /// that row until the next character comes, so the first thing written moves it to the next
    /// row first, where the arithmetic of the columns puts it.
    pending_wrap: bool,
    hints: Option<Hints>,
}

/// The hints a line gets.
#[derive(Clone, Copy)]
pub struct Hints {
    pub list: WordList,
    /// Whether a word that the list does not have is said: in a line of words, not in a password,
    /// which may hold any text.
    pub says_no_word: bool,
}

impl<'a> LineScreen<'a> {
    /// A line after a prompt `start` columns wide, on a terminal `columns` wide. Hints only where
    /// they fit.
    pub fn new(
        controls: &'a mut dyn Write,
        text: &'a mut dyn Write,
        start: usize,
        columns: usize,
        hints: Option<Hints>,
    ) -> Self {
        Self {
            controls,
            text,
            start,
            columns: columns.max(1),
            shown: 0,
            advances: Zeroizing::new(Vec::with_capacity(crate::terminal::LINE_CAPACITY)),
            pending_wrap: start > 0 && start.is_multiple_of(columns.max(1)),
            hints: hints.filter(|_| columns >= NARROWEST_FOR_HINTS),
        }
    }

    /// Moves the cursor to the start of the next row if the prompt filled its row exactly: a space,
    /// which wraps, then a backspace (as after a full row, in [`LineScreen::add`]).
    fn settle(&mut self) -> io::Result<()> {
        if self.pending_wrap {
            self.pending_wrap = false;
            self.controls.write_all(b" \x08")?;
        }
        Ok(())
    }

    /// Shows one more character.
    pub fn add(&mut self, character: &str) -> io::Result<()> {
        self.settle()?;
        let width = cells(character);
        // A wide character does not fit in the last column: the terminal leaves it empty and
        // writes the character at the start of the next row.
        let skipped = usize::from(width == 2 && self.column(self.shown) == self.columns - 1);
        let advance = skipped + width;
        self.controls.write_all(character.as_bytes())?;
        self.shown += advance;
        // At most three cells: a skipped one and a wide character.
        self.advances.push(advance as u8);
        if advance > 0 && self.column(self.shown) == 0 {
            // The character filled its row. A terminal keeps the cursor on that row until the next
            // character comes, or moves on at once; a space then a backspace puts it at the start
            // of the next row in both cases.
            self.controls.write_all(b" \x08")?;
        }
        self.controls.flush()
    }

    /// Takes the last `characters` shown characters off the screen, with any hint below them.
    pub fn remove(&mut self, characters: usize) -> io::Result<()> {
        self.settle()?;
        let mut cells = 0;
        for _ in 0..characters {
            cells += usize::from(self.advances.pop().unwrap_or(0));
        }
        let kept = self.shown.saturating_sub(cells);
        let rows_up = self.row(self.shown) - self.row(kept);
        if rows_up > 0 {
            write!(self.controls, "\x1b[{rows_up}A")?;
        }
        write!(self.controls, "\x1b[{}G\x1b[J", self.column(kept) + 1)?;
        self.shown = kept;
        self.controls.flush()
    }

    /// Shows the hint for `line`, the text typed so far, below it in place of the one before.
    pub fn hint(&mut self, line: &str) -> io::Result<()> {
        let Some(hints) = self.hints else {
            return Ok(());
        };
        self.settle()?;
        let rows = self.rows_of(hints, hints.list.hint(line));
        self.controls.write_all(b"\x1b[J")?;
        for row in &rows {
            self.controls.write_all(b"\r\n")?;
            self.controls.flush()?;
            self.text.write_all(row.as_bytes())?;
            self.text.flush()?;
        }
        if !rows.is_empty() {
            let column = self.column(self.shown) + 1;
            write!(self.controls, "\x1b[{}A\x1b[{column}G", rows.len())?;
        }
        self.controls.flush()
    }

    /// Clears the hint once the line is done.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.hints.is_some() {
            self.controls.write_all(b"\x1b[J")?;
        }
        self.controls.flush()
    }

    /// The rows that show `hint`, each narrower than the terminal so that none wraps.
    fn rows_of(&self, hints: Hints, hint: Hint) -> Vec<String> {
        let name = hints.list.name();
        match hint {
            Hint::Nothing => Vec::new(),
            Hint::NoWord if hints.says_no_word => {
                vec![self.hint_row(WARNING, &format!("! No {name} word begins like this."))]
            }
            Hint::NoWord => Vec::new(),
            Hint::Count(1) => {
                vec![self.hint_row(MUTED, &format!("1 {name} word begins with this letter"))]
            }
            Hint::Count(count) => vec![self.hint_row(
                MUTED,
                &format!("{count} {name} words begin with this letter"),
            )],
            Hint::Words(words) => self.word_rows(words),
        }
    }

    /// `words` in columns, at most [`HINT_ROWS`] rows of them, and how many more on a row of its
    /// own.
    fn word_rows(&self, words: &[&str]) -> Vec<String> {
        let longest = words.iter().map(|word| word.len()).max().unwrap_or(0);
        let cell = longest + WORD_GAP;
        let per_row = (self.room() / cell).max(1);
        let shown = words.len().min(per_row * HINT_ROWS);
        let mut rows: Vec<String> = words[..shown]
            .chunks(per_row)
            .map(|row| {
                let cells: Vec<String> = row.iter().map(|word| format!("{word:<cell$}")).collect();
                self.hint_row(MUTED, cells.concat().trim_end())
            })
            .collect();
        if shown < words.len() {
            rows.push(self.hint_row(MUTED, &format!("and {} more", words.len() - shown)));
        }
        rows
    }

    /// A hint row in `style`, indented and cut to the room of the terminal, so that a fixed text
    /// wider than a narrow terminal never wraps onto the row the typed line comes back to
    /// (AUD-015-UI001). Every hint is ASCII: list words, numbers and fixed text.
    fn hint_row(&self, style: Style, text: &str) -> String {
        let shown = &text[..text.len().min(self.room())];
        format!("{INDENT}{}", paint(style, shown))
    }

    /// The columns a hint row may fill after its indent: all but the last, where a terminal would
    /// move on to the next row.
    fn room(&self) -> usize {
        self.columns - 1 - INDENT.len()
    }

    /// The row of the line, from the prompt's row, where the character after `cells` goes.
    fn row(&self, cells: usize) -> usize {
        (self.start + cells) / self.columns
    }

    /// The column, from 0, where the character after `cells` goes.
    fn column(&self, cells: usize) -> usize {
        (self.start + cells) % self.columns
    }
}

/// The cells a terminal gives `character`, by its first code point: none for a combining mark,
/// which joins the character before it, two for a wide or fullwidth East Asian character or an
/// emoji, one otherwise (cell_widths.rs, generated from Unicode 17.0.0).
fn cells(character: &str) -> usize {
    character.chars().next().map_or(0, char_cells)
}

/// The cells `text` takes on a terminal, by the rule of [`cells`]: for a prompt, so that the line
/// after it starts in the column the terminal puts it in.
pub(crate) fn text_cells(text: &str) -> usize {
    text.chars().map(char_cells).sum()
}

/// The cells of one character (cell_widths.rs).
fn char_cells(character: char) -> usize {
    let code_point = u32::from(character);
    let found = cell_widths::RUNS.binary_search_by(|&(start, end, _)| {
        if end < code_point {
            std::cmp::Ordering::Less
        } else if start > code_point {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    match found {
        Ok(index) => usize::from(cell_widths::RUNS[index].2),
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a line typed character by character writes, after a prompt `start` wide on a terminal
    /// `columns` wide, without colours, with hints from `list`.
    fn screen_of(
        typed: &[&str],
        start: usize,
        columns: usize,
        hints: Option<Hints>,
        then: impl FnOnce(&mut LineScreen),
    ) -> String {
        let mut written = Vec::new();
        let mut text = Vec::new();
        {
            // One buffer for both would need two mutable borrows; the hint text is kept apart and
            // checked on its own.
            let mut screen = LineScreen::new(&mut written, &mut text, start, columns, hints);
            let mut line = String::new();
            for character in typed {
                line.push_str(character);
                screen.add(character).unwrap();
                screen.hint(&line).unwrap();
            }
            then(&mut screen);
        }
        let plain = anstream::adapter::strip_str(&String::from_utf8(text).unwrap()).to_string();
        format!("{}|{plain}", String::from_utf8(written).unwrap())
    }

    const BIP39: Option<Hints> = Some(Hints {
        list: WordList::Bip39,
        says_no_word: true,
    });

    /// A wide character takes two cells: removing it goes back two columns, and one that does not
    /// fit in the last column is written on the next row (AUD-016-UI001).
    #[test]
    fn a_wide_character_takes_two_cells() {
        // U+754C after a prompt of 20 columns, then "a", then "a" removed: the cursor goes back to
        // column 23, after the wide character, not 22.
        let written = screen_of(&["\u{754C}", "a"], 20, 80, None, |screen| {
            screen.remove(1).unwrap();
        });
        assert!(written.ends_with("\x1b[23G\x1b[J|"), "{written:?}");
        let written = screen_of(&["\u{754C}", "a"], 20, 80, None, |screen| {
            screen.remove(2).unwrap();
        });
        assert!(written.ends_with("\x1b[21G\x1b[J|"), "{written:?}");
        // At the last column of 10 a wide character skips it: removing it goes back a row.
        let written = screen_of(&["a", "\u{754C}"], 8, 10, None, |screen| {
            screen.remove(1).unwrap();
        });
        assert!(written.ends_with("\x1b[1A\x1b[10G\x1b[J|"), "{written:?}");
        // A combining mark takes no cell.
        assert_eq!(cells("e\u{301}"), 1);
        assert_eq!(cells("\u{301}"), 0);
        // An emoji is wide too: the cursor after U+1F680 and "a", with "a" removed, is at column 23
        // after a prompt of 20 (AUD-018).
        let written = screen_of(&["\u{1F680}", "a"], 20, 80, None, |screen| {
            screen.remove(1).unwrap();
        });
        assert!(written.ends_with("\x1b[23G\x1b[J|"), "{written:?}");
    }

    /// Known answers of the generated table, each from the Unicode 17.0.0 character database
    /// (East_Asian_Width and General_Category), so that a table generated wrongly fails.
    #[test]
    fn the_cell_table_gives_the_unicode_widths() {
        // The Unicode version of the password rule, so that the cursor and the password agree on
        // what a character is.
        assert_eq!(
            cell_widths::UNICODE_VERSION,
            unicode_normalization::UNICODE_VERSION
        );
        for (character, expected) in [
            ("a", 1),
            ("\u{E9}", 1),
            ("\u{416}", 1),
            ("\u{AD}", 1),
            ("\u{301}", 0),
            ("\u{200B}", 0),
            ("\u{1160}", 0),
            ("\u{754C}", 2),
            ("\u{3000}", 2),
            ("\u{FF21}", 2),
            ("\u{AC00}", 2),
            ("\u{231A}", 2),
            ("\u{1F680}", 2),
            ("\u{1F600}", 2),
            ("\u{20000}", 2),
            ("\u{1F1E6}", 1),
        ] {
            assert_eq!(
                cells(character),
                expected,
                "U+{:X}",
                u32::from(character.chars().next().unwrap())
            );
        }
        // The runs are sorted and apart, as the binary search needs.
        for pair in cell_widths::RUNS.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{pair:?}");
        }
    }

    /// A prompt that fills its row exactly leaves the cursor at the end of that row until the next
    /// character: the line first moves it to the next row, where the columns are counted from
    /// (AUD-018), also when the first character takes no cell.
    #[test]
    fn a_prompt_that_fills_its_row_moves_the_line_to_the_next() {
        assert_eq!(screen_of(&["a"], 10, 10, None, |_| {}), " \x08a|");
        let written = screen_of(&["\u{301}"], 10, 10, None, |screen| {
            screen.remove(1).unwrap();
        });
        assert_eq!(written, " \x08\u{301}\x1b[1G\x1b[J|");
    }

    #[test]
    fn a_line_without_hints_shows_its_characters() {
        assert_eq!(screen_of(&["a", "b"], 5, 80, None, |_| {}), "ab|");
    }

    #[test]
    fn a_full_row_puts_the_cursor_on_the_next_row() {
        // The prompt takes 8 of 10 columns: the second character fills the row.
        assert_eq!(
            screen_of(&["a", "b", "c"], 8, 10, None, |_| {}),
            "ab \x08c|"
        );
    }

    #[test]
    fn removing_goes_back_across_rows_and_clears_what_follows() {
        let written = screen_of(&["a", "b", "c"], 8, 10, None, |screen| {
            screen.remove(2).unwrap();
        });
        // From column 1 of row 1 back to column 9 of row 0.
        assert_eq!(written, "ab \x08c\x1b[1A\x1b[10G\x1b[J|");
        let written = screen_of(&["a", "b"], 0, 80, None, |screen| {
            screen.remove(1).unwrap();
        });
        assert_eq!(written, "ab\x1b[2G\x1b[J|");
    }

    #[test]
    fn hints_follow_the_word_being_typed() {
        let written = screen_of(&["z"], 0, 80, BIP39, |_| {});
        assert_eq!(
            written,
            "z\x1b[J\r\n\x1b[1A\x1b[2G|  4 BIP39 words begin with this letter"
        );
        let written = screen_of(&["z", "o"], 0, 80, BIP39, |screen| {
            screen.finish().unwrap();
        });
        assert!(
            written.ends_with("|  4 BIP39 words begin with this letter  zone  zoo"),
            "{written}"
        );
        assert!(
            written.contains("o\x1b[J\r\n\x1b[1A\x1b[3G\x1b[J|"),
            "{written}"
        );
    }

    #[test]
    fn a_word_no_list_has_is_said_only_in_a_line_of_words() {
        let written = screen_of(&["x"], 0, 80, BIP39, |_| {});
        assert!(
            written.ends_with("|  ! No BIP39 word begins like this."),
            "{written}"
        );
        let mut written = Vec::new();
        let mut text = Vec::new();
        let screen = LineScreen::new(&mut written, &mut text, 0, 80, None);
        let password = Hints {
            list: WordList::Eff,
            says_no_word: false,
        };
        assert!(screen.rows_of(password, Hint::NoWord).is_empty());
    }

    #[test]
    fn many_words_end_with_how_many_more() {
        let words: Vec<&str> = (0..40).map(|_| "word").collect();
        let mut written = Vec::new();
        let mut text = Vec::new();
        let screen = LineScreen::new(&mut written, &mut text, 0, 30, BIP39);
        let rows = screen.word_rows(&words);
        // 27 columns after the indent and the last one: four words of six columns a row.
        assert_eq!(rows.len(), HINT_ROWS + 1);
        let last = anstream::adapter::strip_str(&rows[HINT_ROWS]).to_string();
        assert_eq!(last, "  and 28 more");
    }

    #[test]
    fn a_hint_row_never_wraps() {
        // 24 columns leave 21 after the indent and the last column (AUD-015-UI001).
        let written = screen_of(&["x"], 0, 24, BIP39, |_| {});
        assert!(written.ends_with("|  ! No BIP39 word begin"), "{written}");
        let written = screen_of(&["z"], 0, 30, BIP39, |_| {});
        assert!(
            written.ends_with("|  4 BIP39 words begin with th"),
            "{written}"
        );
        for columns in NARROWEST_FOR_HINTS..=80 {
            let mut written = Vec::new();
            let mut text = Vec::new();
            let screen = LineScreen::new(&mut written, &mut text, 0, columns, BIP39);
            for hint in [
                Hint::NoWord,
                Hint::Count(2048),
                Hint::Words(&["abandon"; 40]),
            ] {
                for row in screen.rows_of(BIP39.unwrap(), hint) {
                    let plain = anstream::adapter::strip_str(&row).to_string();
                    assert!(plain.len() < columns, "{columns}: {plain}");
                }
            }
        }
    }

    #[test]
    fn a_narrow_terminal_gets_no_hints() {
        assert_eq!(screen_of(&["z"], 0, 20, BIP39, |_| {}), "z|");
    }
}
