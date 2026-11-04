//! A private screen that keeps what it shows, so that the person can scroll back to it: the
//! terminal's alternate screen keeps no line that scrolls off its top. `mhfe decrypt` shows the
//! phrase of each password on it as soon as it is recovered; once all are shown, the screen
//! scrolls with the arrow keys and Page Up and Page Down, and in most terminals with the mouse
//! wheel, which they turn into arrow keys on the alternate screen.

use std::cell::RefCell;
use std::convert::Infallible;

use anstream::eprintln;
use mhfe::memory::LockedText;

use crate::exit::Failure;
use crate::hidden_input::{self, Key};
use crate::raw_io::println;
use crate::style::{self, paint, MUTED};
use crate::terminal;

thread_local! {
    /// The lines written while a [`ScrollScreen`] keeps them, each ended by a line break, in
    /// buffers of locked memory.
    static KEPT: RefCell<Option<Vec<LockedText>>> = const { RefCell::new(None) };
}

/// The size of each buffer the lines are kept in. The system locks whole pages, so lines share
/// them: a few buffers hold several phrases, well within the memory a process may lock.
const BUFFER_BYTES: usize = 16 * 1024;

/// Keeps `line`, as written to the terminal, while a [`ScrollScreen`] is being filled, and does
/// nothing otherwise. Every line written through style.rs, and the lines of a phrase, pass here.
/// A buffer the system did not lock is said, as for a typed secret.
pub(crate) fn keep(line: &str) {
    let locked = KEPT.with_borrow_mut(|kept| {
        let buffers = kept.as_mut()?;
        let needed = line.len() + 1;
        let full = buffers
            .last()
            .is_none_or(|buffer| buffer.capacity() - buffer.len() < needed);
        if full {
            buffers.push(new_buffer(needed));
        }
        let buffer = buffers.last_mut()?;
        buffer.push_str(line);
        buffer.push('\n');
        Some(buffer.is_locked())
    });
    // After the buffers are let go: the warning is a line kept too.
    if locked == Some(false) {
        terminal::note_unlocked(false);
    }
}

/// An empty buffer for lines of at least `bytes`, locked where the system allows.
fn new_buffer(bytes: usize) -> LockedText {
    let Ok(buffer) = LockedText::build::<Infallible>(bytes.max(BUFFER_BYTES), |_| Ok(()));
    buffer
}

/// The rows of a terminal whose height cannot be read: a VT100's.
const USUAL_ROWS: usize = 24;
/// The rows around the lines besides the title and the warning to write them down: a blank one
/// above them; a blank one and the keys below; and the row the cursor ends on.
const OTHER_ROWS: usize = 4;

/// The lines a private screen showed, in locked memory, wiped when it is dropped.
pub(crate) struct ScrollScreen {
    keeps: bool,
    buffers: Vec<LockedText>,
}

impl ScrollScreen {
    /// A screen that keeps what is shown on it where `keeps`, a private screen; elsewhere nothing
    /// is kept, as nothing can be scrolled back to. Its first buffer is reserved now, and said
    /// where the system does not lock it.
    pub(crate) fn new(keeps: bool) -> Self {
        let mut buffers = Vec::new();
        if keeps {
            let first = new_buffer(0);
            terminal::note_unlocked(first.is_locked());
            buffers.push(first);
        }
        Self { keeps, buffers }
    }

    /// Runs `show`, which writes on the screen, and keeps every line it writes.
    pub(crate) fn keep_shown<T>(&mut self, show: impl FnOnce() -> T) -> T {
        if !self.keeps {
            return show();
        }
        let buffers = std::mem::take(&mut self.buffers);
        KEPT.with_borrow_mut(|kept| *kept = Some(buffers));
        let shown = show();
        self.buffers = KEPT.with_borrow_mut(Option::take).unwrap_or_default();
        shown
    }

    /// The lines kept, in order, read in place.
    fn lines(&self) -> Vec<&str> {
        self.buffers
            .iter()
            .flat_map(|buffer| buffer.lines())
            .collect()
    }

    /// Shows the lines kept under the command's `title`, from the top, and lets the person scroll
    /// through them until Enter or Escape, after which the caller clears the screen. Keys pressed
    /// before, such as during the work, are discarded, so that none ends the wait at once.
    pub(crate) fn scroll(&self, title: &str) -> Result<(), Failure> {
        hidden_input::with_keys(|_| Ok(()))?;
        let mut top = 0;
        hidden_input::with_keys(|next_key| loop {
            let page = self.draw(title, &mut top)?;
            match next_key()? {
                Key::Enter | Key::Quit => return Ok(()),
                Key::Up => top = top.saturating_sub(1),
                Key::Down => top += 1,
                Key::PageUp => top = top.saturating_sub(page),
                Key::PageDown => top += page,
                _ => {}
            }
        })
    }

    /// Draws the lines from `top`, which it moves back where fewer lines are left than fit, and
    /// returns how many it drew. Drawn again for every key, it follows a change of the size too.
    /// The lines, phrases and passwords among them, go to standard output past the standard
    /// library's buffers (raw_io.rs), the terminal of the private screen.
    fn draw(&self, title: &str, top: &mut usize) -> std::io::Result<usize> {
        terminal::clear_screen();
        let title_rows = style::write_title(title);
        // The warning wraps on a narrow terminal: its rows are counted as it is written.
        let warning_rows = style::rows(&format!("! {}", terminal::WRITE_IT_DOWN));
        let room = hidden_input::rows()
            .unwrap_or(USUAL_ROWS)
            .saturating_sub(title_rows + warning_rows + OTHER_ROWS)
            .max(1);
        let lines = self.lines();
        let rows: Vec<usize> = lines.iter().map(|line| style::rows(line)).collect();
        let last = last_top(&rows, room);
        *top = (*top).min(last);
        let mut used = 0;
        let mut drawn = 0;
        eprintln!();
        for (line, rows) in lines[*top..].iter().zip(&rows[*top..]) {
            if drawn > 0 && used + rows > room {
                break;
            }
            println!("{line}")?;
            used += rows;
            drawn += 1;
        }
        eprintln!();
        style::warn_here(terminal::WRITE_IT_DOWN, "");
        if last > 0 {
            eprintln!("{}", paint(MUTED, "↑ ↓ PgUp PgDn scroll"));
        }
        Ok(drawn)
    }
}

/// The first of the lines, `rows` tall each, from which the rest fill at most `room` rows: the
/// scrolling stops there, with the last line at the bottom. A last line taller than the room is
/// shown alone.
fn last_top(rows: &[usize], room: usize) -> usize {
    let mut used = 0;
    for (index, line_rows) in rows.iter().enumerate().rev() {
        used += line_rows;
        if used > room {
            return (index + 1).min(rows.len() - 1);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrolling_stops_with_the_last_line_at_the_bottom() {
        assert_eq!(last_top(&[1, 1, 1], 5), 0);
        assert_eq!(last_top(&[1, 1, 1, 1, 1, 1], 4), 2);
        // A wrapped line counts all its rows.
        assert_eq!(last_top(&[1, 1, 3, 1], 4), 2);
        assert_eq!(last_top(&[1, 9], 4), 1);
        assert_eq!(last_top(&[], 4), 0);
    }

    #[test]
    fn only_lines_shown_while_keeping_are_kept() {
        keep("before");
        let mut screen = ScrollScreen::new(true);
        screen.keep_shown(|| keep("shown"));
        keep("after");
        screen.keep_shown(|| {
            keep("");
            keep("next");
        });
        assert_eq!(screen.lines(), ["shown", "", "next"]);
        let mut elsewhere = ScrollScreen::new(false);
        elsewhere.keep_shown(|| keep("shown"));
        assert!(elsewhere.lines().is_empty());
    }
}
