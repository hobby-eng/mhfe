//! A command shown one step at a time. At a terminal, every question, secret, wait and stage of
//! work appears on a cleared screen under the command's title, without the steps before it. The
//! summary that the steps leave (the records of the answers, the facts, the warnings and the
//! results) is written once, on the main screen, when the command ends, also after an error or a
//! cancel. A warning is shown again at the top of the next step, so that it is read before the
//! person goes on.
//!
//! The steps lie on the terminal's alternate screen, as the private screens do, so that nothing of
//! them reaches the main screen or its scrollback. A script, a pipe or a file gets every line as it
//! comes, as before.

use std::sync::{Mutex, MutexGuard, PoisonError};

use anstream::eprintln;

use crate::style;
use crate::terminal::{self, Input};

/// What a line of the summary is. A blank line separates two groups of different kinds, as the
/// summary looks when it is written as the steps go.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A line of a table, such as the settings or what to keep (style::fact).
    Fact,
    /// The record of an answer (choice::record).
    Record,
    /// A warning or an alarm, with its link.
    Notice,
    /// A finished stage of work or a success (Progress, style::ok).
    Result,
}

/// Where the last lines kept for the summary were shown, which a "More:" line after them follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shown {
    /// In the summary only.
    Later,
    /// At the top of the next step too.
    NextStep,
    /// On the screen of the step at once too.
    Now,
}

struct State {
    title: String,
    summary: Vec<String>,
    /// The kind of the last group, for the blank line before the next one.
    last: Option<Kind>,
    /// Where the last lines went, for a "More:" line after them.
    shown: Shown,
    /// Lines not yet shown at the top of a step.
    pending: Vec<String>,
    /// False while the steps must leave nothing in the summary (OffTheRecord).
    recording: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Nothing panics while the lock is held, so it is never poisoned; this only avoids an unwrap.
fn state() -> MutexGuard<'static, Option<State>> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Shows the steps of a command one at a time while this lives, and its summary when dropped.
pub struct Flow {
    active: bool,
}

impl Flow {
    /// Starts the steps of the command headed `title`, where a terminal can switch screens and
    /// show them privately; anywhere else this does nothing.
    pub fn start(input: &Input, title: &str) -> Self {
        let active = terminal::enter_steps(input);
        if active {
            *state() = Some(State {
                title: title.to_owned(),
                summary: Vec::new(),
                last: None,
                shown: Shown::Later,
                pending: Vec::new(),
                recording: true,
            });
        }
        Self { active }
    }
}

impl Flow {
    /// Ends the steps at once: the main screen gets the summary, and what the command writes next
    /// follows it there, as the result of a command does.
    pub fn finish(mut self) {
        self.end();
    }

    fn end(&mut self) {
        if self.active {
            self.active = false;
            let finished = state().take();
            terminal::leave_steps();
            if let Some(state) = finished {
                write_summary(&state);
            }
        }
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.end();
    }
}

/// While this lives, the steps keep nothing for the summary: what would be kept is shown on the
/// screen of the step instead, and leaves with it. For the hidden wallets, whose number must leave
/// no trace (AUD-007-SEC005).
pub struct OffTheRecord {
    active: bool,
}

pub fn off_the_record() -> OffTheRecord {
    let mut guard = state();
    let active = match guard.as_mut() {
        Some(state) => {
            state.recording = false;
            true
        }
        None => false,
    };
    OffTheRecord { active }
}

impl Drop for OffTheRecord {
    fn drop(&mut self) {
        if self.active {
            if let Some(state) = state().as_mut() {
                state.recording = true;
            }
        }
    }
}

pub fn is_active() -> bool {
    state().is_some()
}

/// Begins a step: clears the screen and writes the title, then the warnings since the last step.
/// Does nothing outside a flow.
pub fn step() {
    let (title, pending) = {
        let mut guard = state();
        let Some(state) = guard.as_mut() else {
            return;
        };
        (state.title.clone(), std::mem::take(&mut state.pending))
    };
    terminal::clear_screen();
    style::write_title(&title);
    if !pending.is_empty() {
        eprintln!();
        for line in pending {
            eprintln!("{line}");
        }
    }
}

/// Keeps `lines` for the summary instead of writing them. False outside a flow, or off the
/// record, where the caller writes them on the screen as before.
pub fn keep(kind: Kind, lines: &[String]) -> bool {
    keep_lines(kind, lines, Shown::Later)
}

/// Keeps a warning for the summary and for the top of the next step.
pub fn keep_notice(lines: &[String]) -> bool {
    keep_next(Kind::Notice, lines)
}

/// Keeps `lines` for the summary and for the top of the next step, such as what a search will
/// cover, shown before the work starts.
pub fn keep_next(kind: Kind, lines: &[String]) -> bool {
    keep_lines(kind, lines, Shown::NextStep)
}

/// Keeps lines for the summary that the caller has also shown on the screen of the step, such as
/// a result next to what it is about. False where nothing is kept.
pub fn keep_shown(kind: Kind, lines: &[String]) -> bool {
    keep_lines(kind, lines, Shown::Now)
}

/// Shows `lines` at the top of the next step without keeping them, such as the reason why a
/// password typed there was refused.
pub fn show_at_next_step(lines: &[String]) -> bool {
    let mut guard = state();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    state.pending.extend(lines.iter().cloned());
    true
}

/// Keeps a "More:" line with the lines before it, and shows it where they were shown. Returns
/// whether the caller must write it on the screen now, as it does outside a flow.
pub fn keep_link(line: String) -> bool {
    let mut guard = state();
    let Some(state) = guard.as_mut() else {
        return true;
    };
    if state.recording {
        state.summary.push(line.clone());
    }
    match state.shown {
        Shown::Later => !state.recording,
        Shown::NextStep => {
            state.pending.push(line);
            false
        }
        Shown::Now => true,
    }
}

fn keep_lines(kind: Kind, lines: &[String], shown: Shown) -> bool {
    let mut guard = state();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    if !state.recording {
        // Off the record a warning still heads the next step; anything else is shown on the
        // screen of the step by the caller, and leaves with it.
        if shown == Shown::NextStep {
            state.pending.extend(lines.iter().cloned());
            state.shown = Shown::NextStep;
            return true;
        }
        state.shown = Shown::Now;
        return false;
    }
    // A success and the facts after it read as one group, as at the end of an encryption.
    let joins =
        state.last == Some(kind) || (state.last == Some(Kind::Result) && kind == Kind::Fact);
    if state.last.is_some() && !joins {
        state.summary.push(String::new());
    }
    state.last = Some(kind);
    state.shown = shown;
    state.summary.extend(lines.iter().cloned());
    if shown == Shown::NextStep {
        state.pending.extend(lines.iter().cloned());
    }
    true
}

/// For Ctrl+C, which ends the tool from another thread: leaves the steps and writes the summary
/// so far, unless the thread that was interrupted holds the lock.
pub fn end_at_exit() {
    let finished = match STATE.try_lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    if let Some(state) = finished {
        terminal::leave_steps();
        write_summary(&state);
    }
}

fn write_summary(state: &State) {
    style::write_title(&state.title);
    for line in &state.summary {
        eprintln!("{line}");
    }
}
