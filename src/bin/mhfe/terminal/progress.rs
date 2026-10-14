//! The progress bar of an operation's Argon2 rounds.

use std::io::{self, IsTerminal};
use std::time::Instant;

use anstream::{eprint, eprintln};
use mhfe::{ENCRYPTION_ROUNDS, ROUNDS};

use crate::flow::{self, Kind};
use crate::style::{self, paint, ACCENT, MUTED};
use crate::time_text;

/// Shows a progress bar for each stage of an operation: "Encrypting" and "Checking" for an
/// encryption, "Recovering" otherwise. Each stage has its own bar of 12 rounds, the time left for
/// it and, at its end, the time it took. At a terminal the bar is redrawn on one line; otherwise
/// a line is written per round.
pub struct Progress {
    started: Instant,
    stage_started: Instant,
    same_line: bool,
    /// The widest line drawn so far; shorter lines are padded to wipe its end.
    widest: usize,
    /// The stage on screen; empty once it has been finished.
    stage: &'static str,
    /// The name of a 12-round operation: "Recovering", or "Opening" for a hidden wallet.
    single: &'static str,
}

impl Progress {
    pub fn start() -> Self {
        // A stage of work is a step of its own in a command shown one step at a time.
        flow::step();
        eprintln!();
        style::hint("Press Ctrl+C to cancel at any time.");
        eprintln!();
        Self {
            started: Instant::now(),
            stage_started: Instant::now(),
            same_line: io::stderr().is_terminal(),
            widest: 0,
            stage: "",
            single: "Recovering",
        }
    }

    /// [`Progress::start`] for a 12-round operation shown under another name, such as "Opening"
    /// for a hidden wallet, which recovers no phrase the person had.
    pub fn start_as(single: &'static str) -> Self {
        Self {
            single,
            ..Self::start()
        }
    }

    /// Called before each round of an operation: `rounds` is 24 for an encryption, whose rounds
    /// 13 to 24 are the check, and 12 otherwise.
    pub fn round_starts(&mut self, round: u32, rounds: u32) {
        let stage = stage(round, rounds, self.single);
        if stage != self.stage {
            self.finish();
            self.stage = stage;
            self.stage_started = Instant::now();
        }
        // The round within its stage, 1 to 12.
        let stage_round = (round - 1) % ROUNDS + 1;
        // From the second round on, the average time of the finished rounds of the whole
        // operation gives the time left for this stage.
        let finished_rounds = u64::from(round - 1);
        let rounds_left = u64::from(ROUNDS - stage_round + 1);
        let elapsed = self.started.elapsed().as_secs();
        let note = match (elapsed * rounds_left).checked_div(finished_rounds) {
            Some(seconds) => format!("about {} left", time_text::duration(seconds)),
            None => String::new(),
        };
        self.draw(stage_round - 1, &note);
    }

    /// Finishes the stage on screen and starts the time estimate again, for a second operation
    /// shown under the first.
    pub fn next_operation(&mut self) {
        self.finish();
        self.started = Instant::now();
    }

    /// Shows the stage on screen as complete, with the time it took, and ends its line so that
    /// other text can follow. Does nothing when no stage is on screen.
    pub fn finish(&mut self) {
        if self.stage.is_empty() {
            return;
        }
        let note = format!(
            "done in {}",
            time_text::duration(self.stage_started.elapsed().as_secs())
        );
        let line = self.draw(ROUNDS, &note);
        if self.same_line {
            eprintln!();
        }
        // The finished stage belongs to the summary of a command shown one step at a time.
        flow::keep(Kind::Result, &[line]);
        self.stage = "";
        self.widest = 0;
    }

    /// One line: the stage, a bar with `completed` of 12 rounds filled, the round and a note.
    /// Returns the line as drawn.
    fn draw(&mut self, completed: u32, note: &str) -> String {
        let stage = format!("{:<10}", self.stage);
        let count = format!("{:>2}/{ROUNDS}", (completed + 1).min(ROUNDS));
        let bar = style::bar(completed, ROUNDS);
        // The visible width: stage, space, bar, two spaces, count, two spaces, note.
        let width = stage.len() + 1 + style::BAR_CELLS as usize + 2 + count.len() + 2 + note.len();
        let line = format!(
            "{} {bar}  {count}  {}",
            paint(ACCENT, stage),
            paint(MUTED, note)
        );
        if self.same_line {
            self.widest = self.widest.max(width);
            let padding = " ".repeat(self.widest - width);
            eprint!("\r{line}{padding}");
        } else {
            eprintln!("{line}");
        }
        line
    }
}

/// What the rounds of an operation do: an encryption encrypts in rounds 1 to 12 and checks in
/// rounds 13 to 24.
fn stage(round: u32, rounds: u32, single: &'static str) -> &'static str {
    match (rounds, round) {
        (ENCRYPTION_ROUNDS, round) if round <= ROUNDS => "Encrypting",
        (ENCRYPTION_ROUNDS, _) => "Checking",
        _ => single,
    }
}
