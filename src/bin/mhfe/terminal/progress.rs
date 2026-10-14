//! The progress bar of an operation's Argon2 rounds.

use std::io::{self, IsTerminal};
use std::time::Instant;

use mhfe::operation::Stage;
use mhfe::ROUNDS;

use crate::exit::Failure;
use crate::flow::{self, Kind};
use crate::style::{self, paint, ACCENT, MUTED};
use crate::time_text;

/// Shows a progress bar for each stage of an operation: "Encrypting" and "Checking" for an
/// encryption, "Recovering" otherwise. Each stage has its own bar of 12 rounds, the time left for
/// it and, at its end, the time it took. At a terminal the bar is redrawn on one line; otherwise
/// a line is written per round.
pub(crate) struct Progress {
    stage_started: Instant,
    same_line: bool,
    /// The widest line drawn so far; shorter lines are padded to wipe its end.
    widest: usize,
    /// The library stage on screen; absent once it has been finished.
    stage: Option<Stage>,
    /// The first reported round of this stage, in the library's operation-wide numbering.
    first_round: u32,
    /// The name of a 12-round operation: "Recovering", or "Opening" for a hidden wallet.
    single: &'static str,
}

impl Progress {
    pub(crate) fn start() -> Result<Self, Failure> {
        // A stage of work is a step of its own in a command shown one step at a time.
        flow::step()?;
        eprintln!();
        style::hint("Press Ctrl+C to cancel at any time.");
        eprintln!();
        Ok(Self {
            stage_started: Instant::now(),
            same_line: io::stderr().is_terminal(),
            widest: 0,
            stage: None,
            first_round: 0,
            single: "Recovering",
        })
    }

    /// [`Progress::start`] for a 12-round operation shown under another name, such as "Opening"
    /// for a hidden wallet, which recovers no phrase the person had.
    pub(crate) fn start_as(single: &'static str) -> Result<Self, Failure> {
        Ok(Self {
            single,
            ..Self::start()?
        })
    }

    /// Called with the library's stage and unchanged operation-wide round numbers. Each new
    /// stage starts its own counter and clock; names never depend on the total round count.
    pub(crate) fn round_starts(&mut self, stage: Stage, round: u32, _rounds: u32) {
        if Some(stage) != self.stage {
            self.finish();
            self.stage = Some(stage);
            self.first_round = round;
            self.stage_started = Instant::now();
        }
        let completed = round - self.first_round;
        let rounds_left = u64::from(ROUNDS - completed);
        let elapsed = self.stage_started.elapsed().as_secs();
        let note = match (elapsed * rounds_left).checked_div(u64::from(completed)) {
            Some(seconds) => format!("about {} left", time_text::duration(seconds)),
            None => String::new(),
        };
        self.draw(completed, &note);
    }

    /// Finishes the stage on screen and starts the time estimate again, for a second operation
    /// shown under the first.
    pub(crate) fn next_operation(&mut self) {
        self.finish();
    }

    /// Shows the stage on screen as complete, with the time it took, and ends its line so that
    /// other text can follow. Does nothing when no stage is on screen.
    pub(crate) fn finish(&mut self) {
        if self.stage.is_none() {
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
        self.stage = None;
        self.widest = 0;
    }

    /// One line: the stage, a bar with `completed` of 12 rounds filled, the round and a note.
    ///
    /// Returns the line as drawn.
    fn draw(&mut self, completed: u32, note: &str) -> String {
        let stage = format!("{:<10}", stage_name(self.stage, self.single));
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

/// The terminal wording of a reported library stage. Recovery may be named for the command.
fn stage_name(stage: Option<Stage>, single: &'static str) -> &'static str {
    match stage {
        Some(Stage::Encrypt) => "Encrypting",
        Some(Stage::Check) => "Checking",
        Some(Stage::Recover) => single,
        Some(Stage::Compare) => "Comparing",
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_labels_follow_the_reported_stage_with_unchanged_round_numbers() {
        let mut bar = Progress {
            stage_started: Instant::now(),
            same_line: false,
            widest: 0,
            stage: None,
            first_round: 0,
            single: "Recovering",
        };
        // Deliberate copy: public StageCallback sequences from Encryption, Rekey::seal and
        // SelfTest::run. The labels are independent expected terminal output, not inferred.
        for stages in [
            vec![
                (Stage::Encrypt, 1, 24, "Encrypting"),
                (Stage::Check, 13, 24, "Checking"),
            ],
            vec![
                (Stage::Encrypt, 13, 36, "Encrypting"),
                (Stage::Check, 25, 36, "Checking"),
            ],
            vec![
                (Stage::Encrypt, 1, 24, "Encrypting"),
                (Stage::Recover, 13, 24, "Recovering"),
            ],
        ] {
            bar.finish();
            for (stage, first, total, label) in stages {
                for round in first..first + ROUNDS {
                    bar.round_starts(stage, round, total);
                    assert_eq!(stage_name(bar.stage, bar.single), label);
                    assert_eq!(round - bar.first_round, round - first);
                }
            }
        }
        bar.finish();
        assert_eq!(stage_name(Some(Stage::Recover), "Opening"), "Opening");
        assert_eq!(stage_name(Some(Stage::Recover), "Searching"), "Searching");
        assert_eq!(stage_name(Some(Stage::Compare), "Recovering"), "Comparing");
    }
}
