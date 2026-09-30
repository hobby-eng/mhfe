//! Everything the tool reads from and shows to the person at the terminal.
//!
//! Secrets are read without echo into buffers that are wiped when dropped. Results go to
//! standard output; prompts, progress and advice go to standard error, so a result can be piped
//! on without the messages.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anstream::{eprint, eprintln, println};
use mhfe::{ENCRYPTION_ROUNDS, ROUNDS};
use zeroize::Zeroizing;

use crate::exit::{self, Failure};
use crate::hidden_input;
use crate::style::{self, paint, ACCENT, HEADING, MUTED};

/// Longest line accepted, line break included. The buffer is reserved at this size and reading
/// stops there, so it is never reallocated, which would leave an unwiped copy of a secret
/// behind. Every valid answer is far shorter: a password has at most 1024 bytes.
pub(crate) const LINE_CAPACITY: usize = 8192;

/// Where answers come from.
pub enum Input {
    /// A person at a terminal: secrets are hidden and a mistake can be corrected.
    Terminal,
    /// A script: one answer per line on standard input, in the order the command documents.
    Script(io::StdinLock<'static>),
}

impl Input {
    pub fn new(from_standard_input: bool) -> Self {
        if from_standard_input {
            Self::Script(io::stdin().lock())
        } else {
            Self::Terminal
        }
    }

    /// Whether a wrong answer can be asked again.
    pub fn can_ask_again(&self) -> bool {
        matches!(self, Self::Terminal)
    }

    pub fn is_script(&self) -> bool {
        matches!(self, Self::Script(_))
    }

    /// Reads a secret: typed without echo at a terminal, or the next line of a script.
    pub fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>, Failure> {
        match self {
            Self::Terminal => read_hidden(prompt),
            Self::Script(lines) => read_script_line(lines, prompt),
        }
    }

    /// Reads a public answer, such as a container or an address, shown while typed.
    pub fn visible(&mut self, prompt: &str) -> Result<Zeroizing<String>, Failure> {
        match self {
            Self::Terminal => {
                style::prompt(prompt);
                io::stderr().flush()?;
                match read_bounded_line(&mut io::stdin().lock())? {
                    Some(line) => Ok(line),
                    None => Err(Failure::invalid_input("No answer was typed.")),
                }
            }
            Self::Script(lines) => read_script_line(lines, prompt),
        }
    }

    /// Asks a yes-or-no question at a terminal; Enter alone gives `default`.
    pub fn yes_or_no(&mut self, question: &str, default: bool) -> Result<bool, Failure> {
        let choices = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            let answer = self.visible(&format!("{question} {choices}: "))?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => eprintln!("Type y or n."),
            }
        }
    }
}

/// Set while a container is on the screen whose check has not finished, so that Ctrl+C can say so.
static UNVERIFIED_CONTAINER_SHOWN: AtomicBool = AtomicBool::new(false);

pub fn set_unverified_container_shown(shown: bool) {
    UNVERIFIED_CONTAINER_SHOWN.store(shown, Ordering::SeqCst);
}

/// Ctrl+C ends the tool at once, also in the middle of an Argon2 round that may take hours at
/// a high PIM. The operating system then discards all of the tool's memory, including the
/// Argon2 work area and every secret. If a hidden prompt has switched the echo off, the terminal
/// is restored first.
pub fn stop_on_ctrl_c() {
    let handler = || hidden_input::restore_and_exit(exit_cancelled);
    if ctrlc::set_handler(handler).is_err() {
        // Without the handler the default Ctrl+C behaviour still ends the tool at once.
        style::hint("Note: Ctrl+C will end the tool without a message.");
    }
}

pub fn exit_cancelled() -> ! {
    eprintln!();
    if UNVERIFIED_CONTAINER_SHOWN.load(Ordering::SeqCst) {
        style::alarm(
            "Cancelled before the check finished: the container above is NOT verified.",
            "Do not rely on it; encrypt again.",
        );
    } else {
        style::warn(
            "Cancelled.",
            "Nothing was saved; the memory the tool used is released.",
        );
    }
    std::process::exit(exit::CANCELLED);
}

fn read_hidden(prompt: &str) -> Result<Zeroizing<String>, Failure> {
    if !io::stdin().is_terminal() {
        return Err(Failure::invalid_input(
            "There is no terminal to type secrets into. Run the command in a terminal, or pass \
             --stdin and give one answer per line on standard input.",
        ));
    }
    // The line is read exactly as typed; Password::new refuses what a password may not contain.
    let line = hidden_input::read_line(|| {
        style::prompt(prompt);
        io::stderr().flush()?;
        Ok(())
    })?;
    match line {
        Some(text) => Ok(text),
        // Ctrl+D on an empty line: the person closed the input.
        None => exit_cancelled(),
    }
}

fn read_script_line(
    lines: &mut io::StdinLock<'static>,
    prompt: &str,
) -> Result<Zeroizing<String>, Failure> {
    read_bounded_line(lines)?.ok_or_else(|| {
        Failure::invalid_input(format!(
            "Standard input ended before this answer: {}",
            prompt.trim_end_matches([' ', ':'])
        ))
    })
}

/// Reads one line of at most LINE_CAPACITY bytes into a buffer reserved at that size, without
/// its line break. `None` means that the input had ended. A longer line is refused, and what
/// was read of it is wiped with the buffer, so the buffer never grows.
///
/// The standard library keeps its own buffer of what it read from standard input and does not
/// wipe it; only the copies in this program's buffers are under its control.
pub(crate) fn read_bounded_line(
    reader: &mut impl BufRead,
) -> Result<Option<Zeroizing<String>>, Failure> {
    let mut line = Zeroizing::new(String::with_capacity(LINE_CAPACITY));
    let read = reader.take(LINE_CAPACITY as u64).read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') && read == LINE_CAPACITY {
        return Err(Failure::invalid_input(format!(
            "An answer is longer than {LINE_CAPACITY} bytes; no valid answer is that long."
        )));
    }
    strip_line_ending(&mut line);
    Ok(Some(line))
}

/// Removes only the line break. Spaces are part of a password and are never trimmed.
fn strip_line_ending(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
}

/// Prints a phrase to standard output. For a person: in a frame, numbered, for comparing with
/// what was written down, and below it on one plain line, for copying. For a script: the plain
/// line only.
pub fn print_phrase(phrase: &str, input: &Input) {
    if input.is_script() {
        println!("{phrase}");
        return;
    }
    for line in style::boxed_words(phrase) {
        println!("{}", *line);
    }
    eprintln!("{}", paint(MUTED, "On one line, for copying:"));
    println!("{phrase}");
    eprintln!();
}

/// Shows a container as it was read, every word in full, so that a person who typed short
/// forms or odd spacing can compare it with the backup. A script gets only its results.
pub fn show_container_read(container: &str, input: &Input) {
    if input.is_script() {
        return;
    }
    show_words("Read the container as:", container);
}

/// Shows a phrase in a frame on standard error, where prompts go.
pub fn show_words(heading: &str, phrase: &str) {
    eprintln!("{}", paint(HEADING, heading));
    for line in style::boxed_words(phrase) {
        eprintln!("{}", *line);
    }
}

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
}

impl Progress {
    pub fn start() -> Self {
        style::hint("Press Ctrl+C to cancel at any time.");
        eprintln!();
        Self {
            started: Instant::now(),
            stage_started: Instant::now(),
            same_line: io::stderr().is_terminal(),
            widest: 0,
            stage: "",
        }
    }

    /// Called before each round of an operation: `rounds` is 24 for an encryption, whose rounds
    /// 13 to 24 are the check, and 12 otherwise.
    pub fn round_starts(&mut self, round: u32, rounds: u32) {
        let stage = stage(round, rounds);
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
            Some(seconds) => format!("about {} left", duration(seconds)),
            None => String::new(),
        };
        self.draw(stage_round - 1, &note);
    }

    /// Shows the stage on screen as complete, with the time it took, and ends its line so that
    /// other text can follow. Does nothing when no stage is on screen.
    pub fn finish(&mut self) {
        if self.stage.is_empty() {
            return;
        }
        let note = format!(
            "done in {}",
            duration(self.stage_started.elapsed().as_secs())
        );
        self.draw(ROUNDS, &note);
        if self.same_line {
            eprintln!();
        }
        self.stage = "";
        self.widest = 0;
    }

    /// One line: the stage, a bar with `completed` of 12 rounds filled, the round and a note.
    fn draw(&mut self, completed: u32, note: &str) {
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
    }
}

/// What the rounds of an operation do: an encryption encrypts in rounds 1 to 12 and checks in
/// rounds 13 to 24.
fn stage(round: u32, rounds: u32) -> &'static str {
    match (rounds, round) {
        (ENCRYPTION_ROUNDS, round) if round <= ROUNDS => "Encrypting",
        (ENCRYPTION_ROUNDS, _) => "Checking",
        _ => "Recovering",
    }
}

/// "45 s", "3 min 20 s", "2 h 5 min", "1 day 3 h".
pub fn duration(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    match seconds {
        s if s < MINUTE => format!("{s} s"),
        s if s < HOUR => format!("{} min {} s", s / MINUTE, s % MINUTE),
        s if s < DAY => format!("{} h {} min", s / HOUR, (s % HOUR) / MINUTE),
        s => {
            let days = s / DAY;
            let unit = if days == 1 { "day" } else { "days" };
            format!("{days} {unit} {} h", (s % DAY) / HOUR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(200), "3 min 20 s");
        assert_eq!(duration(7_500), "2 h 5 min");
        assert_eq!(duration(97_200), "1 day 3 h");
        assert_eq!(duration(3 * 86_400), "3 days 0 h");
    }

    #[test]
    fn only_the_line_break_is_removed() {
        let mut line = String::from("  pass word \r\n");
        strip_line_ending(&mut line);
        assert_eq!(line, "  pass word ");
    }

    #[test]
    fn lines_are_read_one_at_a_time_without_their_line_break() {
        let mut input = io::Cursor::new("first answer\r\n second \nlast without break");
        let mut next = || {
            read_bounded_line(&mut input)
                .unwrap()
                .map(|line| line.to_string())
        };
        assert_eq!(next().as_deref(), Some("first answer"));
        assert_eq!(next().as_deref(), Some(" second "));
        assert_eq!(next().as_deref(), Some("last without break"));
        assert_eq!(next(), None, "the end of the input is not an empty answer");
    }

    #[test]
    fn a_line_up_to_the_limit_keeps_its_buffer() {
        let longest = format!("{}\n", "a".repeat(LINE_CAPACITY - 1));
        let line = read_bounded_line(&mut io::Cursor::new(longest))
            .unwrap()
            .unwrap();
        assert_eq!(line.len(), LINE_CAPACITY - 1);
        assert_eq!(
            line.capacity(),
            LINE_CAPACITY,
            "the buffer was never reallocated"
        );
    }

    #[test]
    fn a_longer_line_is_refused() {
        let too_long = format!("{}\n", "a".repeat(LINE_CAPACITY));
        let failure = read_bounded_line(&mut io::Cursor::new(too_long)).unwrap_err();
        assert!(
            failure.message.contains("longer than"),
            "{}",
            failure.message
        );
    }
}
