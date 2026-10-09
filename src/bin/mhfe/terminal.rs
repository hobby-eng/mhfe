//! Everything the tool reads from and shows to the person at the terminal.
//!
//! Secrets are typed on a private screen of their own, where they are shown as they are typed and
//! which is cleared once the person is done; anywhere else they are read without echo. Either way
//! they go into buffers that are locked and wiped when dropped. Results go to standard output;
//! prompts, progress and advice go to standard error, so a result can be piped on without the
//! messages.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anstream::{eprint, eprintln, println};
use mhfe::memory::LockedText;
use mhfe::word_hints::WordList;
use mhfe::{ContainerFacts, MhfeError, Password, Suite, ENCRYPTION_ROUNDS, ROUNDS};

use crate::check_word::{self, Reviewed};
use crate::choice::{self, Answer, Question};
use crate::container_repair::{self, CardAsked};
use crate::exit::{self, Failure};
use crate::flow::{self, Kind};
use crate::hidden_input::{self, Content};
use crate::protect;
use crate::settings::Operation;
use crate::style::{self, paint, ACCENT, MUTED, STRONG};

/// Longest line accepted, line break included: the library's typed-line buffer, which its
/// memory-locking check probes. The buffer is reserved at this size and reading stops there, so
/// it is never reallocated, which would leave an unwiped copy of a secret behind.
pub(crate) const LINE_CAPACITY: usize = mhfe::memory::TYPED_LINE_BYTES;

/// Says once, when a typed line's buffer could not be locked, that what is typed may reach swap:
/// the startup summary told what its probe found, and memory locked by later buffers counts
/// against the same limit (AUD-016-SEC002).
pub(crate) fn note_unlocked(locked: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SAID: AtomicBool = AtomicBool::new(false);
    if !locked && !SAID.swap(true, Ordering::Relaxed) {
        style::warn_now(
            "This answer's memory could not be locked, so it may reach swap.",
            "",
        );
    }
}

/// Where answers come from.
pub enum Input {
    /// A person at a terminal: secrets are hidden and a mistake can be corrected.
    /// `command_reads_stdin` tells whether the command has --stdin, so that a refusal for a
    /// missing terminal names it only where it exists (AUD-010).
    Terminal { command_reads_stdin: bool },
    /// A script: one answer per line on standard input, in the order the command documents.
    Script(io::StdinLock<'static>),
}

/// What a refusal of an answer typed at a terminal asks for.
pub const TYPE_AGAIN: &str = "Please type it again.";

impl Input {
    /// The input of a command that has --stdin: a script's lines on standard input when
    /// `from_standard_input`, a person at the terminal otherwise.
    pub fn new(from_standard_input: bool) -> Self {
        if from_standard_input {
            Self::Script(io::stdin().lock())
        } else {
            Self::Terminal {
                command_reads_stdin: true,
            }
        }
    }

    /// The input of a command without --stdin, which only a person at a terminal answers.
    pub fn terminal_only() -> Self {
        Self::Terminal {
            command_reads_stdin: false,
        }
    }

    /// Whether a wrong answer can be asked again.
    pub fn can_ask_again(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }

    /// An answer as `read` took it: `Some` when it was accepted. A refusal is shown at a terminal,
    /// which asks again (`None`), with `then` saying what to do, and ends a script, which cannot.
    pub fn accepted<T>(
        &self,
        read: Result<T, MhfeError>,
        then: &str,
    ) -> Result<Option<T>, Failure> {
        match read {
            Ok(value) => Ok(Some(value)),
            Err(error) if self.can_ask_again() => {
                style::retry(exit::refused(&error, then));
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn is_script(&self) -> bool {
        matches!(self, Self::Script(_))
    }

    /// Reads a secret of free text, such as a BIP39 passphrase: at a terminal, shown as it is
    /// typed on the private screen and hidden anywhere else; from a script, the next line.
    /// `question` has no colon: "Password" is asked as "Password: ", or as "Password (hidden): ".
    pub fn secret(&mut self, question: &str) -> Result<LockedText, Failure> {
        self.secret_of(question, Content::Text)
    }

    /// Reads a password as [`Input::secret`] does; where it is shown, the words of the EFF list
    /// that begin with the word being typed are hinted below it.
    pub fn password(&mut self, question: &str) -> Result<LockedText, Failure> {
        self.secret_of(question, Content::Password)
    }

    /// Reads secret words of `list`, such as a seed phrase, as [`Input::secret`] does; where they
    /// are shown, the words of the list are hinted below them, Tab completes one and Ctrl+W deletes
    /// one.
    pub fn secret_words(&mut self, question: &str, list: WordList) -> Result<LockedText, Failure> {
        self.secret_of(question, Content::Words(list))
    }

    fn secret_of(&mut self, question: &str, content: Content) -> Result<LockedText, Failure> {
        match self {
            Self::Terminal {
                command_reads_stdin,
            } => read_secret(question, *command_reads_stdin, content),
            Self::Script(lines) => read_script_line(lines, question),
        }
    }

    /// Reads a public answer, such as an address, shown while typed.
    pub fn visible(&mut self, prompt: &str) -> Result<LockedText, Failure> {
        match self {
            Self::Terminal { .. } => {
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

    /// Reads public words of `list`, such as a container phrase, shown while typed. At a terminal
    /// that carries out control sequences the words of the list are hinted below them, Tab
    /// completes one and Ctrl+W deletes one; elsewhere as [`Input::visible`].
    pub fn visible_words(&mut self, prompt: &str, list: WordList) -> Result<LockedText, Failure> {
        let hinted = matches!(self, Self::Terminal { .. })
            && io::stdin().is_terminal()
            && io::stderr().is_terminal()
            && hidden_input::control_sequences();
        if !hinted {
            return self.visible(prompt);
        }
        match hidden_input::read_line(prompt, true, Content::Words(list))? {
            Some(line) => Ok(line),
            None => Err(Failure::invalid_input("No answer was typed.")),
        }
    }

    /// Asks a question with a few fixed answers and returns the index of the chosen one; the first
    /// is the default. A person at a terminal chooses from a list with the arrow keys. A script,
    /// or a terminal that cannot redraw lines, gets the answers numbered and types the number on a
    /// line of its own, or nothing for the first.
    pub fn choose(&mut self, question: &Question, answers: &[Answer]) -> Result<usize, Failure> {
        flow::step();
        self.choose_here(question, answers)
    }

    /// [`Input::choose`] below what the screen shows already (choice::choose_here).
    pub fn choose_here(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        if !self.is_script() && choice::can_run() {
            return choice::choose_here(question, answers, None)?
                .ok_or_else(|| MhfeError::Cancelled.into());
        }
        self.choose_numbered(question, answers, true)
    }

    /// [`Input::choose`] with no default, for an answer that must be the person's own: no answer
    /// is highlighted in the list, and the numbered form takes no empty line for the first.
    pub fn choose_without_default(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        flow::step();
        self.choose_here_without_default(question, answers)
    }

    /// [`Input::choose_without_default`] below what the screen shows already
    /// (choice::choose_here_without_default).
    pub fn choose_here_without_default(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        if !self.is_script() && choice::can_run() {
            return choice::choose_here_without_default(question, answers, None)?
                .ok_or_else(|| MhfeError::Cancelled.into());
        }
        self.choose_numbered(question, answers, false)
    }

    /// The answers numbered, for a script or a terminal that cannot redraw; with `first_default`
    /// an empty line chooses the first.
    fn choose_numbered(
        &mut self,
        question: &Question,
        answers: &[Answer],
        first_default: bool,
    ) -> Result<usize, Failure> {
        choice::draw_question(question);
        for (number, answer) in answers.iter().enumerate() {
            let note = if answer.note.is_empty() {
                String::new()
            } else {
                format!(" {}", paint(MUTED, format!("({})", answer.note)))
            };
            eprintln!(
                "  {} {}{note}",
                paint(ACCENT, format!("{}.", number + 1)),
                *answer.label
            );
        }
        let prompt = if first_default {
            "Choice [1]: "
        } else {
            "Choice: "
        };
        loop {
            let typed = self.visible(prompt)?;
            let number = match typed.trim() {
                "" if first_default => Some(1),
                text => text.parse().ok(),
            };
            if let Some(number @ 1..) = number.filter(|number| *number <= answers.len()) {
                return Ok(number - 1);
            }
            let message = format!("Type a number from 1 to {}.", answers.len());
            if !self.can_ask_again() {
                return Err(Failure::invalid_input(message));
            }
            style::retry(message);
        }
    }
}

/// One step of a command at a terminal: a blank line, then its hint, prompts and the messages
/// about mistyped answers. Once the step is answered, `finish` erases all of it, so that the line
/// of the summary written next takes its place (as choice.rs does for a question with a list):
/// the answers then read as a short summary, and the next question always appears at the bottom,
/// after its blank line. A script gets neither the blank line nor the erasing.
pub struct Step {
    /// Lines drawn since the step began, its blank line included.
    lines: usize,
    erasable: bool,
}

impl Step {
    pub fn start(input: &Input) -> Self {
        if input.is_script() {
            return Self {
                lines: 0,
                erasable: false,
            };
        }
        if flow::is_active() {
            // On a screen of its own, the step needs no erasing.
            flow::step();
            return Self {
                lines: 0,
                erasable: false,
            };
        }
        eprintln!();
        Self {
            lines: 1,
            erasable: choice::can_run(),
        }
    }

    pub fn retry(&mut self, text: impl std::fmt::Display) {
        self.lines += style::retry(text);
    }

    /// Reads a public answer, which the terminal shows after the prompt and may wrap.
    pub fn visible(&mut self, input: &mut Input, prompt: &str) -> Result<LockedText, Failure> {
        let answer = input.visible(prompt)?;
        if !input.is_script() {
            self.lines += rows(prompt.chars().count() + answer.chars().count());
        }
        Ok(answer)
    }

    /// Erases the step; the caller then writes its line of the summary.
    pub fn finish(self) -> Result<(), Failure> {
        if self.erasable {
            choice::write_control(&choice::redraw_from(self.lines))?;
        }
        Ok(())
    }
}

/// The lines that `characters` take on the terminal, the Enter after them included: a full line
/// moves on only with the next character, so text that fills its last line exactly takes no more.
fn rows(characters: usize) -> usize {
    // When the width cannot be read, the usual 80 columns.
    let columns = hidden_input::columns().unwrap_or(80);
    characters.div_ceil(columns).max(1)
}

/// Set while a container is on the screen whose check has not finished, so that Ctrl+C can say so.
static UNVERIFIED_CONTAINER_SHOWN: AtomicBool = AtomicBool::new(false);

pub fn set_unverified_container_shown(shown: bool) {
    UNVERIFIED_CONTAINER_SHOWN.store(shown, Ordering::SeqCst);
}

/// Ctrl+C ends the tool at once, also in the middle of an Argon2 round that may take hours at
/// a high PIM. The operating system then discards all of the tool's memory, including the
/// Argon2 work area and every secret. If a hidden prompt has switched the echo off, the terminal
/// is restored first, and a private screen is left. Ctrl+\, Ctrl+Z, a closed terminal (SIGHUP) and
/// SIGTERM end it the same way, so that none leaves a secret on the screen (AUD-015-SEC004).
pub fn stop_on_ctrl_c() {
    let handler = || hidden_input::restore_and_exit(exit_cancelled);
    if ctrlc::set_handler(handler).is_err() {
        // Without the handler the default Ctrl+C behaviour still ends the tool at once.
        style::hint("Note: Ctrl+C will end the tool without a message.");
        return;
    }
    if !protect::interrupt_on_quit_and_suspend() {
        style::hint("Note: Ctrl+\\ or Ctrl+Z may leave a secret on the screen; use Ctrl+C.");
    }
}

pub fn exit_cancelled() -> ! {
    // The summary so far comes first, as when a command ends.
    flow::end_at_exit();
    leave_private_screen();
    eprintln!();
    if UNVERIFIED_CONTAINER_SHOWN.load(Ordering::SeqCst) {
        style::alarm(
            "Cancelled before the check finished: the container shown is NOT verified.",
            "Do NOT rely on it; encrypt again.",
        );
    } else {
        show_cancelled();
    }
    std::process::exit(exit::CANCELLED);
}

/// What a cancelled command says, after Ctrl+C or q in a list.
pub fn show_cancelled() {
    style::warn("Cancelled. Nothing was saved.", "");
}

/// Reads a secret of `content` at the terminal; without one, says how to run the command, naming
/// --stdin only for a command that has it (`command_reads_stdin`).
fn read_secret(
    question: &str,
    command_reads_stdin: bool,
    content: Content,
) -> Result<LockedText, Failure> {
    if !io::stdin().is_terminal() {
        return Err(Failure::invalid_input(no_terminal_advice(
            command_reads_stdin,
        )));
    }
    // Shown only where the screen is cleared once the person is done; hidden anywhere else.
    let shown = PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst);
    let prompt = if shown {
        format!("{question}: ")
    } else {
        format!("{question} (hidden): ")
    };
    // The line is read exactly as typed; Password::new refuses what a password may not contain.
    let line = hidden_input::read_line(&prompt, shown, content)?;
    match line {
        Some(text) => Ok(text),
        // Ctrl+D on an empty line: the person closed the input.
        None => exit_cancelled(),
    }
}

/// What a command says when it has no terminal to read a secret from.
fn no_terminal_advice(command_reads_stdin: bool) -> &'static str {
    if command_reads_stdin {
        "There is no terminal to type secrets into. Run the command in a terminal, or pass \
         --stdin and give one answer per line on standard input."
    } else {
        "There is no terminal to type secrets into. Run the command in a terminal: it has no \
         form for scripts."
    }
}

fn read_script_line(
    lines: &mut io::StdinLock<'static>,
    prompt: &str,
) -> Result<LockedText, Failure> {
    read_bounded_line(lines)?.ok_or_else(|| {
        Failure::invalid_input(format!(
            "Standard input ended before this answer: {}",
            prompt.trim_end_matches([' ', ':'])
        ))
    })
}

/// Reads one line of at most LINE_CAPACITY bytes into a buffer reserved at that size and locked,
/// without its line break. `None` means that the input had ended. A longer line is refused, and
/// what was read of it is wiped with the buffer, so the buffer never grows.
///
/// The standard library keeps its own buffer of what it read from standard input and does not
/// wipe it; only the copies in this program's buffers are under its control.
fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<LockedText>, Failure> {
    let mut read = 0;
    // Locked before anything is read into it: a script's line may be a password or a phrase.
    let line = LockedText::build(LINE_CAPACITY, |line| {
        read = reader.take(LINE_CAPACITY as u64).read_line(line)?;
        if !line.ends_with('\n') && read == LINE_CAPACITY {
            // The line break counts towards LINE_CAPACITY, so the answer itself may have one byte
            // less.
            return Err(Failure::invalid_input(format!(
                "An answer is longer than {} bytes; no valid answer is that long.",
                LINE_CAPACITY - 1
            )));
        }
        strip_line_ending(line);
        Ok(())
    })?;
    note_unlocked(line.is_locked());
    Ok((read > 0).then_some(line))
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
pub fn print_phrase(phrase: &str, wallet: Wallet, input: &Input) {
    if input.is_script() {
        println!("{phrase}");
        return;
    }
    for line in style::boxed_words(phrase) {
        println!("{}", *line);
    }
    eprintln!("{}", paint(MUTED, "On one line, for copying:"));
    println!("{phrase}");
    print_fingerprint(phrase, wallet);
}

/// The wallet a phrase shown opens, whose master key fingerprint is shown under it.
pub enum Wallet<'a> {
    /// A new seed phrase with the BIP39 passphrase chosen for it, empty for none.
    NewPassphrase(&'a str),
    /// A seed phrase whose BIP39 passphrase the command does not know: the wallet without one.
    NoPassphrase,
    /// A container, a valid phrase itself: the wallet its own words open, without a passphrase,
    /// which is not the owner's wallet.
    Container,
}

/// The BIP32 master key fingerprint under a phrase, the eight hex digits that wallet apps show
/// (Sparrow: "Master fingerprint"), to tell which wallet it is. A BIP39 passphrase changes it, so
/// the note says which wallet it belongs to. It goes where the words go, to the terminal; when
/// they go to a file, it would be left alone on the screen and its history, so it is not shown.
/// Scripts get the phrase alone.
fn print_fingerprint(phrase: &str, wallet: Wallet) {
    if !output_on_screen() {
        return;
    }
    let (passphrase, which) = match wallet {
        Wallet::NewPassphrase("") => ("", "no BIP39 passphrase"),
        Wallet::NewPassphrase(passphrase) => (passphrase, "with your BIP39 passphrase"),
        Wallet::NoPassphrase => ("", "if the wallet has no BIP39 passphrase"),
        Wallet::Container => ("", "of the container itself, not your wallet"),
    };
    // Every phrase shown is a valid BIP39 phrase. Should the fingerprint fail all the same, the
    // phrase above is what matters, so it stands without one.
    let Ok(fingerprint) = mhfe::wallet::master_fingerprint_text(phrase, passphrase) else {
        return;
    };
    eprintln!(
        "{} {}  {}",
        paint(MUTED, FINGERPRINT_LABEL),
        paint(STRONG, fingerprint),
        paint(MUTED, format!("({which})"))
    );
}

/// The name `mhfe check --fingerprint` asks for, so that the same number is recognised there.
const FINGERPRINT_LABEL: &str = "Master key fingerprint";

/// Switches to the terminal's alternate screen, clears it and moves to its top left (xterm
/// control sequences, also understood by tmux and most terminals).
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h\x1b[2J\x1b[H";
/// Clears the screen and puts the cursor at its top left (VT100 "erase in display" and "home").
const CLEAR_SCREEN: &str = "\x1b[2J\x1b[H";
/// Clears the alternate screen, then returns to the main screen with its earlier content. The
/// clear comes first so that the words also vanish where the alternate screen is not supported,
/// such as GNU screen without `altscreen on`.
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[2J\x1b[H\x1b[?1049l";

/// Set while secret words are on the alternate screen, so that Ctrl+C can leave it first.
static PRIVATE_SCREEN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the tool writes on the alternate screen now, a private screen or the steps of a command.
pub fn on_alternate_screen() -> bool {
    PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst)
}

/// Secrets on the terminal's alternate screen, as `less` shows a file: they never reach the main
/// screen or its scrollback, and dropping this clears them and returns to where the tool was. A
/// script, a pipe or a file gets none of this.
pub struct PrivateScreen {
    active: bool,
    /// A step of a command shown one step at a time (flow.rs), on the alternate screen it is
    /// already on: dropping it only clears the screen.
    step: bool,
}

impl PrivateScreen {
    /// A screen for typing secrets, which are shown there as they are typed. It needs the
    /// terminal on standard input and standard error only: the result may go to a file.
    pub fn enter(input: &Input, title: &str) -> Self {
        let screen = Self::enter_if(input, true);
        if screen.active {
            style::title(title);
            style::hint("Cleared when you are done; until then anyone who sees it can read it.");
        }
        screen
    }

    /// A screen for showing a secret result, such as a recovered phrase, which goes to standard
    /// output: it is used only when standard output is the terminal too.
    pub fn enter_to_show(input: &Input) -> Self {
        Self::enter_if(input, output_on_screen())
    }

    fn enter_if(input: &Input, output_allows: bool) -> Self {
        // A command shown one step at a time is on the alternate screen throughout: a private
        // screen is a step of its own there, cleared again when it ends.
        if flow::is_active() {
            flow::step();
            return Self {
                active: true,
                step: true,
            };
        }
        // Within a private screen, another one adds nothing: the outer one stays, and is left
        // and cleared only when it ends, so that nothing reaches the main screen in between.
        if PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst) {
            return Self {
                active: false,
                step: false,
            };
        }
        let active =
            output_allows && terminal_screen_possible(input) && hidden_input::control_sequences();
        if active {
            // Written raw: anstream would drop control sequences when NO_COLOR is set.
            write_control(ENTER_ALTERNATE_SCREEN);
            PRIVATE_SCREEN_ACTIVE.store(true, Ordering::SeqCst);
        }
        Self {
            active,
            step: false,
        }
    }

    /// Whether the secrets are on the alternate screen, which then waits for the person.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether what is printed now stays private: this screen is active, or it lies within one
    /// that is.
    pub fn shows_privately(&self) -> bool {
        self.active || PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst)
    }

    /// Clears the screen for what comes next, such as another password in its place.
    pub fn clear(&self) {
        if self.active {
            write_control(CLEAR_SCREEN);
        }
    }
}

/// Whether a person at a terminal can be shown a secret on a private screen: standard input,
/// output and error are the terminal, output and error the same one, and it can switch screens.
/// A command that must show a phrase only privately refuses otherwise, before anything secret is
/// asked (AUD-007-SEC001).
pub fn can_show_privately(input: &Input) -> bool {
    output_on_screen() && terminal_screen_possible(input)
}

/// The input of a command that shows a phrase only on a private screen: the terminal, or the
/// refusal `refused` where there can be none, before anything secret is asked (AUD-007-SEC001).
pub fn private_input(refused: &str) -> Result<Input, Failure> {
    let input = Input::terminal_only();
    if !can_show_privately(&input) {
        return Err(Failure::invalid_input(refused));
    }
    Ok(input)
}

/// Whether what goes to standard output appears on the terminal of standard error, on which the
/// private screen is switched and cleared: both are terminals, and the same one. Output sent to
/// another terminal counts as redirected (AUD-008-SEC004).
pub fn output_on_screen() -> bool {
    io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && hidden_input::output_on_error_terminal()
}

fn terminal_screen_possible(input: &Input) -> bool {
    !input.is_script()
        && io::stdin().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

/// Asks the person to write down what the private screen shows, and waits for Enter or Escape,
/// after which the screen is cleared: what it showed then leaves the terminal and its scrollback.
/// Every other key is ignored, so that a stray one cannot clear the screen too early.
pub fn wait_to_leave() -> Result<(), Failure> {
    wait_to_leave_saying("Write it down now: Enter or Escape clears this screen.")
}

/// [`wait_to_leave`] with another line above the wait, for a screen that needs no writing down.
pub fn wait_to_leave_saying(line: &str) -> Result<(), Failure> {
    eprintln!();
    style::warn_here(line, "");
    hidden_input::with_keys(|next_key| loop {
        match next_key()? {
            hidden_input::Key::Enter | hidden_input::Key::Quit => return Ok(()),
            _ => continue,
        }
    })
}

/// Reads a password on a private screen headed `title`, again until it is one that the
/// specification allows, and records it in the summary.
pub fn read_password(input: &mut Input, operation: Operation) -> Result<Password, Failure> {
    // A command may ask for a BIP39 passphrase or a new password too: say which secret this is.
    let (prompt, what) = match operation {
        Operation::Rekey => (
            "Old container password",
            "The password the container has now; the new one comes later.",
        ),
        _ => (
            "Container password",
            "The password the container was encrypted with; it is NOT a BIP39 passphrase.",
        ),
    };
    let screen = PrivateScreen::enter(input, operation.title());
    let (password, check) = loop {
        if screen.is_active() {
            eprintln!();
            style::hint(what);
            style::hint(check_word::FORGOTTEN_WORD_HINT);
        }
        let typed = input.password(prompt)?;
        // A mistyped word of a password with a check word is repaired here, before any Argon2 work.
        let (text, check) = match check_word::review(input, typed, &screen)? {
            Reviewed::Use(text, check) => (text, check),
            Reviewed::TypeAgain => {
                screen.clear();
                continue;
            }
        };
        if let Some(password) = input.accepted(Password::new(&text), TYPE_AGAIN)? {
            break (password, check);
        }
    };
    drop(screen);
    choice::record("Password", &check.record("typed"));
    Ok(password)
}

impl Drop for PrivateScreen {
    fn drop(&mut self) {
        if self.step {
            let _ = io::stdout().flush();
            write_control(CLEAR_SCREEN);
        } else if self.active {
            leave_private_screen();
        }
    }
}

/// Switches to the alternate screen for the steps of a command (flow.rs). False where they cannot
/// be shown privately, or within a screen that is already private.
pub fn enter_steps(input: &Input) -> bool {
    if PRIVATE_SCREEN_ACTIVE.load(Ordering::SeqCst)
        || !can_show_privately(input)
        || !hidden_input::control_sequences()
    {
        return false;
    }
    write_control(ENTER_ALTERNATE_SCREEN);
    PRIVATE_SCREEN_ACTIVE.store(true, Ordering::SeqCst);
    true
}

/// Returns from the steps of a command to the main screen, clearing what they showed.
pub fn leave_steps() {
    leave_private_screen();
}

/// Clears the screen for the next step of a command.
pub fn clear_screen() {
    let _ = io::stdout().flush();
    write_control(CLEAR_SCREEN);
}

fn leave_private_screen() {
    if PRIVATE_SCREEN_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = io::stdout().flush();
        write_control(LEAVE_ALTERNATE_SCREEN);
    }
}

fn write_control(sequence: &str) {
    let mut terminal = io::stderr();
    let _ = terminal.write_all(sequence.as_bytes());
    let _ = terminal.flush();
}

/// The question for a container: 24 words, or 12 to 21 for a same-length container.
pub const CONTAINER_PROMPT: &str = "Container, 24 words or as long as the original seed phrase: ";

/// Reads a container on a private screen headed `title`, as the phrase is read for an encryption:
/// it is a valid seed phrase too, so it is shown as it is typed, taken at once when it is valid,
/// and leaves no copy in the terminal's history. The summary records its length and its format,
/// the suite identifier, which the specification asks to show.
///
/// Where `card` says so, words typed as `?`, or words that are not a container, are repaired with
/// the container's repair words before it is read (`container_repair::review`).
///
/// A search for missing words asks for the container password; it comes back with the container,
/// so that the command does not ask for it again.
pub fn read_container(
    input: &mut Input,
    title: &str,
    card: CardAsked,
) -> Result<ReadContainer, Failure> {
    let screen = PrivateScreen::enter(input, title);
    let (container, reviewed) = loop {
        if screen.is_active() {
            eprintln!();
            // Where a word typed as ? can be repaired, the person is told so before typing.
            if !matches!(card, CardAsked::Never) {
                style::hint(container_repair::UNREADABLE_HINT);
            }
        }
        let typed = input.visible_words(CONTAINER_PROMPT, WordList::Bip39)?;
        let Some(reviewed) = container_repair::review(input, typed, card)? else {
            continue;
        };
        if let Some(container) =
            input.accepted(ContainerFacts::read(&reviewed.words), TYPE_AGAIN)?
        {
            break (container, reviewed);
        }
    };
    drop(screen);
    let words = container.word_count();
    choice::record("Container", &format!("{words} words, valid"));
    if let Some(repaired) = &reviewed.repaired {
        choice::record("Repaired", repaired);
    }
    // A same-length container gives another valid phrase for a wrong password instead of an
    // error; the result says so again where it matters.
    let suite = container.suite();
    let note = match suite {
        Suite::SameLength => " (no built-in check)",
        Suite::TwentyFourWords => "",
    };
    style::fact("Format", paint(MUTED, format!("{}{note}", suite.id())));
    Ok(ReadContainer {
        facts: container,
        password: reviewed.password,
        found_by: reviewed.found_by,
        repaired: reviewed.repaired,
    })
}

/// A container read, with what a search for its missing words brought: the password it asked for,
/// so that the command does not ask again, and what it matched.
pub struct ReadContainer {
    pub facts: ContainerFacts,
    pub password: Option<Password>,
    pub found_by: Option<String>,
    /// What was repaired, by the repair words or a search, as the summary records it.
    pub repaired: Option<String>,
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
            Some(seconds) => format!("about {} left", duration(seconds)),
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
            duration(self.stage_started.elapsed().as_secs())
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

    /// Only a command with --stdin is told to use it when there is no terminal (AUD-010).
    #[test]
    fn the_advice_without_a_terminal_names_only_what_the_command_has() {
        assert!(no_terminal_advice(true).contains("--stdin"));
        let without = no_terminal_advice(false);
        assert!(!without.contains("--stdin"), "{without}");
        assert!(without.contains("Run the command in a terminal"));
        assert!(Input::new(false).can_ask_again() && Input::terminal_only().can_ask_again());
    }

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
        let Err(failure) = read_bounded_line(&mut io::Cursor::new(too_long)) else {
            panic!("a longer line was accepted");
        };
        assert!(
            failure.message.contains("longer than"),
            "{}",
            failure.message
        );
    }
}
