//! Everything the tool reads from and shows to the person at the terminal.
//!
//! Secrets are typed on a private screen of their own, where they are shown as they are typed and
//! which is cleared once the person is done; anywhere else they are read without echo. Either way
//! they go into buffers that are locked and wiped when dropped. Results go to standard output;
//! prompts, progress and advice go to standard error, so a result can be piped on without the
//! messages.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use mhfe::memory::LockedText;
use mhfe::word_hints::WordList;
use mhfe::{ContainerFacts, MhfeError, Password, Suite};

use crate::check_word::{self, Reviewed};
use crate::choice::{self, Answer, Question};
use crate::container_repair::{self, CardAsked};
use crate::exit::{self, Failure};
use crate::flow;
use crate::hidden_input::{self, Content};
use crate::protect;
use crate::settings::Operation;
use crate::standard_input::StandardInput;
use crate::style::{self, paint, ACCENT, MUTED, STRONG};

mod control;
mod private_screen;
mod progress;

pub(crate) use control::write_control;
use private_screen::leave_private_screen;
pub(crate) use private_screen::{
    can_show_privately, clear_screen, enter_steps, leave_steps, on_alternate_screen,
    output_on_screen, private_input, wait_to_leave, PrivateScreen,
};
pub(crate) use progress::Progress;

/// Reserved line buffer, including room for CRLF: the library's typed-line buffer, which its
/// memory-locking check probes. The buffer is reserved at this size and reading stops there, so
/// it is never reallocated, which would leave an unwiped copy of a secret behind.
pub(crate) const LINE_CAPACITY: usize = mhfe::memory::TYPED_LINE_BYTES;

/// The same longest answer in scripted, visible and edited input, excluding its line ending.
pub(crate) const ANSWER_BYTES: usize = LINE_CAPACITY - 2;

/// The refusal of an answer beyond the common byte limit.
pub(crate) fn too_long_answer() -> Failure {
    Failure::invalid_input(format!(
        "An answer is longer than {ANSWER_BYTES} bytes; no valid answer is that long."
    ))
}

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
pub(crate) enum Input {
    /// A person at a terminal: secrets are hidden and a mistake can be corrected.
    /// `command_reads_stdin` tells whether the command has --stdin, so that a refusal for a
    /// missing terminal names it only where it exists (AUD-010).
    Terminal { command_reads_stdin: bool },
    /// A script: one answer per line on standard input, in the order the command documents.
    Script(StandardInput),
}

/// What a refusal of an answer typed at a terminal asks for.
pub(crate) const TYPE_AGAIN: &str = "Please type it again.";

impl Input {
    /// The input of a command that has --stdin: a script's lines on standard input when
    /// `from_standard_input`, a person at the terminal otherwise.
    pub(crate) fn new(from_standard_input: bool) -> Self {
        if from_standard_input {
            Self::Script(StandardInput::new())
        } else {
            Self::Terminal {
                command_reads_stdin: true,
            }
        }
    }

    /// The input of a command without --stdin, which only a person at a terminal answers.
    pub(crate) fn terminal_only() -> Self {
        Self::Terminal {
            command_reads_stdin: false,
        }
    }

    /// The input of a command that reads a secret: without --stdin, standard input must be a
    /// terminal, or the command says at once how to run it, before any question would take the
    /// lines of a pipe as answers (AUD-023-UI006).
    pub(crate) fn reading_secrets(self) -> Result<Self, Failure> {
        match self {
            Self::Terminal {
                command_reads_stdin,
            } if !io::stdin().is_terminal() => Err(Failure::invalid_input(no_terminal_advice(
                command_reads_stdin,
            ))),
            input => Ok(input),
        }
    }

    /// Refuses an interactive result on a terminal that cannot clear its private screen.
    ///
    /// Explicit script output and output redirected by the caller keep their export format.
    pub(crate) fn require_private_result(&self) -> Result<(), Failure> {
        if !self.is_script() && output_on_screen() && !can_show_privately(self) {
            return Err(Failure::invalid_input(
                "This command can show its result only on a private screen. Use a capable \
                 terminal, or redirect the output to a file.",
            ));
        }
        Ok(())
    }

    /// Whether a wrong answer can be asked again.
    pub(crate) fn can_ask_again(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }

    /// An answer as `read` took it: `Some` when it was accepted. A refusal is shown at a terminal,
    /// which asks again (`None`), with `then` saying what to do, and ends a script, which cannot.
    pub(crate) fn accepted<T, E: Into<MhfeError>>(
        &self,
        read: Result<T, E>,
        then: &str,
    ) -> Result<Option<T>, Failure> {
        match read.map_err(Into::into) {
            Ok(value) => Ok(Some(value)),
            Err(error) if self.can_ask_again() => {
                style::retry(exit::refused(&error, then));
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn is_script(&self) -> bool {
        matches!(self, Self::Script(_))
    }

    /// Reads a secret of free text, such as a BIP39 passphrase: at a terminal, shown as it is
    /// typed on the private screen and hidden anywhere else; from a script, the next line.
    /// `question` has no colon: "Password" is asked as "Password: ", or as "Password (hidden): ".
    pub(crate) fn secret(&mut self, question: &str) -> Result<LockedText, Failure> {
        self.secret_of(question, Content::Text)
    }

    /// Reads a password as [`Input::secret`] does; where it is shown, the words of the EFF list
    /// that begin with the word being typed are hinted below it.
    pub(crate) fn password(&mut self, question: &str) -> Result<LockedText, Failure> {
        self.secret_of(question, Content::Password)
    }

    /// Reads secret words of `list`, such as a seed phrase, as [`Input::secret`] does; where they
    /// are shown, the words of the list are hinted below them, Tab completes one and Ctrl+W deletes
    /// one.
    pub(crate) fn secret_words(
        &mut self,
        question: &str,
        list: WordList,
    ) -> Result<LockedText, Failure> {
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
    pub(crate) fn visible(&mut self, prompt: &str) -> Result<LockedText, Failure> {
        match self {
            Self::Terminal { .. } => {
                style::prompt(prompt);
                io::stderr().flush()?;
                match read_bounded_line(&mut StandardInput::new())? {
                    Some(line) => Ok(line),
                    None => Err(MhfeError::Cancelled.into()),
                }
            }
            Self::Script(lines) => read_script_line(lines, prompt),
        }
    }

    /// Reads public words of `list`, such as a container phrase, shown while typed. At a terminal
    /// that carries out control sequences the words of the list are hinted below them, Tab
    /// completes one and Ctrl+W deletes one; elsewhere as [`Input::visible`].
    pub(crate) fn visible_words(
        &mut self,
        prompt: &str,
        list: WordList,
    ) -> Result<LockedText, Failure> {
        let hinted = matches!(self, Self::Terminal { .. }) && hidden_input::can_redraw();
        if !hinted {
            return self.visible(prompt);
        }
        match hidden_input::read_line(prompt, true, Content::Words(list))? {
            Some(line) => Ok(line),
            None => Err(MhfeError::Cancelled.into()),
        }
    }

    /// Asks a question with a few fixed answers and returns the index of the chosen one; the first
    /// is the default. A person at a terminal chooses from a list with the arrow keys. A script,
    /// or a terminal that cannot redraw lines, gets the answers numbered and types the number on a
    /// line of its own, or nothing for the first.
    pub(crate) fn choose(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        flow::step()?;
        self.choose_here(question, answers)
    }

    /// [`Input::choose`] below what the screen shows already (choice::choose_here).
    pub(crate) fn choose_here(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        if !self.is_script() && hidden_input::can_redraw() {
            return choice::choose_here(question, answers, None)?
                .ok_or_else(|| MhfeError::Cancelled.into());
        }
        self.choose_numbered(question, answers, true)
    }

    /// [`Input::choose`] with no default, for an answer that must be the person's own: no answer
    /// is highlighted in the list, and the numbered form takes no empty line for the first.
    pub(crate) fn choose_without_default(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        flow::step()?;
        self.choose_here_without_default(question, answers)
    }

    /// [`Input::choose_without_default`] below what the screen shows already
    /// (choice::choose_here_without_default).
    pub(crate) fn choose_here_without_default(
        &mut self,
        question: &Question,
        answers: &[Answer],
    ) -> Result<usize, Failure> {
        if !self.is_script() && hidden_input::can_redraw() {
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
            let note = if answer.note().is_empty() {
                String::new()
            } else {
                format!(" {}", paint(MUTED, format!("({})", answer.note())))
            };
            eprintln!(
                "  {} {}{note}",
                paint(ACCENT, format!("{}.", number + 1)),
                answer.label()
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
pub(crate) struct Step {
    /// Lines drawn since the step began, its blank line included.
    lines: usize,
    erasable: bool,
}

impl Step {
    pub(crate) fn start(input: &Input) -> Result<Self, Failure> {
        if input.is_script() {
            return Ok(Self {
                lines: 0,
                erasable: false,
            });
        }
        if flow::is_active() {
            // On a screen of its own, the step needs no erasing.
            flow::step()?;
            return Ok(Self {
                lines: 0,
                erasable: false,
            });
        }
        eprintln!();
        Ok(Self {
            lines: 1,
            erasable: hidden_input::can_redraw(),
        })
    }

    pub(crate) fn retry(&mut self, text: impl std::fmt::Display) {
        self.lines += style::retry(text);
    }

    /// Reads a public answer, which the terminal shows after the prompt and may wrap.
    pub(crate) fn visible(
        &mut self,
        input: &mut Input,
        prompt: &str,
    ) -> Result<LockedText, Failure> {
        let answer = input.visible(prompt)?;
        if !input.is_script() {
            // The answer is measured in place: no copy of it is made.
            self.lines += style::rows_of_cells(
                style::visible_width(prompt) + style::visible_width(&answer),
                hidden_input::columns_or_default(),
            );
        }
        Ok(answer)
    }

    /// Erases the step; the caller then writes its line of the summary.
    pub(crate) fn finish(self) -> Result<(), Failure> {
        if self.erasable {
            write_control(&choice::redraw_from(self.lines))?;
        }
        Ok(())
    }
}

/// Set while a container is on the screen whose check has not finished, so that Ctrl+C can say so.
static UNVERIFIED_CONTAINER_SHOWN: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_unverified_container_shown(shown: bool) {
    UNVERIFIED_CONTAINER_SHOWN.store(shown, Ordering::SeqCst);
}

/// Ctrl+C ends the tool at once, also in the middle of an Argon2 round that may take hours at
/// a high PIM. The operating system then discards all of the tool's memory, including the
/// Argon2 work area and every secret. If a hidden prompt has switched the echo off, the terminal
/// is restored first, and a private screen is left. Ctrl+\, Ctrl+Z, a closed terminal (SIGHUP) and
/// SIGTERM end it the same way, so that none leaves a secret on the screen (AUD-015-SEC004).
pub(crate) fn stop_on_ctrl_c() {
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

pub(crate) fn exit_cancelled() -> ! {
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
pub(crate) fn show_cancelled() {
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
    let shown = on_alternate_screen();
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

fn read_script_line(lines: &mut StandardInput, prompt: &str) -> Result<LockedText, Failure> {
    read_bounded_line(lines)?.ok_or_else(|| {
        Failure::invalid_input(format!(
            "Standard input ended before this answer: {}",
            prompt.trim_end_matches([' ', ':'])
        ))
    })
}

/// Reads an answer of at most ANSWER_BYTES bytes into the reserved, locked LINE_CAPACITY buffer,
/// without its line break. `None` means that the input had ended. A longer line is refused, and
/// what was read of it is wiped with the buffer, so the buffer never grows.
///
/// The reader takes from standard input only what the line needs, and on Unix keeps no copy of it
/// (standard_input.rs); on Windows the standard library keeps its own buffer, which it does not
/// wipe.
fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<LockedText>, Failure> {
    let mut read = 0;
    // Locked before anything is read into it: a script's line may be a password or a phrase.
    let line = LockedText::build(LINE_CAPACITY, |line| {
        read = reader
            .take(LINE_CAPACITY as u64)
            .read_line(line)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    Failure::invalid_input("The answer is not valid UTF-8 text.")
                } else {
                    error.into()
                }
            })?;
        strip_line_ending(line);
        if line.len() > ANSWER_BYTES {
            return Err(too_long_answer());
        }
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
pub(crate) fn print_phrase(phrase: &str, wallet: Wallet, input: &Input) -> Result<(), Failure> {
    if input.is_script() {
        return style::out(phrase);
    }
    for line in style::boxed_words(phrase) {
        style::out(format_args!("{}", *line))?;
    }
    eprintln!("{}", paint(MUTED, "On one line, for copying:"));
    style::out(phrase)?;
    print_fingerprint(phrase, wallet);
    Ok(())
}

/// Shows accepted spellings before their input screen is cleared. A secret is shown only on
/// the private screen; a script receives no extra output or question.
pub(crate) fn read_back(
    input: &Input,
    typed: &str,
    words: &str,
    secret: bool,
) -> Result<(), Failure> {
    if input.is_script() || !spelling_needs_read_back(typed, words) {
        return Ok(());
    }
    if secret && !on_alternate_screen() {
        style::hint("The accepted words were not shown: a private screen is unavailable.");
        return Ok(());
    }
    eprintln!();
    style::hint("Accepted words, written out:");
    for line in style::boxed_words(words) {
        eprintln!("{}", *line);
    }
    if hidden_input::can_redraw() {
        private_screen::wait_to_leave_saying(READ_BACK_PROMPT)
    } else {
        input_read_back_without_redraw()
    }
}

/// The read-back wait is distinct from a secret input and never records its answer.
fn input_read_back_without_redraw() -> Result<(), Failure> {
    style::hint(READ_BACK_PROMPT);
    let mut input = Input::terminal_only();
    loop {
        if input.visible("Enter: ")?.is_empty() {
            return Ok(());
        }
    }
}

/// The person checks the spelling before the next question. Escape clears a capable screen too.
pub(crate) const READ_BACK_PROMPT: &str = "Check the written-out words; Enter continues.";

fn spelling_needs_read_back(typed: &str, words: &str) -> bool {
    !typed.split_whitespace().eq(words.split_whitespace()) || words.split_whitespace().any(|word|
        matches!(WordList::Bip39.hint(word), mhfe::word_hints::Hint::Words(matches) if matches.len() > 1)
    )
}

/// The wallet a phrase shown opens, whose master key fingerprint is shown under it.
pub(crate) enum Wallet<'a> {
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
    // A container's own fingerprint comes from the library's one rule for it.
    let fingerprint = match wallet {
        Wallet::Container => mhfe::ContainerFacts::read(phrase)
            .map_err(MhfeError::from)
            .and_then(|facts| facts.fingerprint()),
        _ => mhfe::wallet::Fingerprint::of(phrase, passphrase).map_err(MhfeError::from),
    };
    // Every phrase shown is a valid BIP39 phrase. Should the fingerprint fail all the same, the
    // phrase above is what matters, so it stands without one.
    let Ok(fingerprint) = fingerprint.map(|fingerprint| fingerprint.to_string()) else {
        return;
    };
    eprintln!(
        "{} {}  {}",
        paint(MUTED, FINGERPRINT_LABEL),
        paint(STRONG, fingerprint),
        paint(MUTED, format!("({which})"))
    );
    style::hint(style::FINGERPRINT_NOTE);
}

/// The name `mhfe check --fingerprint` asks for, so that the same number is recognised there.
const FINGERPRINT_LABEL: &str = "Master key fingerprint";

/// Reads a password on a private screen headed `title`, again until it is one that the
/// specification allows, and records it in the summary.
pub(crate) fn read_password(input: &mut Input, operation: Operation) -> Result<Password, Failure> {
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
    let screen = PrivateScreen::enter(input, operation.title())?;
    let (password, check) = loop {
        if !input.is_script() {
            eprintln!();
            style::hint(what);
            style::hint(check_word::FORGOTTEN_WORD_HINT);
        }
        let typed = input.password(prompt)?;
        // A mistyped word of a password with a check word is repaired here, before any Argon2 work.
        let (text, check) = match check_word::review(input, typed, &screen)? {
            Reviewed::Use(text, check) => (text, check),
            Reviewed::TypeAgain => {
                screen.clear()?;
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

/// The question for a container: 24 words, or 12 to 21 for a same-length container.
pub(crate) const CONTAINER_PROMPT: &str =
    "Container, 24 words or as long as the original seed phrase: ";

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
pub(crate) fn read_container(
    input: &mut Input,
    title: &str,
    card: CardAsked,
) -> Result<ReadContainer, Failure> {
    read_container_for(input, title, card, |_| Ok(()))
}

/// Reads a container usable by this command; a refused typed answer is asked again.
pub(crate) fn read_container_for(
    input: &mut Input,
    title: &str,
    card: CardAsked,
    require: impl Fn(&ContainerFacts) -> Result<(), MhfeError>,
) -> Result<ReadContainer, Failure> {
    let screen = PrivateScreen::enter(input, title)?;
    let (container, reviewed) = loop {
        if !input.is_script() {
            eprintln!();
            // Where a word typed as ? can be repaired, the person is told so before typing.
            if !matches!(card, CardAsked::Never) {
                style::hint(container_repair::UNREADABLE_HINT);
            }
        }
        let typed = input.visible_words(CONTAINER_PROMPT, WordList::Bip39)?;
        // The repair can replace the spelling with canonical words. Keep the original only in
        // a wiping owner until its accepted spelling has been checked on this input screen.
        let spelling = LockedText::copy_of(&typed);
        let Some(reviewed) = container_repair::review(input, typed, card.clone())? else {
            continue;
        };
        let read = ContainerFacts::read(reviewed.words())
            .map_err(MhfeError::from)
            .and_then(|container| {
                require(&container)?;
                Ok(container)
            });
        if let Some(container) = input.accepted(read, TYPE_AGAIN)? {
            read_back(input, &spelling, container.words(), false)?;
            break (container, reviewed);
        }
    };
    drop(screen);
    let words = container.word_count();
    choice::record("Container", &format!("{words} words, valid"));
    if let Some(repaired) = reviewed.repaired() {
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
    let (_, repaired, password, found_by) = reviewed.into_parts();
    Ok(ReadContainer {
        facts: container,
        password,
        found_by,
        repaired,
    })
}

/// A container read, with what a search for its missing words brought: the password it asked for,
/// so that the command does not ask again, and what it matched.
pub(crate) struct ReadContainer {
    facts: ContainerFacts,
    password: Option<Password>,
    found_by: Option<String>,
    /// What was repaired, by the repair words or a search, as the summary records it.
    repaired: Option<String>,
}

impl ReadContainer {
    pub(crate) fn facts(&self) -> &ContainerFacts {
        &self.facts
    }
    pub(crate) fn repaired(&self) -> Option<&str> {
        self.repaired.as_deref()
    }
    /// Move owners into the command that consumes them; no secret text is copied.
    pub(crate) fn into_parts(
        self,
    ) -> (
        ContainerFacts,
        Option<Password>,
        Option<String>,
        Option<String>,
    ) {
        (self.facts, self.password, self.found_by, self.repaired)
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
        for ending in ["\n", "\r\n", ""] {
            let longest = format!("{}{ending}", "a".repeat(ANSWER_BYTES));
            let line = read_bounded_line(&mut io::Cursor::new(longest))
                .unwrap()
                .unwrap();
            assert_eq!(line.len(), ANSWER_BYTES);
            assert_eq!(
                line.capacity(),
                LINE_CAPACITY,
                "the buffer was never reallocated"
            );
        }
    }

    #[test]
    fn a_longer_line_is_refused() {
        let too_long = format!("{}\n", "a".repeat(ANSWER_BYTES + 1));
        let Err(failure) = read_bounded_line(&mut io::Cursor::new(too_long)) else {
            panic!("a longer line was accepted");
        };
        assert_eq!(failure.message(), too_long_answer().message());
    }

    #[test]
    fn invalid_utf8_on_standard_input_is_an_input_refusal() {
        let Err(failure) = read_bounded_line(&mut io::Cursor::new(b"\xff\n")) else {
            panic!("invalid UTF-8 was accepted");
        };
        assert_eq!(failure.exit_code(), crate::exit::INVALID_INPUT);
        assert_eq!(failure.message(), "The answer is not valid UTF-8 text.");
    }
}
