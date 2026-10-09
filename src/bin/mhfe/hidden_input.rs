//! Reads one line from the terminal without changing it: hidden, or, on the private screen,
//! shown as it is typed.
//!
//! The specification requires a password with a control character, such as TAB, NUL or U+0085,
//! to be refused, never cleaned. A reader that swallowed such characters would encrypt with a
//! different password from the one that was typed or pasted. So every character is kept as
//! data, except these keys, which keep their usual meaning:
//!
//! - Backspace deletes the last character and Ctrl+U the whole line;
//! - Enter ends the line, and Ctrl+D on an empty line ends the input;
//! - Ctrl+C cancels the tool.
//!
//! A line of words, such as a seed phrase, is no password, so two more keys edit it there: Tab
//! completes the word being typed as far as the words of its list agree, and Ctrl+W deletes the
//! last word.
//!
//! A line that is shown is shown as the person types it, except its control characters: they are
//! kept for the password check to refuse, but never written to the terminal, which would act on
//! them. Below a shown line of words or a password, a hint lists the words of its list that begin
//! with the word being typed (typed_line.rs).
//!
//! On Unix and on Windows the terminal's own line editing is switched off and this module edits
//! the line itself, so both behave the same. A terminal's line mode would otherwise act on further
//! keys (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O, Ctrl+\, Ctrl+Z) and, on Linux, cut a line
//! after 4095 bytes, although a valid password can take 4096 bytes before normalization (1024
//! characters that NFKD turns into one byte each). scripts/verify-hidden-input.py checks this in a
//! Unix pseudo-terminal and scripts/verify-hidden-input-windows.py in a Windows pseudo-console.
//!
//! The menu that `mhfe` shows when it starts without arguments reads single keys in the same
//! terminal mode: [`with_keys`].

// Changing the terminal settings needs the operating system's terminal calls, which Rust offers
// only through unsafe foreign functions.
#![allow(unsafe_code)]

use std::io::{self, BufRead, IsTerminal};
use std::sync::Mutex;
use std::time::Duration;

use mhfe::memory::{LockedBytes, LockedText};
use mhfe::self_check::{ComponentCheck, ComponentOutcome, Tier};
use mhfe::word_hints::WordList;
use zeroize::Zeroizing;

use crate::exit::Failure;
use crate::typed_line::{self, Hints, LineScreen};

/// The terminal settings to restore while a hidden prompt has changed them. Whoever changes or
/// restores the terminal holds this lock, so the Ctrl+C handler and a prompt never interleave.
static SAVED: Mutex<Option<platform::Settings>> = Mutex::new(None);

/// What a line holds, which decides the keys that edit it and the hints below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// Free text, such as a BIP39 passphrase: no hints, and every other key is data.
    Text,
    /// A password: every other key is data, and where it is shown the words of the EFF list are
    /// hinted, but not a word the list lacks, as a password may hold any text.
    Password,
    /// Words of a list, such as a seed phrase: hinted where shown; Tab completes a word and Ctrl+W
    /// deletes one.
    Words(WordList),
}

impl Content {
    fn hints(self) -> Option<Hints> {
        match self {
            Self::Text => None,
            Self::Password => Some(Hints {
                list: WordList::Eff,
                says_no_word: false,
            }),
            Self::Words(list) => Some(Hints {
                list,
                says_no_word: true,
            }),
        }
    }

    /// The list that Tab completes from, in a line of words only.
    fn completes_from(self) -> Option<WordList> {
        match self {
            Self::Words(list) => Some(list),
            Self::Text | Self::Password => None,
        }
    }
}

/// Switches the terminal to reading single bytes without its own echo, writes `prompt`, reads one
/// line of `content` as described above, shown as it is typed when `shown` is true, and restores
/// the terminal, also when reading fails. `None` means that the input was closed. The terminal is
/// switched before the prompt appears, so that a key typed or text pasted as soon as the prompt
/// shows is already read as data. On Windows the standard library turns the console's UTF-16
/// characters into UTF-8 bytes.
pub fn read_line(
    prompt: &str,
    shown: bool,
    content: Content,
) -> Result<Option<LockedText>, Failure> {
    let result = with_terminal_switched(platform::hide, || {
        crate::style::prompt(prompt);
        io::Write::flush(&mut io::stderr())?;
        if !shown {
            return edit_line(&mut io::stdin().lock(), None, content);
        }
        let (mut controls, mut text) = (io::stderr(), anstream::stderr());
        // The prompt's cells by the same rule as the characters typed after it.
        let width = typed_line::text_cells(prompt);
        // When the width cannot be read, the usual 80 columns.
        let columns = columns().unwrap_or(80);
        let mut screen = LineScreen::new(&mut controls, &mut text, width, columns, content.hints());
        edit_line(&mut io::stdin().lock(), Some(&mut screen), content)
    });
    // The terminal did not show the Enter key either.
    anstream::eprintln!();
    result
}

/// A key that the menu acts on.
#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    /// A digit key from 1 to 9.
    Digit(u8),
    /// ?, which asks for an explanation.
    Help,
    /// Escape alone, q, Ctrl+D or the end of the input. q is an alias: a keyboard layout may have
    /// no q key, where that key types another letter.
    Quit,
    /// Any other key, which the menu ignores.
    Other,
}

/// Switches the terminal to single keys without echo, as for a hidden line, runs `choose` with a
/// function that reads the next key, and restores the terminal, also when `choose` fails.
pub fn with_keys<T>(
    choose: impl FnOnce(&mut dyn FnMut() -> Result<Key, Failure>) -> Result<T, Failure>,
) -> Result<T, Failure> {
    with_terminal_switched(platform::single_keys, || {
        let mut keys = TerminalKeys::new(io::stdin().lock());
        choose(&mut || read_key(&mut keys))
    })
}

/// Switches the terminal with `switch`, runs `body` and restores the terminal, also when `body`
/// fails. The original settings are saved before the switch, so that Ctrl+C can restore them.
fn with_terminal_switched<T>(
    switch: fn(&platform::Settings) -> Result<(), Failure>,
    body: impl FnOnce() -> Result<T, Failure>,
) -> Result<T, Failure> {
    let original = platform::current()?;
    {
        let mut saved = lock_saved();
        *saved = Some(original);
        if let Err(error) = switch(&original) {
            saved.take();
            platform::restore(&original);
            return Err(error);
        }
    }
    let result = body();
    if let Some(original) = lock_saved().take() {
        platform::restore(&original);
    }
    result
}

/// For the Ctrl+C handler: restores the terminal if a hidden prompt changed it, and keeps the lock
/// until `exit` has ended the tool, so that no new prompt can change the terminal in between.
pub fn restore_and_exit(exit: fn() -> !) -> ! {
    let mut saved = lock_saved();
    if let Some(original) = saved.take() {
        platform::restore(&original);
    }
    exit()
}

fn lock_saved() -> std::sync::MutexGuard<'static, Option<platform::Settings>> {
    // A panic while the lock was held cannot leave the saved settings half-written.
    SAVED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn terminal_error(action: &str) -> Failure {
    let error = io::Error::last_os_error();
    Failure::from(io::Error::new(
        error.kind(),
        format!("could not {action} the terminal: {error}"),
    ))
}

/// The refusal when the terminal, asked to stop echoing, reads back with its echo or its own line
/// editing still on: a secret typed then would be shown, so none is read.
fn echo_stays_on() -> Failure {
    Failure::internal("The terminal did not turn its echo off; no secret was read.")
}

/// The identifier of [`HiddenInputCheck`] in a self-check report.
pub const HIDDEN_INPUT_ID: &str = "hidden-input";

/// The `hidden-input` check of the full self-test: the terminal on standard input is switched as
/// for a hidden prompt, read back and restored. Every prompt for a secret reads the switch back as
/// well and refuses to read when the echo stays on.
pub struct HiddenInputCheck;

impl ComponentCheck for HiddenInputCheck {
    fn id(&self) -> &'static str {
        HIDDEN_INPUT_ID
    }

    fn label(&self) -> &'static str {
        "Hidden input"
    }

    /// Only on request: the check at start never touches the terminal, so that nothing typed
    /// ahead is changed before the first prompt.
    fn runs_at(&self, tier: Tier) -> bool {
        tier == Tier::Full
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        if !io::stdin().is_terminal() {
            return ComponentOutcome::NotAvailable("no terminal".to_owned());
        }
        match with_terminal_switched(platform::hide, || Ok(())) {
            Ok(()) => ComponentOutcome::Passed,
            Err(_) => ComponentOutcome::Failed("the terminal did not turn its echo off".to_owned()),
        }
    }
}

/// The keys that edit a hidden line; every other byte is kept.
mod keys {
    pub const BACKSPACE: u8 = 0x08;
    pub const DELETE: u8 = 0x7f;
    pub const CTRL_U: u8 = 0x15;
    /// In a line of words only: elsewhere it is data.
    pub const CTRL_W: u8 = 0x17;
    /// In a line of words only: elsewhere it is data.
    pub const TAB: u8 = b'\t';
    pub const CTRL_D: u8 = 0x04;
    /// Normally the terminal turns Ctrl+C into a signal; should the byte arrive, it quits too.
    pub const CTRL_C: u8 = 0x03;
    pub const ESCAPE: u8 = 0x1b;
}

/// The width of the terminal on standard error, in columns, or `None` when it cannot be read.
pub fn columns() -> Option<usize> {
    platform::columns()
}

/// Whether the terminal on standard error carries out control sequences such as the switch to the
/// alternate screen; on Windows the console is asked to do so first.
pub fn control_sequences() -> bool {
    platform::control_sequences()
}

/// Whether standard output and standard error are one terminal, so that the private screen,
/// switched and cleared through standard error, also holds and clears what goes to standard output.
/// Output redirected to another terminal would stay there, on its main screen (AUD-008-SEC004).
pub fn output_on_error_terminal() -> bool {
    platform::output_on_error_terminal()
}

/// How long a lone Escape waits for the rest of an escape sequence. A terminal sends an arrow
/// key's sequence at once, so an Escape that nothing follows within this time is the Escape key;
/// MnemoCode waits as long (ESCAPE_DELAY_MS in its src/cli/terminal-input.ts).
const ESCAPE_DELAY: Duration = Duration::from_millis(100);

/// Where keys come from: their bytes, and whether more bytes follow at once, which tells the
/// Escape key from the start of an escape sequence.
trait KeySource {
    /// One byte, or `None` at the end of the input.
    fn next_byte(&mut self) -> Result<Option<u8>, Failure>;
    /// Whether another byte is there or arrives within `delay`.
    fn more_within(&mut self, delay: Duration) -> Result<bool, Failure>;
}

/// The keys typed at the terminal. Whatever the standard library has read from the terminal is
/// taken over at once, so that its buffer stays empty and only the operating system needs to be
/// asked whether more is coming. Bytes still here when a choice ends are dropped with this
/// reader: a key pressed once too often must not end up in the next answer, such as a password.
struct TerminalKeys<'a> {
    input: io::StdinLock<'a>,
    /// Bytes taken over and not yet read; wiped when dropped, as they could be typed-ahead text.
    pending: Zeroizing<Vec<u8>>,
    next: usize,
}

impl<'a> TerminalKeys<'a> {
    fn new(input: io::StdinLock<'a>) -> Self {
        Self {
            input,
            // Reserved at the size of the standard library's buffer, whose contents it takes
            // whole, so that it is never reallocated and leaves no unwiped copy.
            pending: Zeroizing::new(Vec::with_capacity(crate::terminal::LINE_CAPACITY)),
            next: 0,
        }
    }
}

impl KeySource for TerminalKeys<'_> {
    fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
        if self.next == self.pending.len() {
            self.pending.clear();
            self.next = 0;
            let available = loop {
                match self.input.fill_buf() {
                    Ok(bytes) => break bytes,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let taken = available.len();
            self.pending.extend_from_slice(available);
            self.input.consume(taken);
        }
        let byte = self.pending.get(self.next).copied();
        self.next += usize::from(byte.is_some());
        Ok(byte)
    }

    fn more_within(&mut self, delay: Duration) -> Result<bool, Failure> {
        Ok(self.next < self.pending.len() || platform::input_within(delay)?)
    }
}

/// Reads one key from raw terminal bytes. The arrow keys send the VT escape sequences ESC [ A and
/// ESC [ B, or ESC O A and ESC O B in a terminal's application mode. Every other escape sequence is
/// read to its end and ignored, so that no byte of it, such as the 5 of Ctrl+Up (ESC [ 1 ; 5 A),
/// is taken for a key of its own. An ESC that nothing follows at once is the Escape key.
fn read_key(keys: &mut impl KeySource) -> Result<Key, Failure> {
    use keys::{CTRL_C, CTRL_D, ESCAPE};

    let Some(byte) = keys.next_byte()? else {
        return Ok(Key::Quit);
    };
    let key = match byte {
        b'\r' | b'\n' => Key::Enter,
        b'1'..=b'9' => Key::Digit(byte - b'0'),
        b'?' => Key::Help,
        b'q' | b'Q' | CTRL_D | CTRL_C => Key::Quit,
        ESCAPE if !keys.more_within(ESCAPE_DELAY)? => Key::Quit,
        ESCAPE => match keys.next_byte()? {
            Some(b'[') => read_control_sequence(keys)?,
            Some(b'O') => arrow(keys.next_byte()?),
            _ => Key::Other,
        },
        _ => Key::Other,
    };
    Ok(key)
}

/// The rest of a control sequence after ESC [: parameter and intermediate bytes, then one final
/// byte from @ to ~ (ECMA-48). Only an arrow key without parameters counts.
fn read_control_sequence(keys: &mut impl KeySource) -> Result<Key, Failure> {
    const FINAL_BYTES: std::ops::RangeInclusive<u8> = 0x40..=0x7e;
    let mut has_parameters = false;
    loop {
        match keys.next_byte()? {
            None => return Ok(Key::Quit),
            Some(byte) if FINAL_BYTES.contains(&byte) => {
                return Ok(if has_parameters {
                    Key::Other
                } else {
                    arrow(Some(byte))
                })
            }
            Some(_) => has_parameters = true,
        }
    }
}

fn arrow(final_byte: Option<u8>) -> Key {
    match final_byte {
        Some(b'A') => Key::Up,
        Some(b'B') => Key::Down,
        _ => Key::Other,
    }
}

/// Edits a line of `content` from raw terminal bytes: Backspace or Delete removes the last
/// character, Ctrl+U the whole line, Enter (CR or LF) ends it, and Ctrl+D on an empty line or the
/// end of the input gives `None`; in a line of words, Tab completes the last word and Ctrl+W
/// deletes it. Every other byte is kept. The buffer is reserved at its largest size and never
/// grows, so it leaves no unwiped copy; a longer line is refused. On `screen`, every complete
/// character that is not a control character is shown as it arrives, the editing keys take off
/// what they remove, and the hint follows each change. The line keeps the lock of its buffer, and
/// a line that ends in any other way, refused or closed, is wiped before its pages are unlocked
/// (AUD-010).
fn edit_line(
    reader: &mut impl io::Read,
    screen: Option<&mut LineScreen>,
    content: Content,
) -> Result<Option<LockedText>, Failure> {
    use crate::terminal::LINE_CAPACITY;

    let mut closed = false;
    // Locked before anything is typed into it: the line may be a password or a phrase.
    let line = LockedBytes::build(LINE_CAPACITY, |line| {
        closed = LineEditor::new(screen, content, line).edit(reader)?;
        Ok::<(), Failure>(())
    })?;
    crate::terminal::note_unlocked(line.is_locked());
    if closed {
        return Ok(None);
    }
    // In the same buffer, under the same lock.
    match line.into_text() {
        Ok(text) => Ok(Some(text)),
        Err(_) => Err(Failure::invalid_input(
            "The answer is not valid UTF-8 text.",
        )),
    }
}

/// The editing of [`edit_line`], into `line`, whose capacity it never exceeds.
struct LineEditor<'e, 's> {
    screen: Option<&'e mut LineScreen<'s>>,
    content: Content,
    line: &'e mut Vec<u8>,
    /// Every character of the line as it was taken: its bytes, so that a removal takes off exactly
    /// those, also of bytes that are not UTF-8, and whether it was shown, as only those are taken
    /// off the screen.
    entries: Vec<Entry>,
    /// Where the character still arriving begins: a UTF-8 character comes one byte at a time.
    complete: usize,
}

impl<'e, 's> LineEditor<'e, 's> {
    fn new(
        screen: Option<&'e mut LineScreen<'s>>,
        content: Content,
        line: &'e mut Vec<u8>,
    ) -> Self {
        Self {
            screen,
            content,
            line,
            entries: Vec::with_capacity(crate::terminal::LINE_CAPACITY),
            complete: 0,
        }
    }

    /// Edits until the line ends; returns whether the person closed the input instead.
    fn edit(&mut self, reader: &mut impl io::Read) -> Result<bool, Failure> {
        use keys::{BACKSPACE, CTRL_D, CTRL_U, CTRL_W, DELETE, TAB};

        let mut byte = Zeroizing::new([0u8; 1]);
        loop {
            match reader.read(&mut byte[..]) {
                Ok(0) if self.line.is_empty() => return Ok(true),
                Ok(0) => return self.end(),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
            let words = self.content.completes_from();
            match (byte[0], words) {
                (b'\r' | b'\n', _) => return self.end(),
                // The first bytes of a character that has not arrived whole go without a trace.
                (BACKSPACE | DELETE, _) if self.complete < self.line.len() => {
                    self.line.truncate(self.complete)
                }
                (BACKSPACE | DELETE, _) => self.remove(1)?,
                (CTRL_U, _) => self.remove(self.entries.len())?,
                (CTRL_W, Some(_)) => self.remove(self.last_word())?,
                (TAB, Some(list)) => self.complete_word(list)?,
                (CTRL_D, _) if self.line.is_empty() => return Ok(true),
                (other, _) => self.push(other)?,
            }
        }
    }

    /// Ends the line, and the hint below it goes. Returns that the input was not closed.
    fn end(&mut self) -> Result<bool, Failure> {
        if let Some(screen) = self.screen.as_mut() {
            screen.finish()?;
        }
        Ok(false)
    }

    /// Adds a byte of a character. A complete character is shown unless it is a control
    /// character, and the hint follows.
    fn push(&mut self, byte: u8) -> Result<(), Failure> {
        use crate::terminal::LINE_CAPACITY;
        if self.line.len() == LINE_CAPACITY {
            return Err(Failure::invalid_input(format!(
                "An answer is longer than {LINE_CAPACITY} bytes; no valid answer is that long."
            )));
        }
        self.line.push(byte);
        match std::str::from_utf8(&self.line[self.complete..]) {
            Ok(character) => {
                let shown = !character.chars().any(not_shown);
                if let (true, Some(screen)) = (shown, self.screen.as_mut()) {
                    screen.add(character)?;
                }
                self.take(shown);
                self.show_hint()?;
            }
            // The rest of the character is still to come.
            Err(error) if error.error_len().is_none() => {}
            // Not UTF-8: kept, so that the whole answer is refused, and not shown.
            Err(_) => self.take(false),
        }
        Ok(())
    }

    /// Records the bytes since the last whole character as one character, `shown` or not.
    fn take(&mut self, shown: bool) {
        // A character has at most four bytes, and an invalid sequence is taken at its first
        // invalid byte, so the count fits.
        let bytes = (self.line.len() - self.complete) as u8;
        self.entries.push(Entry { bytes, shown });
        self.complete = self.line.len();
    }

    /// Removes the last `characters` whole characters, and from the screen those it showed. A
    /// combining mark taken off changes the cell of the character before it, which a terminal
    /// does not redraw by itself, so that cell is drawn again (AUD-018).
    fn remove(&mut self, characters: usize) -> Result<(), Failure> {
        // The first bytes of a character that has not arrived whole go first, without a trace.
        self.line.truncate(self.complete);
        let mut taken_off = 0;
        let mut mark_taken_off = false;
        for _ in 0..characters.min(self.entries.len()) {
            let Some(entry) = self.entries.pop() else {
                break;
            };
            let start = self.line.len() - usize::from(entry.bytes);
            if entry.shown {
                taken_off += 1;
                mark_taken_off |= std::str::from_utf8(&self.line[start..])
                    .is_ok_and(|character| typed_line::text_cells(character) == 0);
            }
            self.line.truncate(start);
        }
        self.complete = self.line.len();
        if let (Some(screen), true) = (self.screen.as_mut(), taken_off > 0) {
            if mark_taken_off {
                let cell = last_cell(self.line, &self.entries);
                screen.remove(taken_off + cell.len())?;
                for &(start, end) in cell.iter().rev() {
                    if let Ok(character) = std::str::from_utf8(&self.line[start..end]) {
                        screen.add(character)?;
                    }
                }
            } else {
                screen.remove(taken_off)?;
            }
        }
        self.show_hint()
    }

    /// How many characters Ctrl+W deletes: the spaces at the end and the word before them.
    fn last_word(&self) -> usize {
        let Ok(text) = std::str::from_utf8(&self.line[..self.complete]) else {
            return 0;
        };
        let without_spaces = text.trim_end();
        let word = without_spaces
            .rsplit(char::is_whitespace)
            .next()
            .unwrap_or_default();
        text[without_spaces.len() - word.len()..].chars().count()
    }

    /// Adds what Tab completes of the last word from `list`, and a space once the word is whole.
    fn complete_word(&mut self, list: WordList) -> Result<(), Failure> {
        if self.complete < self.line.len() {
            return Ok(());
        }
        let Ok(text) = std::str::from_utf8(&self.line[..self.complete]) else {
            return Ok(());
        };
        let completion = list.completion(text);
        let space: &[u8] = if completion.word_ends { b" " } else { b"" };
        for &byte in completion.letters.as_bytes().iter().chain(space) {
            self.push(byte)?;
        }
        Ok(())
    }

    fn show_hint(&mut self) -> Result<(), Failure> {
        if let Some(screen) = self.screen.as_mut() {
            // A line that is not UTF-8 gets no hint.
            let text = std::str::from_utf8(&self.line[..self.complete]).unwrap_or_default();
            screen.hint(text)?;
        }
        Ok(())
    }
}

/// One character of a line as the editor took it.
#[derive(Clone, Copy)]
struct Entry {
    /// Its bytes in the line: one to four, or the invalid bytes taken together.
    bytes: u8,
    /// Whether it is on the screen.
    shown: bool,
}

/// The byte ranges of the shown characters that make up the last cell of `line`, the last first:
/// its combining marks and the character they combine with.
fn last_cell(line: &[u8], entries: &[Entry]) -> Vec<(usize, usize)> {
    let mut cell = Vec::new();
    let mut end = line.len();
    for entry in entries.iter().rev() {
        let start = end - usize::from(entry.bytes);
        if entry.shown {
            cell.push((start, end));
            let takes_a_cell = std::str::from_utf8(&line[start..end])
                .is_ok_and(|character| typed_line::text_cells(character) > 0);
            if takes_a_cell {
                break;
            }
        }
        end = start;
    }
    cell
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::mem::MaybeUninit;
    use std::ptr;
    use std::time::Duration;

    use super::terminal_error;
    use crate::exit::Failure;

    pub type Settings = libc::termios;

    pub fn current() -> Result<Settings, Failure> {
        current_on(libc::STDIN_FILENO)
    }

    /// The settings of the terminal on `descriptor`.
    pub fn current_on(descriptor: libc::c_int) -> Result<Settings, Failure> {
        let mut settings = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills the whole structure when it returns 0.
        if unsafe { libc::tcgetattr(descriptor, settings.as_mut_ptr()) } != 0 {
            return Err(terminal_error("read the settings of"));
        }
        // SAFETY: initialised by the successful tcgetattr above.
        Ok(unsafe { settings.assume_init() })
    }

    pub fn hide(original: &Settings) -> Result<(), Failure> {
        hide_on(libc::STDIN_FILENO, original)
    }

    /// The modes of the terminal's own echo and line editing, which a hidden prompt switches off.
    const ECHO_AND_EDITING: libc::tcflag_t = libc::ECHO | libc::ICANON | libc::IEXTEN;

    /// [`hide`] for the terminal on `descriptor`.
    pub fn hide_on(descriptor: libc::c_int, original: &Settings) -> Result<(), Failure> {
        let mut hidden = *original;
        // No echo and no line mode: this module edits the line. ISIG keeps Ctrl+C as the
        // interrupt key; quit and suspend become ordinary characters.
        hidden.c_lflag &= !ECHO_AND_EDITING;
        hidden.c_lflag |= libc::ISIG;
        hidden.c_cc[libc::VQUIT] = libc::_POSIX_VDISABLE;
        hidden.c_cc[libc::VSUSP] = libc::_POSIX_VDISABLE;
        // A read returns as soon as one byte is there.
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        // No flow control (Ctrl+S, Ctrl+Q) and no changes to the bytes.
        hidden.c_iflag &= !(libc::IXON | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL);
        // SAFETY: a valid termios for the terminal on `descriptor`.
        if unsafe { libc::tcsetattr(descriptor, libc::TCSANOW, &hidden) } != 0 {
            return Err(terminal_error("hide the input on"));
        }
        // tcsetattr succeeds when any one of the changes was made (POSIX), so the terminal is
        // asked what it does now before anything is read.
        if !echo_off(&current_on(descriptor)?) {
            return Err(super::echo_stays_on());
        }
        Ok(())
    }

    /// Whether `settings` have neither the terminal's echo nor its own line editing.
    pub fn echo_off(settings: &Settings) -> bool {
        settings.c_lflag & ECHO_AND_EDITING == 0
    }

    /// The menu's keys need the same settings as a hidden line: every byte at once, no echo.
    pub fn single_keys(original: &Settings) -> Result<(), Failure> {
        hide(original)
    }

    /// A Unix terminal carries out control sequences as they come.
    pub fn control_sequences() -> bool {
        true
    }

    pub fn output_on_error_terminal() -> bool {
        same_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO)
    }

    /// Whether two descriptors are the same terminal: character devices with the same device
    /// number. Two terminals of one system, such as two pseudo-terminals, have different numbers.
    pub fn same_terminal(first: libc::c_int, second: libc::c_int) -> bool {
        let device = |descriptor| {
            let mut status = MaybeUninit::<libc::stat>::zeroed();
            // SAFETY: fstat fills the stat when it returns 0; it was zeroed before.
            let read = unsafe { libc::fstat(descriptor, status.as_mut_ptr()) };
            // SAFETY: all zero bytes are a valid stat, and a successful call filled it.
            let status = unsafe { status.assume_init() };
            (read == 0 && status.st_mode & libc::S_IFMT == libc::S_IFCHR).then_some(status.st_rdev)
        };
        matches!((device(first), device(second)), (Some(first), Some(second)) if first == second)
    }

    pub fn columns() -> Option<usize> {
        let mut size = MaybeUninit::<libc::winsize>::zeroed();
        // SAFETY: TIOCGWINSZ fills the winsize when it returns 0; it was zeroed before.
        let read = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) };
        // SAFETY: all zero bytes are a valid winsize, and a successful call filled it.
        let columns = unsafe { size.assume_init() }.ws_col;
        (read == 0 && columns > 0).then_some(usize::from(columns))
    }

    /// Whether a byte arrives on standard input within `delay`. select, not poll: macOS's poll
    /// does not support terminals.
    pub fn input_within(delay: Duration) -> Result<bool, Failure> {
        loop {
            // SAFETY: an fd_set and a timeval on the stack that select may change, for standard
            // input only; all zero bytes are a valid fd_set.
            let ready = unsafe {
                let mut readable = MaybeUninit::<libc::fd_set>::zeroed().assume_init();
                libc::FD_ZERO(&mut readable);
                libc::FD_SET(libc::STDIN_FILENO, &mut readable);
                let mut timeout = libc::timeval {
                    tv_sec: delay.as_secs() as libc::time_t,
                    tv_usec: delay.subsec_micros() as libc::suseconds_t,
                };
                libc::select(
                    libc::STDIN_FILENO + 1,
                    &mut readable,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut timeout,
                )
            };
            match ready {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                -1 => return Err(terminal_error("wait for a key from")),
                count => return Ok(count > 0),
            }
        }
    }

    pub fn restore(original: &Settings) {
        // SAFETY: the settings read from this terminal before. A failure cannot be reported
        // usefully here; the shell restores the terminal when the tool ends in any case.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original) };
    }
}

#[cfg(windows)]
mod platform {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, PeekConsoleInputW,
        SetConsoleMode, CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, INPUT_RECORD, KEY_EVENT, STD_ERROR_HANDLE,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    use super::terminal_error;
    use crate::exit::Failure;

    pub type Settings = CONSOLE_MODE;

    pub fn current() -> Result<Settings, Failure> {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: a plain console call on the standard input handle.
        if unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) } == 0 {
            return Err(terminal_error("read the settings of"));
        }
        Ok(mode)
    }

    pub fn hide(original: &Settings) -> Result<(), Failure> {
        // No echo and no line mode: this module edits the line. Processed input keeps Ctrl+C as
        // the cancel key; without line input the console acts on no other key.
        let hidden = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
        // SAFETY: a plain console call on the standard input handle.
        if unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), hidden) } == 0 {
            return Err(terminal_error("hide the input on"));
        }
        read_back_echo_off()
    }

    /// Asks the console what it does now, before anything is read: neither echo nor its own line
    /// editing may be left on.
    fn read_back_echo_off() -> Result<(), Failure> {
        if current()? & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) != 0 {
            return Err(super::echo_stays_on());
        }
        Ok(())
    }

    /// As for a hidden line, and the console sends the arrow keys as VT escape sequences, as a
    /// Unix terminal does (Windows 10 and later). The menu redraws itself with VT cursor
    /// sequences on standard error, so the console is also asked to carry those out there; that
    /// output mode stays on, as for any program that writes colours.
    pub fn single_keys(original: &Settings) -> Result<(), Failure> {
        let keys = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT))
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: plain console calls on the standard handles.
        unsafe {
            if SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), keys) == 0 {
                return Err(terminal_error("read single keys from"));
            }
            let output = GetStdHandle(STD_ERROR_HANDLE);
            let mut mode: CONSOLE_MODE = 0;
            if GetConsoleMode(output, &mut mode) == 0
                || SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0
            {
                return Err(terminal_error("draw the menu on"));
            }
        }
        read_back_echo_off()
    }

    /// Asks the console to carry out the VT control sequences written to standard error, such as
    /// switching to the alternate screen; whether it agreed. The mode stays on, as in single_keys.
    pub fn control_sequences() -> bool {
        // SAFETY: plain console calls on the standard error handle.
        unsafe {
            let output = GetStdHandle(STD_ERROR_HANDLE);
            let mut mode: CONSOLE_MODE = 0;
            GetConsoleMode(output, &mut mode) != 0
                && SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }

    /// A process has one console: standard output and standard error, when both are consoles,
    /// are that one.
    pub fn output_on_error_terminal() -> bool {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: plain console calls on the standard output and error handles.
        unsafe {
            GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut mode) != 0
                && GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mut mode) != 0
        }
    }

    /// The width of the console window that standard error writes to.
    pub fn columns() -> Option<usize> {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: a plain console call that fills `info`.
        let read = unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &mut info) };
        let width = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        (read != 0 && width > 0).then_some(width as usize)
    }

    /// Whether a typed character arrives within `delay`. The console has no wait for that alone:
    /// its queue also holds events that give no character, such as the release of the Escape key
    /// itself, so the queue is looked at every few milliseconds until the time is up.
    pub fn input_within(delay: Duration) -> Result<bool, Failure> {
        const LOOK_EVERY: Duration = Duration::from_millis(5);
        let end = Instant::now() + delay;
        loop {
            if character_waiting()? {
                return Ok(true);
            }
            if Instant::now() >= end {
                return Ok(false);
            }
            std::thread::sleep(LOOK_EVERY);
        }
    }

    /// Whether the console's queue holds a key press with a character. With VT input, the rest of
    /// an arrow key's sequence arrives as such presses.
    fn character_waiting() -> Result<bool, Failure> {
        // More than the events of one key's sequence, with their releases.
        const EVENTS: usize = 32;
        let mut events = [INPUT_RECORD::default(); EVENTS];
        let mut count = 0u32;
        // SAFETY: room for EVENTS records; peeking leaves the events in the queue.
        let peeked = unsafe {
            PeekConsoleInputW(
                GetStdHandle(STD_INPUT_HANDLE),
                events.as_mut_ptr(),
                EVENTS as u32,
                &mut count,
            )
        };
        if peeked == 0 {
            return Err(terminal_error("look at the keys of"));
        }
        let typed = events[..count as usize].iter().any(|event| {
            // SAFETY: the union holds a key event when EventType says so, and its character is
            // read as the UTF-16 unit that the W function fills in.
            event.EventType == KEY_EVENT as u16
                && unsafe {
                    event.Event.KeyEvent.bKeyDown != 0
                        && event.Event.KeyEvent.uChar.UnicodeChar != 0
                }
        });
        Ok(typed)
    }

    pub fn restore(original: &Settings) {
        // SAFETY: the mode read from this console before.
        unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), *original) };
    }
}

/// Whether a typed character stays off the screen: a control character, which a terminal would
/// carry out, and an invisible formatting character, such as U+202E, which turns the text after it
/// around (bidirectional controls, zero-width characters, the byte order mark).
fn not_shown(character: char) -> bool {
    character.is_control()
        || matches!(u32::from(character),
            0x061C | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Control and invisible formatting characters stay off the screen; letters of any script and
    /// a wide character are shown.
    #[test]
    fn invisible_characters_are_not_shown() {
        for hidden in [
            '\u{1b}', '\u{7f}', '\u{9b}', '\u{202E}', '\u{200B}', '\u{2066}', '\u{FEFF}',
        ] {
            assert!(not_shown(hidden), "{:x}", u32::from(hidden));
        }
        for shown in ['a', '\u{e9}', '\u{416}', '\u{754C}', ' '] {
            assert!(!not_shown(shown));
        }
    }

    /// AUD-008-SEC004: two pseudo-terminals are two terminals; one descriptor of each, or a file,
    /// is told apart from the same terminal opened twice.
    #[cfg(unix)]
    #[test]
    fn two_terminals_are_told_apart() {
        use std::os::fd::AsRawFd;
        let first = Pty::open();
        let second = Pty::open();
        // SAFETY: dup copies a descriptor that is open.
        let first_again = unsafe { libc::dup(first.follower) };
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(platform::same_terminal(first.follower, first_again));
        assert!(!platform::same_terminal(first.follower, second.follower));
        assert!(!platform::same_terminal(first.follower, file.as_raw_fd()));
        // SAFETY: opened above and closed once; the pseudo-terminals close their own.
        unsafe { libc::close(first_again) };
    }

    /// A pseudo-terminal, both ends, closed when dropped.
    #[cfg(unix)]
    struct Pty {
        leader: libc::c_int,
        follower: libc::c_int,
    }

    #[cfg(unix)]
    impl Pty {
        fn open() -> Self {
            let (mut leader, mut follower) = (0, 0);
            // SAFETY: openpty fills the two descriptors; the name and settings are not asked for.
            // Null pointers of the mutable kind, which macOS's declaration takes and Linux's
            // accepts as well.
            let opened = unsafe {
                libc::openpty(
                    &mut leader,
                    &mut follower,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(opened, 0, "no pseudo-terminal");
            Self { leader, follower }
        }
    }

    #[cfg(unix)]
    impl Drop for Pty {
        fn drop(&mut self) {
            // SAFETY: both were opened by openpty and are closed once.
            unsafe {
                libc::close(self.leader);
                libc::close(self.follower);
            }
        }
    }

    /// A terminal switched for a hidden prompt reads back without echo and line editing, and the
    /// read-back tells such settings from a terminal whose echo stayed on.
    #[cfg(unix)]
    #[test]
    fn hiding_reads_the_terminal_back() {
        let pty = Pty::open();
        let original = platform::current_on(pty.follower).unwrap();
        assert!(!platform::echo_off(&original), "a new terminal echoes");
        platform::hide_on(pty.follower, &original).unwrap();
        let hidden = platform::current_on(pty.follower).unwrap();
        assert!(platform::echo_off(&hidden));
        // A terminal that kept any one of the three modes is refused.
        for mode in [libc::ECHO, libc::ICANON, libc::IEXTEN] {
            let mut kept = hidden;
            kept.c_lflag |= mode;
            assert!(
                !platform::echo_off(&kept),
                "mode {mode:#x} passed for hidden"
            );
        }
    }

    #[test]
    fn hidden_input_refuses_when_echo_stays_on() {
        let refusal = echo_stays_on();
        assert_eq!(refusal.exit_code, crate::exit::INTERNAL_ERROR);
        assert_eq!(
            refusal.message,
            "The terminal did not turn its echo off; no secret was read."
        );
    }

    /// The check of the terminal belongs to the full self-test only, and without a terminal on
    /// standard input, as under `cargo test`, it says so instead of failing.
    #[test]
    fn the_hidden_input_check_runs_on_request_only() {
        let mut check = HiddenInputCheck;
        assert!(!check.runs_at(Tier::Startup));
        assert!(check.runs_at(Tier::Full));
        if !io::stdin().is_terminal() {
            assert_eq!(check.run(Tier::Full).name(), "notAvailable");
        }
    }

    fn edited(bytes: &[u8]) -> Option<String> {
        edited_as(bytes, Content::Password)
    }

    fn edited_as(bytes: &[u8], content: Content) -> Option<String> {
        edit_line(&mut io::Cursor::new(bytes.to_vec()), None, content)
            .unwrap()
            .map(|line| line.to_string())
    }

    #[test]
    fn control_characters_other_than_the_editing_keys_are_kept() {
        for key in [b'\t', 0x00, 0x11, 0x13, 0x16, 0x17, 0x1a, 0x1c, 0x1b] {
            assert_eq!(
                edited(&[b'a', key, b'b', b'\r']).unwrap().as_bytes(),
                [b'a', key, b'b']
            );
        }
        // Ctrl+D inside a line is kept too; the password check refuses it.
        assert_eq!(edited(b"a\x04b\n").unwrap(), "a\u{4}b");
        // Tab and Ctrl+W are data in a password and in free text as well.
        assert_eq!(
            edited_as(b"ab\t\x17\r", Content::Text).unwrap(),
            "ab\t\u{17}"
        );
    }

    /// The line of `content` read and what the screen showed of it, after a prompt 2 columns wide
    /// on a terminal 80 wide, hints left out.
    fn echoed(bytes: &[u8], content: Content) -> (String, String) {
        let mut controls = Vec::new();
        let mut text = Vec::new();
        let mut screen = LineScreen::new(&mut controls, &mut text, 2, 80, None);
        let line = edit_line(
            &mut io::Cursor::new(bytes.to_vec()),
            Some(&mut screen),
            content,
        )
        .unwrap()
        .unwrap();
        (line.to_string(), String::from_utf8(controls).unwrap())
    }

    #[test]
    fn a_shown_line_shows_what_is_typed_but_no_control_character() {
        assert_eq!(
            echoed(b"ab\r", Content::Password),
            ("ab".into(), "ab".into())
        );
        // Backspace takes a whole character off the screen: back to column 4, and clear from there.
        let (line, screen) = echoed("a\u{448}\x7fb\r".as_bytes(), Content::Password);
        assert_eq!(line, "ab");
        assert_eq!(screen, "a\u{448}\x1b[4G\x1b[Jb");
        // A TAB and U+0085 stay in the line, for the password check to refuse, but are not shown,
        // and Backspace over one of them takes nothing off the screen.
        let (line, screen) = echoed("a\tb\u{85}\x7f\r".as_bytes(), Content::Password);
        assert_eq!(line, "a\tb");
        assert_eq!(screen, "ab");
        // Ctrl+U takes off every character that was shown.
        let (line, screen) = echoed(b"ab\tc\x15d\r", Content::Password);
        assert_eq!(line, "d");
        assert_eq!(screen, "abc\x1b[3G\x1b[Jd");
    }

    /// Backspace over a combining mark draws its cell again, so that the screen shows the line as
    /// it is (AUD-018): back to the cell of "e", clear, and "e" again, without the mark.
    #[test]
    fn removing_a_combining_mark_draws_its_cell_again() {
        let (line, screen) = echoed("e\u{301}\x7f\r".as_bytes(), Content::Password);
        assert_eq!(line, "e");
        assert_eq!(screen, "e\u{301}\x1b[3G\x1b[Je");
        // A Thai tone mark on its consonant, typed as a key of its own and taken off again.
        let (line, screen) = echoed("\u{E01}\u{E48}\x7f\r".as_bytes(), Content::Password);
        assert_eq!(line, "\u{E01}");
        assert_eq!(screen, "\u{E01}\u{E48}\x1b[3G\x1b[J\u{E01}");
    }

    /// A byte that is not UTF-8 is a character of its own: Backspace takes off that byte alone,
    /// never the character before it (AUD-018).
    #[test]
    fn backspace_over_a_stray_byte_takes_off_that_byte_alone() {
        assert_eq!(edited(b"a\x80\x7fb\r").unwrap(), "ab");
        let (line, screen) = echoed(b"a\x80\x7fb\r", Content::Password);
        assert_eq!((line.as_str(), screen.as_str()), ("ab", "ab"));
    }

    /// A line of words: Tab completes the last word as far as the list's words agree, with a space
    /// once it is whole, and Ctrl+W deletes the last word with the spaces after it.
    #[test]
    fn tab_and_ctrl_w_edit_a_line_of_words() {
        let words = Content::Words(mhfe::word_hints::WordList::Bip39);
        assert_eq!(edited_as(b"abou\tzo\t\r", words).unwrap(), "about zo");
        assert_eq!(edited_as(b"abandon abou\x17\r", words).unwrap(), "abandon ");
        assert_eq!(
            edited_as(b"abandon about  \x17\x17zoo\r", words).unwrap(),
            "zoo"
        );
        // The completed letters are shown as if typed.
        let (line, screen) = echoed(b"artw\t\r", words);
        assert_eq!((line.as_str(), screen.as_str()), ("artwork ", "artwork "));
    }

    #[test]
    fn backspace_and_ctrl_u_edit_the_line() {
        assert_eq!(edited(b"abx\x7f\r").unwrap(), "ab");
        assert_eq!(edited(b"abx\x08\r").unwrap(), "ab");
        assert_eq!(edited("a\u{1D400}\x7f\r".as_bytes()).unwrap(), "a");
        assert_eq!(edited(b"wrong\x15right\r").unwrap(), "right");
        assert_eq!(edited(b"\x7f\x7fa\r").unwrap(), "a");
    }

    #[test]
    fn ctrl_d_on_an_empty_line_or_the_end_of_input_closes_it() {
        assert_eq!(edited(b"\x04"), None);
        assert_eq!(edited(b""), None);
        assert_eq!(edited(b"abc").unwrap(), "abc");
    }

    /// 1024 characters U+1D400 take 4096 bytes and normalize to 1024 bytes: a valid password.
    #[test]
    fn the_longest_valid_password_fits() {
        let text = "\u{1D400}".repeat(1024);
        assert_eq!(edited(format!("{text}\r").as_bytes()).unwrap(), text);
        assert!(mhfe::Password::new(&text).is_ok());
    }

    /// The keys in `bytes` up to the first Quit, which the end of the input gives too.
    /// Test input that arrives all at once: more follows exactly while bytes are left.
    impl KeySource for io::Cursor<Vec<u8>> {
        fn next_byte(&mut self) -> Result<Option<u8>, Failure> {
            let mut byte = [0u8; 1];
            Ok((io::Read::read(self, &mut byte)? == 1).then_some(byte[0]))
        }

        fn more_within(&mut self, _delay: Duration) -> Result<bool, Failure> {
            Ok((self.position() as usize) < self.get_ref().len())
        }
    }

    fn keys_in(bytes: &[u8]) -> Vec<Key> {
        let mut reader = io::Cursor::new(bytes.to_vec());
        let mut keys = Vec::new();
        loop {
            let key = read_key(&mut reader).unwrap();
            let quit = key == Key::Quit;
            keys.push(key);
            if quit {
                return keys;
            }
        }
    }

    #[test]
    fn arrow_keys_digits_and_enter_are_read() {
        use Key::*;
        assert_eq!(
            keys_in(b"\x1b[A\x1b[B\x1bOA\x1bOB\r\n"),
            [Up, Down, Up, Down, Enter, Enter, Quit]
        );
        assert_eq!(keys_in(b"19q"), [Digit(1), Digit(9), Quit]);
        assert_eq!(keys_in(b"?q"), [Help, Quit]);
        assert_eq!(keys_in(b"0x\x04"), [Other, Other, Quit]);
        assert_eq!(keys_in(b"\x03"), [Quit]);
    }

    #[test]
    fn other_escape_sequences_are_read_to_their_end() {
        use Key::*;
        // Ctrl+Up, Delete and F5: none of their digits may count as a digit key.
        assert_eq!(
            keys_in(b"\x1b[1;5A\x1b[3~\x1b[15~\r"),
            [Other, Other, Other, Enter, Quit]
        );
        // Right and left arrows are ignored.
        assert_eq!(keys_in(b"\x1b[C\x1b[D2"), [Other, Other, Digit(2), Quit]);
    }

    #[test]
    fn the_end_of_the_input_quits() {
        assert_eq!(keys_in(b""), [Key::Quit]);
        assert_eq!(keys_in(b"\x1b["), [Key::Quit]);
    }

    #[test]
    fn escape_alone_quits() {
        use Key::*;
        assert_eq!(keys_in(b"\x1b[B2\x1b"), [Down, Digit(2), Quit]);
        // Escape followed at once by another key, as Alt+x sends it, is no Escape.
        assert_eq!(keys_in(b"\x1bx\r\x1b"), [Other, Enter, Quit]);
    }

    #[test]
    fn a_line_over_the_capacity_or_invalid_utf8_is_refused() {
        use crate::terminal::LINE_CAPACITY;
        let longest = "a".repeat(LINE_CAPACITY);
        assert_eq!(edited(format!("{longest}\r").as_bytes()).unwrap(), longest);
        let too_long = format!("{longest}a\r");
        let refused = |bytes: Vec<u8>| {
            edit_line(&mut io::Cursor::new(bytes), None, Content::Password).is_err()
        };
        assert!(refused(too_long.into_bytes()));
        assert!(refused(b"\xff\r".to_vec()));
    }

    /// The lock of the buffer goes with the line to the caller (AUD-007-SEC003).
    #[test]
    fn a_line_stays_locked_after_it_is_returned() {
        let line = edit_line(
            &mut io::Cursor::new(b"pass word\r".to_vec()),
            None,
            Content::Password,
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*line, "pass word");
        assert_eq!(line.is_locked(), cfg!(unix));
    }
}
