//! `cargo xtask terminal [path/to/mhfe]`: the terminal input and output of the mhfe tool, checked in
//! a pseudo-terminal on Linux and macOS, as a person at a terminal and a script see them. The
//! default program is `target/debug/mhfe`. Only public test data are used: the zero-12 vectors,
//! BIP39's test passphrase "TREZOR", synthetic passwords, and addresses and fingerprints that no
//! recovery here ever compares, as Argon2 never runs.
//!
//! At a terminal every step of a command has a screen of its own on the terminal's alternate
//! screen, and the main screen gets only the summary, when the command ends. Most cases drive
//! `mhfe check --fingerprint --pim 0`, which reads the container on a step of its own, taken at
//! once, then the container password on another, and stop the tool before a fingerprint is given,
//! so no memory is reserved; the PIM given skips the question of the settings. On Linux some runs
//! get an address space too small for the 2 GiB of memory level 0: whatever they ask comes before
//! the memory is reserved, and the reservation is refused before Argon2 runs, with exit code 4;
//! elsewhere they stop at the last question instead.
//!
//! What it checks, case by case, is said in the documentation of each case's function and in the
//! line each prints when it passes:
//!
//! - passwords ([`password`]): every control character reaches the password check and is
//!   refused, also those a terminal would act on; a Unicode password and the longest one are
//!   accepted; Backspace and Ctrl+U edit the line; the password is shown only on the alternate
//!   screen, which is cleared and left; Ctrl+C ends the tool with exit code 130; the terminal
//!   settings are exactly the original ones afterwards; the check word repairs a password only on
//!   the person's choice; the words of the lists are hinted below a typed line; `mhfe decrypt`
//!   takes more passwords on the person's choice and records only one, and without a private
//!   screen or with a stated short length takes one;
//! - the menu and isolation ([`menu`]): the keys of the menu, its password and help entries, its
//!   commands as processes of their own, Ctrl+C and signals, and the isolation each command runs
//!   in;
//! - rekey ([`rekey`]): the warning about other wallets, the question about the wallet's BIP39
//!   passphrase for every kind of confirmation, with no default, and its numbered form;
//! - encrypt ([`encrypt`]): the lists of `mhfe encrypt`, a script, a dumb terminal, a password
//!   made by MHFE, real dice, a phrase offered only at a terminal, and the quit keys at a private
//!   screen;
//! - repair and search ([`repair`]): repair words where a container phrase is read and in `mhfe
//!   repair`, length detection, and the search for missing words;
//! - output without a terminal ([`plain`]): password sizes, usage errors and every help, the
//!   messages of scripts, and a start that prints nothing;
//! - the self-test ([`self_test`]): its report at a terminal, with NO_COLOR, in a pipe and from
//!   the menu, and copies of the program with a damaged known answer, made in
//!   `target/xtask-terminal/` and deleted afterwards.

mod encrypt;
mod menu;
mod password;
mod plain;
mod pty;
mod rekey;
mod repair;
mod self_test;
mod session;
mod text;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::Value;

use crate::terminal_texts as texts;
use crate::{Failure, ensure, wasm};

/// The program the cases run, set once by [`run`].
static PROGRAM: OnceLock<PathBuf> = OnceLock::new();
/// zero-12's container and phrase, read once by [`run`].
static ZERO_12: OnceLock<(String, String)> = OnceLock::new();

fn program() -> &'static Path {
    PROGRAM
        .get()
        .map_or(Path::new("target/debug/mhfe"), PathBuf::as_path)
}

/// The public zero-12 test container and phrase (tests/spec/vectors/suite3/zero-12.json).
fn container() -> &'static str {
    ZERO_12
        .get()
        .map_or("", |(container, _)| container.as_str())
}

fn phrase() -> &'static str {
    ZERO_12.get().map_or("", |(_, phrase)| phrase.as_str())
}

/// Exit codes of the tool when the person cancels, when an answer or the setup is refused, when
/// the memory for Argon2 cannot be reserved and when a part of the program fails its known
/// answers (src/bin/mhfe/exit.rs).
const CANCELLED: i32 = texts::CANCELLED as i32;
const INVALID_INPUT: i32 = 2;
const NOT_ENOUGH_RESOURCES: i32 = 4;
const INTERNAL_ERROR: i32 = 1;
/// The private screen: the terminal's alternate screen, cleared before the tool leaves it
/// (src/bin/mhfe/terminal.rs).
const ENTER_PRIVATE: &[u8] = b"\x1b[?1049h";
const LEAVE_PRIVATE: &[u8] = b"\x1b[2J\x1b[H\x1b[?1049l";
const CLEAR: &[u8] = b"\x1b[2J\x1b[H";
const BACKSPACE: &[u8] = b"\x7f";
const CTRL_U: &[u8] = texts::CTRL_U.as_bytes();
const CTRL_C: &[u8] = texts::CTRL_C.as_bytes();
/// The keys of the menu, as a terminal sends them. Ctrl+Up carries a 5, which must not choose
/// entry 5.
const UP: &[u8] = texts::UP.as_bytes();
const DOWN: &[u8] = texts::DOWN.as_bytes();
const ENTER: &[u8] = texts::ENTER.as_bytes();
const CTRL_UP: &[u8] = texts::CTRL_UP.as_bytes();
const ESCAPE: &[u8] = texts::ESCAPE.as_bytes();
/// What a list shows as its last line, and the marker before the marked answer of a list, as
/// "› 1  Label" (src/bin/mhfe/choice.rs).
const LIST_SHOWN: &[u8] = b"Esc cancels";
const HIGHLIGHT: &[u8] = "›".as_bytes();
/// The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the
/// menu.
const MENU_SHOWN: &[u8] = texts::MENU_SHOWN.as_bytes();
const BACK_TO_MENU: &[u8] = texts::BACK_TO_MENU.as_bytes();
/// The container prompt of every command.
const CONTAINER_ASKED: &[u8] = b"original seed phrase: ";
/// A synthetic password and a public passphrase: BIP39's test vectors'.
const SECRET: &[u8] = texts::SECRET.as_bytes();
const PUBLIC_PASSPHRASE: &[u8] = b"TREZOR";
/// What a run stopped at the memory reservation says, before Argon2.
const MEMORY_REFUSED: &[u8] = b"could not reserve 2 GiB of memory for Argon2";
/// A key the menu and the lists ignore; it appears nowhere in what they print.
const IGNORED_KEY: &[u8] = b"Z";
/// The question about the wallet's BIP39 passphrase of `mhfe rekey`, and its two answers.
const PASSPHRASE_ASKED: &[u8] = b"Does the wallet of this phrase have a BIP39 passphrase?";
/// The prompt and the refusal of a numbered question at a terminal that cannot redraw a list.
const NUMBERED_PROMPT: &[u8] = b"Choice: ";
/// The beginning of every passphrase prompt.
const ANY_PASSPHRASE_ASKED: &[u8] = b"BIP39 passphrase of";
/// The prompt of the wallet's BIP39 passphrase where one is said to be used: no Enter for none.
const KNOWN_PASSPHRASE_ASKED: &[u8] = b"BIP39 passphrase of the wallet: ";
/// The record of any answer about the passphrase, at the start of its line of the summary.
const PASSPHRASE_RECORD: &[u8] = b"\n  Passphrase ";
/// The question of `mhfe encrypt` about repair words, and the hint of a list with no answer
/// marked.
const REPAIR_ASKED: &[u8] = b"Repair words for the container phrase?";
/// The question of the password entry of the menu, and what `mhfe password` asks after one.
const PASSWORD_KIND: &[u8] = texts::PASSWORD_KIND.as_bytes();
/// The first question of `mhfe encrypt` and the link above its list.
const SETTINGS_QUESTION: &[u8] = texts::SETTINGS_QUESTION.as_bytes();
/// Valid words whose checksum fails.
const BAD_CHECKSUM: &[u8] = b"abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon";
/// How an error begins (src/bin/mhfe/style.rs), and the width of running text.
const ERROR_MARK: &str = "✗ Error: ";
const TEXT_WIDTH: usize = 78;
/// The link of the self-test's README section.
const SELF_TEST_LINK: &str = "  More: https://github.com/hobby-eng/mhfe#mhfe-self-test";
/// The menu entries of `mhfe encrypt` and `mhfe password` when no browser tool lies next to the
/// program.
const ENCRYPT_ENTRY: u8 = texts::ENCRYPT_ENTRY;
const PASSWORD_ENTRY: u8 = texts::PASSWORD_ENTRY;
/// The question that `mhfe password` and the menu's password entry ask after a password.
const PASSWORD_AGAIN: &[u8] = texts::PASSWORD_AGAIN.as_bytes();
/// What a password made shows before the person is to copy it, and after it is shown.
const WRITE_IT_DOWN: &[u8] = b"Write it down now: Enter or Escape clears this screen.";

/// The digit that chooses the `entry` of a list or the menu at once.
fn digit(entry: u8) -> Vec<u8> {
    entry.to_string().into_bytes()
}

/// `parts` joined, for keys typed or text expected.
fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    let program = match arguments {
        [] => root.join("target/debug/mhfe"),
        [program] => PathBuf::from(program),
        _ => {
            return Err(Failure(
                "usage: cargo xtask terminal [path/to/mhfe]".to_owned(),
            ));
        }
    };
    let program = std::fs::canonicalize(&program).map_err(|error| crate::at(&program, error))?;
    let _ = PROGRAM.set(program);
    let vector: Value = serde_json::from_str(&wasm::text(
        &root.join("tests/spec/vectors/suite3/zero-12.json"),
    )?)
    .map_err(|error| Failure(format!("zero-12.json: {error}")))?;
    let text = |value: &Value| value.as_str().unwrap_or_default().to_owned();
    let _ = ZERO_12.set((
        text(&vector["container"]),
        text(&vector["inputs"]["phrase"]),
    ));
    password::run()?;
    menu::run()?;
    rekey::run()?;
    encrypt::run()?;
    repair::run()?;
    plain::run()?;
    self_test::run(root)?;
    println!("The terminal input and output of mhfe behave as described.");
    Ok(())
}
