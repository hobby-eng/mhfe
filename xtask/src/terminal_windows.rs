//! `cargo xtask terminal [path\to\mhfe.exe]` on Windows: the hidden input of the mhfe tool in a
//! Windows pseudo-console (ConPTY), the counterpart of the Unix cases. The default program is
//! `target\debug\mhfe.exe`. It drives `mhfe check --fingerprint --pim 0`, which reads the
//! container on a step of its own, taken at once, and then the container password on another,
//! and stops the tool before a fingerprint is given, so no memory is reserved and Argon2 never
//! runs. Only the public zero-12 test container is used. The pseudo-console redraws the screen in
//! its own way, so where the password is shown is checked on Unix only.
//!
//! It checks that control characters in a password reach the password check and are refused,
//! also those a console in line mode would act on; that a Unicode password and the longest valid
//! password are accepted; that Backspace and Ctrl+U edit the line; and that Ctrl+C at the password
//! ends the tool with exit code 130. It drives the menu, which asks the console for VT input so
//! that the arrow keys arrive as on Unix: the arrows and Enter choose `mhfe password`, its number
//! chooses it at once, Ctrl+Up's 5 chooses nothing, q and a lone Escape quit with exit code 0 and
//! Ctrl+C with 130; the password entry regenerates on Enter and returns on Escape or q; help
//! returns on Enter; q in a command's list ends that command and the menu comes back, and Ctrl+C
//! in it ends both. A command, started directly or from the menu, runs at low integrity, and its
//! summary says so; the network stays open, which it warns of.

mod conpty;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::terminal_texts::{
    ACCEPTED, BACK_TO_MENU, CTRL_C, CTRL_U, CTRL_UP, DOWN, ENCRYPT_ENTRY, ENTER, ESCAPE,
    HELP_FROM_PASSWORD, MENU_SHOWN, PASSWORD_AGAIN, PASSWORD_ENTRY, PASSWORD_KIND, REFUSED, SECRET,
    SETTINGS_QUESTION, UP,
};
use crate::{Failure, ensure, wasm};

/// The exit code of a cancel, as this module compares it.
const CANCELLED: u32 = crate::terminal_texts::CANCELLED as u32;
use conpty::Console;

const BACKSPACE: &str = "\x08";
/// What the summary of an isolated command says (isolation_text in src/bin/mhfe/settings.rs), and
/// what it warns of (IsolationCheck in src/bin/mhfe/protect.rs).
const LOW_INTEGRITY: &str = "low integrity";
const NETWORK_OPEN: &str = "the network stays open";
/// U+0085 (NEL) is left out: the pseudo-console parses its input as VT sequences and does not
/// pass the C1 control on to the program. The password check that refuses it is covered by the
/// library tests and by the Unix cases.
const CONTROLS: [(&str, &str); 7] = [
    ("TAB", "\t"),
    ("Ctrl+S", "\x13"),
    ("Ctrl+Q", "\x11"),
    ("Ctrl+V", "\x16"),
    ("Ctrl+W", "\x17"),
    ("Ctrl+Z", "\x1a"),
    ("Ctrl+\\", "\x1c"),
];

/// A run of the tool in a pseudo-console.
struct Session {
    console: Console,
    output: String,
}

impl Session {
    fn start(program: &Path, arguments: &[&str]) -> Result<Self, Failure> {
        Ok(Self {
            console: Console::spawn(program, arguments)?,
            output: String::new(),
        })
    }

    /// Reads until one of `needles` appears after the text already seen; returns it.
    fn wait_for<'n>(&mut self, needles: &[&'n str]) -> Result<&'n str, Failure> {
        let start = self.output.len();
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if let Some(found) = needles
                .iter()
                .find(|needle| self.output[start..].contains(**needle))
            {
                return Ok(found);
            }
            if let Ok(chunk) = self.console.output.recv_timeout(Duration::from_millis(50)) {
                self.output.push_str(&String::from_utf8_lossy(&chunk));
            }
        }
        Err(Failure(format!(
            "none of {needles:?} in {:?}",
            &self.output[start..]
        )))
    }

    fn wait(&mut self, needle: &str) -> Result<(), Failure> {
        self.wait_for(&[needle]).map(|_| ())
    }

    fn type_keys(&mut self, text: &str) -> Result<(), Failure> {
        self.console.write(text)
    }

    /// Waits up to ten seconds for the tool to end, reading meanwhile; its exit code.
    fn ended(&mut self) -> Option<u32> {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(code) = self.console.exit_code() {
                return Some(code);
            }
            if let Ok(chunk) = self.console.output.recv_timeout(Duration::from_millis(100)) {
                self.output.push_str(&String::from_utf8_lossy(&chunk));
            }
        }
        None
    }

    /// Ends the tool with Ctrl+C if it still runs, and forcibly if it does not end; its exit code.
    fn close(&mut self) -> Result<u32, Failure> {
        if self.console.exit_code().is_none() {
            self.type_keys(CTRL_C)?;
        }
        match self.ended() {
            Some(code) => Ok(code),
            None => {
                self.console.terminate();
                Err(Failure("the tool did not end".to_owned()))
            }
        }
    }

    fn at_password_prompt(&mut self, container: &str) -> Result<(), Failure> {
        self.wait("original seed phrase: ")?;
        // The container is read on a step of its own and taken at once.
        self.type_keys(&format!("{container}\r"))?;
        self.wait("Container password: ")
    }
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    let program = match arguments {
        [] => root.join("target").join("debug").join("mhfe.exe"),
        [program] => PathBuf::from(program),
        _ => {
            return Err(Failure(
                "usage: cargo xtask terminal [path\\to\\mhfe.exe]".to_owned(),
            ));
        }
    };
    let vector: Value = serde_json::from_str(&wasm::text(
        &root.join("tests/spec/vectors/suite3/zero-12.json"),
    )?)
    .map_err(|error| Failure(format!("zero-12.json: {error}")))?;
    let container = vector["container"].as_str().unwrap_or_default().to_owned();
    controls_are_refused_and_editing_keys_work(&program, &container)?;
    commands_run_at_low_integrity(&program, &container)?;
    the_menu_keys_choose_and_quit(&program)?;
    println!("The hidden input of mhfe behaves as described in a Windows pseudo-console.");
    Ok(())
}

fn check_password(
    program: &Path,
    container: &str,
    label: &str,
    password: &str,
    expected: &str,
) -> Result<(), Failure> {
    let mut session = Session::start(program, &["check", "--fingerprint", "--pim", "0"])?;
    session.at_password_prompt(container)?;
    session.type_keys(&format!("{password}\r"))?;
    let seen = session.wait_for(&[REFUSED, ACCEPTED])?;
    session.close()?;
    ensure(seen == expected, || {
        format!("{label}: expected {expected:?}, the tool answered {seen:?}")
    })
}

fn controls_are_refused_and_editing_keys_work(
    program: &Path,
    container: &str,
) -> Result<(), Failure> {
    for (label, key) in CONTROLS {
        check_password(
            program,
            container,
            label,
            &format!("{SECRET}{key}x"),
            REFUSED,
        )?;
        println!("refused: a password with {label}");
    }
    check_password(
        program,
        container,
        "Unicode",
        &format!("{SECRET}пароль"),
        ACCEPTED,
    )?;
    check_password(
        program,
        container,
        "1024 x U+1D400",
        &"\u{1D400}".repeat(1024),
        ACCEPTED,
    )?;
    println!("accepted: a Unicode password and the longest valid password");
    check_password(
        program,
        container,
        "Backspace",
        &format!("{SECRET}\t{BACKSPACE}"),
        ACCEPTED,
    )?;
    check_password(
        program,
        container,
        "Ctrl+U",
        &format!("\t{CTRL_U}{SECRET}"),
        ACCEPTED,
    )?;
    println!("edited: Backspace and Ctrl+U at the password");
    let mut session = Session::start(program, &["check", "--fingerprint", "--pim", "0"])?;
    session.at_password_prompt(container)?;
    session.type_keys(&format!("{SECRET}{CTRL_C}"))?;
    session.wait("Cancelled")?;
    let code = session.close()?;
    ensure(code == CANCELLED, || format!("Ctrl+C: exit code {code}"))?;
    println!("cancelled: Ctrl+C at the password, exit code 130");
    Ok(())
}

/// A command runs at low integrity, started directly or from the menu, and the summary it leaves
/// on Ctrl+C says so. The warning that the network stays open comes before the first prompt.
fn commands_run_at_low_integrity(program: &Path, container: &str) -> Result<(), Failure> {
    let mut direct = Session::start(program, &["check", "--fingerprint", "--pim", "0"])?;
    direct.at_password_prompt(container)?;
    let mut menu = Session::start(program, &[])?;
    menu.wait(MENU_SHOWN)?;
    menu.type_keys(&ENCRYPT_ENTRY.to_string())?;
    menu.wait(SETTINGS_QUESTION)?;
    menu.type_keys(ENTER)?;
    menu.wait("seed phrase: ")?;
    for session in [&mut direct, &mut menu] {
        session.type_keys(CTRL_C)?;
        session.wait(LOW_INTEGRITY)?;
        ensure(session.output.contains(NETWORK_OPEN), || {
            format!("no {NETWORK_OPEN:?} in the command's output")
        })?;
        session.close()?;
    }
    println!("isolation: a command, started directly or from the menu, runs at low integrity");
    Ok(())
}

fn the_menu_keys_choose_and_quit(program: &Path) -> Result<(), Failure> {
    let mut session = Session::start(program, &[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(&format!(
        "{CTRL_UP}{}{UP}{ENTER}",
        DOWN.repeat(usize::from(PASSWORD_ENTRY))
    ))?;
    session.wait(PASSWORD_KIND)?;
    session.type_keys(ENTER)?;
    // The password and this prompt may arrive together, and wait_for looks only at new text.
    session.wait(PASSWORD_AGAIN)?;
    ensure(session.output.contains("bits"), || {
        "menu: the arrow keys did not choose mhfe password".to_owned()
    })?;
    for _ in 0..2 {
        session.type_keys(ENTER)?;
        session.wait(PASSWORD_AGAIN)?;
    }
    session.type_keys(ESCAPE)?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(&PASSWORD_ENTRY.to_string())?;
    session.wait(PASSWORD_KIND)?;
    // The second time, random characters.
    session.type_keys("3")?;
    session.wait(PASSWORD_AGAIN)?;
    session.type_keys("q")?;
    session.wait(MENU_SHOWN)?;
    // The menu keeps the password entry highlighted after it.
    session.type_keys(&format!("{}{ENTER}", DOWN.repeat(HELP_FROM_PASSWORD)))?;
    session.wait(BACK_TO_MENU)?;
    session.type_keys(ENTER)?;
    session.wait(MENU_SHOWN)?;
    session.type_keys("q")?;
    let code = session.ended();
    ensure(code == Some(0), || {
        format!("menu: q gave exit code {code:?}")
    })?;
    println!("menu: password regeneration, Escape/q return, exit code 0");

    // Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    let mut session = Session::start(program, &[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(ESCAPE)?;
    let code = session.ended();
    ensure(code == Some(0), || {
        format!("menu: Escape gave exit code {code:?}")
    })?;
    println!("menu: a lone Escape quits, exit code 0");

    let mut session = Session::start(program, &[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(CTRL_C)?;
    session.wait("Cancelled")?;
    let code = session.close()?;
    ensure(code == CANCELLED, || {
        format!("menu: Ctrl+C gave exit code {code}")
    })?;
    println!("menu: Ctrl+C, exit code 130");

    let mut session = Session::start(program, &[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(&ENCRYPT_ENTRY.to_string())?;
    session.wait(SETTINGS_QUESTION)?;
    session.type_keys("q")?;
    session.wait(BACK_TO_MENU)?;
    println!("menu: q in a command's list ends that command; the menu comes back");
    session.type_keys(ENTER)?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(&ENCRYPT_ENTRY.to_string())?;
    session.wait(SETTINGS_QUESTION)?;
    session.type_keys(CTRL_C)?;
    session.wait("Cancelled")?;
    let code = session.close()?;
    ensure(code == CANCELLED, || {
        format!("menu: Ctrl+C in a command gave exit code {code}")
    })?;
    println!("menu: Ctrl+C in a command ends it and the tool, exit code 130");
    Ok(())
}
