//! The menu that `mhfe` shows when it starts without arguments, its commands as processes of their
//! own, and their isolation.

use std::process::Command;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use super::session::{Session, contains, count};
use super::text::without_controls;
use super::{
    BACK_TO_MENU, CANCELLED, CLEAR, CTRL_C, CTRL_UP, DOWN, ENCRYPT_ENTRY, ENTER, ENTER_PRIVATE,
    ESCAPE, IGNORED_KEY, LEAVE_PRIVATE, LIST_SHOWN, MENU_SHOWN, PASSWORD_AGAIN, PASSWORD_ENTRY,
    PASSWORD_KIND, SETTINGS_QUESTION, UP, digit, ensure, join,
};
use crate::Failure;

/// The entry that shows the help, two below the password entry with mhfe self-test between: the
/// ninth, reached with the arrows from the password entry.
const HELP_FROM_PASSWORD: usize = crate::terminal_texts::HELP_FROM_PASSWORD;
/// A password made ends its summary with "bits."; the answers of its kind name bits without the
/// stop.
const PASSWORD_MADE: &[u8] = b"bits.";

pub(super) fn run() -> Result<(), Failure> {
    commands_run_isolated()?;
    the_menu_keys_choose_and_quit()?;
    a_menu_command_ends_alone_or_with_the_menu()
}

/// A menu whose `entry` was chosen, up to what its command, a process of its own, has `shown`.
pub(super) fn menu_command(entry: u8, shown: &[&[u8]]) -> Result<Session, Failure> {
    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    session.answer(&digit(entry), shown)?;
    Ok(session)
}

/// Whether a process of this user may create a user namespace with an empty network, which some
/// systems refuse; tried by `unshare`, so that this process stays as it is.
fn user_namespaces_allowed() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "true"])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// A command, started directly or from the menu, runs isolated and warns of no gap: on Linux under
/// the seccomp filter, in an empty network where the system allows it, as the system shows its
/// process; elsewhere in the system's sandbox, which only the missing warning shows.
fn commands_run_isolated() -> Result<(), Failure> {
    let mut direct = Session::check()?;
    let mut menu = menu_command(ENCRYPT_ENTRY, &[SETTINGS_QUESTION, LIST_SHOWN])?;
    direct.at_password_prompt()?;
    menu.answer(ENTER, &[b"seed phrase: "])?;
    let state = isolation_of(&[direct.pid(), command_of(&menu)?])?;
    direct.close()?;
    menu.close()?;
    for session in [&direct, &menu] {
        ensure(
            !contains(&without_controls(&session.output), b"Isolation is"),
            || "isolation: a command warns that it is weaker than needed".to_owned(),
        )?;
    }
    println!("isolation: a command, started directly or from the menu, runs with {state}");
    Ok(())
}

/// How the `commands` are isolated on Linux, read from /proc, which needs no access to their
/// memory: each under a seccomp filter and, where user namespaces are allowed, seeing only an
/// interface `lo`.
fn isolation_of(commands: &[Pid]) -> Result<&'static str, Failure> {
    if !cfg!(target_os = "linux") {
        return Ok("the system's sandbox");
    }
    let read = |pid: &str, file: &str| {
        std::fs::read_to_string(format!("/proc/{pid}/{file}"))
            .map_err(|error| Failure(format!("isolation: /proc/{pid}/{file}: {error}")))
    };
    let interfaces = |pid: &str| -> Result<Vec<String>, Failure> {
        Ok(read(pid, "net/dev")?
            .lines()
            .skip(2)
            .filter_map(|line| line.split(':').next())
            .map(|name| name.trim().to_owned())
            .collect())
    };
    let empty_network = user_namespaces_allowed();
    for pid in commands {
        let pid = pid.to_string();
        // The filter exists for x86-64 and AArch64 only; elsewhere Landlock is all that applies.
        let filtered = read(&pid, "status")?
            .lines()
            .any(|line| line.split_whitespace().eq(["Seccomp:", "2"]));
        ensure(
            filtered || !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
            || format!("isolation: process {pid} has no seccomp filter"),
        )?;
        if empty_network {
            ensure(interfaces(&pid)? == ["lo"], || {
                format!("isolation: process {pid} sees a network beside lo")
            })?;
        }
    }
    Ok(if empty_network {
        "an empty network and the seccomp filter"
    } else {
        "the seccomp filter alone, as this system allows no namespace"
    })
}

/// The arrow keys and Enter choose an entry, its number chooses it at once, other escape
/// sequences and keys do nothing and are not shown, q and a lone Escape quit with exit code 0
/// and Ctrl+C with 130. The password entry shows each password on one private screen, cleared for
/// the next one; the help entry returns on Enter.
fn the_menu_keys_choose_and_quit() -> Result<(), Failure> {
    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    let moves = join(&[&DOWN.repeat(usize::from(PASSWORD_ENTRY)), UP]);
    // The password and the prompt arrive together; the count of passwords is checked at the end.
    session.answer(
        &join(&[IGNORED_KEY, CTRL_UP, &moves, ENTER]),
        &[PASSWORD_KIND],
    )?;
    session.answer(ENTER, &[PASSWORD_AGAIN])?;
    for _ in 0..2 {
        session.answer(ENTER, &[PASSWORD_AGAIN])?;
    }
    session.answer(ESCAPE, &[MENU_SHOWN])?;
    // The second time, random characters.
    session.answer(&digit(PASSWORD_ENTRY), &[PASSWORD_KIND])?;
    session.answer(b"3", &[b"random characters", PASSWORD_AGAIN])?;
    session.answer(b"q", &[MENU_SHOWN])?;
    // The menu keeps the password entry highlighted after it.
    session.answer(
        &join(&[&DOWN.repeat(HELP_FROM_PASSWORD), ENTER]),
        &[BACK_TO_MENU],
    )?;
    session.answer(ENTER, &[MENU_SHOWN])?;
    session.type_keys(b"q")?;
    // The tool needs a moment to end; close() would send Ctrl+C to a tool that is still running.
    ensure(session.drain_until_exit(10), || {
        "menu: q did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: q")?;
    let output = &session.output;
    ensure(count(output, PASSWORD_MADE) == 4, || {
        "menu: passwords were not regenerated".to_owned()
    })?;
    // One private screen each time the entry is chosen; it is cleared on entering and on leaving,
    // and once more before each password made again.
    ensure(count(output, ENTER_PRIVATE) == 2, || {
        "menu: passwords did not use private screens".to_owned()
    })?;
    ensure(count(output, LEAVE_PRIVATE) == 2, || {
        "menu: password screens were not left".to_owned()
    })?;
    ensure(count(output, CLEAR) == 6, || {
        "menu: a password was not replaced by the next".to_owned()
    })?;
    // A password of random characters may hold the key's letter; nothing else may.
    let others = String::from_utf8_lossy(output)
        .split("\r\n")
        .filter(|line| !is_character_password(line))
        .any(|line| line.contains('Z'));
    ensure(!others, || "menu: a key was shown".to_owned())?;
    println!(
        "menu: password regeneration, Escape/q return, private screens cleared, terminal restored"
    );
    println!("menu: the password entry asks for words or characters and makes both");

    // Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(ESCAPE)?;
    ensure(session.drain_until_exit(10), || {
        "menu: Escape did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: Escape")?;
    println!("menu: a lone Escape quits, exit code 0, terminal restored");

    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    session.type_keys(CTRL_C)?;
    session.wait(b"Cancelled")?;
    session.ends_with(CANCELLED, "menu: Ctrl+C")?;
    println!("menu: Ctrl+C, exit code 130, terminal restored");
    Ok(())
}

/// A line of a password of sixteen random characters, as `mhfe password` shows it.
fn is_character_password(line: &str) -> bool {
    let Some(password) = line.trim_end_matches('\r').strip_prefix("  ") else {
        return false;
    };
    password.chars().count() == 16
        && password
            .chars()
            .all(|char| char.is_ascii_alphanumeric() && !"01IOl".contains(char))
}

/// The process of the command that the menu started.
fn command_of(session: &Session) -> Result<Pid, Failure> {
    let output = Command::new("pgrep")
        .args(["-P", &session.pid().to_string()])
        .output()
        .map_err(|error| Failure(format!("pgrep: {error}")))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map(Pid::from_raw)
        .map_err(|_| Failure("menu: the menu started no command".to_owned()))
}

fn at_password_wait() -> Result<Session, Failure> {
    let mut session = menu_command(PASSWORD_ENTRY, &[PASSWORD_KIND])?;
    session.answer(ENTER, &[PASSWORD_AGAIN])?;
    Ok(session)
}

fn at_list() -> Result<Session, Failure> {
    menu_command(ENCRYPT_ENTRY, &[SETTINGS_QUESTION, LIST_SHOWN])
}

fn signal(pid: Pid, signal: Signal) -> Result<(), Failure> {
    kill(pid, signal).map_err(|error| Failure(format!("kill: {error}")))
}

/// A command of the menu is a process of its own: what stops it alone brings the menu back, what
/// stops the tool ends both, and the menu puts right what a killed command left.
fn a_menu_command_ends_alone_or_with_the_menu() -> Result<(), Failure> {
    let mut session = at_list()?;
    session.answer(b"q", &[b"Cancelled", BACK_TO_MENU])?;
    session.answer(ENTER, &[MENU_SHOWN])?;
    session.type_keys(b"q")?;
    ensure(session.drain_until_exit(10), || {
        "menu: q after a command did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: q in a command")?;
    println!("menu: q in a command's list ends that command; the menu comes back");

    for label in [
        "Ctrl+C in a list",
        "Ctrl+C at the passwords",
        "SIGTERM",
        "SIGTERM to a stopped command",
    ] {
        let mut session = if label == "Ctrl+C at the passwords" {
            at_password_wait()?
        } else {
            at_list()?
        };
        match label {
            "SIGTERM" => session.signal(Signal::SIGTERM)?,
            "SIGTERM to a stopped command" => {
                // As Ctrl+Z leaves a command in the milliseconds before its handlers are set,
                // under a shell with job control: here the kernel would drop that stop, and the
                // time is too short to hit.
                signal(command_of(&session)?, Signal::SIGSTOP)?;
                session.signal(Signal::SIGTERM)?;
            }
            _ => session.type_keys(CTRL_C)?,
        }
        ensure(session.drain_until_exit(10), || {
            format!("menu: {label} did not end the tool")
        })?;
        // A second "Cancelled" of the menu would come as it ends.
        session.idle(b"", 1.0)?;
        session.ends_with(CANCELLED, &format!("menu: {label}"))?;
        ensure(count(&session.output, b"Cancelled") == 1, || {
            format!("menu: {label}: not one Cancelled")
        })?;
        ensure(count(&session.output, LEAVE_PRIVATE) == 1, || {
            format!("menu: {label}: its screen was not left")
        })?;
        println!("menu: {label} ends the command and the tool, one Cancelled, exit code 130");
    }

    let mut session = at_password_wait()?;
    signal(command_of(&session)?, Signal::SIGTERM)?;
    session.answer(b"", &[b"Cancelled", MENU_SHOWN])?;
    session.type_keys(b"q")?;
    ensure(session.drain_until_exit(10), || {
        "menu: q after a command ended alone did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: a command ended alone")?;
    ensure(count(&session.output, b"Cancelled") == 1, || {
        "menu: a command ended alone: not one Cancelled".to_owned()
    })?;
    println!("menu: SIGTERM to the command alone, one Cancelled; the menu comes back");

    let mut session = at_list()?;
    signal(command_of(&session)?, Signal::SIGKILL)?;
    session.answer(
        b"",
        &[LEAVE_PRIVATE, b"crashed or was killed", BACK_TO_MENU],
    )?;
    session.answer(ENTER, &[MENU_SHOWN])?;
    session.type_keys(b"q")?;
    ensure(session.drain_until_exit(10), || {
        "menu: q after a killed command did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: a killed command")?;
    println!("menu: a killed command's screen left, terminal restored, the menu comes back");
    Ok(())
}
