//! The menu that `mhfe` shows when it starts without arguments in a terminal, as from a
//! double-click or a launcher script next to it.
//!
//! Each entry runs a command exactly as if it had been typed after `mhfe`, with its default
//! settings, and shows that command in grey, so that the person can type it later; a command
//! with other settings, such as `mhfe encrypt --pim 1`, is typed. An entry is chosen with the
//! arrow keys and Enter or at once with its number; q quits. After a command the menu waits for
//! Enter, so that a window opened by a double-click stays until its result has been read.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};

use anstream::eprintln;
use clap::{CommandFactory, Parser};

use crate::exit::{Failure, SUCCESS};
use crate::hidden_input::{self, Key};
use crate::style::{self, paint, ACCENT, MUTED, STRONG};
use crate::{serve, show_failure, Cli};

/// The width that a menu line must not exceed; the menu redraws itself by moving the cursor up
/// line by line, which a line wrapped by the terminal would upset. As style.rs: 78 columns.
const LINE_WIDTH: usize = 78;

/// Moves the cursor up `lines_above` lines to the start of the line, then clears to the end of
/// the screen (VT100 "cursor up" and "erase in display").
fn redraw_from(lines_above: usize) -> String {
    format!("\x1b[{lines_above}A\r\x1b[J")
}

/// What an entry does when it is chosen.
enum Action {
    /// Runs `mhfe` with these arguments.
    Run(Vec<OsString>),
    /// Shows `mhfe --help`.
    Help,
    Quit,
}

struct Entry {
    label: String,
    /// The typed command that does the same, shown in grey; empty for Quit.
    command: String,
    action: Action,
}

impl Entry {
    /// An entry for a command without options, labelled with the summary that `mhfe --help`
    /// gives for it.
    fn command(name: &str) -> Self {
        let label = Cli::command()
            .find_subcommand(name)
            .and_then(|command| command.get_about())
            .map(|about| about.to_string())
            .unwrap_or_else(|| name.to_owned());
        Self {
            label,
            command: format!("mhfe {name}"),
            action: Action::Run(vec![name.into()]),
        }
    }
}

/// Whether the menu can run: it reads single keys from a terminal and draws on one. Anything
/// else, such as a script or a pipe, gets the help instead, as before.
pub fn can_run() -> bool {
    io::stdin().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

pub fn run() -> Result<i32, Failure> {
    style::title("Memory-Hard Feistel Encryption for BIP39 Mnemonics");
    eprintln!();
    style::hint(
        "Encrypts a BIP39 recovery phrase into a password-protected 24-word container and \
         recovers it. Choose what to do; the grey command does the same when typed.",
    );
    let entries = entries();
    let mut selected = 0;
    loop {
        eprintln!();
        let Some(chosen) = choose(&entries, &mut selected)? else {
            return Ok(SUCCESS);
        };
        match &entries[chosen].action {
            Action::Quit => return Ok(SUCCESS),
            Action::Help => Cli::command().print_long_help()?,
            Action::Run(arguments) => {
                if let Err(failure) = run_command(arguments) {
                    show_failure(&failure);
                }
            }
        }
        eprintln!();
        if !wait_for_enter()? {
            return Ok(SUCCESS);
        }
    }
}

/// The entries: the fast mode first when a browser tool and its checksum file lie next to the
/// program, as a double-click served it at once before there was a menu.
fn entries() -> Vec<Entry> {
    let mut entries = Vec::new();
    match serve::page_next_to_program() {
        Ok(Some(page)) => {
            let mut entry = Entry::command("serve");
            entry.command = format!("mhfe serve {}", serve::file_name(&page));
            entry.action = Action::Run(vec!["serve".into(), page.into_os_string()]);
            entries.push(entry);
        }
        Ok(None) => {}
        Err(failure) => {
            eprintln!();
            style::warn("The fast mode is not offered.", &failure.message);
        }
    }
    for name in ["encrypt", "decrypt", "check", "password"] {
        entries.push(Entry::command(name));
    }
    entries.push(Entry {
        label: "Show every command and option".to_owned(),
        command: "mhfe --help".to_owned(),
        action: Action::Help,
    });
    entries.push(Entry {
        label: "Quit".to_owned(),
        command: String::new(),
        action: Action::Quit,
    });
    entries
}

/// Draws the entries and reads keys until one is chosen; `None` means quit. `selected` keeps the
/// highlighted entry for the next time the menu is shown.
fn choose(entries: &[Entry], selected: &mut usize) -> Result<Option<usize>, Failure> {
    // The terminal reads single keys before the menu appears, as a hidden prompt does, so that a
    // key pressed as soon as the menu shows is read as a key and never echoed.
    hidden_input::with_keys(|next_key| {
        let drawn_lines = draw(entries, *selected);
        loop {
            match next_key()? {
                Key::Up => *selected = (*selected + entries.len() - 1) % entries.len(),
                Key::Down => *selected = (*selected + 1) % entries.len(),
                Key::Enter => return Ok(Some(*selected)),
                Key::Digit(number) if usize::from(number) <= entries.len() => {
                    *selected = usize::from(number) - 1;
                    return Ok(Some(*selected));
                }
                Key::Quit => return Ok(None),
                Key::Digit(_) | Key::Other => continue,
            }
            write_control(&redraw_from(drawn_lines))?;
            draw(entries, *selected);
        }
    })
}

/// Draws the menu and returns how many lines it took. The highlighted entry has a cyan marker
/// and a bold label, so that it stands out also without colours.
fn draw(entries: &[Entry], selected: usize) -> usize {
    let label_width = entries
        .iter()
        .map(|entry| entry.label.chars().count())
        .max()
        .unwrap_or(0);
    for (index, entry) in entries.iter().enumerate() {
        let number = paint(MUTED, index + 1);
        let (marker, label) = if index == selected {
            (paint(ACCENT, "›"), paint(STRONG, &entry.label))
        } else {
            (" ".to_owned(), entry.label.clone())
        };
        // Marker, number and the gaps: "› 1  " and two spaces before the command.
        let command_room = LINE_WIDTH.saturating_sub(5 + label_width + 2);
        let command = shortened(&entry.command, command_room);
        if command.is_empty() {
            eprintln!("{marker} {number}  {label}");
        } else {
            // Padded by hand: the width of a painted label would count its colour codes.
            let padding = " ".repeat(label_width - entry.label.chars().count());
            eprintln!(
                "{marker} {number}  {label}{padding}  {}",
                paint(MUTED, command)
            );
        }
    }
    eprintln!();
    let last = entries.len();
    style::hint(&format!(
        "↑ ↓ choose · Enter runs · 1 to {last} run at once · q quits"
    ));
    entries.len() + 2
}

/// `text` cut to `room` characters with "…" at the end, so that a long page name cannot wrap
/// the line.
fn shortened(text: &str, room: usize) -> String {
    if text.chars().count() <= room {
        return text.to_owned();
    }
    let kept: String = text.chars().take(room.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn run_command(arguments: &[OsString]) -> Result<i32, Failure> {
    let typed = std::iter::once(OsString::from("mhfe")).chain(arguments.iter().cloned());
    let cli = Cli::try_parse_from(typed)
        .map_err(|error| Failure::internal(format!("The menu built a wrong command: {error}")))?;
    crate::run(cli.command)
}

/// Waits for Enter; false when the person quits instead.
fn wait_for_enter() -> Result<bool, Failure> {
    // Switched before the question appears, as in choose().
    let back = hidden_input::with_keys(|next_key| {
        style::prompt("Press Enter to return to the menu (q quits).");
        io::stderr().flush()?;
        loop {
            match next_key()? {
                Key::Enter => return Ok(true),
                Key::Quit => return Ok(false),
                _ => continue,
            }
        }
    });
    // The key itself was not shown.
    eprintln!();
    back
}

/// Writes a cursor-control sequence as it is: anstream would remove it when NO_COLOR is set.
fn write_control(sequence: &str) -> Result<(), Failure> {
    let mut terminal = io::stderr();
    terminal.write_all(sequence.as_bytes())?;
    terminal.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_is_a_valid_command() {
        for entry in entries() {
            if let Action::Run(arguments) = entry.action {
                let typed = std::iter::once(OsString::from("mhfe")).chain(arguments);
                assert!(Cli::try_parse_from(typed).is_ok(), "{}", entry.command);
            }
        }
    }

    #[test]
    fn entries_are_labelled_with_the_command_summaries() {
        let labels: Vec<String> = entries().into_iter().map(|entry| entry.label).collect();
        assert!(labels.contains(&"Encrypt a recovery phrase into a 24-word container".to_owned()));
        assert_eq!(labels.last().map(String::as_str), Some("Quit"));
    }

    #[test]
    fn every_menu_line_fits_the_width() {
        let entries = entries();
        let label_width = entries.iter().map(|entry| entry.label.len()).max().unwrap();
        let longest_command = entries
            .iter()
            .map(|entry| entry.command.len())
            .max()
            .unwrap();
        assert!(5 + label_width + 2 + longest_command <= LINE_WIDTH);
    }

    #[test]
    fn a_long_command_is_shortened() {
        assert_eq!(
            shortened("mhfe serve tool.html", 40),
            "mhfe serve tool.html"
        );
        assert_eq!(
            shortened("mhfe serve a-very-long-name.html", 15),
            "mhfe serve a-v…"
        );
    }
}
