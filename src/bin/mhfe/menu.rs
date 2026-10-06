//! The menu that `mhfe` shows when it starts without arguments in a terminal, as from a
//! double-click or a launcher script next to it.
//!
//! Each entry runs a command exactly as if it had been typed after `mhfe` and shows that command
//! in grey, so that the person can type it later; the command asks for its settings itself. An
//! entry is chosen with the arrow keys and Enter or at once with its number; Escape, or q, quits.
//! After a command the menu waits for Enter, so that a window opened by a double-click stays until
//! its result has been read. Password generation instead repeats on Enter and returns to the menu
//! on Escape, with each password shown on the private screen.

use std::ffi::OsString;
use std::io::{self, Write};

use anstream::eprintln;
use clap::{CommandFactory, Parser};

use crate::choice::{self, draw_entries, redraw_from, write_control, Answer, Question};
use crate::exit::{Failure, SUCCESS};
use crate::hidden_input::{self, Key};
use crate::readme;
use crate::style;
use crate::{protect, serve, show_failure, terminal, Cli};

/// What an entry does when it is chosen.
enum Action {
    /// Runs `mhfe` with these arguments.
    Run(Vec<OsString>),
    /// Shows `mhfe --help`.
    Help,
    /// Makes passwords until the person returns to the menu.
    Password,
    /// Repairs a plate, or makes repair words for one, as the person chooses.
    Repair,
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

pub fn run() -> Result<i32, Failure> {
    let title_lines = style::title("Memory-Hard Feistel Encryption for BIP39 Mnemonics");
    eprintln!();
    let hint_lines =
        style::hint("Encrypts a seed phrase into a password-protected container and recovers it.");
    let entries = entries();
    let mut selected = 0;
    // The lines the menu takes on the screen: the first time its title, blank lines and hint too,
    // later the wait to return to it.
    let mut menu_lines = title_lines + 1 + hint_lines;
    loop {
        eprintln!();
        menu_lines += 1;
        let chosen = choose(&entries, &mut selected, &mut menu_lines)?;
        // The menu leaves the screen once an entry is chosen, so that nothing of it stands above
        // what the entry shows: a command's steps, and then its summary in the menu's place.
        write_control(&redraw_from(menu_lines))?;
        let Some(chosen) = chosen else {
            return Ok(SUCCESS);
        };
        menu_lines = 0;
        match &entries[chosen].action {
            Action::Quit => return Ok(SUCCESS),
            Action::Help => Cli::command().print_long_help()?,
            Action::Password => match make_passwords() {
                Ok(()) => continue,
                Err(failure) => show_failure(&failure),
            },
            Action::Repair => match repair_or_make_words() {
                Ok(Some(arguments)) => {
                    if let Err(failure) = run_command(&arguments) {
                        show_failure(&failure);
                    }
                }
                // Escape at the question returns to the menu.
                Ok(None) => continue,
                Err(failure) => show_failure(&failure),
            },
            Action::Run(arguments) => {
                if let Err(failure) = run_command(arguments) {
                    show_failure(&failure);
                }
            }
        }
        eprintln!();
        let wait = "Press Enter to return to the menu (Esc quits).";
        if !wait_for_enter(wait)? {
            return Ok(SUCCESS);
        }
        // The blank line and the rows of the wait.
        menu_lines = 1 + style::rows(wait);
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
    for name in ["new", "encrypt", "decrypt", "check", "rekey", "wallets"] {
        entries.push(Entry::command(name));
    }
    // Both repair commands under one entry, which asks which (repair_or_make_words).
    entries.push(Entry {
        label: "Repair a plate, or make its repair words".to_owned(),
        command: "mhfe repair".to_owned(),
        action: Action::Repair,
    });
    // Passwords are made again on Enter until one suits (make_passwords).
    entries.push(Entry {
        action: Action::Password,
        ..Entry::command("password")
    });
    entries.push(Entry::command("self-test"));
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
fn choose(
    entries: &[Entry],
    selected: &mut usize,
    menu_lines: &mut usize,
) -> Result<Option<usize>, Failure> {
    // The terminal reads single keys before the menu appears, as a hidden prompt does, so that a
    // key pressed as soon as the menu shows is read as a key and never echoed.
    hidden_input::with_keys(|next_key| {
        let drawn_lines = draw(entries, *selected);
        *menu_lines += drawn_lines;
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
                Key::Digit(_) | Key::Help | Key::Other => continue,
            }
            write_control(&redraw_from(drawn_lines))?;
            draw(entries, *selected);
        }
    })
}

/// Draws the menu and returns how many lines it took: the entries with their commands in grey,
/// then the hint line.
fn draw(entries: &[Entry], selected: usize) -> usize {
    let lines: Vec<(&str, &str)> = entries
        .iter()
        .map(|entry| (entry.label.as_str(), entry.command.as_str()))
        .collect();
    let entry_lines = draw_entries(&lines, selected);
    eprintln!();
    // Only the first nine entries have a number key.
    let last = entries.len().min(choice::DIGIT_KEYS);
    let hint_lines = style::hint(&format!(
        "↑ ↓ choose · Enter runs · 1 to {last} run at once · Esc quits"
    ));
    entry_lines + 1 + hint_lines
}

/// Runs a command in a thread of its own, isolated as a command started directly would be: the
/// isolation cannot be undone, and the menu must stay free to start the fast mode later.
fn run_command(arguments: &[OsString]) -> Result<i32, Failure> {
    let typed = std::iter::once(OsString::from("mhfe")).chain(arguments.iter().cloned());
    let cli = Cli::try_parse_from(typed)
        .map_err(|error| Failure::internal(format!("The menu built a wrong command: {error}")))?;
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            protect::isolate(crate::needs_of(&cli.command));
            crate::run(cli.command)
        });
        worker
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Runs `mhfe password` on the private screen, of the kind the person chooses first, again on
/// every Enter, until Escape returns to the menu. Each password replaces the one before on the
/// screen, which is cleared when the person leaves; the generator wipes its own copy as soon as it
/// has shown it, before a key is read.
fn make_passwords() -> Result<(), Failure> {
    let question = Question {
        text: "What kind of password?",
        explanation: &[],
        more: Some(readme::PASSWORD),
        record: None,
    };
    // The answers with the options of mhfe password they choose.
    let kinds: [(Answer, Option<&str>); 3] = [
        (Answer::new("Five dice words", "easy to say and type"), None),
        (
            Answer::new(
                "Five words and a check word",
                "one mistyped word is repaired",
            ),
            Some("--check-word"),
        ),
        // --chars alone means sixteen characters.
        (
            Answer::new("Sixteen random characters", "letters and digits"),
            Some("--chars"),
        ),
    ];
    let (answers, options): (Vec<Answer>, Vec<Option<&str>>) = kinds.into_iter().unzip();
    // Escape here returns to the menu too.
    let Some(kind) = choice::choose(&question, &answers, None)? else {
        return Ok(());
    };
    let mut arguments = vec![OsString::from("password")];
    arguments.extend(options[kind].map(OsString::from));
    let input = terminal::Input::new(false);
    let screen = terminal::PrivateScreen::enter_to_show(&input);
    loop {
        run_command(&arguments)?;
        eprintln!();
        if !wait_for_enter("Press Enter for another password (Esc returns to the menu).")? {
            return Ok(());
        }
        screen.clear();
    }
}

/// Asks whether to repair a plate or to make repair words for one; the arguments of the command,
/// or `None` on Escape.
fn repair_or_make_words() -> Result<Option<Vec<OsString>>, Failure> {
    let question = Question {
        text: "Repair a plate, or make repair words for one?",
        explanation: &[],
        more: Some(readme::REPAIR),
        record: None,
    };
    let answers = [
        Answer::new(
            "Repair a plate",
            "with its repair words, without the password",
        ),
        Answer::new("Make repair words", "for a container you have"),
    ];
    let command = match choice::choose(&question, &answers, None)? {
        Some(0) => "repair",
        Some(_) => "repair-words",
        None => return Ok(None),
    };
    Ok(Some(vec![OsString::from(command)]))
}

/// Waits for Enter; false on Escape or its aliases. The caller decides where those keys lead.
fn wait_for_enter(prompt: &str) -> Result<bool, Failure> {
    // Switched before the question appears, as in choose().
    let back = hidden_input::with_keys(|next_key| {
        style::prompt(prompt);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::choice::LINE_WIDTH;

    #[test]
    fn every_entry_is_a_valid_command() {
        for entry in entries() {
            match entry.action {
                Action::Run(arguments) => {
                    let typed = std::iter::once(OsString::from("mhfe")).chain(arguments);
                    assert!(Cli::try_parse_from(typed).is_ok(), "{}", entry.command);
                }
                Action::Password => {
                    assert!(Cli::try_parse_from(["mhfe", "password"]).is_ok());
                }
                Action::Repair => {
                    assert!(Cli::try_parse_from(["mhfe", "repair"]).is_ok());
                    assert!(Cli::try_parse_from(["mhfe", "repair-words"]).is_ok());
                }
                Action::Help | Action::Quit => {}
            }
        }
    }

    #[test]
    fn entries_are_labelled_with_the_command_summaries() {
        let labels: Vec<String> = entries().into_iter().map(|entry| entry.label).collect();
        assert!(labels.contains(&"Encrypt a seed phrase into a container".to_owned()));
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
}
