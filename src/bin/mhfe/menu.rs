//! The menu that `mhfe` shows when it starts without arguments in a terminal, as from a
//! double-click or a launcher script next to it.
//!
//! Each entry runs a command exactly as if it had been typed after `mhfe` and shows that command
//! in grey, so that the person can type it later; the command asks for its settings itself. An
//! entry is chosen with the arrow keys and Enter or at once with its number; Escape, or q, quits.
//! After a command the menu waits for Enter, so that a window opened by a double-click stays until
//! its result has been read. Password generation instead repeats on Enter and returns to the menu
//! on Escape, with each password shown on the private screen. The self-test asks first whether to
//! run the published vectors too, which take minutes.

use std::ffi::OsString;
use std::io::{self, Write};

use anstream::eprintln;
use clap::{CommandFactory, Parser};

use crate::choice::{self, draw_entries, redraw_from, write_control, Answer, Question};
use crate::container_repair;
use crate::exit::{Failure, SUCCESS};
use crate::hidden_input::{self, Key};
use crate::made_password::PasswordKind;
use crate::readme;
use crate::settings::Operation;
use crate::style;
use crate::{protect, self_test, serve, show_failure, startup, terminal, Cli};

/// What an entry does when it is chosen.
enum Action {
    /// Runs `mhfe` with these arguments.
    Run(Vec<OsString>),
    /// Shows `mhfe --help`.
    Help,
    /// Makes passwords until the person returns to the menu.
    Password,
    /// Repairs a container phrase, or makes repair words for one, as the person chooses.
    Repair,
    /// Tests every part, with the published vectors or without, as the person chooses.
    SelfTest,
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

/// The checks at start, once for every command of the menu, then the menu. They run in the menu's
/// own thread before anything is isolated, so with no network namespace: the menu never enters
/// one, and a command of the menu, which runs in a thread of it, is isolated without one
/// (protect.rs). When a check fails, the window that a double-click opened stays until Enter, so
/// that the failure can be read.
pub fn start() -> Result<i32, Failure> {
    if let Err(failure) = startup::check(startup::Checks::EveryPart) {
        // Ctrl+C at the wait restores the terminal, which the wait switches to single keys.
        terminal::stop_on_ctrl_c();
        eprintln!();
        wait_for_enter("Press Enter to quit.")?;
        return Err(failure);
    }
    terminal::stop_on_ctrl_c();
    run()
}

fn run() -> Result<i32, Failure> {
    let header_lines = draw_header();
    let entries = entries();
    let mut selected = 0;
    // The lines the menu takes on the screen: the first time its title, blank lines and hint too,
    // later the wait to return to it.
    let mut menu_lines = header_lines;
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
            // Escape at the question of either returns to the menu.
            Action::Repair => {
                if !run_asked(repair_or_make_words()) {
                    continue;
                }
            }
            Action::SelfTest => {
                if !run_asked(which_self_test()) {
                    continue;
                }
            }
            Action::Run(arguments) => run_shown(arguments),
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

/// The menu heading, also redrawn after a width change discards the old layout.
fn draw_header() -> usize {
    let title_lines = style::title("Memory-Hard Feistel Encryption for BIP39 Mnemonics");
    eprintln!();
    title_lines
        + 1
        + style::hint("Encrypts a seed phrase into a password-protected container and recovers it.")
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
        label: "Repair a container phrase, or make its repair words".to_owned(),
        command: "mhfe repair".to_owned(),
        action: Action::Repair,
    });
    // Passwords are made again on Enter until one suits (make_passwords).
    entries.push(Entry {
        action: Action::Password,
        ..Entry::command("password")
    });
    // With the published vectors or without, which the entry asks (which_self_test).
    entries.push(Entry {
        action: Action::SelfTest,
        ..Entry::command("self-test")
    });
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
        let mut columns = hidden_input::columns();
        let mut drawn_lines = draw(entries, *selected);
        *menu_lines += drawn_lines;
        loop {
            let key = next_key()?;
            let current_columns = hidden_input::columns();
            if current_columns != columns {
                // Terminals differ in whether a resize reflows existing rows. Discard that
                // layout before any key, including Enter or Escape, uses its old row count.
                write_control("\x1b[2J\x1b[H")?;
                *menu_lines = draw_header();
                eprintln!();
                drawn_lines = draw(entries, *selected);
                *menu_lines += 1 + drawn_lines;
                columns = current_columns;
            }
            match key {
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
            *menu_lines = menu_lines.saturating_sub(drawn_lines);
            drawn_lines = draw(entries, *selected);
            *menu_lines += drawn_lines;
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
/// Runs the command a question of the menu chose, or shows why it could not ask; false when the
/// person went back with Escape and no command runs.
fn run_asked(asked: Result<Option<Vec<OsString>>, Failure>) -> bool {
    match asked {
        Ok(Some(arguments)) => run_shown(&arguments),
        Ok(None) => return false,
        Err(failure) => show_failure(&failure),
    }
    true
}

/// Runs a command of the menu and shows its failure, after which the menu comes back.
fn run_shown(arguments: &[OsString]) {
    if let Err(failure) = run_command(arguments) {
        show_failure(&failure);
    }
}

fn run_command(arguments: &[OsString]) -> Result<i32, Failure> {
    let typed = std::iter::once(OsString::from("mhfe")).chain(arguments.iter().cloned());
    let cli = Cli::try_parse_from(typed)
        .map_err(|error| Failure::internal(format!("The menu built a wrong command: {error}")))?;
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            protect::isolate(crate::needs_of(&cli.command));
            // The checks at start ran once before the menu, in its own thread, which is not
            // isolated; what isolate() reports for this thread is probed here.
            protect::verify_isolation();
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
    let answers = PasswordKind::MADE.map(PasswordKind::answer);
    // Escape here returns to the menu too.
    let Some(chosen) = choice::choose(&question, &answers, None)? else {
        return Ok(());
    };
    let mut arguments = vec![OsString::from("password")];
    arguments.extend(
        PasswordKind::MADE[chosen]
            .password_option()
            .map(OsString::from),
    );
    let input = terminal::Input::terminal_only();
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

/// Asks whether to repair a container phrase or to make repair words for one; the arguments of the
/// command, or `None` on Escape.
fn repair_or_make_words() -> Result<Option<Vec<OsString>>, Failure> {
    let question = Question {
        text: "Repair a container phrase, or make repair words for one?",
        explanation: &[],
        more: Some(readme::REPAIR),
        record: None,
    };
    let answers = [
        Answer::new(
            Operation::Repair.title(),
            "with its repair words, without the password",
        ),
        Answer::new(container_repair::WORDS_TITLE, "for a container you have"),
    ];
    let command = match choice::choose(&question, &answers, None)? {
        Some(0) => "repair",
        Some(_) => "repair-words",
        None => return Ok(None),
    };
    Ok(Some(vec![OsString::from(command)]))
}

/// The commands of the answers of [`which_self_test`], in their order.
const SELF_TESTS: [&[&str]; 2] = [&["self-test"], &["self-test", "--vectors"]];

/// Asks whether to test every part alone, in seconds, or with the published vectors, in minutes;
/// the arguments of the command, or `None` on Escape.
fn which_self_test() -> Result<Option<Vec<OsString>>, Failure> {
    let question = Question {
        text: "Which test?",
        explanation: &[],
        more: Some(readme::SELF_TEST),
        record: None,
    };
    let answers = [
        Answer::new("Every part", "a few seconds"),
        Answer::new(
            "Every part and the published vectors",
            self_test::vectors_cost(),
        ),
    ];
    let Some(answer) = choice::choose(&question, &answers, None)? else {
        return Ok(None);
    };
    Ok(Some(
        SELF_TESTS[answer].iter().map(OsString::from).collect(),
    ))
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
                // The answers of which_self_test: every part, then with the published vectors.
                Action::SelfTest => {
                    for arguments in SELF_TESTS {
                        let typed = std::iter::once("mhfe").chain(arguments.iter().copied());
                        assert!(Cli::try_parse_from(typed).is_ok(), "{arguments:?}");
                    }
                    assert_eq!(SELF_TESTS[1].last(), Some(&"--vectors"));
                    assert!(!SELF_TESTS[0].contains(&"--vectors"));
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
        // The fast mode's entry, shown when a browser tool lies next to the program, with the
        // name of the package's tool page.
        let fast_mode = "mhfe serve tool.html".len();
        let longest_command = entries
            .iter()
            .map(|entry| entry.command.len())
            .chain([fast_mode])
            .max()
            .unwrap();
        assert!(5 + label_width + 2 + longest_command <= LINE_WIDTH);
    }
}
