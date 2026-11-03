//! `mhfe self-test`: its report at a terminal, with NO_COLOR, in a pipe and from the menu, and
//! copies of the program with one bit flipped in a known answer of the checks at start.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::session::{Session, Start, code, find, rfind, run_without_terminal, shown};
use super::text::{has_colour, screen_lines, wrapped};
use super::{
    BACK_TO_MENU, ENTER, ERROR_MARK, ESCAPE, INTERNAL_ERROR, LIST_SHOWN, MENU_SHOWN,
    PASSWORD_ENTRY, SELF_TEST_LINK, TEXT_WIDTH, digit, ensure, join,
};
use crate::{Failure, at};

/// mhfe's colours as its terminal output writes them (src/bin/mhfe/style.rs): bold cyan for the
/// tool's name, grey (bright black) for labels and secondary text, bold for what matters and bold
/// green for a pass, each ended by a reset.
const NAME: &str = "\x1b[1m\x1b[36m";
const GREY: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const PASS: &str = "\x1b[1m\x1b[32m";
const RESET: &str = "\x1b[0m";
/// A fact's label is padded to 10 columns (src/bin/mhfe/style.rs).
const FACT_LABEL_WIDTH: usize = 10;
/// How the self-test words a part that this system cannot test (ComponentOutcome::NotAvailable).
const NOT_AVAILABLE: &str = "not available here: ";
/// The parts `mhfe self-test` tests, in the order of its report, and the mark each gets when it
/// gives its known answers or its protection holds (verdicts in src/bin/mhfe/self_test.rs).
/// Hidden input is tested only at a terminal.
const PARTS: [(&str, &str); 29] = [
    ("Cipher hashes", "as published"),
    ("Argon2id", "as published"),
    ("Cipher rounds", "as published"),
    ("Formats", "as published"),
    ("Container facts", "as published"),
    ("Keep advice", "as published"),
    ("Passwords (Unicode 18)", "as published"),
    ("BIP39 words", "as published"),
    ("Repair words (MHFE-REPAIR-1)", "as published"),
    ("Search for missing words", "as published"),
    (
        "Password check word (MHFE-PASSWORD-CHECK-1)",
        "as published",
    ),
    ("Wallet hashes", "as published"),
    ("BIP39 seeds", "as published"),
    ("BIP32 keys", "as published"),
    ("Address encodings", "as published"),
    ("Wallet check (MHFE-WALLET-CHECK-SEED-1)", "as published"),
    ("Hidden wallets", "as published"),
    ("Rekey", "as published"),
    ("Rehearsal", "as published"),
    ("Argon2id at 64 and 256 MiB", "as published"),
    ("Password generator", "as published"),
    ("Word hints", "as published"),
    ("Random source", "healthy"),
    ("Address search", "as published"),
    ("Chosen word of a new phrase", "as published"),
    ("Locked memory", "works"),
    ("Core dumps", "off"),
    ("Isolation", "enforced"),
    ("Hidden input", "echo off"),
];
/// What the published vectors cost by the estimate of the default settings (vectors_cost in
/// src/bin/mhfe/self_test.rs).
const VECTORS_COST: &str = "about 2 to 4 minutes, 2 GiB";
const ALL_PASSED: &str = "Every part of this program gives its known answers.";
/// The verdict of a self-test that a part failed (alarm in src/bin/mhfe/self_test.rs).
const ALARM: [&str; 2] = [
    "✗ A part of this program does NOT give its known answers.",
    "! Do NOT use it for a real phrase; try another computer or build.",
];
/// How long a self-test is waited for, beyond which it counts as hung.
const SELF_TEST_SECONDS: u64 = 120;
/// The menu's entry of the self-test, below the password entry, its question and its two
/// answers, the first marked.
const SELF_TEST_ENTRY: u8 = PASSWORD_ENTRY + 1;
const SELF_TEST_ANSWERS: [&str; 2] = [
    "› 1  Every part                            a few seconds",
    "  2  Every part and the published vectors  about 2 to 4 minutes, 2 GiB",
];
const PRESS_ENTER_TO_QUIT: &str = "Press Enter to quit.";
/// Known answers that the checks at start compare, each held once in the program, with the part
/// that compares it and what that part reports once a bit of the text is flipped, at start and in
/// the full self-test: the six repair words of the container phrase of zero-12 (MHFE-REPAIR-1),
/// and the third vector of MHFE-PASSWORD-CHECK-1, both public vectors of the specification.
const DAMAGED_VECTORS: [(&[u8], &str, &str, &str); 2] = [
    (
        b"credit buzz orbit tired sail coffee",
        "Repair words (MHFE-REPAIR-1)",
        "card 1 of 1 gives other words",
        "card 1 of 4 gives other words",
    ),
    (
        b"jovial trailing chokehold pavilion cresting ninth",
        "Password check word (MHFE-PASSWORD-CHECK-1)",
        "vector 3 of 4 gives other words",
        "vector 3 of 4 gives other words",
    ),
];

/// How text is written: plain, or painted in a colour and reset.
type Paint = fn(&str, &str) -> String;

fn plain(_: &str, text: &str) -> String {
    text.to_owned()
}

fn painted(colour: &str, text: &str) -> String {
    format!("{colour}{text}{RESET}")
}

/// A fact of a summary: its grey label padded to the facts' column, then its value.
fn fact_line(paint: Paint, label: &str, value: &str) -> String {
    format!(
        "  {} {value}",
        paint(GREY, &format!("{label:<FACT_LABEL_WIDTH$}"))
    )
}

/// The lines of `mhfe self-test` before its verdict when its parts give `marks`: the title; a
/// row per part, with its grey label in a column as wide as the widest and its mark painted as a
/// pass and wrapped under its own column; the time it took, as [`took_a_few_seconds`] reads it;
/// and the published vectors, which it did not run.
fn report(marks: &[(&str, String)], paint: Paint) -> Vec<String> {
    let width = marks
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    // Two columns of indent before the label and two after it.
    let column = 2 + width + 2;
    let mut lines = vec![
        String::new(),
        format!(
            "{} {} {}",
            paint(NAME, "MHFE"),
            paint(GREY, "·"),
            paint(BOLD, "Test this program")
        ),
    ];
    for (label, mark) in marks {
        // A protection this system does not offer is said in grey, not as a pass.
        let style = if mark.starts_with(NOT_AVAILABLE) {
            GREY
        } else {
            PASS
        };
        let mut rows = wrapped(mark, TEXT_WIDTH - column).into_iter();
        let first = rows.next().unwrap_or_default();
        lines.push(format!(
            "  {}  {}",
            paint(GREY, &format!("{label:<width$}")),
            paint(style, &first)
        ));
        lines.extend(rows.map(|row| format!("{}{}", " ".repeat(column), paint(style, &row))));
    }
    let vectors = paint(
        GREY,
        &format!("not run · mhfe self-test --vectors, {VECTORS_COST}"),
    );
    lines.extend([
        String::new(),
        fact_line(paint, "Time", "a few seconds"),
        fact_line(paint, "Vectors", &vectors),
        String::new(),
    ]);
    lines
}

/// The verdict of a self-test whose every part passed, and the line break after it.
fn passed(paint: Paint) -> Vec<String> {
    vec![format!("{} {ALL_PASSED}", paint(PASS, "✓")), String::new()]
}

/// The marks of every part, at a terminal or without one on standard input.
fn marks(at_a_terminal: bool) -> Vec<(&'static str, String)> {
    PARTS
        .iter()
        .map(|&(label, mark)| match label {
            "Hidden input" if !at_a_terminal => (label, format!("{NOT_AVAILABLE}no terminal")),
            _ => (label, mark.to_owned()),
        })
        .collect()
}

/// Whether `value` is how the self-test states a few seconds: below ten seconds with a decimal,
/// whole seconds above, below a minute (seconds() in src/bin/mhfe/self_test.rs).
fn a_few_seconds(value: &str) -> bool {
    let Some(number) = value.strip_suffix(" s") else {
        return false;
    };
    match number.as_bytes() {
        [whole, b'.', tenth] => whole.is_ascii_digit() && tenth.is_ascii_digit(),
        [tens, ones] => (b'1'..=b'5').contains(tens) && ones.is_ascii_digit(),
        _ => false,
    }
}

/// `lines` with the value of their Time fact read as "a few seconds" where it says so.
fn took_a_few_seconds(lines: Vec<String>, paint: Paint) -> Vec<String> {
    let took = fact_line(paint, "Time", "");
    lines
        .into_iter()
        .map(|line| match line.strip_prefix(&took) {
            Some(value) if a_few_seconds(value) => format!("{took}a few seconds"),
            _ => line,
        })
        .collect()
}

pub(super) fn run(root: &Path) -> Result<(), Failure> {
    the_self_test_reports_every_part()?;
    a_damaged_known_answer_stops_the_program(root)
}

/// The names of the parts in the lines "Testing <part>…" that a terminal shows while each is
/// tested.
fn parts_named(output: &str) -> Vec<String> {
    output
        .split('\r')
        .filter_map(|piece| piece.strip_prefix("  Testing "))
        .filter_map(|rest| rest.split_once('…').map(|(name, _)| name.to_owned()))
        .collect()
}

/// `mhfe self-test` tests every part in seconds and reports each with its mark in mhfe's style:
/// in colour at a terminal, without colour codes with NO_COLOR and in a pipe, and from the menu,
/// whose entry asks which of the two tests to run.
fn the_self_test_reports_every_part() -> Result<(), Failure> {
    let mut session = Session::start(Start {
        colour: true,
        ..Start::of(&["self-test"])
    })?;
    ensure(session.drain_until_exit(SELF_TEST_SECONDS), || {
        "self-test: it did not end".to_owned()
    })?;
    session.ends_with(0, "self-test")?;
    // The line that names the part being tested is written over by the report's first row.
    let shown_lines: Vec<String> = String::from_utf8_lossy(&session.output)
        .split("\r\n")
        .map(|line| line.rsplit('\r').next().unwrap_or_default().to_owned())
        .collect();
    let expected = [report(&marks(true), painted), passed(painted)].concat();
    let got = took_a_few_seconds(shown_lines, painted);
    ensure(got == expected, || {
        format!("self-test: the report is {got:?}")
    })?;
    println!("self-test: every part with its pass mark, in mhfe's colours; ✓ and exit code 0");

    let mut session = Session::of(&["self-test"])?;
    ensure(session.drain_until_exit(SELF_TEST_SECONDS), || {
        "self-test, NO_COLOR: it did not end".to_owned()
    })?;
    session.ends_with(0, "self-test, NO_COLOR")?;
    ensure(!has_colour(&session.output), || {
        "self-test, NO_COLOR: colour codes".to_owned()
    })?;
    // At a terminal a line names each part while it is tested, in the order of the report.
    let named = parts_named(&String::from_utf8_lossy(&session.output));
    let labels: Vec<String> = PARTS.iter().map(|(label, _)| (*label).to_owned()).collect();
    ensure(named == labels, || format!("self-test: {named:?} named"))?;
    // Erased before the report: the screen shows the report alone.
    let got = took_a_few_seconds(screen_lines(&session.output), plain);
    let expected = [report(&marks(true), plain), passed(plain)].concat();
    ensure(got == expected, || {
        format!("self-test, NO_COLOR: the screen shows {got:?}")
    })?;
    println!("self-test, NO_COLOR: no colour codes; each part named while tested, then erased");

    // Neither NO_COLOR nor a dumb terminal: only the pipe turns colour off.
    let output = Command::new(super::program())
        .arg("self-test")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE")
        .env("TERM", "xterm-256color")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure(error.to_string()))?;
    let exit = code(&output);
    ensure(exit == 0, || {
        format!("self-test in a pipe: exit code {exit}")
    })?;
    ensure(output.stdout.is_empty(), || {
        "self-test in a pipe: wrote to standard output".to_owned()
    })?;
    ensure(!output.stderr.contains(&0x1b), || {
        "self-test in a pipe: control sequences in the report".to_owned()
    })?;
    let lines = String::from_utf8_lossy(&output.stderr)
        .split('\n')
        .map(str::to_owned)
        .collect();
    let got = took_a_few_seconds(lines, plain);
    let expected = [report(&marks(false), plain), passed(plain)].concat();
    ensure(got == expected, || {
        format!("self-test in a pipe: the report is {got:?}")
    })?;
    println!("self-test in a pipe: the same report, without colour codes or the part being tested");

    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    let which = join(&[b"Which test?\r\n", SELF_TEST_LINK.as_bytes()]);
    let answers: Vec<Vec<u8>> = SELF_TEST_ANSWERS
        .iter()
        .map(|answer| format!("\r\n{answer}\r\n").into_bytes())
        .collect();
    session.answer(
        &digit(SELF_TEST_ENTRY),
        &[&which, &answers[0], &answers[1], LIST_SHOWN],
    )?;
    session.answer(ESCAPE, &[MENU_SHOWN])?;
    session.answer(&digit(SELF_TEST_ENTRY), &[&which, LIST_SHOWN])?;
    let start = session.output.len();
    session.answer_within(b"1", &[BACK_TO_MENU], SELF_TEST_SECONDS)?;
    let title = find(
        &session.output,
        "\r\nMHFE · Test this program".as_bytes(),
        start,
    )
    .unwrap_or(start);
    let end = rfind(&session.output, BACK_TO_MENU).unwrap_or(session.output.len());
    let got = took_a_few_seconds(screen_lines(&session.output[title..end]), plain);
    // The menu leaves a blank line before its wait.
    let expected = [
        report(&marks(true), plain),
        passed(plain),
        vec![String::new()],
    ]
    .concat();
    ensure(got == expected, || {
        format!("menu, every part: the screen shows {got:?}")
    })?;
    session.type_keys(ESCAPE)?;
    ensure(session.drain_until_exit(10), || {
        "menu: Escape after the self-test did not end the tool".to_owned()
    })?;
    session.ends_with(0, "menu: Escape after the self-test")?;
    println!(
        "menu: the self-test entry asks which test, offering both; Escape returns to the menu"
    );
    println!("menu: every part tested from the menu, with the same report");
    Ok(())
}

/// A copy of the program in `folder` with the lowest bit of the last letter of `text`, which the
/// program holds once, flipped, as a damaged download or a faulty memory might; its path.
fn damaged_copy(folder: &Path, text: &[u8]) -> Result<PathBuf, Failure> {
    let program = super::program();
    let mut data = fs::read(program).map_err(|error| at(program, error))?;
    let place = find(&data, text, 0);
    let once = place.is_some_and(|place| find(&data, text, place + 1).is_none());
    ensure(once, || {
        format!(
            "damaged copy: {} is not held once in the program",
            shown(text)
        )
    })?;
    let last = place.unwrap_or_default() + text.len() - 1;
    data[last] ^= 1;
    let copy = folder.join(program.file_name().unwrap_or_default());
    fs::write(&copy, data).map_err(|error| at(&copy, error))?;
    let mut permissions = fs::metadata(&copy)
        .map_err(|error| at(&copy, error))?
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
    fs::set_permissions(&copy, permissions).map_err(|error| at(&copy, error))?;
    if cfg!(target_os = "macos") {
        // macOS on Apple silicon runs only signed code, and the flipped bit breaks the signature
        // the linker gave the program: the copy is signed again in the same way, ad hoc.
        let signed = Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&copy)
            .output()
            .is_ok_and(|output| output.status.success());
        ensure(signed, || "damaged copy: codesign failed".to_owned())?;
    }
    Ok(copy)
}

/// What a command shows when `part` fails its known answers at start, and nothing else: one
/// error wrapped to the text width under its first line, then the link to the README section of
/// the self-test (failure_text in src/bin/mhfe/startup.rs).
fn stopped_at_start(part: &str, detail: &str) -> Vec<String> {
    let text = format!(
        "Self-test at start failed: {part}: {detail}. Do not use this program on this computer."
    );
    let indent = " ".repeat(ERROR_MARK.chars().count());
    let mut lines = wrapped(&text, TEXT_WIDTH - ERROR_MARK.chars().count()).into_iter();
    let mut shown_lines = vec![format!("{ERROR_MARK}{}", lines.next().unwrap_or_default())];
    shown_lines.extend(lines.map(|line| format!("{indent}{line}")));
    shown_lines.push(SELF_TEST_LINK.to_owned());
    shown_lines
}

/// A copy of the program with one bit flipped in a known answer stops a command that handles a
/// secret before it asks for anything, and the menu before it is shown, with exit code 1 and the
/// part named; the full self-test names the part too. The copies are made in
/// `target/xtask-terminal/`, never beside the program, and deleted afterwards.
fn a_damaged_known_answer_stops_the_program(root: &Path) -> Result<(), Failure> {
    let folder = root.join("target/xtask-terminal");
    let _ = fs::remove_dir_all(&folder);
    let result = DAMAGED_VECTORS
        .iter()
        .enumerate()
        .try_for_each(|(index, vector)| {
            // A folder of its own for each copy: macOS keeps the signature of a program it has run,
            // and stops another written over the same file.
            let own = folder.join(index.to_string());
            fs::create_dir_all(&own).map_err(|error| at(&own, error))?;
            damaged(&own, *vector)
        });
    let _ = fs::remove_dir_all(&folder);
    result
}

fn damaged(
    folder: &Path,
    (text, part, at_start, in_full): (&[u8], &str, &str, &str),
) -> Result<(), Failure> {
    let program = damaged_copy(folder, text)?;
    let stopped = stopped_at_start(part, at_start);

    let mut session = Session::start(Start {
        program: Some(&program),
        ..Start::of(&["encrypt"])
    })?;
    ensure(session.drain_until_exit(10), || {
        format!("damaged {part}: encrypt did not stop")
    })?;
    session.ends_with(INTERNAL_ERROR, &format!("damaged {part}: encrypt"))?;
    let got: Vec<String> = String::from_utf8_lossy(&session.output)
        .split("\r\n")
        .map(str::to_owned)
        .collect();
    let expected = [stopped.clone(), vec![String::new()]].concat();
    ensure(got == expected, || {
        format!("damaged {part}: encrypt showed {got:?}")
    })?;
    println!("damaged {part}: encrypt stops before it asks anything, exit code 1");

    // The window that a double-click opened stays until the message has been read.
    let mut session = Session::start(Start {
        program: Some(&program),
        ..Start::of(&[])
    })?;
    session.wait(PRESS_ENTER_TO_QUIT.as_bytes())?;
    session.type_keys(ENTER)?;
    ensure(session.drain_until_exit(10), || {
        format!("damaged {part}: Enter did not end the menu")
    })?;
    session.ends_with(INTERNAL_ERROR, &format!("damaged {part}: the menu"))?;
    let got: Vec<String> = String::from_utf8_lossy(&session.output)
        .split("\r\n")
        .map(str::to_owned)
        .collect();
    let expected = [
        stopped,
        vec![String::new(), PRESS_ENTER_TO_QUIT.to_owned(), String::new()],
    ]
    .concat();
    ensure(got == expected, || {
        format!("damaged {part}: the menu showed {got:?}")
    })?;
    println!("damaged {part}: no menu; the message stays until Enter, exit code 1");

    let output = run_without_terminal(&program, &["self-test"], b"", false, false)?;
    let exit = code(&output);
    ensure(exit == INTERNAL_ERROR, || {
        format!("damaged {part}: self-test gave exit code {exit}")
    })?;
    let failed: Vec<(&str, String)> = marks(false)
        .into_iter()
        .map(|(label, mark)| {
            if label == part {
                (label, format!("NOT as published: {in_full}"))
            } else {
                (label, mark)
            }
        })
        .collect();
    let lines = String::from_utf8_lossy(&output.stderr)
        .split('\n')
        .map(str::to_owned)
        .collect();
    let got = took_a_few_seconds(lines, plain);
    let alarm: Vec<String> = ALARM
        .iter()
        .map(|line| (*line).to_owned())
        .chain([SELF_TEST_LINK.to_owned(), String::new()])
        .collect();
    let expected = [report(&failed, plain), alarm].concat();
    ensure(got == expected, || {
        format!("damaged {part}: the self-test reported {got:?}")
    })?;
    println!("damaged {part}: the self-test names it and raises the alarm, exit code 1");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_few_seconds_are_read_as_the_report_states_them() {
        assert!(a_few_seconds("1.2 s") && a_few_seconds("12 s") && a_few_seconds("59 s"));
        assert!(!a_few_seconds("60 s") && !a_few_seconds("1 min 2 s") && !a_few_seconds("1 s"));
    }

    #[test]
    fn the_parts_being_tested_are_read_from_their_lines() {
        let output = "\r  Testing Cipher hashes…   \r  Testing Argon2id… \r";
        assert_eq!(parts_named(output), ["Cipher hashes", "Argon2id"]);
    }
}
