//! What a person reads without a terminal and in a script, which follows the tool's style
//! (AUD-010), and a start that prints nothing when the checks at start pass.

use std::time::Duration;

use super::session::{Session, capped_here, code, contains, find, run_plainly, shown};
use super::text::{without_controls, words, wrapped};
use super::{
    BAD_CHECKSUM, CANCELLED, CTRL_C, ENTER_PRIVATE, ERROR_MARK, ESCAPE, INVALID_INPUT, LIST_SHOWN,
    MEMORY_REFUSED, MENU_SHOWN, NOT_ENOUGH_RESOURCES, SECRET, SETTINGS_QUESTION, TEXT_WIDTH,
    container, ensure, join,
};
use crate::Failure;

/// The red of an error as the tool writes it at a terminal: bold, then red (BAD in style.rs).
const ERROR_RED: &str = "\x1b[1m\x1b[31m";
/// The width of the help texts (HELP_WIDTH in src/bin/mhfe/style.rs), and every command of the
/// tool, each of whose help must end with examples.
const HELP_WIDTH: usize = 80;
const COMMANDS: [&str; 12] = [
    "new",
    "encrypt",
    "decrypt",
    "check",
    "rekey",
    "wallets",
    "repair",
    "repair-words",
    "password",
    "self-test",
    "serve",
    "test-benchmark",
];
/// The first Ethereum address of the public zero-12 phrase without a passphrase (BIP44,
/// m/44'/60'/0'/0/0), and the first receiving address of BIP84's test vectors.
const PUBLIC_ETHEREUM_ADDRESS: &[u8] = b"0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const PUBLIC_ADDRESS: &[u8] = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/// What a command without a terminal says. What a script that compares with an address without
/// --coin records, and what the refusal of another coin's address then adds (SCRIPT_DEFAULT_COIN
/// in src/bin/mhfe/check.rs).
const NO_TERMINAL: &str = "There is no terminal to type secrets into.";
const COIN_ASSUMED: &str = "  Coin       Bitcoin, as no --coin was given";
const NAMES_COIN: [&str; 2] = [
    "The address cannot be used for the check: without --coin a script compares with a Bitcoin \
     address, and ",
    "; name the address's coin with --coin, such as --coin ethereum",
];
/// The title of `mhfe encrypt`'s first step, and of the menu.
const ENCRYPT_TITLE: &[u8] = "MHFE · Encrypt a seed phrase".as_bytes();
const MENU_TITLE: &[u8] = "MHFE · Memory-Hard Feistel Encryption for BIP39 Mnemonics".as_bytes();
/// Seconds after its start when a command is in its checks at start: its handlers are set within
/// milliseconds, and the checks end after a quarter of a second in a release build, later in a
/// debug build. Should they be over, Ctrl+C says the same at the first question.
const IN_THE_CHECKS: Duration = Duration::from_millis(100);

pub(super) fn run() -> Result<(), Failure> {
    password_sizes_out_of_range_are_refused()?;
    usage_errors_and_helps_follow_the_style()?;
    script_messages_wrap_and_name_what_a_command_has()?;
    the_checks_at_start_show_nothing()
}

/// A run of `arguments` without a terminal that is refused with exit code 2 and writes nothing to
/// standard output.
fn refused_plainly(arguments: &[&str], label: &str) -> Result<std::process::Output, Failure> {
    let result = run_plainly(arguments, b"", false, false)?;
    let exit = code(&result);
    ensure(exit == INVALID_INPUT, || {
        format!("{label}: exit code {exit}")
    })?;
    ensure(result.stdout.is_empty(), || {
        format!("{label}: wrote to standard output")
    })?;
    Ok(result)
}

/// A password size out of range is refused before anything is made, in the library's words
/// (AUD-011-ARC001), with exit code 2; the sizes at the limits are made.
fn password_sizes_out_of_range_are_refused() -> Result<(), Failure> {
    for (arguments, message) in [
        (
            ["password", "--words", "33"],
            "Choose between 1 and 32 words",
        ),
        (
            ["password", "--words", "0"],
            "Choose between 1 and 32 words",
        ),
        (
            ["password", "--chars", "65"],
            "Choose between 1 and 64 characters",
        ),
    ] {
        let label = arguments.join(" ");
        let result = refused_plainly(&arguments, &label)?;
        let said = format!("{ERROR_MARK}{message}");
        ensure(contains(&result.stderr, said.as_bytes()), || {
            format!("{label}: {}", shown(&result.stderr))
        })?;
    }
    for arguments in [
        ["password", "--words", "1"],
        ["password", "--words", "32"],
        ["password", "--chars", "64"],
    ] {
        let result = run_plainly(&arguments, b"", false, false)?;
        ensure(
            code(&result) == 0 && !result.stdout.trim_ascii().is_empty(),
            || arguments.join(" "),
        )?;
    }
    println!("password sizes: out of range refused in the library's words, the limits made");
    Ok(())
}

/// A usage error is one "✗ Error:" line, bold red in colour, followed by clap's tip, the usage and
/// its pointer to --help, with exit code 2, nothing on standard output and no clap "error:";
/// --help and --version print to standard output with exit code 0. The help of the tool and of
/// every command, -h and --help, fits 80 columns and has an "Examples:" section.
fn usage_errors_and_helps_follow_the_style() -> Result<(), Failure> {
    let refused = run_plainly(&["encrypt", "--pim", "abandon"], b"", false, false)?;
    let refused = String::from_utf8_lossy(&refused.stderr);
    ensure(
        refused.contains("Invalid value for --pim <N>") && !refused.contains("abandon"),
        || refused.to_string(),
    )?;
    for (arguments, message) in [
        (&["encrypt", "--no-such-option"][..], "Unexpected argument"),
        (
            &["serve"],
            "The following required arguments were not provided: <FILE>",
        ),
        (
            &["check", "--address", "--fingerprint"],
            "The argument '--address' cannot be used with '--fingerprint'",
        ),
    ] {
        let label = arguments.join(" ");
        let result = refused_plainly(arguments, &label)?;
        let text = String::from_utf8_lossy(&result.stderr);
        let lines: Vec<&str> = text.split('\n').collect();
        let first = format!("{ERROR_MARK}{message}");
        ensure(
            lines.len() > 1 && lines[0].is_empty() && lines[1] == first,
            || format!("{label}: {lines:?}"),
        )?;
        ensure(!text.contains("error:"), || {
            format!("{label}: clap's own error line")
        })?;
        ensure(text.contains("Usage: mhfe"), || {
            format!("{label}: no usage")
        })?;
        ensure(
            lines.iter().all(|line| line.chars().count() <= TEXT_WIDTH),
            || format!("{label}: a line is too long"),
        )?;
    }
    let result = run_plainly(&["encrypt", "--no-such-option"], b"", true, false)?;
    let red = format!("{ERROR_RED}{}", ERROR_MARK.trim());
    ensure(contains(&result.stderr, red.as_bytes()), || {
        format!("usage error: not in mhfe's red: {}", shown(&result.stderr))
    })?;
    println!("usage errors: one red ✗ Error: line, then the usage in grey; exit code 2");
    for flag in ["--help", "--version"] {
        let result = run_plainly(&[flag], b"", false, false)?;
        let exit = code(&result);
        ensure(exit == 0, || format!("mhfe {flag}: exit code {exit}"))?;
        ensure(
            !result.stdout.is_empty() && result.stderr.is_empty(),
            || format!("mhfe {flag}: not on standard output"),
        )?;
    }
    let commands = std::iter::once(None).chain(COMMANDS.iter().copied().map(Some));
    for command in commands {
        for flag in ["-h", "--help"] {
            let arguments: Vec<&str> = command.into_iter().chain([flag]).collect();
            let label = format!("mhfe {}", arguments.join(" "));
            let result = run_plainly(&arguments, b"", false, false)?;
            let exit = code(&result);
            ensure(exit == 0, || format!("{label}: exit code {exit}"))?;
            let text = String::from_utf8_lossy(&result.stdout);
            ensure(text.contains("\nExamples:\n"), || {
                format!("{label}: no examples")
            })?;
            let wide: Vec<&str> = text
                .split('\n')
                .filter(|line| line.chars().count() > HELP_WIDTH)
                .collect();
            ensure(wide.is_empty(), || {
                format!("{label}: lines wider than {HELP_WIDTH} columns: {wide:?}")
            })?;
        }
    }
    println!(
        "help: --help and --version unchanged; every -h and --help fits {HELP_WIDTH} columns, with examples"
    );
    Ok(())
}

/// The lines of an error from its mark on, as `lines` of standard error hold them.
fn error_lines(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with(ERROR_MARK))
        .unwrap_or(lines.len());
    lines[start..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
}

/// `text` as an error shows it: wrapped to the text width under its mark.
fn as_error(text: &str) -> Vec<String> {
    let mut lines = wrapped(text, TEXT_WIDTH - ERROR_MARK.chars().count()).into_iter();
    let indent = " ".repeat(ERROR_MARK.chars().count());
    let first = format!("{ERROR_MARK}{}", lines.next().unwrap_or_default());
    std::iter::once(first)
        .chain(lines.map(|line| format!("{indent}{line}")))
        .collect()
}

/// Errors wrap at the text width, the advice without a terminal names only what a command has,
/// and a script that compares with an address without --coin is told that Bitcoin is assumed;
/// on Linux the capped runs with the phrase's Bitcoin address, and with --coin ethereum and its
/// Ethereum address, stop at the memory reservation with exit code 4.
fn script_messages_wrap_and_name_what_a_command_has() -> Result<(), Failure> {
    let lines = join(&[BAD_CHECKSUM, b"\n", SECRET, b"\n", SECRET, b"\n"]);
    let result = run_plainly(&["encrypt", "--stdin", "--pim", "0"], &lines, false, false)?;
    let exit = code(&result);
    ensure(exit == INVALID_INPUT, || {
        format!("encrypt --stdin: exit code {exit}")
    })?;
    let error = error_lines(&String::from_utf8_lossy(&result.stderr));
    let expected = as_error(
        "The seed phrase is not a valid English BIP39 phrase: its checksum does not match, so a \
         word is wrong or words are out of order",
    );
    ensure(error == expected, || {
        format!("encrypt --stdin: the error is shown as {error:?}")
    })?;
    println!("errors: a long one wraps to 78 columns under its mark");

    let container_line = format!("1\n{}\n", container());
    for (arguments, data, names_stdin) in [
        (&["password", "--dice"][..], "", false),
        (
            &["rekey", "--pim", "0", "--words", "24"],
            container_line.as_str(),
            false,
        ),
        (&["encrypt", "--pim", "0"], "", true),
    ] {
        let label = arguments.join(" ");
        let result = run_plainly(arguments, data.as_bytes(), false, false)?;
        let said = words(&result.stderr);
        let exit = code(&result);
        ensure(exit == INVALID_INPUT, || {
            format!("{label}: exit code {exit}")
        })?;
        ensure(said.contains(NO_TERMINAL), || format!("{label}: {said:?}"))?;
        ensure(said.contains("--stdin") == names_stdin, || {
            format!("{label}: {said:?}")
        })?;
    }
    println!("without a terminal: --stdin named only by a command that has it");

    let answers = |address: &[u8]| {
        join(&[
            container().as_bytes(),
            b"\n",
            SECRET,
            b"\n",
            address,
            b"\n\n",
        ])
    };
    let without_coin = ["check", "--stdin", "--address", "--pim", "0"];
    let result = run_plainly(
        &without_coin,
        &answers(PUBLIC_ETHEREUM_ADDRESS),
        false,
        false,
    )?;
    let text = String::from_utf8_lossy(&result.stderr).into_owned();
    let error = words(
        text.get(text.find(ERROR_MARK).unwrap_or(0)..)
            .unwrap_or_default()
            .as_bytes(),
    );
    let exit = code(&result);
    ensure(exit == INVALID_INPUT, || {
        format!("check --stdin --address: {exit}")
    })?;
    ensure(text.split('\n').any(|line| line == COIN_ASSUMED), || {
        format!("check --stdin --address: {text:?}")
    })?;
    let start = words(format!("{ERROR_MARK}{}", NAMES_COIN[0]).as_bytes());
    ensure(
        error.starts_with(&start) && error.ends_with(NAMES_COIN[1]),
        || format!("check --stdin --address: {error:?}"),
    )?;
    ensure(result.stdout.is_empty(), || {
        "check --stdin --address: wrote to standard output".to_owned()
    })?;
    if capped_here() {
        let result = run_plainly(&without_coin, &answers(PUBLIC_ADDRESS), false, true)?;
        let exit = code(&result);
        let text = String::from_utf8_lossy(&result.stderr).into_owned();
        ensure(exit == NOT_ENOUGH_RESOURCES, || {
            format!("check --stdin --address, a Bitcoin address: exit code {exit}")
        })?;
        ensure(text.split('\n').any(|line| line == COIN_ASSUMED), || {
            "check --stdin --address, a Bitcoin address: the coin assumed is not recorded"
                .to_owned()
        })?;
        ensure(contains(&result.stderr, MEMORY_REFUSED), || {
            "check --stdin --address: not at the reservation".to_owned()
        })?;
        let with_coin = [
            "check",
            "--stdin",
            "--address",
            "--coin",
            "ethereum",
            "--pim",
            "0",
        ];
        let result = run_plainly(&with_coin, &answers(PUBLIC_ETHEREUM_ADDRESS), false, true)?;
        let exit = code(&result);
        ensure(exit == NOT_ENOUGH_RESOURCES, || {
            format!("check --stdin --address --coin ethereum: exit code {exit}")
        })?;
        ensure(!contains(&result.stderr, b"--coin was given"), || {
            "check --coin ethereum: records a coin assumed".to_owned()
        })?;
        ensure(contains(&result.stderr, MEMORY_REFUSED), || {
            "check --coin ethereum: not at the reservation".to_owned()
        })?;
    }
    println!(
        "check --stdin --address: Bitcoin without --coin, recorded, and another coin's address \
         refused with a pointer to --coin; the coin given takes its address"
    );
    Ok(())
}

/// The checks at start show nothing when they pass: `mhfe encrypt`, which handles a secret,
/// writes its first step first, and the menu its title. Ctrl+C in them says "Cancelled".
fn the_checks_at_start_show_nothing() -> Result<(), Failure> {
    let mut session = Session::of(&["encrypt"])?;
    std::thread::sleep(IN_THE_CHECKS);
    session.type_keys(CTRL_C)?;
    session.wait(b"Cancelled")?;
    let (exit, _) = session.close()?;
    ensure(exit == CANCELLED, || {
        format!("encrypt: Ctrl+C in the checks at start gave exit code {exit}")
    })?;
    println!("encrypt: Ctrl+C in the checks at start says Cancelled, exit code 130");

    let mut session = Session::of(&["encrypt"])?;
    session.answer(b"", &[SETTINGS_QUESTION, LIST_SHOWN])?;
    let end = find(&session.output, SETTINGS_QUESTION, 0).unwrap_or(0);
    let before = session.output[..end].to_vec();
    ensure(before.starts_with(ENTER_PRIVATE), || {
        format!("encrypt: {} before its first step", shown(&before))
    })?;
    let text = without_controls(&before);
    ensure(text.trim_ascii() == ENCRYPT_TITLE, || {
        format!("encrypt: {} before its first question", shown(&text))
    })?;
    session.answer(ESCAPE, &[b"Cancelled"])?;
    ensure(session.drain_until_exit(10), || {
        "encrypt: Escape did not end the tool".to_owned()
    })?;
    let (exit, _) = session.close()?;
    ensure(exit == CANCELLED, || {
        format!("encrypt: Escape gave exit code {exit}")
    })?;
    println!("encrypt: the checks at start pass unseen; its first step comes first");

    let mut session = Session::of(&[])?;
    session.wait(MENU_SHOWN)?;
    let end = find(&session.output, MENU_TITLE, 0).unwrap_or(0);
    ensure(&session.output[..end] == b"\r\n", || {
        format!("menu: {} before its title", shown(&session.output[..end]))
    })?;
    session.type_keys(b"q")?;
    ensure(session.drain_until_exit(10), || {
        "menu: q did not end the tool".to_owned()
    })?;
    let (exit, _) = session.close()?;
    ensure(exit == 0, || format!("menu: q gave exit code {exit}"))?;
    println!("menu: the checks at start pass unseen; its title comes first");
    Ok(())
}
