//! `cargo xtask parity [PROGRAM]`: the command-line tool and the browser package give the same
//! results, as both call the same library: the program's script mode (`--stdin`) here, the
//! package's WebAssembly in a module worker of the pinned browsers, on public data, without any
//! full-cost Argon2 work. Build both first: the program with `cargo build --release`, the package with
//! scripts/build-wasm.sh. PROGRAM is the program's path, by default the one that build made.
//!
//! Compared: the repair words of a container and the repair of a damaged one; the refusals that
//! come before any round, by their words, which the program writes after "✗ Error:" and a page
//! reads from the package (sentence() in web/runtime.js); and the other lengths that detection
//! could read, which the program warns of for the container chosen and readPhrase() lists for each.
//! Each run of the program also passes its own startup checks and needs the 2 GiB of free memory
//! that a recovery takes, though none is reserved before these refusals.
//!
//! `xtask/pages/package/parity.js` prints, as a line of JSON, each run of the program and what the
//! package says it must give; this task runs them and compares.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::package::{handed_over, worker_page};
use super::server::PageServer;
use super::{browsers_folder, check_pages, work_folder};
use crate::{Failure, at};

/// The package's side of the comparison.
const PARITY: &str = include_str!("../../pages/package/parity.js");
/// The program's exit code for input it refuses (src/bin/mhfe/exit.rs).
const INVALID_INPUT: i32 = 2;
/// The mark before an error of the program (src/bin/mhfe/style.rs).
const ERROR_MARK: &str = "✗ Error:";
/// What the program writes before the other lengths that detection could read.
const OTHER_LENGTH: &str = "also reads as";
/// How long a run of the program may take: its startup checks take about a second.
const PROGRAM_TIMEOUT: Duration = Duration::from_secs(60);
/// How often a run of the program is looked at.
const POLL: Duration = Duration::from_millis(10);

/// A run of the program, and what the package says it must give.
#[derive(Deserialize)]
struct Case {
    what: String,
    args: Vec<String>,
    lines: Vec<String>,
    expected: Expected,
}

/// What the program must give.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Expected {
    /// This on standard output, and exit code 0.
    Prints(String),
    /// A refusal that starts with these words; it may add what it did not do after them.
    Refuses(String),
    /// A warning of exactly these other lengths.
    Warns(Vec<u32>),
}

/// The program that `cargo build --release` made, wherever CARGO_TARGET_DIR puts it.
pub(crate) fn built_program(root: &Path) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR");
    target
        .map_or_else(|| root.join("target"), PathBuf::from)
        .join("release/mhfe")
}

/// Compares the program at `program` with the package in `dist/`, in each pinned browser.
pub(crate) fn run(root: &Path, program: &Path) -> Result<(), Failure> {
    let folder = browsers_folder()?;
    let page = worker_page(&handed_over(root)?.join("\n"), PARITY);
    let server = PageServer::start(page.into_bytes())?;
    let url = format!("http://127.0.0.1:{}/", server.port);
    let lines = check_pages(&folder, &work_folder(root)?, &server, &[("fast", url)])?
        .ok_or_else(|| Failure("The package's side of the parity check failed.".to_owned()))?;
    let [chrome, firefox] = lines.as_slice() else {
        return Err(Failure(
            "the parity check did not run in two browsers".to_owned(),
        ));
    };
    if chrome != firefox {
        return Err(Failure(
            "Chrome and Firefox expect different results.".to_owned(),
        ));
    }
    let cases: Vec<Case> = chrome
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<_, _>>()
        .map_err(|error| Failure(format!("a case of the package: {error}")))?;
    if cases.is_empty() {
        return Err(Failure("the package gave no case".to_owned()));
    }
    for case in &cases {
        check(program, case)?;
    }
    println!("The command-line tool and the browser package give the same results.");
    Ok(())
}

/// Runs the program as `case` says and compares what it gives.
fn check(program: &Path, case: &Case) -> Result<(), Failure> {
    let output = run_program(program, &case.args, &case.lines)?;
    let code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if gives(&case.expected, code, &stdout, &stderr) {
        return Ok(());
    }
    Err(Failure(format!(
        "{}: the package says {:?}, the program ends with {code:?}\n  stdout: {stdout}\n  stderr: \
         {stderr}",
        case.what, case.expected
    )))
}

/// Whether a run that ended with `code` and wrote `stdout` and `stderr` gave `expected`. A warning
/// comes before the password, where standard input ends, which the program refuses.
fn gives(expected: &Expected, code: Option<i32>, stdout: &str, stderr: &str) -> bool {
    match expected {
        Expected::Prints(text) => code == Some(0) && stdout.trim() == text,
        Expected::Refuses(words) => {
            code == Some(INVALID_INPUT)
                && refusal(stderr).is_some_and(|text| text.starts_with(words.as_str()))
        }
        Expected::Warns(lengths) => {
            let all = |words: &u32| stderr.contains(&format!("{OTHER_LENGTH} {words} words"));
            code == Some(INVALID_INPUT)
                && lengths.iter().all(all)
                && stderr.contains(OTHER_LENGTH) != lengths.is_empty()
        }
    }
}

/// The program's error message, its wrapped lines joined, without the mark.
fn refusal(stderr: &str) -> Option<String> {
    let (_, message) = stderr.split_once(ERROR_MARK)?;
    let lines: Vec<&str> = message.split('\n').map(str::trim).collect();
    Some(lines.join(" ").trim().to_owned())
}

/// Runs the program in script mode with `lines` on standard input, without colour.
fn run_program(program: &Path, args: &[String], lines: &[String]) -> Result<Output, Failure> {
    let failed = |error: std::io::Error| at(program, error);
    let mut child = Command::new(program)
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed)?;
    if let Some(mut stdin) = child.stdin.take() {
        let input: String = lines.iter().map(|line| format!("{line}\n")).collect();
        match stdin.write_all(input.as_bytes()) {
            // It may refuse before it reads all of this.
            Err(error) if error.kind() != ErrorKind::BrokenPipe => return Err(failed(error)),
            _ => {}
        }
    }
    let started = Instant::now();
    while child.try_wait().map_err(failed)?.is_none() {
        if started.elapsed() > PROGRAM_TIMEOUT {
            child.kill().map_err(failed)?;
            return Err(Failure(format!("mhfe {} did not end", args.join(" "))));
        }
        sleep(POLL);
    }
    child.wait_with_output().map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal of the program, wrapped over two lines.
    const REFUSED: &str = "Some text\n✗ Error: The repair words cannot be used: a card has 2, 4, \
                           6 or 8 repair\n         words, not 3\n";
    /// A warning of the program before the password, where standard input ended.
    const WARNED: &str = "⚠ This phrase also reads as 21 words.\n✗ Error: Standard input ended\n";

    fn refuses(words: &str) -> Expected {
        Expected::Refuses(words.to_owned())
    }

    #[test]
    fn output_counts_only_with_exit_code_0_and_the_same_text() {
        let prints = Expected::Prints("a b".to_owned());
        assert!(gives(&prints, Some(0), "a b\n", ""));
        assert!(!gives(&prints, Some(0), "a c\n", ""));
        assert!(!gives(&prints, Some(1), "a b\n", ""));
        assert!(!gives(&prints, None, "a b\n", ""));
    }

    #[test]
    fn a_refusal_wrapped_over_two_lines_is_read_whole() {
        let words = "The repair words cannot be used: a card has 2, 4, 6 or 8 repair words, not 3";
        assert!(gives(&refuses(words), Some(INVALID_INPUT), "", REFUSED));
        assert!(gives(
            &refuses("The repair words"),
            Some(INVALID_INPUT),
            "",
            REFUSED
        ));
    }

    #[test]
    fn another_refusal_or_exit_code_or_no_mark_is_no_refusal() {
        let words = "The repair words cannot be used";
        assert!(!gives(
            &refuses("The passwords differ"),
            Some(INVALID_INPUT),
            "",
            REFUSED
        ));
        assert!(!gives(&refuses(words), Some(1), "", REFUSED));
        assert!(!gives(&refuses(words), Some(INVALID_INPUT), "", words));
        assert!(!gives(&refuses(""), Some(INVALID_INPUT), "", "no mark"));
    }

    #[test]
    fn a_warning_must_name_each_length_and_appear_only_when_lengths_are_listed() {
        let code = Some(INVALID_INPUT);
        assert!(gives(&Expected::Warns(vec![21]), code, "", WARNED));
        assert!(gives(
            &Expected::Warns(Vec::new()),
            code,
            "",
            "Standard input ended\n"
        ));
        assert!(!gives(&Expected::Warns(vec![21, 15]), code, "", WARNED));
        assert!(!gives(&Expected::Warns(vec![15]), code, "", WARNED));
        assert!(!gives(&Expected::Warns(Vec::new()), code, "", WARNED));
        assert!(!gives(&Expected::Warns(vec![21]), Some(0), "", WARNED));
        assert!(!gives(&Expected::Warns(Vec::new()), Some(0), "", ""));
    }
}
