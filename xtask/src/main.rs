//! The tools of the mhfe repository (TOOL-01), run from anywhere in it as `cargo xtask <task>`:
//!
//! - `browser-check-page`: writes a page that runs the browser package at full size in any browser.
//! - `cell-widths [--check]`: writes `src/bin/mhfe/cell_widths.rs` from the Unicode 18.0.0 data in
//!   `tests/fixtures/unicode18-ucd`; with `--check` it fails when the file differs from them.
//! - `browsers`: the browser package in the pinned Chrome and Firefox, through WebDriver.
//! - `package-check [--full]`: the checks of the browser package that run its code, in the pinned
//!   browsers.
//! - `parity`: the command-line tool and the browser package give the same results, in the pinned
//!   browsers.
//! - `code-rules`: the rules of the coding guide that the compiler, Clippy and the formatters
//!   cannot see: file lengths, script headers, lint reasons, exact versions, no Node.js tooling,
//!   tight Markdown lists.
//! - `copies`: code copied from one place to another (CORE-10) in `src/`, `web/` and `xtask/src/`.
//! - `fast-mode`: the checks of `packaging/mhfe-fast-mode.py`, run with python3.
//! - `licences [--check | --archives <archive>...]`: writes the Rust crates part of
//!   `THIRD_PARTY_NOTICES.md`; with `--check` it fails when the file is out of date; with
//!   `--archives` it checks that release archives carry the licence files.
//! - `published-rounds [--check]`: writes `src/mhfe/published_rounds.rs` from the published
//!   vectors in `tests/spec/vectors`; with `--check` it writes nothing and fails when the file
//!   differs from what the fixtures give.
//! - `release-artifacts --test-binary`: prints the library's test binary, for
//!   `scripts/check-release-artifacts.sh`.
//! - `package-release-args`: checks that `scripts/package-release.sh` refuses a wrong package list
//!   before it writes anything.
//! - `package-version` and `target-dir`: the package's version and the target directory, as
//!   `cargo metadata` gives them, for the shell scripts; `standalone`: no package of the
//!   dependency graph comes from a local path but this one and xtask.
//! - `terminal [program]`: the terminal input and output of the command-line tool, in a
//!   pseudo-terminal on Linux and macOS and in a pseudo-console on Windows.
//! - `wasm <step>`: the steps of `scripts/build-wasm.sh` between the compilers: the network
//!   loaders replaced, the build stamped, the package manifest written, the built package
//!   checked.
//!
//! A task that fails prints why and exits 1.

mod browser;
mod cell_widths;
mod code_rules;
mod copies;
mod fast_mode;
mod licences;
mod metadata;
mod package_release_args;
mod published_rounds;
mod release_artifacts;
#[cfg(unix)]
mod terminal;
mod terminal_texts;
#[cfg(windows)]
mod terminal_windows;
mod wasm;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Why a task failed, as the message printed before exit code 1: a check's refusal, a file that
/// could not be read or written, or a wrong argument (RUST-04's exception for a program's own
/// messages).
#[derive(Debug)]
pub(crate) struct Failure(pub(crate) String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

/// Fails with `message` when `condition` does not hold.
pub(crate) fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure(message()))
    }
}

/// Writes `text` to the generated file `file` of the repository, or with `check` fails when the
/// file differs from it; `task` regenerates it.
pub(crate) fn generated(
    root: &Path,
    file: &str,
    text: &str,
    check: bool,
    task: &str,
) -> Result<(), Failure> {
    let output = root.join(file);
    if !check {
        return wasm::write(&output, text);
    }
    ensure(wasm::text(&output)? == text, || {
        format!("{file} differs from what its sources give; regenerate it with cargo xtask {task}")
    })
}

/// A failure that names the file it concerns.
pub(crate) fn at(path: &Path, error: impl fmt::Display) -> Failure {
    Failure(format!("{}: {error}", path.display()))
}

const USAGE: &str = "usage: cargo xtask <browser-check-page | browsers | \
                     cell-widths [--check] | code-rules | copies | fast-mode | \
                     licences [--check | --archives <archive>...] | package-check [--full] | \
                     package-release-args | package-version | parity | \
                     published-rounds [--check] | release-artifacts --test-binary | standalone | \
                     target-dir | \
                     terminal [program] | wasm <step>>";

/// The repository's root: the folder above this crate's.
fn root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

/// Runs `task` with its arguments.
fn run(task: &str, arguments: &[String]) -> Result<(), Failure> {
    let root = root();
    match (task, arguments) {
        ("browser-check-page", []) => browser::full_size::run(&root),
        ("browsers", []) => browser::run(&root),
        ("cell-widths", []) => cell_widths::run(&root, false),
        ("cell-widths", [check]) if check == "--check" => cell_widths::run(&root, true),
        ("code-rules", []) => code_rules::run(&root),
        ("copies", []) => copies::run(&root),
        ("fast-mode", []) => fast_mode::run(&root),
        ("licences", arguments) => licences::run(&root, arguments),
        ("package-check", []) => browser::package::run(&root, false),
        ("package-check", [full]) if full == "--full" => browser::package::run(&root, true),
        ("parity", []) => browser::parity::run(&root),
        ("published-rounds", []) => published_rounds::run(&root, false),
        ("published-rounds", [check]) if check == "--check" => published_rounds::run(&root, true),
        ("release-artifacts", [mode]) if mode == "--test-binary" => release_artifacts::run(&root),
        ("package-release-args", []) => package_release_args::run(&root),
        ("package-version", []) => metadata::package_version(&root),
        ("standalone", []) => metadata::standalone(&root),
        ("target-dir", []) => metadata::target_dir(&root),
        #[cfg(unix)]
        ("terminal", arguments) => terminal::run(&root, arguments),
        #[cfg(windows)]
        ("terminal", arguments) => terminal_windows::run(&root, arguments),
        ("wasm", arguments) => wasm::run(&root, arguments),
        _ => Err(Failure(USAGE.to_owned())),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((task, rest)) = arguments.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    match run(task, rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
    }
}
