//! The tools of the mhfe repository (TOOL-01), run from anywhere in it as `cargo xtask <task>`:
//!
//! - `copies [--tokens N]`: code copied from one place to another (CORE-10) in `src/`, `web/` and
//!   `xtask/src/`.
//! - `published-rounds [--check]`: writes `src/mhfe/published_rounds.rs` from the published
//!   vectors in `tests/fixtures`; with `--check` it writes nothing and fails when the file differs
//!   from what the fixtures give.
//! - `release-artifacts --test-binary`: prints the library's test binary, for
//!   `scripts/check-release-artifacts.sh`.
//! - `package-release-args`: checks that `scripts/package-release.sh` refuses a wrong package list
//!   before it writes anything.
//!
//! A task that fails prints why and exits 1.

mod copies;
mod package_release_args;
mod published_rounds;
mod release_artifacts;

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

const USAGE: &str = "usage: cargo xtask <copies [--tokens N] | published-rounds [--check] | \
                     release-artifacts --test-binary | package-release-args>";

/// The repository's root: the folder above this crate's.
fn root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

/// Runs `task` with its arguments.
fn run(task: &str, arguments: &[String]) -> Result<(), Failure> {
    let root = root();
    match (task, arguments) {
        ("copies", arguments) => copies::run(&root, arguments),
        ("published-rounds", []) => published_rounds::run(&root, false),
        ("published-rounds", [check]) if check == "--check" => published_rounds::run(&root, true),
        ("release-artifacts", [mode]) if mode == "--test-binary" => release_artifacts::run(&root),
        ("package-release-args", []) => package_release_args::run(&root),
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
