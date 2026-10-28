//! `cargo xtask package-release-args`: checks that `scripts/package-release.sh` refuses an
//! unknown or repeated package with the usage and exit code 2 before it builds or writes anything,
//! so that no archive is left without its licence check and SHA256SUMS. As a control, a legal
//! command line must get past that check: with RUSTFLAGS set, which
//! `packaging/remap-builder-paths.sh` refuses before any build, it creates the output folder and
//! stops there. Each command line writes into a fresh folder under `target/`.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Failure, at};

/// The output folder in the command lines below.
const OUTPUT: &str = "<output>";
/// Command lines that the script must refuse.
const REFUSED: [&[&str]; 2] = [
    &["v0.0.0", OUTPUT, "browser", "no-such-package"],
    &["v0.0.0", OUTPUT, "browser", "linux-x86_64", "browser"],
];
/// A legal command line, which must get past the package check.
const LEGAL: &[&str] = &["v0.0.0", OUTPUT, "browser", "linux-x86_64"];

/// How one run of the script ended.
struct Outcome {
    /// The exit code, or `None` when a signal stopped the script.
    code: Option<i32>,
    stderr: String,
    /// Whether the script created the output folder.
    created: bool,
}

/// Runs the refused command lines and the control, and fails with what went wrong.
pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let base = root.join("target").join("package-release-args");
    let mut failures = Vec::new();
    for arguments in REFUSED {
        let outcome = package_release(root, &base, arguments, None)?;
        if outcome.code != Some(2) || !outcome.stderr.contains("usage: ") || outcome.created {
            failures.push(format!(
                "{}: {}, output created: {}\n{}",
                arguments.join(" "),
                ended(outcome.code),
                outcome.created,
                outcome.stderr
            ));
        }
    }
    let legal = package_release(root, &base, LEGAL, Some("-C debuginfo=0"))?;
    if !legal.created || !legal.stderr.contains("RUSTFLAGS") {
        failures.push(format!(
            "a legal command line did not get past the check: {}\n{}",
            ended(legal.code),
            legal.stderr
        ));
    }
    if !failures.is_empty() {
        return Err(Failure(failures.join("\n")));
    }
    println!(
        "package-release.sh refuses {} wrong package lists before any output.",
        REFUSED.len()
    );
    Ok(())
}

/// How a run of the script ended, as a failure says it: its exit code, or that a signal stopped
/// it.
fn ended(code: Option<i32>) -> String {
    code.map_or_else(
        || "stopped by a signal".to_owned(),
        |code| format!("exit {code}"),
    )
}

/// Runs the script with `arguments`, `OUTPUT` replaced by a folder in a fresh `base`, and with
/// RUSTFLAGS set to `rustflags` when given; `base` is removed afterwards.
fn package_release(
    root: &Path,
    base: &Path,
    arguments: &[&str],
    rustflags: Option<&str>,
) -> Result<Outcome, Failure> {
    let failed = |error: std::io::Error| at(base, error);
    if base.exists() {
        fs::remove_dir_all(base).map_err(failed)?;
    }
    fs::create_dir_all(base).map_err(failed)?;
    let output = base.join("out");
    let mut command = Command::new("bash");
    command
        .arg(root.join("scripts").join("package-release.sh"))
        .current_dir(root);
    for argument in arguments {
        if *argument == OUTPUT {
            command.arg(&output);
        } else {
            command.arg(argument);
        }
    }
    if let Some(flags) = rustflags {
        command.env("RUSTFLAGS", flags);
    }
    let result = command
        .output()
        .map_err(|error| Failure(format!("bash scripts/package-release.sh: {error}")))?;
    let outcome = Outcome {
        code: result.status.code(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        created: output.exists(),
    };
    fs::remove_dir_all(base).map_err(failed)?;
    Ok(outcome)
}
