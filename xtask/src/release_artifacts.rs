//! `cargo xtask release-artifacts --test-binary`: prints the library's test binary for
//! `scripts/check-release-artifacts.sh`, which checks that the test-only reduced Argon2 engine is
//! in that binary and in no release artifact. The task builds the library's tests without running
//! them and prints the executable that cargo's JSON messages name for the target `mhfe`.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::Failure;

/// Prints the path of the library's test binary.
pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let failed = |error: &dyn std::fmt::Display| Failure(format!("cargo test --no-run: {error}"));
    // $CARGO is the cargo that runs this task, so the build uses the pinned toolchain.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args([
            "test",
            "--locked",
            "--lib",
            "--no-run",
            "--message-format=json",
        ])
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| failed(&error))?;
    if !output.status.success() {
        return Err(failed(&output.status));
    }
    let messages = String::from_utf8(output.stdout).map_err(|error| failed(&error))?;
    for line in messages.lines().filter(|line| !line.trim().is_empty()) {
        let message: Value = serde_json::from_str(line).map_err(|error| failed(&error))?;
        if message["reason"] == "compiler-artifact"
            && message["target"]["name"] == "mhfe"
            && let Some(executable) = message["executable"].as_str()
            && !executable.is_empty()
        {
            println!("{executable}");
        }
    }
    Ok(())
}
