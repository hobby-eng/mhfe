//! `cargo xtask target-dir` and `cargo xtask package-version`: what the shell scripts and the
//! release workflow read from `cargo metadata`, printed on a line of its own: the target
//! directory, which CARGO_TARGET_DIR may move out of `target/`, and the version of the
//! `mhfe-experimental` package. `cargo xtask standalone` fails when the dependency graph holds a
//! package from a local path other than this package and its tools.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::Failure;

const PACKAGE: &str = "mhfe-experimental";

fn metadata(root: &Path, dependencies: bool) -> Result<Value, Failure> {
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command.args(["metadata", "--locked", "--format-version", "1"]);
    if !dependencies {
        command.args(["--offline", "--no-deps"]);
    }
    let output = command
        .current_dir(root)
        .output()
        .map_err(|error| Failure(format!("cargo did not start: {error}")))?;
    if !output.status.success() {
        return Err(Failure(format!(
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| Failure(format!("cargo metadata: {error}")))
}

pub(crate) fn target_dir(root: &Path) -> Result<(), Failure> {
    let metadata = metadata(root, false)?;
    let directory = metadata["target_directory"]
        .as_str()
        .ok_or_else(|| Failure("cargo metadata names no target directory".to_owned()))?;
    println!("{directory}");
    Ok(())
}

pub(crate) fn package_version(root: &Path) -> Result<(), Failure> {
    let metadata = metadata(root, false)?;
    let version = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|package| package["name"] == PACKAGE)
        .and_then(|package| package["version"].as_str())
        .ok_or_else(|| Failure(format!("cargo metadata lists no {PACKAGE}")))?;
    println!("{version}");
    Ok(())
}

pub(crate) fn standalone(root: &Path) -> Result<(), Failure> {
    let metadata = metadata(root, true)?;
    let workspace = metadata["workspace_root"].as_str().unwrap_or_default();
    let own = [
        format!("{workspace}/Cargo.toml"),
        format!("{workspace}/xtask/Cargo.toml"),
    ];
    let foreign: Vec<&str> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|package| package["source"].is_null())
        .filter_map(|package| package["manifest_path"].as_str())
        .filter(|path| !own.iter().any(|own| own == path))
        .collect();
    if !foreign.is_empty() {
        return Err(Failure(format!(
            "unexpected packages from local paths: {foreign:?}"
        )));
    }
    println!("The dependency graph holds no package from a local path but this one and xtask.");
    Ok(())
}
