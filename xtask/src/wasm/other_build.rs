//! The other build of the package: its files with their stamps taken out and a comment added to one
//! script, stamped again in a folder of their own. Two packages that differ in one script alone
//! must have different builds, so that their files are not used together; `cargo xtask
//! package-check` then gives this package's worker and runtime the other build's files, which they
//! must refuse. Stamping it checks the stamp's refusals on the way: a package stamped already, and
//! a script without its build constant. `cargo xtask wasm verify` does that much, as it needs no
//! browser.

use std::path::Path;

use super::stamp::{self, SCRIPTS, UNSTAMPED, WASM_FILE};
use super::verify::{ensure, unstamped};
use super::{manifest, text, write};
use crate::{Failure, at};

/// The folder of the other build, from the root.
pub(crate) const OTHER_BUILD: &str = "target/other-build";
/// The script that the other build changes, and how.
const CHANGED: (&str, &str) = ("repair/repair.js", "// another build\n");
/// The script whose build constant is left out, as scripts/build-wasm.sh could fail to append it
/// to an Argon2 build.
const WITHOUT_CONSTANT: &str = "core/argon2-st.js";

/// Stamps the other build of the package in `dist` into OTHER_BUILD under `root` and returns its
/// build.
pub(crate) fn stamp_other_build(root: &Path, dist: &Path) -> Result<String, Failure> {
    let folder = &root.join(OTHER_BUILD);
    let build = manifest::build_of(dist)?;
    let (wasm, scripts) = unstamped(dist, &build)?;
    let mut without = scripts.clone();
    let script = script_of(&mut without, WITHOUT_CONSTANT)?;
    *script = script.replacen(UNSTAMPED, "", 1);
    write_files(folder, &wasm, &without)?;
    let no_constant = format!(
        "{} holds 0 build constants instead of one.",
        folder.join(WITHOUT_CONSTANT).display()
    );
    refused(stamp::run(folder), &no_constant)?;
    let mut other = scripts;
    let (changed, comment) = CHANGED;
    script_of(&mut other, changed)?.push_str(comment);
    write_files(folder, &wasm, &other)?;
    let other_build = stamp::run(folder)?;
    ensure(other_build != build, || {
        "a script alone does not change the build".to_owned()
    })?;
    for (path, constant) in SCRIPTS {
        let carries =
            text(&folder.join(path))?.contains(&format!("{constant} = \"{other_build}\";"));
        ensure(carries, || {
            format!("{path} of the other build does not carry its build")
        })?;
    }
    let stamped_already = format!(
        "{} is stamped already; build it again.",
        folder.join(WASM_FILE).display()
    );
    refused(stamp::run(folder), &stamped_already)?;
    Ok(other_build)
}

/// The script at `path` of `scripts`, which are in the order of SCRIPTS.
fn script_of<'a>(scripts: &'a mut [String], path: &str) -> Result<&'a mut String, Failure> {
    let index = SCRIPTS.iter().position(|(own, _)| *own == path);
    index
        .and_then(|index| scripts.get_mut(index))
        .ok_or_else(|| Failure(format!("{path} is not a script of the package")))
}

/// Writes the WebAssembly and the scripts of a package into `folder`, which holds nothing else.
fn write_files(folder: &Path, wasm: &[u8], scripts: &[String]) -> Result<(), Failure> {
    if folder.exists() {
        std::fs::remove_dir_all(folder).map_err(|error| at(folder, error))?;
    }
    for path in std::iter::once(WASM_FILE).chain(SCRIPTS.map(|(path, _)| path)) {
        let file = folder.join(path);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|error| at(parent, error))?;
        }
    }
    write(&folder.join(WASM_FILE), wasm)?;
    for ((path, _), script) in SCRIPTS.iter().zip(scripts) {
        write(&folder.join(path), script)?;
    }
    Ok(())
}

/// Checks that the stamp refused with `message`.
fn refused(outcome: Result<String, Failure>, message: &str) -> Result<(), Failure> {
    match outcome {
        Err(Failure(refusal)) if refusal == message => Ok(()),
        Err(Failure(refusal)) => Err(Failure(format!(
            "the stamp refused with {refusal:?}, not {message:?}"
        ))),
        Ok(_) => Err(Failure(format!("the stamp did not refuse: {message}"))),
    }
}
