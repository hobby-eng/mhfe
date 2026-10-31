//! `cargo xtask package-check [--full]`: the checks of the browser package that run its code, with
//! `--full` also one full-size encryption (2 GiB). They run in a module worker of a real browser,
//! which the Argon2 builds need: the threaded one blocks on its lanes, and only in a cross-origin
//! isolated page, so the page comes from the page server (`server.rs`) alone.
//!
//! The checks (`xtask/pages/package/checks/`) run the Argon2 builds alone, then the core module of
//! the package's WebAssembly with the real Argon2 bridge and both builds. To stay fast they lower
//! the Argon2 cost in a test wrapper, which lets only the known answers of the build through
//! unchanged (1 MiB with one pass, before and after every operation, and 64 MiB with three passes
//! and 256 MiB with two in the full self-check); the result must equal the container that the
//! native engine gives at the same cost (REDUCED_COST_CONTAINER in src/mhfe.rs). They give the core
//! Argon2 builds that fail their known answer, and the self-test the published round keys in place
//! of Argon2 at full size, to check the fault it names. They run the repair, passwords and wallet
//! modules with public vectors, the self-check of every module at both tiers, with a WebAssembly
//! whose vectors were damaged, the package's worker.js in the worker itself with Argon2 builds that
//! do not start or are of another build, and the page-side classes against a stand-in worker, whose
//! self-checks run the real WebAssembly. The real worker runs in `cargo xtask browsers`, and
//! `cargo xtask wasm verify` checks what needs no JavaScript engine.
//!
//! The checks were written for Node.js: `xtask/pages/package/support.js` gives them the little of
//! its API that they use, and this task hands them the files they read.

use std::path::Path;

use serde_json::{Map, Value};

use super::page::{base64, classes, constant, data_line, document, hash, text};
use super::server::PageServer;
use super::{browsers_folder, check_pages, work_folder};
use crate::{Failure, at, wasm};

/// The checks, one module with `SUPPORT` in front of them, in the order they run.
const CHECKS: [&str; 11] = [
    include_str!("../../pages/package/checks/core.js"),
    include_str!("../../pages/package/checks/argon2-build.js"),
    include_str!("../../pages/package/checks/argon2-build-rekeys.js"),
    include_str!("../../pages/package/checks/core-self-test.js"),
    include_str!("../../pages/package/checks/modules.js"),
    include_str!("../../pages/package/checks/self-checks.js"),
    include_str!("../../pages/package/checks/in-process-worker.js"),
    include_str!("../../pages/package/checks/package-facts.js"),
    include_str!("../../pages/package/checks/classes.js"),
    include_str!("../../pages/package/checks/classes-sessions.js"),
    include_str!("../../pages/package/checks/class-self-checks.js"),
];
/// The part of Node.js's API that the checks use.
const SUPPORT: &str = include_str!("../../pages/package/support.js");
/// The module worker that runs the checks.
const WORKER: &str = include_str!("../../pages/package/worker.js");
/// The page that starts the worker and keeps what it posts.
const PAGE: &str = include_str!("../../pages/package/page.js");
/// The fixed `const` lines of `xtask/pages/page-data.js` that the checks use.
const DATA: [&str; 7] = [
    "SELF_CHECK",
    "PHRASE",
    "ZERO_24",
    "REDUCED_COST_CONTAINER",
    "REDUCED_COST_SAME_LENGTH_CONTAINER",
    "FULL_SIZE_CONTAINER",
    "AMBIGUOUS_12_WORDS",
];
/// The files that the checks read beside the package, from the root.
const FILES_BESIDE: [&str; 7] = [
    "Cargo.toml",
    "tests/fixtures/suite3-vectors/zero-12.json",
    "tests/fixtures/suite4-vectors/same-length-zero-12.json",
    "vendor/phc-winner-argon2/include/argon2.h",
    "web/argon2-engine.js",
    "web/repair-worker.js",
    "web/worker-runtime.js",
];

/// Runs the checks in each pinned browser.
pub(crate) fn run(root: &Path, full: bool) -> Result<(), Failure> {
    let folder = browsers_folder()?;
    let dist = root.join("dist");
    let other_build = wasm::stamp_other_build(root, &dist)?;
    let server = PageServer::start(page(root, &other_build, full)?.into_bytes())?;
    let fast_url = format!("http://127.0.0.1:{}/", server.port);
    if !check_pages(&folder, &work_folder(root)?, &server, &[("fast", fast_url)])? {
        return Err(Failure("The package check failed.".to_owned()));
    }
    println!("The browser package passes its package checks in Chrome and Firefox.");
    Ok(())
}

/// The page: the checks' module and the worker as text, and the script that starts them. Its policy
/// is the wallet tools' but for what the checks do that no page of the package does: they evaluate
/// the glue and the Argon2 builds, and import the classes from `blob:` URLs.
fn page(root: &Path, other_build: &str, full: bool) -> Result<String, Failure> {
    let dist = root.join("dist");
    let mut files = Map::new();
    files_of(&dist, "dist/", &mut files)?;
    for path in FILES_BESIDE {
        let file = root.join(path);
        let bytes = std::fs::read(&file).map_err(|error| at(&file, error))?;
        files.insert(path.to_owned(), Value::from(base64(&bytes)));
    }
    let mut other_files = Map::new();
    files_of(&root.join(wasm::OTHER_BUILD), "", &mut other_files)?;
    let mut lines = vec![
        constant("FILES", &Value::Object(files)),
        constant("OTHER_BUILD_FILES", &Value::Object(other_files)),
        constant("OTHER_BUILD_ID", &Value::from(other_build)),
        constant("GLUE", &Value::from(glue(root, &dist)?)),
        constant("VECTOR_TEXTS", &Value::from(wasm::vector_texts(root)?)),
        constant("JOINED_CLASSES", &Value::from(classes(&dist)?)),
        constant("FULL", &Value::from(full)),
    ];
    for name in DATA {
        lines.push(data_line(name)?.to_owned());
    }
    let module = format!("{}\n{SUPPORT}\n{}", lines.join("\n"), CHECKS.concat());
    let script = format!(
        "{}\n{}\n{PAGE}",
        constant("CHECKS", &Value::from(module)),
        constant("WORKER", &Value::from(WORKER))
    );
    let sources = format!(
        "'sha256-{}' 'unsafe-eval' 'wasm-unsafe-eval' blob:",
        hash(&script)
    );
    Ok(document(&sources, "<script>", &script))
}

/// The wasm-bindgen glue of the package: what scripts/build-wasm.sh put in front of the Argon2
/// bridge in its worker. A release checks the published archive, where no build left `target/`.
fn glue(root: &Path, dist: &Path) -> Result<String, Failure> {
    let worker = text(&dist.join("runtime/worker.js"))?;
    let bridge = text(&root.join("web/argon2-engine.js"))?;
    let (glue, _) = worker
        .split_once(&bridge)
        .ok_or_else(|| Failure("runtime/worker.js does not hold the Argon2 bridge".to_owned()))?;
    Ok(glue.to_owned())
}

/// Adds every file under `folder` to `files`, base64 by its path from `folder` after `prefix`.
fn files_of(folder: &Path, prefix: &str, files: &mut Map<String, Value>) -> Result<(), Failure> {
    let failed = |error: std::io::Error| at(folder, error);
    for entry in std::fs::read_dir(folder).map_err(failed)? {
        let entry = entry.map_err(failed)?;
        let path = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().map_err(failed)?.is_dir() {
            files_of(&entry.path(), &format!("{path}/"), files)?;
        } else {
            let bytes = std::fs::read(entry.path()).map_err(|error| at(&entry.path(), error))?;
            files.insert(path, Value::from(base64(&bytes)));
        }
    }
    Ok(())
}
