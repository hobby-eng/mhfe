//! `cargo xtask browser-check-page`: writes target/browser-check/index.html, a self-contained page
//! that runs the browser package under the same Content-Security-Policy as the offline wallet tools
//! and reports PASS or FAIL in its title. Build the package first with scripts/build-wasm.sh.
//!
//! Open it as a file for the standard mode, or with `mhfe serve target/browser-check/index.html`
//! for the fast mode. By default it runs one full-size encryption (2 GiB); add "#all" to the
//! address to also decrypt and check, "#selftest" to run the self-test with the published vectors,
//! or "#check" to run the full self-check of every class, in seconds. Public test data only.

use std::path::Path;

use super::page::{classes, data_line, hash, package_constants, policy, text};
use super::work_folder;
use crate::wasm::sha256_hex;
use crate::{Failure, at};

/// The page's checks.
const CHECKS: &str = include_str!("../../pages/full-size-check.js");
/// The fixed `const` lines of `xtask/pages/page-data.js` that the checks use.
const DATA: [&str; 4] = [
    "PHRASE",
    "TEST_PASSWORD",
    "BIP84_ADDRESS",
    "FULL_SIZE_CONTAINER",
];
/// The page, in the browser checks' folder.
const PAGE_FILE: &str = "index.html";
/// The file that names the page's digest, beside it, which the fast-mode launchers read.
const DIGEST_FILE: &str = "mhfe-fast-mode.sha256";

/// Writes the page and the digest file.
pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let page = page(&root.join("dist"))?;
    let work = work_folder(root)?;
    let write = |name: &str, content: &str| {
        let path = work.join(name);
        std::fs::write(&path, content).map_err(|error| at(&path, error))
    };
    write(PAGE_FILE, &page)?;
    // The fast-mode launchers serve only the page named in this file, with this exact digest.
    let digest = sha256_hex(page.as_bytes());
    write(DIGEST_FILE, &format!("{digest}  {PAGE_FILE}\n"))?;
    println!(
        "Wrote {} ({} bytes) and {DIGEST_FILE}",
        work.join(PAGE_FILE).display(),
        page.len()
    );
    Ok(())
}

/// The page: the package's classes, its other files and the data as constants, and the checks.
fn page(dist: &Path) -> Result<String, Failure> {
    let worker = text(&dist.join("runtime/worker.js"))?;
    let mut parts = vec![classes(dist)?, String::new()];
    parts.extend(package_constants(dist, worker)?);
    for name in DATA {
        parts.push(data_line(name)?.to_owned());
    }
    parts.push(CHECKS.to_owned());
    let script = parts.join("\n");
    let policy = policy(&format!("'sha256-{}' 'wasm-unsafe-eval'", hash(&script)));
    Ok(format!(
        "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"utf-8\" />\n    \
         <meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\" />\n    \
         <title>running</title>\n  </head>\n  <body>\n    <pre id=\"log\"></pre>\n    \
         <script type=\"module\">{script}</script>\n  </body>\n</html>\n"
    ))
}
