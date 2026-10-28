//! The check page of the browser package: the package's classes, the page's data and its checks
//! (`xtask/pages/`) in one module script, under the Content-Security-Policy of the offline wallet
//! tools, which allows that script, WebAssembly and Blob workers alone, and here the page's event
//! recorder too: a classic script before the module that records what the page throws or the
//! policy blocks. The
//! page calls every method of the four classes with each of its options and compares the results,
//! or the refusals, with known values: public vectors, values computed independently, or the
//! results of another method or class. Only public test data is used.
//!
//! So that Argon2 takes seconds, a test-only wrapper in the page's copy of the worker runs it with
//! 256 KiB and one pass instead of the 2 GiB and twelve passes of suite 3, after checking that the
//! core asked for those. The container must then be REDUCED_COST_CONTAINER, which the native tests
//! (src/mhfe.rs) and scripts/verify-browser-package.mjs check at the same cost; the same-length
//! container must be REDUCED_COST_SAME_LENGTH_CONTAINER of src/mhfe.rs at that cost. The same
//! wrapper stands for a browser that cannot give the memory, for one marker password and one marker
//! container. A run takes a few minutes, mostly for the two phrases per page drawn to pass the
//! wallet check, about 65,536 BIP39 seeds each.
//!
//! What the reduced cost cannot show: a PIM above 0 (the wrapper refuses any cost but suite 3's, so
//! the page only checks the cost the core asks for) and the self-test's verdict on the published
//! vectors, which are computed at full cost (the page checks that it runs both and says "not as
//! published"). Nor can a page see whether a worker it stopped has really ended. The known answers
//! of the Argon2 builds, at 1, 64 and 256 MiB, pass the wrapper unchanged: every class's startup
//! check runs in each page, with its time, under the same policy, the full self-checks too, and a
//! WebAssembly whose vector was damaged must close its classes, while an Argon2 build that does not
//! start must leave the client open and one of another build must be refused.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Failure, at};

/// The checks: the body of the function that the page calls, in its files' order. They share the
/// function's scope, so that no name of theirs meets one of the package's classes; `run.js`,
/// last, calls `main()` once every constant is set.
const CHECKS: [&str; 18] = [
    include_str!("../../pages/checks/support.js"),
    include_str!("../../pages/checks/main.js"),
    include_str!("../../pages/checks/construction.js"),
    include_str!("../../pages/checks/encrypt.js"),
    include_str!("../../pages/checks/decrypt.js"),
    include_str!("../../pages/checks/rehearsal.js"),
    include_str!("../../pages/checks/callbacks.js"),
    include_str!("../../pages/checks/rekey.js"),
    include_str!("../../pages/checks/rekey-same-length.js"),
    include_str!("../../pages/checks/rekey-refusals.js"),
    include_str!("../../pages/checks/hidden-wallets.js"),
    include_str!("../../pages/checks/self-checks.js"),
    include_str!("../../pages/checks/argon2-start.js"),
    include_str!("../../pages/checks/repair.js"),
    include_str!("../../pages/checks/passwords.js"),
    include_str!("../../pages/checks/wallet.js"),
    include_str!("../../pages/checks/runtime.js"),
    include_str!("../../pages/checks/run.js"),
];
/// The block appended to the worker that runs Argon2 at a reduced cost; each `${inline(NAME)}` in
/// it takes the JSON value of NAME from PAGE_DATA. The suite 3 cost the core must ask for is
/// replaced by the cost of REDUCED_COST_CONTAINER in src/mhfe.rs. Any other cost is refused with
/// the cost asked for in the message, so that the page sees what a PIM asks for. With
/// FAULTY_CHECK_PASSWORD the wrapper changes one bit of the key from the 13th call on, the rounds
/// in which an encryption checks its new container: it stands for a fault during the long
/// computation, which that check must catch. The memory markers fail with the message of the real
/// Argon2 bridge (web/argon2-engine.js), whose prefix the core turns into MEMORY_ALLOCATION_FAILED,
/// as by a browser that cannot give the memory. The wrapper replaces argon2For, which receives the
/// request, so that the reserve sees the container; a block keeps its names apart from those of the
/// worker and of the Argon2 build in front of it.
/// Fault: a key bit from the 13th call of FAULTY_CHECK_PASSWORD, as a fault during the work.
/// Fault: the Argon2 memory for the MEMORY_FAILURE markers, refused as by a browser without it.
const WRAPPER: &str = include_str!("../../pages/reduced-cost-wrapper.js");
/// The values of PAGE_DATA that WRAPPER takes.
const WRAPPER_VALUES: [&str; 3] = [
    "FAULTY_CHECK_PASSWORD",
    "MEMORY_FAILURE_PASSWORD",
    "MEMORY_FAILURE_CONTAINER",
];
/// The fixed `const` lines of the page.
const PAGE_DATA: &str = include_str!("../../pages/page-data.js");
/// The page's event recorder, its first script.
const EVENTS: &str = include_str!("../../pages/page-events.js");
/// The class files that follow the runtime in the module, by path in the package.
const CLASSES: [&str; 4] = [
    "core/client.js",
    "repair/repair.js",
    "passwords/passwords.js",
    "wallet/wallet.js",
];
/// The end of a class file's list that imports or exports from the runtime.
const RUNTIME_LIST_END: &str = "} from \"../runtime/runtime.js\";\n";
/// The digits of base64, in their order.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The page for the package in `dist`.
pub(super) fn page(dist: &Path) -> Result<String, Failure> {
    let checks = CHECKS.concat();
    let module = format!(
        "{}{}(function pageScript() {{\n{checks}}})();\n",
        classes(dist)?,
        sources(dist)?
    );
    let policy = [
        "default-src 'none'".to_owned(),
        format!(
            "script-src 'sha256-{}' 'sha256-{}' 'wasm-unsafe-eval'",
            hash(EVENTS),
            hash(&module)
        ),
        "connect-src 'none'".to_owned(),
        "worker-src blob:".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
    ]
    .join("; ");
    Ok(format!(
        "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"utf-8\" />\n    \
         <meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\" />\n    \
         <title>MHFE browser check</title>\n  </head>\n  <body>\n    \
         <script>{EVENTS}</script>\n    \
         <script type=\"module\">{module}</script>\n  </body>\n</html>\n"
    ))
}

/// The runtime and the class files as one module's text: each class file without its lists that
/// import or export from the runtime, whose names are in the same module then.
fn classes(dist: &Path) -> Result<String, Failure> {
    let mut parts = vec![text(&dist.join("runtime/runtime.js"))?];
    for path in CLASSES {
        parts.push(without_runtime_lists(&text(&dist.join(path))?));
    }
    Ok(parts.join("\n"))
}

/// `text` without the lists that start a line with `import {` or `export {` and whose first `}`
/// ends RUNTIME_LIST_END. A deliberate copy of the rule of scripts/bundle-browser-classes.mjs,
/// which the package checks still running in Node use until they are ported: a change goes to
/// both.
fn without_runtime_lists(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        if (rest.starts_with("import {") || rest.starts_with("export {"))
            && let Some(brace) = rest.find('}')
            && rest[brace..].starts_with(RUNTIME_LIST_END)
        {
            at += brace + RUNTIME_LIST_END.len();
            continue;
        }
        let line = rest.find('\n').map_or(rest.len(), |end| end + 1);
        kept.push_str(&rest[..line]);
        at += line;
    }
    kept
}

/// The page's `const` lines: the version and the build of the package, its WebAssembly and
/// Argon2 builds, the worker with the reduced-cost wrapper, and the fixed data in between.
fn sources(dist: &Path) -> Result<String, Failure> {
    let data: Vec<(&str, &str)> = PAGE_DATA
        .lines()
        .filter_map(|line| Some((line.strip_prefix("const ")?.split_once(" = ")?.0, line)))
        .collect();
    let line_of = |name: &str| {
        data.iter()
            .find(|(own, _)| *own == name)
            .map(|(_, line)| *line)
            .ok_or_else(|| Failure(format!("xtask/pages/page-data.js holds no {name}")))
    };
    let manifest: Value = serde_json::from_str(&text(&dist.join("modules.json"))?)
        .map_err(|error| at(&dist.join("modules.json"), error))?;
    let mut wrapper = WRAPPER.to_owned();
    for name in WRAPPER_VALUES {
        let value = line_of(name)?
            .split_once(" = ")
            .map_or("", |(_, value)| value);
        let value = value.strip_suffix(';').unwrap_or(value);
        wrapper = wrapper.replace(&format!("${{inline({name})}}"), value);
    }
    let worker = format!("{}\n{wrapper}", text(&dist.join("runtime/worker.js"))?);
    let wasm = std::fs::read(dist.join("runtime/mhfe.wasm"))
        .map_err(|error| at(&dist.join("runtime/mhfe.wasm"), error))?;
    let mut lines = vec![
        constant("VERSION", &manifest["version"]),
        constant("PACKAGE_BUILD_ID", &manifest["buildId"]),
        line_of("SELF_CHECK")?.replace('<', "\\u003c"),
        constant("WORKER_SOURCE", &Value::from(worker)),
        constant("WASM_BASE64", &Value::from(base64(&wasm))),
        constant(
            "ARGON2_THREADED",
            &Value::from(text(&dist.join("core/argon2-mt.js"))?),
        ),
        constant(
            "ARGON2_SINGLE_THREADED",
            &Value::from(text(&dist.join("core/argon2-st.js"))?),
        ),
    ];
    // The fixed lines as safe in a script element as the computed ones: "</script" cannot appear.
    let rest = data.iter().filter(|(name, _)| *name != "SELF_CHECK");
    lines.extend(rest.map(|(_, line)| line.replace('<', "\\u003c")));
    Ok(format!("\n{}\n", lines.join("\n")))
}

/// The line `const NAME = value;`, the value as JSON that is safe in a script element: `<` is
/// escaped, so that "</script" cannot appear.
fn constant(name: &str, value: &Value) -> String {
    format!(
        "const {name} = {};",
        value.to_string().replace('<', "\\u003c")
    )
}

/// The text of `path`.
fn text(path: &Path) -> Result<String, Failure> {
    std::fs::read_to_string(path).map_err(|error| at(path, error))
}

/// The SHA-256 of `script` in base64, as a Content-Security-Policy names a script.
fn hash(script: &str) -> String {
    base64(&Sha256::digest(script.as_bytes()))
}

/// `bytes` in base64 with padding, as RFC 4648 writes it.
fn base64(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let bits = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |bits, (index, &byte)| {
                bits | u32::from(byte) << (16 - 8 * index)
            });
        for digit in 0..4 {
            if digit <= chunk.len() {
                let six = (bits >> (18 - 6 * digit)) & 0x3f;
                encoded.push(char::from(BASE64[usize::try_from(six).unwrap_or_default()]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_written_as_rfc_4648_writes_it() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (text, encoded) in vectors {
            assert_eq!(base64(text.as_bytes()), encoded);
        }
    }

    #[test]
    fn only_the_lists_from_the_runtime_are_left_out() {
        let text = "import { A } from \"../runtime/runtime.js\";\nexport {\n  B,\n} from \
                    \"../runtime/runtime.js\";\nimport { C } from \"./other.js\";\nconst x = 1;\n";
        assert_eq!(
            without_runtime_lists(text),
            "import { C } from \"./other.js\";\nconst x = 1;\n"
        );
    }
}
