//! `cargo xtask wasm stamp-build-id DIR`: stamps the build of the browser package in DIR into its
//! parts, so that a page and a worker tell files of different builds apart before they use them
//! together (PackageCheck and WorkerJob in web/runtime.js, requireSameBuild in
//! web/worker-runtime.js, startArgon2 in web/core-worker.js).
//!
//! The build is derived from every file a page loads, before any of them is stamped: the first 16
//! hex digits of the SHA-256 of a list with one line per file, the WebAssembly and then SCRIPTS,
//! each the file's own SHA-256, two spaces and its path, as `sha256sum` prints it. So two
//! reproducible builds stamp the same, and two builds that differ in any of these files, in a
//! script alone too, stamp different ones. The build goes into `runtime/mhfe.wasm` as the custom
//! section "mhfe-build", and in place of "development" into the build constant of every script. A
//! script that does not hold exactly one such constant, or a WebAssembly stamped already, stops
//! the build before anything is written. It catches parts of different builds mixed by accident,
//! not deliberate tampering, which SHA256SUMS and its signature cover.

use std::path::Path;

use super::{
    BUILD_SECTION, CUSTOM_SECTION_ID, custom_sections, leb128, read, sha256_hex, text, write,
};
use crate::Failure;

/// Hex digits of the SHA-256 kept: 64 bits tell builds apart well beyond any need.
pub(super) const BUILD_ID_DIGITS: usize = 16;
/// The WebAssembly, which carries its build in BUILD_SECTION.
pub(super) const WASM_FILE: &str = "runtime/mhfe.wasm";
/// The scripts a page loads, by path in the package, in the order of the list the build is
/// derived from, each with the start of its build constant. The Argon2 builds get theirs from
/// scripts/build-wasm.sh.
pub(super) const SCRIPTS: [(&str, &str); 8] = [
    ("runtime/runtime.js", "export const BUILD_ID"),
    ("runtime/worker.js", "const WORKER_BUILD_ID"),
    ("core/client.js", "const CLIENT_BUILD_ID"),
    ("core/argon2-mt.js", "const ARGON2_THREADED_BUILD_ID"),
    ("core/argon2-st.js", "const ARGON2_SINGLE_THREADED_BUILD_ID"),
    ("repair/repair.js", "const REPAIR_BUILD_ID"),
    ("passwords/passwords.js", "const PASSWORDS_BUILD_ID"),
    ("wallet/wallet.js", "const WALLET_BUILD_ID"),
];
/// The value of a build constant before stamping, as in `const CLIENT_BUILD_ID = "development";`.
const UNSTAMPED: &str = "\"development\";";
/// The characters that end a line, as for JavaScript's `^` and `$` in a multiline pattern.
const LINE_ENDS: [char; 4] = ['\n', '\r', '\u{2028}', '\u{2029}'];

/// Stamps the package in `folder`.
pub(super) fn run(folder: &Path) -> Result<(), Failure> {
    let wasm_path = folder.join(WASM_FILE);
    let mut wasm = read(&wasm_path)?;
    if !custom_sections(&wasm, BUILD_SECTION, &wasm_path)?.is_empty() {
        return Err(Failure(format!(
            "{} is stamped already; build it again.",
            wasm_path.display()
        )));
    }
    let mut scripts = Vec::with_capacity(SCRIPTS.len());
    for (path, _) in SCRIPTS {
        scripts.push(text(&folder.join(path))?);
    }
    let build_id = build_id(&wasm, &scripts);
    let mut stamped = Vec::with_capacity(scripts.len());
    for ((path, _), script) in SCRIPTS.iter().zip(scripts) {
        let file = folder.join(path);
        let text = stamp(&script, &build_id).map_err(|count| {
            Failure(format!(
                "{} holds {count} build constants instead of one.",
                file.display()
            ))
        })?;
        stamped.push((file, text));
    }
    for (file, text) in stamped {
        write(&file, text)?;
    }
    wasm.extend(section(&build_id));
    write(&wasm_path, wasm)?;
    println!("Stamped build {build_id} into the package.");
    Ok(())
}

/// The build of a package whose files before stamping are `wasm` and `scripts`, in the order of
/// SCRIPTS: the first hex digits of the SHA-256 of their list.
pub(super) fn build_id(wasm: &[u8], scripts: &[String]) -> String {
    let mut list = format!("{}  {WASM_FILE}\n", sha256_hex(wasm));
    for ((path, _), script) in SCRIPTS.iter().zip(scripts) {
        list.push_str(&format!("{}  {path}\n", sha256_hex(script.as_bytes())));
    }
    sha256_hex(list.as_bytes())[..BUILD_ID_DIGITS].to_owned()
}

/// The custom section that names `build_id`, as the stamp ends the WebAssembly with it: its id,
/// its size, the length of its name and the name, then the build.
pub(super) fn section(build_id: &str) -> Vec<u8> {
    let mut body = leb128(BUILD_SECTION.len());
    body.extend(BUILD_SECTION.as_bytes());
    body.extend(build_id.as_bytes());
    let mut section = vec![CUSTOM_SECTION_ID];
    section.extend(leb128(body.len()));
    section.extend(body);
    section
}

/// `text` with its build constant stamped with `build_id`, or the number of build constants when
/// it holds not exactly one. A build constant is a line `const NAME = "development";`, with
/// `export ` allowed before it, whose NAME is capitals, digits and `_` and ends in `BUILD_ID`. A
/// line ends where JavaScript's `$` ends one: at LINE_ENDS.
fn stamp(text: &str, build_id: &str) -> Result<String, usize> {
    let mut count = 0;
    let mut stamped = String::with_capacity(text.len());
    for piece in text.split_inclusive(LINE_ENDS) {
        let line = piece.strip_suffix(LINE_ENDS).unwrap_or(piece);
        match constant(line) {
            Some(start) => {
                count += 1;
                stamped.push_str(&format!("{start}\"{build_id}\";"));
                stamped.push_str(&piece[line.len()..]);
            }
            None => stamped.push_str(piece),
        }
    }
    if count == 1 { Ok(stamped) } else { Err(count) }
}

/// The part of the build constant `line` before its value, or None when the line is none.
fn constant(line: &str) -> Option<&str> {
    let start = line.strip_suffix(UNSTAMPED)?;
    let declaration = start.strip_prefix("export ").unwrap_or(start);
    let name = declaration.strip_prefix("const ")?.strip_suffix(" = ")?;
    let capitals = name
        .bytes()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
    (capitals && name.ends_with("BUILD_ID")).then_some(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_build_constant_is_stamped_in_place() {
        let text = "a\nexport const CLIENT_BUILD_ID = \"development\";\nb\n";
        let stamped = stamp(text, "0123456789abcdef");
        assert_eq!(
            stamped,
            Ok("a\nexport const CLIENT_BUILD_ID = \"0123456789abcdef\";\nb\n".to_owned())
        );
        assert_eq!(
            stamp("const BUILD_ID = \"development\";", "x"),
            Ok("const BUILD_ID = \"x\";".to_owned())
        );
    }

    #[test]
    fn a_line_ends_where_javascript_ends_one() {
        let constant = "const A_BUILD_ID = \"development\";";
        let crlf = stamp(&format!("{constant}\r\n"), "x");
        assert_eq!(crlf, Ok("const A_BUILD_ID = \"x\";\r\n".to_owned()));
        let other = constant.replace('A', "B");
        assert_eq!(stamp(&format!("{constant}\nx\r{other}"), "x"), Err(2));
        for end in ["\u{2028}", "\u{2029}"] {
            assert_eq!(stamp(&format!("{constant}{end}{other}"), "x"), Err(2));
        }
        // U+0085 ends no line for JavaScript.
        assert_eq!(stamp(&format!("x\u{85}{constant}"), "x"), Err(0));
    }

    #[test]
    fn a_text_without_one_build_constant_is_refused_with_its_count() {
        let constant = "const A_BUILD_ID = \"development\";";
        assert_eq!(stamp("a\nb", "x"), Err(0));
        assert_eq!(stamp(&format!("{constant}\n{constant}"), "x"), Err(2));
        for other in [
            "const a_BUILD_ID = \"development\";",
            "let A_BUILD_ID = \"development\";",
            "  const A_BUILD_ID = \"development\";",
            "const A_BUILD_ID = \"development\"; // x",
            "const A_BUILD_IDS = \"development\";",
        ] {
            assert_eq!(stamp(other, "x"), Err(0), "{other}");
        }
    }
}
