//! `cargo xtask wasm verify DIR`: the checks of the browser package that scripts/build-wasm.sh
//! built in DIR which need no JavaScript engine:
//!
//! - `modules.json` and `README.md` are what the package's files give, so every file has the
//!   SHA-256 they name, with the version of Cargo.toml and the build of the WebAssembly;
//! - the WebAssembly names no folder of the machine that built it, and no absolute source path but
//!   rustc's own, while the dependencies' paths are there, remapped from CARGO_HOME to `cargo/`;
//! - no script holds code that could reach the network or a vector text of the wallet's or the
//!   rehearsal's known answers;
//! - one build: the WebAssembly's one `mhfe-build` section and the build constant of every script
//!   name the build of `modules.json`, the one derived again from the files with their stamps
//!   taken out, and the WebAssembly without its stamp is what wasm-bindgen wrote;
//! - the stamp changes the build for a change of one script, and refuses a package stamped already
//!   and a script without its build constant;
//! - the sources that the page and the worker share by copy agree: the secret fields they wipe,
//!   the advice of PACKAGE_MISMATCH and the news that the worker scripts post.
//!
//! The checks that run the package's code stay with the browser checks.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::stamp::{BUILD_ID_DIGITS, SCRIPTS, UNSTAMPED, WASM_FILE, build_id, section};
use super::{
    BUILD_SECTION, custom_sections, manifest, network::network_code, read, stamp_other_build, text,
};
use crate::Failure;

/// Where rustc puts the standard library's sources and its dependencies' itself.
const REMAPPED_BY_RUSTC: [&str; 2] = ["/rustc/", "/rust/deps/"];
/// The Rust files whose strings hold the vectors of the wallet's and the rehearsal's checks.
const KNOWN_ANSWERS: [&str; 2] = [
    "src/wallet/known_answers.rs",
    "src/rehearsal/known_answers.rs",
];
/// Two of those vectors, one over several lines of its file, so that a reading that misses
/// strings is caught.
const KNOWN_VECTORS: [&str; 2] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
];
/// The advice of PACKAGE_MISMATCH, which the page's runtime and the worker's both give.
const ADVICE: &str = ": take every file of the package from one build.";
/// The worker scripts in web/, whose news the page's WORKER_NEWS must name.
const WORKERS: [&str; 5] = [
    "worker-runtime.js",
    "core-worker.js",
    "repair-worker.js",
    "passwords-worker.js",
    "wallet-worker.js",
];
/// The messages of the worker's own protocol, which are not news.
const OWN_MESSAGES: [&str; 4] = ["ready", "result", "error", "ask"];

/// Runs the checks on the package in `folder`.
pub(super) fn run(root: &Path, folder: &Path) -> Result<(), Failure> {
    let (json, readme) = manifest::render(root, folder)?;
    let same = |name: &str, expected: &str| -> Result<(), Failure> {
        let found = text(&folder.join(name))?;
        ensure(found == expected, || {
            format!("{name} is not what the package's files give")
        })
    };
    same("modules.json", &json)?;
    same("README.md", &readme)?;
    let wasm = read(&folder.join(WASM_FILE))?;
    check_paths(&wasm, root)?;
    let vectors = vector_texts(root)?;
    for path in scripts(folder)? {
        let script = text(&folder.join(&path))?;
        if let Some(word) = network_code(&script) {
            return Err(Failure(format!("{path} holds network code: {word}")));
        }
        if let Some(vector) = vectors
            .iter()
            .find(|vector| script.contains(vector.as_str()))
        {
            return Err(Failure(format!("{path} carries the vector text {vector}")));
        }
    }
    let build = manifest::build_of(folder)?;
    check_build(root, folder, &build)?;
    check_sources(root)?;
    stamp_other_build(root, folder)?;
    println!(
        "The browser package's manifest, build, WebAssembly paths and scripts pass their checks."
    );
    Ok(())
}

/// Every script of the package, by path in it: the `.js` files of the runtime and of each module.
fn scripts(folder: &Path) -> Result<Vec<String>, Failure> {
    let mut scripts = Vec::new();
    for name in std::iter::once("runtime").chain(manifest::MODULES) {
        let files = manifest::files_of(&folder.join(name))?;
        let names = files.into_keys().filter(|file| file.ends_with(".js"));
        scripts.extend(names.map(|file| format!("{name}/{file}")));
    }
    Ok(scripts)
}

/// Fails with `message` when `condition` does not hold.
pub(super) fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure(message()))
    }
}

/// Checks that the WebAssembly's one build section and every script's build constant name
/// `build`, and that `build` is the build of the files with their stamps taken out.
fn check_build(root: &Path, folder: &Path, build: &str) -> Result<(), Failure> {
    let hex = build.len() == BUILD_ID_DIGITS
        && build
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    ensure(hex, || {
        format!("the build {build} is not {BUILD_ID_DIGITS} hex digits")
    })?;
    let (wasm, scripts) = unstamped(folder, build)?;
    let bindgen = root.join("target/wasm-bindgen/mhfe_bg.wasm");
    ensure(read(&bindgen)? == wasm, || {
        format!("{WASM_FILE} without its build is not {}", bindgen.display())
    })?;
    let derived = build_id(&wasm, &scripts);
    ensure(derived == build, || {
        format!("the files give the build {derived}, not {build}")
    })
}

/// The WebAssembly and the scripts of SCRIPTS of the package in `folder` as they were before
/// `build` was stamped into them, after checking that the WebAssembly's one build section and every
/// script's build constant name `build`.
pub(super) fn unstamped(folder: &Path, build: &str) -> Result<(Vec<u8>, Vec<String>), Failure> {
    let wasm_path = folder.join(WASM_FILE);
    let wasm = read(&wasm_path)?;
    let sections = custom_sections(&wasm, BUILD_SECTION, &wasm_path)?;
    ensure(sections == [build.as_bytes()], || {
        format!("{WASM_FILE} does not name the build once")
    })?;
    let unstamped = wasm
        .strip_suffix(section(build).as_slice())
        .ok_or_else(|| Failure(format!("{WASM_FILE} does not end with its build")))?;
    let mut scripts = Vec::with_capacity(SCRIPTS.len());
    for (path, constant) in SCRIPTS {
        let script = text(&folder.join(path))?;
        let stamped = format!("{constant} = \"{build}\";");
        ensure(script.matches(&stamped).count() == 1, || {
            format!("{path} is not stamped once")
        })?;
        let unstamped_left = script.contains("BUILD_ID = \"development\"");
        ensure(!unstamped_left, || {
            format!("{path} holds an unstamped build")
        })?;
        let last = path.contains("argon2") && !script.ends_with(&format!("\n{stamped}\n"));
        ensure(!last, || format!("{path} does not end with its build"))?;
        let development = format!("{constant} = {UNSTAMPED}");
        scripts.push(script.replacen(&stamped, &development, 1));
    }
    Ok((unstamped.to_vec(), scripts))
}

/// Checks that `wasm` names no folder of this machine and no absolute source path but rustc's
/// own, and that it holds the dependencies' remapped paths.
fn check_paths(wasm: &[u8], root: &Path) -> Result<(), Failure> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let named_or = |variable: &str, default: &str| {
        // cargo and rustup take an empty value as unset.
        let named = std::env::var_os(variable).filter(|value| !value.is_empty());
        named.map_or_else(|| home.join(default), PathBuf::from)
    };
    let folders = [
        PathBuf::from("/home/"),
        root.to_path_buf(),
        named_or("CARGO_HOME", ".cargo"),
        named_or("RUSTUP_HOME", ".rustup"),
    ];
    for folder in folders {
        let folder = folder.to_string_lossy().into_owned();
        if let Some(at) = find(wasm, folder.as_bytes()) {
            let context = latin1(wasm.get(at..wasm.len().min(at + 160)).unwrap_or_default());
            return Err(Failure(format!(
                "{WASM_FILE} names {folder} of the machine that built it, in {context:?}"
            )));
        }
    }
    let paths = source_paths(wasm);
    ensure(!paths.is_empty(), || {
        format!("no source path is found in {WASM_FILE}")
    })?;
    let foreign: Vec<&String> = paths
        .iter()
        .filter(|path| {
            !REMAPPED_BY_RUSTC
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .collect();
    ensure(foreign.is_empty(), || {
        format!("{WASM_FILE} names absolute source paths: {foreign:?}")
    })?;
    ensure(registry_path(wasm), || {
        format!("{WASM_FILE} holds no dependency path remapped from CARGO_HOME to cargo/")
    })
}

/// Where `needle` first occurs in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// `bytes` read as Latin-1, a character for each byte.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// Whether `byte` is printable ASCII but the space.
fn printable(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}

/// The absolute source paths in `wasm`: a slash that no printable byte precedes, then at least
/// five printable bytes, as few as end in a Rust or C file name that no letter, digit or `_`
/// follows.
fn source_paths(wasm: &[u8]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut at = 0;
    while at < wasm.len() {
        let starts = wasm[at] == b'/' && (at == 0 || !printable(wasm[at - 1]));
        if starts && let Some(end) = source_path_end(wasm, at) {
            paths.push(latin1(&wasm[at..end]));
            at = end;
        } else {
            at += 1;
        }
    }
    paths
}

/// Where the source path that starts with the slash at `start` ends, or None when none does.
fn source_path_end(wasm: &[u8], start: usize) -> Option<usize> {
    let word = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_';
    let mut end = start + 1;
    while wasm.get(end).copied().is_some_and(printable) {
        end += 1;
        if end - start - 1 < 5 {
            continue;
        }
        for extension in [&b".rs"[..], b".c", b".h"] {
            let after = end + extension.len();
            if wasm.get(end..after) == Some(extension) && !wasm.get(after).is_some_and(word) {
                return Some(after);
            }
        }
    }
    None
}

/// Whether `wasm` holds a dependency's path remapped to `cargo/registry/src/…/bip39-…`, with no
/// printable byte before it.
fn registry_path(wasm: &[u8]) -> bool {
    const PREFIX: &[u8] = b"cargo/registry/src/";
    let mut from = 0;
    while let Some(at) = wasm
        .get(from..)
        .and_then(|rest| find(rest, PREFIX))
        .map(|at| at + from)
    {
        let alone = at == 0 || !printable(wasm[at - 1]);
        let rest = &wasm[at + PREFIX.len()..];
        let segment = rest
            .iter()
            .position(|&byte| byte == b'/')
            .unwrap_or(rest.len());
        if alone && segment > 0 && rest[segment..].starts_with(b"/bip39-") {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The vector texts of KNOWN_ANSWERS: their strings of 8 characters or more that hold a digit and
/// no space (an address, a digest, a seed or a path) or 12 words or more (a phrase).
pub(crate) fn vector_texts(root: &Path) -> Result<Vec<String>, Failure> {
    let mut vectors = Vec::new();
    for file in KNOWN_ANSWERS {
        for string in rust_strings(&text(&root.join(file))?) {
            let digit =
                string.contains(|char: char| char.is_ascii_digit()) && !string.contains(' ');
            let vector = string.chars().count() >= 8 && (digit || string.split(' ').count() >= 12);
            if vector && !vectors.contains(&string) {
                vectors.push(string);
            }
        }
    }
    for known in KNOWN_VECTORS {
        let read = vectors.iter().any(|vector| vector == known);
        ensure(read, || {
            format!("the vector {known} is not read from {KNOWN_ANSWERS:?}")
        })?;
    }
    Ok(vectors)
}

/// The string literals of a Rust file, with their escapes resolved: `\n`, `\t`, `\0`, `\u{…}`, a
/// line continuation, and any other escaped character as itself. Line comments are skipped.
fn rust_strings(source: &str) -> Vec<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut strings = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '/' && chars.get(at + 1) == Some(&'/') {
            at += chars[at..]
                .iter()
                .position(|&char| char == '\n')
                .unwrap_or(chars.len() - at);
        } else if chars[at] == '"' {
            let (string, end) = rust_string(&chars, at + 1);
            strings.push(string);
            at = end + 1;
        } else {
            at += 1;
        }
    }
    strings
}

/// The string whose text starts at `from`, and where its closing quote stands.
fn rust_string(chars: &[char], from: usize) -> (String, usize) {
    let mut string = String::new();
    let mut at = from;
    while let Some(&char) = chars.get(at)
        && char != '"'
    {
        if char != '\\' {
            string.push(char);
            at += 1;
            continue;
        }
        match chars.get(at + 1) {
            // A line continuation: the line break and the next line's indentation are left out.
            Some('\n') => {
                at += 2;
                while chars.get(at).is_some_and(|char| char.is_whitespace()) {
                    at += 1;
                }
            }
            Some('u') => {
                // `\u{…}`: the hex digits after the brace, as far as the closing one.
                let close = chars[at..].iter().position(|&char| char == '}');
                let end = close.map_or(chars.len(), |close| at + close);
                let digits: String = chars.get(at + 3..end).unwrap_or_default().iter().collect();
                string.extend(
                    u32::from_str_radix(&digits, 16)
                        .ok()
                        .and_then(char::from_u32),
                );
                at = end + 1;
            }
            escaped => {
                string.push(match escaped {
                    Some('n') => '\n',
                    Some('t') => '\t',
                    Some('0') => '\0',
                    Some(&other) => other,
                    None => '\\',
                });
                at += 2;
            }
        }
    }
    (string, at)
}

/// Checks the copies that the page's runtime and the worker scripts keep of each other in web/.
fn check_sources(root: &Path) -> Result<(), Failure> {
    let source = |file: &str| text(&root.join("web").join(file));
    let runtime = source("runtime.js")?;
    let worker_runtime = source("worker-runtime.js")?;
    let fields = |script: &str| {
        list_after(script, "const SECRET_FIELDS = [").map(|list| {
            list.chars()
                .filter(|char| !char.is_whitespace())
                .collect::<String>()
        })
    };
    let same = fields(&runtime).is_some() && fields(&runtime) == fields(&worker_runtime);
    ensure(same, || {
        "the page and the worker do not wipe the same secret fields".to_owned()
    })?;
    for (file, script) in [
        ("runtime.js", &runtime),
        ("worker-runtime.js", &worker_runtime),
    ] {
        ensure(script.contains(ADVICE), || {
            format!("{file} lacks the advice of PACKAGE_MISMATCH")
        })?;
    }
    let news = list_after(&runtime, "const WORKER_NEWS = [")
        .and_then(|list| serde_json::from_str::<Vec<String>>(&format!("[{list}]")).ok())
        .ok_or_else(|| Failure("web/runtime.js holds no WORKER_NEWS list".to_owned()))?;
    let mut workers = String::new();
    for file in WORKERS {
        workers.push_str(&source(file)?);
        workers.push('\n');
    }
    let mut posted: BTreeSet<&str> = names_after(&workers, "postMessage({ type: \"");
    posted.extend(names_after(&workers, "host.post(\""));
    for own in OWN_MESSAGES {
        posted.remove(own);
    }
    let mut news: Vec<&str> = news.iter().map(String::as_str).collect();
    news.sort_unstable();
    let posted: Vec<&str> = posted.into_iter().collect();
    ensure(posted == news, || {
        format!("the page knows the news {news:?}, the workers post {posted:?}")
    })
}

/// The text between the first `start` in `script` and the `]` after it.
fn list_after<'a>(script: &'a str, start: &str) -> Option<&'a str> {
    let from = script.find(start)? + start.len();
    let length = script[from..].find(']')?;
    Some(&script[from..from + length])
}

/// The names that follow `start` in `text`, letters, digits and `_` closed by a quote.
fn names_after<'a>(text: &'a str, start: &str) -> BTreeSet<&'a str> {
    text.match_indices(start)
        .filter_map(|(at, _)| {
            let rest = &text[at + start.len()..];
            let length = rest.find(|char: char| !(char.is_ascii_alphanumeric() || char == '_'))?;
            (length > 0 && rest[length..].starts_with('"')).then_some(&rest[..length])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_source_paths_are_found_as_the_package_check_found_them() {
        let wasm =
            b"\0/rustc/abc/library/core/src/str.rs\0x/home/a.rs\0/a/b.rsx\0/ab.c\0/abcdef.h\0";
        let paths = source_paths(wasm);
        assert_eq!(paths, ["/rustc/abc/library/core/src/str.rs", "/abcdef.h"]);
        assert!(registry_path(
            b"\0cargo/registry/src/index-1/bip39-2.2.0/src/lib.rs"
        ));
        assert!(!registry_path(
            b"xcargo/registry/src/index-1/bip39-2.2.0/src/lib.rs"
        ));
        assert!(!registry_path(
            b"\0cargo/registry/src//bip39-2.2.0/src/lib.rs"
        ));
    }

    #[test]
    fn rust_strings_resolve_their_escapes_and_skip_line_comments() {
        let source =
            "// \"not a string\"\nlet a = \"one \\\n        two\\n\\u{41}\\\"\";\nlet b = \"x\";";
        assert_eq!(rust_strings(source), ["one two\nA\"", "x"]);
    }

    #[test]
    fn news_and_lists_are_read_as_the_package_check_read_them() {
        let workers = "postMessage({ type: \"progress\" });host.post(\"warning\", x);host.post(x);\
                       postMessage({ type: \"ready\" })";
        let names: Vec<&str> = names_after(workers, "postMessage({ type: \"")
            .into_iter()
            .collect();
        assert_eq!(names, ["progress", "ready"]);
        assert_eq!(names_after(workers, "host.post(\"").len(), 1);
        assert_eq!(list_after("const A = [1, 2];", "const A = ["), Some("1, 2"));
    }
}
