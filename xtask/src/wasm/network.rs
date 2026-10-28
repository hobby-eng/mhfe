//! `cargo xtask wasm remove-network-code argon2|glue FILE…`: removes the network loaders from the
//! generated browser scripts, so that the package contains no code that could fetch anything, not
//! even code that never runs.
//!
//! Emscripten and wasm-bindgen always emit loaders that fetch a WebAssembly file by URL. MHFE
//! never uses them: the Argon2 builds embed their WebAssembly (SINGLE_FILE) and read it
//! synchronously, and the worker passes the Rust core to `initSync`. Each loader is replaced by a
//! stub that throws. Every replaced text must occur exactly once, so an update of either tool that
//! changes it stops the build instead of leaving a loader behind. Tools that embed the package,
//! such as the wallet tools, refuse a page that contains fetch or XMLHttpRequest at all.

use std::path::Path;

use super::{USAGE, text, write};
use crate::Failure;

/// What every stub says when it is called.
const EMBEDDED: &str = "MHFE loads no files: its WebAssembly is embedded";
/// The minified Emscripten 6.0.12 loaders of a worker build, each with the start of its stub.
const ARGON2_LOADERS: [(&str, &str); 2] = [
    (
        "readBinary=url=>{var xhr=new XMLHttpRequest;xhr.open(\"GET\",url,false);\
         xhr.responseType=\"arraybuffer\";xhr.send(null);return new Uint8Array(xhr.response)}",
        "readBinary=",
    ),
    (
        "readAsync=async url=>{var response=await fetch(url,{credentials:\"same-origin\"});\
         if(response.ok){return response.arrayBuffer()}\
         throw new Error(response.status+\" : \"+response.url)}",
        "readAsync=async ",
    ),
];
/// The wasm-bindgen glue's loader by URL, `__wbg_load`, as far as the line that follows it.
const GLUE_LOAD: (&str, &str) = (
    "    async function __wbg_load(module, imports) {",
    "    function initSync(module) {",
);
/// The glue's asynchronous initializer, as far as the line that follows it.
const GLUE_INIT: (&str, &str) = (
    "    async function __wbg_init(module_or_path) {",
    "    return Object.assign(__wbg_init, { initSync }, exports);",
);
/// Code that could reach the network: none of it may remain. Each name counts as a whole word, and
/// `fetch` only with an opening parenthesis after it, white space allowed between.
const NETWORK_WORDS: [&str; 5] = [
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "sendBeacon",
];

/// Replaces the loaders of `files`, Emscripten builds (`argon2`) or the wasm-bindgen glue (`glue`).
pub(super) fn run(kind: &str, files: &[String]) -> Result<(), Failure> {
    if kind != "argon2" && kind != "glue" {
        return Err(Failure(USAGE.to_owned()));
    }
    for file in files {
        let path = Path::new(file);
        let text = text(path)?;
        let text = if kind == "argon2" {
            without_argon2_loaders(text, file)?
        } else {
            without_glue_loader(&text, file)?
        };
        if let Some(word) = network_code(&text) {
            return Err(Failure(format!(
                "{file}: network code is still present: {word}"
            )));
        }
        write(path, text)?;
    }
    Ok(())
}

/// `text` with each loader of ARGON2_LOADERS, which must occur exactly once, replaced by its stub.
fn without_argon2_loaders(mut text: String, file: &str) -> Result<String, Failure> {
    for (loader, start) in ARGON2_LOADERS {
        let count = text.matches(loader).count();
        if count != 1 {
            let shown = loader.get(..60).unwrap_or(loader);
            return Err(Failure(format!(
                "{file}: expected the loader text exactly once, found it {count} times: {shown}"
            )));
        }
        let stub = format!("{start}url=>{{throw new Error(\"{EMBEDDED}\")}}");
        text = text.replacen(loader, &stub, 1);
    }
    Ok(text)
}

/// The glue without its loader by URL: `__wbg_load` only serves `__wbg_init`; both go, and the
/// asynchronous initializer that the glue exports becomes a stub. `initSync`, which the worker
/// uses, stays as it is.
fn without_glue_loader(text: &str, file: &str) -> Result<String, Failure> {
    let without_load = replace_block(text, GLUE_LOAD, "", file)?;
    let stub = format!(
        "    // Loading by URL is removed: MHFE passes the module to initSync and \
         fetches nothing.\n    \
         function __wbg_init() {{\n        throw new Error('{EMBEDDED}; use initSync');\n    }}\n\n"
    );
    replace_block(&without_load, GLUE_INIT, &stub, file)
}

/// `text` with `replacement` in place of the part from the text `from`, which must occur exactly
/// once, up to the first `to` after it.
fn replace_block(
    text: &str,
    (from, to): (&str, &str),
    replacement: &str,
    file: &str,
) -> Result<String, Failure> {
    let missing = || {
        Failure(format!(
            "{file}: the wasm-bindgen loader block \"{}\" was not found exactly once",
            from.trim()
        ))
    };
    let start = text.find(from).ok_or_else(missing)?;
    let end = text[start..].find(to).ok_or_else(missing)? + start;
    if text[start + 1..].contains(from) {
        return Err(missing());
    }
    Ok(format!("{}{replacement}{}", &text[..start], &text[end..]))
}

/// The first name of NETWORK_WORDS that `text` holds as code that could reach the network.
pub(super) fn network_code(text: &str) -> Option<&'static str> {
    let word_char = |char: char| char.is_ascii_alphanumeric() || char == '_';
    // Rust's white space and U+FEFF: JavaScript's, and U+0085, which only makes the check stricter.
    let space = |char: char| char.is_whitespace() || char == '\u{feff}';
    NETWORK_WORDS.into_iter().find(|word| {
        text.match_indices(word).any(|(at, _)| {
            let after = &text[at + word.len()..];
            let alone_before = !text[..at].chars().next_back().is_some_and(word_char);
            alone_before
                && if *word == "fetch" {
                    after.trim_start_matches(space).starts_with('(')
                } else {
                    !after.chars().next().is_some_and(word_char)
                }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_code_is_found_as_a_whole_word_and_fetch_only_as_a_call() {
        for text in [
            "fetch(url)",
            "x=fetch \n (url)",
            "new XMLHttpRequest",
            "a.sendBeacon(b)",
        ] {
            assert!(network_code(text).is_some(), "{text}");
        }
        for text in [
            "prefetch(url)",
            "fetched(url)",
            "fetch.call",
            "MyWebSocket",
            "EventSources",
        ] {
            assert!(network_code(text).is_none(), "{text}");
        }
    }

    #[test]
    fn each_argon2_loader_must_occur_exactly_once() {
        let both = format!("a;{};b;{};c", ARGON2_LOADERS[0].0, ARGON2_LOADERS[1].0);
        let stubbed = without_argon2_loaders(both.clone(), "x.js").ok();
        let expected = format!(
            "a;readBinary=url=>{{throw new Error(\"{EMBEDDED}\")}};b;\
             readAsync=async url=>{{throw new Error(\"{EMBEDDED}\")}};c"
        );
        assert_eq!(stubbed, Some(expected));
        assert!(network_code(&without_argon2_loaders(both.clone(), "x.js").unwrap()).is_none());
        let twice = format!("{both}{}", ARGON2_LOADERS[0].0);
        assert!(without_argon2_loaders(twice, "x.js").is_err());
        assert!(without_argon2_loaders(ARGON2_LOADERS[1].0.to_owned(), "x.js").is_err());
    }

    #[test]
    fn the_glue_loses_its_loaders_and_keeps_init_sync() {
        let glue = format!(
            "head\n{}\n        load\n    }}\n\n{}\n        sync\n    }}\n\n\
             {}\n        init\n    }}\n\n{}\n}}",
            GLUE_LOAD.0, GLUE_LOAD.1, GLUE_INIT.0, GLUE_INIT.1
        );
        let Ok(stripped) = without_glue_loader(&glue, "mhfe.js") else {
            panic!("the blocks are not found");
        };
        assert!(!stripped.contains("__wbg_load") && !stripped.contains("module_or_path"));
        assert!(stripped.contains(GLUE_LOAD.1) && stripped.contains("        sync\n"));
        assert!(stripped.contains("function __wbg_init() {\n        throw new Error("));
        assert!(without_glue_loader(&format!("{glue}\n{}", GLUE_LOAD.0), "mhfe.js").is_err());
    }
}
