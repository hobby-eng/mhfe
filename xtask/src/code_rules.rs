//! `cargo xtask code-rules`: the `code-rules` and `markdown` gates of the coding guide, for what
//! the compiler, Clippy and the formatters cannot see:
//!
//! - CORE-15: at most 800 lines of code in a file, comments, blank lines and a Rust file's
//!   `#[cfg(test)]` module left out; a file that reads best whole says `long: <reason>` on its
//!   first line.
//! - TOOL-02: a shell script starts with `#!/usr/bin/env bash` and `set -euo pipefail`; a launcher
//!   that must run on any system's `/bin/sh` says why on its second line, naming TOOL-02, and a
//!   file that scripts source says so on its first line.
//! - A reason on every lint exception: Rust's `allow` and `expect` carry `reason = "..."`.
//! - CORE-25: every Cargo requirement is an exact version, as this repository builds programs.
//!   Cargo.lock is the one lockfile (TOOL-05). RUST-01: every Cargo.toml has its lints table.
//! - TOOL-01: the repository's tools are `cargo xtask` tasks, so it holds no Node.js tooling
//!   (package.json, its lockfiles, .node-version) and no script outside the browser code, `web/`
//!   and the check pages in `xtask/pages/`, which run in the browsers (TS-13's exception). The
//!   Python it holds is `packaging/mhfe-fast-mode.py`, the launcher for a computer without mhfe.
//! - DOC-01, the `markdown` gate: no blank line inside a Markdown list. mhfe-core, the multi-chain
//!   wallet tools and MnemoCode check the same rule: a change goes to all four.
//!
//! The patterns are small matchers written by hand, so that the gate needs no crate; each names
//! the regular expression it stands for. It follows mhfe-core's `xtask/src/code_rules.rs`, adapted
//! to the browser code and the launchers of this repository.

use std::fs;
use std::path::Path;

use crate::{Failure, at};

/// Folders not read: Git's, the builds', the browser package built, the data files, the
/// specification's repository and the vendored tree, and the audit records, which are frozen.
const SKIPPED: [&str; 8] = [
    ".git",
    "canonical-output",
    "dist",
    "docs/audits",
    "target",
    "tests/fixtures",
    "tests/spec",
    "vendor/phc-winner-argon2",
];
const MOST_LINES: usize = 800;
/// The files whose lines of code CORE-15 counts: a file by its path from the root, or a folder by
/// its path with a final slash.
const COUNTED: [&str; 8] = [
    "src/",
    "tests/",
    "web/",
    "xtask/src/",
    "xtask/pages/",
    "scripts/",
    "packaging/",
    ".github/workflows/",
];

/// The comment syntax of a language whose lines of code CORE-15 counts.
#[derive(Clone, Copy, PartialEq)]
enum Comments {
    /// `//` and `/* */`.
    Slash,
    /// `#`.
    Hash,
}

/// The comment syntax of each file ending that CORE-15 counts.
const COMMENTS: [(&str, Comments); 6] = [
    (".rs", Comments::Slash),
    (".js", Comments::Slash),
    (".ts", Comments::Slash),
    (".sh", Comments::Hash),
    (".py", Comments::Hash),
    (".yml", Comments::Hash),
];
/// The first line and the first command of a shell script (TOOL-02), and the first line of a
/// launcher for any system's shell, whose second line says why.
const SHEBANG: &str = "#!/usr/bin/env bash";
const STRICT_MODE: &str = "set -euo pipefail";
const POSIX_SHEBANG: &str = "#!/bin/sh";
/// The lints tables of RUST-01.
const LINTS_TABLES: [&str; 2] = ["[lints.rust]", "[lints.clippy]"];
/// The files of Node.js tooling, which a Rust repository does not hold (TOOL-01).
const NODE_FILES: [&str; 7] = [
    "package.json",
    "pnpm-lock.yaml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    ".node-version",
    ".nvmrc",
];
/// The endings of Node.js scripts (TOOL-01), and the folders of browser code where `.js` and
/// `.ts` files are pages' scripts and their types instead.
const NODE_SCRIPTS: [&str; 4] = [".js", ".mjs", ".cjs", ".ts"];
const BROWSER_CODE: [&str; 2] = ["web/", "xtask/pages/"];
/// The indentation that continues a list item after a blank line, as `^\s{2,}\S` reads it.
const CONTINUATION_INDENT: usize = 2;

/// Runs the gate on the repository at `root`.
pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let files = files_under(root, "")?;
    let mut problems = Vec::new();
    for path in &files {
        check_file(path, &text_of(root, path)?, &mut problems);
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| at(root, error))? {
        let entry = entry.map_err(|error| at(root, error))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    check_root_files(&names, &mut problems);
    if problems.is_empty() {
        println!(
            "The rules of the coding guide hold in {} files.",
            files.len()
        );
        return Ok(());
    }
    let count = problems.len();
    problems.push(format!(
        "{count} problems with the rules of the coding guide."
    ));
    Err(Failure(problems.join("\n")))
}

/// Every file under `directory`, by its path from the root, the SKIPPED folders left out, each
/// folder in the order of its names.
fn files_under(root: &Path, directory: &str) -> Result<Vec<String>, Failure> {
    let mut entries = Vec::new();
    let folder = root.join(directory);
    for entry in fs::read_dir(&folder).map_err(|error| at(&folder, error))? {
        let entry = entry.map_err(|error| at(&folder, error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry.file_type().map_err(|error| at(&folder, error))?;
        entries.push((name, kind.is_dir()));
    }
    entries.sort();
    let mut files = Vec::new();
    for (name, is_folder) in entries {
        let path = if directory.is_empty() {
            name
        } else {
            format!("{directory}/{name}")
        };
        if SKIPPED.contains(&path.as_str()) {
            continue;
        }
        if is_folder {
            files.extend(files_under(root, &path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

/// The text of the file at `path` from the root, any bytes that are not UTF-8 replaced.
fn text_of(root: &Path, path: &str) -> Result<String, Failure> {
    let bytes = fs::read(root.join(path)).map_err(|error| Failure(format!("{path}: {error}")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Every rule that reads one file, by its path from the root.
fn check_file(path: &str, text: &str, problems: &mut Vec<String>) {
    let ending = path.rfind('.').map_or("", |dot| &path[dot..]);
    let syntax = COMMENTS.iter().find(|(known, _)| *known == ending);
    if let Some((_, syntax)) = syntax
        && is_counted(path)
    {
        check_length(path, text, *syntax, problems);
    }
    if ending == ".sh" || ending == ".command" {
        check_shell_header(path, text, problems);
        for line in unquoted_expansions(text) {
            problems.push(format!(
                "{path}:{line}: an expansion without quotes (TOOL-02)"
            ));
        }
    }
    if ending == ".py" {
        check_python(path, text, problems);
    }
    let browser_code = BROWSER_CODE.iter().any(|folder| path.starts_with(folder));
    if NODE_SCRIPTS.contains(&ending) && !browser_code {
        problems.push(format!(
            "{path}: a Node.js script; the tools are `cargo xtask` tasks (TOOL-01)"
        ));
    }
    if ending == ".rs" {
        check_lint_reasons(path, text, problems);
    }
    if ending == ".md" {
        for line in loose_list_lines(text) {
            problems.push(format!(
                "{path}:{line}: a blank line inside a list, which GitHub renders loose (DOC-01)"
            ));
        }
    }
    if path == "Cargo.toml" || path.ends_with("/Cargo.toml") {
        check_cargo_requirements(path, text, problems);
        check_lints_tables(path, text, problems);
    }
}

/// Whether CORE-15 counts the lines of the file at `path`.
fn is_counted(path: &str) -> bool {
    COUNTED.iter().any(|place| {
        if place.ends_with('/') {
            path.starts_with(*place)
        } else {
            path == *place
        }
    })
}

/// CORE-15 for one file.
fn check_length(path: &str, text: &str, syntax: Comments, problems: &mut Vec<String>) {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.first().is_some_and(|first| first.contains("long: ")) {
        return;
    }
    // The unit tests at the end of a Rust file (RUST-08).
    let tests = lines
        .windows(2)
        .position(|pair| pair == ["#[cfg(test)]", "mod tests {"]);
    if let Some(tests) = tests
        && path.ends_with(".rs")
    {
        lines.truncate(tests);
    }
    let count = lines_of_code(&lines, syntax);
    if count > MOST_LINES {
        problems.push(format!(
            "{path}: {count} lines of code, more than {MOST_LINES} (CORE-15)"
        ));
    }
}

/// How many of `lines` hold code: comment and blank lines left out, by the comment syntax.
fn lines_of_code(lines: &[&str], syntax: Comments) -> usize {
    let mut in_block = false;
    let mut count = 0;
    for line in lines {
        let mut code = line.trim();
        if syntax == Comments::Hash {
            count += usize::from(!code.is_empty() && !code.starts_with('#'));
            continue;
        }
        if in_block {
            let Some((_, after)) = code.split_once("*/") else {
                continue;
            };
            in_block = false;
            code = after.trim();
        }
        if code.starts_with("/*") {
            // The end is looked for from the opening slash on, so `/*/` opens and closes.
            match code.split_once("*/") {
                Some((_, after)) => code = after.trim(),
                None => {
                    in_block = true;
                    code = "";
                }
            }
        }
        count += usize::from(!code.is_empty() && !code.starts_with("//"));
    }
    count
}

/// TOOL-02 for one shell script.
fn check_shell_header(path: &str, text: &str, problems: &mut Vec<String>) {
    let mut lines = text.split('\n');
    let shebang = lines.next();
    // A file sourced by scripts that have the header, which says so first, and a launcher for any
    // system's shell, with its reason on the next line.
    if shebang.is_some_and(|first| first.starts_with("# Sourced, not run")) {
        return;
    }
    let reason = text
        .split('\n')
        .nth(1)
        .is_some_and(|line| line.starts_with('#') && line.contains("TOOL-02"));
    if shebang == Some(POSIX_SHEBANG) && reason {
        return;
    }
    let command = lines.find(|line| !line.trim().is_empty() && !line.trim().starts_with('#'));
    if shebang != Some(SHEBANG) || command != Some(STRICT_MODE) {
        problems.push(format!(
            "{path}: does not start with {SHEBANG} and {STRICT_MODE} (TOOL-02)"
        ));
    }
}

/// TOOL-02's quotes: the 1-based numbers of the lines of a shell script where a `$` expansion
/// stands outside double quotes. Single quotes, comments and escaped characters are skipped, and
/// a command substitution starts a quoting of its own, as the shell reads `"$(dirname "$0")"`.
fn unquoted_expansions(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    // Whether each open command substitution, the script itself first, is inside double quotes.
    let mut quoted = vec![false];
    let (mut single, mut line, mut at) = (false, 1, 0);
    while at < bytes.len() {
        let byte = bytes[at];
        let in_double = quoted.last().copied().unwrap_or(false);
        let next = bytes.get(at + 1).copied();
        match byte {
            b'\n' => line += 1,
            b'\'' if single => single = false,
            _ if single => {}
            b'\\' => {
                line += usize::from(next == Some(b'\n'));
                at += 1;
            }
            b'\'' if !in_double => single = true,
            b'"' => {
                if let Some(state) = quoted.last_mut() {
                    *state = !*state;
                }
            }
            b'#' if !in_double && (at == 0 || b" \t\n;(".contains(&bytes[at - 1])) => {
                while at + 1 < bytes.len() && bytes[at + 1] != b'\n' {
                    at += 1;
                }
            }
            b'$' if next == Some(b'(') => {
                if !in_double {
                    found.push(line);
                }
                quoted.push(false);
                at += 1;
            }
            b'$' if next.is_some_and(|next| {
                next.is_ascii_alphanumeric() || b"{_@*#?!-".contains(&next)
            }) =>
            {
                if !in_double {
                    found.push(line);
                }
            }
            b')' if quoted.len() > 1 && !in_double => {
                quoted.pop();
            }
            _ => {}
        }
        at += 1;
    }
    found.dedup();
    found
}

/// The one Python script of the repository, the launcher for a computer without mhfe (TOOL-01),
/// and the standard library modules it may import (TOOL-03): a new import is reviewed here first.
const PYTHON_SCRIPTS: [&str; 1] = ["packaging/mhfe-fast-mode.py"];
const PYTHON_STANDARD_MODULES: [&str; 9] = [
    "argparse",
    "hashlib",
    "os",
    "socket",
    "sys",
    "threading",
    "time",
    "unicodedata",
    "webbrowser",
];

/// TOOL-01 and TOOL-03 for one Python file.
fn check_python(path: &str, text: &str, problems: &mut Vec<String>) {
    if !PYTHON_SCRIPTS.contains(&path) {
        problems.push(format!(
            "{path}: Python outside the launcher; the tools are `cargo xtask` tasks (TOOL-01)"
        ));
        return;
    }
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let module = match words.as_slice() {
            ["import", module, ..] | ["from", module, "import", ..] => *module,
            _ => continue,
        };
        let top = module
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(',');
        if !PYTHON_STANDARD_MODULES.contains(&top) {
            problems.push(format!(
                "{path}: imports {top}, which is not among the standard modules it may use (TOOL-03)"
            ));
        }
    }
}

/// A reason on every lint exception of one Rust file.
fn check_lint_reasons(path: &str, text: &str, problems: &mut Vec<String>) {
    for attribute in rust_attributes(text) {
        let exception = word_then(attribute, "allow", '(') || word_then(attribute, "expect", '(');
        if exception && !word_then(attribute, "reason", '=') {
            let attribute = attribute.split_whitespace().collect::<Vec<_>>().join(" ");
            problems.push(format!("{path}: {attribute} has no reason"));
        }
    }
}

/// The Rust attributes of `text`, outer or inner, with at most one level of brackets inside:
/// `#!?\[(?:[^[\]]|\[[^[\]]*\])*\]`, found from left to right without overlapping.
fn rust_attributes(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut resume = 0;
    for (at, _) in text.match_indices('#') {
        if at < resume {
            continue;
        }
        let open = at + 1 + usize::from(bytes.get(at + 1) == Some(&b'!'));
        if bytes.get(open) == Some(&b'[')
            && let Some(close) = closing_bracket(bytes, open + 1)
        {
            found.push(&text[at..=close]);
            resume = close + 1;
        }
    }
    found
}

/// Where the bracket opened just before `from` closes, or None when a bracket nested twice or the
/// end of the text comes first.
fn closing_bracket(bytes: &[u8], from: usize) -> Option<usize> {
    let mut nested = false;
    for (at, byte) in bytes.iter().enumerate().skip(from) {
        match (byte, nested) {
            (b']', false) => return Some(at),
            (b']', true) => nested = false,
            (b'[', false) => nested = true,
            (b'[', true) => return None,
            _ => {}
        }
    }
    None
}

/// Whether `word` stands in `text` at the start of a word, followed after any white space by
/// `next`: `\bword\s*next`.
fn word_then(text: &str, word: &str, next: char) -> bool {
    text.match_indices(word).any(|(at, _)| {
        starts_word(text.as_bytes(), at) && text[at + word.len()..].trim_start().starts_with(next)
    })
}

/// Whether a regular expression's `\b` holds before `at`, where a word character stands.
fn starts_word(bytes: &[u8], at: usize) -> bool {
    at.checked_sub(1)
        .and_then(|before| bytes.get(before))
        .is_none_or(|byte| !is_word(*byte))
}

/// A character of `\w`, which is ASCII in a JavaScript regular expression.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// DOC-01: the 1-based numbers of the blank lines that make a list of `text` loose.
fn loose_list_lines(text: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut in_fence = false;
    let mut in_list = false;
    let mut blank_in_list = false;
    // The 0-based index of a line is the 1-based number of the blank line just above it.
    for (index, line) in text.split('\n').enumerate() {
        if is_fence(line) {
            // A fence at the left margin belongs to no list item, so it ends the list; an indented
            // one after a blank line is a second block of the item.
            if !in_fence && !line.starts_with(char::is_whitespace) {
                in_list = false;
            } else if !in_fence && blank_in_list {
                found.push(index);
            }
            in_fence = !in_fence;
            blank_in_list = false;
        } else if in_fence {
            continue;
        } else if line.trim().is_empty() {
            blank_in_list = in_list;
        } else if is_list_item(line) || (blank_in_list && is_continuation(line)) {
            if blank_in_list {
                found.push(index);
            }
            in_list = true;
            blank_in_list = false;
        } else {
            if blank_in_list || line.starts_with('#') {
                in_list = false;
            }
            blank_in_list = false;
        }
    }
    found
}

/// `^\s*(?:```|~~~)`: a line that opens or closes a fenced block.
fn is_fence(line: &str) -> bool {
    let code = line.trim_start();
    code.starts_with("```") || code.starts_with("~~~")
}

/// `^\s*(?:[-*+]|\d+[.)])\s`: a bullet, or a number with its dot or parenthesis, then a space.
fn is_list_item(line: &str) -> bool {
    let item = line.trim_start();
    let after_number = item.trim_start_matches(|character: char| character.is_ascii_digit());
    let after_marker = if after_number.len() < item.len() {
        after_number.strip_prefix(['.', ')'])
    } else {
        item.strip_prefix(['-', '*', '+'])
    };
    after_marker.is_some_and(|after| after.starts_with(char::is_whitespace))
}

/// `^\s{2,}\S`: an indented line that continues a list item.
fn is_continuation(line: &str) -> bool {
    let indent = line
        .chars()
        .take_while(|character| character.is_whitespace())
        .count();
    indent >= CONTINUATION_INDENT && !line.trim_start().is_empty()
}

/// CORE-25 for one Cargo.toml at `path`: every requirement an exact version.
fn check_cargo_requirements(path: &str, manifest: &str, problems: &mut Vec<String>) {
    let mut in_dependencies = false;
    for line in manifest.split('\n') {
        if line.starts_with('[') {
            in_dependencies = line.ends_with("dependencies]");
        }
        let Some((name, requirement)) = cargo_dependency(line) else {
            continue;
        };
        if in_dependencies && !is_exact(requirement) {
            problems.push(format!(
                "{path}: {name} = \"{requirement}\" is not an exact version (CORE-25)"
            ));
        }
    }
}

/// A full exact Cargo comparator, including a prerelease or build suffix when present.
fn is_exact(requirement: &str) -> bool {
    let Some(version) = requirement.strip_prefix('=') else {
        return false;
    };
    let core = version.split(['-', '+']).next().unwrap_or_default();
    version_numbers(core) == Some(3)
}

/// A dependency line of Cargo.toml: its name, and its version alone or in an inline table, as
/// `^([\w-]+)\s*=\s*(?:"([^"]*)"|\{.*?\bversion\s*=\s*"([^"]*)")` reads it.
fn cargo_dependency(line: &str) -> Option<(&str, &str)> {
    let name_length = line
        .find(|character: char| !(character.is_ascii_alphanumeric() || "_-".contains(character)))
        .unwrap_or(line.len());
    let (name, rest) = line.split_at(name_length);
    if name.is_empty() {
        return None;
    }
    let value = rest.trim_start().strip_prefix('=')?.trim_start();
    if let Some(quoted) = value.strip_prefix('"') {
        return quoted.split_once('"').map(|(version, _)| (name, version));
    }
    let table = value.strip_prefix('{')?;
    table.match_indices("version").find_map(|(at, word)| {
        if !starts_word(table.as_bytes(), at) {
            return None;
        }
        let quoted = table[at + word.len()..].trim_start().strip_prefix('=')?;
        let (version, _) = quoted.trim_start().strip_prefix('"')?.split_once('"')?;
        Some((name, version))
    })
}

/// RUST-01 for one Cargo.toml.
fn check_lints_tables(path: &str, manifest: &str, problems: &mut Vec<String>) {
    for table in LINTS_TABLES {
        if !manifest.contains(&format!("\n{table}\n")) {
            problems.push(format!("{path} has no {table} (RUST-01)"));
        }
    }
}

/// How many numbers `version` holds, joined by dots, or None when it holds anything else.
fn version_numbers(version: &str) -> Option<usize> {
    let numbers: Vec<&str> = version.split('.').collect();
    let digits = |number: &&str| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
    numbers.iter().all(digits).then_some(numbers.len())
}

/// TOOL-01 and TOOL-05 for the files at the repository's root, `names`: Cargo.lock is the one
/// lockfile, and a Rust repository holds no Node.js tooling.
fn check_root_files(names: &[String], problems: &mut Vec<String>) {
    if !names.iter().any(|name| name == "Cargo.lock") {
        problems.push("Cargo.lock is missing".to_owned());
    }
    for name in names {
        if NODE_FILES.contains(&name.as_str()) {
            problems.push(format!(
                "{name}: a Rust repository has no Node.js tooling (TOOL-01)"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The problems that the rules of one file find in `text` at `path`.
    fn problems_of(path: &str, text: &str) -> Vec<String> {
        let mut problems = Vec::new();
        check_file(path, text, &mut problems);
        problems
    }

    /// `count` lines of Rust code.
    fn rust_lines(count: usize) -> String {
        "let x = 1;\n".repeat(count)
    }

    #[test]
    fn a_file_over_800_lines_of_code_is_refused_and_one_of_800_passes() {
        assert_eq!(
            problems_of("src/long.rs", &rust_lines(801)),
            ["src/long.rs: 801 lines of code, more than 800 (CORE-15)"]
        );
        assert!(problems_of("src/long.rs", &rust_lines(800)).is_empty());
    }

    #[test]
    fn comments_blank_lines_and_the_test_module_are_not_counted() {
        let commented = rust_lines(800) + "// a\n\n/* b\n c */\n/// d\n";
        let with_tests = rust_lines(800) + "#[cfg(test)]\nmod tests {\n" + &rust_lines(10) + "}\n";
        assert!(problems_of("src/a.rs", &commented).is_empty());
        assert!(problems_of("src/a.rs", &with_tests).is_empty());
        // Outside Rust the test module is code like any other.
        assert_eq!(problems_of(".github/workflows/a.yml", &with_tests).len(), 1);
    }

    #[test]
    fn code_after_a_block_comment_counts_and_code_inside_it_does_not() {
        let lines = [
            "/* a",
            "let b = 1;",
            "*/ let c = 2;",
            "/* d */ let e = 3;",
            "/*/ let f;",
        ];
        assert_eq!(lines_of_code(&lines, Comments::Slash), 3);
        assert_eq!(
            lines_of_code(&["# a", "", "b: 1", "  # c"], Comments::Hash),
            1
        );
    }

    #[test]
    fn a_long_reason_on_the_first_line_lifts_the_limit() {
        let text = "// long: one table of every case\n".to_owned() + &rust_lines(801);
        assert!(problems_of("src/table.rs", &text).is_empty());
    }

    #[test]
    fn the_counted_folders_and_endings_alone_are_counted() {
        let yaml = "a: 1\n".repeat(801);
        assert_eq!(problems_of("xtask/src/gate.rs", &rust_lines(801)).len(), 1);
        assert_eq!(problems_of(".github/workflows/ci.yml", &yaml).len(), 1);
        assert_eq!(problems_of("web/client.js", &rust_lines(801)).len(), 1);
        assert!(problems_of("docs/example.rs", &rust_lines(801)).is_empty());
        assert!(problems_of("src/table.txt", &rust_lines(801)).is_empty());
    }

    #[test]
    fn a_shell_script_without_its_header_is_refused() {
        let refused = "tests/run.sh: does not start with #!/usr/bin/env bash and set -euo \
                       pipefail (TOOL-02)";
        assert_eq!(
            problems_of("tests/run.sh", "#!/bin/sh\nset -euo pipefail\n"),
            [refused]
        );
        assert_eq!(
            problems_of("tests/run.sh", "#!/usr/bin/env bash\nset -eu\n"),
            [refused]
        );
        assert_eq!(
            problems_of("tests/run.sh", "#!/usr/bin/env bash\n"),
            [refused]
        );
        let header = "#!/usr/bin/env bash\n# Why it runs.\n\nset -euo pipefail\necho\n";
        assert!(problems_of("tests/run.sh", header).is_empty());
    }

    #[test]
    fn a_lint_exception_without_a_reason_is_refused() {
        // Planted through `concat!`, so that this file holds no such attribute itself.
        let text = concat!(
            "#",
            "[allow(dead_code)]\nfn a() {}\n#",
            "![expect(\n  unused,\n)]\n"
        );
        assert_eq!(
            problems_of("src/a.rs", text),
            [
                concat!("src/a.rs: #", "[allow(dead_code)] has no reason"),
                concat!("src/a.rs: #", "![expect( unused, )] has no reason"),
            ]
        );
        let nested = concat!("#", "[cfg_attr(test, allow(clippy::panic))]");
        assert_eq!(problems_of("tests/a.rs", nested).len(), 1);
    }

    #[test]
    fn a_lint_exception_with_a_reason_and_other_attributes_pass() {
        let text = "#[expect(clippy::expect_used, reason = \"the value is ours\")]\n\
                    #[derive(Debug)]\n#[doc = \"disallow (x) [y]\"]\nlet a = b[0]; // #[x]\n";
        assert!(problems_of("src/a.rs", text).is_empty());
        // Brackets nested twice end no attribute, as the regular expression read them.
        assert!(rust_attributes("#[a[b[c]]]").is_empty());
        assert_eq!(rust_attributes("x #[a[b]] #![c]"), ["#[a[b]]", "#![c]"]);
    }

    #[test]
    fn a_blank_line_inside_a_list_is_refused_with_its_number() {
        let text =
            "Text.\n\n- one\n\n- two\n  more\n\n  again\n1. three\n\n   ```\n   code\n   ```\n";
        assert_eq!(loose_list_lines(text), [4, 7, 10]);
        assert_eq!(
            problems_of("docs/a.md", "- a\n\n- b\n"),
            ["docs/a.md:2: a blank line inside a list, which GitHub renders loose (DOC-01)"]
        );
    }

    #[test]
    fn tight_lists_fences_headings_and_paragraphs_end_lists_without_a_problem() {
        let text = "- a\n- b\n\nText.\n\n- c\n```\n\n- d\n```\n\n- e\n# Title\n\n- f\n\nAfter.\n";
        assert!(loose_list_lines(text).is_empty());
        assert!(loose_list_lines("-x\n\n- y\n\n2.z\n").is_empty());
    }

    #[test]
    fn private_tools_require_full_exact_versions_without_library_exceptions() {
        for version in [
            "0.11",
            "^0.11.1",
            "=0.11",
            "=0.11.*",
            ">=0.11.1",
            ">=0.1.26, <0.1.27",
        ] {
            let manifest = format!("[dependencies]\nunicode-normalization = \"{version}\"\n");
            let mut problems = Vec::new();
            check_cargo_requirements("xtask/Cargo.toml", &manifest, &mut problems);
            assert_eq!(problems.len(), 1, "{version}");
        }
        for version in ["=0.11.1", "=1.2.3-rc.1", "=1.2.3+build"] {
            let manifest = format!("[dependencies]\na = \"{version}\"\n");
            let mut problems = Vec::new();
            check_cargo_requirements("xtask/Cargo.toml", &manifest, &mut problems);
            assert!(problems.is_empty(), "{version}");
        }
    }

    #[test]
    fn a_cargo_toml_without_its_lints_tables_is_refused() {
        let text = "[package]\nname = \"xtask\"\n\n[lints.clippy]\nall = \"deny\"\n";
        let refused = "xtask/Cargo.toml has no [lints.rust] (RUST-01)";
        assert_eq!(problems_of("xtask/Cargo.toml", text), [refused]);
        assert!(problems_of("Cargo.toml", "[package]\n[lints.rust]\n[lints.clippy]\n").is_empty());
    }

    #[test]
    fn node_tooling_and_a_missing_cargo_lock_are_refused() {
        let names = |list: &[&str]| {
            list.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let mut problems = Vec::new();
        check_root_files(
            &names(&["Cargo.lock", "Cargo.toml", "dprint.json"]),
            &mut problems,
        );
        assert!(problems.is_empty());
        check_root_files(
            &names(&["package.json", "pnpm-lock.yaml", ".node-version"]),
            &mut problems,
        );
        assert_eq!(
            problems,
            [
                "Cargo.lock is missing",
                "package.json: a Rust repository has no Node.js tooling (TOOL-01)",
                "pnpm-lock.yaml: a Rust repository has no Node.js tooling (TOOL-01)",
                ".node-version: a Rust repository has no Node.js tooling (TOOL-01)",
            ]
        );
    }

    #[test]
    fn a_node_script_is_refused() {
        assert_eq!(
            problems_of("tools/a.mjs", ""),
            ["tools/a.mjs: a Node.js script; the tools are `cargo xtask` tasks (TOOL-01)"]
        );
        assert!(problems_of("src/a.rs", "").is_empty());
    }

    #[test]
    fn the_walk_reads_the_repository_and_leaves_the_skipped_folders_out() {
        let files = files_under(&crate::root(), "").unwrap();
        assert!(files.iter().any(|path| path == "xtask/src/code_rules.rs"));
        assert!(files.iter().any(|path| path == "Cargo.toml"));
        for path in &files {
            let skipped = SKIPPED
                .iter()
                .any(|folder| path.starts_with(&format!("{folder}/")));
            assert!(!skipped, "{path}");
        }
    }

    #[test]
    fn a_launcher_for_any_shell_says_why_on_its_second_line() {
        let reason =
            "#!/bin/sh\n# POSIX sh, which any system has, so no pipefail of TOOL-02.\nexec a\n";
        assert!(problems_of("packaging/mhfe-launch.sh", reason).is_empty());
        assert!(problems_of("packaging/mhfe-launch.command", reason).is_empty());
        assert_eq!(
            problems_of("packaging/mhfe-launch.sh", "#!/bin/sh\nexec a\n").len(),
            1
        );
    }

    #[test]
    fn every_cargo_requirement_is_an_exact_version() {
        let manifest = "[dependencies]\na = \"=1.2.3\"\nb = { version = \"~1\" }\nc = \"1.2\"\n\
                        d = { git = \"https://example.org/d\", rev = \"0a\" }\n";
        let mut problems = Vec::new();
        check_cargo_requirements("Cargo.toml", manifest, &mut problems);
        assert_eq!(
            problems,
            [
                "Cargo.toml: b = \"~1\" is not an exact version (CORE-25)",
                "Cargo.toml: c = \"1.2\" is not an exact version (CORE-25)",
            ]
        );
    }

    #[test]
    fn scripts_of_the_browser_code_are_no_node_scripts() {
        assert!(problems_of("web/client.js", "").is_empty());
        assert!(problems_of("xtask/pages/checks/menu.js", "").is_empty());
        assert_eq!(problems_of("scripts/a.js", "").len(), 1);
    }

    #[test]
    fn an_expansion_outside_double_quotes_is_refused_with_its_line() {
        let script = "#!/usr/bin/env bash\nset -euo pipefail\nroot=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
                      echo '$not' \\\n  \"$a\"\nif [[ $# -eq 0 ]]; then # $comment\n  echo $b\nfi\n";
        assert_eq!(unquoted_expansions(script), [6, 7]);
    }

    #[test]
    fn python_is_the_launcher_alone_with_standard_modules() {
        assert_eq!(problems_of("scripts/a.py", "import os\n").len(), 1);
        assert!(
            problems_of(
                "packaging/mhfe-fast-mode.py",
                "import os\nfrom hashlib import sha256\n"
            )
            .is_empty()
        );
        assert_eq!(
            problems_of("packaging/mhfe-fast-mode.py", "import requests\n").len(),
            1
        );
    }
}
