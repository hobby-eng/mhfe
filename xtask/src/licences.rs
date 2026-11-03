//! `cargo xtask licences [--check | --archives <archive>...]`: writes the Rust crates part of
//! `THIRD_PARTY_NOTICES.md`, the licence of every crate a release ships; with `--check` it writes
//! nothing and fails when the committed file is out of date; with `--archives` it fails unless
//! each release archive, a `.zip` or a `.tar.gz`, carries `LICENSE` and `THIRD_PARTY_NOTICES.md`
//! byte for byte as in this checkout.
//!
//! The crates are the union of `cargo tree --locked --offline -e normal,no-proc-macro` over every
//! release target and feature set ([`TREES`]). Build scripts, build dependencies and proc macros
//! run only on the build machine, so they are left out. The licence texts come from the crates'
//! sources in the local Cargo registry, as `cargo metadata` finds them; nothing is downloaded. Run
//! `cargo fetch --locked` first on a machine whose registry lacks the sources of some target.
//!
//! How the licence of a crate is chosen, the same for every crate:
//! - The licence expression is read from the crate's Cargo.toml. "A/B" is the old way of writing
//!   "A OR B".
//! - Every part joined by AND is required, so each gets its own text, for example Unicode-3.0
//!   next to MIT for unicode-ident.
//! - Within a part with alternatives joined by OR, MIT is used when it is offered, otherwise
//!   Apache-2.0, otherwise the only licence. Any other choice stops the task.
//! - The text is the crate's own licence file for that licence, copied unchanged, with its
//!   copyright lines. Line endings become LF, and blank lines and spaces at the end are dropped.
//! - A crate that publishes no licence file gets the standard text of its licence instead: for
//!   MIT, the SPDX text with the copyright holders taken from the crate's `authors`; for CC0-1.0,
//!   the CC0 1.0 legal code as another crate in the list ships it. Its entry says so. A licence
//!   without such a rule stops the task.
//!
//! Crates with byte-identical texts share one text section, so no copyright line is ever dropped.
//! The archives are read with the system's `tar` and `unzip`.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::{Failure, at, wasm};

const OUTPUT: &str = "THIRD_PARTY_NOTICES.md";
/// The written notices for material that is not a crate come first, by hand; everything from
/// this line on is generated. The line is HTML, so it does not show where the file is rendered.
const MARKER: &str = "<!-- Everything below is written by `cargo xtask licences` from Cargo.lock \
                      and the crates' own licence files; do not edit it by hand. -->";
const OWN_PACKAGE: &str = "mhfe-experimental";

/// Every target a release is built for (packaging/Dockerfile.reproducible and
/// .github/workflows/release.yml), with its features. The browser package is the wasm32 build with
/// `wasm`.
const TREES: [(&str, &str); 6] = [
    ("x86_64-unknown-linux-gnu", ""),
    ("aarch64-unknown-linux-gnu", ""),
    ("x86_64-pc-windows-gnu", ""),
    ("x86_64-apple-darwin", ""),
    ("aarch64-apple-darwin", ""),
    ("wasm32-unknown-unknown", "wasm"),
];

/// The order in which an alternative of an OR is chosen.
const PREFERRED_LICENCES: [&str; 2] = ["MIT", "Apache-2.0"];

/// Licence file names to look for, per licence, before the generic names.
const LICENCE_FILE_NAMES: [(&str, &[&str]); 4] = [
    (
        "MIT",
        &[
            "LICENSE-MIT",
            "LICENSE-MIT.md",
            "LICENSE-MIT.txt",
            "license-mit",
            "LICENSE.MIT",
        ],
    ),
    (
        "Apache-2.0",
        &[
            "LICENSE-APACHE",
            "LICENSE-APACHE.md",
            "LICENSE-APACHE.txt",
            "license-apache-2.0",
            "LICENSE-APACHE-2.0",
        ],
    ),
    ("Unicode-3.0", &["LICENSE-UNICODE"]),
    ("Zlib", &["LICENSE-ZLIB", "LICENSE-ZLIB.md"]),
];
const GENERIC_FILE_NAMES: [&str; 5] =
    ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"];

/// A phrase every text of the licence contains. A file is used for a licence only when it
/// contains the phrase, so that a file of another licence is never copied by mistake.
const LICENCE_MARKERS: [(&str, &str); 6] = [
    ("MIT", "Permission is hereby granted, free of charge"),
    ("Apache-2.0", "Apache License"),
    (
        "BSD-3-Clause",
        "Redistribution and use in source and binary forms",
    ),
    ("CC0-1.0", "CC0 1.0 Universal"),
    ("Unicode-3.0", "UNICODE LICENSE V3"),
    (
        "Zlib",
        "This notice may not be removed or altered from any source distribution",
    ),
];

/// The SPDX text of the MIT licence (https://spdx.org/licenses/MIT.html) with the year left out,
/// as for example tokio's LICENSE writes it. `{holders}` is filled from the crate's `authors`.
const SPDX_MIT_TEXT: &str = "MIT License

Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.";

const NO_FILE_MIT: &str = "The crate publishes no licence file. This is the standard SPDX MIT \
                           text with the copyright holders taken from the crate's `authors`.";
const NO_FILE_CC0: &str = "The crate publishes no licence file. This is the CC0 1.0 legal code \
                           as other crates in this list ship it.";

/// A licence a crate is used under: its name, its text (`None` until a crate that ships it is
/// found) and the note of an entry whose text is not the crate's own.
struct Licence {
    name: String,
    text: Option<String>,
    note: Option<&'static str>,
}

/// A crate with its licence expression and the licences it needs.
struct Crate {
    name: String,
    version: String,
    expression: String,
    licences: Vec<Licence>,
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    match arguments {
        [flag, archives @ ..] if flag == "--archives" && !archives.is_empty() => {
            check_archives(root, archives)
        }
        [] => write(root, false),
        [flag] if flag == "--check" => write(root, true),
        _ => Err(Failure(
            "usage: cargo xtask licences [--check | --archives <archive>...]".to_owned(),
        )),
    }
}

fn write(root: &Path, check: bool) -> Result<(), Failure> {
    let crates = resolve(&shipped_crates(root)?, &registry_packages(root)?).map_err(|why| {
        Failure(format!(
            "Cannot determine a licence text: {why}. Nothing was written."
        ))
    })?;
    let output = root.join(OUTPUT);
    let written = wasm::text(&output)?;
    let Some(start) = written.find(MARKER) else {
        return Err(Failure(format!(
            "{OUTPUT} lacks the line that starts the generated part:\n{MARKER}"
        )));
    };
    let content = format!("{}{}", &written[..start], render(&crates));
    if !check {
        wasm::write(&output, &content)?;
        println!("Wrote {OUTPUT}.");
        return Ok(());
    }
    if written != content {
        return Err(Failure(format!(
            "{OUTPUT} is out of date; run cargo xtask licences."
        )));
    }
    println!("{OUTPUT} matches the shipped crates.");
    Ok(())
}

/// The output of `cargo` with `arguments`, run at the root without colour.
fn cargo(root: &Path, arguments: &[&str]) -> Result<String, Failure> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(arguments)
        .current_dir(root)
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|error| Failure(format!("cargo did not start: {error}")))?;
    if !output.status.success() {
        return Err(Failure(format!(
            "cargo {} failed:\n{}Run `cargo fetch --locked` so that the registry holds the \
             sources of every target.",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| Failure(format!("cargo's output: {error}")))
}

/// (name, version) of every crate compiled into a release, without this package.
fn shipped_crates(root: &Path) -> Result<BTreeSet<(String, String)>, Failure> {
    let mut crates = BTreeSet::new();
    for (target, features) in TREES {
        let mut arguments = vec![
            "tree",
            "--locked",
            "--offline",
            "-e",
            "normal,no-proc-macro",
        ];
        arguments.extend(["--target", target, "--prefix", "none", "--format", "{p}"]);
        if !features.is_empty() {
            arguments.extend(["--features", features]);
        }
        for line in cargo(root, &arguments)?.lines() {
            // "name vX.Y.Z", followed by " (*)" for a repeat or by the path of a local package.
            let mut words = line.split_whitespace();
            let (Some(name), Some(version)) = (words.next(), words.next()) else {
                continue;
            };
            if let Some(version) = version.strip_prefix('v')
                && name != OWN_PACKAGE
            {
                crates.insert((name.to_owned(), version.to_owned()));
            }
        }
    }
    Ok(crates)
}

/// Metadata of every package in Cargo.lock, by (name, version). With every feature, so that the
/// optional dependencies of the `wasm` feature are among them.
fn registry_packages(root: &Path) -> Result<HashMap<(String, String), Value>, Failure> {
    let arguments = [
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version",
        "1",
    ];
    let metadata: Value = serde_json::from_str(&cargo(root, &arguments)?)
        .map_err(|error| Failure(format!("cargo metadata: {error}")))?;
    let packages = metadata["packages"].as_array().cloned().unwrap_or_default();
    Ok(packages
        .into_iter()
        .map(|package| {
            let key = (
                package["name"].as_str().unwrap_or_default().to_owned(),
                package["version"].as_str().unwrap_or_default().to_owned(),
            );
            (key, package)
        })
        .collect())
}

/// The parts joined by AND, each a list of the alternatives joined by OR.
fn licence_parts(expression: &str) -> Result<Vec<Vec<String>>, String> {
    let words: Vec<String> = expression
        .replace('/', " OR ")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let mut parts = Vec::new();
    for part in words.split(|word| word == "AND") {
        let joined = part.join(" ");
        let inner = joined
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or(&joined);
        let alternatives: Vec<String> = inner
            .split(" OR ")
            .map(|name| name.trim().to_owned())
            .collect();
        let plain = |name: &String| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|char| char.is_ascii_alphanumeric() || ".+-".contains(char))
        };
        if !alternatives.iter().all(plain) {
            return Err(format!(
                "licence expression {expression:?} is not a plain AND of ORs"
            ));
        }
        parts.push(alternatives);
    }
    Ok(parts)
}

fn choose(alternatives: &[String]) -> Result<String, String> {
    if let Some(preferred) = PREFERRED_LICENCES
        .iter()
        .find(|preferred| alternatives.iter().any(|name| name == *preferred))
    {
        return Ok((*preferred).to_owned());
    }
    match alternatives {
        [only] => Ok(only.clone()),
        _ => Err(format!(
            "no rule chooses between {}",
            alternatives.join(" OR ")
        )),
    }
}

fn read_text(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    Some(text.replace("\r\n", "\n").trim_end().to_owned())
}

/// The text of the crate's own file for `licence`, or `None` if it ships none.
fn licence_file_text(directory: &Path, licence: &str) -> Result<Option<String>, String> {
    let Some((_, marker)) = LICENCE_MARKERS.iter().find(|(name, _)| *name == licence) else {
        return Err(format!("no marker phrase is known for {licence}"));
    };
    let own: &[&str] = LICENCE_FILE_NAMES
        .iter()
        .find(|(name, _)| *name == licence)
        .map_or(&[], |(_, names)| *names);
    let found = own
        .iter()
        .chain(&GENERIC_FILE_NAMES)
        .map(|name| directory.join(name))
        .filter(|path| path.is_file())
        .filter_map(|path| read_text(&path))
        .find(|text| text.contains(marker));
    Ok(found)
}

/// The names in the crate's `authors`, without their e-mail addresses.
fn holders(package: &Value) -> Result<String, String> {
    let names: Vec<String> = package["authors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(without_addresses)
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        return Err(format!(
            "{} ships no MIT text and names no authors",
            package["name"].as_str().unwrap_or_default()
        ));
    }
    Ok(names.join(", "))
}

/// `author` without each "<…>" and the spaces before it.
fn without_addresses(author: &str) -> String {
    let mut rest = author;
    let mut name = String::new();
    while let Some(open) = rest.find('<') {
        let Some(close) = rest[open..].find('>') else {
            break;
        };
        name.push_str(rest[..open].trim_end());
        rest = &rest[open + close + 1..];
    }
    name.push_str(rest);
    name.trim().to_owned()
}

/// For each crate, its entry and the licences it needs, with their texts.
fn resolve(
    crates: &BTreeSet<(String, String)>,
    packages: &HashMap<(String, String), Value>,
) -> Result<Vec<Crate>, String> {
    let mut resolved = Vec::new();
    let mut standard_cc0 = None;
    for (name, version) in crates {
        let package = packages
            .get(&(name.clone(), version.clone()))
            .ok_or_else(|| format!("cargo metadata does not list {name} {version}"))?;
        let expression = package["license"]
            .as_str()
            .filter(|expression| !expression.is_empty())
            .ok_or_else(|| format!("{name} {version} declares no licence expression"))?;
        let directory = PathBuf::from(package["manifest_path"].as_str().unwrap_or_default());
        let directory = directory.parent().unwrap_or(Path::new(""));
        let mut licences = Vec::new();
        for alternatives in licence_parts(expression)? {
            let licence = choose(&alternatives)?;
            let mut text = licence_file_text(directory, &licence)?;
            let note = match (&text, licence.as_str()) {
                (Some(_), _) => None,
                (None, "MIT") => {
                    text = Some(SPDX_MIT_TEXT.replace("{holders}", &holders(package)?));
                    Some(NO_FILE_MIT)
                }
                (None, "CC0-1.0") => Some(NO_FILE_CC0),
                (None, _) => return Err(format!("{name} {version} ships no {licence} text")),
            };
            if note.is_none() && licence == "CC0-1.0" && standard_cc0.is_none() {
                standard_cc0.clone_from(&text);
            }
            licences.push(Licence {
                name: licence,
                text,
                note,
            });
        }
        resolved.push(Crate {
            name: name.clone(),
            version: version.clone(),
            expression: expression.to_owned(),
            licences,
        });
    }
    // The standard CC0 text is known only once some crate has shipped it.
    for entry in &mut resolved {
        for licence in entry
            .licences
            .iter_mut()
            .filter(|licence| licence.text.is_none())
        {
            let text = standard_cc0.clone().ok_or_else(|| {
                format!(
                    "{} {}: no crate ships a {} text to use",
                    entry.name, entry.version, licence.name
                )
            })?;
            licence.text = Some(text);
        }
    }
    Ok(resolved)
}

/// A code fence longer than any run of backticks in the text.
fn fence(text: &str) -> String {
    let longest = text
        .split(|char| char != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    "`".repeat((longest + 1).max(3))
}

/// The heading and the rules of the generated part.
const HEADER: [&str; 21] = [
    "## Rust crates",
    "",
    "The `mhfe` command-line tools and the browser package of a release are compiled from",
    "the Rust crates below. Each crate is listed with its licence expression, the licence",
    "MHFE uses it under and the text of that licence. The other third-party material, the",
    "Argon2 reference code, the EFF wordlist, the JavaScript code of the browser package,",
    "the Rust standard library and the MinGW-w64 runtime, is described above.",
    "",
    "### How the licence is chosen",
    "",
    "- The crates are those compiled into the program for every release target: Linux,",
    "  Windows and macOS on x86-64, Linux and macOS on ARM64, and WebAssembly with the `wasm`",
    "  feature. Build scripts and procedural macros, which run only while building, are left",
    "  out. Not every crate is in every archive.",
    "- Every licence joined by AND is required and listed. Among licences joined by OR, MIT is",
    "  used when it is offered, otherwise Apache-2.0, otherwise the only licence.",
    "- The text is the crate's own licence file, unchanged, with its copyright lines. Where a",
    "  crate publishes no licence file, its entry says so and the standard text of its licence",
    "  is used.",
    "",
    "### Crates",
];

/// Each distinct (licence, text) in the order first used, with the crates using it.
type Texts<'a> = Vec<(&'a str, &'a str, Vec<String>)>;

/// The number of the text of `licence` in `texts`, added when new, with `user` among its crates.
fn number_of<'a>(texts: &mut Texts<'a>, licence: &'a str, text: &'a str, user: String) -> usize {
    let at = texts
        .iter()
        .position(|(name, body, _)| *name == licence && *body == text)
        .unwrap_or_else(|| {
            texts.push((licence, text, Vec::new()));
            texts.len() - 1
        });
    texts[at].2.push(user);
    at + 1
}

fn render(crates: &[Crate]) -> String {
    let mut texts: Texts<'_> = Vec::new();
    let mut lines = vec![MARKER.to_owned(), String::new()];
    lines.extend(HEADER.iter().map(|line| (*line).to_owned()));
    lines.push(String::new());
    for entry in crates {
        let used: Vec<&str> = entry
            .licences
            .iter()
            .map(|licence| licence.name.as_str())
            .collect();
        let links: Vec<String> = entry
            .licences
            .iter()
            .map(|licence| {
                let text = licence.text.as_deref().unwrap_or_default();
                let user = format!("{} {}", entry.name, entry.version);
                let number = number_of(&mut texts, &licence.name, text, user);
                format!("[text {number}](#text-{number})")
            })
            .collect();
        lines.push(format!(
            "- `{}` {}: `{}`, used under {}; {}.",
            entry.name,
            entry.version,
            entry.expression,
            used.join(" and "),
            links.join(", ")
        ));
        lines.extend(
            entry
                .licences
                .iter()
                .filter_map(|licence| licence.note)
                .map(|note| format!("  {note}")),
        );
    }
    lines.extend(["", "### Licence texts", ""].map(str::to_owned));
    for (index, (licence, text, users)) in texts.iter().enumerate() {
        let marker = fence(text);
        lines.extend([
            format!("#### Text {}", index + 1),
            String::new(),
            format!("{licence}, for {}.", users.join(", ")),
            String::new(),
            marker.clone(),
            (*text).to_owned(),
            marker,
            String::new(),
        ]);
    }
    lines.join("\n")
}

/// The bytes of the file `name` at the top of `archive`, read with the system's `unzip` or `tar`;
/// `None` when the archive has no such file.
fn archive_file(archive: &str, name: &str) -> Result<Option<Vec<u8>>, Failure> {
    let attempts: Vec<Vec<String>> = if archive.ends_with(".zip") {
        vec![vec![
            "unzip".into(),
            "-p".into(),
            archive.into(),
            name.into(),
        ]]
    } else {
        // The member may be named with or without a leading "./".
        [name.to_owned(), format!("./{name}")]
            .into_iter()
            .map(|member| vec!["tar".into(), "-xzOf".into(), archive.into(), member])
            .collect()
    };
    for attempt in attempts {
        let output = Command::new(&attempt[0])
            .args(&attempt[1..])
            .output()
            .map_err(|error| Failure(format!("{} did not start: {error}", attempt[0])))?;
        if output.status.success() {
            return Ok(Some(output.stdout));
        }
    }
    Ok(None)
}

/// Fails unless every archive carries the licence files of this checkout.
fn check_archives(root: &Path, archives: &[String]) -> Result<(), Failure> {
    let mut failed = false;
    for archive in archives {
        for name in ["LICENSE", OUTPUT] {
            let path = root.join(name);
            let here = fs::read(&path).map_err(|error| at(&path, error))?;
            if archive_file(archive, name)?.as_deref() != Some(here.as_slice()) {
                eprintln!("{archive} lacks {name} or holds another version of it.");
                failed = true;
            }
        }
    }
    if failed {
        return Err(Failure("An archive lacks its licence files.".to_owned()));
    }
    println!(
        "Every archive carries the licence files: {} checked.",
        archives.len()
    );
    Ok(())
}
