//! `cargo xtask cell-widths [--check]`: writes `src/bin/mhfe/cell_widths.rs`, the terminal cells a
//! character takes, from Unicode 18.0.0; with `--check` it writes nothing and fails when the file
//! differs from what the data give.
//!
//! The line editor of the command-line tool moves the cursor by the cells each typed character
//! takes (`src/bin/mhfe/typed_line.rs`), so that a wide character, such as a CJK ideograph or an
//! emoji, and a combining mark put it in the right column (AUD-016-UI001, AUD-018). The rule is the
//! one terminals follow, after Markus Kuhn's wcwidth:
//!
//! - two cells: East_Asian_Width W (wide) or F (fullwidth), which includes the emoji shown as
//!   emoji;
//! - no cell: the combining marks (General_Category Mn and Me), the format characters (Cf) other
//!   than the soft hyphen U+00AD, and the Hangul Jamo vowels and final consonants (U+1160 to
//!   U+11FF, U+D7B0 to U+D7C6, U+D7CB to U+D7FB), which join the syllable before them;
//! - one cell: everything else.
//!
//! The model is the per-character width of glibc's wcwidth and GLib (VTE terminals), which xterm
//! and most Linux terminals follow. Terminals that measure whole grapheme clusters (kitty,
//! WezTerm, foot, Windows Terminal) can differ for emoji sequences, such as a variation selector
//! or a skin-tone modifier; the line editor shows no zero-width joiner, so such sequences stay
//! apart.
//!
//! The character data are two files of the Unicode Character Database 18.0.0, the Unicode version
//! of the password rule, kept in `tests/fixtures/unicode18-ucd/` with their SHA-256, which this
//! task checks before it reads them. The output is deterministic: the same data give the same
//! bytes.

use std::fs;
use std::ops::RangeInclusive;
use std::path::Path;

use crate::{Failure, at, wasm};

/// The file the task writes, from the repository's root.
const OUTPUT: &str = "src/bin/mhfe/cell_widths.rs";
/// The folder of the data files, from the repository's root.
const DATA: &str = "tests/fixtures/unicode18-ucd";
const UNICODE_VERSION: &str = "18.0.0";
/// The data files, whose SHA-256 `tests/fixtures/unicode18-ucd/SHA256SUMS` records.
const GENERAL_CATEGORY: &str = "DerivedGeneralCategory.txt";
const EAST_ASIAN_WIDTH: &str = "EastAsianWidth.txt";
/// One past the last code point.
const CODE_POINTS: u32 = 0x11_0000;
const SURROGATES: RangeInclusive<u32> = 0xD800..=0xDFFF;
const SOFT_HYPHEN: u32 = 0x00AD;
/// Hangul Jamo medial vowels and final consonants, which join the syllable before them: the Jamo
/// block's and those of Hangul Jamo Extended-B (Hangul_Syllable_Type V and T there), as glibc and
/// GLib count them.
const HANGUL_JAMO_JOINING: [RangeInclusive<u32>; 3] =
    [0x1160..=0x11FF, 0xD7B0..=0xD7C6, 0xD7CB..=0xD7FB];

pub(crate) fn run(root: &Path, check: bool) -> Result<(), Failure> {
    let data = root.join(DATA);
    let categories = property(&data, GENERAL_CATEGORY, "Cn")?;
    let widths = property(&data, EAST_ASIAN_WIDTH, "N")?;
    let text = render(&runs(&categories, &widths));
    crate::generated(root, OUTPUT, &text, check, "cell-widths")?;
    if check {
        println!("{OUTPUT} matches Unicode {UNICODE_VERSION}.");
    }
    Ok(())
}

/// The value of a property for every code point, read from a data file of lines
/// `first[..last] ; value # comment`; `missing` for a code point the file does not list.
fn property(data: &Path, name: &str, missing: &str) -> Result<Vec<String>, Failure> {
    let sums = data.join("SHA256SUMS");
    let listed = wasm::text(&sums)?.lines().find_map(|line| {
        line.strip_suffix(name)?
            .strip_suffix("  ")
            .map(str::to_owned)
    });
    let path = data.join(name);
    let bytes = fs::read(&path).map_err(|error| at(&path, error))?;
    if listed.as_deref() != Some(wasm::sha256_hex(&bytes).as_str()) {
        return Err(at(
            &path,
            "it is not the file of Unicode 18.0.0 (SHA-256 differs)",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|error| at(&path, error))?;
    let mut values = vec![missing.to_owned(); CODE_POINTS as usize];
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let wrong = || {
            at(
                &path,
                format!("line {} is not `code points ; value`", number + 1),
            )
        };
        let (code_points, value) = line.split_once(';').ok_or_else(wrong)?;
        let (first, last) = code_points
            .trim()
            .split_once("..")
            .unwrap_or((code_points.trim(), code_points.trim()));
        let first = u32::from_str_radix(first, 16).map_err(|_| wrong())?;
        let last = u32::from_str_radix(last, 16).map_err(|_| wrong())?;
        if first > last || last >= CODE_POINTS {
            return Err(wrong());
        }
        for code_point in first..=last {
            values[code_point as usize] = value.trim().to_owned();
        }
    }
    Ok(values)
}

/// The cells of a code point by the rule above.
fn cells(code_point: u32, category: &str, width: &str) -> u8 {
    let joining = HANGUL_JAMO_JOINING
        .iter()
        .any(|run| run.contains(&code_point));
    if matches!(category, "Mn" | "Me") || joining {
        return 0;
    }
    if category == "Cf" && code_point != SOFT_HYPHEN {
        return 0;
    }
    if matches!(width, "W" | "F") {
        return 2;
    }
    1
}

/// The runs of code points that do not take one cell, as (first, last, cells).
fn runs(categories: &[String], widths: &[String]) -> Vec<(u32, u32, u8)> {
    let mut runs: Vec<(u32, u32, u8)> = Vec::new();
    for code_point in (0..CODE_POINTS).filter(|code_point| !SURROGATES.contains(code_point)) {
        let index = code_point as usize;
        let width = cells(code_point, &categories[index], &widths[index]);
        if width == 1 {
            continue;
        }
        match runs.last_mut() {
            Some(run) if run.1 + 1 == code_point && run.2 == width => run.1 = code_point,
            _ => runs.push((code_point, code_point, width)),
        }
    }
    runs
}

fn render(runs: &[(u32, u32, u8)]) -> String {
    let version = UNICODE_VERSION.replace('.', ", ");
    let mut lines =
        vec![
        format!(
            "// Generated by `cargo xtask cell-widths` from Unicode {UNICODE_VERSION}; do not edit."
        ),
        String::new(),
        "//! The terminal cells of the characters that do not take one: runs of code points, in"
            .to_owned(),
        "//! order, with no cell (combining marks, format characters, joining Hangul Jamo) or two"
            .to_owned(),
        "//! (East Asian wide and fullwidth, emoji among them). Every other character takes one."
            .to_owned(),
        String::new(),
        "/// The Unicode version of the table, the version of the password rule; the tests compare"
            .to_owned(),
        "/// it with the one the password rule's normalization has.".to_owned(),
        "#[cfg(test)]".to_owned(),
        format!("pub(crate) const UNICODE_VERSION: (u8, u8, u8) = ({version});"),
        String::new(),
        "/// (first, last, cells) of each run, sorted and not overlapping. One run a line, as the"
            .to_owned(),
        "/// generator writes it, which rustfmt would otherwise pack.".to_owned(),
        "#[rustfmt::skip]".to_owned(),
        format!("pub(crate) const RUNS: [(u32, u32, u8); {}] = [", runs.len()),
    ];
    lines.extend(
        runs.iter()
            .map(|(first, last, cells)| format!("    (0x{first:X}, 0x{last:X}, {cells}),")),
    );
    lines.extend(["];".to_owned(), String::new()]);
    lines.join("\n")
}
