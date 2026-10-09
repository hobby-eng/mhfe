//! AUD-015 R1 probe. Prints what the mhfe library's public API returns, one line per input, so
//! that an independent oracle (ICU through Node.js, Python) can compare it. It decides nothing.
//!
//!   password-probe all      every Unicode scalar value as a one-character password
//!   password-probe lines    stdin: one hex-encoded UTF-8 password per line
//!   password-probe phrases  stdin: one hex-encoded UTF-8 phrase per line, read with read_phrase
//!
//! Output: "<input> ok:<hex of P_enc or of the phrase as read>" or "<input> err:<MhfeError code>".
//! Public test data only: every input is synthetic.

use std::io::{self, BufRead, Write};

use mhfe::{read_phrase, Password};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex input"))
        .collect()
}

fn password(bytes: &[u8]) -> String {
    match Password::from_utf8(bytes) {
        Ok(password) => format!("ok:{}", hex(password.as_bytes())),
        Err(error) => format!("err:{}", error.code()),
    }
}

fn phrase(bytes: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return "err:UTF8".to_owned();
    };
    match read_phrase(text) {
        Ok(read) => format!("ok:{}", hex(read.as_bytes())),
        Err(error) => format!("err:{}", error.code()),
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    match mode.as_str() {
        "all" => {
            for code_point in 0u32..=0x10FFFF {
                if let Some(character) = char::from_u32(code_point) {
                    let text = character.to_string();
                    writeln!(out, "{code_point:x} {}", password(text.as_bytes())).unwrap();
                }
            }
        }
        "lines" | "phrases" => {
            for line in io::stdin().lock().lines() {
                let line = line.unwrap();
                let bytes = unhex(line.trim());
                let result = if mode == "lines" {
                    password(&bytes)
                } else {
                    phrase(&bytes)
                };
                writeln!(out, "{} {result}", line.trim()).unwrap();
            }
        }
        other => {
            eprintln!("unknown mode {other:?}: all, lines or phrases");
            std::process::exit(2);
        }
    }
}
