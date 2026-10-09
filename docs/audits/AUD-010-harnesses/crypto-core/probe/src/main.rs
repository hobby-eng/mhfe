//! Reads one request per line from standard input, `<op> <hex argument> ...`, and prints one answer
//! line per request. Arguments are hexadecimal UTF-8 so that spaces, tabs and any Unicode pass
//! through unchanged; numbers are decimal. Public test data only.

use std::io::{self, BufRead, Write};

use mhfe::check_word::{check_index, PasswordReview, Reading};
use mhfe::eff::EffList;
use mhfe::repair::{repair, repair_words};
use mhfe::wallet::{
    find_address, master_fingerprint, Address, AddressSearch, Coin, DerivationPath, SearchLimits,
};
use mhfe::wallet_check::{phrase_passes, verify, PhraseDraw};
use mhfe::{
    check_container, other_detected_lengths, read_phrase, ContainerFacts, MhfeError, Password,
};

fn text(hex_text: &str) -> String {
    if hex_text == "-" {
        return String::new();
    }
    let bytes: Vec<u8> = (0..hex_text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_text[i..i + 2], 16).expect("hex argument"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 argument")
}

fn err(error: MhfeError) -> String {
    format!("ERR {}", error.code())
}

fn answer(op: &str, a: &[&str]) -> String {
    match op {
        "fp" => match master_fingerprint(&text(a[0]), &text(a[1])) {
            Ok(fp) => format!(
                "OK {}",
                fp.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            Err(e) => err(e),
        },
        "find" => {
            let coin: Coin = match text(a[0]).parse() {
                Ok(coin) => coin,
                Err(e) => return err(e),
            };
            let address = match Address::parse(coin, &text(a[1])) {
                Ok(address) => address,
                Err(e) => return err(e),
            };
            let path = match text(a[4]).as_str() {
                "" => None,
                p => match p.parse::<DerivationPath>() {
                    Ok(path) => Some(path),
                    Err(e) => return err(e),
                },
            };
            let limits = match SearchLimits::new(a[5].parse().unwrap(), a[6].parse().unwrap()) {
                Ok(limits) => limits,
                Err(e) => return err(e),
            };
            match find_address(&text(a[2]), &text(a[3]), &address, path.as_ref(), limits) {
                Ok(Some(found)) => format!("FOUND {found}"),
                Ok(None) => "NONE".to_owned(),
                Err(e) => err(e),
            }
        }
        "parse" => {
            let coin: Coin = match text(a[0]).parse() {
                Ok(coin) => coin,
                Err(e) => return err(e),
            };
            match Address::parse(coin, &text(a[1])) {
                Ok(address) => format!(
                    "OK {:?} {}",
                    address.address_type(),
                    address
                        .type_description()
                        .unwrap_or_default()
                        .replace(' ', "_")
                ),
                Err(e) => err(e),
            }
        }
        "path" => match text(a[0]).parse::<DerivationPath>() {
            Ok(path) => format!("OK {path}"),
            Err(e) => err(e),
        },
        "limits" => match (a[0].parse::<u32>(), a[1].parse::<u32>()) {
            (Ok(accounts), Ok(indexes)) => match SearchLimits::new(accounts, indexes) {
                Ok(limits) => format!("OK {} {}", limits.accounts(), limits.indexes()),
                Err(e) => err(e),
            },
            _ => "NOTU32".to_owned(),
        },
        "describe" => match AddressSearch::describe(&text(a[0]), &text(a[1]), &text(a[2])) {
            Ok(search) => format!(
                "OK {} {} {} {}",
                search.pattern(),
                search.addresses(),
                search.only_path(),
                search.type_description().unwrap_or("-").replace(' ', "_")
            ),
            Err(e) => err(e),
        },
        "read" => match read_phrase(&text(a[0])) {
            Ok(words) => format!("OK {}", *words),
            Err(e) => err(e),
        },
        "container" => match check_container(&text(a[0])) {
            Ok(words) => format!("OK {words}"),
            Err(e) => err(e),
        },
        "facts" => match ContainerFacts::read(&text(a[0])) {
            Ok(facts) => format!(
                "OK {} {:?} {:?} {}",
                facts.word_count(),
                facts.suite(),
                facts.phrase_lengths(),
                facts.offers_wallet_check()
            )
            .replace(' ', "_"),
            Err(e) => err(e),
        },
        "detect" => match other_detected_lengths(&text(a[0])) {
            Ok(lengths) => format!("OK {lengths:?}").replace(' ', ""),
            Err(e) => err(e),
        },
        "wcpass" => match phrase_passes(&text(a[0]), &text(a[1])) {
            Ok(passes) => format!("OK {passes}"),
            Err(e) => err(e),
        },
        "wcverify" => match verify(&text(a[0]), &text(a[1])) {
            Ok(passes) => format!("OK {passes}"),
            Err(e) => err(e),
        },
        "wcdraw" => match PhraseDraw::with_check(&text(a[0])) {
            Ok(draw) => format!("OK {}", draw.is_checked()),
            Err(e) => err(e),
        },
        "rwords" => match repair_words(&text(a[0]), a[1].parse().unwrap()) {
            Ok(words) => format!("OK {words}"),
            Err(e) => err(e),
        },
        "repair" => match repair(&text(a[0]), &text(a[1])) {
            Ok(repaired) => format!(
                "OK {}|{:?}|{:?}|{}",
                repaired.container,
                repaired.plate_words,
                repaired.card_words,
                repaired.changes.len()
            )
            .replace(' ', "_"),
            Err(e) => err(e),
        },
        "cindex" => {
            let d: Vec<usize> = a.iter().map(|v| v.parse().unwrap()).collect();
            format!("OK {}", check_index(&[d[0], d[1], d[2], d[3], d[4]]))
        }
        "review" => {
            let review = PasswordReview::of(&text(a[0]));
            let reading = match review.reading() {
                Reading::NotThisShape => "NotThisShape",
                Reading::Fits => "Fits",
                Reading::Restorable => "Restorable",
                Reading::Mismatch => "Mismatch",
            };
            let repairs: Vec<String> = review
                .repairs()
                .iter()
                .map(|r| format!("{}:{}", r.position(), r.word()))
                .collect();
            format!(
                "OK {reading} {:?} {}",
                review.correction(),
                repairs.join(",")
            )
        }
        "eff" => format!("OK {}", EffList::get().words().join(" ")),
        "password" => match Password::new(&text(a[0])) {
            Ok(password) => format!(
                "OK {}",
                password
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            Err(e) => err(e),
        },
        other => format!("UNKNOWN {other}"),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("a line");
        let mut parts = line.split(' ');
        let op = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();
        writeln!(out, "{op} {}", answer(op, &args)).unwrap();
    }
}
