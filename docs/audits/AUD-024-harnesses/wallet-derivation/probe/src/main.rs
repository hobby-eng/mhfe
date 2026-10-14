//! AUD-024 wallet-derivation probe: runs cases computed by an independent oracle (oracle.py,
//! validated against published vectors) or copied from published documents through the public
//! API of mhfe at the reviewed commit, and prints PASS or FAIL for each. Exits 1 when any case
//! fails, 2 on a malformed case file.
//!
//!     aud024-wallet-probe <cases.json>

use std::process::ExitCode;

use mhfe::search::ContainerSearch;
use mhfe::wallet::{
    find_address, master_fingerprint, parse_fingerprint, Address, AddressSearch, Coin,
    DerivationPath, SearchLimits,
};
use mhfe::{MhfeError, Reference};
use serde_json::Value;

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case.get(key).and_then(Value::as_str).unwrap_or("")
}

fn number(case: &Value, key: &str) -> u64 {
    case.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn coin(case: &Value) -> Result<Coin, String> {
    text(case, "coin").parse().map_err(|e: MhfeError| e.to_string())
}

fn path(text: &str) -> Result<DerivationPath, String> {
    text.parse::<DerivationPath>()
        .map_err(|e| format!("path {text} refused: {}", e.code()))
}

fn expect(ok: bool, detail: impl FnOnce() -> String) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(detail())
    }
}

fn run(case: &Value) -> Result<(), String> {
    match text(case, "t") {
        "addr" => {
            let address = Address::parse(coin(case)?, text(case, "address"))
                .map_err(|e| format!("parse: {} {e}", e.code()))?;
            let at = path(text(case, "path"))?;
            let one = SearchLimits::new(1, 1).map_err(|e| e.to_string())?;
            let found = find_address(text(case, "phrase"), text(case, "pass"), &address, Some(&at), one)
                .map_err(|e| format!("derive: {} {e}", e.code()))?;
            expect(found.as_ref() == Some(&at), || format!("not at its path {at}"))?;
            if let Some(limits) = case.get("search").and_then(Value::as_array) {
                let limits = SearchLimits::new(
                    limits[0].as_u64().unwrap_or(0) as u32,
                    limits[1].as_u64().unwrap_or(0) as u32,
                )
                .map_err(|e| e.to_string())?;
                let found = find_address(text(case, "phrase"), text(case, "pass"), &address, None, limits)
                    .map_err(|e| format!("search: {} {e}", e.code()))?;
                let want = case.get("found").and_then(Value::as_str);
                let got = found.map(|p| p.to_string());
                expect(got.as_deref() == want, || format!("search found {got:?}, want {want:?}"))?;
            }
            Ok(())
        }
        "not_at" => {
            let address = Address::parse(coin(case)?, text(case, "address"))
                .map_err(|e| format!("parse: {} {e}", e.code()))?;
            let at = path(text(case, "path"))?;
            let one = SearchLimits::new(1, 1).map_err(|e| e.to_string())?;
            let found = find_address(text(case, "phrase"), text(case, "pass"), &address, Some(&at), one)
                .map_err(|e| format!("derive: {} {e}", e.code()))?;
            expect(found.is_none(), || format!("found at {at}, where it is not"))
        }
        "fp" => {
            let fp = master_fingerprint(text(case, "phrase"), text(case, "pass"))
                .map_err(|e| format!("{} {e}", e.code()))?;
            expect(hex::encode(fp) == text(case, "fp"), || format!("fingerprint {}", hex::encode(fp)))
        }
        "fp_text" => {
            let parsed = parse_fingerprint(text(case, "text"));
            match text(case, "want") {
                "" => expect(parsed.is_err(), || format!("accepted as {parsed:?}")),
                want => expect(parsed.as_ref().map(hex::encode).ok().as_deref() == Some(want), || {
                    format!("read as {parsed:?}")
                }),
            }
        }
        "parse_ok" => Address::parse(coin(case)?, text(case, "text"))
            .map(|_| ())
            .map_err(|e| format!("refused: {} {e}", e.code())),
        "parse_eq" => {
            let a = Address::parse(coin(case)?, text(case, "a")).map_err(|e| e.to_string())?;
            let b = Address::parse(coin(case)?, text(case, "b")).map_err(|e| e.to_string())?;
            expect(a == b, || "differ".to_owned())
        }
        "parse_type" => {
            let a = Address::parse(coin(case)?, text(case, "text")).map_err(|e| e.to_string())?;
            let got = a.type_description().unwrap_or_default();
            let roots = format!("{:?}", a.search_roots());
            expect(got == text(case, "type") && roots == text(case, "roots"), || {
                format!("type {got:?} roots {roots}")
            })
        }
        "parse_err" => match Address::parse(coin(case)?, text(case, "text")) {
            Ok(a) => Err(format!("accepted as {a:?}")),
            Err(e) => expect(e.code() == "INVALID_ADDRESS", || format!("refused with {}", e.code())),
        },
        "path_ok" => {
            let p = path(text(case, "text"))?;
            expect(p.to_string() == text(case, "display"), || format!("read as {p}"))
        }
        "path_err" => match text(case, "text").parse::<DerivationPath>() {
            Ok(p) => Err(format!("accepted, depth {} ({})", p.to_string().matches('/').count(),
                                 if p.to_string().len() > 60 { "long" } else { "short" })),
            Err(e) => expect(e.code() == "INVALID_DERIVATION_PATH", || e.code().to_owned()),
        },
        "limits" => {
            let made = SearchLimits::new(number(case, "accounts") as u32, number(case, "indexes") as u32);
            expect(made.is_ok() == case.get("ok").and_then(Value::as_bool).unwrap_or(false), || {
                format!("{made:?}")
            })
        }
        "scope" => {
            let gap = number(case, "gap") as u32;
            let limits = if gap == 0 {
                SearchLimits::default()
            } else {
                SearchLimits::first_account(gap).map_err(|e| e.to_string())?
            };
            let s = AddressSearch::describe_within(
                text(case, "coin"),
                text(case, "address"),
                text(case, "path"),
                limits,
            )
            .map_err(|e| e.code().to_owned())?;
            let want_count: u128 = text(case, "addresses").parse().unwrap_or(0);
            expect(
                s.pattern() == text(case, "pattern") && s.addresses() == want_count,
                || format!("{} {}", s.pattern(), s.addresses()),
            )
        }
        "candidates" => {
            let search = ContainerSearch::new(text(case, "written"))
                .map_err(|e| format!("{} {e}", e.code()))?;
            let want: Vec<usize> = case["missing"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_u64).map(|v| v as usize).collect())
                .unwrap_or_default();
            expect(
                search.count() as u64 == number(case, "count") && search.missing() == want,
                || format!("count {} missing {:?}", search.count(), search.missing()),
            )
        }
        "search_err" => match ContainerSearch::new(text(case, "written")) {
            Ok(s) => Err(format!("accepted with missing {:?}", s.missing())),
            Err(e) => expect(e.code() == text(case, "code"), || e.code().to_owned()),
        },
        "decoy" => {
            let search = ContainerSearch::new(text(case, "written"))
                .map_err(|e| format!("{} {e}", e.code()))?;
            let address;
            let at;
            let reference = match text(case, "kind") {
                "fingerprint" => Reference::Fingerprint {
                    fingerprint: parse_fingerprint(text(case, "fp")).map_err(|e| e.to_string())?,
                    passphrase: text(case, "pass"),
                },
                _ => {
                    address = Address::parse(coin(case)?, text(case, "address"))
                        .map_err(|e| e.to_string())?;
                    at = match text(case, "path") {
                        "" => None,
                        p => Some(path(p)?),
                    };
                    Reference::Address {
                        address: &address,
                        passphrase: text(case, "pass"),
                        path: at.as_ref(),
                        limits: SearchLimits::default(),
                    }
                }
            };
            let found = search
                .search_decoy(&reference, number(case, "gap") as u32, &mut |_, _| Ok(()))
                .map_err(|e| format!("{} {e}", e.code()))?;
            let got = found.as_ref().map(|f| f.container.to_string());
            let want = case.get("container").and_then(Value::as_str);
            expect(got.as_deref() == want, || format!("found {got:?}"))?;
            if let (Some(found), Some(p)) = (found, case.get("found_path").and_then(Value::as_str)) {
                let got = found.path.map(|p| p.to_string());
                expect(got.as_deref() == Some(p), || format!("path {got:?}"))?;
            }
            Ok(())
        }
        other => Err(format!("unknown case type {other}")),
    }
}

fn main() -> ExitCode {
    let Some(file) = std::env::args().nth(1) else {
        eprintln!("usage: aud024-wallet-probe <cases.json>");
        return ExitCode::from(2);
    };
    let Ok(data) = std::fs::read_to_string(&file) else {
        eprintln!("cannot read {file}");
        return ExitCode::from(2);
    };
    let Ok(Value::Array(cases)) = serde_json::from_str::<Value>(&data) else {
        eprintln!("{file} is not a JSON array");
        return ExitCode::from(2);
    };
    let mut failed = 0;
    for case in &cases {
        let id = text(case, "id");
        match run(case) {
            Ok(()) => println!("PASS {id}"),
            Err(detail) => {
                failed += 1;
                println!("FAIL {id}: {detail}");
            }
        }
    }
    println!("{} cases, {} passed, {} failed", cases.len(), cases.len() - failed, failed);
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
