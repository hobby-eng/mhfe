//! AUD-015 R4 probe of the wallet and word features of the mhfe library, through its public API.
//!
//!   aud015-r4-probe addresses     every case of r4-wallet-cases.json (address-oracle.mjs): found at
//!                                 its path and by the search, the search statement, fingerprints
//!   aud015-r4-probe hints         word_hints against the documented rule, every prefix of both lists
//!   aud015-r4-probe wishes        the stated odds and draw counts against measured acceptance rates
//!   aud015-r4-probe wallet-check  the fresh MHFE-WALLET-CHECK-SEED-1 vector of wallet-check-oracle.mjs,
//!                                 a checked draw and a draw on every core, with and without wishes
//!
//! Run from the repository root. Each command exits 1 when a comparison fails and prints each
//! failure. Public test data only; no full-cost Argon2.

use std::process::ExitCode;

use mhfe::random::RandomSource;
use mhfe::wallet::{
    find_address, master_fingerprint_text, Address, AddressSearch, Coin, DerivationPath,
    SearchLimits,
};
use mhfe::wallet_check::{self, PhraseDraw};
use mhfe::word_hints::{Hint, WordList};
use mhfe::word_wishes::{Place, Randomness, WordWishes};
use mhfe::MhfeError;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE: &str = "docs/audits/AUD-015-evidence";

#[derive(Default)]
struct Report {
    checks: usize,
    failures: Vec<String>,
}

impl Report {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        self.checks += 1;
        if !ok {
            let what = what();
            eprintln!("FAIL {what}");
            self.failures.push(what);
        }
    }

    fn finish(self, name: &str) -> ExitCode {
        println!(
            "{name}: {} checks, {} failures",
            self.checks,
            self.failures.len()
        );
        if self.failures.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

fn read_json(name: &str) -> Value {
    let path = format!("{EVIDENCE}/{name}");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("run the oracle for {path}"));
    serde_json::from_str(&text).expect("JSON")
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("addresses") => addresses(),
        Some("hints") => hints(),
        Some("wishes") => wishes(),
        Some("wallet-check") => wallet_check_vector(),
        _ => {
            eprintln!("usage: aud015-r4-probe addresses|hints|wishes|wallet-check");
            ExitCode::from(2)
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Addresses

/// What the search of a form should state, written here from the coins' standards (SLIP-44, BIP44,
/// BIP49, BIP84, BIP86, DIP17), not from mhfe: the type description, the roots and the chains.
fn expected_statement(form: &str) -> (Option<&'static str>, &'static str, u128) {
    let default = |roots: &'static str| (roots, if roots.contains('{') { 4000 } else { 2000 });
    let (kind, (roots, count)) = match form {
        "bitcoin-p2pkh" => (Some("legacy (BIP44)"), default("44'/0'")),
        "bitcoin-p2sh-p2wpkh" => (Some("nested SegWit (BIP49)"), default("49'/0'")),
        "bitcoin-p2wpkh" => (Some("native SegWit (BIP84)"), default("84'/0'")),
        "bitcoin-p2tr" => (Some("Taproot (BIP86)"), default("86'/0'")),
        "bitcoin-testnet-p2pkh" => (Some("testnet, legacy (BIP44)"), default("44'/1'")),
        "bitcoin-testnet-p2sh-p2wpkh" => {
            (Some("testnet, nested SegWit (BIP49)"), default("49'/1'"))
        }
        "bitcoin-testnet-p2wpkh" => (Some("testnet, native SegWit (BIP84)"), default("84'/1'")),
        "bitcoin-testnet-p2tr" => (Some("testnet, Taproot (BIP86)"), default("86'/1'")),
        "litecoin-p2pkh" => (Some("legacy (BIP44)"), default("44'/2'")),
        "litecoin-p2sh-p2wpkh" | "litecoin-p2sh-p2wpkh-3" => {
            (Some("nested SegWit (BIP49)"), default("49'/2'"))
        }
        "litecoin-p2wpkh" => (Some("native SegWit (BIP84)"), default("84'/2'")),
        "dogecoin" => (None, default("44'/3'")),
        "dash-core" => (Some("Core (BIP44)"), default("44'/5'")),
        "zcash" => (Some("transparent"), default("44'/133'")),
        "bitcoin-cash" | "bitcoin-cash-legacy" | "bitcoin-cash-second-root" => {
            (None, default("44'/{145,0}'"))
        }
        "xrp" => (None, default("44'/144'")),
        "tron" => (None, default("44'/195'")),
        "ethereum" => (None, default("44'/60'")),
        "ethereum-classic" | "ethereum-classic-second-root" => (None, default("44'/{61,60}'")),
        "cosmos" => (None, default("44'/118'")),
        "injective" => (None, default("44'/60'")),
        "dash-platform" => (Some("Platform payment (DIP17)"), default("9'/5'/17'")),
        "dash-platform-testnet" => (
            Some("testnet, Platform payment (DIP17)"),
            default("9'/1'/17'"),
        ),
        "outside-default-limits" => (Some("native SegWit (BIP84)"), default("84'/0'")),
        other => panic!("unknown form {other}"),
    };
    (kind, roots, count)
}

fn addresses() -> ExitCode {
    let mut report = Report::default();
    let data = read_json("r4-wallet-cases.json");
    let phrases: Vec<&str> = data["phrases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    let one = SearchLimits::new(1, 1).unwrap();
    let wider = SearchLimits::new(11, 101).unwrap();
    let mut found_at_path = 0;
    let mut found_by_search = 0;
    for case in data["cases"].as_array().unwrap() {
        let coin_id = case["coin"].as_str().unwrap();
        let form = case["form"].as_str().unwrap();
        let phrase = phrases[case["phraseIndex"].as_u64().unwrap() as usize];
        let passphrase = case["passphrase"].as_str().unwrap();
        let path_text = case["path"].as_str().unwrap();
        let text = case["address"].as_str().unwrap();
        let label = format!("{form} {path_text} {passphrase:?} {text}");
        let coin: Coin = coin_id.parse().unwrap();
        let address = match Address::parse(coin, text) {
            Ok(address) => address,
            Err(error) => {
                report.check(false, || format!("{label}: refused: {error}"));
                continue;
            }
        };
        let path: DerivationPath = path_text.parse().unwrap();
        let at_path = find_address(phrase, passphrase, &address, Some(&path), one).unwrap();
        report.check(at_path.as_ref() == Some(&path), || {
            format!("{label}: not at its path")
        });
        found_at_path += usize::from(at_path.is_some());
        let searched =
            find_address(phrase, passphrase, &address, None, SearchLimits::default()).unwrap();
        if form == "outside-default-limits" {
            report.check(searched.is_none(), || {
                format!("{label}: found outside the default limits")
            });
            let wide = find_address(phrase, passphrase, &address, None, wider).unwrap();
            report.check(wide.as_ref() == Some(&path), || {
                format!("{label}: not found within 11 x 101")
            });
        } else {
            report.check(searched.as_ref() == Some(&path), || {
                format!(
                    "{label}: search found {:?}",
                    searched.as_ref().map(ToString::to_string)
                )
            });
            found_by_search += usize::from(searched.is_some());
        }
        // The statement made before a check, compared with the standards' paths.
        let (kind, roots, count) = expected_statement(form);
        let chains = if form.starts_with("dash-platform") {
            "0'-1'"
        } else {
            "0-1"
        };
        let pattern = format!("m/{roots}/0'-9'/{chains}/0-99");
        let stated = AddressSearch::describe(coin_id, text, "").unwrap();
        report.check(
            stated.type_description() == kind
                && stated.pattern() == pattern
                && stated.addresses() == count,
            || {
                format!(
                    "{label}: stated {:?} {} {} instead of {kind:?} {pattern} {count}",
                    stated.type_description(),
                    stated.pattern(),
                    stated.addresses()
                )
            },
        );
    }
    for entry in data["fingerprints"].as_array().unwrap() {
        let phrase = phrases[entry["phraseIndex"].as_u64().unwrap() as usize];
        let passphrase = entry["passphrase"].as_str().unwrap();
        let expected = entry["fingerprint"].as_str().unwrap();
        let fingerprint = master_fingerprint_text(phrase, passphrase).unwrap();
        report.check(fingerprint == expected, || {
            format!("fingerprint {passphrase:?}: {fingerprint} != {expected}")
        });
    }
    // The statement of the decoy search of two missing words (first account, a scan gap).
    let gap = AddressSearch::describe_within(
        "bitcoin",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "",
        SearchLimits::first_account(20).unwrap(),
    )
    .unwrap();
    println!(
        "decoy statement with scan gap 20: {} ({} addresses)",
        gap.pattern(),
        gap.addresses()
    );
    report.check(gap.addresses() == 40, || {
        format!("scan gap 20 states {}", gap.addresses())
    });
    println!("{found_at_path} found at their path, {found_by_search} found by the default search");
    report.finish("addresses")
}

// ------------------------------------------------------------------------------------------------
// Word hints

/// The documented rule (README "word hints", docs/API.md word_hints, BROWSER-PACKAGE.md
/// wordHints), written as a plain scan of the list: the last word of the line, after its last
/// space; nothing when no word of letters is being typed; after one letter how many words begin
/// with it; from two letters those words; "no word" when none does; nothing when the list has it
/// whole and no longer word begins with it.
fn documented_hint(words: &[&'static str], line: &str) -> (String, Vec<&'static str>) {
    let token = line.rsplit(char::is_whitespace).next().unwrap_or("");
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-') {
        return ("nothing".into(), vec![]);
    }
    let token = token.to_ascii_lowercase();
    let matches: Vec<&'static str> = words
        .iter()
        .copied()
        .filter(|w| w.starts_with(&token))
        .collect();
    if matches.is_empty() {
        ("noWord".into(), vec![])
    } else if matches.len() == 1 && matches[0] == token {
        ("nothing".into(), vec![])
    } else if token.len() == 1 {
        (format!("count {}", matches.len()), vec![])
    } else {
        ("words".into(), matches)
    }
}

fn documented_completion(words: &[&'static str], line: &str) -> (String, bool) {
    let token = line.rsplit(char::is_whitespace).next().unwrap_or("");
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-') {
        return (String::new(), false);
    }
    let token = token.to_ascii_lowercase();
    let matches: Vec<&str> = words
        .iter()
        .copied()
        .filter(|w| w.starts_with(&token))
        .collect();
    if matches.is_empty() {
        return (String::new(), false);
    }
    let first = matches[0].as_bytes();
    let shared = matches.iter().fold(first.len(), |shared, w| {
        first
            .iter()
            .zip(w.as_bytes())
            .take(shared)
            .take_while(|(a, b)| a == b)
            .count()
    });
    (
        matches[0][token.len()..shared].to_owned(),
        matches.len() == 1,
    )
}

fn library_hint(list: WordList, line: &str) -> (String, Vec<&'static str>) {
    match list.hint(line) {
        Hint::Nothing => ("nothing".into(), vec![]),
        Hint::Count(n) => (format!("count {n}"), vec![]),
        Hint::Words(words) => ("words".into(), words.to_vec()),
        Hint::NoWord => ("noWord".into(), vec![]),
    }
}

fn hints() -> ExitCode {
    let mut report = Report::default();
    let eff_text =
        std::fs::read_to_string("vendor/eff-large-wordlist/eff_large_wordlist.txt").unwrap();
    let eff: Vec<&'static str> = eff_text
        .leak()
        .lines()
        .map(|line| line.split('\t').nth(1).unwrap())
        .collect();
    let bip39: Vec<&'static str> = bip39::Language::English.word_list().to_vec();
    let mut long_mismatches: Vec<String> = Vec::new();
    for (list, words) in [(WordList::Bip39, &bip39), (WordList::Eff, &eff)] {
        let mut lines: Vec<String> = Vec::new();
        for word in words.iter() {
            for end in 1..=word.len() {
                let prefix = &word[..end];
                lines.push(prefix.to_owned());
                lines.push(format!("{prefix}q"));
                lines.push(format!("abandon {}", prefix.to_ascii_uppercase()));
            }
            // Typing goes on past the end of a word: one to four letters too many.
            for extra in ["x", "xy", "xyz", "xyzw"] {
                lines.push(format!("{word}{extra}"));
            }
        }
        for line in [
            "",
            " ",
            "abandon ",
            "a1",
            "?",
            "toolongforanyword",
            "zzzzzzzzzz",
        ] {
            lines.push(line.to_owned());
        }
        for line in &lines {
            let documented = documented_hint(words, line);
            let library = library_hint(list, line);
            if documented != library {
                let token = line.rsplit(' ').next().unwrap_or("");
                let entry = format!(
                    "{} {line:?} ({} letters): library {:?}, documented {:?}",
                    list.name(),
                    token.len(),
                    library.0,
                    documented.0
                );
                if token.len() > 9 && library.0 == "nothing" && documented.0 == "noWord" {
                    long_mismatches.push(entry);
                } else {
                    report.check(false, || entry);
                    continue;
                }
            }
            let completion = list.completion(line);
            let expected = documented_completion(words, line);
            report.check(
                (completion.letters.to_owned(), completion.word_ends) == expected,
                || {
                    format!(
                        "{} completion {line:?}: {:?} vs {expected:?}",
                        list.name(),
                        (completion.letters, completion.word_ends)
                    )
                },
            );
        }
    }
    println!(
        "{} lines typed past the longest word (more than 9 letters) get no hint where the \
         documented rule says no word begins like this; first: {:?}",
        long_mismatches.len(),
        long_mismatches.first()
    );
    report.check(long_mismatches.is_empty(), || {
        format!(
            "{} long-word lines without the no-word hint",
            long_mismatches.len()
        )
    });
    report.finish("hints")
}

// ------------------------------------------------------------------------------------------------
// Word wishes

/// SHA-256 in counter mode: a deterministic stand-in for a random generator, never for a phrase
/// in use. Counts every fill.
struct Counter {
    block: u64,
    fills: u64,
}

impl RandomSource for Counter {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self.fills += 1;
        for chunk in bytes.chunks_mut(32) {
            self.block += 1;
            let digest = Sha256::new()
                .chain_update(b"AUD-015 R4 probe")
                .chain_update(self.block.to_be_bytes())
                .finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        Ok(())
    }
}

fn wishes() -> ExitCode {
    let mut report = Report::default();
    // The documented figures, from first principles: a fixed word 11 bits, an "anywhere" word the
    // log of the share of phrases holding it, each free word avoiding the word never to use.
    let l = 2048f64;
    let never_23 = 23.0 * (2047.0 / l).log2();
    let anywhere_never = ((2047.0 / l).powi(24) - (2046.0 / l).powi(24)).log2();
    let anywhere = (1.0 - (2047.0 / l).powi(24)).log2();
    let figures = [
        (
            "fixed + never + check",
            256.0 - 11.0 + never_23 - 16.0,
            228.98,
        ),
        ("fixed + never", 256.0 - 11.0 + never_23, 244.98),
        (
            "anywhere + never + check",
            256.0 + anywhere_never - 16.0,
            233.56,
        ),
        ("anywhere + never", 256.0 + anywhere_never, 249.56),
    ];
    for (what, value, stated) in figures {
        report.check((value * 100.0).floor() / 100.0 == stated, || {
            format!("{what}: {value} vs stated {stated}")
        });
        println!("{what}: {value:.4} bits (documented {stated})");
    }
    println!(
        "a word anywhere holds once in {:.2} random phrases; {:.2} with a word never to use",
        1.0 / (1.0 - (2047.0 / l).powi(24)),
        1.0 / 2f64.powf(anywhere_never)
    );
    let _ = anywhere;

    // Measured acceptance: draws per phrase against odds().expected_draws, five standard errors.
    let scenarios: [(&str, &[(Place, &str)], &[&str], usize); 6] = [
        ("anywhere zoo", &[(Place::Anywhere, "zoo")], &[], 3000),
        (
            "anywhere zoo, never abandon",
            &[(Place::Anywhere, "zoo")],
            &["abandon"],
            3000,
        ),
        ("zoo at 24", &[(Place::At(24), "zoo")], &[], 1500),
        (
            "zoo at 24, never abandon",
            &[(Place::At(24), "zoo")],
            &["abandon"],
            1500,
        ),
        (
            "happy at 1, never abandon",
            &[(Place::At(1), "happy")],
            &["abandon"],
            20000,
        ),
        ("never abandon", &[], &["abandon"], 20000),
    ];
    let words = bip39::Language::English.word_list();
    for (what, chosen, never, count) in scenarios {
        let wishes = WordWishes::new(chosen, never).unwrap();
        let draw = PhraseDraw::unchecked().with_wishes(wishes);
        let odds = draw.odds();
        let mut source = Counter { block: 0, fills: 0 };
        let mut tries = 0u64;
        for _ in 0..count {
            let before = source.fills;
            let phrase = draw.draw(&mut source, &mut |_| Ok(())).unwrap();
            // Two probes of the source, then the tries.
            tries += source.fills - before - 2;
            // The phrase meets the wishes, read independently of the library's bit slicing.
            let list: Vec<&str> = phrase.phrase().split(' ').collect();
            let ok = list.len() == 24
                && never.iter().all(|w| !list.contains(w))
                && chosen.iter().all(|(place, w)| match place {
                    Place::At(p) => list[p - 1] == *w,
                    Place::Anywhere => list.contains(w),
                })
                && list.iter().all(|w| words.contains(w));
            report.check(ok, || format!("{what}: a phrase misses its wishes"));
        }
        let mean = tries as f64 / count as f64;
        let p = 1.0 / odds.expected_draws;
        let standard_error = ((1.0 - p).sqrt() / p) / (count as f64).sqrt();
        println!(
            "{what}: {mean:.2} draws per phrase measured, {:.2} stated (se {standard_error:.2}); \
             {:.2} bits, {:?}, recognisable {}",
            odds.expected_draws, odds.random_bits, odds.randomness, odds.recognisable
        );
        report.check(
            (mean - odds.expected_draws).abs() <= 5.0 * standard_error.max(0.01),
            || {
                format!(
                    "{what}: {mean} draws measured, {} stated",
                    odds.expected_draws
                )
            },
        );
        report.check(odds.recognisable == !chosen.is_empty(), || {
            format!("{what}: recognisable")
        });
        report.check(
            (odds.randomness == Randomness::Ample) == (odds.random_bits >= 240.0),
            || {
                format!(
                    "{what}: randomness {:?} at {}",
                    odds.randomness, odds.random_bits
                )
            },
        );
    }
    report.finish("wishes")
}

// ------------------------------------------------------------------------------------------------
// Wallet check

/// Entropies of 24 zero bytes and a big-endian counter, as in the published vectors.
fn counted(counter: u64) -> [u8; 32] {
    let mut entropy = [0u8; 32];
    entropy[24..].copy_from_slice(&counter.to_be_bytes());
    entropy
}

struct Counting {
    next: u64,
}

impl RandomSource for Counting {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self.next += 1;
        bytes.copy_from_slice(&counted(self.next));
        Ok(())
    }
}

fn wallet_check_vector() -> ExitCode {
    let mut report = Report::default();
    let vector = read_json("r4-wallet-check-vector.json");
    let passphrase = vector["passphrase"].as_str().unwrap();
    let nfkd = vector["passphraseNfkd"].as_str().unwrap();
    let counter = vector["counter"].as_u64().unwrap();
    let mnemonic = vector["mnemonic"].as_str().unwrap();
    let entropy = counted(counter);
    report.check(
        hex::encode(entropy) == vector["entropyHex"].as_str().unwrap(),
        || "entropy".into(),
    );
    report.check(
        wallet_check::passes(&entropy, passphrase) == Ok(true),
        || "the fresh vector passes".into(),
    );
    report.check(wallet_check::passes(&entropy, nfkd) == Ok(true), || {
        "its NFKD form passes".into()
    });
    report.check(
        wallet_check::passes(&entropy, "Cafe fi") == Ok(false),
        || "an ASCII look-alike fails".into(),
    );
    report.check(wallet_check::passes(&entropy, "") == Ok(false), || {
        "no passphrase fails".into()
    });
    report.check(
        wallet_check::passes(&counted(counter - 1), passphrase) == Ok(false),
        || "the previous counter fails".into(),
    );
    report.check(
        wallet_check::verify(mnemonic, passphrase) == Ok(true),
        || "verify".into(),
    );
    let typed: String = mnemonic
        .split(' ')
        .map(|word| word[..word.len().min(4)].to_uppercase())
        .collect::<Vec<_>>()
        .join("  ");
    report.check(wallet_check::verify(&typed, passphrase) == Ok(true), || {
        "verify as typed".into()
    });
    report.check(
        wallet_check::verify(mnemonic, "") == Err(MhfeError::WalletCheckNeedsPassphrase),
        || "verify without a passphrase".into(),
    );
    // Every counter from 1 to the vector fails in the oracle; the library agrees on the last 64.
    for earlier in counter.saturating_sub(64)..counter {
        report.check(
            wallet_check::passes(&counted(earlier), passphrase) == Ok(false),
            || format!("counter {earlier} passes"),
        );
    }
    // A checked draw from a source just before the vector: two probes, then the vector.
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let compatible: Vec<(&str, WordWishes)> = vec![
        ("none", WordWishes::none()),
        (
            "last word fixed",
            WordWishes::new(&[(Place::At(24), words[23])], &[]).unwrap(),
        ),
        (
            "word 22 fixed, never zoo",
            WordWishes::new(&[(Place::At(22), words[21])], &["zoo"]).unwrap(),
        ),
        (
            "anywhere",
            WordWishes::new(&[(Place::Anywhere, words[22])], &[]).unwrap(),
        ),
    ];
    for (what, wishes) in compatible {
        let draw = PhraseDraw::with_check(passphrase)
            .unwrap()
            .with_wishes(wishes);
        let mut source = Counting { next: counter - 3 };
        let drawn = draw.draw(&mut source, &mut |_| Ok(())).unwrap();
        report.check(drawn.phrase() == mnemonic && drawn.checked(), || {
            format!("draw, {what}")
        });
    }
    // A wish the vector misses sends the draw on: it is stopped at its first report.
    let missing = WordWishes::new(&[], &[words[23]]).unwrap();
    let draw = PhraseDraw::with_check(passphrase)
        .unwrap()
        .with_wishes(missing);
    let mut source = Counting { next: counter - 3 };
    let stopped = draw.draw(&mut source, &mut |_| Err(MhfeError::Cancelled));
    report.check(matches!(stopped, Err(MhfeError::Cancelled)), || {
        "a missed wish is skipped".into()
    });
    // On every core: the first source reaches the vector at once; the others start far away.
    let made = std::sync::atomic::AtomicU64::new(0);
    let sources = || {
        let index = made.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Counting {
            next: if index == 0 {
                counter - 3
            } else {
                1 << 40 | index << 20
            },
        }
    };
    let draw = PhraseDraw::with_check(passphrase).unwrap();
    let drawn = draw.draw_on_every_core(sources, &mut |_| Ok(())).unwrap();
    report.check(drawn.phrase() == mnemonic, || {
        format!("draw on every core gave {}", drawn.phrase())
    });
    println!(
        "fresh vector: counter {counter}, {} threads made sources",
        made.load(std::sync::atomic::Ordering::SeqCst)
    );
    report.finish("wallet-check")
}
