//! AUD-044 fun probes: each subcommand runs one reproduction through the library's public interface
//! and prints what it saw. Public test data only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use mhfe::rekey::Rekey;
use mhfe::search::ContainerSearch;
use mhfe::strength::Strength;
use mhfe::wallet::{master_fingerprint, Address, Coin, SearchLimits};
use mhfe::word_wishes::{Place, WordWishes};
use mhfe::{
    check_phrase, decrypt, recover_for_check, CheckOutcome, Confirmation, PhraseLength, Recovery,
    Reference, WordCount,
};
use mhfe_core::{Mhfe, NativeArgon2, Password, Phrase, Suite, WorkFactor};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "public test password";

fn cipher() -> Mhfe<NativeArgon2> {
    let work = WorkFactor::default();
    Mhfe::new(work).unwrap()
}

fn encrypt(mhfe: &mut Mhfe<NativeArgon2>, phrase: &str, suite: Suite) -> String {
    let password = Password::new(PASSWORD).unwrap();
    mhfe::encrypt(mhfe, phrase, &password, suite, &mut |_, _| Ok(()), &mut |_| Ok(()))
        .unwrap()
        .as_str()
        .to_owned()
}

/// The 24-word phrase whose entropy is the packed state of the 12-word entropy `e`: a 24-word
/// original that passes the 12-word built-in check, as about one 24-word phrase in 2^124 does.
fn twenty_four_passing_12(e: &[u8; 16]) -> String {
    let mut state = [0u8; 32];
    state[..16].copy_from_slice(e);
    let hash = Sha256::digest(e);
    state[16..].copy_from_slice(&hash[..16]);
    Phrase::from_entropy(&state).unwrap().as_str().to_owned()
}

/// AUD-024-FUN008: the check and the rekey of one container with one fingerprint.
fn rekey_reference() {
    let e = [0x42u8; 16];
    let phrase = twenty_four_passing_12(&e);
    let mut mhfe = cipher();
    let container = encrypt(&mut mhfe, &phrase, Suite::TwentyFourWords);
    let fingerprint = master_fingerprint(&phrase, "").unwrap();
    println!("original (24 words): {phrase}");
    println!("container: {container}");
    println!("fingerprint of the original: {}", hex::encode(fingerprint));
    let password = Password::new(PASSWORD).unwrap();
    let reference = Reference::Fingerprint { fingerprint, passphrase: "" };
    let evidence = recover_for_check(&mut mhfe, &container, &password, &reference, &mut |_, _| Ok(()))
        .unwrap()
        .compare(&reference)
        .unwrap();
    println!("rehearsal check: {evidence:?}");
    for (label, length) in [
        ("detected", PhraseLength::Detect),
        ("12 stated", PhraseLength::Words(WordCount::new(12).unwrap())),
        ("24 stated", PhraseLength::Words(WordCount::new(24).unwrap())),
    ] {
        let rekey = Rekey::new(&container, length, password.clone_for_probe(), WorkFactor::default()).unwrap();
        let outcome = rekey.recover(
            &mut mhfe,
            Confirmation::Wallet(&reference),
            Some(false),
            &mut |_, _, _| Ok(()),
        );
        match outcome {
            Ok(confirmed) => println!("rekey, {label}: confirmed, {} words", confirmed.phrase().words()),
            Err(error) => println!("rekey, {label}: refused with {}", error.code()),
        }
    }
}

trait CloneForProbe {
    fn clone_for_probe(&self) -> Password;
}
impl CloneForProbe for Password {
    fn clone_for_probe(&self) -> Password {
        Password::new(PASSWORD).unwrap()
    }
}

/// AUD-024-FUN008, a stated length among two that pass: the public state ambiguous-12-21.
fn rekey_ambiguous() {
    let phrase = "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
    let mut mhfe = cipher();
    let container = encrypt(&mut mhfe, phrase, Suite::TwentyFourWords);
    let password = Password::new(PASSWORD).unwrap();
    let recovery = decrypt(&mut mhfe, &container, &password, PhraseLength::Detect, &mut |_, _| Ok(())).unwrap();
    let Recovery::Ambiguous(readings) = recovery else { panic!("one reading") };
    let longer = readings.iter().find(|reading| reading.words() == 21).unwrap();
    let fingerprint = master_fingerprint(longer.phrase(), "").unwrap();
    println!("fingerprint of the 21-word reading: {}", hex::encode(fingerprint));
    let reference = Reference::Fingerprint { fingerprint, passphrase: "" };
    let checked = recover_for_check(&mut mhfe, &container, &password, &reference, &mut |_, _| Ok(()))
        .unwrap()
        .compare(&reference)
        .unwrap();
    println!("rehearsal check: {checked:?}");
    let stated = PhraseLength::Words(WordCount::new(12).unwrap());
    let rekey = Rekey::new(&container, stated, password.clone_for_probe(), WorkFactor::default()).unwrap();
    let state = rekey
        .recover_state(&mut mhfe, Confirmation::BuiltInCheck, &mut |_, _, _| Ok(()))
        .unwrap();
    let built_in = rekey.confirm(&state, Confirmation::BuiltInCheck, Some(false), &mut |_, _, _| Ok(()));
    println!("rekey, 12 stated, built-in check: {:?}", built_in.err().map(|error| (error.code(), error.to_string())));
    let wallet = rekey.confirm(&state, Confirmation::Wallet(&reference), Some(false), &mut |_, _, _| Ok(()));
    println!("rekey, 12 stated, then the fingerprint: {:?}", wallet.err().map(|error| error.code()));
}

/// AUD-024-FUN010: the wallet-check reference on a 12-word original, right password.
fn wallet_check_on_short() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut mhfe = cipher();
    let container = encrypt(&mut mhfe, phrase, Suite::TwentyFourWords);
    let password = Password::new(PASSWORD).unwrap();
    let reference = Reference::WalletCheck { passphrase: "any" };
    let evidence = recover_for_check(&mut mhfe, &container, &password, &reference, &mut |_, _| Ok(()))
        .unwrap()
        .compare(&reference)
        .unwrap();
    println!("wallet-check reference, 12-word original, right password: {evidence:?}");
}

/// AUD-024-FUN012: U+212A KELVIN SIGN.
fn kelvin() {
    let typed = "\u{212a}ite";
    println!("as a chosen word: {:?}", WordWishes::new(&[(Place::Anywhere, typed)], &[]).map(|_| "accepted"));
    println!("as a word never to use: {:?}", WordWishes::new(&[], &[typed]).map(|_| "accepted"));
    let line = format!("{typed} abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    println!("as a phrase word: {:?}", check_phrase(&line).map_err(|error| error.code()));
    println!("Phrase::read_word: {:?}", Phrase::read_word(typed));
}

/// AUD-024-FUN003 and FUN011.
fn strength() {
    for text in [
        "1234 1234 1234 1234 1234",
        "abcdabcdabcdabcdabcdabcdabcdabcd",
        "abacus abdomen abdominal abide abiding aids",
        "abacus abdomen abdominal abide abiding",
    ] {
        let s = Strength::of(text);
        println!("{text:?}: {:.3} bits, weak: {}", s.bits(), s.is_weak());
    }
}

/// The words of the English list, read through the library.
fn list() -> Vec<&'static str> {
    (0..2048u16)
        .map(|n| {
            let mut bits = [0u8; 16];
            // The first word's 11 bits are the number; the words after it read the rest as zero.
            bits[0] = (n >> 3) as u8;
            bits[1] = ((n & 7) << 5) as u8;
            let phrase = Phrase::from_entropy(&bits).unwrap();
            let first = phrase.as_str().split(' ').next().unwrap().to_owned();
            Phrase::read_word(&first).unwrap()
        })
        .collect()
}

/// AUD-024-FUN001: two missing words of a 12-word container, a fingerprint that another candidate
/// shares. `base` is the public same-length-zero-12 container.
fn first_match() {
    let base = "renew alert there knife dose allow fashion casino kiwi lens sister bless";
    let words: Vec<&str> = base.split(' ').collect();
    let list = list();
    // Every candidate with words 1 and 2 missing, in the search's order.
    let mut candidates: Vec<(u16, u16)> = Vec::new();
    let rest: Vec<u16> = words[2..]
        .iter()
        .map(|word| list.iter().position(|w| w == word).unwrap() as u16)
        .collect();
    for first in 0..2048u16 {
        for second in 0..2048u16 {
            let numbers = [&[first, second][..], &rest[..]].concat();
            let mut bits = [0u8; 17];
            for (index, number) in numbers.iter().enumerate() {
                for bit in 0..11 {
                    if number >> (10 - bit) & 1 == 1 {
                        let at = index * 11 + bit;
                        bits[at / 8] |= 0x80 >> (at % 8);
                    }
                }
            }
            if Sha256::digest(&bits[..16])[0] >> 4 == bits[16] >> 4 {
                candidates.push((first, second));
            }
        }
    }
    println!("{} candidates", candidates.len());
    let text = |&(first, second): &(u16, u16)| {
        let mut phrase = vec![list[usize::from(first)], list[usize::from(second)]];
        phrase.extend(&words[2..]);
        phrase.join(" ")
    };
    let next = AtomicUsize::new(0);
    let prints: Mutex<HashMap<[u8; 4], usize>> = Mutex::new(HashMap::new());
    let pairs: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
    let threads: usize = std::env::var("PROBE_THREADS").ok().and_then(|n| n.parse().ok()).unwrap_or(3);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= candidates.len() {
                    break;
                }
                let print = master_fingerprint(&text(&candidates[index]), "").unwrap();
                let mut seen = prints.lock().unwrap();
                if let Some(&other) = seen.get(&print) {
                    pairs.lock().unwrap().push((other.min(index), other.max(index)));
                } else {
                    seen.insert(print, index);
                }
            });
        }
    });
    let pairs = pairs.into_inner().unwrap();
    println!("{} pairs of candidates share a fingerprint", pairs.len());
    let written = format!("? ? {}", words[2..].join(" "));
    let search = ContainerSearch::new(&written).unwrap();
    println!("written: {written}, candidates by the library: {}", search.count());
    for &(earlier, later) in pairs.iter().take(3) {
        let real = text(&candidates[later]);
        let fingerprint = master_fingerprint(&real, "").unwrap();
        let reference = Reference::Fingerprint { fingerprint, passphrase: "" };
        let found = search.search_decoy(&reference, 20, &mut |_, _| Ok(())).unwrap().unwrap();
        println!(
            "fingerprint {} of the real container {real}\n  search gives {}\n  other candidate {} ; right: {}",
            hex::encode(fingerprint),
            found.container.as_str(),
            text(&candidates[earlier]),
            found.container.as_str() == real
        );
    }
}

/// Addresses read and found on their standard paths, for an independent derivation to compare.
fn addresses() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for line in std::io::stdin().lines() {
        let line = line.unwrap();
        let mut parts = line.split_whitespace();
        let (Some(coin), Some(text)) = (parts.next(), parts.next()) else { continue };
        let coin: Coin = coin.parse().unwrap();
        // With "at" and a path, as `--path` looks: only there.
        let only: Option<mhfe::wallet::DerivationPath> = match (parts.next(), parts.next()) {
            (Some("at"), Some(path)) => Some(path.parse().unwrap()),
            _ => None,
        };
        match Address::parse(coin, text) {
            Ok(address) => {
                let found = mhfe::wallet::find_address(phrase, "", &address, only.as_ref(), SearchLimits::default());
                println!("{coin:?} {text}: {:?}", found.map(|path| path.map(|p| p.to_string())).map_err(|e| e.code()));
            }
            Err(error) => println!("{coin:?} {text}: refused {}", error.code()),
        }
    }
}

/// The candidates the library lists, for an independent count, and its refusals at the edges.
fn counts() {
    let phrases = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    ];
    for phrase in phrases {
        let words: Vec<&str> = phrase.split(' ').collect();
        assert!(check_phrase(phrase).is_ok(), "{phrase}");
        let last = format!("{} ?", words[..words.len() - 1].join(" "));
        let first = format!("? {}", words[1..].join(" "));
        let two = format!("? ? {}", words[2..].join(" "));
        println!(
            "{} words: last missing {}, first missing {}, two missing {}",
            words.len(),
            ContainerSearch::new(&last).unwrap().count(),
            ContainerSearch::new(&first).unwrap().count(),
            ContainerSearch::new(&two).unwrap().count()
        );
    }
    let written = "? ? there knife dose allow fashion casino kiwi lens sister bless";
    println!("{written}: {}", ContainerSearch::new(written).unwrap().count());
    for (label, written) in [
        ("three missing", "? ? ? knife dose allow fashion casino kiwi lens sister bless"),
        ("nothing marked", "renew alert there knife dose allow fashion casino kiwi lens sister bless"),
        ("13 tokens with a mark", "? alert there knife dose allow fashion casino kiwi lens sister bless bless"),
        ("word outside the list, no mark", "renew alert there knife dose allow fashion casino kiwi lens sister zzzz"),
    ] {
        println!("{label}: {:?}", ContainerSearch::new(written).map(|_| "accepted").map_err(|e| (e.code(), e.to_string())));
    }
}

/// Master key fingerprints of phrases with passphrases, for an independent derivation to compare:
/// each line of standard input is the passphrase in hexadecimal, a space and the phrase.
fn fingerprints() {
    for line in std::io::stdin().lines() {
        let line = line.unwrap();
        let (passphrase, phrase) = line.split_once(' ').unwrap();
        let passphrase = String::from_utf8(hex::decode(passphrase).unwrap()).unwrap();
        match master_fingerprint(phrase, &passphrase) {
            Ok(print) => println!("{}", hex::encode(print)),
            Err(error) => println!("refused {}", error.code()),
        }
    }
}

fn main() {
    let _ = (decrypt::<NativeArgon2> as *const () as usize, std::mem::size_of::<Recovery>(), std::mem::size_of::<CheckOutcome>());
    match std::env::args().nth(1).as_deref() {
        Some("rekey-reference") => rekey_reference(),
        Some("rekey-ambiguous") => rekey_ambiguous(),
        Some("wallet-check-on-short") => wallet_check_on_short(),
        Some("kelvin") => kelvin(),
        Some("strength") => strength(),
        Some("first-match") => first_match(),
        Some("addresses") => addresses(),
        Some("counts") => counts(),
        Some("fingerprints") => fingerprints(),
        _ => eprintln!("rekey-reference | wallet-check-on-short | kelvin | strength | first-match | addresses"),
    }
}
