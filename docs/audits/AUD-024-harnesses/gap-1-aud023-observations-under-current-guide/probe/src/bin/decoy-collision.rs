//! AUD-024 harness (gap-1-aud023-observations-under-current-guide): in a two-word decoy search of a 12-word container phrase with a master key
//! fingerprint, the library returns the first candidate whose fingerprint matches, so when two
//! candidates share the fingerprint it can return the wrong container and never says that another
//! candidate matched. Public test data only: the candidates are "abandon" x 10 plus two words.
use std::sync::Mutex;

use mhfe::Reference;
use mhfe::search::{ContainerSearch, DECOY_SCAN_GAP};
use mhfe::wallet::master_fingerprint;

const LIST: usize = 2048;

fn main() {
    let words = bip39_words();
    let prefix = "abandon ".repeat(10);
    // Every candidate in the library's order: the first missing word slowest.
    let found: Mutex<Vec<(usize, [u8; 4])>> = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|scope| {
        for t in 0..threads {
            let (found, words, prefix) = (&found, &words, &prefix);
            scope.spawn(move || {
                let mut local = Vec::new();
                for first in (t..LIST).step_by(threads) {
                    for second in 0..LIST {
                        let phrase = format!("{prefix}{} {}", words[first], words[second]);
                        if let Ok(fingerprint) = master_fingerprint(&phrase, "") {
                            local.push((first * LIST + second, fingerprint));
                        }
                    }
                }
                found.lock().unwrap().extend(local);
            });
        }
    });
    let mut all = found.into_inner().unwrap();
    all.sort_by_key(|&(order, _)| order);
    println!("candidates passing the BIP39 checksum: {}", all.len());
    let mut by_fingerprint = all.clone();
    by_fingerprint.sort_by_key(|&(order, fingerprint)| (fingerprint, order));
    let pairs: Vec<_> = by_fingerprint
        .windows(2)
        .filter(|pair| pair[0].1 == pair[1].1)
        .map(|pair| (pair[0], pair[1]))
        .collect();
    println!("pairs of candidates with the same master key fingerprint: {}", pairs.len());
    let text = |order: usize| format!("{prefix}{} {}", words[order / LIST], words[order % LIST]);
    let written = format!("{prefix}? ?");
    let search = ContainerSearch::new(&written).expect("two marked words");
    println!("ContainerSearch::new({written:?}).count() = {}", search.count());
    let mut wrong = 0;
    for ((first, fingerprint), (second, _)) in &pairs {
        let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
        let last_two = |order: usize| format!("{} {}", words[order / LIST], words[order % LIST]);
        println!("fingerprint {hex}: candidate #{first} [{}] and candidate #{second} [{}]",
            last_two(*first), last_two(*second));
        // The owner's container is the later candidate; the fingerprint is the one shown under it.
        let reference = Reference::Fingerprint { fingerprint: *fingerprint, passphrase: "" };
        let result = search
            .search_decoy(&reference, DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .expect("the search runs");
        let Some(result) = result else {
            println!("  search_decoy: nothing found");
            continue;
        };
        let returned = result.container.to_string();
        let is_owner = returned == text(*second);
        println!("  owner's container is #{second}; search_decoy returned {} words {:?} -> {}",
            result.words.len(),
            result.words,
            if is_owner { "the owner's container" } else { "ANOTHER container (the earlier candidate)" });
        if !is_owner {
            wrong += 1;
        }
    }
    println!("RESULT: {wrong} of {} searches returned another container than the owner's, with no sign that a second candidate matched", pairs.len());
    std::process::exit(if wrong > 0 { 1 } else { 0 });
}

fn bip39_words() -> Vec<&'static str> {
    bip39::Language::English.word_list().to_vec()
}
