//! AUD-016 core public-API probes. Public BIP39 zero entropy only; no Argon2 work.
//! Compile against the reviewed library using the command in this folder's README.

use std::io::{self, Write};
use std::process::ExitCode;

use mhfe::search::ContainerSearch;
use mhfe::wallet::{find_address, Address, Coin, SearchLimits};
use mhfe::{phrase_from_entropy, MhfeError, Reference};

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("search-inputs") => search_inputs(),
        Some("wallet") => wallet(),
        Some("cancel") => cancel(),
        _ => ExitCode::from(2),
    }
}

fn search_inputs() -> ExitCode {
    let mut cases = 0;
    let mut failures = 0;
    for bytes in [16, 20, 24, 28, 32] {
        let original = phrase_from_entropy(&vec![0; bytes]).unwrap();
        let mut words: Vec<&str> = original.split_whitespace().collect();
        for position in 0..words.len() {
            let saved = words[position];
            words[position] = "?";
            let marked = ContainerSearch::new(&words.join(" ")).unwrap();
            assert_eq!(marked.missing(), [position + 1]);
            assert!(marked.count() > 0);
            words[position] = "notaword";
            cases += 1;
            match ContainerSearch::new(&words.join(" ")) {
                Ok(unknown) => {
                    assert_eq!(unknown.missing(), marked.missing());
                    assert_eq!(unknown.count(), marked.count());
                }
                Err(error) => {
                    failures += 1;
                    println!(
                        "FAIL {} words, position {}: unknown word rejected as {}",
                        words.len(),
                        position + 1,
                        error.code()
                    );
                }
            }
            words[position] = saved;
        }
    }
    println!("search-inputs: {cases} cases, {failures} failures");
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn wallet() -> ExitCode {
    let phrase = phrase_from_entropy(&[0; 16]).unwrap();
    // Published BIP49, BIP84 and BIP86 first receiving addresses of the BIP39 zero vector.
    for (text, path) in [
        ("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", "m/49'/0'/0'/0/0"),
        (
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "m/84'/0'/0'/0/0",
        ),
        (
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            "m/86'/0'/0'/0/0",
        ),
    ] {
        let address = Address::parse(Coin::Bitcoin, text).unwrap();
        let found = find_address(
            &phrase,
            "",
            &address,
            None,
            SearchLimits::new(1, 1).unwrap(),
        )
        .unwrap();
        assert_eq!(found.map(|path| path.to_string()).as_deref(), Some(path));
    }
    assert!(Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fya").is_err());
    println!("wallet: three published receiving addresses and one corrupt address passed");
    ExitCode::SUCCESS
}

fn cancel() -> ExitCode {
    let original = phrase_from_entropy(&[0; 32]).unwrap();
    let mut words: Vec<&str> = original.split_whitespace().collect();
    words[22] = "?";
    words[23] = "?";
    let search = ContainerSearch::new(&words.join(" ")).unwrap();
    let address = Address::parse(Coin::Bitcoin, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT").unwrap();
    let reference = Reference::Address {
        address: &address,
        passphrase: "",
        path: None,
        limits: SearchLimits::default(),
    };
    println!("PREPARED {} candidates", search.count());
    io::stdout().flush().unwrap();
    let outcome = search.search_decoy(&reference, SearchLimits::MOST, &mut |_, _| {
        // The watchdog starts its deadline only once cancellation has actually been requested.
        println!("CANCEL_REQUESTED");
        io::stdout().flush().unwrap();
        Err(MhfeError::Cancelled)
    });
    assert!(matches!(outcome, Err(MhfeError::Cancelled)));
    println!("CANCEL_RETURNED");
    ExitCode::SUCCESS
}
