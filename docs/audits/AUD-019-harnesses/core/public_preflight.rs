//! AUD-019 bounded public API probes; synthetic data and no Argon2 allocation or call.
//! These check validation and early rekey refusals, not cryptographic security.

use mhfe::rekey::Rekey;
use mhfe::wallet::{master_fingerprint, parse_fingerprint};
use mhfe::{
    other_detected_lengths, phrase_from_entropy, Confirmation, ConfirmationNeeded, ContainerFacts,
    Password, PhraseLength, Reference, WordCount, WorkFactor,
};

fn main() {
    let mut checks = 0usize;
    let short = phrase_from_entropy(&[0; 16]).unwrap();
    let full = phrase_from_entropy(&[0; 32]).unwrap();
    for container in [&short, &full] {
        for stated in [None, Some(12), Some(15), Some(18), Some(21), Some(24)] {
            let length = stated.map_or(PhraseLength::Detect, |n| {
                PhraseLength::Words(WordCount::new(n).unwrap())
            });
            let result = Rekey::new(
                container,
                length,
                Password::new("AUD019 public synthetic password").unwrap(),
                WorkFactor::default(),
            );
            if container == &short && stated.is_some_and(|n| n != 12) {
                assert!(result.is_err());
            } else {
                let rekey = result.unwrap();
                let built_in = container == &full && stated.is_some_and(|n| n < 24);
                assert_eq!(
                    rekey.confirmation_needed(),
                    if built_in {
                        ConfirmationNeeded::BuiltInCheck
                    } else {
                        ConfirmationNeeded::WalletOrOwner
                    }
                );
                let confirmation =
                    rekey.check_confirmation(&Confirmation::BuiltInCheck, Some(false));
                if built_in {
                    assert_eq!(confirmation.unwrap(), false);
                } else {
                    assert_eq!(confirmation.unwrap_err().code(), "REFERENCE_REQUIRED");
                }
                assert!(rekey
                    .check_confirmation(&Confirmation::Owner, None)
                    .is_err());
                assert_eq!(
                    rekey
                        .check_confirmation(&Confirmation::Owner, Some(true))
                        .unwrap(),
                    true
                );
                checks += 4;
            }
            checks += 1;
        }
    }

    let detected = Rekey::new(
        &full,
        PhraseLength::Detect,
        Password::new("AUD019 public synthetic password").unwrap(),
        WorkFactor::default(),
    )
    .unwrap();
    let source_check = Reference::WalletCheck {
        passphrase: "public synthetic passphrase",
    };
    assert_eq!(
        detected
            .check_confirmation(&Confirmation::Wallet(&source_check), Some(true))
            .unwrap_err()
            .code(),
        "REFERENCE_REQUIRED"
    );
    checks += 1;

    assert_eq!(
        Password::new("\u{00e9}").unwrap().as_bytes(),
        Password::new("e\u{0301}").unwrap().as_bytes()
    );
    assert_eq!(
        Password::new("x".repeat(1024).as_str())
            .unwrap()
            .as_bytes()
            .len(),
        1024
    );
    assert!(Password::new("x".repeat(1025).as_str()).is_err());
    assert!(Password::new("").is_err());
    for c in (0..=0x1f).chain(0x7f..=0x9f).chain([0x2028, 0x2029]) {
        let input = format!("public{}data", char::from_u32(c).unwrap());
        assert!(Password::new(&input).is_err());
        checks += 1;
    }
    assert!(Password::new("\u{e000}").is_ok());
    assert!(Password::new("\u{fdd0}").is_err());
    assert!(Password::new("\u{10ffff}").is_err());
    assert!(
        !format!("{:?}", Password::new("synthetic secret marker").unwrap())
            .contains("synthetic secret marker")
    );
    checks += 8;

    // Public counter states retained from earlier audits; Python hashlib independently
    // checks their complete verifier bytes in source_review.py, without a cipher replay.
    for (bytes, detected) in [
        (
            decode("4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad"),
            vec![12, 21],
        ),
        (
            decode("4d48464520616d626967756f00000000d7215b3cc350c32cc955fd4e3e272edf"),
            vec![15, 21],
        ),
        (
            decode("4d48464520616d626967756f7573207400000000643a0b3e565fd3c1659f6749"),
            vec![18, 21],
        ),
    ] {
        let original = phrase_from_entropy(&bytes).unwrap();
        assert_eq!(other_detected_lengths(&original).unwrap(), detected);
        checks += 1;
    }

    let facts = ContainerFacts::read(&full).unwrap();
    assert!(facts.opens_hidden_wallets());
    assert!(!ContainerFacts::read(&short).unwrap().opens_hidden_wallets());
    assert_eq!(
        master_fingerprint(&short, "").unwrap(),
        [0x73, 0xc5, 0xda, 0x0a]
    );
    assert_eq!(
        master_fingerprint(&short, "\u{00e9}").unwrap(),
        master_fingerprint(&short, "e\u{0301}").unwrap()
    );
    let wrong_field = "AUD019 public wrong-field marker";
    let refusal = parse_fingerprint(wrong_field).unwrap_err();
    assert!(!refusal.to_string().contains(wrong_field));
    checks += 5;
    println!("public-preflight: {checks} assertions passed; no Argon2 engine constructed");
}

fn decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
