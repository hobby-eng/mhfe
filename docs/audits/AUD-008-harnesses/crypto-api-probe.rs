//! AUD-008: public, no-Argon2 probes for source-check width and repair-card claims.

fn main() {
    let short_result = mhfe::wallet_check::passes(&[0u8; 16], "TREZOR");
    let short_accepted = short_result.is_ok();
    let short_passes = short_result.unwrap_or(false);
    println!(
        "{{\"probe\":\"source-check-128-bit-input\",\"accepted\":{short_accepted},\"passes\":{short_passes}}}"
    );

    // These two valid BIP39 mnemonics differ only in their final symbol. With k = 2,
    // plate A and B's card are within one unknown-symbol error of B's RS codeword.
    let prefix = "abandon ".repeat(23);
    let plate_a = format!("{prefix}art");
    let plate_b = format!("{prefix}diesel");
    assert_eq!(mhfe::check_phrase(&plate_a).unwrap(), 24);
    assert_eq!(mhfe::check_phrase(&plate_b).unwrap(), 24);
    let card_b = mhfe::repair::repair_words(&plate_b, 2).unwrap();
    let repaired = mhfe::repair::repair(&plate_a, &card_b).unwrap();
    assert_eq!(repaired.container, plate_b);
    assert_eq!(repaired.plate_words, [24]);
    assert!(repaired.card_words.is_empty());
    println!(
        "{{\"probe\":\"another-plates-card\",\"card\":\"{card_b}\",\"accepted\":true,\"plateWordChanged\":24,\"resultIsPlateB\":true}}"
    );
}
