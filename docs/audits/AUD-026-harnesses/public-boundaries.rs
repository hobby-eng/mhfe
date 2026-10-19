// AUD-026 public Rust API refusals. Public/synthetic inputs only; no Argon2 work.
use mhfe::check_word::PasswordReview;
use mhfe::new_password::Millibits;
use mhfe::wallet::{Address, Coin, DerivationPath, SearchLimits};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn main() {
    assert_eq!(Millibits::words(1).get(), 12_925);
    assert_eq!(Millibits::characters(1).get(), 5_833);
    let mut defects = 0;
    for (label, calculate) in [
        ("words", Millibits::words as fn(usize) -> Millibits),
        (
            "characters",
            Millibits::characters as fn(usize) -> Millibits,
        ),
    ] {
        let result = catch_unwind(|| calculate(std::hint::black_box(usize::MAX)));
        if result.is_err() {
            println!("DEFECT: {label}(usize::MAX) panicked");
            defects += 1;
        } else {
            println!("Returned {label}(usize::MAX); inspect exactness/overflow policy");
        }
    }
    let offered = PasswordReview::of("jovial trailing ? pavilion cresting ninth");
    let other = PasswordReview::of("x");
    assert!(!offered.repairs().is_empty());
    let repair = offered.repairs()[0].clone();
    let result = catch_unwind(AssertUnwindSafe(|| other.typed_word(&repair)));
    if result.is_err() {
        println!("DEFECT: typed_word accepted a foreign Repair then panicked");
        defects += 1;
    }
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let address =
        Address::parse(Coin::Bitcoin, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
    let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
    let calls = std::cell::Cell::new(0);
    let stopped = || {
        calls.set(calls.get() + 1);
        true
    };
    let result = address.find_until(phrase, "", Some(&path), SearchLimits::default(), &stopped);
    if result.as_ref().err().map(|e| e.code()) != Some("CANCELLED") {
        println!(
            "DEFECT: explicit-path cancellation ignored; callback calls={}, match={}",
            calls.get(),
            result.is_ok_and(|v| v.is_some())
        );
        defects += 1;
    }
    let normal = address.find_until(phrase, "", None, SearchLimits::default(), &|| true);
    assert_eq!(normal.unwrap_err().code(), "CANCELLED");
    println!("confirmed failing boundary cases: {defects}");
    std::process::exit(if defects == 0 { 0 } else { 1 });
}
