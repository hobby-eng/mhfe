//! Public, synthetic inputs only; this probe never creates an Argon2 engine.
use mhfe::vectors::PUBLIC_INPUTS;
use mhfe::wallet::BitcoinAddress;

fn main() {
    let address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    for text in [address.to_owned(), address.to_ascii_uppercase()] {
        println!("address {text}: {:?}", text.parse::<BitcoinAddress>());
    }
    let mut input = PUBLIC_INPUTS.into_iter().next().unwrap();
    input.name = "synthetic-mutation-probe";
    input.password = "synthetic password not in the public corpus";
    input.phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    assert!(!PUBLIC_INPUTS
        .iter()
        .any(|item| item.password == input.password));
    assert!(!PUBLIC_INPUTS.iter().any(|item| item.phrase == input.phrase));
    assert_eq!(mhfe::check_phrase(input.phrase).unwrap(), 12);
    mhfe::Password::new(input.password).unwrap();
    println!("PublicInput fields accept arbitrary valid synthetic inputs outside PUBLIC_INPUTS.");
    println!("No MHFE computation or vector generation was performed.");
    // This is a conformance probe: exposing writable fields is itself the demonstrated defect.
    std::process::exit(1);
}
