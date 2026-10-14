//! AUD-024 secrets-native harness: what `Debug` prints of the library's check-word review of a
//! password (src/check_word.rs, `#[derive(Clone, Debug, PartialEq, Eq)] pub struct Repair`),
//! beside a type that redacts (`Password`). The password is a public test value: five EFF words
//! and "?" in the place of its check word, which the review restores. Exits 1 when the Debug text
//! of a repair names the word it restores (the defect of AUD-024), 0 otherwise.
fn main() {
    let typed = "zookeeper zoning zoologist zoology zoom ?";
    let review = mhfe::check_word::PasswordReview::of(typed);
    println!("reading: {:?}", review.reading());
    let mut named = false;
    for repair in review.repairs() {
        let shown = format!("{repair:?}");
        println!("Debug of a Repair: {shown}");
        println!("the word it restores: {}", repair.word());
        named |= shown.contains(repair.word());
    }
    let password = mhfe::Password::new("public test password").expect("a valid test password");
    println!("Debug of a Password: {password:?}");
    if named {
        println!("FAIL: Debug of a Repair names a word of the password");
    } else {
        println!("PASS: Debug of a Repair names no word of the password");
    }
    std::process::exit(i32::from(named));
}
