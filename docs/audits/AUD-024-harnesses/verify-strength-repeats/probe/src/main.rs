//! AUD-024 verifier probe: public mhfe::strength::Strength::of on repeated groups.
use mhfe::strength::{Strength, WEAK_BELOW_BITS};

fn show(text: &str) -> Strength {
    let s = Strength::of(text);
    println!("{:>8.3} bits weak={:<5} {:?}", s.bits(), s.is_weak(), text);
    s
}

fn main() {
    println!("WEAK_BELOW_BITS = {WEAK_BELOW_BITS}");
    let mut fail = false;
    // Character repeats and word repeats: recognised.
    show("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    show("staple");
    show("staplestaplestaplestaple");
    show("staple staple staple staple");
    show("password password password password");
    // Repeated groups that are not list words.
    for text in [
        "1234 1234 1234 1234 1234",
        "12341234123412341234123412341234",
        "2024 2024 2024 2024 2024",
        "20242024202420242024202420242024",
        "abcdabcdabcdabcdabcdabcdabcdabcd",
        "abcabcabcabcabcabcabcabcabcabc",
        "xyzxyzxyzxyzxyzxyzxyzxyz",
        "qwer qwer qwer qwer qwer",
        "zzzz zzzz zzzz zzzz zzzz",
        "Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!",
    ] {
        let s = show(text);
        if !s.is_weak() {
            fail = true;
        }
    }
    // Not a repeat of one group, shown only: runs separated by spaces.
    show("1111 2222 3333 4444 5555");
    // A group once, for comparison.
    for g in ["1234", "2024", "abcd", "abc", "xyz", "qwer", "zzzz", "Ab1!"] {
        show(g);
    }
    // One character repeated: each repeat counts 1 bit, so a long enough run is not weak.
    for n in [46usize, 47, 100] {
        let text = "a".repeat(n);
        let s = Strength::of(&text);
        println!("{:>8.3} bits weak={:<5} \"a\" x {n}", s.bits(), s.is_weak());
    }
    // Long input: only the first 100 characters are read.
    let long = "zzzz ".repeat(1600);
    println!("{} bytes of 'zzzz ': {:.3} bits", long.len(), Strength::of(&long).bits());
    if fail {
        println!("FAIL: at least one repeated group that is not a list word is rated 50 bits or more");
        std::process::exit(1);
    }
    println!("OK");
}
