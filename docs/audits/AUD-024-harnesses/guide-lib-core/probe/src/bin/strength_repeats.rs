//! AUD-024 probe (guide-lib-core): the public `Strength::of` on passwords that repeat one short
//! group, with and without spaces, against the group once. src/strength.rs:1-6 reads repeats
//! "each counting what an attacker who tries such parts must guess", and README.md:183-185 says
//! the estimator recognises repetitions and sequences; WEAK_BELOW_BITS is 50. Public test text
//! only. Exits 1 when "1234 1234 1234 1234 1234" or "1234" eight times without spaces is not
//! rated weak.
use mhfe::strength::Strength;

fn main() {
    let mut failed = false;
    for group in ["1234", "2024", "qwer", "zzzz", "abcd", "staple"] {
        let once = Strength::of(group).bits();
        for (times, separator) in [(3usize, " "), (5, " "), (8, " "), (8, "")] {
            let text = vec![group; times].join(separator);
            let strength = Strength::of(&text);
            println!(
                "{text:?}: {:.2} bits, weak = {} (the group once: {once:.2})",
                strength.bits(),
                strength.is_weak()
            );
            let pinned = group == "1234" && ((times, separator) == (5, " ") || (times, separator) == (8, ""));
            if pinned && !strength.is_weak() {
                failed = true;
            }
        }
    }
    if failed {
        println!("FAIL: a repeated group of four characters is not rated weak");
        std::process::exit(1);
    }
    println!("OK");
}
