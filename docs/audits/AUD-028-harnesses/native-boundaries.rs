//! AUD-028 public scalar-boundary probes; no Argon2 engine is instantiated.
use mhfe::{eff::EffList, word_wishes::WordWishes};

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("odds") => {
            let draws = WordWishes::none().odds(u32::MAX).expected_draws();
            println!("expected draws for u32::MAX check bits: {draws}");
            assert!(draws >= 1.0, "a restrictive check cannot need fewer than one draw");
        }
        Some("index") => {
            // A public out-of-range request must refuse; a panic demonstrates this baseline bug.
            let _ = EffList::get().word(7_776);
            panic!("an out-of-range lookup was accepted instead of refused");
        }
        _ => panic!("expected the public probe mode odds or index"),
    }
}
