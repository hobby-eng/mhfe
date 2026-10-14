//! AUD-024 verifier probe at b6fca69: the chosen-word reader (word_wishes::number_of) against the
//! phrase reader (phrase::parse via check_phrase/read_phrase) for non-ASCII letters whose Unicode
//! lower case is ASCII. Public data only: BIP39 English words and an all-"abandon" phrase body.
//! Exits 1 when the two readers disagree on any probed token (the defect), 0 when they agree.
use mhfe::word_wishes::{Place, WordWishes};

fn main() {
    // 1. Every non-ASCII scalar value whose Unicode lower case is all ASCII.
    let folding: Vec<String> = (0x80u32..=0x10FFFF)
        .filter_map(char::from_u32)
        .filter(|c| c.to_lowercase().collect::<String>().is_ascii())
        .map(|c| format!("U+{:04X} -> {:?}", c as u32, c.to_lowercase().collect::<String>()))
        .collect();
    println!("non-ASCII scalar values whose to_lowercase is ASCII: {}", folding.join(", "));

    // 2. A valid 12-word phrase that starts with "kite": the last word is searched.
    let body = "kite abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let lasts = [
        "about", "abandon", "ability", "able", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add",
        "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
    ];
    let phrase = lasts
        .iter()
        .map(|last| format!("{body} {last}"))
        .find(|text| mhfe::check_phrase(text).is_ok())
        .expect("a valid phrase starting with kite");
    println!("valid public phrase used: {phrase}");

    let mut disagreements = 0;
    for (label, typed) in [
        ("ASCII lower", "kite"),
        ("ASCII capitals", "KITE"),
        ("ASCII four letters", "Kite"),
        ("U+212A KELVIN SIGN + ite", "\u{212A}ite"),
        ("U+212A KELVIN SIGN + ITE", "\u{212A}ITE"),
        ("U+212A in a four-letter prefix (kitc -> kitchen)", "\u{212A}itc"),
    ] {
        let chosen = WordWishes::new(&[(Place::At(1), typed)], &[]).is_ok();
        let never = WordWishes::new(&[], &[typed]).is_ok();
        // Same number as "kite": then the library refuses it as also a word never to use.
        let with_kite = WordWishes::new(&[(Place::At(1), typed)], &["kite"])
            .err()
            .map(|error| error.to_string());
        let in_phrase = phrase.replacen("kite", typed, 1);
        let checked = mhfe::check_phrase(&in_phrase).map_err(|error| error.code());
        let read = mhfe::read_phrase(&in_phrase)
            .map(|text| text.split(' ').next().unwrap_or_default().to_owned())
            .map_err(|error| error.to_string());
        println!(
            "[{label}] typed={typed:?}\n  WordWishes::new(chosen At(1)) = {}\n  WordWishes::new(never_use) = {}\n  WordWishes::new(chosen At(1), never_use \"kite\") = {:?}\n  check_phrase(phrase with it as word 1) = {:?}\n  read_phrase(...) first word = {:?}",
            if chosen { "accepted" } else { "refused" },
            if never { "accepted" } else { "refused" },
            with_kite,
            checked,
            read
        );
        // A word typed the same way is accepted in a phrase iff the phrase reader resolves it;
        // the prefix case is only comparable as a word, not in this phrase.
        if !label.contains("prefix") && (chosen != checked.is_ok() || never != checked.is_ok()) {
            disagreements += 1;
            println!("  -> DISAGREE: chosen-word reader and phrase reader answer differently");
        }
    }
    // 3. The trim step: Unicode whitespace around a word, which the phrase reader splits off too.
    let spaced = "\u{3000}kite\u{00A0}";
    println!(
        "chosen word with U+3000/U+00A0 around it: {}; the same in a phrase: {:?}",
        if WordWishes::new(&[(Place::At(1), spaced)], &[]).is_ok() { "accepted" } else { "refused" },
        mhfe::check_phrase(&phrase.replacen("kite", spaced, 1)).map_err(|error| error.code())
    );
    println!("disagreements: {disagreements}");
    std::process::exit(i32::from(disagreements > 0));
}
