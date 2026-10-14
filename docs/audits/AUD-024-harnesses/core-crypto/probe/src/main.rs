//! AUD-024 core-crypto probes against the public API of mhfe at b6fca69. Public test data only.
use std::time::Instant;

use mhfe::random::{uniform_below, RandomSource};
use mhfe::MhfeError;
use sha2::{Digest, Sha256};

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    match which.as_str() {
        "uniform-below-panics" => uniform_below_panics(),
        "uniform-below-hangs" => uniform_below_hangs(),
        "kelvin" => kelvin(),
        "password-scan" => password_scan(),
        "strength-time" => strength_time(),
        "check-word-trailing-space" => check_word_trailing_space(),
        "read-phrases" => read_phrases(),
        "repair" => repair_lines(),
        "dice-count" => dice_count(),
        "short-fill" => short_fill(),
        "findings" => findings(),
        "phrases-of-entropy" => phrases_of_entropy(),
        other => panic!("unknown probe {other}"),
    }
}

/// uniform_below is a public library function; a bound outside 2..=65536 is wrong input.
fn uniform_below_panics() {
    let mut source = |bytes: &mut [u8]| {
        bytes.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 1);
        Ok::<(), MhfeError>(())
    };
    for n in [1usize, 0, 65_537] {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            uniform_below(&mut source, n)
        }));
        match result {
            Ok(value) => println!("n={n}: returned {value:?}"),
            Err(_) => println!("n={n}: PANICKED instead of returning an error"),
        }
    }
}

/// A source that passes the probe of check_source (two different non-zero blocks) and then gives
/// 0xff for ever: every byte is above 228, the last full multiple of 57, so each draw is refused.
struct StuckAfterProbe {
    calls: u64,
}
impl RandomSource for StuckAfterProbe {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self.calls += 1;
        if self.calls <= 2 {
            bytes.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8) ^ (self.calls as u8 * 0x5a));
        } else {
            bytes.fill(0xff);
        }
        Ok(())
    }
}

fn uniform_below_hangs() {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut source = StuckAfterProbe { calls: 0 };
        let made = mhfe::new_password::PasswordRecipe::characters(16)
            .unwrap()
            .make(&mut source)
            .map(|password| password.text().len());
        let _ = sender.send((made, source.calls));
    });
    match receiver.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok((made, calls)) => println!("make() returned {made:?} after {calls} fills"),
        Err(_) => println!("make() did not return within 10 s: no error, no limit (still drawing)"),
    }
}

/// The chosen-word reader against the phrase reader for U+212A KELVIN SIGN in place of "k".
fn kelvin() {
    use mhfe::word_wishes::{Place, WordWishes};
    let typed = "\u{212A}ite";
    let wish = WordWishes::new(&[(Place::At(1), typed)], &[]);
    println!("WordWishes::new(At(1), \"\\u{{212A}}ite\") = {}", if wish.is_ok() { "accepted (read as kite)" } else { "refused" });
    let never = WordWishes::new(&[], &[typed]);
    println!("WordWishes::new(never_use \"\\u{{212A}}ite\") = {}", if never.is_ok() { "accepted" } else { "refused" });
    // The same word in a phrase: a valid 12-word phrase that starts with "kite", read by both.
    let kite = mhfe::phrase_from_entropy(&[0u8; 16]).unwrap();
    let mut words: Vec<String> = kite.split(' ').map(str::to_owned).collect();
    words[0] = "kite".to_owned();
    let mut found = None;
    for last in ["about", "abandon", "ability", "able", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act"] {
        words[11] = last.to_owned();
        let text = words.join(" ");
        if mhfe::check_phrase(&text).is_ok() {
            found = Some(text);
            break;
        }
    }
    let phrase = found.expect("a valid phrase starting with kite");
    println!("check_phrase(\"kite ...\") = {:?}", mhfe::check_phrase(&phrase).map_err(|e| e.code()));
    let with_kelvin = phrase.replacen("kite", typed, 1);
    println!(
        "check_phrase(\"\\u{{212A}}ite ...\") = {:?}",
        mhfe::check_phrase(&with_kelvin).map_err(|e| e.code())
    );
}

/// Every Unicode scalar value through Password::new: status and encoded bytes, hashed in the
/// same format as password_scan.py writes with unicodedata2.
fn password_scan() {
    let mut hasher = Sha256::new();
    let mut accepted = 0u32;
    let mut refused = [0u32; 3];
    for cp in 0u32..=0x10FFFF {
        let Some(c) = char::from_u32(cp) else { continue };
        let text = c.to_string();
        let line = match mhfe::Password::new(&text) {
            Ok(p) => {
                accepted += 1;
                format!("{cp:x} ok {}\n", hex::encode(p.as_bytes()))
            }
            Err(MhfeError::ControlCharacterInPassword) => {
                refused[0] += 1;
                format!("{cp:x} control\n")
            }
            Err(MhfeError::UnassignedCharacter) => {
                refused[1] += 1;
                format!("{cp:x} unassigned\n")
            }
            Err(other) => {
                refused[2] += 1;
                format!("{cp:x} other {}\n", other.code())
            }
        };
        hasher.update(line.as_bytes());
    }
    println!("accepted {accepted} control {} unassigned {} other {}", refused[0], refused[1], refused[2]);
    println!("sha256 {}", hex::encode(hasher.finalize()));
}

fn strength_time() {
    for count in [1_000usize, 20_000, 200_000] {
        let text = "zoom ".repeat(count);
        let start = Instant::now();
        let bits = mhfe::strength::Strength::of(&text).bits();
        println!("Strength::of(\"zoom \" x {count}, {} bytes) = {bits} bits in {:?}", text.len(), start.elapsed());
    }
    let text = "zoom ".repeat(200_000);
    let start = Instant::now();
    let _ = mhfe::check_word::PasswordReview::of(&text);
    println!("PasswordReview::of(1,000,000 bytes) in {:?}", start.elapsed());
}

fn check_word_trailing_space() {
    use mhfe::check_word::{PasswordReview, ReviewChoice};
    // The third public vector with its third word left out and a space at the end.
    let typed = "jovial trailing pavilion cresting ninth ";
    let review = PasswordReview::of(typed);
    println!("reading {:?}, repairs {}", review.reading(), review.repairs().len());
    for repair in review.repairs() {
        let repaired = review.apply(ReviewChoice::Repair(repair.position())).unwrap();
        println!("repair at {} -> {:?}", repair.position(), &*repaired);
    }
}

/// Reads one phrase per line of standard input (hex of its UTF-8 bytes) and prints what
/// read_phrase gives: the canonical words or the error code.
fn read_phrases() {
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        let bytes = hex::decode(line.unwrap().trim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        match mhfe::read_phrase(&text) {
            Ok(words) => println!("ok {}", &*words),
            Err(error) => println!("err {}", error.code()),
        }
    }
}

/// Prints the phrase of each entropy (hex per line on standard input).
fn phrases_of_entropy() {
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        let bytes = hex::decode(line.unwrap().trim()).unwrap();
        match mhfe::phrase_from_entropy(&bytes) {
            Ok(words) => println!("ok {}", &*words),
            Err(error) => println!("err {}", error.code()),
        }
    }
}

/// Repairs each line of standard input, "container phrase<TAB>card", and prints the repaired
/// container or the error code.
fn repair_lines() {
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let (written, card) = line.split_once('\t').unwrap();
        match mhfe::repair::repair(written, card) {
            Ok(repaired) => println!("ok {}", repaired.container),
            Err(error) => println!("err {}", error.code()),
        }
    }
}

/// Dice rolls of valid digits but one group too many or too few for the recipe.
fn dice_count() {
    use mhfe::new_password::PasswordRecipe;
    for (recipe, name, rolls) in [
        (PasswordRecipe::words(2).unwrap(), "2 words", "11111 22222 33333"),
        (PasswordRecipe::check_word(), "check word", "11111 11112 11113 11114 11115 11116"),
        (PasswordRecipe::words(2).unwrap(), "2 words", "11111"),
    ] {
        match recipe.make_from_rolls(rolls) {
            Ok(password) => println!("{name} with {rolls:?}: made {:?}", password.text()),
            Err(error) => println!("{name} with {rolls:?}: {}: {error}", error.code()),
        }
    }
}

/// A source that fills only the first half of every buffer it is given, with varying bytes.
struct HalfFill {
    counter: u8,
}
impl RandomSource for HalfFill {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        let half = bytes.len().div_ceil(2);
        for byte in &mut bytes[..half] {
            self.counter = self.counter.wrapping_mul(29).wrapping_add(71);
            *byte = self.counter;
        }
        Ok(())
    }
}

fn short_fill() {
    let probe = mhfe::random::check_source(&mut HalfFill { counter: 1 });
    println!("check_source(half-filling source) = {:?}", probe.map_err(|e| e.code()));
    let drawn = mhfe::wallet_check::PhraseDraw::unchecked().draw(&mut HalfFill { counter: 1 }, &mut |_| Ok(()));
    match drawn {
        Ok(phrase) => println!("unchecked draw gives: {}", phrase.phrase()),
        Err(error) => println!("unchecked draw refused: {}", error.code()),
    }
    let spread = mhfe::random::check_spread(&mut HalfFill { counter: 1 });
    println!("check_spread (full self-test only) = {:?}", spread.map_err(|e| e.code()));
}

/// The behaviour the AUD-024 core-crypto findings expect, one line each: "PASS" or "FAIL", and
/// exit code 1 if any fails. At b6fca69 every one fails.
fn findings() {
    let mut failed = 0;
    let mut report = |id: &str, passed: bool, detail: String| {
        println!("{} {id}: {detail}", if passed { "PASS" } else { "FAIL" });
        if !passed {
            failed += 1;
        }
    };
    // Library code returns errors (RUST-05): a bound outside 2..=65536 is refused, not a panic.
    let mut counter = |bytes: &mut [u8]| {
        bytes.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 1);
        Ok::<(), MhfeError>(())
    };
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        uniform_below(&mut counter, 1).map_err(|e| e.code())
    }));
    std::panic::set_hook(hook);
    report(
        "uniform-below-refuses-a-bad-bound",
        matches!(outcome, Ok(Err(_))),
        format!("uniform_below(source, 1) = {}", match outcome {
            Ok(result) => format!("{result:?}"),
            Err(_) => "panic".to_owned(),
        }),
    );
    // A source that is stuck after the probe ends in RANDOM_FAILED, within a limit (CORE-50).
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let made = mhfe::new_password::PasswordRecipe::characters(16)
            .unwrap()
            .make(&mut StuckAfterProbe { calls: 0 })
            .map(|_| ())
            .map_err(|e| e.code());
        let _ = sender.send(made);
    });
    let stuck = receiver.recv_timeout(std::time::Duration::from_secs(10));
    report(
        "stuck-source-is-refused",
        matches!(stuck, Ok(Err("RANDOM_FAILED"))),
        format!("make() with a source stuck after its probe: {stuck:?}"),
    );
    // A source that fills half of each buffer gives no phrase.
    let drawn = mhfe::wallet_check::PhraseDraw::unchecked()
        .draw(&mut HalfFill { counter: 1 }, &mut |_| Ok(()))
        .map(|phrase| phrase.phrase().to_owned())
        .map_err(|e| e.code());
    report(
        "half-filling-source-is-refused",
        matches!(drawn, Err("RANDOM_FAILED")),
        format!("unchecked draw: {drawn:?}"),
    );
    // One rule reads a word typed from the BIP39 list (CORE-10): the chosen word refuses what the
    // phrase refuses.
    use mhfe::word_wishes::{Place, WordWishes};
    let wish = WordWishes::new(&[(Place::At(1), "\u{212A}ite")], &[]).is_ok();
    report(
        "chosen-word-read-as-a-phrase-word",
        !wish,
        format!("WordWishes::new with U+212A KELVIN SIGN + \"ite\" accepted: {wish}"),
    );
    // A dice text with one group too many names the count, not a word the password lacks.
    let refused = mhfe::new_password::PasswordRecipe::words(2)
        .unwrap()
        .make_from_rolls("11111 22222 33333")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    report(
        "dice-group-count-is-named",
        !refused.is_empty() && !refused.contains("word 3"),
        format!("make_from_rolls(2 words, 3 groups): {refused}"),
    );
    // The check word adds no randomness (MHFE-PASSWORD-CHECK-1, "Properties"): the estimate of a
    // check-word password is the recipe's 64.6 bits, not six dice words' 77.6.
    let recipe = mhfe::new_password::PasswordRecipe::check_word();
    let password = recipe.make_from_rolls("35214 62431 15543 44126 21365").unwrap();
    let estimate = mhfe::strength::Strength::of(password.text()).bits();
    report(
        "check-word-adds-no-strength",
        (estimate - recipe.bits()).abs() < 0.01,
        format!("Strength::of({:?}) = {estimate} bits, recipe {} bits", password.text(), recipe.bits()),
    );
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
