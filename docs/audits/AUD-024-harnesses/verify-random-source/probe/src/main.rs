//! AUD-024 verify-random-source probe (commit b6fca69): what the public API does with a random
//! source that passes check_source's two 32-byte probes and then misbehaves. Public data only; no
//! Argon2. One line per expected behaviour, "PASS" or "FAIL"; exit code 1 if any FAIL.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use mhfe::new_password::PasswordRecipe;
use mhfe::random::{check_source, check_spread, RandomSource};
use mhfe::wallet_check::PhraseDraw;
use mhfe::MhfeError;

/// Two different, non-zero 32-byte probes, then `stuck` in every byte for ever. Counts its fills.
struct StuckAfterProbe {
    fills: Arc<AtomicU64>,
    stuck: u8,
}
impl RandomSource for StuckAfterProbe {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        let n = self.fills.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 2 {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(1).wrapping_mul(n as u8 * 3 + 1);
            }
        } else {
            bytes.fill(self.stuck);
        }
        Ok(())
    }
}

/// Writes only the first half of each buffer (a 32-bit LCG's top bytes), leaving the rest as it was.
struct HalfFill(u32);
impl RandomSource for HalfFill {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        let half = bytes.len().div_ceil(2);
        for b in &mut bytes[..half] {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}

/// Runs `work` on a thread and waits 5 s: Some(result), or None if it is still running.
fn within_5_s<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(Duration::from_secs(5)).ok()
}

fn main() {
    let mut failed = 0;
    let mut report = |id: &str, passed: bool, detail: String| {
        println!("{} {id}: {detail}", if passed { "PASS" } else { "FAIL" });
        if !passed {
            failed += 1;
        }
    };
    let probe = check_source(&mut StuckAfterProbe { fills: Arc::default(), stuck: 0xff });
    println!("note: check_source(source stuck on 0xff after its probes) = {:?}", probe.map_err(|e| e.code()));
    println!("note: check_source(half-filling source) = {:?}", check_source(&mut HalfFill(7)).map_err(|e| e.code()));

    // Expected (CORE-50): a source stuck after its probe ends a password draw with RANDOM_FAILED
    // within a stated limit. 0xff >= 228 (57 characters) and 0xffff >= 62,208 (7,776 words) are
    // refused by uniform_below every time.
    for (label, recipe) in [
        ("characters-16", PasswordRecipe::characters(16).unwrap()),
        ("words-5", PasswordRecipe::words(5).unwrap()),
        ("check-word", PasswordRecipe::check_word()),
    ] {
        let fills = Arc::new(AtomicU64::new(0));
        let counted = fills.clone();
        let made = within_5_s(move || {
            recipe
                .make(&mut StuckAfterProbe { fills: counted, stuck: 0xff })
                .map(|_| ())
                .map_err(|e| e.code())
        });
        let detail = match made {
            Some(result) => format!("make() returned {result:?}"),
            None => format!(
                "make() did not return within 5 s: {} fills and still drawing, no error",
                fills.load(Ordering::Relaxed)
            ),
        };
        report(&format!("stuck-source-ends-password-draw-{label}"), made == Some(Err("RANDOM_FAILED")), detail);
    }

    // Expected (CHECK-SEC-004): a source that repeats itself after its probe gives no phrase.
    for stuck in [0xffu8, 0x5a] {
        let drawn = PhraseDraw::unchecked()
            .draw(&mut StuckAfterProbe { fills: Arc::default(), stuck }, &mut |_| Ok(()))
            .map(|p| p.phrase().to_owned())
            .map_err(|e| e.code());
        report(
            &format!("stuck-source-gives-no-phrase-{stuck:02x}"),
            matches!(drawn, Err("RANDOM_FAILED")),
            format!("unchecked draw: {drawn:?}"),
        );
    }

    // Expected (CHECK-SEC-004): a source that fills only half of each buffer gives no phrase.
    let drawn = PhraseDraw::unchecked()
        .draw(&mut HalfFill(7), &mut |_| Ok(()))
        .map(|p| p.phrase().to_owned())
        .map_err(|e| e.code());
    report("half-filling-source-gives-no-phrase", matches!(drawn, Err("RANDOM_FAILED")), format!("unchecked draw: {drawn:?}"));

    // Controls, which pass at b6fca69: the full self-test's spread test refuses both sources, and
    // a working source makes a password at once.
    let spread_half = check_spread(&mut HalfFill(7)).map_err(|e| e.code());
    let spread_stuck = check_spread(&mut StuckAfterProbe { fills: Arc::new(AtomicU64::new(2)), stuck: 0xff }).map_err(|e| e.code());
    report(
        "control-spread-test-refuses-both",
        spread_half.is_err() && spread_stuck.is_err(),
        format!("check_spread(half-fill) = {spread_half:?}, check_spread(stuck) = {spread_stuck:?}"),
    );
    let mut state = 0x2545_f491u32;
    let mut working = move |bytes: &mut [u8]| {
        for b in bytes.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        Ok::<(), MhfeError>(())
    };
    let made = PasswordRecipe::characters(16).unwrap().make(&mut working).map(|p| p.text().len()).map_err(|e| e.code());
    report("control-working-source-makes-a-password", made == Ok(16), format!("make() = {made:?}"));
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
