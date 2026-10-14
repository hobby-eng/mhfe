//! AUD-024 verifier probe: public library functions of mhfe that panic on wrong input instead of
//! returning an error (RUST-05, CORE-22). Each call runs under catch_unwind; the probe prints one
//! line per call and exits 1 when any call panicked.

use std::convert::Infallible;
use std::panic::{self, AssertUnwindSafe};

use mhfe::memory::{LockedBytes, LockedText};
use mhfe::random::uniform_below;
use mhfe::MhfeError;

/// A deterministic byte stream (public, not secret): a counter.
fn counter() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    let mut next = 0u8;
    move |bytes: &mut [u8]| {
        for byte in bytes {
            *byte = next;
            next = next.wrapping_add(37);
        }
        Ok(())
    }
}

/// Runs `call`; returns its debug text or the panic message.
fn outcome<T: std::fmt::Debug>(call: impl FnOnce() -> T) -> Result<String, String> {
    panic::catch_unwind(AssertUnwindSafe(call))
        .map(|value| format!("{value:?}"))
        .map_err(|payload| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-text panic>".to_owned())
        })
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let mut panicked = 0;
    let mut report = |name: String, result: Result<String, String>| match result {
        Ok(value) => println!("{name}: returned {value}"),
        Err(message) => {
            panicked += 1;
            println!("{name}: PANICKED: {message}");
        }
    };
    // In range: 2 and 65,536 are the documented ends.
    for n in [2usize, 57, 7776, 65_536] {
        let mut source = counter();
        report(format!("uniform_below(n={n})"), outcome(|| uniform_below(&mut source, n)));
    }
    // Out of range: wrong input, which CORE-22 says fails with an Err.
    for n in [0usize, 1, 65_537, usize::MAX] {
        let mut source = counter();
        report(format!("uniform_below(n={n})"), outcome(|| uniform_below(&mut source, n)));
    }
    // memory::LockedText::build and LockedBytes::build with a fill that writes past `capacity`.
    report(
        "LockedText::build(capacity=4, fill writes 41 bytes)".to_owned(),
        outcome(|| {
            LockedText::build::<Infallible>(4, |text| {
                text.push_str("public text longer than the four reserved");
                Ok(())
            })
            .map(|text| text.capacity())
        }),
    );
    report(
        "LockedBytes::build(capacity=4, fill writes 41 bytes)".to_owned(),
        outcome(|| {
            LockedBytes::build::<Infallible>(4, |bytes| {
                bytes.extend_from_slice(b"public text longer than the four reserved");
                Ok(())
            })
            .map(|bytes| bytes.is_locked())
        }),
    );
    println!("{panicked} call(s) panicked instead of returning");
    std::process::exit(i32::from(panicked > 0));
}
