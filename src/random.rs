//! Randomness from the host. The library draws nothing by itself: the command-line tool passes the
//! operating system's generator and the browser binding passes `crypto.getRandomValues`, both as
//! a [`RandomSource`]. Every draw goes through [`uniform_below`], so no index is biased.

use zeroize::Zeroizing;

use crate::MhfeError;

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
mod health;
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub(crate) use health::ScriptedSource;
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub use health::{check_spread, RandomSourceCheck};

/// Bytes for a probe of the source: as many as an entropy of a 24-word phrase.
const PROBE_BYTES: usize = 32;

/// Fills byte buffers with uniformly random bytes. The library checks a source before each draw
/// ([`check_source`]), bounds how long [`uniform_below`] draws again, and refuses a new phrase's
/// entropy that cannot be random (AUD-024-SEC014); a source that passes these and then gives fixed
/// bytes it accepts is not seen: only its design can rule that out.
pub trait RandomSource {
    /// Fills `bytes` completely, or fails with [`MhfeError::RandomFailed`].
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError>;
}

impl<F> RandomSource for F
where
    F: FnMut(&mut [u8]) -> Result<(), MhfeError>,
{
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        self(bytes)
    }
}

/// Refuses a source that cannot be random: two probes of 32 bytes that are equal, one of a single
/// byte value, or one whose second half is zeros, as the probes start zeroed. It catches a host
/// that fills a copy instead of the buffer, fills only part of it (AUD-024-SEC014), or a stub,
/// before anything secret is drawn from it; a working source is refused with a probability below
/// 2^-126. The probes are wiped.
pub fn check_source(source: &mut dyn RandomSource) -> Result<(), MhfeError> {
    let mut first = Zeroizing::new([0u8; PROBE_BYTES]);
    let mut second = Zeroizing::new([0u8; PROBE_BYTES]);
    source.fill(&mut first[..])?;
    source.fill(&mut second[..])?;
    let narrow = |probe: &[u8]| {
        probe.iter().all(|&byte| byte == probe[0])
            || probe[PROBE_BYTES / 2..].iter().all(|&byte| byte == 0)
    };
    if narrow(&first[..]) || narrow(&second[..]) || *first == *second {
        return Err(MhfeError::RandomFailed(
            "it gave bytes that cannot be random".to_owned(),
        ));
    }
    Ok(())
}

/// Values above the range that [`uniform_below`] draws again in a row before it refuses the
/// source. Fewer than half of the values are ever above it, so a working source reaches this with
/// a probability below 2^-128 (AUD-024-SEC014).
const MOST_DRAWN_AGAIN: usize = 128;

/// An unbiased number below `n`, which is from 2 to 65,536. It takes the fewest bytes that hold
/// `n` values and uses only the largest multiple of `n` they hold, drawing again above it: for
/// 57 characters one byte, of which 228 values are used; for 7,776 words two bytes, of which
/// 62,208 are used. After 128 values above it in a row the source is refused, as a source stuck
/// on such a value would otherwise keep the draw going for ever. Any other `n` is refused with
/// [`MhfeError::InvalidRequest`] (AUD-024-API016).
pub fn uniform_below(source: &mut dyn RandomSource, n: usize) -> Result<usize, MhfeError> {
    if !(2..=1 << 16).contains(&n) {
        return Err(MhfeError::InvalidRequest(format!(
            "a number below {n} is not drawn: only ranges of 2 to 65,536 are"
        )));
    }
    let bytes = if n <= 256 { 1 } else { 2 };
    let values = 1usize << (8 * bytes);
    let accepted = values / n * n;
    let mut buffer = Zeroizing::new([0u8; 2]);
    for _ in 0..MOST_DRAWN_AGAIN {
        source.fill(&mut buffer[..bytes])?;
        let value = buffer[..bytes]
            .iter()
            .fold(0usize, |value, &byte| value << 8 | usize::from(byte));
        if value < accepted {
            return Ok(value % n);
        }
    }
    Err(MhfeError::RandomFailed(format!(
        "it gave {MOST_DRAWN_AGAIN} values above the range in a row"
    )))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A deterministic stand-in for a random source: bytes of a simple counter generator.
    pub(crate) fn counter_source(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
        // Knuth's multiplicative hash spreads the small seeds apart.
        health::lcg_source(u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1))
    }

    #[test]
    fn a_source_that_fills_nothing_is_refused() {
        let mut zeros = |_: &mut [u8]| Ok(());
        assert!(matches!(
            check_source(&mut zeros),
            Err(MhfeError::RandomFailed(_))
        ));
        let mut repeating = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        assert!(check_source(&mut repeating).is_err());
        assert!(check_source(&mut counter_source(1)).is_ok());
        // A source that fills only the first half of each buffer is refused too
        // (AUD-024-SEC014).
        let mut working = counter_source(2);
        let mut half = |bytes: &mut [u8]| {
            let middle = bytes.len() / 2;
            working(&mut bytes[..middle])
        };
        assert!(check_source(&mut half).is_err());
    }

    /// A source stuck on a value above the range ends the draw instead of keeping it going, and
    /// fewer than half the values of any range are above it, so a working source is refused with
    /// a probability below 2^-128 (AUD-024-SEC014).
    #[test]
    fn a_source_stuck_above_the_range_is_refused() {
        for n in 2..=1usize << 16 {
            let values = if n <= 256 { 256 } else { 1 << 16 };
            assert!(2 * (values % n) < values, "{n}");
        }
        const { assert!(MOST_DRAWN_AGAIN >= 128) };
        // A bound outside 2 to 65,536 is refused, not a panic (AUD-024-API016).
        for bound in [0, 1, (1 << 16) + 1] {
            assert!(matches!(
                uniform_below(&mut counter_source(4), bound),
                Err(MhfeError::InvalidRequest(_))
            ));
        }
        for n in [57, 7776] {
            let mut fills = 0;
            let mut stuck = |bytes: &mut [u8]| {
                fills += 1;
                bytes.fill(0xff);
                Ok(())
            };
            assert!(matches!(
                uniform_below(&mut stuck, n),
                Err(MhfeError::RandomFailed(_))
            ));
            assert_eq!(fills, MOST_DRAWN_AGAIN);
        }
    }

    #[test]
    fn draws_stay_below_their_bound_and_reach_every_value() {
        let mut source = counter_source(3);
        let mut seen = [false; 57];
        for _ in 0..5000 {
            let value = uniform_below(&mut source, 57).unwrap();
            seen[value] = true;
        }
        assert!(seen.iter().all(|&seen| seen));
        for _ in 0..2000 {
            assert!(uniform_below(&mut source, 7776).unwrap() < 7776);
        }
    }

    #[test]
    fn values_above_the_last_full_multiple_are_drawn_again() {
        for &(bytes, bound, expected) in &crate::new_password::known_answers::REJECTION_CASES {
            let mut bytes = bytes.iter().copied();
            let mut source = |buffer: &mut [u8]| {
                buffer
                    .iter_mut()
                    .for_each(|byte| *byte = bytes.next().unwrap());
                Ok(())
            };
            assert_eq!(uniform_below(&mut source, bound).unwrap(), expected);
        }
    }
}
