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

/// Fills byte buffers with uniformly random bytes.
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

/// Refuses a source that cannot be random: two probes of 32 bytes that are equal, or all zero.
/// It catches a host that fills a copy instead of the buffer, or a stub, before anything secret is
/// drawn from it; the probes are wiped.
pub fn check_source(source: &mut dyn RandomSource) -> Result<(), MhfeError> {
    let mut first = Zeroizing::new([0u8; PROBE_BYTES]);
    let mut second = Zeroizing::new([0u8; PROBE_BYTES]);
    source.fill(&mut first[..])?;
    source.fill(&mut second[..])?;
    let all_zero = first.iter().all(|&byte| byte == 0) || second.iter().all(|&byte| byte == 0);
    if all_zero || *first == *second {
        return Err(MhfeError::RandomFailed(
            "it gave bytes that cannot be random".to_owned(),
        ));
    }
    Ok(())
}

/// An unbiased number below `n`, which is from 2 to 65,536. It takes the fewest bytes that hold
/// `n` values and uses only the largest multiple of `n` they hold, drawing again above it: for
/// 57 characters one byte, of which 228 values are used; for 7,776 words two bytes, of which
/// 62,208 are used.
pub fn uniform_below(source: &mut dyn RandomSource, n: usize) -> Result<usize, MhfeError> {
    assert!(
        (2..=1 << 16).contains(&n),
        "only ranges of 2 to 65,536 are drawn"
    );
    let bytes = if n <= 256 { 1 } else { 2 };
    let values = 1usize << (8 * bytes);
    let accepted = values / n * n;
    let mut buffer = Zeroizing::new([0u8; 2]);
    loop {
        source.fill(&mut buffer[..bytes])?;
        let value = buffer[..bytes]
            .iter()
            .fold(0usize, |value, &byte| value << 8 | usize::from(byte));
        if value < accepted {
            return Ok(value % n);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A deterministic stand-in for a random source: bytes of a simple counter generator.
    pub(crate) fn counter_source(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
        let mut state = u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1);
        move |bytes: &mut [u8]| {
            for byte in bytes.iter_mut() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            Ok(())
        }
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
        // 228 = 4 x 57 is the first byte value refused for 57; 62,208 = 8 x 7,776 for 7,776.
        let mut bytes = vec![228u8, 5].into_iter();
        let mut source = |buffer: &mut [u8]| {
            buffer
                .iter_mut()
                .for_each(|byte| *byte = bytes.next().unwrap());
            Ok(())
        };
        assert_eq!(uniform_below(&mut source, 57).unwrap(), 5);
        let mut pairs = vec![0xF3u8, 0x00, 0x00, 0x07].into_iter();
        let mut source = |buffer: &mut [u8]| {
            buffer
                .iter_mut()
                .for_each(|byte| *byte = pairs.next().unwrap());
            Ok(())
        };
        assert_eq!(uniform_below(&mut source, 7776).unwrap(), 7);
    }
}
