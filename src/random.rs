//! Randomness from the host. The library draws nothing by itself: the command-line tool passes the
//! operating system's generator and the browser binding passes `crypto.getRandomValues`, both as
//! a [`RandomSource`]. Every draw goes through [`RandomSampler::uniform_below`], so no index is biased.

use zeroize::Zeroizing;

mod error;
pub use error::RandomError;

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
pub use health::RandomSourceCheck;
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords",
    feature = "browser-wallet"
))]
pub(crate) use health::ScriptedSource;

/// Bytes for a probe of the source: as many as an entropy of a 24-word phrase.
const PROBE_BYTES: usize = 32;

/// Values above the range that [`RandomSampler::uniform_below`] draws again in a row before it
/// refuses the source. Fewer than half of the values are ever above it, so a working source reaches
/// this with
/// a probability below 2^-128 (AUD-024-SEC014).
const MOST_DRAWN_AGAIN: usize = 128;

/// Width of the uniform sampler's largest draw: one unsigned 16-bit value.
const MAX_SAMPLE_BYTES: usize = std::mem::size_of::<u16>();
/// A draw must choose at least between two values.
const SMALLEST_BOUND: usize = 2;
/// The largest bound fits every value of the sampler's fixed-width buffer.
const LARGEST_BOUND: usize = 1 << (MAX_SAMPLE_BYTES * u8::BITS as usize);

/// Fills byte buffers with uniformly random bytes. The library checks a source before each draw
/// ([`RandomSampler::check_source`]), bounds how long [`RandomSampler::uniform_below`] draws again,
/// and refuses a new phrase's entropy that cannot be random (AUD-024-SEC014); a source that passes
/// these and then gives fixed
/// bytes it accepts is not seen: only its design can rule that out.
pub trait RandomSource {
    /// Fills `bytes` completely, fails with [`RandomError`], or forwards host cancellation as
    /// [`RandomError::Cancelled`].
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError>;
}

impl<F> RandomSource for F
where
    F: FnMut(&mut [u8]) -> Result<(), RandomError>,
{
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
        self(bytes)
    }
}

/// Health probes and bounded unbiased draws from a host's byte source. The host implements only
/// [`RandomSource::fill`]; it cannot override these rules. Borrowing the source stores no random
/// bytes outside the wiped probes and draw buffer.
pub struct RandomSampler<'a> {
    source: &'a mut dyn RandomSource,
}

impl<'a> RandomSampler<'a> {
    /// Borrows a source for probes and draws. `check_source()` is explicit: library generators
    /// call it before the first draw; individual bounded-sampling self-checks need no live probe.
    pub fn new(source: &'a mut dyn RandomSource) -> Self {
        Self { source }
    }

    /// Refuses a source that cannot be random: two probes of 32 bytes that are equal, one of a single
    /// byte value, or one whose second half is zeros, as the probes start zeroed. It catches a host
    /// that fills a copy instead of the buffer, fills only part of it (AUD-024-SEC014), or a stub,
    /// before anything secret is drawn from it; a working source is refused with a probability below
    /// 2^-126. The probes are wiped.
    pub fn check_source(&mut self) -> Result<(), RandomError> {
        let mut first = Zeroizing::new([0u8; PROBE_BYTES]);
        let mut second = Zeroizing::new([0u8; PROBE_BYTES]);
        self.source.fill(&mut first[..])?;
        self.source.fill(&mut second[..])?;
        let narrow = |probe: &[u8]| {
            probe.iter().all(|&byte| byte == probe[0])
                || probe[PROBE_BYTES / 2..].iter().all(|&byte| byte == 0)
        };
        if narrow(&first[..]) || narrow(&second[..]) || *first == *second {
            return Err(RandomError::UnusableProbes);
        }
        Ok(())
    }

    /// An unbiased number below `n`, which is from 2 to 65,536. It takes the fewest bytes that hold
    /// `n` values and uses only the largest multiple of `n` they hold, drawing again above it: for
    /// 57 characters one byte, of which 228 values are used; for 7,776 words two bytes, of which
    /// 62,208 are used. After 128 values above it in a row the source is refused, as a source stuck
    /// on such a value would otherwise keep the draw going for ever. Any other `n` is refused with
    /// [`RandomError::InvalidBound`] (AUD-024-API016).
    pub fn uniform_below(&mut self, n: usize) -> Result<usize, RandomError> {
        if !(SMALLEST_BOUND..=LARGEST_BOUND).contains(&n) {
            return Err(RandomError::InvalidBound(n));
        }
        let bytes = if n <= 1 << u8::BITS {
            1
        } else {
            MAX_SAMPLE_BYTES
        };
        let values = 1usize << (u8::BITS as usize * bytes);
        let accepted = values / n * n;
        let mut buffer = Zeroizing::new([0u8; MAX_SAMPLE_BYTES]);
        for _ in 0..MOST_DRAWN_AGAIN {
            self.source.fill(&mut buffer[..bytes])?;
            let value = buffer[..bytes]
                .iter()
                .fold(0usize, |value, &byte| value << 8 | usize::from(byte));
            if value < accepted {
                return Ok(value % n);
            }
        }
        Err(RandomError::RejectionLimit)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A deterministic stand-in for a random source: bytes of a simple counter generator.
    pub(crate) fn counter_source(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), RandomError> {
        // Knuth's multiplicative hash spreads the small seeds apart.
        health::lcg_source(u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1))
    }

    #[test]
    fn a_source_that_fills_nothing_is_refused() {
        let mut zeros = |_: &mut [u8]| Ok(());
        assert!(matches!(
            RandomSampler::new(&mut zeros).check_source(),
            Err(RandomError::UnusableProbes)
        ));
        let mut repeating = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        assert!(RandomSampler::new(&mut repeating).check_source().is_err());
        assert!(RandomSampler::new(&mut counter_source(1))
            .check_source()
            .is_ok());
        // A source that fills only the first half of each buffer is refused too
        // (AUD-024-SEC014).
        let mut working = counter_source(2);
        let mut half = |bytes: &mut [u8]| {
            let middle = bytes.len() / 2;
            working(&mut bytes[..middle])
        };
        assert!(RandomSampler::new(&mut half).check_source().is_err());
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
                RandomSampler::new(&mut counter_source(4)).uniform_below(bound),
                Err(RandomError::InvalidBound(_))
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
                RandomSampler::new(&mut stuck).uniform_below(n),
                Err(RandomError::RejectionLimit)
            ));
            assert_eq!(fills, MOST_DRAWN_AGAIN);
        }
    }

    #[test]
    fn draws_stay_below_their_bound_and_reach_every_value() {
        let mut source = counter_source(3);
        let mut seen = [false; 57];
        for _ in 0..5000 {
            let value = RandomSampler::new(&mut source).uniform_below(57).unwrap();
            seen[value] = true;
        }
        assert!(seen.iter().all(|&seen| seen));
        for _ in 0..2000 {
            assert!(RandomSampler::new(&mut source).uniform_below(7776).unwrap() < 7776);
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
            assert_eq!(
                RandomSampler::new(&mut source)
                    .uniform_below(bound)
                    .unwrap(),
                expected
            );
        }
    }
}
