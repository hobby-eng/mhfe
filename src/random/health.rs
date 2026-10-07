//! The health of a random source: the self-check `random-source`, and the spread test of the full
//! self-test.
//!
//! At startup only scripted sources run, with no call to the operating system or the page: the
//! source check ([`super::check_source`]) must refuse a stuck source and accept a working one, so
//! that the guard before every draw is known to work. The full self-test adds the live source:
//! two probes, and the spread of 1,024 of its bytes. No test can see a source that is
//! deterministic but looks random; only its design can rule that out.

use zeroize::Zeroizing;

use super::{check_source, RandomSource};
use crate::self_check::{expect, ComponentCheck, ComponentOutcome, Findings, Tier};
use crate::MhfeError;

/// Bytes the spread test draws.
const SPREAD_BYTES: usize = 1024;
/// At least this many of the 256 byte values must appear among them; 251.3 are expected.
const LEAST_DIFFERENT_VALUES: usize = 200;
/// No value may appear more often than this; 4 times is expected. With the bound above, a working
/// source fails the test with a probability below 2^-70 (binomial tails, asserted in the tests).
const MOST_REPEATS: usize = 40;

/// Refuses a source whose bytes are not spread as random bytes are: 1,024 bytes with fewer than
/// 200 different values, or one value more than 40 times. It catches a source stuck on a few
/// values, a counter or a narrow generator, before it is trusted. The bytes are wiped.
pub fn check_spread(source: &mut dyn RandomSource) -> Result<(), MhfeError> {
    let mut bytes = Zeroizing::new([0u8; SPREAD_BYTES]);
    source.fill(&mut bytes[..])?;
    let mut counts = Zeroizing::new([0usize; 256]);
    for &byte in bytes.iter() {
        counts[usize::from(byte)] += 1;
    }
    let different = counts.iter().filter(|&&count| count > 0).count();
    let most = counts.iter().copied().max().unwrap_or(0);
    if different < LEAST_DIFFERENT_VALUES || most > MOST_REPEATS {
        return Err(MhfeError::RandomFailed(
            "its bytes are not spread as random bytes are".to_owned(),
        ));
    }
    Ok(())
}

/// A source that gives the bytes of a script and then fails: a stand-in for a host source in the
/// checks, never used to draw a secret.
pub(crate) struct ScriptedSource {
    bytes: Vec<u8>,
    position: usize,
}

impl ScriptedSource {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }

    /// Two different, non-zero blocks that [`check_source`] accepts, followed by `bytes`: what a
    /// draw that checks its source first takes.
    pub(crate) fn after_probes(bytes: &[u8]) -> Self {
        let mut script: Vec<u8> = (1..=2 * super::PROBE_BYTES as u8).collect();
        script.extend_from_slice(bytes);
        Self::new(script)
    }
}

impl RandomSource for ScriptedSource {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), MhfeError> {
        let end = self.position + bytes.len();
        let script = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| MhfeError::RandomFailed("the script ran out".to_owned()))?;
        bytes.copy_from_slice(script);
        self.position = end;
        Ok(())
    }
}

/// A stuck source: the same byte every time.
fn constant_source(byte: u8) -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    move |bytes: &mut [u8]| {
        bytes.fill(byte);
        Ok(())
    }
}

/// A source that fills nothing, as a host that writes into a copy of the buffer does.
fn untouched_source() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    |_: &mut [u8]| Ok(())
}

/// A linear congruential generator: deterministic, but spread like random bytes, which the
/// checks must accept.
fn counter_source() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    // Numerical Recipes' constants for a 32-bit LCG; its top byte is spread evenly.
    let mut state: u32 = 0x2545_f491;
    move |bytes: &mut [u8]| {
        for byte in bytes.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        Ok(())
    }
}

/// A source that gives only 16 different values, which passes the source check but not the
/// spread.
fn narrow_source() -> impl FnMut(&mut [u8]) -> Result<(), MhfeError> {
    let mut counter = counter_source();
    move |bytes: &mut [u8]| {
        counter(bytes)?;
        bytes.iter_mut().for_each(|byte| *byte &= 0x0f);
        Ok(())
    }
}

/// The `random-source` check.
pub struct RandomSourceCheck<'a> {
    live: Option<&'a mut dyn RandomSource>,
}

impl<'a> RandomSourceCheck<'a> {
    /// The check of the source checks, and in the full self-test of `live`, the source the
    /// program draws from: the operating system's generator, or the page's
    /// `crypto.getRandomValues`.
    pub fn new(live: Option<&'a mut dyn RandomSource>) -> Self {
        Self { live }
    }

    fn scripted(findings: &mut Findings) {
        type Source = Box<dyn FnMut(&mut [u8]) -> Result<(), MhfeError>>;
        /// A source the source check must refuse, by what a failure calls it.
        type Refused = (&'static str, fn() -> Source);
        let refused: [Refused; 2] = [
            ("a source that fills nothing", || {
                Box::new(untouched_source())
            }),
            ("a stuck source", || Box::new(constant_source(7))),
        ];
        for (name, make) in refused {
            findings.one(|| {
                let mut source = make();
                expect(
                    matches!(check_source(&mut source), Err(MhfeError::RandomFailed(_))),
                    &format!("the source check accepts {name}"),
                )
            });
        }
        findings.one(|| {
            expect(
                check_source(&mut counter_source()).is_ok()
                    && check_spread(&mut counter_source()).is_ok(),
                "the source check refuses a working source",
            )
        });
        findings.one(|| {
            expect(
                check_spread(&mut narrow_source()).is_err()
                    && check_spread(&mut constant_source(0)).is_err(),
                "the spread test accepts a narrow source",
            )
        });
    }
}

impl ComponentCheck for RandomSourceCheck<'_> {
    fn id(&self) -> &'static str {
        "random-source"
    }

    fn label(&self) -> &'static str {
        "Random source"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        Self::scripted(&mut findings);
        if tier == Tier::Startup {
            return findings.outcome();
        }
        let Some(live) = self.live.as_deref_mut() else {
            return match findings.outcome() {
                ComponentOutcome::Passed => {
                    ComponentOutcome::NotRun("no random source was given to test".to_owned())
                }
                failed => failed,
            };
        };
        findings.one(|| {
            check_source(live)
                .map_err(|_| "the source gives bytes that cannot be random".to_owned())
        });
        findings.one(|| {
            check_spread(live)
                .map_err(|_| "the source's bytes are not spread as random bytes are".to_owned())
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_checks_pass_with_scripted_and_live_sources() {
        assert_eq!(
            RandomSourceCheck::new(None).run(Tier::Startup),
            ComponentOutcome::Passed
        );
        let mut live = counter_source();
        assert_eq!(
            RandomSourceCheck::new(Some(&mut live)).run(Tier::Full),
            ComponentOutcome::Passed
        );
        assert!(matches!(
            RandomSourceCheck::new(None).run(Tier::Full),
            ComponentOutcome::NotRun(_)
        ));
    }

    #[test]
    fn a_stuck_or_narrow_live_source_fails() {
        let mut stuck = constant_source(0x5a);
        assert_eq!(
            RandomSourceCheck::new(Some(&mut stuck)).run(Tier::Full),
            ComponentOutcome::Failed("the source gives bytes that cannot be random".to_owned())
        );
        let mut narrow = narrow_source();
        assert_eq!(
            RandomSourceCheck::new(Some(&mut narrow)).run(Tier::Full),
            ComponentOutcome::Failed(
                "the source's bytes are not spread as random bytes are".to_owned()
            )
        );
        let mut failing = |_: &mut [u8]| Err(MhfeError::RandomFailed("no source".to_owned()));
        assert!(RandomSourceCheck::new(Some(&mut failing))
            .run(Tier::Full)
            .is_failure());
    }

    #[test]
    fn the_spread_refuses_counters_and_repeats() {
        // A counter of every byte value in turn has all 256 values, each four times: it passes,
        // which is why the spread test is no proof of randomness.
        let mut counting = {
            let mut next = 0u8;
            move |bytes: &mut [u8]| {
                for byte in bytes.iter_mut() {
                    *byte = next;
                    next = next.wrapping_add(1);
                }
                Ok(())
            }
        };
        assert!(check_spread(&mut counting).is_ok());
        // Sixteen values, or one value 41 times among others, fail.
        let mut sixteen = |bytes: &mut [u8]| {
            bytes
                .iter_mut()
                .enumerate()
                .for_each(|(i, b)| *b = (i % 16) as u8);
            Ok(())
        };
        assert!(check_spread(&mut sixteen).is_err());
        let mut repeated = |bytes: &mut [u8]| {
            bytes
                .iter_mut()
                .enumerate()
                .for_each(|(i, b)| *b = if i < 41 { 0 } else { (i % 255) as u8 + 1 });
            Ok(())
        };
        assert!(check_spread(&mut repeated).is_err());
    }

    /// ln of the binomial coefficient, by the log-gamma sum: exact enough for these bounds.
    fn ln_choose(n: u64, k: u64) -> f64 {
        let ln_factorial = |m: u64| (1..=m).map(|i| (i as f64).ln()).sum::<f64>();
        ln_factorial(n) - ln_factorial(k) - ln_factorial(n - k)
    }

    /// The false-alarm bound of [`check_spread`] for a uniform source: one value more than 40
    /// times among 1,024 bytes (a union bound over the 256 values of a binomial tail), plus fewer
    /// than 200 different values (a union bound over the sets of 57 values left out).
    #[test]
    fn a_uniform_source_fails_the_spread_less_than_once_in_2_to_the_70() {
        let n = SPREAD_BYTES as u64;
        let p: f64 = 1.0 / 256.0;
        // P(X > 40) for X ~ Binomial(1024, 1/256), summed in log space.
        let tail: f64 = ((MOST_REPEATS as u64 + 1)..=n)
            .map(|k| (ln_choose(n, k) + k as f64 * p.ln() + (n - k) as f64 * (1.0 - p).ln()).exp())
            .sum();
        let repeats = 256.0 * tail;
        // At most 199 different values means some 57 values never appear:
        // C(256, 57) * (199/256)^1024 bounds it.
        let missing = 256 - (LEAST_DIFFERENT_VALUES as u64 - 1);
        let absent =
            (ln_choose(256, missing) + n as f64 * ((256 - missing) as f64 / 256.0).ln()).exp();
        let bound = repeats + absent;
        assert!(bound < 2f64.powi(-70), "{bound:e}");
        assert!(bound > 0.0);
    }

    #[test]
    fn a_script_gives_its_bytes_and_then_fails() {
        let mut script = ScriptedSource::after_probes(&[9, 8]);
        assert!(check_source(&mut script).is_ok());
        let mut two = [0u8; 2];
        script.fill(&mut two).unwrap();
        assert_eq!(two, [9, 8]);
        assert!(matches!(
            script.fill(&mut two),
            Err(MhfeError::RandomFailed(_))
        ));
    }
}
