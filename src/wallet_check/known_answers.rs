//! Known answers of the wallet check (MHFE-WALLET-CHECK-SEED-1): the self-check `wallet-check`.
//!
//! The tag, `BE32(ENT)`, the BIP39 seed and the 16-bit criterion, with the whole digest compared,
//! a phrase that passes and one that fails, a draw through the source check and the read-back, and
//! the refusal of a source that fills nothing. The values are the specification's public vectors
//! (vectors/profiles/README.md). Where it gives only the first eight hex digits of a digest that
//! fails, the whole digest was computed with Python's hashlib and unicodedata, an implementation
//! independent of this one, after it had reproduced the BIP39 English list's SHA-256, BIP-0039's
//! first seed with "TREZOR" and both published passing digests.

use super::{digest, digest_passes, PhraseDraw, WalletCheck, NEW_ENTROPY_BYTES};
use crate::random::ScriptedSource;
use crate::self_check::{
    damaged, expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

/// A vector: the entropy 192 zero bits and a 64-bit counter, a passphrase, the whole digest `T`
/// and whether it passes.
#[derive(Clone, Copy)]
struct WalletCheckVector {
    counter: u64,
    passphrase: &'static str,
    digest: &'static str,
    passes: bool,
    /// The last words of its phrase, for a vector that passes.
    ends_with: &'static str,
    startup: bool,
}

/// The first counter whose phrase passes with the public test passphrase "TREZOR": entropy of
/// 24 zero bytes and 76,562, "abandon" 21 times, "above proof fatigue". Found once with the
/// release build, about 65,536 BIP39 seeds, and confirmed by an independent computation.
pub(crate) const TREZOR_COUNTER: u64 = 76_562;

/// The first counter whose phrase passes with an empty passphrase: 24 zero bytes and 98,918,
/// "abandon" 21 times, "absorb another spoil". Found with an independent Python computation
/// (digest 0000ede7…), which also confirmed that it fails with "TREZOR" (8d2b97fb…).
pub(crate) const EMPTY_COUNTER: u64 = 98_918;

const VECTORS: [WalletCheckVector; 4] = [
    WalletCheckVector {
        counter: TREZOR_COUNTER,
        passphrase: "TREZOR",
        digest: "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853",
        passes: true,
        ends_with: "abandon above proof fatigue",
        startup: true,
    },
    WalletCheckVector {
        counter: TREZOR_COUNTER,
        passphrase: "",
        // The specification gives "ebd07f71"; the rest from hashlib, as the module says.
        digest: "ebd07f7120cfeb611077221ca20da98c6bef15e72f0cbfd2ef2c6c6514ad7ddb",
        passes: false,
        ends_with: "",
        startup: true,
    },
    WalletCheckVector {
        counter: EMPTY_COUNTER,
        passphrase: "",
        digest: "0000ede77b44fbd62025e1d36a45ebe3846cf48f7b3e76ca6a91495fdadc1fb2",
        passes: true,
        ends_with: "abandon absorb another spoil",
        startup: false,
    },
    WalletCheckVector {
        counter: EMPTY_COUNTER,
        passphrase: "TREZOR",
        // The specification gives "8d2b97fb"; the rest from hashlib, as the module says.
        digest: "8d2b97fb997a034302b996efea1a302ce3721b645ed056c5304c3c327fb77df4",
        passes: false,
        ends_with: "",
        startup: false,
    },
];

/// The entropy of a vector: 24 zero bytes, then the counter as a big-endian 64-bit number.
pub(crate) fn entropy(counter: u64) -> [u8; NEW_ENTROPY_BYTES] {
    let mut entropy = [0u8; NEW_ENTROPY_BYTES];
    entropy[NEW_ENTROPY_BYTES - 8..].copy_from_slice(&counter.to_be_bytes());
    entropy
}

/// The `wallet-check` check.
pub(crate) struct WalletCheckProfile {
    vectors: &'static [WalletCheckVector],
}

impl WalletCheckProfile {
    pub(crate) fn new() -> Self {
        Self { vectors: &VECTORS }
    }

    /// The digest of a vector, compared whole with the published one, and the criterion on it.
    fn vector(vector: &WalletCheckVector) -> Result<(), crate::self_check::FailureDetail> {
        let entropy = entropy(vector.counter);
        let digest = digest(&entropy, vector.passphrase).map_err(stopped)?;
        expect(
            hex::encode(&digest[..]) == vector.digest,
            crate::self_check::KnownAnswerDifference::GivesAnotherDigest,
        )?;
        expect(
            digest_passes(&digest) == vector.passes,
            if vector.passes {
                crate::self_check::KnownAnswerDifference::FailsWhereItMustPass
            } else {
                crate::self_check::KnownAnswerDifference::PassesWhereItMustFail
            },
        )?;
        if vector.passes {
            let phrase = crate::phrase::phrase_from_entropy(&entropy).map_err(stopped)?;
            expect(
                phrase.ends_with(vector.ends_with),
                crate::self_check::KnownAnswerDifference::GivesOtherWords,
            )?;
        }
        Ok(())
    }
}

impl ComponentCheck for WalletCheckProfile {
    fn id(&self) -> &'static str {
        "wallet-check"
    }

    fn label(&self) -> &'static str {
        "Wallet check (MHFE-WALLET-CHECK-SEED-1)"
    }

    fn run(&mut self, tier: Tier) -> ComponentOutcome {
        let vectors: Vec<WalletCheckVector> = self
            .vectors
            .iter()
            .filter(|vector| tier == Tier::Full || vector.startup)
            .copied()
            .collect();
        let mut findings = Findings::new();
        findings.each(crate::self_check::CaseKind::Vector, &vectors, Self::vector);
        // A draw with the check from a source scripted to give the first vector's entropy after
        // the two probes of the source check: the passing phrase, read back and checked again.
        findings.one(|| {
            let first = self.vectors.first().ok_or_else(damaged)?;
            let draw = PhraseDraw::with_check(first.passphrase).map_err(stopped)?;
            let mut source = ScriptedSource::after_probes(&entropy(first.counter));
            let drawn = draw.draw(&mut source, &mut |_| Ok(())).map_err(stopped)?;
            expect(
                drawn.checked() && drawn.phrase().ends_with(first.ends_with),
                crate::self_check::KnownAnswerDifference::ADrawGivesAnotherPhrase,
            )
        });
        // An entropy of zeros means the source filled nothing.
        findings.one(|| {
            let mut zeros = ScriptedSource::new(vec![0; NEW_ENTROPY_BYTES]);
            expect_refusal(
                PhraseDraw::unchecked().try_draws(&mut zeros, 1),
                "RANDOM_FAILED",
            )
            .map_err(|what| crate::self_check::FailureDetail::Context {
                context: crate::self_check::CheckContext::ASourceOfZeros,
                cause: Box::new(what),
            })
        });
        // Without a passphrase, anyone who sees the phrase could test it.
        findings.one(|| {
            let phrase = crate::phrase::phrase_from_entropy(&entropy(VECTORS[0].counter))
                .map_err(stopped)?;
            expect_refusal(
                WalletCheck::new("").verify(&phrase),
                "WALLET_CHECK_NEEDS_PASSPHRASE",
            )
            .map_err(|what| crate::self_check::FailureDetail::Context {
                context: crate::self_check::CheckContext::ACheckWithoutAPassphrase,
                cause: Box::new(what),
            })
        });
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wallet_check_passes() {
        for tier in [Tier::Startup, Tier::Full] {
            assert_eq!(
                WalletCheckProfile::new().run(tier),
                ComponentOutcome::Passed
            );
        }
    }

    #[test]
    fn a_corrupted_vector_fails() {
        let mut vectors = VECTORS;
        vectors[0].digest = "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840854";
        let mut check = WalletCheckProfile {
            vectors: Box::leak(Box::new(vectors)),
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "vector 1 of 2 gives another digest".to_owned()
        );
        // A vector that must fail, turned into one that must pass.
        let mut vectors = VECTORS;
        vectors[1].passes = true;
        let mut check = WalletCheckProfile {
            vectors: Box::leak(Box::new(vectors)),
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "vector 2 of 2 fails where it must pass".to_owned()
        );
        // The whole digest of a vector that fails is compared, its last digit too.
        let mut vectors = VECTORS;
        vectors[1].digest = "ebd07f7120cfeb611077221ca20da98c6bef15e72f0cbfd2ef2c6c6514ad7dda";
        let mut check = WalletCheckProfile {
            vectors: Box::leak(Box::new(vectors)),
        };
        crate::self_check::assert_failed!(
            check.run(Tier::Startup),
            "vector 2 of 2 gives another digest".to_owned()
        );
        let mut vectors = VECTORS;
        vectors[3].counter = 98_917;
        let mut check = WalletCheckProfile {
            vectors: Box::leak(Box::new(vectors)),
        };
        assert_eq!(check.run(Tier::Startup), ComponentOutcome::Passed);
        crate::self_check::assert_failed!(
            check.run(Tier::Full),
            "vector 4 of 4 gives another digest".to_owned()
        );
    }
}
