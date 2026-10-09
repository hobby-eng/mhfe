//! Known answers of the search for missing words: the self-check `container-search`.
//!
//! The candidates of the suite 3 vector zero-12's container phrase with one word missing, and the
//! search with its decoy wallet's master key fingerprint, without Argon2. Every expected value
//! was computed by an independent Python implementation (hashlib's SHA-256 and PBKDF2, and its own
//! secp256k1 arithmetic) that first reproduced the published container of zero-12; the search
//! with the owner's wallet adds only full recoveries, which the cipher's checks cover.

use super::ContainerSearch;
use crate::rehearsal::Reference;
use crate::self_check::{
    expect, expect_refusal, stopped, ComponentCheck, ComponentOutcome, Findings, Tier,
};

// The container phrase of the suite 3 vector zero-12.
use crate::self_check::ZERO_12_CONTAINER as ZERO_12;
/// The master key fingerprint of that container phrase as a wallet without a passphrase: the
/// decoy wallet, as MHFE shows it under the container.
const ZERO_12_DECOY_FINGERPRINT: [u8; 4] = [0x48, 0x7a, 0x15, 0x6e];

/// A word of zero-12 typed as `?`, how many candidates the checksum leaves, the first of them and
/// where the real word stands among them, from 1.
#[derive(Clone, Copy)]
struct CandidatesCase {
    missing: usize,
    count: usize,
    first: &'static str,
    real_at: usize,
}

const CANDIDATES: [CandidatesCase; 2] = [
    CandidatesCase {
        missing: 3,
        count: 7,
        first: "bubble",
        real_at: 7,
    },
    // The last word holds 3 bits of entropy beside its 8 checksum bits: exactly 8 candidates.
    CandidatesCase {
        missing: 24,
        count: 8,
        first: "brave",
        real_at: 6,
    },
];

/// The `container-search` check.
pub(crate) struct ContainerSearchCheck {
    candidates: &'static [CandidatesCase],
    fingerprint: [u8; 4],
}

impl ContainerSearchCheck {
    pub(crate) fn new() -> Self {
        Self {
            candidates: &CANDIDATES,
            fingerprint: ZERO_12_DECOY_FINGERPRINT,
        }
    }

    fn typed(missing: &[usize]) -> String {
        ZERO_12
            .split_whitespace()
            .enumerate()
            .map(|(index, word)| {
                if missing.contains(&(index + 1)) {
                    "?"
                } else {
                    word
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn candidates(case: &CandidatesCase) -> Result<(), String> {
        let search = ContainerSearch::new(&Self::typed(&[case.missing])).map_err(stopped)?;
        expect(search.count() == case.count, "leaves another number")?;
        let words: Vec<String> = search
            .candidates
            .iter()
            .map(|missing| {
                let container = search.container(missing);
                container
                    .split(' ')
                    .nth(case.missing - 1)
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        let real = ZERO_12.split(' ').nth(case.missing - 1).unwrap_or("");
        expect(
            words.first().map(String::as_str) == Some(case.first)
                && words.get(case.real_at - 1).map(String::as_str) == Some(real),
            "lists other words",
        )
    }

    /// The decoy fingerprint finds the last word; another fingerprint finds nothing, and three
    /// missing words are refused before any work.
    fn decoy(&self) -> Result<(), String> {
        let search = ContainerSearch::new(&Self::typed(&[24])).map_err(stopped)?;
        let reference = Reference::Fingerprint {
            fingerprint: self.fingerprint,
            passphrase: "",
        };
        let found = search
            .search_decoy(&reference, super::DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .map_err(stopped)?;
        let real = ZERO_12.split(' ').nth(23).unwrap_or("");
        expect(
            found.is_some_and(|found| found.words == [(24, real)] && *found.container == ZERO_12),
            "finds another container",
        )?;
        let other = Reference::Fingerprint {
            fingerprint: [!self.fingerprint[0], 0, 0, 0],
            passphrase: "",
        };
        let none = search
            .search_decoy(&other, super::DECOY_SCAN_GAP, &mut |_, _| Ok(()))
            .map_err(stopped)?;
        expect(none.is_none(), "takes another wallet's fingerprint")?;
        expect_refusal(
            ContainerSearch::new(&Self::typed(&[1, 2, 3])),
            "TOO_MANY_MISSING_WORDS",
        )
    }
}

impl ComponentCheck for ContainerSearchCheck {
    fn id(&self) -> &'static str {
        "container-search"
    }

    fn label(&self) -> &'static str {
        "Search for missing words"
    }

    fn run(&mut self, _: Tier) -> ComponentOutcome {
        let mut findings = Findings::new();
        findings.each("candidates", self.candidates, Self::candidates);
        findings.each("decoy search", &[()], |_| self.decoy());
        findings.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_check::{fails_with, leak};

    #[test]
    fn the_search_passes() {
        assert_eq!(
            ContainerSearchCheck::new().run(Tier::Startup),
            ComponentOutcome::Passed
        );
    }

    #[test]
    fn a_wrong_count_or_fingerprint_fails() {
        let mut candidates = CANDIDATES;
        candidates[1].count = 7;
        fails_with(
            ContainerSearchCheck {
                candidates: leak(candidates),
                ..ContainerSearchCheck::new()
            },
            "candidates 2 of 2 leaves another number",
        );
        let mut check = ContainerSearchCheck {
            fingerprint: [0x48, 0x7a, 0x15, 0x6f],
            ..ContainerSearchCheck::new()
        };
        assert_eq!(
            check.run(Tier::Startup),
            ComponentOutcome::Failed("decoy search 1 of 1 finds another container".to_owned())
        );
    }
}
