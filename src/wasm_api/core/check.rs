//! The rehearsal check in the browser: a recovery once, then comparisons with the references
//! the page gives, as [`CheckSession`].

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{mhfe_for, password_from, reference_target, report, verified};
use crate::engine::browser::JsArgon2;
use crate::wasm_api::{js_error, json, SecretText};
use crate::{PassedCheck, RecoveredForCheck};

#[derive(Serialize)]
struct CheckJson {
    /// [`mhfe::CheckOutcome::id`].
    outcome: &'static str,
    /// Where a matched address was found, such as "m/84'/0'/0'/0/5"; null otherwise.
    path: Option<String>,
    /// The original seed phrase's own checks, from the same recovery.
    evidence: EvidenceJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceJson {
    /// The length of the one verified reading, a 12- to 21-word original seed phrase whose
    /// built-in check passes, or null ([`mhfe::CheckEvidence::built_in_check`]).
    built_in_check: Option<usize>,
    /// Every 12- to 21-word length whose built-in check passes, in ascending order.
    matching_lengths: Vec<usize>,
    /// The original seed phrase's own checks that passed, as a page lists them beside the result
    /// ([`mhfe::CheckEvidence::own_checks_passed`]).
    passed: Vec<PassedJson>,
    /// Whether the 24-word reading passes the 16-bit phrase + passphrase check, with the
    /// passphrase given or the empty one when none was given. Null for a stated length, for a
    /// same-length container, and when exactly one shorter length passes its built-in check and
    /// the reference did not match the 24-word reading.
    wallet_check: Option<bool>,
}

/// One of the original seed phrase's own checks that passed ([`PassedCheck`]).
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "check")]
enum PassedJson {
    BuiltInCheck { words: usize },
    BuiltInChecks { lengths: Vec<usize> },
    WalletCheck,
}

impl From<PassedCheck> for PassedJson {
    fn from(passed: PassedCheck) -> Self {
        match passed {
            PassedCheck::BuiltInCheck(words) => Self::BuiltInCheck { words },
            PassedCheck::BuiltInChecks(lengths) => Self::BuiltInChecks { lengths },
            PassedCheck::WalletCheck => Self::WalletCheck,
        }
    }
}

/// A rehearsal check in one worker: the recovery once, then a comparison with the page's
/// reference and, when detection found no length, with the one the page gives next, without the
/// rounds again ([`RecoveredForCheck`]). Only whether each matches comes out; freed or dropped,
/// it wipes the recovered state.
#[wasm_bindgen]
pub struct CheckSession {
    recovered: RecoveredForCheck,
    detection_follow_up: bool,
}

#[wasm_bindgen]
impl CheckSession {
    /// Recovers `container` for a check against the reference, which is refused first, before
    /// any round, when the container cannot be checked with it. The rounds are reported as
    /// "recover", then once "compare". `reference_kind` is "address", "fingerprint", "words" or
    /// "walletCheck" (the phrase and passphrase check of a 24-word container); see
    /// [`reference_target`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the WebAssembly binding takes every input as an argument of its own"
    )]
    #[wasm_bindgen(constructor)]
    pub fn new(
        container: &str,
        password_utf8: Vec<u8>,
        choice: &str,
        position: f64,
        pim: f64,
        memory_level: f64,
        reference_kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase_utf8: Vec<u8>,
        argon2: JsArgon2,
        on_round: &js_sys::Function,
    ) -> Result<CheckSession, JsError> {
        // Both secrets are put under a wiping owner before anything can fail, so that no early
        // return drops either of them unwiped. The passphrase is read in place, without a copy.
        let passphrase = SecretText::new(passphrase_utf8);
        let password = password_from(password_utf8, choice, position)?;
        let passphrase = passphrase.passphrase()?;
        let wallet = reference_target(reference_kind, reference, coin, path)?;
        wallet.refuse_unused(passphrase).map_err(js_error)?;
        // The library refuses a check that cannot be, an empty passphrase of the wallet check
        // among them, before any round, in the same order for every front end. The work area is
        // freed when this engine is dropped, before the page is asked anything.
        let (mut mhfe, _) = mhfe_for(pim, memory_level, argon2)?;
        let recovered = mhfe.recover_for_check_in_stages(
            container,
            &password,
            &wallet.with(passphrase),
            &mut |stage, round, rounds| report(on_round, stage, round, rounds),
        );
        let recovered = verified(&mhfe, recovered)?;
        Ok(Self {
            recovered,
            detection_follow_up: false,
        })
    }

    /// Compares the recovery with a reference given as for [`CheckSession::new`], as JSON
    /// `{"outcome": "matches" | "notVerified" | "doesNotMatch", "path": string | null,
    /// "evidence": {...}}`: only the outcome comes out, with the facts beside it that reveal no
    /// word, and for a matched address the path where it was found.
    pub fn compare(
        &mut self,
        reference_kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase_utf8: Vec<u8>,
    ) -> Result<String, JsError> {
        let passphrase = SecretText::new(passphrase_utf8);
        let passphrase = passphrase.passphrase()?;
        let wallet = reference_target(reference_kind, reference, coin, path)?;
        wallet.refuse_unused(passphrase).map_err(js_error)?;
        let reference = wallet.with(passphrase);
        let evidence = if self.detection_follow_up {
            self.recovered.compare_after_detection(&reference)
        } else {
            self.recovered.compare(&reference)
        }
        .map_err(js_error)?;
        self.detection_follow_up |= evidence.asks_length();
        json(&CheckJson {
            outcome: evidence.outcome().id(),
            path: evidence.outcome().path().map(ToString::to_string),
            evidence: EvidenceJson {
                passed: evidence
                    .own_checks_passed()
                    .into_iter()
                    .map(PassedJson::from)
                    .collect(),
                built_in_check: evidence.built_in_check(),
                matching_lengths: evidence.matching_lengths().to_vec(),
                wallet_check: evidence.wallet_check(),
            },
        })
    }
    /// Whether the library's detection asks for a stated length or a wallet reference next.
    #[wasm_bindgen(js_name = asksLength)]
    pub fn asks_length(&self) -> bool {
        self.detection_follow_up
    }
}
