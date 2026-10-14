//! Searches for the missing words of a container phrase in the browser: the candidates of the
//! written words, and the searches that compare each candidate with a decoy or a wallet.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{mhfe_for, password_from, reference_target, report, verified};
use crate::engine::browser::JsArgon2;
use crate::operation::Stage;
use crate::search::{ContainerSearch, Found};
use crate::wasm_api::{
    call_page, container_fingerprint_text, js_error, json, whole_number, SecretText,
};
use crate::{refuse_unused_passphrase, MhfeError, PassphraseReferences, ReferenceTarget};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidatesJson {
    missing: Vec<usize>,
    candidates: usize,
    /// Whether the original seed phrase's wallet can tell the candidates apart (one missing word).
    offers_wallet_search: bool,
    /// Whether the original seed phrase's own checks can too: one missing word in a container that
    /// carries them.
    offers_own_checks: bool,
}

/// The candidates of a container phrase with words typed as "?", before a search: JSON
/// `{ missing, candidates, offersWalletSearch, offersOwnChecks }`, the missing words' positions
/// from 1, how many candidate containers pass the BIP39 checksum, and which searches with the
/// password the library offers for them, as the command-line tool asks it. More than two missing
/// words are refused (`TOO_MANY_MISSING_WORDS`), and words with none marked (`INVALID_REQUEST`).
#[wasm_bindgen(js_name = searchCandidates)]
pub fn search_candidates(written: &str) -> Result<String, JsError> {
    let search = ContainerSearch::new(written).map_err(js_error)?;
    json(&CandidatesJson {
        missing: search.missing(),
        candidates: search.count(),
        offers_wallet_search: search.offers_wallet_search(),
        offers_own_checks: search.offers_own_checks(),
    })
}

#[derive(Serialize)]
struct FoundWordJson {
    position: usize,
    word: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchJson {
    found: bool,
    /// The container phrase found, or null.
    container: Option<String>,
    container_fingerprint: Option<String>,
    words: Vec<FoundWordJson>,
    /// Where a matched address was found, or null.
    path: Option<String>,
    candidates: usize,
}

fn search_json(search: &ContainerSearch, found: Option<Found>) -> Result<String, JsError> {
    let Some(found) = found else {
        return json(&SearchJson {
            found: false,
            container: None,
            container_fingerprint: None,
            words: Vec::new(),
            path: None,
            candidates: search.count(),
        });
    };
    let fingerprint = container_fingerprint_text(&found.container)?;
    json(&SearchJson {
        found: true,
        container: Some(found.container.to_string()),
        container_fingerprint: Some(fingerprint),
        words: found
            .words
            .iter()
            .map(|&(position, word)| FoundWordJson { position, word })
            .collect(),
        path: found.path.as_ref().map(ToString::to_string),
        candidates: search.count(),
    })
}

/// Candidates compared between two reports of a search with the decoy wallet, so that thousands
/// of them do not flood the page with messages.
const DECOY_REPORT_EVERY: usize = 64;

/// The search for words typed as "?" with the decoy wallet, the container itself as a wallet:
/// every candidate is compared with an address (`reference_kind` "address", `coin`, `path`) or a
/// fingerprint ("fingerprint") with `passphrase_utf8`, the BIP39 passphrase used with the
/// container phrase, empty for none, without the password and without Argon2.
/// Up to two missing words; for two, an address is searched among the first `scan_gap`
/// receiving and as many change addresses of the first account, 20 being the usual gap of a
/// wallet. `on_candidates(done, count)` hears of the progress.
/// Returns JSON `{ found, container, containerFingerprint, words: [{ position, word }], path,
/// candidates }`.
#[wasm_bindgen(js_name = searchDecoy)]
#[expect(
    clippy::too_many_arguments,
    reason = "the WebAssembly boundary takes every input as an argument of its own"
)]
pub fn search_decoy(
    written: &str,
    reference_kind: &str,
    reference: &str,
    coin: &str,
    path: &str,
    passphrase_utf8: Vec<u8>,
    scan_gap: f64,
    on_candidates: &js_sys::Function,
) -> Result<String, JsError> {
    let passphrase = SecretText::new(passphrase_utf8);
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let scan_gap = whole_number(
        scan_gap,
        MhfeError::InvalidRequest(String::new()).code(),
        "scanGap",
    )?;
    let wallet = reference_target(reference_kind, reference, coin, path)?;
    let search = ContainerSearch::new(written).map_err(js_error)?;
    let found = search
        .search_decoy(&wallet.with(passphrase), scan_gap, &mut |done, count| {
            // The first candidate too, so that a page hears of a search that ends at once.
            if done == 1 || done % DECOY_REPORT_EVERY == 0 || done == count {
                report_candidates(on_candidates, done, count)?;
            }
            Ok(())
        })
        .map_err(js_error)?;
    search_json(&search, found)
}

/// The search for one word typed as "?" with the owner's wallet: every candidate is recovered
/// with the password at the settings given, a full recovery each, and compared with an address
/// or a fingerprint, or with the original seed phrase's own checks: "builtInCheck" (empty
/// reference), the built-in check of a 12- to 21-word one, and "walletCheck", which adds with its
/// BIP39 passphrase the phrase + passphrase check of a 24-word one made by `mhfe new`.
/// `on_candidates(candidate, count)` hears of each candidate as it starts, `on_round` of its
/// rounds. Returns JSON as [`search_decoy`].
#[wasm_bindgen(js_name = searchWallet)]
#[expect(
    clippy::too_many_arguments,
    reason = "the WebAssembly boundary takes every input as an argument of its own"
)]
pub fn search_wallet(
    // A deliberate copy of the arguments of CheckSession::new: the WebAssembly boundary takes
    // every input as an argument of its own, the secrets as bytes that the binding wipes.
    written: &str,
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
    on_candidates: &js_sys::Function,
    on_round: &js_sys::Function,
) -> Result<String, JsError> {
    // Both secrets are put under a wiping owner before anything can fail.
    let passphrase = SecretText::new(passphrase_utf8);
    let password = password_from(password_utf8, choice, position)?;
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    // The original seed phrase's own checks need no reference: the built-in check, and with the
    // passphrase of "walletCheck" the phrase + passphrase check too.
    enum Compared<'a> {
        OwnChecks(Option<&'a str>),
        Wallet(ReferenceTarget),
    }
    let compared = match reference_kind {
        "builtInCheck" => {
            refuse_unused_passphrase(passphrase, PassphraseReferences::Check).map_err(js_error)?;
            Compared::OwnChecks(None)
        }
        "walletCheck" => Compared::OwnChecks(Some(passphrase)),
        _ => Compared::Wallet(reference_target(reference_kind, reference, coin, path)?),
    };
    let search = ContainerSearch::new(written).map_err(js_error)?;
    let (mut mhfe, _) = mhfe_for(pim, memory_level, argon2)?;
    let mut current = 0;
    let mut progress = |candidate, count, round, rounds| {
        if candidate != current {
            current = candidate;
            report_candidates(on_candidates, candidate, count)?;
        }
        report(on_round, Stage::Recover, round, rounds)
    };
    let found = match &compared {
        Compared::OwnChecks(passphrase) => {
            search.search_own_checks(&mut mhfe, &password, *passphrase, &mut progress)
        }
        Compared::Wallet(wallet) => search.search_wallet(
            &mut mhfe,
            &password,
            &wallet.with(passphrase),
            &mut progress,
        ),
    };
    let found = verified(&mhfe, found)?;
    search_json(&search, found)
}

/// Tells the worker how far a search has come. An exception thrown there stops it.
fn report_candidates(
    on_candidates: &js_sys::Function,
    candidate: usize,
    count: usize,
) -> Result<(), MhfeError> {
    call_page(
        on_candidates,
        &[JsValue::from(candidate as u32), JsValue::from(count as u32)],
    )
}
