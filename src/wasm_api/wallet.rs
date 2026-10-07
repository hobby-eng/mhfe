//! The wallet module: the wallet check of a recovered phrase (MHFE-WALLET-CHECK-SEED-1), master key
//! fingerprints, what an address check searches, new 24-word phrases, and its self-check. No
//! Argon2.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{js_error, json, run_self_check, secret_json, JsRandom, SecretText};
use crate::self_check::sets;
use crate::wallet::{master_fingerprint, AddressSearch, Coin};
use crate::wallet_check::{self, PhraseDraw, DRAW_REPORT_INTERVAL, WALLET_CHECK_BITS};
use crate::MhfeError;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoinJson {
    id: &'static str,
    name: &'static str,
    address_forms: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletParameters {
    version: &'static str,
    coins: Vec<CoinJson>,
    wallet_check_bits: u32,
    draw_report_interval: u64,
}

/// The fixed values of the wallet module, with every coin an address check knows.
#[wasm_bindgen(js_name = walletParameters)]
pub fn wallet_parameters() -> Result<String, JsError> {
    json(&WalletParameters {
        version: env!("CARGO_PKG_VERSION"),
        coins: Coin::ALL
            .into_iter()
            .map(|coin| CoinJson {
                id: coin.id(),
                name: coin.name(),
                address_forms: coin.address_forms(),
            })
            .collect(),
        wallet_check_bits: WALLET_CHECK_BITS,
        draw_report_interval: DRAW_REPORT_INTERVAL,
    })
}

/// Whether a recovered 24-word phrase, its UTF-8 bytes, passes the wallet check with the owner's
/// BIP39 passphrase, which must not be empty (WALLET_CHECK_NEEDS_PASSPHRASE). One BIP39 seed:
/// quick. Both secrets are wiped afterwards.
#[wasm_bindgen(js_name = walletCheck)]
pub fn wallet_check(phrase_utf8: Vec<u8>, passphrase_utf8: Vec<u8>) -> Result<bool, JsError> {
    // Both under a wiping owner before anything can fail.
    let phrase = SecretText::new(phrase_utf8);
    let passphrase = SecretText::new(passphrase_utf8);
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    wallet_check::verify(phrase.phrase()?, passphrase).map_err(js_error)
}

/// The master key fingerprint of a phrase, its UTF-8 bytes, with a BIP39 passphrase, which may be
/// empty, as eight hex digits. It does not reveal the phrase. Both secrets are wiped afterwards.
#[wasm_bindgen(js_name = walletFingerprint)]
pub fn wallet_fingerprint(
    phrase_utf8: Vec<u8>,
    passphrase_utf8: Vec<u8>,
) -> Result<String, JsError> {
    // Both under a wiping owner before anything can fail.
    let phrase = SecretText::new(phrase_utf8);
    let passphrase = SecretText::new(passphrase_utf8);
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let fingerprint = master_fingerprint(phrase.phrase()?, passphrase).map_err(js_error)?;
    Ok(hex::encode(fingerprint))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchJson<'a> {
    #[serde(rename = "type")]
    kind: Option<&'a str>,
    search: &'a str,
    addresses: u64,
    only_path: bool,
}

/// What an address check would search, to show before it runs: JSON `{ type, search, addresses,
/// onlyPath }`. `coin` is one of the ids of `walletParameters().coins` (INVALID_COIN otherwise);
/// `path` is empty for the standard paths. The library states it ([`AddressSearch::describe`]),
/// the same call the self-check part "address-search" compares with its known answers. No coin is
/// named here: the glue carries this text, and a page for one coin carries no other coin's name.
#[wasm_bindgen(js_name = describeAddress)]
pub fn describe_address(address: &str, coin: &str, path: &str) -> Result<String, JsError> {
    let search = AddressSearch::describe(coin, address, path).map_err(js_error)?;
    json(&SearchJson {
        kind: search.type_description(),
        search: search.pattern(),
        addresses: search.addresses(),
        only_path: search.only_path(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewPhraseJson<'a> {
    phrase: &'a str,
    words: usize,
    wallet_check: bool,
    fingerprint_with_passphrase: String,
}

/// Draws a new 24-word phrase from `random`, which the draw probes first and refuses when it cannot
/// be random (RANDOM_FAILED). With `wallet_check`, it draws until the phrase passes
/// the wallet check with the passphrase, which must not be empty; that takes about 65,536 BIP39
/// seeds, and `on_draws(draws)` hears the count every 1,024 draws, a throw there stopping it
/// (CANCELLED). A page may run it in several workers at once and take the first result. Returns
/// JSON `{ phrase, words, walletCheck, fingerprintWithPassphrase }`.
#[wasm_bindgen(js_name = drawPhrase)]
pub fn draw_phrase(
    passphrase_utf8: Vec<u8>,
    wallet_check: bool,
    mut random: JsRandom,
    on_draws: &js_sys::Function,
) -> Result<js_sys::JsString, JsError> {
    let passphrase = SecretText::new(passphrase_utf8);
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let draw = if wallet_check {
        PhraseDraw::with_check(passphrase)
    } else {
        Ok(PhraseDraw::unchecked())
    }
    .map_err(js_error)?;
    let phrase = draw
        .draw(&mut random, &mut |draws| {
            on_draws
                .call1(&JsValue::UNDEFINED, &JsValue::from(draws as f64))
                .map(|_| ())
                .map_err(|_| MhfeError::Cancelled)
        })
        .map_err(js_error)?;
    let fingerprint = master_fingerprint(phrase.phrase(), passphrase).map_err(js_error)?;
    secret_json(&NewPhraseJson {
        phrase: phrase.phrase(),
        words: phrase.phrase().split(' ').count(),
        wallet_check: phrase.checked(),
        fingerprint_with_passphrase: hex::encode(fingerprint),
    })
}

/// The self-check of the wallet module at `tier`, "startup" or "full": the BIP39 word list, the
/// wallet hashes, seeds, keys and address encodings, what an address check searches (the
/// statement of [`describe_address`]), the wallet check and the random source, each with a case it
/// must refuse. The startup tier tries the source checks on scripted sources only;
/// the full tier also tries `random`, the page's `crypto.getRandomValues`. `skip_ids` leaves out
/// parts that another module of the page has passed already. Returns JSON as described at
/// [`run_self_check`]; no part names a coin.
#[wasm_bindgen(js_name = selfCheckWallet)]
pub fn self_check_wallet(
    tier: &str,
    skip_ids: Vec<String>,
    mut random: JsRandom,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    run_self_check(
        sets::wallet(Some(&mut random)),
        tier,
        &skip_ids,
        on_start,
        on_result,
    )
}
