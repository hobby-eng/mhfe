//! The wallet module: the wallet check of a recovered phrase (MHFE-WALLET-CHECK-SEED-1), master key
//! fingerprints, what an address check searches, and its self-check. No Argon2, and nothing drawn
//! at random.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{js_error, json, run_self_check, whole_number, SecretText};
use crate::self_check::sets;
use crate::wallet::{master_fingerprint_text, AddressSearch, Coin, SearchLimits};
use crate::wallet_check::{self, WALLET_CHECK_BITS};
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
    master_fingerprint_text(phrase.phrase()?, passphrase).map_err(js_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchJson<'a> {
    coins: &'a [&'static str],
    #[serde(rename = "type")]
    kind: Option<&'a str>,
    search: &'a str,
    addresses: u128,
    only_path: bool,
}

/// What an address check would search, to show before it runs: JSON `{ coins, type, search,
/// addresses, onlyPath }`. `coin` is one of the ids of `walletParameters().coins` (INVALID_COIN
/// otherwise), or empty for every coin whose form the address has; `path` is empty for the
/// standard paths. `scan_gap` 0 states the usual search, and any other the first account's first
/// `scan_gap` receiving and change addresses, as the decoy search of two missing words looks for
/// an address. The library states it ([`AddressSearch::describe`]), the same call the self-check
/// part "address-search" compares with its known answers. Coins are given by their ids, which
/// `walletParameters().coins` names: a page for one coin carries no other coin's name.
#[wasm_bindgen(js_name = describeAddress)]
pub fn describe_address(
    address: &str,
    coin: &str,
    path: &str,
    scan_gap: f64,
) -> Result<String, JsError> {
    // 0 is the usual search; a gap is where the decoy search of two missing words looks.
    let limits = match whole_number(scan_gap, "INVALID_REQUEST", "scanGap")? {
        0 => SearchLimits::default(),
        gap => SearchLimits::first_account(gap).map_err(js_error)?,
    };
    let search = AddressSearch::describe_within(coin, address, path, limits).map_err(js_error)?;
    json(&SearchJson {
        coins: search.coins(),
        kind: search.type_description(),
        search: search.pattern(),
        addresses: search.addresses(),
        only_path: search.only_path(),
    })
}

/// The self-check of the wallet module at `tier`, "startup" or "full": the BIP39 word list, the
/// wallet hashes, seeds, keys and address encodings, what an address check searches (the
/// statement of [`describe_address`]), the wallet check and the word hints, each with a case it
/// must refuse. `skip_ids` leaves out parts that another module of the page has passed already.
/// Returns JSON as described at [`run_self_check`]; no part names a coin.
#[wasm_bindgen(js_name = selfCheckWallet)]
pub fn self_check_wallet(
    tier: &str,
    skip_ids: Vec<String>,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    run_self_check(sets::wallet(), tier, &skip_ids, on_start, on_result)
}
