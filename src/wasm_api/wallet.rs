//! The wallet module: the wallet check of a recovered phrase (MHFE-WALLET-CHECK-SEED-1), master key
//! fingerprints, what an address check searches, new 24-word phrases, and its self-check. No
//! Argon2.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    call_page, js_error, json, run_self_check, secret_json, whole_number, JsRandom, SecretText,
};
use crate::self_check::sets;
use crate::wallet::{master_fingerprint_text, AddressSearch, Coin, SearchLimits};
use crate::wallet_check::{self, PhraseDraw, DRAW_REPORT_INTERVAL, WALLET_CHECK_BITS};
use crate::word_wishes::{
    Place, Randomness, WordWishes, MAX_CHOSEN_WORDS, MAX_NEVER_USE_WORDS, RECOMMENDED_RANDOM_BITS,
};
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
    max_chosen_words: usize,
    max_never_use_words: usize,
    recommended_random_bits: u32,
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
        max_chosen_words: MAX_CHOSEN_WORDS,
        max_never_use_words: MAX_NEVER_USE_WORDS,
        recommended_random_bits: RECOMMENDED_RANDOM_BITS,
    })
}

/// The wishes of a new phrase as a page passes them: `chosen_words`, the chosen words one space
/// apart, a secret; `places`, the place of each, 0 for anywhere and otherwise its position from
/// 1; and `never_use`, the words never to use, one space apart.
fn wishes_from(chosen_words: &str, places: &[u32], never_use: &str) -> Result<WordWishes, JsError> {
    let words: Vec<&str> = chosen_words.split_whitespace().collect();
    if words.len() != places.len() {
        return Err(js_error(MhfeError::InvalidRequest(
            "give one place for every chosen word".to_owned(),
        )));
    }
    let chosen: Vec<(Place, &str)> = places
        .iter()
        .zip(words)
        .map(|(&place, word)| match place {
            0 => (Place::Anywhere, word),
            position => (Place::At(position as usize), word),
        })
        .collect();
    let never: Vec<&str> = never_use.split_whitespace().collect();
    WordWishes::new(&chosen, &never).map_err(js_error)
}

/// The refusal of chosen words that are not UTF-8 text.
fn not_utf8() -> MhfeError {
    MhfeError::InvalidWordWish("the chosen words are not UTF-8 text".to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DrawJson {
    random_bits: f64,
    /// "full", "ample" or "notRecommended".
    randomness: &'static str,
    expected_draws: f64,
    /// Whether chosen words make the phrase recognisable ([`mhfe::word_wishes::WishOdds`]).
    recognisable: bool,
    /// Whether the chosen word has a fixed position, where it costs more than anywhere.
    fixed_position: bool,
}

/// What a new phrase drawn with these wishes keeps, before it is drawn, as JSON `{ randomBits,
/// randomness, expectedDraws, recognisable, fixedPosition }`: the random bits it keeps, about, with
/// the wallet check's 16 taken when `wallet_check`; "full" for all 256, "ample" from 240,
/// "notRecommended" below, rated without a word never to use; the draws it is expected to take;
/// whether a chosen word lets someone who learns or guesses it rule out almost every wrong password
/// and tell the wallet from a decoy; and whether that word has a fixed position. Wishes that cannot
/// be used are refused (INVALID_WORD_WISH). The chosen words are wiped afterwards.
#[wasm_bindgen(js_name = describeDraw)]
pub fn describe_draw(
    chosen_words_utf8: Vec<u8>,
    places: Vec<u32>,
    never_use: &str,
    wallet_check: bool,
) -> Result<String, JsError> {
    let chosen_words = SecretText::new(chosen_words_utf8);
    let wishes = wishes_from(chosen_words.text(not_utf8())?, &places, never_use)?;
    let check_bits = if wallet_check { WALLET_CHECK_BITS } else { 0 };
    let odds = wishes.odds(check_bits);
    json(&DrawJson {
        random_bits: odds.random_bits,
        randomness: match odds.randomness {
            Randomness::Full => "full",
            Randomness::Ample => "ample",
            Randomness::NotRecommended => "notRecommended",
        },
        expected_draws: odds.expected_draws,
        recognisable: odds.recognisable,
        fixed_position: odds.fixed_position,
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
    #[serde(rename = "type")]
    kind: Option<&'a str>,
    search: &'a str,
    addresses: u128,
    only_path: bool,
}

/// What an address check would search, to show before it runs: JSON `{ type, search, addresses,
/// onlyPath }`. `coin` is one of the ids of `walletParameters().coins` (INVALID_COIN otherwise);
/// `path` is empty for the standard paths. `scan_gap` 0 states the usual search, and any other
/// the first account's first `scan_gap` receiving and change addresses, as the decoy search of two
/// missing words looks for an address. The library states it ([`AddressSearch::describe`]),
/// the same call the self-check part "address-search" compares with its known answers. No coin is
/// named here: the glue carries this text, and a page for one coin carries no other coin's name.
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
/// be random (RANDOM_FAILED). A passphrase is typed twice: `passphrase_repeat_utf8` must be the
/// same text (PASSPHRASES_DIFFER). With `wallet_check`, it draws until the phrase passes
/// the wallet check with the passphrase, which must not be empty; that takes about 65,536 BIP39
/// seeds, and `on_draws(draws)` hears the count every 1,024 draws, a throw there stopping it
/// (CANCELLED). The phrase meets the wishes given as for [`describe_draw`], refused as it says. A
/// page may run it in several workers at once and take the first result. Returns JSON `{ phrase,
/// words, walletCheck, fingerprintWithPassphrase }`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = drawPhrase)]
pub fn draw_phrase(
    passphrase_utf8: Vec<u8>,
    passphrase_repeat_utf8: Vec<u8>,
    chosen_words_utf8: Vec<u8>,
    places: Vec<u32>,
    never_use: &str,
    wallet_check: bool,
    mut random: JsRandom,
    on_draws: &js_sys::Function,
) -> Result<js_sys::JsString, JsError> {
    // Every secret under a wiping owner before any is read, so that a refusal of one drops the
    // others wiped too (AUD-013-SEC001).
    let passphrase = SecretText::new(passphrase_utf8);
    let repeat = SecretText::new(passphrase_repeat_utf8);
    let chosen_words = SecretText::new(chosen_words_utf8);
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let repeat = repeat.text(MhfeError::InvalidPassphrase)?;
    wallet_check::require_same_passphrase(passphrase, repeat).map_err(js_error)?;
    let wishes = wishes_from(chosen_words.text(not_utf8())?, &places, never_use)?;
    let draw = if wallet_check {
        PhraseDraw::with_check(passphrase)
    } else {
        Ok(PhraseDraw::unchecked())
    }
    .map(|draw| draw.with_wishes(wishes))
    .map_err(js_error)?;
    let phrase = draw
        .draw(&mut random, &mut |draws| {
            call_page(on_draws, &[JsValue::from(draws as f64)])
        })
        .map_err(js_error)?;
    let fingerprint = master_fingerprint_text(phrase.phrase(), passphrase).map_err(js_error)?;
    secret_json(&NewPhraseJson {
        phrase: phrase.phrase(),
        words: phrase.phrase().split(' ').count(),
        wallet_check: phrase.checked(),
        fingerprint_with_passphrase: fingerprint,
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
