//! The repair module: the repair words of a container and the repair of a damaged plate
//! (MHFE-REPAIR-1), and its self-check. No Argon2 and no secret: a container alone reveals nothing.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{js_error, json, run_self_check, whole_number};
use crate::repair::{self, Repaired, PROFILE, RECOMMENDED_REPAIR_WORDS, REPAIR_WORD_COUNTS};
use crate::self_check::sets;
use crate::wallet::master_fingerprint;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capacity {
    count: usize,
    unreadable: usize,
    wrong: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairParameters {
    version: &'static str,
    profile: &'static str,
    repair_word_counts: [usize; 4],
    recommended_repair_words: usize,
    repair_capacities: Vec<Capacity>,
}

/// The fixed values of the repair module.
#[wasm_bindgen(js_name = repairParameters)]
pub fn repair_parameters() -> Result<String, JsError> {
    json(&RepairParameters {
        version: env!("CARGO_PKG_VERSION"),
        profile: PROFILE,
        repair_word_counts: REPAIR_WORD_COUNTS,
        recommended_repair_words: RECOMMENDED_REPAIR_WORDS,
        repair_capacities: REPAIR_WORD_COUNTS
            .iter()
            .map(|&count| capacity(count))
            .collect(),
    })
}

fn capacity(count: usize) -> Capacity {
    let (unreadable, wrong) = repair::capacity(count);
    Capacity {
        count,
        unreadable,
        wrong,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CardJson {
    profile: &'static str,
    words: String,
    repairs_unreadable: usize,
    repairs_wrong: usize,
}

/// The repair words of a container, as JSON `{ profile, words, repairsUnreadable, repairsWrong }`.
#[wasm_bindgen(js_name = repairWords)]
pub fn repair_words(container: &str, count: f64) -> Result<String, JsError> {
    let count = whole_number(count, "INVALID_REPAIR_WORDS", "the repair word count")? as usize;
    let words = repair::repair_words(container, count).map_err(js_error)?;
    let capacity = capacity(count);
    json(&CardJson {
        profile: PROFILE,
        words,
        repairs_unreadable: capacity.unreadable,
        repairs_wrong: capacity.wrong,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeJson<'a> {
    on_card: bool,
    position: usize,
    read: Option<&'a str>,
    word: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairedJson<'a> {
    container: &'a str,
    /// The master key fingerprint of the container's own words, without a passphrase: not the
    /// wallet's, but a way to tell this container from another.
    container_fingerprint: String,
    unchanged: bool,
    plate_words: &'a [usize],
    card_words: &'a [usize],
    changes: Vec<ChangeJson<'a>>,
}

/// Repairs a container from its plate and card words as read, `?` for a word that cannot be read.
/// Returns JSON `{ container, containerFingerprint, unchanged, plateWords, cardWords, changes:
/// [{ onCard, position, read, word }] }`. A repair is never silent, and it does not show that the
/// card belongs to the plate, which only a rehearsal against the wallet does.
#[wasm_bindgen(js_name = repairPlate)]
pub fn repair_plate(plate: &str, card: &str) -> Result<String, JsError> {
    let repaired: Repaired = repair::repair(plate, card).map_err(js_error)?;
    let fingerprint = master_fingerprint(&repaired.container, "").map_err(js_error)?;
    json(&RepairedJson {
        container: &repaired.container,
        container_fingerprint: hex::encode(fingerprint),
        unchanged: repaired.changes.is_empty(),
        plate_words: &repaired.plate_words,
        card_words: &repaired.card_words,
        changes: repaired
            .changes
            .iter()
            .map(|change| ChangeJson {
                on_card: change.on_card,
                position: change.position,
                read: change.read.as_deref(),
                word: &change.word,
            })
            .collect(),
    })
}

/// The self-check of the repair module at `tier`, "startup" or "full": the BIP39 word list and
/// the repair words, each with a case it must refuse. `skip_ids` leaves out parts that another
/// module of the page has passed already. Returns JSON as described at [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckRepair)]
pub fn self_check_repair(
    tier: &str,
    skip_ids: Vec<String>,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    run_self_check(sets::repair(), tier, &skip_ids, on_start, on_result)
}
