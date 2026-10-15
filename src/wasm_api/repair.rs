//! The repair module: the repair words of a container and the repair of a damaged container phrase
//! (MHFE-REPAIR-1), and its self-check. No Argon2 and no secret: a container alone reveals nothing.

use crate::self_check::SelfCheck;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    container_fingerprint_text, js_error, json, repair_capacities, run_self_check, whole_number,
    CapacityJson,
};
use crate::repair::{
    ContainerReading, RepairWordCount, Repaired, PROFILE, RECOMMENDED_REPAIR_WORDS,
    REPAIR_WORD_COUNTS,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairParameters {
    version: &'static str,
    profile: &'static str,
    repair_word_counts: [usize; 4],
    recommended_repair_words: usize,
    repair_capacities: Vec<CapacityJson>,
}

/// The fixed values of the repair module.
#[wasm_bindgen(js_name = repairParameters)]
pub fn repair_parameters() -> Result<String, JsError> {
    json(&RepairParameters {
        version: env!("CARGO_PKG_VERSION"),
        profile: PROFILE,
        repair_word_counts: REPAIR_WORD_COUNTS,
        recommended_repair_words: RECOMMENDED_REPAIR_WORDS,
        repair_capacities: repair_capacities(),
    })
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
    let count = whole_number(count, crate::request::NumberField::RepairWordCount)? as usize;
    let count = RepairWordCount::new(count).map_err(js_error)?;
    let words = count.words_of(container).map_err(js_error)?;
    let (unreadable, wrong) = count.capacity();
    json(&CardJson {
        profile: PROFILE,
        words,
        repairs_unreadable: unreadable,
        repairs_wrong: wrong,
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
    container_words: &'a [usize],
    card_words: &'a [usize],
    changes: Vec<ChangeJson<'a>>,
}

/// Repairs a container from its container phrase and card words as read, `?` for a word that cannot
/// be read. Returns JSON `{ container, containerFingerprint, unchanged, containerWords, cardWords,
/// changes: [{ onCard, position, read, word }] }`. A repair is never silent, and it does not show
/// that the card belongs to the container phrase, which only a rehearsal against the wallet does.
#[wasm_bindgen(js_name = repairContainer)]
pub fn repair_container(written: &str, card: &str) -> Result<String, JsError> {
    let repaired: Repaired = RepairWordCount::repair(written, card).map_err(js_error)?;
    let fingerprint = container_fingerprint_text(repaired.container())?;
    json(&RepairedJson {
        container: repaired.container(),
        container_fingerprint: fingerprint,
        unchanged: repaired.changes().is_empty(),
        container_words: repaired.container_words(),
        card_words: repaired.card_words(),
        changes: repaired
            .changes()
            .iter()
            .map(|change| ChangeJson {
                on_card: change.on_card(),
                position: change.position(),
                read: change.read(),
                word: change.word(),
            })
            .collect(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadingJson {
    reading: &'static str,
    word_count: usize,
    unreadable: Vec<usize>,
}

/// What a container phrase as typed is, before it is decrypted, checked or repaired, as JSON
/// `{ reading, wordCount, unreadable }`: "container" as it stands; "marked", words typed as "?"
/// with `unreadable` every word that cannot be read, from 1, for which a page asks for the repair
/// words at once; "notAContainer", a container's length but not a container, for which it offers
/// them; "wrongLength", a length no container has.
#[wasm_bindgen(js_name = inspectContainer)]
pub fn inspect_container(written: &str) -> Result<String, JsError> {
    let word_count = written.split_whitespace().count();
    let (reading, unreadable) = match ContainerReading::read(written) {
        ContainerReading::Container => ("container", Vec::new()),
        ContainerReading::Marked { unreadable } => ("marked", unreadable),
        ContainerReading::NotAContainer => ("notAContainer", Vec::new()),
        ContainerReading::WrongLength(_) => ("wrongLength", Vec::new()),
    };
    json(&ReadingJson {
        reading,
        word_count,
        unreadable,
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
    run_self_check(SelfCheck::repair(), tier, &skip_ids, on_start, on_result)
}
