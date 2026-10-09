//! The word hints of the wallet and password modules (mhfe::word_hints): what a page shows below a
//! word being typed from the BIP39 or the EFF list, by the same rule as the command-line tool.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{js_error, secret_json, SecretText};
use crate::word_hints::{Hint, WordList};
use crate::MhfeError;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HintJson {
    /// "nothing", "count", "words" or "noWord".
    hint: &'static str,
    count: usize,
    words: &'static [&'static str],
    completion: CompletionJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompletionJson {
    letters: &'static str,
    word_ends: bool,
}

/// The hint for `typed_utf8`, a line typed so far from `list`, "bip39" or "eff" (INVALID_REQUEST
/// otherwise), as JSON `{ hint, count, words, completion: { letters, wordEnds } }`: "nothing" when
/// no word is being typed or it is whole with no longer word after it; "count" after one letter,
/// with how many words begin with it; "words" from two letters, with the words that begin with them
/// and their count; "noWord" when none does. `completion` is what Tab adds: the letters every such
/// word has next, and whether one word is left, which then ends with a space. The line may be part
/// of a password or a seed phrase: it is wiped after use, and so is the result's buffer, which
/// tells its last letters.
#[wasm_bindgen(js_name = wordHints)]
pub fn word_hints(list: &str, typed_utf8: Vec<u8>) -> Result<js_sys::JsString, JsError> {
    let typed = SecretText::new(typed_utf8);
    let list = WordList::from_name(list).map_err(js_error)?;
    let line = typed.text(MhfeError::InvalidRequest(
        "the typed text is not UTF-8".to_owned(),
    ))?;
    let (hint, count, words) = match list.hint(line) {
        Hint::Nothing => ("nothing", 0, &[][..]),
        Hint::Count(count) => ("count", count, &[][..]),
        Hint::Words(words) => ("words", words.len(), words),
        Hint::NoWord => ("noWord", 0, &[][..]),
    };
    let completion = list.completion(line);
    secret_json(&HintJson {
        hint,
        count,
        words,
        completion: CompletionJson {
            letters: completion.letters,
            word_ends: completion.word_ends,
        },
    })
}
