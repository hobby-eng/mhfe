//! The passwords module: the review of a typed password under its check word
//! (MHFE-PASSWORD-CHECK-1), the strength estimate, the password generator and its self-check. No
//! Argon2.

use crate::self_check::SelfCheck;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    js_error, json, review_choice, run_self_check, secret_json, whole_number, yes_or_no, JsRandom,
    SecretText,
};
use crate::check_word::{Correction, PasswordReview, Reading, PROFILE};
use crate::new_password::{
    PasswordRecipe, DEFAULT_CHARACTERS, DEFAULT_WORDS, MOST_CHARACTERS, MOST_WORDS,
    RECOMMENDED_CHARACTERS, RECOMMENDED_WORDS,
};
use crate::strength::{Strength, WEAK_BELOW_BITS};
use crate::Password;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordParameters {
    version: &'static str,
    check_word_profile: &'static str,
    default_words: usize,
    recommended_words: usize,
    most_words: usize,
    default_characters: usize,
    recommended_characters: usize,
    most_characters: usize,
    weak_below_bits: f64,
}

/// The fixed values of the passwords module.
#[wasm_bindgen(js_name = passwordParameters)]
pub fn password_parameters() -> Result<String, JsError> {
    json(&PasswordParameters {
        version: env!("CARGO_PKG_VERSION"),
        check_word_profile: PROFILE,
        default_words: DEFAULT_WORDS,
        recommended_words: RECOMMENDED_WORDS,
        most_words: MOST_WORDS,
        default_characters: DEFAULT_CHARACTERS,
        recommended_characters: RECOMMENDED_CHARACTERS,
        most_characters: MOST_CHARACTERS,
        weak_below_bits: WEAK_BELOW_BITS,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairJson<'a> {
    position: usize,
    word: &'a str,
    /// The word as typed that a repair replaces; null for a restored word, which may be "?" or a
    /// long word outside the list.
    typed: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewJson<'a> {
    profile: &'static str,
    reading: &'static str,
    correction: Option<&'static str>,
    correction_text: Option<&'static str>,
    offers_correction: bool,
    repairs_first: bool,
    repairs: Vec<RepairJson<'a>>,
}

/// Reviews a typed password under the check word profile, before any Argon2 work. When
/// `repeated`, `repeat_utf8` is the password typed a second time, and the two entries must be the
/// same, an empty repetition included (PASSWORDS_DIFFER), as they are compared before any
/// review. Returns JSON `{ profile, reading, correction, correctionText, offersCorrection,
/// repairsFirst, repairs: [{ position, word, typed }] }`; `reading` is
/// "notThisShape", "fits", "restorable" or "mismatch". It holds words of the password.
#[wasm_bindgen(js_name = reviewPassword)]
pub fn review_password(
    password_utf8: Vec<u8>,
    repeat_utf8: Vec<u8>,
    repeated: JsValue,
) -> Result<js_sys::JsString, JsError> {
    let password = SecretText::new(password_utf8);
    let repeat = SecretText::new(repeat_utf8);
    let typed = password.text(crate::PasswordError::InvalidPasswordUtf8.into())?;
    let repeat = repeat.text(crate::PasswordError::InvalidPasswordUtf8.into())?;
    let repeated = yes_or_no(&repeated, crate::request::BooleanField::Repeated)?;
    Password::check_typed_twice(typed, repeated.then_some(repeat)).map_err(js_error)?;
    let review = PasswordReview::of(typed);
    let restorable = review.reading() == Reading::Restorable;
    secret_json(&ReviewJson {
        profile: PROFILE,
        reading: match review.reading() {
            Reading::NotThisShape => "notThisShape",
            Reading::Fits => "fits",
            Reading::Restorable => "restorable",
            Reading::Mismatch => "mismatch",
        },
        correction: review.correction().map(|correction| match correction {
            Correction::ExtraSpaces => "extraSpaces",
            Correction::Capitals => "capitals",
            Correction::SpacesAndCapitals => "spacesAndCapitals",
        }),
        correction_text: review.correction().map(Correction::text),
        offers_correction: review.offers_correction(),
        repairs_first: review.repairs_first(),
        repairs: review
            .repairs()
            .iter()
            .map(|repair| RepairJson {
                position: repair.position(),
                word: repair.word(),
                typed: (!restorable).then(|| review.typed_word(repair)),
            })
            .collect(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StrengthJson {
    bits: f64,
    weak: bool,
}

/// The rough strength estimate of a password or passphrase, after the review choice the person
/// made (`choice` and `position` as for the long operations), so that it is of the final text.
/// Returns JSON `{ bits, weak }`.
#[wasm_bindgen(js_name = passwordStrength)]
pub fn password_strength(
    password_utf8: Vec<u8>,
    choice: &str,
    position: f64,
) -> Result<String, JsError> {
    let password = SecretText::new(password_utf8);
    let typed = password.text(crate::PasswordError::InvalidPasswordUtf8.into())?;
    let chosen =
        PasswordReview::choose(typed, review_choice(choice, position)?).map_err(js_error)?;
    let strength = Strength::of(&chosen);
    json(&StrengthJson {
        bits: strength.bits(),
        weak: strength.is_weak(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewPasswordJson<'a> {
    password: &'a str,
    bits: f64,
    weak: bool,
    check_word: bool,
}

/// Makes a password. `kind` is "words", "checkWord" or "characters"; `count` the words or
/// characters, by default as many as the command-line tool makes: 5 words or 16 characters.
/// "checkWord" always makes five words and their check word and takes no count (INVALID_REQUEST),
/// as `mhfe password` refuses `--check-word` with `--words`, rather than give another size than
/// the one asked for. With `rolls_utf8` not empty, the words come from real dice, five digits from
/// 1 to 6 per word; otherwise from `random`, which the recipe probes first and refuses when it
/// cannot be random (RANDOM_FAILED). Returns JSON `{ password, bits, weak, checkWord }`, `bits` a
/// number as `passwordStrength` gives it.
#[wasm_bindgen(js_name = makePassword)]
pub fn make_password(
    kind: &str,
    count: Option<f64>,
    rolls_utf8: Vec<u8>,
    mut random: JsRandom,
) -> Result<js_sys::JsString, JsError> {
    let rolls = SecretText::new(rolls_utf8);
    let size = |default: usize| match count {
        None => Ok(default),
        Some(count) => {
            whole_number(count, crate::request::NumberField::PasswordSize).map(|n| n as usize)
        }
    };
    let recipe = match kind {
        "words" => PasswordRecipe::words(size(DEFAULT_WORDS)?),
        // The class's TypeError (web/passwords.js) is a deliberate copy of this refusal, made
        // before a worker starts; scripts/verify-browser-package.mjs keeps both equal.
        "checkWord" if count.is_some() => {
            Err(crate::new_password::NewPasswordError::CheckWordCount)
        }
        "checkWord" => Ok(PasswordRecipe::check_word()),
        "characters" => PasswordRecipe::characters(size(DEFAULT_CHARACTERS)?),
        _ => Err(crate::new_password::NewPasswordError::UnknownKind),
    }
    .map_err(js_error)?;
    let rolls = rolls.text(crate::eff::EffError::InvalidDiceRolls(1).into())?;
    let password = if rolls.is_empty() {
        recipe.make(&mut random)
    } else {
        recipe.make_from_rolls(rolls)
    }
    .map_err(js_error)?;
    secret_json(&NewPasswordJson {
        password: password.text(),
        bits: recipe.bits(),
        weak: recipe.is_weak(),
        check_word: recipe.has_check_word(),
    })
}

/// The self-check of the passwords module at `tier`, "startup" or "full": the Unicode tables of
/// passwords, the check word, the generator and the random source, each with a case it must
/// refuse. The startup tier tries the source checks on scripted sources only; the full tier also
/// tries `random`, the page's `crypto.getRandomValues`. `skip_ids` leaves out parts that another
/// module of the page has passed already. Returns JSON as described at [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckPasswords)]
pub fn self_check_passwords(
    tier: &str,
    skip_ids: Vec<String>,
    mut random: JsRandom,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    run_self_check(
        SelfCheck::passwords(Some(&mut random)),
        tier,
        &skip_ids,
        on_start,
        on_result,
    )
}
