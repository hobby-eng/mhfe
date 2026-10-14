//! The core module: encryption, recovery, the rehearsal check, rekey, hidden wallets and the
//! self-test, with Argon2, and the self-checks of these parts and of the page's Argon2 builds.
//! Each call runs one whole operation synchronously inside its worker; the worker reports
//! progress, and the page cancels by terminating the worker. A rekey and a session of hidden
//! wallets live in one worker over several calls, as objects.
//!
//! Every call that runs Argon2 first runs the known answer of the page's Argon2 build, and again
//! after its last round: a result is returned only when the build gave its known answer on both
//! sides of the work (SELF_CHECK_FAILED otherwise), which also covers the optimized code a browser
//! makes of a long-running loop.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    call_page, container_fingerprint_text, js_error, json, repair_capacities, review_choice,
    secret_json, whole_number, yes_or_no, CapacityJson, SecretText,
};
use crate::check_word;
use crate::engine::browser::{BrowserEngine, JsArgon2, HIGHEST_BROWSER_MEMORY_LEVEL};
use crate::mhfe::RecoveredPhrase;
use crate::operation::{
    Encryption, Keep, KeepItem, Sealed, Stage, StageCallback, WalletPassphrase,
};
use crate::rekey::ReplacementRehearsal;
use crate::repair::{PROFILE as REPAIR_PROFILE, RECOMMENDED_REPAIR_WORDS, REPAIR_WORD_COUNTS};
use crate::search::DECOY_SCAN_GAP;
use crate::wallet::{fingerprint_text, master_fingerprint_text, parse_fingerprint, Address, Coin};
use crate::{
    container_fingerprint, ConfirmationNeeded, ContainerFacts, HiddenWallets, Mhfe, MhfeError,
    OriginalFacts, Password, PhraseLength, Recovery, RecoveryStatus, ReferenceTarget, Settings,
    Suite, WordCount, WorkFactor, BUILT_IN_CHECK_WORD_COUNTS, MAX_MEMORY_LEVEL, MAX_PIM, ROUNDS,
    SAME_LENGTH_SUITE_ID, SUITE_ID, WORD_COUNTS,
};

mod check;
mod hidden;
mod rekey;
mod search;
mod self_test;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuiteParameters {
    version: &'static str,
    suite_id: &'static str,
    same_length_suite_id: &'static str,
    rounds: u32,
    max_pim: u32,
    max_memory_level: u32,
    highest_browser_memory_level: u32,
    word_counts: [usize; 5],
    built_in_check_word_counts: &'static [usize],
    repair_word_counts: [usize; 4],
    recommended_repair_words: usize,
    repair_capacities: Vec<CapacityJson>,
    /// The error codes after which a session of hidden wallets stays open: the library's
    /// `KEEPS_SESSION_OPEN`, under the name the page reads.
    hidden_wallet_refusals: &'static [&'static str],
    /// The addresses of each chain searched for two missing words unless a page says otherwise.
    decoy_scan_gap: u32,
    /// The parts of the self-check that run Argon2: at 1 MiB, then at 64 and 256 MiB.
    argon2_parts: [&'static str; 2],
}

/// The fixed suite values and the limits of the browser build.
#[wasm_bindgen(js_name = suiteParameters)]
pub fn suite_parameters() -> Result<String, JsError> {
    json(&SuiteParameters {
        version: env!("CARGO_PKG_VERSION"),
        suite_id: SUITE_ID,
        same_length_suite_id: SAME_LENGTH_SUITE_ID,
        rounds: ROUNDS,
        max_pim: MAX_PIM,
        max_memory_level: MAX_MEMORY_LEVEL,
        highest_browser_memory_level: HIGHEST_BROWSER_MEMORY_LEVEL,
        word_counts: WORD_COUNTS,
        built_in_check_word_counts: &BUILT_IN_CHECK_WORD_COUNTS,
        repair_word_counts: REPAIR_WORD_COUNTS,
        recommended_repair_words: RECOMMENDED_REPAIR_WORDS,
        hidden_wallet_refusals: &HiddenWallets::KEEPS_SESSION_OPEN,
        repair_capacities: repair_capacities(),
        decoy_scan_gap: DECOY_SCAN_GAP,
        argon2_parts: crate::engine::known_answers::PART_IDS,
    })
}

/// Checks a password before anything runs. The bytes are wiped afterwards.
#[wasm_bindgen(js_name = checkPassword)]
pub fn check_password(password_utf8: Vec<u8>) -> Result<(), JsError> {
    password_from(password_utf8, "", 0.0).map(|_| ())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChoiceJson<'a> {
    same_length: bool,
    words: usize,
    wrong_word_passes_one_in: u32,
    /// The other lengths detection could read from this container, as the command-line tool warns
    /// of them once the container is chosen: none for a same-length one.
    other_lengths: &'a [usize],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhraseFactsJson<'a> {
    phrase: &'a str,
    words: usize,
    other_lengths: &'a [usize],
    containers: Vec<ChoiceJson<'a>>,
}

/// Reads an original phrase, its UTF-8 bytes as the person may have typed it, and returns JSON
/// `{ phrase, words, otherLengths, containers: [{ sameLength, words, wrongWordPassesOneIn,
/// otherLengths }] }`, the phrase with every word written out, for showing back, and the
/// containers it can be encrypted into with the consequence of each; `otherLengths` at the top is
/// the 24-word container's. The bytes are wiped afterwards.
#[wasm_bindgen(js_name = describePhrase)]
pub fn describe_phrase(phrase_utf8: Vec<u8>) -> Result<js_sys::JsString, JsError> {
    let phrase = SecretText::new(phrase_utf8);
    let facts = OriginalFacts::read(phrase.phrase()?).map_err(js_error)?;
    secret_json(&PhraseFactsJson {
        phrase: facts.words(),
        words: facts.word_count(),
        other_lengths: facts.other_lengths(),
        containers: facts
            .container_choices()
            .into_iter()
            .map(|choice| ChoiceJson {
                same_length: choice.suite() == Suite::SameLength,
                words: choice.word_count(),
                wrong_word_passes_one_in: choice.wrong_word_passes_one_in(),
                other_lengths: facts.other_lengths_in(choice.suite()),
            })
            .collect(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainerFactsJson<'a> {
    container: &'a str,
    words: usize,
    suite_id: &'static str,
    phrase_lengths: &'a [usize],
    built_in_check_lengths: &'static [usize],
    /// For each phrase length: "builtInCheck" or "walletOrOwner", what confirms a recovery.
    confirmation_for: std::collections::BTreeMap<String, &'static str>,
    hidden_wallets: bool,
    offers_wallet_check: bool,
    container_fingerprint: String,
}

/// Reads a container and returns JSON `{ container, words, suiteId, phraseLengths,
/// builtInCheckLengths, confirmationFor, hiddenWallets, offersWalletCheck, containerFingerprint }`.
#[wasm_bindgen(js_name = describeContainer)]
pub fn describe_container(container: &str) -> Result<String, JsError> {
    let facts = ContainerFacts::read(container).map_err(js_error)?;
    let mut confirmation_for = std::collections::BTreeMap::new();
    for &words in facts.phrase_lengths() {
        let length = PhraseLength::Words(WordCount::new(words).map_err(js_error)?);
        let needed = facts.confirmation_needed(length).map_err(js_error)?;
        confirmation_for.insert(words.to_string(), confirmation_name(needed));
    }
    // 0: the length detected after the recovery.
    let detected = facts
        .confirmation_needed(PhraseLength::Detect)
        .map_err(js_error)?;
    confirmation_for.insert("0".to_owned(), confirmation_name(detected));
    json(&ContainerFactsJson {
        container: facts.words(),
        words: facts.word_count(),
        suite_id: facts.suite().id(),
        phrase_lengths: facts.phrase_lengths(),
        built_in_check_lengths: facts.built_in_check_lengths(),
        confirmation_for,
        hidden_wallets: facts.opens_hidden_wallets(),
        offers_wallet_check: facts.offers_wallet_check(),
        container_fingerprint: fingerprint_text(facts.fingerprint().map_err(js_error)?),
    })
}

fn confirmation_name(needed: ConfirmationNeeded) -> &'static str {
    match needed {
        ConfirmationNeeded::BuiltInCheck => "builtInCheck",
        ConfirmationNeeded::WalletOrOwner => "walletOrOwner",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnverifiedJson<'a> {
    container: &'a str,
    container_fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "item")]
enum KeepJson {
    ContainerWords { words: usize },
    Password,
    Passphrase,
    PassphraseIfAny,
    RepairWords,
    Pim { value: u32 },
    MemoryLevel { value: u32 },
    WordCount { words: usize },
    OldContainer,
    OldPasswords,
}

/// An item to keep as the page reads it, with `apart: true` where the library keeps it apart from
/// the container phrase ([`KeepItem::kept_apart`]).
#[derive(Serialize)]
struct KeptJson {
    #[serde(flatten)]
    item: KeepJson,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    apart: bool,
}

/// The library's keep list as the page reads it.
fn keep_json(keep: &Keep) -> Vec<KeptJson> {
    keep.items()
        .iter()
        .map(|item| KeptJson {
            item: match *item {
                KeepItem::ContainerWords(words) => KeepJson::ContainerWords { words },
                KeepItem::Password => KeepJson::Password,
                KeepItem::Passphrase => KeepJson::Passphrase,
                KeepItem::PassphraseIfAny => KeepJson::PassphraseIfAny,
                KeepItem::RepairWords => KeepJson::RepairWords,
                KeepItem::Pim(value) => KeepJson::Pim { value },
                KeepItem::MemoryLevel(value) => KeepJson::MemoryLevel { value },
                KeepItem::WordCount(words) => KeepJson::WordCount { words },
                KeepItem::OldContainer => KeepJson::OldContainer,
                KeepItem::OldPasswords => KeepJson::OldPasswords,
            },
            apart: item.kept_apart(),
        })
        .collect()
}

/// What to keep of the old container of a rekey made at `pim` and `memory_level` until the funds
/// of the wallets that other passwords open on it are moved, as JSON `[{ item, value? }]`:
/// "oldContainer", "oldPasswords", and "pim" or "memoryLevel" where it is not 0
/// ([`Keep::old_container`]). A page says it before every rekey, whatever the container.
#[wasm_bindgen(js_name = keepOldContainer)]
pub fn keep_old_container(pim: f64, memory_level: f64) -> Result<String, JsError> {
    json(&keep_json(&Keep::old_container(work_from(
        pim,
        memory_level,
    )?)))
}

/// What the rehearsal of a rekey's new container compares ([`ReplacementRehearsal`]).
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum RehearsalJson {
    BuiltInCheck,
    ConfirmingReference,
    Fingerprint { fingerprint: String },
}

impl From<&ReplacementRehearsal> for RehearsalJson {
    fn from(rehearsal: &ReplacementRehearsal) -> Self {
        match rehearsal {
            ReplacementRehearsal::BuiltInCheck => Self::BuiltInCheck,
            ReplacementRehearsal::ConfirmingReference => Self::ConfirmingReference,
            ReplacementRehearsal::Fingerprint(fingerprint) => Self::Fingerprint {
                fingerprint: fingerprint_text(*fingerprint),
            },
        }
    }
}

/// A rekey's result: the sealed container as `encrypt` gives it, and what its rehearsal compares.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResealedJson<'a> {
    #[serde(flatten)]
    sealed: SealedJson<'a>,
    rehearsal: RehearsalJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedJson<'a> {
    container: &'a str,
    suite_id: &'static str,
    container_fingerprint: String,
    built_in_check: bool,
    other_lengths: &'a [usize],
    repair_words: Option<&'a str>,
    repair_profile: Option<&'static str>,
    keep: Vec<KeptJson>,
}

/// The result of an encryption or a rekey: the checked container and what to keep.
fn sealed_view(
    sealed: &Sealed,
    work: WorkFactor,
    passphrase: WalletPassphrase,
) -> Result<SealedJson<'_>, JsError> {
    Ok(SealedJson {
        container: sealed.container(),
        suite_id: sealed.suite().id(),
        container_fingerprint: container_fingerprint_text(sealed.container())?,
        built_in_check: sealed.built_in_check(),
        other_lengths: sealed.other_lengths(),
        repair_words: sealed.repair_words(),
        repair_profile: sealed.repair_words().map(|_| REPAIR_PROFILE),
        keep: keep_json(&sealed.keep(work, passphrase)),
    })
}

fn sealed_json(
    sealed: &Sealed,
    work: WorkFactor,
    passphrase: WalletPassphrase,
) -> Result<String, JsError> {
    json(&sealed_view(sealed, work, passphrase)?)
}

/// Encrypts the phrase, its UTF-8 bytes `phrase_utf8`, and returns JSON `{ container, suiteId,
/// containerFingerprint, builtInCheck, otherLengths, repairWords, repairProfile, keep: [{ item,
/// ... }] }` once its check has passed: a 24-word container, or with `same_length`, which only the
/// user's own choice may set, a container as long as the 12- to 21-word phrase.
///
/// The password is typed twice: `repeat_utf8` must be the same text (PASSWORDS_DIFFER), and
/// `choice` with `position` applies a correction or repair of its check word review ("" keeps it
/// as typed). `repair_word_count` is 0 for none, or 2, 4, 6 or 8. `wallet_has_passphrase` is
/// whether the wallet has a BIP39 passphrase, where the page knows it: true adds it to what to
/// keep, since MHFE encrypts only the phrase, and false leaves it out. Undefined or null, not
/// known, adds `{ item: "passphraseIfAny" }` in its place; anything else is INVALID_REQUEST.
///
/// After the first twelve rounds `on_unverified({ container, containerFingerprint })` receives
/// the container, so that a page can show it, marked as not yet verified, while the check runs.
/// The repair words come only with the result, after the check has passed.
#[expect(
    clippy::too_many_arguments,
    reason = "the WebAssembly binding takes every input as an argument of its own"
)]
#[wasm_bindgen]
pub fn encrypt(
    phrase_utf8: Vec<u8>,
    password_utf8: Vec<u8>,
    repeat_utf8: Vec<u8>,
    choice: &str,
    position: f64,
    pim: f64,
    memory_level: f64,
    same_length: JsValue,
    repair_word_count: f64,
    wallet_has_passphrase: JsValue,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
    on_unverified: &js_sys::Function,
) -> Result<String, JsError> {
    // Every secret is put under a wiping owner before anything can fail, so that no early return
    // drops one of them unwiped. The phrase is read in place, without a copy.
    let phrase = SecretText::new(phrase_utf8);
    let typed = SecretText::new(password_utf8);
    let repeat = SecretText::new(repeat_utf8);
    let password = new_password_from(&typed, &repeat, choice, position)?;
    let wallet_passphrase = WalletPassphrase::from(passphrase_answer(&wallet_has_passphrase)?);
    let phrase = phrase.phrase()?;
    let suite = if yes_or_no(&same_length, "sameLength")? {
        Suite::SameLength
    } else {
        Suite::TwentyFourWords
    };
    let encryption =
        Encryption::new(phrase, suite, repair_count(repair_word_count)?).map_err(js_error)?;
    let (mut mhfe, work) = mhfe_for(pim, memory_level, argon2)?;
    let sealed = sealed_for_page(
        &mut mhfe,
        on_round,
        on_unverified,
        |mhfe, progress, shown| encryption.run(mhfe, phrase, &password, progress, shown),
    )?;
    sealed_json(&sealed, work, wallet_passphrase)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateJson<'a> {
    words: usize,
    verified: bool,
    /// "verified", "noBuiltInCheck", "readAs24" or "readAs24Chosen".
    status: &'static str,
    phrase: &'a str,
    /// The suite of the container, which its word count selected.
    suite_id: &'static str,
    fingerprint_without_passphrase: String,
    /// Whether a 24-word reading passes the 16-bit source check with the passphrase given, or the
    /// empty one; null for every other length, where it does not apply.
    wallet_check: Option<bool>,
    /// The length stated, where the built-in checks gave this reading another; null otherwise.
    stated_words: Option<usize>,
    /// The other 12- to 21-word lengths whose built-in check passes too, by chance.
    other_lengths: &'a [usize],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryJson<'a> {
    /// "phrase" for one result, "ambiguous" when several lengths passed their check.
    kind: &'static str,
    candidates: Vec<CandidateJson<'a>>,
}

/// Recovers the phrase; the container's word count selects the suite. `words` is 0 for automatic
/// detection, otherwise the chosen length, which a same-length container takes only as its own.
/// `passphrase_utf8` is the wallet's BIP39 passphrase, empty for none, for the 16-bit source
/// check, which every recovery evaluates on each 24-word reading; it is wiped afterwards. Returns
/// JSON `{ kind, candidates: [{ words, verified, status, phrase, suiteId,
/// fingerprintWithoutPassphrase, walletCheck, statedWords, otherLengths }] }`. A stated length
/// does not replace detection: a built-in check that passes takes precedence, and
/// `statedWords` then names the length stated; 24 stated words beside a check that passes
/// give "ambiguous", the checked reading first.
#[expect(
    clippy::too_many_arguments,
    reason = "the WebAssembly binding takes every input as an argument of its own"
)]
#[wasm_bindgen]
pub fn decrypt(
    container: &str,
    password_utf8: Vec<u8>,
    choice: &str,
    position: f64,
    pim: f64,
    memory_level: f64,
    words: f64,
    passphrase_utf8: Vec<u8>,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
) -> Result<js_sys::JsString, JsError> {
    // Under a wiping owner first, so that a refusal below drops it wiped too.
    let passphrase = SecretText::new(passphrase_utf8);
    let password = password_from(password_utf8, choice, position)?;
    let length = word_count(words)?;
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let (mut mhfe, _) = mhfe_for(pim, memory_level, argon2)?;
    let recovery = mhfe.decrypt(container, &password, length, &mut |round, rounds| {
        report(on_round, Stage::Recover, round, rounds)
    });
    let recovery = verified(&mhfe, recovery)?;
    let (kind, phrases) = match recovery {
        Recovery::Phrase(phrase) => ("phrase", vec![phrase]),
        Recovery::Ambiguous(candidates) => ("ambiguous", candidates),
    };
    let candidates = phrases
        .iter()
        .map(|candidate| candidate_json(candidate, length, passphrase))
        .collect::<Result<Vec<_>, JsError>>()?;
    secret_json(&RecoveryJson { kind, candidates })
}

fn candidate_json<'a>(
    candidate: &'a RecoveredPhrase,
    length: PhraseLength,
    passphrase: &str,
) -> Result<CandidateJson<'a>, JsError> {
    Ok(CandidateJson {
        words: candidate.words(),
        verified: candidate.verified(),
        status: match candidate.status(length) {
            RecoveryStatus::Verified => "verified",
            RecoveryStatus::NoBuiltInCheck => "noBuiltInCheck",
            RecoveryStatus::ReadAs24Detected => "readAs24",
            RecoveryStatus::ReadAs24Chosen => "readAs24Chosen",
        },
        phrase: candidate.phrase(),
        suite_id: candidate.suite().id(),
        fingerprint_without_passphrase: master_fingerprint_text(candidate.phrase(), "")
            .map_err(js_error)?,
        wallet_check: candidate
            .passes_wallet_check(passphrase)
            .map_err(js_error)?,
        stated_words: candidate.stated_words(),
        other_lengths: candidate.other_lengths(),
    })
}

/// A reference as the page passes it: `kind` is "address", "fingerprint", "words" or
/// "walletCheck"; `reference` the address, the eight hex digits or the word count, 0 to detect
/// it, empty for "walletCheck"; `coin` an address's coin id; `path` empty for the standard path
/// search.
fn reference_target(
    kind: &str,
    reference: &str,
    coin: &str,
    path: &str,
) -> Result<ReferenceTarget, JsError> {
    Ok(match kind {
        "address" => {
            let coin: Coin = coin.parse().map_err(js_error)?;
            ReferenceTarget::Address {
                address: Address::parse(coin, reference).map_err(js_error)?,
                path: match path {
                    "" => None,
                    text => Some(text.parse().map_err(js_error)?),
                },
            }
        }
        "fingerprint" => {
            ReferenceTarget::Fingerprint(parse_fingerprint(reference).map_err(js_error)?)
        }
        "words" => {
            let words = reference.parse().map_err(|_| {
                js_error(MhfeError::InvalidRequest(
                    "the word count must be a whole number".to_owned(),
                ))
            })?;
            ReferenceTarget::Length(PhraseLength::from_count(words).map_err(js_error)?)
        }
        "walletCheck" => ReferenceTarget::WalletCheck,
        other => {
            return Err(js_error(MhfeError::InvalidRequest(format!(
                "unknown reference kind {other}"
            ))))
        }
    })
}

/// A phrase given to the page to be shown: one the owner compares with their backup, or a
/// hidden wallet, with the fingerprint of its wallet without a passphrase.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhraseJson<'a> {
    phrase: &'a str,
    words: usize,
    /// The length the person stated, where the built-in check found this one instead: the page
    /// says so before the owner compares (AUD-017-API001). Left out otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    stated_words: Option<usize>,
    fingerprint_without_passphrase: String,
}

impl<'a> PhraseJson<'a> {
    fn of(recovered: &'a RecoveredPhrase) -> Result<Self, JsError> {
        Ok(Self {
            phrase: recovered.phrase(),
            words: recovered.words(),
            stated_words: recovered.stated_words(),
            fingerprint_without_passphrase: master_fingerprint_text(recovered.phrase(), "")
                .map_err(js_error)?,
        })
    }
}

/// The answer whether the wallet has a BIP39 passphrase: true or false, or none when it is
/// undefined or null. Anything else is refused rather than read as a truth value, so that no stray
/// value drops the passphrase from what to keep.
fn passphrase_answer(value: &JsValue) -> Result<Option<bool>, JsError> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value.as_bool().map(Some).ok_or_else(|| {
        js_error(MhfeError::InvalidRequest(
            "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase"
                .to_owned(),
        ))
    })
}

/// A password of an existing container, with the review choice of its check word.
fn password_from(password_utf8: Vec<u8>, choice: &str, position: f64) -> Result<Password, JsError> {
    let typed = SecretText::new(password_utf8);
    let choice = review_choice(choice, position)?;
    if choice.is_none() {
        return Password::from_utf8(typed.bytes()).map_err(js_error);
    }
    let text = typed.text(MhfeError::InvalidPasswordUtf8)?;
    check_word::typed_password(text, None, choice).map_err(js_error)
}

/// A new password typed twice, with the review choice of its check word: the password's own rules
/// first, then the two entries compared exactly as typed (check_word::check_typed_twice).
fn new_password_from(
    typed: &SecretText,
    repeat: &SecretText,
    choice: &str,
    position: f64,
) -> Result<Password, JsError> {
    let text = typed.text(MhfeError::InvalidPasswordUtf8)?;
    let repeat = repeat.text(MhfeError::InvalidPasswordUtf8)?;
    check_word::typed_password(text, Some(repeat), review_choice(choice, position)?)
        .map_err(js_error)
}

/// The length of the original seed phrase as the page passes it: a word count, or 0 to detect it.
fn word_count(words: f64) -> Result<PhraseLength, JsError> {
    let words = whole_number(
        words,
        MhfeError::InvalidWordCount(0).code(),
        "the word count",
    )?;
    PhraseLength::from_count(words as usize).map_err(js_error)
}

/// 0 for no repair words, else 2, 4, 6 or 8, which the encryption checks.
fn repair_count(count: f64) -> Result<Option<usize>, JsError> {
    match whole_number(
        count,
        MhfeError::InvalidRepairWords(String::new()).code(),
        "the repair word count",
    )? {
        0 => Ok(None),
        count => Ok(Some(count as usize)),
    }
}

fn work_from(pim: f64, memory_level: f64) -> Result<WorkFactor, JsError> {
    settings_from(pim, memory_level, Settings::Current)
}

/// The settings `settings` from `pim` and `memory_level`, which a refusal names.
fn settings_from(pim: f64, memory_level: f64, settings: Settings) -> Result<WorkFactor, JsError> {
    let pim = whole_number(
        pim,
        MhfeError::InvalidPim { pim: 0, settings }.code(),
        &format!("{settings} PIM"),
    )?;
    let memory_level = whole_number(
        memory_level,
        MhfeError::InvalidMemoryLevel { level: 0, settings }.code(),
        &format!("{settings} memory level"),
    )?;
    WorkFactor::of(settings, pim, memory_level).map_err(js_error)
}

fn mhfe_for(
    pim: f64,
    memory_level: f64,
    argon2: JsArgon2,
) -> Result<(Mhfe<BrowserEngine>, WorkFactor), JsError> {
    mhfe_with(work_from(pim, memory_level)?, argon2)
}

/// The engine of an operation, once the page's Argon2 build has given its known answer: before
/// round 1, so that no secret meets a build that computes something else.
fn mhfe_with(
    work: WorkFactor,
    argon2: JsArgon2,
) -> Result<(Mhfe<BrowserEngine>, WorkFactor), JsError> {
    let engine = BrowserEngine::new(argon2, work).map_err(js_error)?;
    engine.verify_known_answer().map_err(js_error)?;
    Ok((Mhfe::with_engine(work, engine), work))
}

/// Seals a phrase with `seal`, an encryption or a rekey: its rounds reported to `on_round`, the
/// container before its check to `on_unverified`, and the Argon2 build's known answer checked
/// after the last round ([`verified`]).
fn sealed_for_page(
    mhfe: &mut Mhfe<BrowserEngine>,
    on_round: &js_sys::Function,
    on_unverified: &js_sys::Function,
    seal: impl FnOnce(
        &mut Mhfe<BrowserEngine>,
        StageCallback<'_>,
        &mut dyn FnMut(&str) -> Result<(), MhfeError>,
    ) -> Result<Sealed, MhfeError>,
) -> Result<Sealed, JsError> {
    let sealed = seal(
        mhfe,
        &mut |stage, round, rounds| report(on_round, stage, round, rounds),
        &mut |container| unverified(on_unverified, container),
    );
    verified(mhfe, sealed)
}

/// The outcome of an operation once the page's Argon2 build has given its known answer again after
/// the last round. A build that went wrong during the work, such as in the optimized code the
/// browser made of it, fails here with SELF_CHECK_FAILED, and the result is dropped instead of
/// returned. The answer is checked after a failed operation too, since a fault of the build is the
/// more fundamental cause.
fn verified<T>(mhfe: &Mhfe<BrowserEngine>, outcome: Result<T, MhfeError>) -> Result<T, JsError> {
    mhfe.engine().verify_known_answer().map_err(js_error)?;
    outcome.map_err(js_error)
}

/// Tells the worker that round `round` of `rounds` starts, in `stage`. An exception thrown there
/// stops the operation.
fn report(
    on_round: &js_sys::Function,
    stage: Stage,
    round: u32,
    rounds: u32,
) -> Result<(), MhfeError> {
    call_page(
        on_round,
        &[
            JsValue::from(round),
            JsValue::from(rounds),
            JsValue::from_str(stage.name()),
        ],
    )
}

/// Gives the page the container before its check, with its own fingerprint.
fn unverified(on_unverified: &js_sys::Function, container: &str) -> Result<(), MhfeError> {
    let fingerprint = fingerprint_text(container_fingerprint(container)?);
    let text = serde_json::to_string(&UnverifiedJson {
        container,
        container_fingerprint: fingerprint,
    })
    .map_err(|error| MhfeError::Internal(error.to_string()))?;
    call_page(on_unverified, &[JsValue::from_str(&text)])
}
