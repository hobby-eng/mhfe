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

use super::{js_error, json, review_choice, run_self_check, secret_json, whole_number, SecretText};
use crate::check_word::chosen_password;
use crate::engine::browser::{BrowserEngine, JsArgon2, HIGHEST_BROWSER_MEMORY_LEVEL};
use crate::engine::{BrowserArgon2Check, BrowserArgon2SizesCheck};
use crate::mhfe::RecoveredPhrase;
use crate::operation::{Encryption, Sealed, Stage};
use crate::rekey::{ConfirmedPhrase, Rekey};
use crate::repair::{
    self, PROFILE as REPAIR_PROFILE, RECOMMENDED_REPAIR_WORDS, REPAIR_WORD_COUNTS,
};
use crate::self_check::{sets, ComponentCheck, SelfCheck};
use crate::self_test::{SelfTest, SelfTestFault};
use crate::wallet::{
    master_fingerprint, parse_fingerprint, Address, Coin, DerivationPath, SearchLimits,
};
use crate::{
    Confirmation, ConfirmationNeeded, ContainerFacts, HiddenWallets, Mhfe, MhfeError,
    OriginalFacts, Password, PhraseLength, Recovery, RecoveryStatus, Reference, Suite, WordCount,
    WorkFactor, BUILT_IN_CHECK_WORD_COUNTS, MAX_MEMORY_LEVEL, MAX_PIM, ROUNDS,
    SAME_LENGTH_SUITE_ID, SUITE_ID, WORD_COUNTS,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capacity {
    count: usize,
    unreadable: usize,
    wrong: usize,
}

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
    repair_capacities: Vec<Capacity>,
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
        repair_capacities: REPAIR_WORD_COUNTS
            .iter()
            .map(|&count| {
                let (unreadable, wrong) = repair::capacity(count);
                Capacity {
                    count,
                    unreadable,
                    wrong,
                }
            })
            .collect(),
    })
}

/// Checks a password before anything runs. The bytes are wiped afterwards.
#[wasm_bindgen(js_name = checkPassword)]
pub fn check_password(password_utf8: Vec<u8>) -> Result<(), JsError> {
    password_from(password_utf8, "", 0.0).map(|_| ())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChoiceJson {
    same_length: bool,
    words: usize,
    wrong_word_passes_one_in: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhraseFactsJson<'a> {
    phrase: &'a str,
    words: usize,
    other_lengths: &'a [usize],
    containers: Vec<ChoiceJson>,
}

/// Reads an original phrase, its UTF-8 bytes as the person may have typed it, and returns JSON
/// `{ phrase, words, otherLengths, containers: [{ sameLength, words, wrongWordPassesOneIn }] }`,
/// the phrase with every word written out, for showing back, and the containers it can be
/// encrypted into with the consequence of each. The bytes are wiped afterwards.
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
        let needed = facts
            .confirmation_needed(WordCount::new(words).map_err(js_error)?)
            .map_err(js_error)?;
        confirmation_for.insert(words.to_string(), confirmation_name(needed));
    }
    json(&ContainerFactsJson {
        container: facts.words(),
        words: facts.word_count(),
        suite_id: facts.suite().id(),
        phrase_lengths: facts.phrase_lengths(),
        built_in_check_lengths: facts.built_in_check_lengths(),
        confirmation_for,
        hidden_wallets: facts.opens_hidden_wallets(),
        offers_wallet_check: facts.offers_wallet_check(),
        container_fingerprint: hex::encode(facts.fingerprint().map_err(js_error)?),
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
    RepairWords,
    Pim { value: u32 },
    MemoryLevel { value: u32 },
    WordCount { words: usize },
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
    keep: Vec<KeepJson>,
}

/// The result of an encryption or a rekey: the checked container and what to keep.
fn sealed_json(sealed: &Sealed, work: WorkFactor, passphrase: bool) -> Result<String, JsError> {
    use crate::operation::KeepItem;
    let keep = sealed
        .keep(work, passphrase)
        .items()
        .iter()
        .map(|item| match *item {
            KeepItem::ContainerWords(words) => KeepJson::ContainerWords { words },
            KeepItem::Password => KeepJson::Password,
            KeepItem::Passphrase => KeepJson::Passphrase,
            KeepItem::RepairWords => KeepJson::RepairWords,
            KeepItem::Pim(value) => KeepJson::Pim { value },
            KeepItem::MemoryLevel(value) => KeepJson::MemoryLevel { value },
            KeepItem::WordCount(words) => KeepJson::WordCount { words },
        })
        .collect();
    json(&SealedJson {
        container: sealed.container(),
        suite_id: sealed.suite().id(),
        container_fingerprint: hex::encode(
            master_fingerprint(sealed.container(), "").map_err(js_error)?,
        ),
        built_in_check: sealed.built_in_check(),
        other_lengths: sealed.other_lengths(),
        repair_words: sealed.repair_words(),
        repair_profile: sealed.repair_words().map(|_| REPAIR_PROFILE),
        keep,
    })
}

/// Encrypts the phrase, its UTF-8 bytes `phrase_utf8`, and returns JSON `{ container, suiteId,
/// containerFingerprint, builtInCheck, otherLengths, repairWords, repairProfile, keep: [{ item,
/// ... }] }` once its check has passed: a 24-word container, or with `same_length`, which only the
/// user's own choice may set, a container as long as the 12- to 21-word phrase.
///
/// The password is typed twice: `repeat_utf8` must be the same text (PASSWORDS_DIFFER), and
/// `choice` with `position` applies a correction or repair of its check word review ("" keeps it
/// as typed). `repair_word_count` is 0 for none, or 2, 4, 6 or 8. `wallet_has_passphrase`, true
/// or false and nothing else (INVALID_REQUEST), is the user's answer whether the wallet has a
/// BIP39 passphrase: true adds it to what to keep, since MHFE encrypts only the phrase.
///
/// After the first twelve rounds `on_unverified({ container, containerFingerprint })` receives
/// the container, so that a page can show it, marked as not yet verified, while the check runs.
/// The repair words come only with the result, after the check has passed.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn encrypt(
    phrase_utf8: Vec<u8>,
    password_utf8: Vec<u8>,
    repeat_utf8: Vec<u8>,
    choice: &str,
    position: f64,
    pim: f64,
    memory_level: f64,
    same_length: bool,
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
    let wallet_has_passphrase = passphrase_answer(&wallet_has_passphrase)?;
    let phrase = phrase.phrase()?;
    let suite = if same_length {
        Suite::SameLength
    } else {
        Suite::TwentyFourWords
    };
    let encryption =
        Encryption::new(phrase, suite, repair_count(repair_word_count)?).map_err(js_error)?;
    let (mut mhfe, work) = mhfe_for(pim, memory_level, argon2)?;
    let sealed = encryption.run(
        &mut mhfe,
        phrase,
        &password,
        &mut |stage, round, rounds| report(on_round, stage, round, rounds),
        &mut |container| unverified(on_unverified, container),
    );
    let sealed = verified(&mhfe, sealed)?;
    sealed_json(&sealed, work, wallet_has_passphrase)
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
    /// Null where the wallet check does not apply: every length but 24.
    passes_wallet_check_without_passphrase: Option<bool>,
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
/// Returns JSON `{ kind, candidates: [{ words, verified, status, phrase, suiteId,
/// fingerprintWithoutPassphrase, passesWalletCheckWithoutPassphrase }] }`.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn decrypt(
    container: &str,
    password_utf8: Vec<u8>,
    choice: &str,
    position: f64,
    pim: f64,
    memory_level: f64,
    words: f64,
    argon2: JsArgon2,
    on_round: &js_sys::Function,
) -> Result<js_sys::JsString, JsError> {
    let password = password_from(password_utf8, choice, position)?;
    let length = match whole_number(words, "INVALID_WORD_COUNT", "the word count")? {
        0 => PhraseLength::Detect,
        words => PhraseLength::Words(WordCount::new(words as usize).map_err(js_error)?),
    };
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
        .map(|candidate| candidate_json(candidate, length))
        .collect::<Result<Vec<_>, JsError>>()?;
    secret_json(&RecoveryJson { kind, candidates })
}

fn candidate_json(
    candidate: &RecoveredPhrase,
    length: PhraseLength,
) -> Result<CandidateJson<'_>, JsError> {
    Ok(CandidateJson {
        words: candidate.words,
        verified: candidate.verified,
        status: match candidate.status(length) {
            RecoveryStatus::Verified => "verified",
            RecoveryStatus::NoBuiltInCheck => "noBuiltInCheck",
            RecoveryStatus::ReadAs24Detected => "readAs24",
            RecoveryStatus::ReadAs24Chosen => "readAs24Chosen",
        },
        phrase: &candidate.phrase,
        suite_id: candidate.suite.id(),
        fingerprint_without_passphrase: hex::encode(
            master_fingerprint(&candidate.phrase, "").map_err(js_error)?,
        ),
        passes_wallet_check_without_passphrase: candidate.passes_wallet_check_without_passphrase(),
    })
}

#[derive(Serialize)]
struct CheckJson {
    matches: bool,
    /// Where a matched address was found, such as "m/84'/0'/0'/0/5"; null otherwise.
    path: Option<String>,
}

/// A reference of the wallet as the page passes it, owning what the library's [`Reference`]
/// borrows.
struct WalletReference {
    address: Option<Address>,
    path: Option<DerivationPath>,
    fingerprint: Option<[u8; 4]>,
    words: Option<WordCount>,
    wallet_check: bool,
}

impl WalletReference {
    /// `kind` is "address", "fingerprint", "words" or "walletCheck"; `reference` the address, the
    /// eight hex digits or the word count, empty for "walletCheck"; `coin` an address's coin id;
    /// `path` empty for the standard path search.
    fn parse(kind: &str, reference: &str, coin: &str, path: &str) -> Result<Self, JsError> {
        let mut parsed = Self {
            address: None,
            path: None,
            fingerprint: None,
            words: None,
            wallet_check: false,
        };
        match kind {
            "address" => {
                let coin: Coin = coin.parse().map_err(js_error)?;
                parsed.address = Some(Address::parse(coin, reference).map_err(js_error)?);
                parsed.path = match path {
                    "" => None,
                    text => Some(text.parse().map_err(js_error)?),
                };
            }
            "fingerprint" => {
                parsed.fingerprint = Some(parse_fingerprint(reference).map_err(js_error)?);
            }
            "words" => {
                parsed.words = Some(
                    reference
                        .parse()
                        .map_err(|_| MhfeError::InvalidWordCount(0))
                        .and_then(WordCount::new)
                        .map_err(js_error)?,
                );
            }
            "walletCheck" => parsed.wallet_check = true,
            other => {
                return Err(js_error(MhfeError::InvalidRequest(format!(
                    "unknown reference kind {other}"
                ))))
            }
        }
        Ok(parsed)
    }

    /// The library's reference, with `passphrase` the wallet's BIP39 passphrase.
    fn reference<'a>(&'a self, passphrase: &'a str) -> Reference<'a> {
        if let Some(address) = &self.address {
            Reference::Address {
                address,
                passphrase,
                path: self.path.as_ref(),
                limits: SearchLimits::default(),
            }
        } else if let Some(fingerprint) = self.fingerprint {
            Reference::Fingerprint {
                fingerprint,
                passphrase,
            }
        } else if let Some(words) = self.words {
            Reference::BuiltInCheck { words }
        } else {
            debug_assert!(self.wallet_check);
            Reference::WalletCheck { passphrase }
        }
    }
}

/// The rehearsal check, as JSON: `{"matches": bool, "path": string | null}`. Only whether the
/// recovery matches comes out, and for a matched address the path where it was found. The rounds
/// of the recovery are reported as "recover", then once "compare" before the comparison.
///
/// `reference_kind` is "address", "fingerprint", "words" or "walletCheck" (the phrase and
/// passphrase check of a 24-word container); see [`WalletReference::parse`].
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn check(
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
) -> Result<String, JsError> {
    // Both secrets are put under a wiping owner before anything can fail, so that no early
    // return drops either of them unwiped. The passphrase is read in place, without a copy.
    let passphrase = SecretText::new(passphrase_utf8);
    let password = password_from(password_utf8, choice, position)?;
    let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
    let wallet = WalletReference::parse(reference_kind, reference, coin, path)?;
    // The library refuses a wallet check that cannot be, an empty passphrase among them, before
    // any round, in the same order for every front end.
    let (mut mhfe, _) = mhfe_for(pim, memory_level, argon2)?;
    let outcome = mhfe.check_in_stages(
        container,
        &password,
        &wallet.reference(passphrase),
        &mut |stage, round, rounds| report(on_round, stage, round, rounds),
    );
    let outcome = verified(&mhfe, outcome)?;
    json(&CheckJson {
        matches: outcome.matches(),
        path: outcome.path().map(ToString::to_string),
    })
}

/// Where a rekey stands, so that its calls come in their order only.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RekeyStep {
    /// Made; the new password and settings come next.
    Made,
    /// The new password and settings are set; the recovery comes next.
    Ready,
    /// Recovered; the owner's answer about the shown phrase comes next.
    AwaitingOwner,
    /// Recovered and confirmed; the seal comes next.
    Confirmed,
    /// Sealed, failed or refused: nothing more.
    Ended,
}

/// A rekey in one worker: made, given the new password and settings, recovered (and confirmed by
/// the owner where that is the confirmation), then sealed. A call out of this order is refused
/// with INVALID_REQUEST, and any failure ends the rekey.
#[wasm_bindgen]
pub struct RekeySession {
    rekey: Rekey,
    argon2: JsArgon2,
    old_work: WorkFactor,
    new_password: Option<Password>,
    new_work: Option<WorkFactor>,
    repair_word_count: Option<usize>,
    confirmed: Option<ConfirmedPhrase>,
    step: RekeyStep,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerCheckJson<'a> {
    phrase: &'a str,
    words: usize,
    fingerprint_without_passphrase: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveredJson<'a> {
    /// The phrase for the owner to compare with their backup, when the owner confirms it; null
    /// when the built-in check or the wallet confirmed it.
    owner_check: Option<OwnerCheckJson<'a>>,
}

#[wasm_bindgen]
impl RekeySession {
    /// A rekey of `container` with the old password and settings. `words` is the phrase's word
    /// count, 0 to take a same-length container's own; `other_wallets_moved` is the owner's yes to
    /// the warning that the wallets other passwords open on this container change.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(constructor)]
    pub fn new(
        container: &str,
        words: f64,
        password_utf8: Vec<u8>,
        choice: &str,
        position: f64,
        pim: f64,
        memory_level: f64,
        other_wallets_moved: bool,
        argon2: JsArgon2,
    ) -> Result<RekeySession, JsError> {
        let password = password_from(password_utf8, choice, position)?;
        let old_work = work_from(pim, memory_level)?;
        let words = match whole_number(words, "INVALID_WORD_COUNT", "the word count")? {
            0 => None,
            words => Some(words as usize),
        };
        let rekey = Rekey::new(container, words, password, old_work, other_wallets_moved)
            .map_err(js_error)?;
        Ok(Self {
            rekey,
            argon2,
            old_work,
            new_password: None,
            new_work: None,
            repair_word_count: None,
            confirmed: None,
            step: RekeyStep::Made,
        })
    }

    /// The new password, typed twice, with its review choice, and the new settings and repair
    /// words. Refused before any Argon2 work when they would give the old container again.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = setNew)]
    pub fn set_new(
        &mut self,
        password_utf8: Vec<u8>,
        repeat_utf8: Vec<u8>,
        choice: &str,
        position: f64,
        pim: f64,
        memory_level: f64,
        repair_word_count: f64,
    ) -> Result<(), JsError> {
        // Under a wiping owner first, so that a step out of its order drops them wiped too.
        let typed = SecretText::new(password_utf8);
        let repeat = SecretText::new(repeat_utf8);
        self.expect(RekeyStep::Made)?;
        let outcome = (|| {
            let password = new_password_from(&typed, &repeat, choice, position)?;
            let work = work_from(pim, memory_level)?;
            self.rekey.check_new(&password, work).map_err(js_error)?;
            let repair = repair_count(repair_word_count)?;
            Ok((password, work, repair))
        })();
        let (password, work, repair) = self.or_end(outcome)?;
        self.new_password = Some(password);
        self.new_work = Some(work);
        self.repair_word_count = repair;
        self.step = RekeyStep::Ready;
        Ok(())
    }

    /// Recovers the phrase with the old password (rounds 1 to 12 of 36), confirmed by `kind`:
    /// "builtInCheck", "owner", or a wallet reference as for `check` ("address" or
    /// "fingerprint"); `passphrase` belongs only to a reference (INVALID_REQUEST with the others).
    /// `wallet_has_passphrase` states whether the wallet has a BIP39 passphrase, for the new
    /// container's keep list: true, false, or undefined or null for none given; anything else is
    /// INVALID_REQUEST. Only a reference with a non-empty passphrase shows the answer, and there
    /// false is refused; everywhere else it is required (see [`Rekey::recover`]). Every refusal
    /// comes before any Argon2 work. Returns JSON `{ ownerCheck }`: for "owner", the phrase to
    /// compare, and the rekey then waits for `ownerAnswer`.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        &mut self,
        kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase_utf8: Vec<u8>,
        wallet_has_passphrase: JsValue,
        on_round: &js_sys::Function,
    ) -> Result<js_sys::JsString, JsError> {
        // Under a wiping owner first, so that a step out of its order drops it wiped too.
        let passphrase = SecretText::new(passphrase_utf8);
        self.expect(RekeyStep::Ready)?;
        let outcome = (|| {
            let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
            let wallet_has_passphrase = optional_passphrase_answer(&wallet_has_passphrase)?;
            // The wallet check (16 bits) and a word count never confirm a phrase to seal again.
            let wallet = match kind {
                "builtInCheck" | "owner" if !passphrase.is_empty() => {
                    return Err(js_error(MhfeError::InvalidRequest(
                        "a passphrase belongs to an address or fingerprint confirmation".to_owned(),
                    )))
                }
                "builtInCheck" | "owner" => None,
                "address" | "fingerprint" => {
                    Some(WalletReference::parse(kind, reference, coin, path)?)
                }
                other => {
                    return Err(js_error(MhfeError::InvalidRequest(format!(
                        "a rekey is not confirmed by {other}"
                    ))))
                }
            };
            let reference = wallet.as_ref().map(|wallet| wallet.reference(passphrase));
            let confirmation = match (kind, &reference) {
                ("builtInCheck", _) => Confirmation::BuiltInCheck,
                ("owner", _) => Confirmation::Owner,
                (_, Some(reference)) => Confirmation::Wallet(reference),
                (_, None) => unreachable!("a wallet kind has its reference"),
            };
            // The old work area is freed when this engine is dropped, before the owner is asked
            // or the new one is made.
            let (mut mhfe, _) = mhfe_with(self.old_work, self.argon2.clone().unchecked_into())?;
            let confirmed = self.rekey.recover(
                &mut mhfe,
                confirmation,
                wallet_has_passphrase,
                &mut |stage, round, rounds| report(on_round, stage, round, rounds),
            );
            verified(&mhfe, confirmed)
        })();
        let confirmed = self.or_end(outcome)?;
        let phrase = confirmed.phrase();
        let owner = kind == "owner";
        let fingerprint = hex::encode(master_fingerprint(&phrase.phrase, "").map_err(js_error)?);
        let result = secret_json(&RecoveredJson {
            owner_check: owner.then(|| OwnerCheckJson {
                phrase: &phrase.phrase,
                words: phrase.words,
                fingerprint_without_passphrase: fingerprint,
            }),
        })?;
        self.confirmed = Some(confirmed);
        self.step = if owner {
            RekeyStep::AwaitingOwner
        } else {
            RekeyStep::Confirmed
        };
        Ok(result)
    }

    /// The owner's answer after comparing the shown phrase with their backup: anything but yes
    /// ends the rekey (NOT_CONFIRMED_BY_OWNER) and drops the phrase.
    #[wasm_bindgen(js_name = ownerAnswer)]
    pub fn owner_answer(&mut self, confirmed: bool) -> Result<(), JsError> {
        self.expect(RekeyStep::AwaitingOwner)?;
        if !confirmed {
            self.confirmed = None;
            self.step = RekeyStep::Ended;
            return Err(js_error(MhfeError::NotConfirmedByOwner));
        }
        self.step = RekeyStep::Confirmed;
        Ok(())
    }

    /// Seals the confirmed phrase with the new password and settings (rounds 13 to 36) and returns
    /// the result as `encrypt` does. `on_unverified` gets the container before its check.
    pub fn seal(
        &mut self,
        on_round: &js_sys::Function,
        on_unverified: &js_sys::Function,
    ) -> Result<String, JsError> {
        self.expect(RekeyStep::Confirmed)?;
        self.step = RekeyStep::Ended;
        let (Some(confirmed), Some(password), Some(work)) = (
            self.confirmed.take(),
            self.new_password.take(),
            self.new_work,
        ) else {
            return Err(js_error(MhfeError::Internal(
                "a confirmed rekey lacks its phrase or new password".to_owned(),
            )));
        };
        let (mut mhfe, _) = mhfe_with(work, self.argon2.clone().unchecked_into())?;
        let sealed = self.rekey.seal(
            &mut mhfe,
            &confirmed,
            &password,
            self.repair_word_count,
            &mut |stage, round, rounds| report(on_round, stage, round, rounds),
            &mut |container| unverified(on_unverified, container),
        );
        let sealed = verified(&mhfe, sealed)?;
        sealed_json(&sealed, work, confirmed.wallet_has_passphrase())
    }

    fn expect(&mut self, step: RekeyStep) -> Result<(), JsError> {
        if self.step == step {
            return Ok(());
        }
        self.step = RekeyStep::Ended;
        self.confirmed = None;
        Err(js_error(MhfeError::InvalidRequest(
            "a rekey step out of its order".to_owned(),
        )))
    }

    /// Ends the rekey when `outcome` failed.
    fn or_end<T>(&mut self, outcome: Result<T, JsError>) -> Result<T, JsError> {
        if outcome.is_err() {
            self.step = RekeyStep::Ended;
            self.confirmed = None;
        }
        outcome
    }
}

/// A session of hidden wallets in one worker: one container, the main wallet's passphrase, and a
/// wallet for each new password. Nothing is listed or counted. The session ends on `close` or when
/// its worker is terminated.
#[wasm_bindgen]
pub struct HiddenWalletSession {
    wallets: HiddenWallets,
    mhfe: Mhfe<BrowserEngine>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HiddenWalletJson<'a> {
    phrase: &'a str,
    words: usize,
    fingerprint_without_passphrase: String,
}

#[wasm_bindgen]
impl HiddenWalletSession {
    /// A session on a 24-word container, refused otherwise before any work, with the main
    /// wallet's BIP39 passphrase, empty for a wallet without one. The page's Argon2 build gives its
    /// known answer first, and the work area is reserved here, so SELF_CHECK_FAILED and
    /// MEMORY_ALLOCATION_FAILED come now rather than at the first wallet.
    #[wasm_bindgen(constructor)]
    pub fn new(
        container: &str,
        pim: f64,
        memory_level: f64,
        main_passphrase_utf8: Vec<u8>,
        argon2: JsArgon2,
    ) -> Result<HiddenWalletSession, JsError> {
        let passphrase = SecretText::new(main_passphrase_utf8);
        let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
        let wallets = HiddenWallets::new(container, passphrase).map_err(js_error)?;
        let work = work_from(pim, memory_level)?;
        let engine = BrowserEngine::new(argon2, work).map_err(js_error)?;
        engine.verify_known_answer().map_err(js_error)?;
        engine.reserve().map_err(js_error)?;
        Ok(Self {
            wallets,
            mhfe: Mhfe::with_engine(work, engine),
        })
    }

    /// Opens the wallet of a new password, typed twice, with its review choice: twelve rounds,
    /// reported as "recover". A password used already in this session is refused before any work
    /// (PASSWORD_ALREADY_USED); one whose wallet would pass a check after it
    /// (HIDDEN_WALLET_PASSES_CHECK); the session stays open after both. The page's Argon2 build
    /// gives its known answer before and after the rounds (SELF_CHECK_FAILED otherwise). Returns
    /// JSON `{ phrase, words, fingerprintWithoutPassphrase }`.
    pub fn open(
        &mut self,
        password_utf8: Vec<u8>,
        repeat_utf8: Vec<u8>,
        choice: &str,
        position: f64,
        on_round: &js_sys::Function,
    ) -> Result<js_sys::JsString, JsError> {
        let typed = SecretText::new(password_utf8);
        let repeat = SecretText::new(repeat_utf8);
        let password = new_password_from(&typed, &repeat, choice, position)?;
        self.mhfe.engine().verify_known_answer().map_err(js_error)?;
        let wallet = self
            .wallets
            .open(&mut self.mhfe, password, &mut |round, rounds| {
                report(on_round, Stage::Recover, round, rounds)
            });
        let wallet = verified(&self.mhfe, wallet)?;
        secret_json(&HiddenWalletJson {
            phrase: &wallet.phrase,
            words: wallet.words,
            fingerprint_without_passphrase: hex::encode(
                master_fingerprint(&wallet.phrase, "").map_err(js_error)?,
            ),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VectorJson<'a> {
    vector: &'a str,
    as_published: bool,
}

/// Where a self-test that did not pass first left the published path, as the library tells it
/// ([`SelfTestFault`]): its kind, its round, and the sentence a page shows as it is.
#[derive(Serialize)]
struct FaultJson {
    /// "argon2-input", "argon2-key" or "after-argon2".
    kind: &'static str,
    /// 1 to 24; null for "after-argon2".
    round: Option<u32>,
    message: String,
}

impl FaultJson {
    fn of(fault: SelfTestFault) -> Self {
        Self {
            kind: fault.id(),
            round: fault.round(),
            message: fault.to_string(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfTestJson<'a> {
    passed: bool,
    suite3: VectorJson<'a>,
    suite4: VectorJson<'a>,
    /// The round of `fault`, 1 to 12 the suite 3 encryption and 13 to 24 the suite 4 recovery,
    /// where Argon2id's input or its key first differed from the published one; null when the
    /// test passed or the fault lies after the last Argon2id call. Only `fault` tells which.
    first_wrong_round: Option<u32>,
    /// Null when the test passed.
    fault: Option<FaultJson>,
}

/// The self-test with the two published vectors at their full cost, PIM 0 and memory level 0: an
/// encryption of suite 3 ("encrypt", rounds 1 to 12 of 24) and a recovery of suite 4 ("recover",
/// rounds 13 to 24). It takes minutes; a page runs it only when the person asks. Returns JSON
/// `{ passed, suite3: { vector, asPublished }, suite4: { vector, asPublished }, firstWrongRound,
/// fault: { kind, round, message } | null }`.
#[wasm_bindgen(js_name = selfTest)]
pub fn self_test(argon2: JsArgon2, on_round: &js_sys::Function) -> Result<String, JsError> {
    let test = SelfTest::published().map_err(js_error)?;
    let (mut mhfe, _) = mhfe_with(WorkFactor::default(), argon2)?;
    let result = test.run(&mut mhfe, &mut |stage, round, rounds| {
        report(on_round, stage, round, rounds)
    });
    let result = verified(&mhfe, result)?;
    json(&SelfTestJson {
        first_wrong_round: result.first_wrong_round(),
        fault: result.fault().map(FaultJson::of),
        passed: result.passed(),
        suite3: VectorJson {
            vector: test.suite_3_vector(),
            as_published: result.suite_3_as_published(),
        },
        suite4: VectorJson {
            vector: test.suite_4_vector(),
            as_published: result.suite_4_as_published(),
        },
    })
}

/// The self-check of the core module's parts at `tier`, "startup" or "full": the cipher's hashes
/// and rounds, the formats, the container facts and what to keep, passwords, the word list, the
/// repair words, the check word, the wallet's hashes, seeds, keys and addresses, the wallet check,
/// hidden wallets, rekey and the rehearsal check, each with a case it must refuse. With `argon2`,
/// the worker's Argon2 build, it also runs Argon2's known answer through it; without, Argon2 is
/// listed as not run. `skip_ids` leaves out parts that another module of the page has passed
/// already. Returns JSON as described at [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckCore)]
pub fn self_check_core(
    tier: &str,
    skip_ids: Vec<String>,
    argon2: Option<JsArgon2>,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    let argon2_check = argon2
        .as_ref()
        .map(|argon2| Box::new(BrowserArgon2Check::new(argon2)) as Box<dyn ComponentCheck + '_>);
    run_self_check(
        sets::core(argon2_check),
        tier,
        &skip_ids,
        on_start,
        on_result,
    )
}

/// The self-check of one of the page's Argon2 builds alone at `tier`: its known answer at 1 MiB,
/// and in the full tier at 64 and 256 MiB too, where a browser that cannot give the memory makes
/// that part not available rather than failed. A page runs it for each build in turn, never two at
/// once. `skip_ids` leaves out parts checked already. Returns JSON as described at
/// [`run_self_check`].
#[wasm_bindgen(js_name = selfCheckArgon2)]
pub fn self_check_argon2(
    tier: &str,
    skip_ids: Vec<String>,
    argon2: JsArgon2,
    on_start: &js_sys::Function,
    on_result: &js_sys::Function,
) -> Result<String, JsError> {
    let set = SelfCheck::new()
        .with(BrowserArgon2Check::new(&argon2))
        .with(BrowserArgon2SizesCheck::new(&argon2));
    run_self_check(set, tier, &skip_ids, on_start, on_result)
}

/// The user's answer whether the wallet has a BIP39 passphrase: true or false. Anything else is
/// refused rather than read as a truth value, so that no stray value drops the passphrase from
/// what to keep.
fn passphrase_answer(value: &JsValue) -> Result<bool, JsError> {
    value.as_bool().ok_or_else(|| {
        js_error(MhfeError::InvalidRequest(
            "walletHasPassphrase must be true or false: whether the wallet has a BIP39 passphrase"
                .to_owned(),
        ))
    })
}

/// [`passphrase_answer`], or none when it is undefined or null: not given.
fn optional_passphrase_answer(value: &JsValue) -> Result<Option<bool>, JsError> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    passphrase_answer(value).map(Some)
}

/// A password of an existing container, with the review choice of its check word.
fn password_from(password_utf8: Vec<u8>, choice: &str, position: f64) -> Result<Password, JsError> {
    let typed = SecretText::new(password_utf8);
    let choice = review_choice(choice, position)?;
    if choice.is_none() {
        return Password::from_utf8(typed.bytes()).map_err(js_error);
    }
    let text = typed.text(MhfeError::InvalidPasswordUtf8)?;
    let chosen = chosen_password(text, None, choice).map_err(js_error)?;
    Password::new(&chosen).map_err(js_error)
}

/// A new password typed twice, with the review choice of its check word: the two entries are
/// compared first, exactly as typed.
fn new_password_from(
    typed: &SecretText,
    repeat: &SecretText,
    choice: &str,
    position: f64,
) -> Result<Password, JsError> {
    let text = typed.text(MhfeError::InvalidPasswordUtf8)?;
    // The checks of a password come first, as the command-line tool makes them.
    Password::new(text).map_err(js_error)?;
    let repeat = repeat.text(MhfeError::InvalidPasswordUtf8)?;
    let chosen =
        chosen_password(text, Some(repeat), review_choice(choice, position)?).map_err(js_error)?;
    Password::new(&chosen).map_err(js_error)
}

/// 0 for no repair words, else 2, 4, 6 or 8, which the encryption checks.
fn repair_count(count: f64) -> Result<Option<usize>, JsError> {
    match whole_number(count, "INVALID_REPAIR_WORDS", "the repair word count")? {
        0 => Ok(None),
        count => Ok(Some(count as usize)),
    }
}

fn work_from(pim: f64, memory_level: f64) -> Result<WorkFactor, JsError> {
    let pim = whole_number(pim, "INVALID_PIM", "the PIM")?;
    let memory_level = whole_number(memory_level, "INVALID_MEMORY_LEVEL", "the memory level")?;
    WorkFactor::new(pim, memory_level).map_err(js_error)
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
    on_round
        .call3(
            &JsValue::UNDEFINED,
            &JsValue::from(round),
            &JsValue::from(rounds),
            &JsValue::from_str(stage.name()),
        )
        .map(|_| ())
        .map_err(|_| MhfeError::Cancelled)
}

/// Gives the page the container before its check, with its own fingerprint.
fn unverified(on_unverified: &js_sys::Function, container: &str) -> Result<(), MhfeError> {
    let fingerprint = hex::encode(master_fingerprint(container, "")?);
    let text = serde_json::to_string(&UnverifiedJson {
        container,
        container_fingerprint: fingerprint,
    })
    .map_err(|error| MhfeError::Internal(error.to_string()))?;
    on_unverified
        .call1(&JsValue::UNDEFINED, &JsValue::from_str(&text))
        .map(|_| ())
        .map_err(|_| MhfeError::Cancelled)
}
