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
    call_page, js_error, json, repair_capacities, review_choice, run_self_check, secret_json,
    whole_number, CapacityJson, SecretText,
};
use crate::check_word;
use crate::engine::browser::{BrowserEngine, JsArgon2, HIGHEST_BROWSER_MEMORY_LEVEL};
use crate::engine::{BrowserArgon2Check, BrowserArgon2SizesCheck};
use crate::mhfe::RecoveredPhrase;
use crate::operation::{Encryption, Sealed, Stage, StageCallback, WalletPassphrase};
use crate::rekey::{ConfirmedPhrase, Rekey};
use crate::repair::{PROFILE as REPAIR_PROFILE, RECOMMENDED_REPAIR_WORDS, REPAIR_WORD_COUNTS};
use crate::search::{ContainerSearch, Found, DECOY_SCAN_GAP};
use crate::self_check::{sets, ComponentCheck, SelfCheck};
use crate::self_test::{SelfTest, SelfTestFault};
use crate::wallet::{fingerprint_text, master_fingerprint_text, parse_fingerprint, Address, Coin};
use crate::{
    Confirmation, ConfirmationNeeded, ContainerFacts, HiddenWallets, Mhfe, MhfeError,
    OriginalFacts, Password, PhraseLength, RecoveredForCheck, RecoveredForRekey, Recovery,
    RecoveryStatus, ReferenceTarget, Suite, WordCount, WorkFactor, BUILT_IN_CHECK_WORD_COUNTS,
    MAX_MEMORY_LEVEL, MAX_PIM, ROUNDS, SAME_LENGTH_SUITE_ID, SUITE_ID, WORD_COUNTS,
};

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
fn sealed_json(
    sealed: &Sealed,
    work: WorkFactor,
    passphrase: WalletPassphrase,
) -> Result<String, JsError> {
    use crate::operation::KeepItem;
    let keep = sealed
        .keep(work, passphrase)
        .items()
        .iter()
        .map(|item| match *item {
            KeepItem::ContainerWords(words) => KeepJson::ContainerWords { words },
            KeepItem::Password => KeepJson::Password,
            KeepItem::Passphrase => KeepJson::Passphrase,
            KeepItem::PassphraseIfAny => KeepJson::PassphraseIfAny,
            KeepItem::RepairWords => KeepJson::RepairWords,
            KeepItem::Pim(value) => KeepJson::Pim { value },
            KeepItem::MemoryLevel(value) => KeepJson::MemoryLevel { value },
            KeepItem::WordCount(words) => KeepJson::WordCount { words },
        })
        .collect();
    json(&SealedJson {
        container: sealed.container(),
        suite_id: sealed.suite().id(),
        container_fingerprint: master_fingerprint_text(sealed.container(), "").map_err(js_error)?,
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
/// as typed). `repair_word_count` is 0 for none, or 2, 4, 6 or 8. `wallet_has_passphrase` is
/// whether the wallet has a BIP39 passphrase, where the page knows it: true adds it to what to
/// keep, since MHFE encrypts only the phrase, and false leaves it out. Undefined or null, not
/// known, adds `{ item: "passphraseIfAny" }` in its place; anything else is INVALID_REQUEST.
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
    let wallet_passphrase = WalletPassphrase::from(passphrase_answer(&wallet_has_passphrase)?);
    let phrase = phrase.phrase()?;
    let suite = if same_length {
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

#[derive(Serialize)]
struct CheckJson {
    matches: bool,
    /// Where a matched address was found, such as "m/84'/0'/0'/0/5"; null otherwise.
    path: Option<String>,
    /// The original seed phrase's own checks, from the same recovery.
    evidence: EvidenceJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceJson {
    /// The length of a 12- to 21-word original seed phrase whose built-in check passes, or null.
    built_in_check: Option<usize>,
    /// Whether the 24-word reading passes the 16-bit phrase + passphrase check, with the
    /// passphrase given or the empty one when none was given. Null for a stated length, for a
    /// same-length container, and when exactly one shorter length passes its built-in check and
    /// the reference did not match the 24-word reading.
    wallet_check: Option<bool>,
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

/// A rehearsal check in one worker: the recovery once, then a comparison with the page's
/// reference and, when detection found no length, with the one the page gives next, without the
/// rounds again ([`RecoveredForCheck`]). Only whether each matches comes out; freed or dropped,
/// it wipes the recovered state.
#[wasm_bindgen]
pub struct CheckSession {
    recovered: RecoveredForCheck,
}

#[wasm_bindgen]
impl CheckSession {
    /// Recovers `container` for a check against the reference, which is refused first, before
    /// any round, when the container cannot be checked with it. The rounds are reported as
    /// "recover", then once "compare". `reference_kind` is "address", "fingerprint", "words" or
    /// "walletCheck" (the phrase and passphrase check of a 24-word container); see
    /// [`reference_target`].
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(constructor)]
    pub fn new(
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
    ) -> Result<CheckSession, JsError> {
        // Both secrets are put under a wiping owner before anything can fail, so that no early
        // return drops either of them unwiped. The passphrase is read in place, without a copy.
        let passphrase = SecretText::new(passphrase_utf8);
        let password = password_from(password_utf8, choice, position)?;
        let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
        let wallet = reference_target(reference_kind, reference, coin, path)?;
        // The library refuses a check that cannot be, an empty passphrase of the wallet check
        // among them, before any round, in the same order for every front end. The work area is
        // freed when this engine is dropped, before the page is asked anything.
        let (mut mhfe, _) = mhfe_for(pim, memory_level, argon2)?;
        let recovered = mhfe.recover_for_check_in_stages(
            container,
            &password,
            &wallet.with(passphrase),
            &mut |stage, round, rounds| report(on_round, stage, round, rounds),
        );
        let recovered = verified(&mhfe, recovered)?;
        Ok(Self { recovered })
    }

    /// Compares the recovery with a reference given as for [`CheckSession::new`], as JSON
    /// `{"matches": bool, "path": string | null, "evidence": {...}}`: only whether it matches
    /// comes out, and for a matched address the path where it was found.
    pub fn compare(
        &self,
        reference_kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase_utf8: Vec<u8>,
    ) -> Result<String, JsError> {
        let passphrase = SecretText::new(passphrase_utf8);
        let passphrase = passphrase.text(MhfeError::InvalidPassphrase)?;
        let wallet = reference_target(reference_kind, reference, coin, path)?;
        let evidence = self
            .recovered
            .compare(&wallet.with(passphrase))
            .map_err(js_error)?;
        json(&CheckJson {
            matches: evidence.outcome.matches(),
            path: evidence.outcome.path().map(ToString::to_string),
            evidence: EvidenceJson {
                built_in_check: evidence.built_in_check,
                wallet_check: evidence.wallet_check,
            },
        })
    }
}

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
    let fingerprint = master_fingerprint_text(&found.container, "").map_err(js_error)?;
    json(&SearchJson {
        found: true,
        container: Some(found.container.to_string()),
        container_fingerprint: Some(fingerprint),
        words: found
            .words
            .iter()
            .map(|&(position, word)| FoundWordJson { position, word })
            .collect(),
        path: found.outcome.path().map(ToString::to_string),
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
#[allow(clippy::too_many_arguments)]
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
    let scan_gap = whole_number(scan_gap, "INVALID_REQUEST", "scanGap")?;
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
#[allow(clippy::too_many_arguments)]
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
        "builtInCheck" => Compared::OwnChecks(None),
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

/// Where a rekey stands, so that its calls come in their order only.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RekeyStep {
    /// Made; the new password and settings come next.
    Made,
    /// The new password and settings are set; the recovery comes next.
    Ready,
    /// Recovered, and its confirmation refused with another allowed on the same recovery:
    /// `confirmAgain` comes next.
    Refused,
    /// Recovered; the owner's answer about the shown phrase comes next.
    AwaitingOwner,
    /// Recovered and confirmed; the seal comes next.
    Confirmed,
    /// Sealed, failed or refused: nothing more.
    Ended,
}

/// A rekey in one worker: made, given the new password and settings, recovered and confirmed
/// (again on the same recovery after a refusal that allows it, and by the owner's answer where the
/// owner confirms), then sealed. A call out of this order is refused with INVALID_REQUEST, and any
/// other failure ends the rekey.
#[wasm_bindgen]
pub struct RekeySession {
    rekey: Rekey,
    argon2: JsArgon2,
    old_work: WorkFactor,
    new_password: Option<Password>,
    new_work: Option<WorkFactor>,
    repair_word_count: Option<usize>,
    /// The old container's state between a refused confirmation and the next, in locked memory.
    recovered: Option<RecoveredForRekey>,
    /// Whether the wallet has a BIP39 passphrase, judged with the first confirmation before the
    /// rounds; it holds for every confirmation that follows, as the command-line tool asks it once.
    wallet_has_passphrase: Option<bool>,
    /// The lengths at which the owner may confirm after the refusal (`ownerLengths`).
    owner_lengths: Vec<usize>,
    confirmed: Option<ConfirmedPhrase>,
    step: RekeyStep,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveredJson<'a> {
    /// The phrase for the owner to compare with their backup, when the owner confirms it; null
    /// when the built-in check or the wallet confirmed it.
    owner_check: Option<PhraseJson<'a>>,
    /// The 16-bit source check of a 24-word reading, with the reference's passphrase, or the empty
    /// one; null for other lengths. It never confirms a rekey: 16 bits are too few.
    wallet_check: Option<bool>,
}

/// Why a confirmation on the recovered state did not confirm the phrase: a refusal that another
/// confirmation may follow, the owner's lengths with it, or a failure that ends the rekey.
enum NotConfirmed {
    Again {
        refusal: MhfeError,
        owner_lengths: Vec<usize>,
    },
    Ends(JsError),
}

impl From<JsError> for NotConfirmed {
    fn from(error: JsError) -> Self {
        Self::Ends(error)
    }
}

impl From<MhfeError> for NotConfirmed {
    fn from(error: MhfeError) -> Self {
        Self::Ends(js_error(error))
    }
}

/// Calls `then` with the library's confirmation of a rekey as the page names it, and the text of
/// `passphrase`: "builtInCheck" and "owner", which take no passphrase (INVALID_REQUEST with one),
/// or the wallet's reference of "address" or "fingerprint", as for `check`, compared with the
/// passphrase.
fn with_rekey_confirmation<T>(
    kind: &str,
    reference: &str,
    coin: &str,
    path: &str,
    passphrase: &SecretText,
    then: impl FnOnce(Confirmation<'_>, &str) -> T,
) -> Result<T, JsError> {
    let text = passphrase.text(MhfeError::InvalidPassphrase)?;
    // The wallet check (16 bits) and a word count never confirm a phrase to seal again.
    let wallet = match kind {
        "builtInCheck" | "owner" if !text.is_empty() => {
            return Err(js_error(MhfeError::InvalidRequest(
                "a passphrase belongs to an address or fingerprint confirmation".to_owned(),
            )))
        }
        "builtInCheck" | "owner" => None,
        "address" | "fingerprint" => Some(reference_target(kind, reference, coin, path)?),
        other => {
            return Err(js_error(MhfeError::InvalidRequest(format!(
                "a rekey is not confirmed by {other}"
            ))))
        }
    };
    let reference = wallet.as_ref().map(|wallet| wallet.with(text));
    let confirmation = match (kind, &reference) {
        (_, Some(reference)) => Confirmation::Wallet(reference),
        ("owner", None) => Confirmation::Owner,
        _ => Confirmation::BuiltInCheck,
    };
    Ok(then(confirmation, text))
}

#[wasm_bindgen]
impl RekeySession {
    /// A rekey of `container` with the old password and settings. `words` is the phrase's word
    /// count, 0 to detect it (a same-length container's own length). A page tells every user
    /// first that wallets other passwords open on the old container do not move to the new one,
    /// so the old container, its passwords and settings are kept until their funds are moved.
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
        argon2: JsArgon2,
    ) -> Result<RekeySession, JsError> {
        let password = password_from(password_utf8, choice, position)?;
        let old_work = work_from(pim, memory_level)?;
        let length = word_count(words)?;
        let rekey = Rekey::new(container, length, password, old_work).map_err(js_error)?;
        Ok(Self {
            rekey,
            argon2,
            old_work,
            new_password: None,
            new_work: None,
            repair_word_count: None,
            recovered: None,
            wallet_has_passphrase: None,
            owner_lengths: Vec::new(),
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
    /// false is refused; everywhere else it is required (see [`Rekey::recover`]). The answer holds
    /// for every confirmation of the rekey. These refusals, and REFERENCE_REQUIRED for a
    /// confirmation that cannot confirm a phrase of the rekey's length, come before the first
    /// round; only the Argon2 build's 1 MiB known answer runs before them. Returns JSON
    /// `{ ownerCheck, walletCheck }`: for "owner", the phrase to compare, and the rekey then waits
    /// for `ownerAnswer`; `walletCheck` the 16-bit source check of a 24-word reading with the
    /// reference's passphrase or the empty one, null for other lengths. A refusal after the
    /// rounds that allows another confirmation (AMBIGUOUS_LENGTH, LENGTH_DIFFERS) keeps the
    /// recovery for `confirmAgain`; `ownerLengths` then says whether the owner may give it.
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
        let outcome = with_rekey_confirmation(
            kind,
            reference,
            coin,
            path,
            &passphrase,
            |confirmation, _| {
                let stated = passphrase_answer(&wallet_has_passphrase)?;
                let has_passphrase = self
                    .rekey
                    .check_confirmation(&confirmation, stated)
                    .map_err(js_error)?;
                // The old work area is freed when this engine is dropped, at the end of this block,
                // before the owner is asked or the new one is made.
                let (mut mhfe, _) = mhfe_with(self.old_work, self.argon2.clone().unchecked_into())?;
                let recovered = self.rekey.recover_state(
                    &mut mhfe,
                    confirmation,
                    &mut |stage, round, rounds| report(on_round, stage, round, rounds),
                );
                Ok((verified(&mhfe, recovered)?, has_passphrase))
            },
        )
        // A refusal of the confirmation as named, or else the recovery's own outcome.
        .and_then(|outcome| outcome);
        let (recovered, has_passphrase) = self.or_end(outcome)?;
        self.recovered = Some(recovered);
        self.wallet_has_passphrase = Some(has_passphrase);
        self.confirm_recovered(kind, reference, coin, path, &passphrase, on_round)
    }

    /// After a refused confirmation that allows another (the rekey waits for `confirmAgain`), the
    /// lengths at which the owner may compare the phrase with their backup, as JSON: empty where
    /// only an address or the fingerprint confirms it. After AMBIGUOUS_LENGTH the owner states one
    /// of them; after LENGTH_DIFFERS it is the stated length, at which the owner is shown the
    /// reading the built-in check found. null when no confirmation may follow.
    #[wasm_bindgen(js_name = ownerLengths)]
    pub fn owner_lengths(&self) -> Result<String, JsError> {
        json(&(self.step == RekeyStep::Refused).then_some(&self.owner_lengths))
    }

    /// Confirms the phrase again on the same recovery, without its rounds, after a refusal that
    /// allows it (AUD-017-UI002): `kind`, `reference`, `coin`, `path` and `passphrase` as for
    /// `recover`, with its answer whether the wallet has a BIP39 passphrase. `words` is the length
    /// the owner compares, one of `ownerLengths` (INVALID_REQUEST otherwise), and 0 with every
    /// other kind. Returns what `recover` returns; a refusal that allows another keeps the
    /// recovery again, and any other failure ends the rekey.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = confirmAgain)]
    pub fn confirm_again(
        &mut self,
        kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase_utf8: Vec<u8>,
        words: f64,
        on_round: &js_sys::Function,
    ) -> Result<js_sys::JsString, JsError> {
        // Under a wiping owner first, so that a step out of its order drops it wiped too.
        let passphrase = SecretText::new(passphrase_utf8);
        self.expect(RekeyStep::Refused)?;
        let outcome = self
            .owner_length(kind, words)
            .and_then(|length| match length {
                Some(length) => self.rekey.set_length(length).map_err(js_error),
                None => Ok(()),
            });
        self.or_end(outcome)?;
        self.confirm_recovered(kind, reference, coin, path, &passphrase, on_round)
    }

    /// The owner's answer after comparing the shown phrase with their backup: anything but yes
    /// ends the rekey (NOT_CONFIRMED_BY_OWNER) and drops the phrase.
    #[wasm_bindgen(js_name = ownerAnswer)]
    pub fn owner_answer(&mut self, confirmed: JsValue) -> Result<(), JsError> {
        self.expect(RekeyStep::AwaitingOwner)?;
        // Only the value true is a yes: a bool of the ABI would take 1, "1" or [1] as one.
        if confirmed.as_bool() != Some(true) {
            self.end();
            return Err(js_error(MhfeError::NotConfirmedByOwner));
        }
        // The library seals an owner's phrase only once it has the yes.
        self.confirmed = self
            .confirmed
            .take()
            .map(ConfirmedPhrase::confirmed_by_owner);
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
        let repair_words = self.repair_word_count;
        let sealed = sealed_for_page(
            &mut mhfe,
            on_round,
            on_unverified,
            |mhfe, progress, shown| {
                self.rekey
                    .seal(mhfe, &confirmed, &password, repair_words, progress, shown)
            },
        )?;
        sealed_json(&sealed, work, confirmed.wallet_has_passphrase().into())
    }
}

impl RekeySession {
    /// Confirms the phrase on the recovered state as `kind` says, and returns what `recover`
    /// returns. The state is dropped, and wiped, once the phrase is confirmed or the rekey ends;
    /// a refusal that allows another confirmation keeps it.
    fn confirm_recovered(
        &mut self,
        kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase: &SecretText,
        on_round: &js_sys::Function,
    ) -> Result<js_sys::JsString, JsError> {
        match self.try_confirm(kind, reference, coin, path, passphrase, on_round) {
            Ok((confirmed, result)) => {
                self.recovered = None;
                self.step = if confirmed.awaits_owner() {
                    RekeyStep::AwaitingOwner
                } else {
                    RekeyStep::Confirmed
                };
                self.confirmed = Some(confirmed);
                Ok(result)
            }
            Err(NotConfirmed::Again {
                refusal,
                owner_lengths,
            }) => {
                self.owner_lengths = owner_lengths;
                self.step = RekeyStep::Refused;
                Err(js_error(refusal))
            }
            Err(NotConfirmed::Ends(error)) => {
                self.end();
                Err(error)
            }
        }
    }

    fn try_confirm(
        &self,
        kind: &str,
        reference: &str,
        coin: &str,
        path: &str,
        passphrase: &SecretText,
        on_round: &js_sys::Function,
    ) -> Result<(ConfirmedPhrase, js_sys::JsString), NotConfirmed> {
        let recovered = self.recovered.as_ref().ok_or_else(|| {
            MhfeError::Internal("a rekey confirms without its recovery".to_owned())
        })?;
        with_rekey_confirmation(
            kind,
            reference,
            coin,
            path,
            passphrase,
            |confirmation, text| {
                let confirmed = self.rekey.confirm(
                    recovered,
                    confirmation,
                    self.wallet_has_passphrase,
                    &mut |stage, round, rounds| report(on_round, stage, round, rounds),
                );
                let confirmed = match confirmed {
                    Ok(confirmed) => confirmed,
                    Err(refusal) => {
                        return Err(match self.rekey.owner_lengths_after(recovered, &refusal)? {
                            Some(owner_lengths) => NotConfirmed::Again {
                                refusal,
                                owner_lengths,
                            },
                            None => refusal.into(),
                        })
                    }
                };
                // Every recovery evaluates it on a 24-word reading (the specification's recovery
                // rules), with the passphrase given or the empty one.
                let wallet_check = confirmed.phrase().passes_wallet_check(text)?;
                let owner_check = confirmed
                    .awaits_owner()
                    .then(|| PhraseJson::of(confirmed.phrase()))
                    .transpose()?;
                let result = secret_json(&RecoveredJson {
                    owner_check,
                    wallet_check,
                })?;
                Ok((confirmed, result))
            },
        )?
    }

    /// The length the owner states with `words` for a confirmation of `kind` after a refusal: one
    /// of the lengths the library left the owner, and 0 with every other kind.
    fn owner_length(&self, kind: &str, words: f64) -> Result<Option<PhraseLength>, JsError> {
        let words = whole_number(words, "INVALID_WORD_COUNT", "the word count")? as usize;
        match (kind, words) {
            ("owner", words) if self.owner_lengths.contains(&words) => Ok(Some(
                PhraseLength::Words(WordCount::new(words).map_err(js_error)?),
            )),
            ("owner", _) if self.owner_lengths.is_empty() => {
                Err(js_error(MhfeError::InvalidRequest(
                    "the owner cannot confirm this phrase: an address or the fingerprint does"
                        .to_owned(),
                )))
            }
            ("owner", words) => Err(js_error(MhfeError::InvalidRequest(format!(
                "the owner confirms a reading of {:?} words here, not {words}",
                self.owner_lengths
            )))),
            (_, 0) => Ok(None),
            _ => Err(js_error(MhfeError::InvalidRequest(
                "only the owner's confirmation states a length".to_owned(),
            ))),
        }
    }

    fn expect(&mut self, step: RekeyStep) -> Result<(), JsError> {
        if self.step == step {
            return Ok(());
        }
        self.end();
        Err(js_error(MhfeError::InvalidRequest(
            "a rekey step out of its order".to_owned(),
        )))
    }

    /// Ends the rekey when `outcome` failed.
    fn or_end<T>(&mut self, outcome: Result<T, JsError>) -> Result<T, JsError> {
        if outcome.is_err() {
            self.end();
        }
        outcome
    }

    /// Ends the rekey: the recovered state and the phrase are dropped, and wiped.
    fn end(&mut self) {
        self.step = RekeyStep::Ended;
        self.recovered = None;
        self.confirmed = None;
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
        secret_json(&PhraseJson::of(&wallet)?)
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
    let words = whole_number(words, "INVALID_WORD_COUNT", "the word count")?;
    PhraseLength::from_count(words as usize).map_err(js_error)
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
    let fingerprint = master_fingerprint_text(container, "")?;
    let text = serde_json::to_string(&UnverifiedJson {
        container,
        container_fingerprint: fingerprint,
    })
    .map_err(|error| MhfeError::Internal(error.to_string()))?;
    call_page(on_unverified, &[JsValue::from_str(&text)])
}
