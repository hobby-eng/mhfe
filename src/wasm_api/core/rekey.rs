//! A rekey in the browser, over several calls in one worker, as [`RekeySession`]: the new
//! password and settings, the recovery, its confirmation and the sealing, in their order.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    mhfe_with, new_password_from, passphrase_answer, password_from, reference_target, repair_count,
    report, sealed_for_page, sealed_view, settings_from, verified, word_count, work_from,
    PhraseJson, RehearsalJson, ResealedJson,
};
use crate::engine::browser::JsArgon2;
use crate::rekey::{ConfirmedPhrase, Rekey, ReplacementRehearsal};
use crate::wasm_api::{js_error, json, secret_json, SecretText};
use crate::{
    Confirmation, MhfeError, PassphraseReferences, Password, PhraseLength, RecoveredForRekey,
    Settings, WordCount, WorkFactor,
};

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
    /// The old container's state between a refused confirmation and the next, wiped when dropped;
    /// a browser cannot lock it, so it may be swapped out with the rest of the page.
    recovered: Option<RecoveredForRekey>,
    /// Whether the wallet has a BIP39 passphrase, judged with the first confirmation before the
    /// rounds; it holds for every confirmation that follows, as the command-line tool asks it once.
    wallet_has_passphrase: Option<bool>,
    /// The lengths at which the owner may confirm after the refusal (`ownerLengths`).
    owner_lengths: Vec<usize>,
    refusal: Option<MhfeError>,
    confirmed: Option<ConfirmedPhrase>,
    /// What the new container's rehearsal compares, known before it is sealed.
    rehearsal: Option<ReplacementRehearsal>,
    step: RekeyStep,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveredJson<'a> {
    /// The phrase for the owner to compare with their backup, when the owner confirms it; null
    /// when the built-in check or the wallet confirmed it.
    owner_check: Option<PhraseJson<'a>>,
    /// The 16-bit wallet check of a 24-word reading, with the reference's passphrase, or the empty
    /// one; null for other lengths. It never confirms a rekey: 16 bits are too few.
    wallet_check: Option<bool>,
    /// Whether the owner's yes must come with the wallet's BIP39 passphrase, for the fingerprint
    /// the new container's rehearsal compares ([`ConfirmedPhrase::rehearsal_needs_passphrase`]).
    rehearsal_needs_passphrase: bool,
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

/// The non-secret fields of a page's confirmation, including an optional owner length.
struct PageConfirmation<'a> {
    kind: &'a str,
    reference: &'a str,
    coin: &'a str,
    path: &'a str,
    words: Option<WordCount>,
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
    let text = passphrase.passphrase()?;
    // The wallet check (16 bits) and a word count never confirm a phrase to seal again.
    let wallet = match kind {
        "builtInCheck" | "owner" => {
            PassphraseReferences::Rekey
                .refuse_unused(text)
                .map_err(js_error)?;
            None
        }
        "address" | "fingerprint" => Some(reference_target(kind, reference, coin, path)?),
        _ => {
            return Err(js_error(MhfeError::Rekey(
                crate::rekey::RekeyError::UnsupportedConfirmation,
            )))
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
    /// first what to keep of the old container until the funds of the wallets that other
    /// passwords open on it are moved ([`keep_old_container`]).
    #[expect(
        clippy::too_many_arguments,
        reason = "the WebAssembly binding takes every input as an argument of its own"
    )]
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
            refusal: None,
            confirmed: None,
            rehearsal: None,
            step: RekeyStep::Made,
        })
    }

    /// The new password, typed twice, with its review choice, and the new settings and repair
    /// words. Refused before any Argon2 work when they would give the old container again.
    #[expect(
        clippy::too_many_arguments,
        reason = "the WebAssembly binding takes every input as an argument of its own"
    )]
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
            let work = settings_from(pim, memory_level, Settings::New)?;
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
    /// round and before the Argon2 build's 1 MiB known answer. Returns JSON
    /// `{ ownerCheck, walletCheck }`: for "owner", the phrase to compare, and the rekey then waits
    /// for `ownerAnswer`; `walletCheck` the 16-bit wallet check of a 24-word reading with the
    /// reference's passphrase or the empty one, null for other lengths. A refusal after the
    /// rounds that allows another confirmation (AMBIGUOUS_LENGTH, LENGTH_DIFFERS) keeps the
    /// recovery for `confirmAgain`; `ownerLengths` then says whether the owner may give it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the WebAssembly binding takes every input as an argument of its own"
    )]
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
        self.confirm_recovered(
            PageConfirmation {
                kind,
                reference,
                coin,
                path,
                words: None,
            },
            &passphrase,
            on_round,
        )
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
    #[expect(
        clippy::too_many_arguments,
        reason = "the WebAssembly binding takes every input as an argument of its own"
    )]
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
        let words = word_count(words).map(|length| match length {
            PhraseLength::Detect => None,
            PhraseLength::Words(words) => Some(words),
        });
        let words = self.or_end(words)?;
        self.confirm_recovered(
            PageConfirmation {
                kind,
                reference,
                coin,
                path,
                words,
            },
            &passphrase,
            on_round,
        )
    }

    /// The owner's answer after comparing the shown phrase with their backup: anything but yes
    /// ends the rekey (NOT_CONFIRMED_BY_OWNER) and drops the phrase. With the yes comes
    /// `passphrase_utf8`, the wallet's BIP39 passphrase where the recovery said that the
    /// rehearsal needs it (`rehearsalNeedsPassphrase`), empty otherwise: the fingerprint the new
    /// container's rehearsal compares is made from it before the seal.
    #[wasm_bindgen(js_name = ownerAnswer)]
    pub fn owner_answer(
        &mut self,
        confirmed: JsValue,
        passphrase_utf8: Vec<u8>,
    ) -> Result<(), JsError> {
        let passphrase = SecretText::new(passphrase_utf8);
        self.expect(RekeyStep::AwaitingOwner)?;
        // Only the value true is a yes: a bool of the ABI would take 1, "1" or [1] as one.
        if confirmed.as_bool() != Some(true) {
            self.end();
            return Err(js_error(MhfeError::Rekey(
                crate::rekey::RekeyError::OwnerRejected,
            )));
        }
        // The library seals an owner's phrase only once it has the yes.
        let confirmed = self
            .confirmed
            .take()
            .map(ConfirmedPhrase::confirmed_by_owner);
        let rehearsal = match &confirmed {
            Some(confirmed) => passphrase
                .passphrase()
                .and_then(|text| confirmed.replacement_rehearsal(text).map_err(js_error)),
            None => Err(js_error(MhfeError::Rekey(
                crate::rekey::RekeyError::OwnerAnswerWithoutPhrase,
            ))),
        };
        self.confirmed = confirmed;
        self.rehearsal = Some(self.or_end(rehearsal)?);
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
        let (Some(confirmed), Some(password), Some(work), Some(rehearsal)) = (
            self.confirmed.take(),
            self.new_password.take(),
            self.new_work,
            self.rehearsal.take(),
        ) else {
            return Err(js_error(MhfeError::Rekey(
                crate::rekey::RekeyError::MissingSealingInputs,
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
        json(&ResealedJson {
            sealed: sealed_view(&sealed, work, confirmed.wallet_has_passphrase().into())?,
            rehearsal: RehearsalJson::from(&rehearsal),
        })
    }
}

impl RekeySession {
    /// Confirms the phrase on the recovered state as `kind` says, and returns what `recover`
    /// returns. The state is dropped, and wiped, once the phrase is confirmed or the rekey ends;
    /// a refusal that allows another confirmation keeps it.
    fn confirm_recovered(
        &mut self,
        input: PageConfirmation<'_>,
        passphrase: &SecretText,
        on_round: &js_sys::Function,
    ) -> Result<js_sys::JsString, JsError> {
        match self.try_confirm(input, passphrase, on_round) {
            Ok((confirmed, result)) => {
                self.recovered = None;
                self.step = if confirmed.awaits_owner() {
                    RekeyStep::AwaitingOwner
                } else {
                    // A reference or the built-in check confirmed it: the rehearsal needs no
                    // passphrase of its own.
                    let rehearsal = confirmed.replacement_rehearsal("").map_err(js_error);
                    self.rehearsal = Some(self.or_end(rehearsal)?);
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
                self.refusal = Some(refusal.clone());
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
        &mut self,
        input: PageConfirmation<'_>,
        passphrase: &SecretText,
        on_round: &js_sys::Function,
    ) -> Result<(ConfirmedPhrase, js_sys::JsString), NotConfirmed> {
        let recovered = self.recovered.as_ref().ok_or(MhfeError::Rekey(
            crate::rekey::RekeyError::ConfirmationWithoutRecovery,
        ))?;
        with_rekey_confirmation(
            input.kind,
            input.reference,
            input.coin,
            input.path,
            passphrase,
            |confirmation, text| {
                let mut progress = |stage, round, rounds| report(on_round, stage, round, rounds);
                let confirmed = if let Some(refusal) = &self.refusal {
                    self.rekey.confirm_again(
                        recovered,
                        refusal,
                        confirmation,
                        input.words,
                        self.wallet_has_passphrase,
                        &mut progress,
                    )
                } else {
                    self.rekey.confirm(
                        recovered,
                        confirmation,
                        self.wallet_has_passphrase,
                        &mut progress,
                    )
                };
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
                let wallet_check = confirmed
                    .phrase()
                    .passes_wallet_check(text)
                    .map_err(MhfeError::from)?;
                let owner_check = confirmed
                    .awaits_owner()
                    .then(|| PhraseJson::of(confirmed.phrase()))
                    .transpose()?;
                let result = secret_json(&RecoveredJson {
                    owner_check,
                    wallet_check,
                    rehearsal_needs_passphrase: confirmed.rehearsal_needs_passphrase(),
                })?;
                Ok((confirmed, result))
            },
        )?
    }

    fn expect(&mut self, step: RekeyStep) -> Result<(), JsError> {
        if self.step == step {
            return Ok(());
        }
        self.end();
        Err(js_error(MhfeError::Rekey(
            crate::rekey::RekeyError::StepOutOfOrder,
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
        self.refusal = None;
        self.confirmed = None;
    }
}
