//! Hidden wallets in the browser: a session on one container, as [`HiddenWalletSession`].

use wasm_bindgen::prelude::*;

use super::{new_password_from, report, verified, work_from, PhraseJson};
use crate::engine::browser::{BrowserEngine, JsArgon2};
use crate::operation::Stage;
use crate::wasm_api::{js_error, secret_json, SecretText};
use crate::{HiddenWallets, Mhfe, MhfeError};

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
