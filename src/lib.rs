//! MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics, suites
//! `MHFE-BIP39-256-EXPERIMENTAL-3` and `MHFE-BIP39-LP-EXPERIMENTAL-4`.
//!
//! [`Mhfe::encrypt`] turns an English BIP39 phrase of 12 to 24 words into a password-protected
//! 24-word container that is itself a valid BIP39 phrase, or, with [`Suite::SameLength`], a 12- to
//! 21-word phrase into a container of its own length; [`Mhfe::decrypt`] turns the container back
//! into the original, the container's word count selecting the suite. Every one of the twelve
//! Feistel rounds runs Argon2id with 2 GiB of memory by default, using the reference C
//! implementation of Argon2.
//!
//! The construction is experimental and has not been independently reviewed. Do not use it to
//! protect real funds.
//!
//! ```no_run
//! use mhfe::{Mhfe, Password, PhraseLength, Recovery, Suite, WorkFactor};
//!
//! let password = Password::new("correct horse battery staple")?;
//! let mut mhfe = Mhfe::new(WorkFactor::default())?; // reserves 2 GiB
//! let original = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon about";
//! let container = mhfe.encrypt(original, &password, Suite::TwentyFourWords, &mut |round, rounds| {
//!     println!("Round {round}/{rounds}");
//!     Ok(())
//! })?;
//! let recovery = mhfe.decrypt(&container, &password, PhraseLength::Detect, &mut |_, _| Ok(()))?;
//! if let Recovery::Phrase(phrase) = recovery {
//!     assert_eq!(phrase.phrase(), original);
//! }
//! # Ok::<(), mhfe::MhfeError>(())
//! ```

// Unsafe code is allowed locally in engine::ffi for C calls and memory::os for page policy;
// each foreign-function interface states its reason and each block its safety conditions.
#![deny(unsafe_code)]

mod bip39_seed;
mod cancelled;
mod check_state;
pub mod check_word;
mod container;
mod detection;
pub mod eff;
pub mod engine;
mod error;
mod error_code;
mod feistel;
mod hidden;
#[cfg(all(target_arch = "wasm32", feature = "browser-core"))]
mod js_error;
pub mod memory;
mod mhfe;
pub mod new_password;
pub mod operation;
pub mod output;
mod packing;
mod password;
mod phrase;
pub mod random;
mod rehearsal;
pub mod rekey;
pub mod repair;
pub mod request;
pub mod search;
pub mod self_check;
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub mod self_test;
pub mod strength;
mod suite;
#[cfg(test)]
mod test_support;
mod text;
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
mod validation_fixtures;
pub mod vectors;
pub mod wallet;
pub mod wallet_check;
#[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
#[allow(
    unreachable_pub,
    reason = "wasm-bindgen exports are reached by JavaScript through generated glue"
)]
mod wasm_api;
pub mod word_hints;
pub mod word_wishes;
#[cfg(not(target_arch = "wasm32"))]
mod workers;

pub use bip39_seed::PassphraseError;
pub use cancelled::CancelledError;
pub use check_state::CheckState;
pub use container::{
    ConfirmationNeeded, ContainerChoice, ContainerFacts, OriginalFacts, BUILT_IN_CHECK_WORD_COUNTS,
};
pub use error::MhfeError;
pub use error_code::{ErrorCode, ErrorIdentity};
pub use hidden::{HiddenError, HiddenWallets};
pub use mhfe::{
    CipherError, Mhfe, NewContainer, ProgressCallback, RecoveredPhrase, Recovery, RecoveryStatus,
    ENCRYPTION_ROUNDS,
};
pub use password::{Password, PasswordError, MAX_PASSWORD_BYTES};
pub use phrase::{Phrase, PhraseError, PhraseIssue, WORD_COUNTS};
pub use rehearsal::{
    CheckEvidence, CheckOutcome, Confirmation, PassedCheck, PassphraseReferences,
    RecoveredForCheck, RecoveredForRekey, Reference, ReferenceTarget, RehearsalError,
};
pub use suite::{
    FormatError, PhraseLength, Settings, SettingsError, Suite, WordCount, WorkFactor,
    MAX_MEMORY_LEVEL, MAX_PIM, ROUNDS, SAME_LENGTH_SUITE_ID, SUITE_ID,
};
pub use text::GroupedCount;
