//! MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics, suites
//! `MHFE-BIP39-256-EXPERIMENTAL-3` and `MHFE-BIP39-LP-EXPERIMENTAL-4`.
//!
//! [`encrypt`] turns an English BIP39 phrase of 12 to 24 words into a password-protected
//! 24-word container that is itself a valid BIP39 phrase, or, with `Suite::SameLength`, a 12- to
//! 21-word phrase into a container of its own length; [`decrypt`] turns the container back into
//! the original, the container's word count selecting the suite. Every one of the twelve
//! Feistel rounds runs Argon2id with 2 GiB of memory by default, on RustCrypto's `argon2`
//! natively and on the reference C implementation in a browser. The cipher is [`mhfe_core`]'s;
//! this crate adds the front ends' rules and refusals around it.
//!
//! The construction is experimental and has not been independently reviewed. Do not use it to
//! protect real funds.
//!
//! ```no_run
//! use std::ops::ControlFlow;
//! use mhfe::engine::reserve;
//! use mhfe::{decrypt, encrypt, PhraseLength, Recovery, GO_ON};
//! use mhfe_core::{Mhfe, Password, Suite, WorkFactor};
//!
//! let password = Password::new("correct horse battery staple")?;
//! let work = WorkFactor::default();
//! let mut mhfe = Mhfe::with_engine(work, reserve(work)?); // reserves 2 GiB
//! let original = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon about";
//! // A callback's `Ok(ControlFlow::Break(()))` stops the operation, which then returns `Break`.
//! let ControlFlow::Continue(container) = encrypt(
//!     &mut mhfe,
//!     original,
//!     &password,
//!     Suite::TwentyFourWords,
//!     &mut |round, rounds| {
//!         println!("Round {round}/{rounds}");
//!         GO_ON
//!     },
//!     &mut |_| GO_ON,
//! )?
//! else {
//!     return Ok(());
//! };
//! let recovery = decrypt(
//!     &mut mhfe,
//!     container.as_str(),
//!     &password,
//!     PhraseLength::Detect,
//!     &mut |_, _| GO_ON,
//! )?;
//! if let ControlFlow::Continue(Recovery::Phrase(phrase)) = recovery {
//!     assert_eq!(phrase.phrase(), original);
//! }
//! # Ok::<(), mhfe::MhfeError>(())
//! ```

// Unsafe code is allowed in one module only, src/engine/ffi.rs, which calls the operating system.
#![deny(unsafe_code)]

/// `Display` and `Error` for a module's own error, whose text is that of the [`MhfeError`] it turns
/// into, so that each text is written once.
macro_rules! shown_as_mhfe_error {
    ($error:ty) => {
        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                MhfeError::from(self.clone()).fmt(f)
            }
        }

        impl std::error::Error for $error {}
    };
}

/// The value of an [`Outcome`] that goes on, or the `Break` of a callback, returned at once from
/// the enclosing function, whose own result is an [`Outcome`].
macro_rules! proceed {
    ($outcome:expr) => {
        match $outcome? {
            std::ops::ControlFlow::Continue(value) => value,
            std::ops::ControlFlow::Break(()) => return Ok(std::ops::ControlFlow::Break(())),
        }
    };
}

pub mod check_word;
mod container;
mod detection;
pub mod eff;
pub mod engine;
mod error;
mod hidden;
pub mod memory;
mod mhfe;
pub mod new_password;
pub mod operation;
mod packing;
pub mod password;
mod phrase;
pub mod random;
mod rehearsal;
pub mod rekey;
pub mod repair;
pub mod search;
pub mod self_check;
#[cfg(any(not(target_arch = "wasm32"), feature = "browser-core"))]
pub mod self_test;
pub mod strength;
mod suite;
#[cfg(test)]
mod test_support;
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-passwords"
))]
mod validation_fixtures;
pub mod wallet;
pub mod wallet_check;
#[cfg(all(feature = "wasm-bindings", target_arch = "wasm32"))]
mod wasm_api;
pub mod word_hints;
pub mod word_wishes;

pub use container::{
    ConfirmationNeeded, ContainerChoice, ContainerFacts, OriginalFacts, BUILT_IN_CHECK_WORD_COUNTS,
};
pub use error::MhfeError;

/// What an operation that a callback can stop comes to: `Continue` with its result, `Break` when a
/// callback stopped it, as a person who cancels does, or the error that refused it. A callback
/// returns one of its own, with no value.
pub type Outcome<T = ()> = Result<std::ops::ControlFlow<(), T>, MhfeError>;

/// The [`Outcome`] of a callback that lets the operation go on.
pub const GO_ON: Outcome = Ok(std::ops::ControlFlow::Continue(()));

/// The result of an operation whose callbacks never say `Break`, as in the checks at start.
#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
pub(crate) trait Unstopped<T> {
    fn unstopped(self) -> Result<T, MhfeError>;
}

#[cfg(any(
    not(target_arch = "wasm32"),
    feature = "browser-core",
    feature = "browser-wallet"
))]
impl<T> Unstopped<T> for Outcome<T> {
    fn unstopped(self) -> Result<T, MhfeError> {
        self?.continue_value().ok_or_else(|| {
            MhfeError::Internal("an operation stopped although nothing could stop it".to_owned())
        })
    }
}
pub use hidden::{derive_wallet, HiddenWallets};
pub use mhfe::{
    decrypt, decrypt_as, encrypt, PhraseLength, ProgressCallback, RecoveredPhrase, Recovery,
    RecoveryStatus, WordCount, ENCRYPTION_ROUNDS,
};
pub use phrase::{check_phrase, read_phrase, WORD_COUNTS};
pub use rehearsal::{
    check, recover_for_check, recover_for_check_in_stages, require_built_in_check_length,
    CheckEvidence, CheckOutcome, Confirmation, RecoveredForCheck, RecoveredForRekey, Reference,
    ReferenceTarget,
};
pub use suite::{estimated_seconds, memory_bytes, memory_text, require_original, ROUNDS};
