//! MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics, suites
//! `MHFE-BIP39-256-EXPERIMENTAL-3` and `MHFE-BIP39-LP-EXPERIMENTAL-4`.
//!
//! [`encrypt`] turns an English BIP39 phrase of 12 to 24 words into a password-protected
//! 24-word container that is itself a valid BIP39 phrase, or, with [`Suite::SameLength`], a 12- to
//! 21-word phrase into a container of its own length; [`decrypt`] turns the container back into
//! the original, the container's word count selecting the suite. Every one of the twelve
//! Feistel rounds runs Argon2id with 2 GiB of memory by default, using the reference C
//! implementation of Argon2.
//!
//! The construction is experimental and has not been independently reviewed. Do not use it to
//! protect real funds.
//!
//! ```no_run
//! use mhfe::{decrypt, encrypt, Mhfe, PhraseLength, Recovery, Suite, WorkFactor};
//! use mhfe_core::Password;
//!
//! let password = Password::new("correct horse battery staple")?;
//! let mut mhfe = Mhfe::new(WorkFactor::default())?; // reserves 2 GiB
//! let original = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon about";
//! let container = encrypt(
//!     &mut mhfe,
//!     original,
//!     &password,
//!     Suite::TwentyFourWords,
//!     &mut |round, rounds| {
//!         println!("Round {round}/{rounds}");
//!         Ok(())
//!     },
//!     &mut |_| Ok(()),
//! )?;
//! let recovery = decrypt(
//!     &mut mhfe,
//!     &container,
//!     &password,
//!     PhraseLength::Detect,
//!     &mut |_, _| Ok(()),
//! )?;
//! if let Recovery::Phrase(phrase) = recovery {
//!     assert_eq!(phrase.phrase(), original);
//! }
//! # Ok::<(), mhfe::MhfeError>(())
//! ```

// Unsafe code is allowed in one module only, src/engine/ffi.rs, which calls the operating system.
#![deny(unsafe_code)]

pub mod check_word;
mod container;
mod detection;
pub mod eff;
pub mod engine;
mod error;
mod feistel;
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
pub use hidden::{derive_wallet, HiddenWallets};
pub use mhfe::{
    decrypt, decrypt_as, encrypt, other_detected_lengths, Mhfe, PhraseLength, ProgressCallback,
    RecoveredPhrase, Recovery, RecoveryStatus, WordCount, ENCRYPTION_ROUNDS,
};
pub use phrase::{check_container, check_phrase, phrase_from_entropy, read_phrase, WORD_COUNTS};
pub use rehearsal::{
    check, recover_confirmed, recover_for_check, recover_for_check_in_stages,
    require_built_in_check_length, CheckEvidence, CheckOutcome, Confirmation, RecoveredForCheck,
    RecoveredForRekey, Reference, ReferenceTarget,
};
pub use suite::{
    memory_text, Suite, WorkFactor, MAX_MEMORY_LEVEL, MAX_PIM, ROUNDS, SAME_LENGTH_SUITE_ID,
    SUITE_ID,
};
