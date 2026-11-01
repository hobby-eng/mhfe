//! MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics, suites
//! `MHFE-BIP39-256-EXPERIMENTAL-3` and `MHFE-BIP39-LP-EXPERIMENTAL-4`.
//!
//! [`encrypt`] turns an English BIP39 phrase of 12 to 24 words into a password-protected
//! 24-word container that is itself a valid BIP39 phrase, or, with `Suite::SameLength`, a 12- to
//! 21-word phrase into a container of its own length; [`decrypt`] turns the container back into
//! the original, the container's word count selecting the suite. Every one of the twelve
//! Feistel rounds runs Argon2id with 2 GiB of memory by default, using the reference C
//! implementation of Argon2. The cipher is [`mhfe_core`]'s; this crate adds the front ends' rules
//! and refusals around it.
//!
//! The construction is experimental and has not been independently reviewed. Do not use it to
//! protect real funds.
//!
//! ```no_run
//! use mhfe::engine::reserve;
//! use mhfe::{decrypt, encrypt, PhraseLength, Recovery};
//! use mhfe_core::{Mhfe, Password, Suite, WorkFactor};
//!
//! let password = Password::new("correct horse battery staple")?;
//! let work = WorkFactor::default();
//! let mut mhfe = Mhfe::with_engine(work, reserve(work)?); // reserves 2 GiB
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
//!     container.as_str(),
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
    decrypt, decrypt_as, encrypt, PhraseLength, ProgressCallback, RecoveredPhrase, Recovery,
    RecoveryStatus, WordCount, ENCRYPTION_ROUNDS,
};
pub use phrase::{check_container, check_phrase, read_phrase, WORD_COUNTS};
pub use rehearsal::{
    check, recover_confirmed, recover_for_check, recover_for_check_in_stages,
    require_built_in_check_length, CheckEvidence, CheckOutcome, Confirmation, RecoveredForCheck,
    RecoveredForRekey, Reference, ReferenceTarget,
};
pub use suite::{estimated_seconds, memory_bytes, memory_text, require_original, ROUNDS};
