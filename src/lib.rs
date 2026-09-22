//! Experimental Memory-Hard Feistel Encryption for BIP39 Mnemonics,
//! implementing `MHFE-BIP39-256-EXPERIMENTAL-2`.
//!
//! This crate exists to generate interoperable test vectors and measurements.
//! The construction has not received independent cryptographic review and MUST
//! NOT be used to protect real funds.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use bip39::{Language, Mnemonic};
use blake2::{digest::consts::U32, Blake2b, Digest as BlakeDigest};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm_api;

pub const API_VERSION: u32 = 1;
pub const SUITE_ID: &str = "MHFE-BIP39-256-EXPERIMENTAL-2";
pub const ROUND_COUNT: u32 = 12;
pub const MEMORY_KIB: u32 = 524_288;
pub const LANES: u32 = 4;
pub const BASE_PASSES: u32 = 12;
pub const MAX_PIM: u32 = 31;

const DS_SALT_SUFFIX: &[u8] = b"/ROUND-SALT";
const DS_MASK_SUFFIX: &[u8] = b"/ROUND-MASK";

type Blake2b256 = Blake2b<U32>;
type HmacSha256 = Hmac<Sha256>;
type RoundMaterial = ([u8; 16], [u8; 32], [u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MhfeError {
    InvalidMnemonic(String),
    InvalidContainer(String),
    InvalidSourceWords(usize),
    InvalidEntropyLength(usize),
    InvalidPim(u32),
    EmptyPassword,
    PasswordTooLong(usize),
    InvalidPasswordUtf8,
    UnsupportedUnicodePassword,
    PasswordNotSet,
    FixedPoint,
    RecoveryVerifierMismatch,
    AmbiguousSourceWords(Vec<usize>),
    Argon2(String),
    MemoryAllocation,
    Internal(String),
}

impl fmt::Display for MhfeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMnemonic(message) => write!(f, "invalid source mnemonic: {message}"),
            Self::InvalidContainer(message) => write!(f, "invalid encrypted mnemonic: {message}"),
            Self::InvalidSourceWords(words) => {
                write!(
                    f,
                    "source word count must be 12, 15, 18, 21, or 24; received {words}"
                )
            }
            Self::InvalidEntropyLength(bytes) => write!(
                f,
                "entropy must contain 16, 20, 24, 28, or 32 bytes; received {bytes}"
            ),
            Self::InvalidPim(pim) => write!(f, "PIM must be in 0..={MAX_PIM}; received {pim}"),
            Self::EmptyPassword => write!(f, "the normalized password must not be empty"),
            Self::PasswordTooLong(bytes) => {
                write!(
                    f,
                    "the normalized password exceeds 1024 UTF-8 bytes; received {bytes}"
                )
            }
            Self::InvalidPasswordUtf8 => write!(f, "the normalized password is not valid UTF-8"),
            Self::UnsupportedUnicodePassword => write!(
                f,
                "this first test-vector implementation accepts ASCII passwords only; \
                 Unicode 18 NPSS-NFKD is not silently approximated"
            ),
            Self::PasswordNotSet => write!(f, "no password is loaded for this operation"),
            Self::FixedPoint => write!(
                f,
                "the encrypted state equals the source state; use a different password or PIM"
            ),
            Self::RecoveryVerifierMismatch => write!(
                f,
                "recovery verifier mismatch: password, PIM, source length, or container is wrong"
            ),
            Self::AmbiguousSourceWords(matches) => write!(
                f,
                "ambiguous source length: recovery verifier matches {} words",
                format_word_counts(matches)
            ),
            Self::Argon2(message) => write!(f, "Argon2id failure: {message}"),
            Self::MemoryAllocation => {
                write!(f, "unable to allocate the 512 MiB Argon2id work area")
            }
            Self::Internal(message) => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for MhfeError {}

impl MhfeError {
    /// Stable machine-readable error code for native and browser adapters.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidMnemonic(_) => "INVALID_MNEMONIC",
            Self::InvalidContainer(_) => "INVALID_CONTAINER",
            Self::InvalidSourceWords(_) => "INVALID_SOURCE_WORDS",
            Self::InvalidEntropyLength(_) => "INVALID_ENTROPY_LENGTH",
            Self::InvalidPim(_) => "INVALID_PIM",
            Self::EmptyPassword => "EMPTY_PASSWORD",
            Self::PasswordTooLong(_) => "PASSWORD_TOO_LONG",
            Self::InvalidPasswordUtf8 => "INVALID_PASSWORD_UTF8",
            Self::UnsupportedUnicodePassword => "UNSUPPORTED_UNICODE_PASSWORD",
            Self::PasswordNotSet => "PASSWORD_NOT_SET",
            Self::FixedPoint => "FIXED_POINT",
            Self::RecoveryVerifierMismatch => "RECOVERY_VERIFIER_MISMATCH",
            Self::AmbiguousSourceWords(_) => "AMBIGUOUS_SOURCE_WORDS",
            Self::Argon2(_) => "ARGON2_FAILURE",
            Self::MemoryAllocation => "MEMORY_ALLOCATION_FAILURE",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct NormalizedPassword(Vec<u8>);

impl NormalizedPassword {
    /// Normalize a password for the initial vector implementation.
    ///
    /// ASCII is unchanged by NFKD and all ASCII scalar values are assigned in
    /// Unicode 18, so this subset is exact. Non-ASCII input is rejected until
    /// a pinned Unicode 18 NPSS implementation is included.
    pub fn from_test_ascii(value: &str) -> Result<Self, MhfeError> {
        if !value.is_ascii() {
            return Err(MhfeError::UnsupportedUnicodePassword);
        }
        Self::from_npss_nfkd_utf8(value.as_bytes())
    }

    /// Construct from bytes already normalized exactly according to the
    /// specification's pinned Unicode 18 NPSS-NFKD procedure.
    ///
    /// This method validates UTF-8 and protocol length only. It intentionally
    /// cannot prove that the caller performed the required normalization.
    pub fn from_npss_nfkd_utf8(value: &[u8]) -> Result<Self, MhfeError> {
        Self::from_npss_nfkd_utf8_owned(value.to_vec())
    }

    /// Construct from an owned buffer and retain it without another secret copy.
    pub fn from_npss_nfkd_utf8_owned(mut value: Vec<u8>) -> Result<Self, MhfeError> {
        let error = if std::str::from_utf8(&value).is_err() {
            Some(MhfeError::InvalidPasswordUtf8)
        } else if value.is_empty() {
            Some(MhfeError::EmptyPassword)
        } else if value.len() > 1024 {
            Some(MhfeError::PasswordTooLong(value.len()))
        } else {
            None
        };
        if let Some(error) = error {
            value.zeroize();
            return Err(error);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuiteParameters {
    pub api_version: u32,
    pub suite_id: &'static str,
    pub round_count: u32,
    pub memory_kib: u32,
    pub base_passes: u32,
    pub lanes: u32,
    pub max_pim: u32,
    pub supported_source_words: [usize; 5],
    pub password_normalization: &'static str,
}

/// Return the complete public parameter set required by an API consumer.
pub const fn suite_parameters() -> SuiteParameters {
    SuiteParameters {
        api_version: API_VERSION,
        suite_id: SUITE_ID,
        round_count: ROUND_COUNT,
        memory_kib: MEMORY_KIB,
        base_passes: BASE_PASSES,
        lanes: LANES,
        max_pim: MAX_PIM,
        supported_source_words: [12, 15, 18, 21, 24],
        password_normalization: "Unicode 18.0.0 NPSS-NFKD UTF-8; ASCII helper is exact; non-ASCII must be pre-normalized by a conforming caller",
    }
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct RoundTrace {
    pub round: u32,
    pub input_left_hex: String,
    pub input_right_hex: String,
    pub salt_hex: String,
    pub argon2_key_hex: String,
    pub mask_hex: String,
    pub output_left_hex: String,
    pub output_right_hex: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct PermutationTrace {
    pub direction: String,
    pub input_state_hex: String,
    pub output_state_hex: String,
    pub rounds: Vec<RoundTrace>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct EncryptionResult {
    pub suite_id: String,
    pub pim: u32,
    pub effective_passes: u32,
    pub source_words: usize,
    pub encrypted_mnemonic: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct DecryptionResult {
    pub suite_id: String,
    pub pim: u32,
    pub effective_passes: u32,
    pub source_words: usize,
    pub recovered_mnemonic: String,
    pub recovery_verified: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct VectorEncryptionResult {
    pub suite_id: String,
    pub pim: u32,
    pub effective_passes: u32,
    pub source_words: usize,
    pub source_entropy_hex: String,
    pub recovery_verifier_hex: String,
    pub packed_plaintext_hex: String,
    pub encrypted_entropy_hex: String,
    pub encrypted_mnemonic: String,
    pub trace: PermutationTrace,
}

#[derive(Debug, Serialize, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct VectorDecryptionResult {
    pub suite_id: String,
    pub pim: u32,
    pub effective_passes: u32,
    pub source_words: usize,
    pub encrypted_entropy_hex: String,
    pub packed_plaintext_hex: String,
    pub recovered_entropy_hex: String,
    pub recovered_mnemonic: String,
    pub recovery_verified: bool,
    pub trace: PermutationTrace,
}

/// Reusable MHFE engine. Its 512 MiB Argon2 work area is allocated once and
/// reused by every round and operation.
pub struct MhfeEngine {
    pim: u32,
    effective_passes: u32,
    argon2: Argon2<'static>,
    memory: Vec<Block>,
}

impl MhfeEngine {
    pub fn new(pim: u32) -> Result<Self, MhfeError> {
        if pim > MAX_PIM {
            return Err(MhfeError::InvalidPim(pim));
        }
        let effective_passes = BASE_PASSES
            .checked_mul(pim + 1)
            .ok_or(MhfeError::InvalidPim(pim))?;
        let params = Params::new(MEMORY_KIB, effective_passes, LANES, Some(32))
            .map_err(|error| MhfeError::Argon2(error.to_string()))?;
        let block_count = params.block_count();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(block_count)
            .map_err(|_| MhfeError::MemoryAllocation)?;
        memory.resize(block_count, Block::default());
        Ok(Self {
            pim,
            effective_passes,
            argon2,
            memory,
        })
    }

    #[cfg(test)]
    fn new_reduced_for_test() -> Result<Self, MhfeError> {
        let effective_passes = 1;
        let params = Params::new(1_024, effective_passes, 1, Some(32))
            .map_err(|error| MhfeError::Argon2(error.to_string()))?;
        let block_count = params.block_count();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(block_count)
            .map_err(|_| MhfeError::MemoryAllocation)?;
        memory.resize(block_count, Block::default());
        Ok(Self {
            pim: 0,
            effective_passes,
            argon2,
            memory,
        })
    }

    pub fn pim(&self) -> u32 {
        self.pim
    }

    pub fn effective_passes(&self) -> u32 {
        self.effective_passes
    }

    pub fn encrypt_mnemonic(
        &mut self,
        mnemonic: &str,
        password: &NormalizedPassword,
    ) -> Result<EncryptionResult, MhfeError> {
        let source = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|error| MhfeError::InvalidMnemonic(error.to_string()))?;
        let source_words = source.word_count();
        validate_source_words(source_words)?;
        let entropy = Zeroizing::new(source.to_entropy());
        let (mut packed_value, mut verifier) = pack_entropy(&entropy)?;
        verifier.zeroize();
        let packed = Zeroizing::new(packed_value);
        packed_value.zeroize();
        let (encrypted, _) = self.permute_forward(*packed, password, false)?;
        reject_fixed_point(&packed, &encrypted)?;
        let encrypted_mnemonic = Mnemonic::from_entropy_in(Language::English, &encrypted)
            .map_err(|error| MhfeError::Internal(error.to_string()))?
            .to_string();

        Ok(EncryptionResult {
            suite_id: SUITE_ID.to_owned(),
            pim: self.pim,
            effective_passes: self.effective_passes,
            source_words,
            encrypted_mnemonic,
        })
    }

    /// Generate detailed public test-vector material. Never use this method
    /// with a real recovery phrase or password.
    pub fn encrypt_vector(
        &mut self,
        mnemonic: &str,
        password: &NormalizedPassword,
    ) -> Result<VectorEncryptionResult, MhfeError> {
        let source = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|error| MhfeError::InvalidMnemonic(error.to_string()))?;
        let source_words = source.word_count();
        validate_source_words(source_words)?;
        let entropy = Zeroizing::new(source.to_entropy());
        let (mut packed_value, verifier_value) = pack_entropy(&entropy)?;
        let packed = Zeroizing::new(packed_value);
        packed_value.zeroize();
        let verifier = Zeroizing::new(verifier_value);
        let (encrypted, trace) = self.permute_forward(*packed, password, true)?;
        reject_fixed_point(&packed, &encrypted)?;
        let encrypted_mnemonic = Mnemonic::from_entropy_in(Language::English, &encrypted)
            .map_err(|error| MhfeError::Internal(error.to_string()))?
            .to_string();

        Ok(VectorEncryptionResult {
            suite_id: SUITE_ID.to_owned(),
            pim: self.pim,
            effective_passes: self.effective_passes,
            source_words,
            source_entropy_hex: hex::encode(&*entropy),
            recovery_verifier_hex: hex::encode(&*verifier),
            packed_plaintext_hex: hex::encode(*packed),
            encrypted_entropy_hex: hex::encode(encrypted),
            encrypted_mnemonic,
            trace: trace.ok_or_else(|| MhfeError::Internal("missing vector trace".to_owned()))?,
        })
    }

    pub fn decrypt_mnemonic(
        &mut self,
        encrypted_mnemonic: &str,
        source_words: usize,
        password: &NormalizedPassword,
    ) -> Result<DecryptionResult, MhfeError> {
        validate_source_words(source_words)?;
        let container = Mnemonic::parse_in(Language::English, encrypted_mnemonic)
            .map_err(|error| MhfeError::InvalidContainer(error.to_string()))?;
        if container.word_count() != 24 {
            return Err(MhfeError::InvalidContainer(format!(
                "container must contain 24 words; received {}",
                container.word_count()
            )));
        }
        let encrypted_entropy = Zeroizing::new(container.to_entropy());
        let encrypted: [u8; 32] = encrypted_entropy
            .as_slice()
            .try_into()
            .map_err(|_| MhfeError::Internal("24-word entropy was not 32 bytes".to_owned()))?;
        let (mut packed_value, _) = self.permute_inverse(encrypted, password, false)?;
        let packed = Zeroizing::new(packed_value);
        packed_value.zeroize();
        let entropy = Zeroizing::new(unpack_entropy(&packed, source_words)?);
        let recovered_mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|error| MhfeError::Internal(error.to_string()))?
            .to_string();

        Ok(DecryptionResult {
            suite_id: SUITE_ID.to_owned(),
            pim: self.pim,
            effective_passes: self.effective_passes,
            source_words,
            recovered_mnemonic,
            recovery_verified: source_words < 24,
        })
    }

    /// Recover a mnemonic while detecting a short source length from its
    /// encrypted recovery verifier. All four short layouts are tested. If
    /// none matches, the result is interpreted as a 24-word source; if more
    /// than one matches, every matching length is returned in the error.
    pub fn decrypt_mnemonic_auto(
        &mut self,
        encrypted_mnemonic: &str,
        password: &NormalizedPassword,
    ) -> Result<DecryptionResult, MhfeError> {
        let container = Mnemonic::parse_in(Language::English, encrypted_mnemonic)
            .map_err(|error| MhfeError::InvalidContainer(error.to_string()))?;
        if container.word_count() != 24 {
            return Err(MhfeError::InvalidContainer(format!(
                "container must contain 24 words; received {}",
                container.word_count()
            )));
        }
        let encrypted_entropy = Zeroizing::new(container.to_entropy());
        let encrypted: [u8; 32] = encrypted_entropy
            .as_slice()
            .try_into()
            .map_err(|_| MhfeError::Internal("24-word entropy was not 32 bytes".to_owned()))?;
        let (mut packed_value, _) = self.permute_inverse(encrypted, password, false)?;
        let packed = Zeroizing::new(packed_value);
        packed_value.zeroize();
        let source_words = detect_source_words(&packed)?;
        let entropy = Zeroizing::new(unpack_entropy(&packed, source_words)?);
        let recovered_mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|error| MhfeError::Internal(error.to_string()))?
            .to_string();

        Ok(DecryptionResult {
            suite_id: SUITE_ID.to_owned(),
            pim: self.pim,
            effective_passes: self.effective_passes,
            source_words,
            recovered_mnemonic,
            recovery_verified: source_words < 24,
        })
    }

    /// Generate detailed public recovery-vector material. Never use this
    /// method with a real recovery phrase or password.
    pub fn decrypt_vector(
        &mut self,
        encrypted_mnemonic: &str,
        source_words: usize,
        password: &NormalizedPassword,
    ) -> Result<VectorDecryptionResult, MhfeError> {
        validate_source_words(source_words)?;
        let container = Mnemonic::parse_in(Language::English, encrypted_mnemonic)
            .map_err(|error| MhfeError::InvalidContainer(error.to_string()))?;
        if container.word_count() != 24 {
            return Err(MhfeError::InvalidContainer(format!(
                "container must contain 24 words; received {}",
                container.word_count()
            )));
        }
        let encrypted_entropy = Zeroizing::new(container.to_entropy());
        let encrypted: [u8; 32] = encrypted_entropy
            .as_slice()
            .try_into()
            .map_err(|_| MhfeError::Internal("24-word entropy was not 32 bytes".to_owned()))?;
        let (mut packed_value, trace) = self.permute_inverse(encrypted, password, true)?;
        let packed = Zeroizing::new(packed_value);
        packed_value.zeroize();
        let entropy = Zeroizing::new(unpack_entropy(&packed, source_words)?);
        let recovered_mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|error| MhfeError::Internal(error.to_string()))?
            .to_string();

        Ok(VectorDecryptionResult {
            suite_id: SUITE_ID.to_owned(),
            pim: self.pim,
            effective_passes: self.effective_passes,
            source_words,
            encrypted_entropy_hex: hex::encode(encrypted),
            packed_plaintext_hex: hex::encode(*packed),
            recovered_entropy_hex: hex::encode(&*entropy),
            recovered_mnemonic,
            recovery_verified: source_words < 24,
            trace: trace.ok_or_else(|| MhfeError::Internal("missing vector trace".to_owned()))?,
        })
    }

    fn permute_forward(
        &mut self,
        mut input: [u8; 32],
        password: &NormalizedPassword,
        include_trace: bool,
    ) -> Result<([u8; 32], Option<PermutationTrace>), MhfeError> {
        let mut left: [u8; 16] = input[..16].try_into().expect("fixed slice length");
        let mut right: [u8; 16] = input[16..].try_into().expect("fixed slice length");
        let mut rounds = Vec::with_capacity(ROUND_COUNT as usize);

        for round in 0..ROUND_COUNT {
            let mut input_left = left;
            let mut input_right = right;
            let (mut salt, mut key, mut mask) = match self.round_material(password, round, &right) {
                Ok(material) => material,
                Err(error) => {
                    self.memory.iter_mut().zeroize();
                    input.zeroize();
                    left.zeroize();
                    right.zeroize();
                    return Err(error);
                }
            };
            let output_left = right;
            let output_right = xor16(&left, &mask);
            left = output_left;
            right = output_right;
            if include_trace {
                rounds.push(trace_round(
                    round,
                    input_left,
                    input_right,
                    salt,
                    key,
                    mask,
                    left,
                    right,
                ));
            }
            input_left.zeroize();
            input_right.zeroize();
            salt.zeroize();
            key.zeroize();
            mask.zeroize();
        }

        let output = join_state(left, right);
        let trace = include_trace.then(|| PermutationTrace {
            direction: "encrypt".to_owned(),
            input_state_hex: hex::encode(input),
            output_state_hex: hex::encode(output),
            rounds,
        });
        self.memory.iter_mut().zeroize();
        input.zeroize();
        left.zeroize();
        right.zeroize();
        Ok((output, trace))
    }

    fn permute_inverse(
        &mut self,
        mut input: [u8; 32],
        password: &NormalizedPassword,
        include_trace: bool,
    ) -> Result<([u8; 32], Option<PermutationTrace>), MhfeError> {
        let mut left_next: [u8; 16] = input[..16].try_into().expect("fixed slice length");
        let mut right_next: [u8; 16] = input[16..].try_into().expect("fixed slice length");
        let mut rounds = Vec::with_capacity(ROUND_COUNT as usize);

        for round in (0..ROUND_COUNT).rev() {
            let mut input_left = left_next;
            let mut input_right = right_next;
            let right = left_next;
            let (mut salt, mut key, mut mask) = match self.round_material(password, round, &right) {
                Ok(material) => material,
                Err(error) => {
                    self.memory.iter_mut().zeroize();
                    input.zeroize();
                    left_next.zeroize();
                    right_next.zeroize();
                    return Err(error);
                }
            };
            let left = xor16(&right_next, &mask);
            if include_trace {
                rounds.push(trace_round(
                    round,
                    input_left,
                    input_right,
                    salt,
                    key,
                    mask,
                    left,
                    right,
                ));
            }
            input_left.zeroize();
            input_right.zeroize();
            salt.zeroize();
            left_next = left;
            right_next = right;
            key.zeroize();
            mask.zeroize();
        }

        let output = join_state(left_next, right_next);
        let trace = include_trace.then(|| PermutationTrace {
            direction: "decrypt".to_owned(),
            input_state_hex: hex::encode(input),
            output_state_hex: hex::encode(output),
            rounds,
        });
        self.memory.iter_mut().zeroize();
        input.zeroize();
        left_next.zeroize();
        right_next.zeroize();
        Ok((output, trace))
    }

    fn round_material(
        &mut self,
        password: &NormalizedPassword,
        round: u32,
        right: &[u8; 16],
    ) -> Result<RoundMaterial, MhfeError> {
        let pim_bytes = self.pim.to_be_bytes();
        let round_bytes = round.to_be_bytes();

        let mut salt_input = Vec::with_capacity(SUITE_ID.len() + DS_SALT_SUFFIX.len() + 24);
        salt_input.extend_from_slice(SUITE_ID.as_bytes());
        salt_input.extend_from_slice(DS_SALT_SUFFIX);
        salt_input.extend_from_slice(&pim_bytes);
        salt_input.extend_from_slice(&round_bytes);
        salt_input.extend_from_slice(right);
        let mut salt_digest = Blake2b256::digest(&salt_input);
        let salt: [u8; 16] = salt_digest[..16].try_into().expect("digest prefix length");
        salt_digest.zeroize();
        salt_input.zeroize();

        let mut key = [0u8; 32];
        self.argon2
            .hash_password_into_with_memory(password.as_bytes(), &salt, &mut key, &mut self.memory)
            .map_err(|error| MhfeError::Argon2(error.to_string()))?;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
            .map_err(|error| MhfeError::Internal(error.to_string()))?;
        mac.update(SUITE_ID.as_bytes());
        mac.update(DS_MASK_SUFFIX);
        mac.update(&pim_bytes);
        mac.update(&round_bytes);
        mac.update(right);
        let mut mask_digest = mac.finalize().into_bytes();
        let mask: [u8; 16] = mask_digest[..16].try_into().expect("HMAC prefix length");
        mask_digest.zeroize();
        Ok((salt, key, mask))
    }
}

impl Drop for MhfeEngine {
    fn drop(&mut self) {
        self.memory.zeroize();
    }
}

pub fn pack_entropy(entropy: &[u8]) -> Result<([u8; 32], Vec<u8>), MhfeError> {
    if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
        return Err(MhfeError::InvalidEntropyLength(entropy.len()));
    }
    let mut packed = [0u8; 32];
    packed[..entropy.len()].copy_from_slice(entropy);
    let verifier_len = 32 - entropy.len();
    let verifier = if verifier_len == 0 {
        Vec::new()
    } else {
        let digest = Sha256::digest(entropy);
        let value = digest[..verifier_len].to_vec();
        packed[entropy.len()..].copy_from_slice(&value);
        value
    };
    Ok((packed, verifier))
}

pub fn unpack_entropy(packed: &[u8; 32], source_words: usize) -> Result<Vec<u8>, MhfeError> {
    let entropy_len = entropy_bytes_for_words(source_words)?;
    let entropy = packed[..entropy_len].to_vec();
    let verifier_len = 32 - entropy_len;
    if verifier_len > 0 {
        let digest = Sha256::digest(&entropy);
        if packed[entropy_len..] != digest[..verifier_len] {
            return Err(MhfeError::RecoveryVerifierMismatch);
        }
    }
    Ok(entropy)
}

/// Detect the source length by testing every short-source verifier layout.
/// No match falls back to 24 words; multiple matches are always ambiguous.
pub fn detect_source_words(packed: &[u8; 32]) -> Result<usize, MhfeError> {
    detect_source_words_with(|words| unpack_entropy(packed, words).is_ok())
}

fn detect_source_words_with(
    mut matches_layout: impl FnMut(usize) -> bool,
) -> Result<usize, MhfeError> {
    let mut matches = Vec::with_capacity(4);
    for words in [12, 15, 18, 21] {
        if matches_layout(words) {
            matches.push(words);
        }
    }
    match matches.as_slice() {
        [] => Ok(24),
        [words] => Ok(*words),
        _ => Err(MhfeError::AmbiguousSourceWords(matches)),
    }
}

fn format_word_counts(words: &[usize]) -> String {
    words
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn entropy_bytes_for_words(words: usize) -> Result<usize, MhfeError> {
    match words {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        _ => Err(MhfeError::InvalidSourceWords(words)),
    }
}

fn validate_source_words(words: usize) -> Result<(), MhfeError> {
    entropy_bytes_for_words(words).map(|_| ())
}

fn reject_fixed_point(input: &[u8; 32], output: &[u8; 32]) -> Result<(), MhfeError> {
    if input == output {
        Err(MhfeError::FixedPoint)
    } else {
        Ok(())
    }
}

fn xor16(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] = left[index] ^ right[index];
    }
    output
}

fn join_state(left: [u8; 16], right: [u8; 16]) -> [u8; 32] {
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&left);
    output[16..].copy_from_slice(&right);
    output
}

#[allow(clippy::too_many_arguments)]
fn trace_round(
    round: u32,
    mut input_left: [u8; 16],
    mut input_right: [u8; 16],
    mut salt: [u8; 16],
    mut key: [u8; 32],
    mut mask: [u8; 16],
    mut output_left: [u8; 16],
    mut output_right: [u8; 16],
) -> RoundTrace {
    let trace = RoundTrace {
        round,
        input_left_hex: hex::encode(input_left),
        input_right_hex: hex::encode(input_right),
        salt_hex: hex::encode(salt),
        argon2_key_hex: hex::encode(key),
        mask_hex: hex::encode(mask),
        output_left_hex: hex::encode(output_left),
        output_right_hex: hex::encode(output_right),
    };
    input_left.zeroize();
    input_right.zeroize();
    salt.zeroize();
    key.zeroize();
    mask.zeroize();
    output_left.zeroize();
    output_right.zeroize();
    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip39_zero_vector_round_trips() {
        let mnemonic = Mnemonic::parse_in(Language::English, ZERO_12).unwrap();
        assert_eq!(mnemonic.to_entropy(), vec![0u8; 16]);
        assert_eq!(
            Mnemonic::from_entropy_in(Language::English, &[0u8; 16])
                .unwrap()
                .to_string(),
            ZERO_12
        );
    }

    #[test]
    fn universal_packing_uses_sha256_prefix() {
        let entropy = [0u8; 16];
        let (packed, verifier) = pack_entropy(&entropy).unwrap();
        let digest = Sha256::digest(entropy);
        assert_eq!(&packed[..16], &entropy);
        assert_eq!(&packed[16..], &digest[..16]);
        assert_eq!(verifier, digest[..16]);
        assert_eq!(unpack_entropy(&packed, 12).unwrap(), entropy);
    }

    #[test]
    fn verifier_serialization_is_leftmost_msb_first_and_host_independent() {
        let entropy: Vec<u8> = (0u8..28).collect();
        let (packed, verifier) = pack_entropy(&entropy).unwrap();

        // Literal cross-platform micro-vector. SHA256(000102...1b) begins
        // dc27f8e8..., so V32 is those four bytes in digest-output order. It
        // must never be interpreted through host-native integer endianness.
        assert_eq!(verifier, [0xdc, 0x27, 0xf8, 0xe8]);
        assert_eq!(&packed[..28], entropy.as_slice());
        assert_eq!(&packed[28..], &[0xdc, 0x27, 0xf8, 0xe8]);

        // A 21-word BIP39 mnemonic appends CS7(E). In the last 11-bit word,
        // the low seven bits are exactly the seven most-significant bits of
        // the first SHA-256 byte: 0xdc >> 1 = 0x6e.
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
        let last_word_index = mnemonic.word_indices().last().unwrap();
        assert_eq!(last_word_index & 0x7f, 0x6e);
        assert_eq!(verifier[0] >> 1, 0x6e);
        assert_eq!(unpack_entropy(&packed, 21).unwrap(), entropy);
    }

    #[test]
    fn packing_rejects_invalid_entropy_length_precisely() {
        assert_eq!(
            pack_entropy(&[0u8; 17]).unwrap_err(),
            MhfeError::InvalidEntropyLength(17)
        );
    }

    #[test]
    fn twenty_one_word_verifier_rejects_extended_hash_bit_corruption() {
        let entropy = [7u8; 28];
        let (packed, verifier) = pack_entropy(&entropy).unwrap();
        assert_eq!(verifier.len(), 4);
        assert_eq!(unpack_entropy(&packed, 21).unwrap(), entropy);

        // A 21-word source stores V32 = first_32_bits(SHA256(E)). Its first
        // seven bits are the ordinary BIP39 checksum; the remaining 25 bits
        // provide additional recovery verification. Flip the first and last
        // of those additional bits independently, then together.
        for corrupted in [
            {
                let mut value = packed;
                value[28] ^= 0x01; // V32[7], immediately after CS7(E).
                value
            },
            {
                let mut value = packed;
                value[31] ^= 0x01; // V32[31], the last verifier bit.
                value
            },
            {
                let mut value = packed;
                value[28] ^= 0x01;
                value[31] ^= 0x01;
                value
            },
        ] {
            assert_eq!(
                unpack_entropy(&corrupted, 21).unwrap_err(),
                MhfeError::RecoveryVerifierMismatch
            );
        }
    }

    #[test]
    fn twenty_one_word_verifier_rejects_checksum_prefix_corruption() {
        let (mut packed, _) = pack_entropy(&[7u8; 28]).unwrap();
        packed[28] ^= 0x80; // V32[0], also the first BIP39 checksum bit.
        assert_eq!(
            unpack_entropy(&packed, 21).unwrap_err(),
            MhfeError::RecoveryVerifierMismatch
        );
    }

    #[test]
    fn automatic_detection_checks_every_short_layout_and_reports_all_matches() {
        for expected in [vec![12, 15], vec![12, 18, 21], vec![12, 15, 18, 21]] {
            let mut visited = Vec::new();
            let error = detect_source_words_with(|words| {
                visited.push(words);
                expected.contains(&words)
            })
            .unwrap_err();

            assert_eq!(visited, vec![12, 15, 18, 21]);
            assert_eq!(error, MhfeError::AmbiguousSourceWords(expected.clone()));
            let rendered = error.to_string();
            for words in expected {
                assert!(rendered.contains(&words.to_string()));
            }
        }
    }

    #[test]
    fn automatic_detection_uses_unique_match_or_twenty_four_word_fallback() {
        assert_eq!(detect_source_words_with(|_| false).unwrap(), 24);
        assert_eq!(detect_source_words_with(|words| words == 18).unwrap(), 18);
    }

    #[test]
    fn machine_readable_validation_cases_match_the_api() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/validation-cases.json")).unwrap();

        for case in fixture["pre_normalized_passwords"].as_array().unwrap() {
            let bytes = hex::decode(case["npss_nfkd_utf8_hex"].as_str().unwrap()).unwrap();
            let password = NormalizedPassword::from_npss_nfkd_utf8(&bytes).unwrap();
            assert_eq!(password.as_bytes(), bytes);
        }

        for case in fixture["boundaries"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            match id {
                "empty-normalized-password"
                | "maximum-normalized-password"
                | "oversized-normalized-password" => {
                    let byte =
                        u8::from_str_radix(case["repeat_byte_hex"].as_str().unwrap(), 16).unwrap();
                    let input = vec![byte; case["count"].as_u64().unwrap() as usize];
                    let result = NormalizedPassword::from_npss_nfkd_utf8(&input);
                    if let Some(code) = case["expected_error_code"].as_str() {
                        let error = match result {
                            Ok(_) => panic!("invalid password fixture was accepted: {id}"),
                            Err(error) => error,
                        };
                        assert_eq!(error.code(), code);
                    } else {
                        assert_eq!(result.unwrap().as_bytes(), input);
                    }
                }
                "pim-above-suite-maximum" => {
                    let error = match MhfeEngine::new(case["pim"].as_u64().unwrap() as u32) {
                        Ok(_) => panic!("invalid PIM was accepted"),
                        Err(error) => error,
                    };
                    assert_eq!(error.code(), case["expected_error_code"].as_str().unwrap());
                }
                "unsupported-source-word-count" => {
                    let error =
                        entropy_bytes_for_words(case["source_words"].as_u64().unwrap() as usize)
                            .unwrap_err();
                    assert_eq!(error.code(), case["expected_error_code"].as_str().unwrap());
                }
                _ => panic!("unknown validation fixture: {id}"),
            }
        }

        for case in fixture["automatic_detection_classifier"]
            .as_array()
            .unwrap()
        {
            let matches = case["matching_short_source_words"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as usize)
                .collect::<Vec<_>>();
            let result = detect_source_words_with(|words| matches.contains(&words));
            if let Some(expected) = case["expected_source_words"].as_u64() {
                assert_eq!(result.unwrap(), expected as usize);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code(), case["expected_error_code"].as_str().unwrap());
                assert_eq!(error, MhfeError::AmbiguousSourceWords(matches));
            }
        }
    }

    #[test]
    fn automatic_detection_recognizes_real_packed_states() {
        for (entropy_len, expected_words) in [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)] {
            let entropy = (0..entropy_len)
                .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
                .collect::<Vec<_>>();
            let (packed, _) = pack_entropy(&entropy).unwrap();
            assert_eq!(detect_source_words(&packed).unwrap(), expected_words);
        }
    }

    #[test]
    fn fixed_point_guard_rejects_equality() {
        let state = [7u8; 32];
        assert_eq!(
            reject_fixed_point(&state, &state),
            Err(MhfeError::FixedPoint)
        );
        let mut different = state;
        different[0] ^= 1;
        assert_eq!(reject_fixed_point(&state, &different), Ok(()));
    }

    #[test]
    fn reduced_engine_exercises_feistel_and_verifier_paths() {
        let password = NormalizedPassword::from_test_ascii("correct password").unwrap();
        let wrong_password = NormalizedPassword::from_test_ascii("wrong password").unwrap();
        let mut engine = MhfeEngine::new_reduced_for_test().unwrap();
        let encrypted = engine.encrypt_mnemonic(ZERO_12, &password).unwrap();
        let recovered = engine
            .decrypt_mnemonic_auto(&encrypted.encrypted_mnemonic, &password)
            .unwrap();
        assert_eq!(recovered.recovered_mnemonic, ZERO_12);
        assert!(recovered.recovery_verified);
        assert_eq!(
            engine
                .decrypt_mnemonic(&encrypted.encrypted_mnemonic, 12, &wrong_password)
                .unwrap_err(),
            MhfeError::RecoveryVerifierMismatch
        );
    }

    #[test]
    fn validates_test_password_subset_and_pim() {
        assert!(NormalizedPassword::from_test_ascii("public vector password").is_ok());
        assert!(matches!(
            NormalizedPassword::from_test_ascii(""),
            Err(MhfeError::EmptyPassword)
        ));
        assert!(matches!(
            NormalizedPassword::from_test_ascii("пароль"),
            Err(MhfeError::UnsupportedUnicodePassword)
        ));
        assert!(matches!(
            MhfeEngine::new(32),
            Err(MhfeError::InvalidPim(32))
        ));
    }

    #[test]
    fn validates_pre_normalized_password_bytes() {
        let one_byte = NormalizedPassword::from_npss_nfkd_utf8(b"a").unwrap();
        assert_eq!(one_byte.as_bytes(), b"a");
        assert!(matches!(
            NormalizedPassword::from_npss_nfkd_utf8(&[]),
            Err(MhfeError::EmptyPassword)
        ));
        let maximum = vec![b'a'; 1024];
        let accepted = NormalizedPassword::from_npss_nfkd_utf8(&maximum).unwrap();
        assert_eq!(accepted.as_bytes(), maximum.as_slice());
        assert_eq!(accepted.as_bytes().len(), 1024);
        assert!(matches!(
            NormalizedPassword::from_npss_nfkd_utf8(&vec![b'a'; 1025]),
            Err(MhfeError::PasswordTooLong(1025))
        ));
    }

    #[test]
    fn pre_normalized_unicode_is_preserved_without_extra_transformations() {
        for value in [
            "пароль",
            "🔐",
            " Пароль\t🔐\n ",
            "\0",
            "e\u{301}",
            "Case Sensitive",
            "case sensitive",
        ] {
            let password = NormalizedPassword::from_npss_nfkd_utf8(value.as_bytes()).unwrap();
            assert_eq!(password.as_bytes(), value.as_bytes());
        }

        let spaced = NormalizedPassword::from_npss_nfkd_utf8(b"  a\t\n  b  ").unwrap();
        assert_eq!(spaced.as_bytes(), b"  a\t\n  b  ");
        assert_ne!(spaced.as_bytes(), b"a b");

        let upper = NormalizedPassword::from_npss_nfkd_utf8(b"Password").unwrap();
        let lower = NormalizedPassword::from_npss_nfkd_utf8(b"password").unwrap();
        assert_ne!(upper.as_bytes(), lower.as_bytes());
    }

    #[test]
    fn rejects_multiple_classes_of_malformed_utf8() {
        for invalid in [
            &[0xff][..],                   // impossible leading byte
            &[0xc0, 0xaf][..],             // overlong encoding
            &[0xe2, 0x82][..],             // truncated sequence
            &[0xed, 0xa0, 0x80][..],       // encoded UTF-16 surrogate U+D800
            &[0xf4, 0x90, 0x80, 0x80][..], // above Unicode U+10FFFF
        ] {
            assert!(matches!(
                NormalizedPassword::from_npss_nfkd_utf8(invalid),
                Err(MhfeError::InvalidPasswordUtf8)
            ));
        }
    }

    #[test]
    fn password_length_limit_counts_utf8_bytes() {
        let within_limit = "я".repeat(512);
        assert_eq!(within_limit.len(), 1024);
        assert!(NormalizedPassword::from_npss_nfkd_utf8(within_limit.as_bytes()).is_ok());

        let over_limit = "я".repeat(513);
        assert_eq!(over_limit.len(), 1026);
        assert!(matches!(
            NormalizedPassword::from_npss_nfkd_utf8(over_limit.as_bytes()),
            Err(MhfeError::PasswordTooLong(1026))
        ));
    }

    #[test]
    fn suite_parameters_are_frozen() {
        assert_eq!(
            suite_parameters(),
            SuiteParameters {
                api_version: 1,
                suite_id: "MHFE-BIP39-256-EXPERIMENTAL-2",
                round_count: 12,
                memory_kib: 524_288,
                base_passes: 12,
                lanes: 4,
                max_pim: 31,
                supported_source_words: [12, 15, 18, 21, 24],
                password_normalization: "Unicode 18.0.0 NPSS-NFKD UTF-8; ASCII helper is exact; non-ASCII must be pre-normalized by a conforming caller",
            }
        );
    }
}
