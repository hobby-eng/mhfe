//! The 12-round balanced Feistel permutation of suite 3 (specification: "Permutation").
//!
//! ```text
//! S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//! K_i = Argon2id(P_enc, S_i)
//! M_i = Trunc_128(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//! ```

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::packing::{State, STATE_BYTES};
use crate::suite::{DS_MASK, DS_SALT, ROUNDS};
use crate::{MhfeError, Password, WorkFactor};

type Blake2b256 = Blake2b<U32>;
type HmacSha256 = Hmac<Sha256>;

pub const HALF_BYTES: usize = STATE_BYTES / 2;
type Half = [u8; HALF_BYTES];
/// The message of a round: three 32-bit numbers and the right half.
pub type RoundMessage = [u8; 12 + HALF_BYTES];

/// Called with the number (1 to 12) of each round before it starts. Returning an error, such as
/// [`MhfeError::Cancelled`], stops the permutation before that round.
pub(crate) type RoundCallback<'a> = &'a mut dyn FnMut(u32) -> Result<(), MhfeError>;

/// All values of one round, for test vectors. States are `L || R` before and after the round.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoundTrace {
    pub round: u32,
    pub state_before: State,
    /// `BE32(MEM) || BE32(PIM) || BE32(i) || R`, which follows DS_SALT in the salt input and
    /// DS_MASK in the mask message.
    pub message: RoundMessage,
    pub salt: [u8; SALT_BYTES],
    pub key: [u8; KEY_BYTES],
    pub mask: Half,
    pub state_after: State,
}

/// The permutation for one password and one work factor.
pub struct Permutation<'a> {
    pub engine: &'a mut dyn Argon2Engine,
    pub password: &'a Password,
    pub work: WorkFactor,
}

impl Permutation<'_> {
    /// `Y = Perm(X)`: rounds 0 to 11.
    pub fn forward(
        &mut self,
        x: &State,
        on_round: RoundCallback<'_>,
        mut trace: Option<&mut Vec<RoundTrace>>,
    ) -> Result<Zeroizing<State>, MhfeError> {
        let (mut left, mut right) = split(x);
        for round in 0..ROUNDS {
            on_round(round + 1)?;
            let values = self.round_values(round, &right)?;
            let before = join(&left, &right);
            // L_{i+1} = R_i and R_{i+1} = L_i XOR M_i.
            let next_right = xor(&left, &values.mask);
            *left = *right;
            *right = *next_right;
            if let Some(trace) = trace.as_deref_mut() {
                trace.push(values.into_trace(round, &before, &join(&left, &right)));
            }
        }
        Ok(join(&left, &right))
    }

    /// `X = Perm^-1(Y)`: rounds 11 down to 0. The callback still counts from 1 to 12.
    pub fn inverse(
        &mut self,
        y: &State,
        on_round: RoundCallback<'_>,
        mut trace: Option<&mut Vec<RoundTrace>>,
    ) -> Result<Zeroizing<State>, MhfeError> {
        let (mut left, mut right) = split(y);
        for (step, round) in (0..ROUNDS).rev().enumerate() {
            on_round(step as u32 + 1)?;
            // R_i = L_{i+1}, so the mask comes from the current left half;
            // then L_i = R_{i+1} XOR M_i.
            let values = self.round_values(round, &left)?;
            let before = join(&left, &right);
            let previous_left = xor(&right, &values.mask);
            *right = *left;
            *left = *previous_left;
            if let Some(trace) = trace.as_deref_mut() {
                trace.push(values.into_trace(round, &before, &join(&left, &right)));
            }
        }
        Ok(join(&left, &right))
    }

    /// `RoundMask(i, R)` together with the salt and key it passes through.
    fn round_values(&mut self, round: u32, right: &Half) -> Result<RoundValues, MhfeError> {
        let mut values = RoundValues {
            message: round_message(self.work, round, right),
            salt: round_salt(self.work, round, right),
            key: [0u8; KEY_BYTES],
            mask: [0u8; HALF_BYTES],
        };
        self.engine
            .derive(self.password.as_bytes(), &values.salt, &mut values.key)?;
        values.mask = round_mask(&values.key, self.work, round, right);
        Ok(values)
    }
}

/// Message, salt, Argon2id key and mask of one round; wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RoundValues {
    message: RoundMessage,
    salt: [u8; SALT_BYTES],
    key: [u8; KEY_BYTES],
    mask: Half,
}

impl RoundValues {
    fn into_trace(self, round: u32, before: &State, after: &State) -> RoundTrace {
        RoundTrace {
            round,
            state_before: *before,
            message: self.message,
            salt: self.salt,
            key: self.key,
            mask: self.mask,
            state_after: *after,
        }
    }
}

/// The message shared by salt and mask: `BE32(MEM) || BE32(PIM) || BE32(i) || R`.
fn round_message(work: WorkFactor, round: u32, right: &Half) -> RoundMessage {
    let mut message = [0u8; 12 + HALF_BYTES];
    message[0..4].copy_from_slice(&work.memory_level().to_be_bytes());
    message[4..8].copy_from_slice(&work.pim().to_be_bytes());
    message[8..12].copy_from_slice(&round.to_be_bytes());
    message[12..].copy_from_slice(right);
    message
}

/// `S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R))`.
fn round_salt(work: WorkFactor, round: u32, right: &Half) -> [u8; SALT_BYTES] {
    let mut message = round_message(work, round, right);
    let mut digest = Blake2b256::new()
        .chain_update(DS_SALT)
        .chain_update(message)
        .finalize();
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&digest[..SALT_BYTES]);
    digest.zeroize();
    message.zeroize();
    salt
}

/// `M_i = Trunc_128(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R))`.
fn round_mask(key: &[u8; KEY_BYTES], work: WorkFactor, round: u32, right: &Half) -> Half {
    let mut message = round_message(work, round, right);
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(DS_MASK);
    mac.update(&message);
    let mut digest = mac.finalize().into_bytes();
    let mut mask = [0u8; HALF_BYTES];
    mask.copy_from_slice(&digest[..HALF_BYTES]);
    digest.zeroize();
    message.zeroize();
    mask
}

fn split(state: &State) -> (Zeroizing<Half>, Zeroizing<Half>) {
    let mut left = Zeroizing::new([0u8; HALF_BYTES]);
    let mut right = Zeroizing::new([0u8; HALF_BYTES]);
    left.copy_from_slice(&state[..HALF_BYTES]);
    right.copy_from_slice(&state[HALF_BYTES..]);
    (left, right)
}

fn join(left: &Half, right: &Half) -> Zeroizing<State> {
    let mut state = Zeroizing::new([0u8; STATE_BYTES]);
    state[..HALF_BYTES].copy_from_slice(left);
    state[HALF_BYTES..].copy_from_slice(right);
    state
}

fn xor(a: &Half, b: &Half) -> Zeroizing<Half> {
    let mut result = Zeroizing::new([0u8; HALF_BYTES]);
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = a[index] ^ b[index];
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A stand-in for Argon2 in structural tests: a key that depends on password and salt.
    pub(crate) struct HashEngine;

    impl Argon2Engine for HashEngine {
        fn derive(
            &mut self,
            password: &[u8],
            salt: &[u8; SALT_BYTES],
            key: &mut [u8; KEY_BYTES],
        ) -> Result<(), MhfeError> {
            // sha2 implements an older `Digest` trait than blake2, so name it explicitly.
            let digest = <Sha256 as sha2::Digest>::digest([password, &salt[..]].concat());
            key.copy_from_slice(&digest);
            Ok(())
        }
    }

    fn permutation<'a>(engine: &'a mut HashEngine, password: &'a Password) -> Permutation<'a> {
        Permutation {
            engine,
            password,
            work: WorkFactor::default(),
        }
    }

    #[test]
    fn inverse_undoes_forward() {
        let password = Password::new("public test password").unwrap();
        let mut engine = HashEngine;
        let x: State = std::array::from_fn(|index| index as u8);
        let y = permutation(&mut engine, &password)
            .forward(&x, &mut |_| Ok(()), None)
            .unwrap();
        assert_ne!(*y, x);
        let back = permutation(&mut engine, &password)
            .inverse(&y, &mut |_| Ok(()), None)
            .unwrap();
        assert_eq!(*back, x);
    }

    #[test]
    fn traces_record_every_round_in_both_directions() {
        let password = Password::new("public test password").unwrap();
        let mut engine = HashEngine;
        let x: State = std::array::from_fn(|index| 255 - index as u8);
        let mut forward_trace = Vec::new();
        let y = permutation(&mut engine, &password)
            .forward(&x, &mut |_| Ok(()), Some(&mut forward_trace))
            .unwrap();
        let mut inverse_trace = Vec::new();
        permutation(&mut engine, &password)
            .inverse(&y, &mut |_| Ok(()), Some(&mut inverse_trace))
            .unwrap();

        assert_eq!(forward_trace.len(), 12);
        assert_eq!(forward_trace[0].state_before, x);
        assert_eq!(forward_trace[11].state_after, *y);
        for (index, round) in forward_trace.iter().enumerate() {
            assert_eq!(round.round, index as u32);
            if index > 0 {
                assert_eq!(round.state_before, forward_trace[index - 1].state_after);
            }
        }
        // The inverse runs the same rounds backwards with the same salts, keys and masks.
        for (inverse_round, forward_round) in inverse_trace.iter().zip(forward_trace.iter().rev()) {
            assert_eq!(inverse_round.round, forward_round.round);
            assert_eq!(inverse_round.salt, forward_round.salt);
            assert_eq!(inverse_round.key, forward_round.key);
            assert_eq!(inverse_round.mask, forward_round.mask);
            assert_eq!(inverse_round.state_before, forward_round.state_after);
            assert_eq!(inverse_round.state_after, forward_round.state_before);
        }
    }

    #[test]
    fn the_callback_counts_rounds_and_can_stop_before_one() {
        let password = Password::new("public test password").unwrap();
        let mut engine = HashEngine;
        let mut seen = Vec::new();
        let result = permutation(&mut engine, &password).forward(
            &[7u8; STATE_BYTES],
            &mut |round| {
                seen.push(round);
                if round == 4 {
                    Err(MhfeError::Cancelled)
                } else {
                    Ok(())
                }
            },
            None,
        );
        assert_eq!(result.unwrap_err(), MhfeError::Cancelled);
        assert_eq!(seen, vec![1, 2, 3, 4]);
    }

    #[test]
    fn salt_and_mask_messages_bind_both_settings_and_the_round() {
        let right = [9u8; HALF_BYTES];
        let key = [5u8; KEY_BYTES];
        let default = WorkFactor::default();
        let other_pim = WorkFactor::new(1, 0).unwrap();
        let other_memory = WorkFactor::new(0, 1).unwrap();
        for work in [other_pim, other_memory] {
            assert_ne!(round_salt(work, 0, &right), round_salt(default, 0, &right));
            assert_ne!(
                round_mask(&key, work, 0, &right),
                round_mask(&key, default, 0, &right)
            );
        }
        assert_ne!(
            round_salt(default, 1, &right),
            round_salt(default, 0, &right)
        );

        // BLAKE2b with a 32-byte output length parameter (RFC 7693), computed with Python's
        // hashlib.blake2b(digest_size=32). A truncated BLAKE2b-512 would give 90c2bba9...
        assert_eq!(
            hex::encode(round_salt(default, 0, &right)),
            "202bd3e87f33e58415e4c27227c1ef51"
        );

        let message = round_message(WorkFactor::new(0x0102, 3).unwrap(), 0x0a, &right);
        assert_eq!(message[..12], [0, 0, 0, 3, 0, 0, 1, 2, 0, 0, 0, 0x0a]);
        assert_eq!(message[12..], right);
    }
}
