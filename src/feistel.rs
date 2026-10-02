//! The 12-round balanced Feistel permutation (specification: "Permutation", and "Suite 4" for
//! the same-length containers).
//!
//! ```text
//! Suite 3, 128-bit halves:
//! S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//! K_i = Argon2id(P_enc, S_i)
//! M_i = Trunc_128(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//!
//! Suite 4, h = ENT/2-bit halves, with its own domain strings and BE32(ENT) in both messages:
//! S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R))
//! M_i = Trunc_h(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R))
//! ```

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::packing::STATE_BYTES;
use crate::suite::{DS_MASK, DS_SALT, ROUNDS, SAME_LENGTH_DS_MASK, SAME_LENGTH_DS_SALT};
use crate::{MhfeError, Password, WorkFactor};

type Blake2b256 = Blake2b<U32>;
type HmacSha256 = Hmac<Sha256>;

/// The left and right half of a state, wiped when dropped.
type Halves = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// Called with the number (1 to 12) of each round before it starts. Returning an error, such as
/// [`MhfeError::Cancelled`], stops the permutation before that round.
pub(crate) type RoundCallback<'a> = &'a mut dyn FnMut(u32) -> Result<(), MhfeError>;

/// The shape of one suite's permutation: its domain strings, the size of its halves and whether
/// its round message carries the entropy size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    ds_salt: &'static [u8],
    ds_mask: &'static [u8],
    half_bytes: usize,
    /// `ENT` of suite 4, written as `BE32(ENT)` after the settings; suite 3 has none.
    entropy_bits: Option<u32>,
}

impl Geometry {
    /// Suite 3: the 256-bit packed state in two 128-bit halves.
    pub const SUITE_3: Self = Self {
        ds_salt: DS_SALT,
        ds_mask: DS_MASK,
        half_bytes: STATE_BYTES / 2,
        entropy_bits: None,
    };

    /// Suite 4 for an original of `entropy_bytes` bytes (16, 20, 24 or 28): the entropy itself
    /// in two halves of `ENT/2` bits.
    pub fn same_length(entropy_bytes: usize) -> Result<Self, MhfeError> {
        if !matches!(entropy_bytes, 16 | 20 | 24 | 28) {
            return Err(MhfeError::Internal(format!(
                "a same-length container cannot hold {entropy_bytes} bytes of entropy"
            )));
        }
        Ok(Self {
            ds_salt: SAME_LENGTH_DS_SALT,
            ds_mask: SAME_LENGTH_DS_MASK,
            half_bytes: entropy_bytes / 2,
            entropy_bits: Some(8 * entropy_bytes as u32),
        })
    }

    pub fn half_bytes(self) -> usize {
        self.half_bytes
    }

    pub fn state_bytes(self) -> usize {
        2 * self.half_bytes
    }

    pub fn ds_salt(self) -> &'static [u8] {
        self.ds_salt
    }

    pub fn ds_mask(self) -> &'static [u8] {
        self.ds_mask
    }
}

/// All values of one round, for test vectors. States are `L || R` before and after the round.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoundTrace {
    pub round: u32,
    pub state_before: Vec<u8>,
    /// `BE32(MEM) || BE32(PIM) || [BE32(ENT)] || BE32(i) || R`, which follows DS_SALT in the
    /// salt input and DS_MASK in the mask message.
    pub message: Vec<u8>,
    pub salt: [u8; SALT_BYTES],
    pub key: [u8; KEY_BYTES],
    pub mask: Vec<u8>,
    pub state_after: Vec<u8>,
}

/// The permutation for one password, one work factor and one suite's geometry.
pub struct Permutation<'a> {
    pub engine: &'a mut dyn Argon2Engine,
    pub password: &'a Password,
    pub work: WorkFactor,
    pub geometry: Geometry,
}

impl Permutation<'_> {
    /// `Y = Perm(X)`: rounds 0 to 11.
    pub fn forward(
        &mut self,
        x: &[u8],
        on_round: RoundCallback<'_>,
        mut trace: Option<&mut Vec<RoundTrace>>,
    ) -> Result<Zeroizing<Vec<u8>>, MhfeError> {
        let (mut left, mut right) = self.split(x)?;
        for round in 0..ROUNDS {
            on_round(round + 1)?;
            let values = self.round_values(round, &right)?;
            let before = join(&left, &right);
            // L_{i+1} = R_i and R_{i+1} = L_i XOR M_i.
            let next_right = xor(&left, &values.mask);
            left.copy_from_slice(&right);
            right.copy_from_slice(&next_right);
            if let Some(trace) = trace.as_deref_mut() {
                trace.push(values.into_trace(round, &before, &join(&left, &right)));
            }
        }
        Ok(join(&left, &right))
    }

    /// `X = Perm^-1(Y)`: rounds 11 down to 0. The callback still counts from 1 to 12.
    pub fn inverse(
        &mut self,
        y: &[u8],
        on_round: RoundCallback<'_>,
        mut trace: Option<&mut Vec<RoundTrace>>,
    ) -> Result<Zeroizing<Vec<u8>>, MhfeError> {
        let (mut left, mut right) = self.split(y)?;
        for (step, round) in (0..ROUNDS).rev().enumerate() {
            on_round(step as u32 + 1)?;
            // R_i = L_{i+1}, so the mask comes from the current left half;
            // then L_i = R_{i+1} XOR M_i.
            let values = self.round_values(round, &left)?;
            let before = join(&left, &right);
            let previous_left = xor(&right, &values.mask);
            right.copy_from_slice(&left);
            left.copy_from_slice(&previous_left);
            if let Some(trace) = trace.as_deref_mut() {
                trace.push(values.into_trace(round, &before, &join(&left, &right)));
            }
        }
        Ok(join(&left, &right))
    }

    /// `RoundMask(i, R)` together with the salt and key it passes through.
    fn round_values(&mut self, round: u32, right: &[u8]) -> Result<RoundValues, MhfeError> {
        let message = round_message(self.geometry, self.work, round, right);
        let mut values = RoundValues {
            salt: round_salt(self.geometry, &message),
            message,
            key: [0u8; KEY_BYTES],
            mask: Vec::new(),
        };
        self.engine
            .derive(self.password.as_bytes(), &values.salt, &mut values.key)?;
        values.mask = round_mask(self.geometry, &values.key, &values.message);
        Ok(values)
    }

    /// `L_0` is the first half of the state and `R_0` the second.
    fn split(&self, state: &[u8]) -> Result<Halves, MhfeError> {
        if state.len() != self.geometry.state_bytes() {
            return Err(MhfeError::Internal(format!(
                "a state of {} bytes does not fit halves of {} bytes",
                state.len(),
                self.geometry.half_bytes
            )));
        }
        let (left, right) = state.split_at(self.geometry.half_bytes);
        Ok((
            Zeroizing::new(left.to_vec()),
            Zeroizing::new(right.to_vec()),
        ))
    }
}

/// Message, salt, Argon2id key and mask of one round; wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RoundValues {
    message: Vec<u8>,
    salt: [u8; SALT_BYTES],
    key: [u8; KEY_BYTES],
    mask: Vec<u8>,
}

impl RoundValues {
    fn into_trace(mut self, round: u32, before: &[u8], after: &[u8]) -> RoundTrace {
        RoundTrace {
            round,
            state_before: before.to_vec(),
            message: std::mem::take(&mut self.message),
            salt: self.salt,
            key: self.key,
            mask: std::mem::take(&mut self.mask),
            state_after: after.to_vec(),
        }
    }
}

/// The message shared by salt and mask: `BE32(MEM) || BE32(PIM) || BE32(i) || R`, with
/// `BE32(ENT)` before `BE32(i)` in suite 4.
pub(crate) fn round_message(
    geometry: Geometry,
    work: WorkFactor,
    round: u32,
    right: &[u8],
) -> Vec<u8> {
    // Reserved at full size, so the message holding R is never copied by a reallocation.
    let mut message = Vec::with_capacity(16 + right.len());
    message.extend_from_slice(&work.memory_level().to_be_bytes());
    message.extend_from_slice(&work.pim().to_be_bytes());
    if let Some(bits) = geometry.entropy_bits {
        message.extend_from_slice(&bits.to_be_bytes());
    }
    message.extend_from_slice(&round.to_be_bytes());
    message.extend_from_slice(right);
    message
}

/// `S_i = Trunc_128(BLAKE2b-256(DS_SALT || message))`.
pub(crate) fn round_salt(geometry: Geometry, message: &[u8]) -> [u8; SALT_BYTES] {
    let mut digest = Blake2b256::new()
        .chain_update(geometry.ds_salt)
        .chain_update(message)
        .finalize();
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&digest[..SALT_BYTES]);
    digest.zeroize();
    salt
}

/// `M_i = Trunc_h(HMAC-SHA-256(K_i, DS_MASK || message))`, as long as one half.
pub(crate) fn round_mask(geometry: Geometry, key: &[u8; KEY_BYTES], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(geometry.ds_mask);
    mac.update(message);
    let mut digest = mac.finalize().into_bytes();
    let mask = digest[..geometry.half_bytes].to_vec();
    digest.zeroize();
    mask
}

fn join(left: &[u8], right: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut state = Zeroizing::new(Vec::with_capacity(left.len() + right.len()));
    state.extend_from_slice(left);
    state.extend_from_slice(right);
    state
}

fn xor(a: &[u8], b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
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
            geometry: Geometry::SUITE_3,
        }
    }

    #[test]
    fn inverse_undoes_forward() {
        let password = Password::new("public test password").unwrap();
        let mut engine = HashEngine;
        let x: [u8; STATE_BYTES] = std::array::from_fn(|index| index as u8);
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
        let x: [u8; STATE_BYTES] = std::array::from_fn(|index| 255 - index as u8);
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
        let geometry = Geometry::SUITE_3;
        let right = [9u8; STATE_BYTES / 2];
        let key = [5u8; KEY_BYTES];
        let salt =
            |work, round| round_salt(geometry, &round_message(geometry, work, round, &right));
        let mask = |work, round| {
            round_mask(
                geometry,
                &key,
                &round_message(geometry, work, round, &right),
            )
        };
        let default = WorkFactor::default();
        let other_pim = WorkFactor::new(1, 0).unwrap();
        let other_memory = WorkFactor::new(0, 1).unwrap();
        for work in [other_pim, other_memory] {
            assert_ne!(salt(work, 0), salt(default, 0));
            assert_ne!(mask(work, 0), mask(default, 0));
        }
        assert_ne!(salt(default, 1), salt(default, 0));

        // BLAKE2b with a 32-byte output length parameter (RFC 7693), computed with Python's
        // hashlib.blake2b(digest_size=32). A truncated BLAKE2b-512 would give 90c2bba9...
        assert_eq!(
            hex::encode(salt(default, 0)),
            "202bd3e87f33e58415e4c27227c1ef51"
        );

        let message = round_message(geometry, WorkFactor::new(0x0102, 3).unwrap(), 0x0a, &right);
        assert_eq!(message[..12], [0, 0, 0, 3, 0, 0, 1, 2, 0, 0, 0, 0x0a]);
        assert_eq!(message[12..], right);
    }

    #[test]
    fn same_length_rounds_carry_the_entropy_size_and_their_own_domain() {
        let work = WorkFactor::new(0x0102, 3).unwrap();
        for (bytes, half) in [(16, 8), (20, 10), (24, 12), (28, 14)] {
            let geometry = Geometry::same_length(bytes).unwrap();
            assert_eq!(geometry.half_bytes(), half);
            let right = vec![9u8; half];
            let message = round_message(geometry, work, 0x0a, &right);
            let bits = (8 * bytes as u32).to_be_bytes();
            assert_eq!(message[..8], [0, 0, 0, 3, 0, 0, 1, 2]);
            assert_eq!(message[8..12], bits);
            assert_eq!(message[12..16], [0, 0, 0, 0x0a]);
            assert_eq!(message[16..], right[..]);
            assert_eq!(
                round_mask(geometry, &[5u8; KEY_BYTES], &message).len(),
                half
            );
        }
        // Another suite or another length gives another salt for the same half.
        let right = [9u8; 8];
        let twelve = Geometry::same_length(16).unwrap();
        let mut as_suite_3 = round_message(Geometry::SUITE_3, work, 0, &right);
        assert_ne!(
            round_salt(twelve, &round_message(twelve, work, 0, &right)),
            round_salt(Geometry::SUITE_3, &as_suite_3)
        );
        as_suite_3.zeroize();
        assert!(Geometry::same_length(32).is_err());
    }

    #[test]
    fn same_length_inverse_undoes_forward_for_every_length() {
        let password = Password::new("public test password").unwrap();
        for bytes in [16, 20, 24, 28] {
            let mut engine = HashEngine;
            let mut permutation = Permutation {
                engine: &mut engine,
                password: &password,
                work: WorkFactor::default(),
                geometry: Geometry::same_length(bytes).unwrap(),
            };
            let x: Vec<u8> = (0..bytes).map(|index| index as u8).collect();
            let y = permutation.forward(&x, &mut |_| Ok(()), None).unwrap();
            assert_eq!(y.len(), bytes);
            assert_ne!(*y, x);
            assert_eq!(*permutation.inverse(&y, &mut |_| Ok(()), None).unwrap(), x);
            // A state of another size is refused, not cut or padded.
            assert!(permutation
                .forward(&[0u8; 32], &mut |_| Ok(()), None)
                .is_err());
        }
    }
}
