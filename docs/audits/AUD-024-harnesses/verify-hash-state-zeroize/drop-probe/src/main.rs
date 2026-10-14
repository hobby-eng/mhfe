//! Does a hash or MAC state of the versions mhfe pins keep its secret-derived bytes after it is
//! dropped? Each state is built in a heap slot, fed a secret pattern, dropped in place, and the
//! slot's bytes are compared with the bytes it held just before the drop.
use std::mem::{size_of, MaybeUninit};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

fn bytes_of<T>(slot: &MaybeUninit<T>) -> Vec<u8> {
    let start = slot.as_ptr().cast::<u8>();
    (0..size_of::<T>())
        .map(|i| unsafe { std::ptr::read_volatile(start.add(i)) })
        .collect()
}

/// Returns (bytes before drop that are not zero, of those how many are unchanged after the drop,
/// whether the secret pattern itself is found in the slot after the drop).
fn probe<T>(name: &str, value: T, pattern: &[u8]) -> bool {
    let mut slot: Box<MaybeUninit<T>> = Box::new(MaybeUninit::uninit());
    slot.write(value);
    let before = bytes_of(&slot);
    unsafe { slot.assume_init_drop() };
    let after = bytes_of(&slot);
    let nonzero = before.iter().filter(|&&b| b != 0).count();
    let kept = before
        .iter()
        .zip(&after)
        .filter(|(b, a)| **b != 0 && b == a)
        .count();
    let pattern_found = after.windows(pattern.len()).any(|w| w == pattern);
    println!(
        "{name}: {} bytes, {nonzero} not zero before drop, {kept} of them unchanged after drop, \
         secret pattern in slot after drop: {pattern_found}",
        size_of::<T>()
    );
    kept > 0
}

fn main() {
    // Stand-ins: K_i (32 bytes), a Feistel half R (16 bytes), a BIP39 seed (64 bytes).
    let key = [0xA5u8; 32];
    let right = [0x5Au8; 16];
    let seed = [0x3Cu8; 64];
    let mut survived = 0;

    // feistel.rs:259-268 round_mask: HMAC-SHA-256 keyed with K_i, over DS_MASK || settings || R.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(b"MHFE-MASK");
    mac.update(&[0u8; 16]);
    mac.update(&right);
    survived += usize::from(probe("Hmac<Sha256> keyed with K_i, after R", mac, &right));

    // feistel.rs:246-255 round_salt: BLAKE2b-256 over DS_SALT || settings || R.
    let salt = Blake2b::<U32>::new()
        .chain_update(b"MHFE-SALT")
        .chain_update([0u8; 16])
        .chain_update(right);
    survived += usize::from(probe("Blake2b<U32> after R", salt, &right));

    // wallet/keys.rs:134-146 from_hmac: HMAC-SHA512("Bitcoin seed", seed).
    let mut master = <Hmac<Sha512> as KeyInit>::new_from_slice(b"Bitcoin seed").unwrap();
    master.update(&seed[..40]);
    survived += usize::from(probe("Hmac<Sha512> over 40 seed bytes", master, &seed[..40]));

    // wallet_check.rs:102-111 tagged_digest: SHA-256(DOMAIN || BE32(bits) || seed).
    let tagged = Sha256::new().chain_update([0u8; 8]).chain_update(&seed[..40]);
    survived += usize::from(probe("Sha256 over 40 seed bytes", tagged, &seed[..40]));

    // The MAC output type: mac.finalize() returns CtOutput, whose Drop wipes only with zeroize.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(&right);
    let out = mac.finalize();
    let digest = out.clone().into_bytes();
    survived += usize::from(probe("CtOutput<Hmac<Sha256>>", out, &digest[..16]));

    let wipe = cfg!(feature = "wipe");
    println!("zeroize features on: {wipe}; states with bytes left after drop: {survived} of 5");
    // Exit non-zero when a state keeps its bytes after drop (RUST-13).
    std::process::exit(if survived == 0 { 0 } else { 1 });
}
