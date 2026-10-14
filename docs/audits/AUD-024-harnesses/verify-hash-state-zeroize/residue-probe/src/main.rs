//! After a public mhfe call returns, is the padded last block of a SHA-256 or SHA-512 state that
//! hashed the BIP39 seed still in the dead stack below? The needle is the seed bytes the state's
//! buffer holds followed by the 0x80 padding byte, which only the hash state's own buffer holds.
//! Public test data only: the BIP39 vector "abandon x11 about" with passphrase "TREZOR".
use std::hint::black_box;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
const SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6\
                        987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const SCAN: usize = 256 * 1024;

#[inline(never)]
fn clear_stack() {
    let mut area = [0u8; SCAN + 4096];
    black_box(&mut area);
}

#[inline(always)]
fn stack_pointer() -> usize {
    let sp: usize;
    unsafe { std::arch::asm!("mov {}, rsp", out(reg) sp) };
    sp
}

/// Counts the needle below the stack pointer, with no call that could reuse the dead frames.
#[inline(always)]
fn count_below(needle: &[u8; 96], len: usize) -> usize {
    let sp = stack_pointer();
    let start = sp - SCAN;
    let mut found = 0;
    let mut at = start;
    while at + len <= sp - 128 {
        let mut same = true;
        let mut i = 0;
        while i < len {
            if unsafe { std::ptr::read_volatile((at + i) as *const u8) } != needle[i] {
                same = false;
                break;
            }
            i += 1;
        }
        if same {
            found += 1;
        }
        at += 1;
    }
    found
}

fn needle_of(bytes: &[u8]) -> ([u8; 96], usize) {
    let mut needle = [0u8; 96];
    needle[..bytes.len()].copy_from_slice(bytes);
    needle[bytes.len()] = 0x80;
    (needle, bytes.len() + 1)
}

fn run(name: &'static str, needle: [u8; 96], len: usize, call: fn()) -> usize {
    std::thread::Builder::new()
        .stack_size(4 << 20)
        .spawn(move || {
            clear_stack();
            let before = count_below(&needle, len);
            call();
            let after = count_below(&needle, len);
            println!("{name}: needle of {len} bytes below the stack: {before} before, {after} after");
            after
        })
        .unwrap()
        .join()
        .unwrap()
}

fn main() {
    let seed = hex::decode(SEED_HEX).unwrap();
    let mut left = 0;
    // wallet/keys.rs:134-146: HMAC-SHA512("Bitcoin seed", seed); the inner SHA-512 buffer holds
    // the whole 64-byte seed and then 0x80 after finalize pads it.
    let (needle, len) = needle_of(&seed);
    left += run("master_fingerprint (HMAC-SHA512 inner buffer)", needle, len, || {
        black_box(mhfe::wallet::master_fingerprint(black_box(PHRASE), black_box("TREZOR")).unwrap());
    });
    // wallet_check.rs:102-111: SHA-256(DOMAIN(24) || BE32 || seed(64)) = 92 bytes; the last block
    // holds seed[36..64] and then 0x80.
    let (needle, len) = needle_of(&seed[36..]);
    left += run("wallet_check::phrase_passes (SHA-256 buffer)", needle, len, || {
        black_box(mhfe::wallet_check::phrase_passes(black_box(PHRASE), black_box("TREZOR")).unwrap());
    });
    // Control of the needle, computed only after the scans: the published seed is BIP39's.
    let computed = bip39::Mnemonic::parse(PHRASE).unwrap().to_seed("TREZOR");
    println!("control: published seed equals the BIP39 seed: {}", computed[..] == seed[..]);
    println!("zeroize features on: {}; states found after their call: {left}", cfg!(feature = "wipe"));
    std::process::exit(if left == 0 { 0 } else { 1 });
}
