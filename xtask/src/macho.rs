//! `cargo xtask macos-binary <program>`: makes a macOS program linked by Zig the same bytes on
//! every build. Zig's linker writes a UUID that depends on the paths of its input files, and rustc
//! puts one of them in a temporary folder of a new name each time; everything else it writes is the
//! same. This gives the program a UUID computed from its own bytes instead and, where it carries an
//! ad-hoc signature, as every Apple Silicon program must, the hashes of the pages that changed.
//!
//! The UUID is the first 16 bytes of the SHA-256 of the program with its UUID zeroed and its
//! signature left out, marked as a UUID of version 8 (RFC 9562, "custom"). The signature keeps
//! everything but the hashes of its code pages, which are computed again with SHA-256; a
//! signature with another hash type is refused.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{Failure, at};

/// The magic number of a 64-bit Mach-O file in little-endian order.
const MH_MAGIC_64: u32 = 0xfeed_facf;
/// The size of the Mach-O header before the first load command.
const HEADER_BYTES: usize = 32;
/// The load commands this needs.
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
/// The magic numbers of a signature's superblob and code directory (big-endian).
const SUPERBLOB_MAGIC: u32 = 0xfade_0cc0;
const CODE_DIRECTORY_MAGIC: u32 = 0xfade_0c02;
/// The code directory's hash type for SHA-256 and that hash's size.
const SHA256_TYPE: u8 = 2;
const SHA256_BYTES: usize = 32;

pub(crate) fn run(arguments: &[String]) -> Result<(), Failure> {
    let [program] = arguments else {
        return Err(Failure(
            "usage: cargo xtask macos-binary <program>".to_owned(),
        ));
    };
    let path = Path::new(program);
    let mut bytes = std::fs::read(path).map_err(|error| at(path, error))?;
    normalise(&mut bytes).map_err(|why| Failure(format!("{program}: {why}")))?;
    std::fs::write(path, &bytes).map_err(|error| at(path, error))?;
    println!("{program}: UUID {}", hex(&uuid_of(&bytes)?));
    Ok(())
}

/// Where the UUID and the signature of a program lie.
struct Layout {
    uuid: usize,
    signature: Option<std::ops::Range<usize>>,
}

/// Gives `bytes`, a 64-bit Mach-O program, its UUID from its contents and refreshes its signature.
fn normalise(bytes: &mut [u8]) -> Result<(), String> {
    let layout = layout(bytes)?;
    bytes[layout.uuid..layout.uuid + 16].fill(0);
    let mut digest = Sha256::new();
    match &layout.signature {
        Some(signature) => {
            digest.update(&bytes[..signature.start]);
            digest.update(&bytes[signature.end..]);
        }
        None => digest.update(&bytes[..]),
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest.finalize()[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    bytes[layout.uuid..layout.uuid + 16].copy_from_slice(&uuid);
    if let Some(signature) = layout.signature {
        rehash_pages(bytes, &signature)?;
    }
    Ok(())
}

fn uuid_of(bytes: &[u8]) -> Result<[u8; 16], Failure> {
    let start = layout(bytes).map_err(Failure)?.uuid;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[start..start + 16]);
    Ok(uuid)
}

/// Finds the UUID and the signature among the load commands.
fn layout(bytes: &[u8]) -> Result<Layout, String> {
    if little(bytes, 0)? != MH_MAGIC_64 {
        return Err("not a 64-bit little-endian Mach-O program".to_owned());
    }
    let commands = little(bytes, 16)?;
    let mut offset = HEADER_BYTES;
    let (mut uuid, mut signature) = (None, None);
    for _ in 0..commands {
        let (command, size) = (little(bytes, offset)?, little(bytes, offset + 4)? as usize);
        match command {
            LC_UUID if size < 24 => return Err("LC_UUID is shorter than its UUID".to_owned()),
            LC_UUID => uuid = Some(offset + 8),
            LC_CODE_SIGNATURE => {
                let start = little(bytes, offset + 8)? as usize;
                let end = start
                    .checked_add(little(bytes, offset + 12)? as usize)
                    .filter(|&end| end <= bytes.len())
                    .ok_or("the signature lies beyond the end of the file")?;
                signature = Some(start..end);
            }
            _ => {}
        }
        if size < 8 {
            return Err("a load command is shorter than its header".to_owned());
        }
        offset = offset
            .checked_add(size)
            .ok_or("the load commands overflow")?;
    }
    let uuid = uuid.ok_or("the program has no UUID")?;
    if uuid + 16 > bytes.len() {
        return Err("the UUID lies beyond the end of the file".to_owned());
    }
    Ok(Layout { uuid, signature })
}

/// Computes again every code page hash of each code directory of the signature at `signature`. A
/// code directory must lie inside the signature, hash with SHA-256 pages of 2^1 to 2^31 bytes that
/// end before the signature, and have exactly one slot for each of those pages.
fn rehash_pages(bytes: &mut [u8], signature: &std::ops::Range<usize>) -> Result<(), String> {
    let start = signature.start;
    if big(bytes, start)? != SUPERBLOB_MAGIC {
        return Err("the signature is no superblob".to_owned());
    }
    let count = big(bytes, start + 8)? as usize;
    for index in 0..count {
        let entry = index
            .checked_mul(8)
            .and_then(|offset| offset.checked_add(start + 16))
            .ok_or("the signature's index overflows")?;
        let blob = start
            .checked_add(big(bytes, entry)? as usize)
            .filter(|blob| signature.contains(blob))
            .ok_or("a blob lies outside the signature")?;
        if big(bytes, blob)? != CODE_DIRECTORY_MAGIC {
            continue;
        }
        let hash_offset = big(bytes, blob + 16)? as usize;
        let code_slots = big(bytes, blob + 28)? as usize;
        let code_limit = big(bytes, blob + 32)? as usize;
        let (hash_size, hash_type, page_shift) = (
            usize::from(byte(bytes, blob + 36)?),
            byte(bytes, blob + 37)?,
            byte(bytes, blob + 39)?,
        );
        if hash_type != SHA256_TYPE || hash_size != SHA256_BYTES {
            return Err(format!(
                "a code directory hashes with type {hash_type}, not SHA-256"
            ));
        }
        if !(1..32).contains(&page_shift) {
            return Err(format!(
                "a code directory has pages of 2^{page_shift} bytes"
            ));
        }
        let page = 1usize << page_shift;
        if code_limit > start || code_slots != code_limit.div_ceil(page) {
            return Err("a code directory's pages do not end before the signature".to_owned());
        }
        let hashes = blob
            .checked_add(hash_offset)
            .filter(|&first| first + code_slots * hash_size <= signature.end)
            .ok_or("a page hash lies outside the signature")?;
        for slot in 0..code_slots {
            let from = slot * page;
            let to = (from + page).min(code_limit);
            let hash: [u8; SHA256_BYTES] = Sha256::digest(&bytes[from..to]).into();
            let at = hashes + slot * hash_size;
            bytes[at..at + hash_size].copy_from_slice(&hash);
        }
    }
    Ok(())
}

fn little(bytes: &[u8], at: usize) -> Result<u32, String> {
    word(bytes, at).map(u32::from_le_bytes)
}

fn big(bytes: &[u8], at: usize) -> Result<u32, String> {
    word(bytes, at).map(u32::from_be_bytes)
}

fn word(bytes: &[u8], at: usize) -> Result<[u8; 4], String> {
    bytes
        .get(at..at + 4)
        .and_then(|word| word.try_into().ok())
        .ok_or_else(|| "the file ends inside its load commands or signature".to_owned())
}

fn byte(bytes: &[u8], at: usize) -> Result<u8, String> {
    bytes
        .get(at)
        .copied()
        .ok_or_else(|| "the file ends inside its signature".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program of two 4 KiB pages: the header with LC_UUID and LC_CODE_SIGNATURE, a page of
    /// code, then a superblob with one SHA-256 code directory over both pages.
    fn program(uuid: [u8; 16]) -> Vec<u8> {
        let code_limit = 8192usize;
        let mut bytes = vec![0u8; code_limit];
        bytes[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        let mut at = HEADER_BYTES;
        for (command, size) in [(LC_UUID, 24u32), (LC_CODE_SIGNATURE, 16)] {
            bytes[at..at + 4].copy_from_slice(&command.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
            at += size as usize;
        }
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 24].copy_from_slice(&uuid);
        bytes[4096..4100].copy_from_slice(b"code");
        let directory_offset = 20usize;
        let hash_offset = 44usize;
        let mut signature = Vec::new();
        for word in [SUPERBLOB_MAGIC, 0, 1, 0, directory_offset as u32] {
            signature.extend_from_slice(&word.to_be_bytes());
        }
        let mut directory = Vec::new();
        for word in [
            CODE_DIRECTORY_MAGIC,
            0,
            0x20400,
            0,
            hash_offset as u32,
            0,
            0,
            2,
        ] {
            directory.extend_from_slice(&word.to_be_bytes());
        }
        directory.extend_from_slice(&(code_limit as u32).to_be_bytes());
        directory.extend_from_slice(&[32, SHA256_TYPE, 0, 12, 0, 0, 0, 0]);
        directory.resize(hash_offset + 2 * SHA256_BYTES, 0xee);
        signature.extend_from_slice(&directory);
        let signature_offset = bytes.len() as u32;
        let command = HEADER_BYTES + 24;
        bytes[command + 8..command + 12].copy_from_slice(&signature_offset.to_le_bytes());
        bytes[command + 12..command + 16].copy_from_slice(&(signature.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&signature);
        bytes
    }

    #[test]
    fn programs_that_differ_in_their_uuid_alone_become_the_same() {
        let mut first = program([1; 16]);
        let mut second = program([2; 16]);
        normalise(&mut first).unwrap();
        normalise(&mut second).unwrap();
        assert_eq!(first, second);
        let uuid = uuid_of(&first).unwrap();
        assert_eq!(
            (uuid[6] >> 4, uuid[8] >> 6),
            (8, 0b10),
            "version 8, RFC 9562 variant"
        );
        // Run again, it changes nothing.
        let again = first.clone();
        normalise(&mut first).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn the_page_hashes_follow_the_new_uuid() {
        let mut bytes = program([7; 16]);
        normalise(&mut bytes).unwrap();
        let directory = 8192 + 20;
        for page in 0..2 {
            let expected: [u8; 32] = Sha256::digest(&bytes[page * 4096..(page + 1) * 4096]).into();
            let at = directory + 44 + page * 32;
            assert_eq!(bytes[at..at + 32], expected);
        }
    }

    #[test]
    fn a_program_without_a_signature_gets_its_uuid() {
        let mut first = program([1; 16]);
        first.truncate(8192);
        first[HEADER_BYTES + 24..HEADER_BYTES + 40].fill(0);
        first[16..20].copy_from_slice(&1u32.to_le_bytes());
        let mut second = first.clone();
        second[HEADER_BYTES + 8..HEADER_BYTES + 24].fill(2);
        normalise(&mut first).unwrap();
        normalise(&mut second).unwrap();
        assert_eq!(first, second);
        assert_ne!(uuid_of(&first).unwrap(), [0; 16]);
    }

    #[test]
    fn a_code_directory_out_of_shape_is_refused() {
        let directory = 8192 + 20;
        let refused = |change: &dyn Fn(&mut Vec<u8>), why: &str| {
            let mut bytes = program([0; 16]);
            change(&mut bytes);
            let error = normalise(&mut bytes).unwrap_err();
            assert!(error.contains(why), "{error}");
        };
        for shift in [0u8, 32, 64, 255] {
            refused(&|bytes| bytes[directory + 39] = shift, "pages of 2^");
        }
        refused(
            &|bytes| bytes[directory + 32..directory + 36].copy_from_slice(&9000u32.to_be_bytes()),
            "do not end before the signature",
        );
        refused(
            &|bytes| bytes[directory + 28..directory + 32].copy_from_slice(&3u32.to_be_bytes()),
            "do not end before the signature",
        );
        refused(
            &|bytes| bytes[8192 + 16..8192 + 20].copy_from_slice(&u32::MAX.to_be_bytes()),
            "outside the signature",
        );
        refused(
            &|bytes| bytes[directory + 16..directory + 20].copy_from_slice(&4000u32.to_be_bytes()),
            "outside the signature",
        );
        refused(
            &|bytes| {
                bytes[HEADER_BYTES + 4..HEADER_BYTES + 8].copy_from_slice(&16u32.to_le_bytes())
            },
            "shorter than its UUID",
        );
    }

    #[test]
    fn another_file_or_hash_is_refused() {
        assert!(normalise(&mut [0u8; 64]).is_err());
        let mut bytes = program([0; 16]);
        bytes[8192 + 20 + 37] = 1;
        assert!(normalise(&mut bytes).unwrap_err().contains("not SHA-256"));
    }
}
