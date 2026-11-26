//! `cargo xtask macos-binary <program>`: makes a macOS program linked by Zig the same bytes on
//! every build, and signs it ad hoc with the hardened runtime. Zig's linker writes a UUID that
//! depends on the paths of its input files, and rustc puts one of them in a temporary folder of a
//! new name each time; everything else it writes is the same. This gives the program a UUID
//! computed from its own bytes instead.
//!
//! The signature takes the place of the one Zig's linker writes on Apple silicon, which has no
//! hardened runtime, and is added to the Intel program, which has none. Without the hardened
//! runtime, a process of the same user on a Mac with the developer tools turned on, or of root,
//! gets the program's task port and with it its memory: `PT_DENY_ATTACH` stops `ptrace` alone. With
//! it, and without the entitlement `com.apple.security.get-task-allow`, macOS gives that port to no
//! other process. As `codesign --sign - --options runtime` writes it, the signature holds a code
//! directory of version 0x20500 with the flags ad hoc and runtime, the SDK version of the program
//! as its runtime version and a SHA-256 hash of every 4 KiB page before the signature; an empty set
//! of requirements, whose hash is the directory's special slot -2; and an empty CMS blob.
//! `cargo xtask hardened` checks on a Mac that macOS reads it so (hardened.rs).
//!
//! The UUID is the first 16 bytes of the SHA-256 of the program as it is signed, without its
//! signature and with its UUID zeroed, marked as a UUID of version 8 (RFC 9562, "custom"). A
//! program signed before is signed again from the same bytes, so a second run changes nothing.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{Failure, at};

/// The magic number of a 64-bit Mach-O file in little-endian order.
const MH_MAGIC_64: u32 = 0xfeed_facf;
/// The size of the Mach-O header before the first load command.
const HEADER_BYTES: usize = 32;
/// The processors this signs for, the file type of a program and its first segment's flag.
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const MH_EXECUTE: u32 = 2;
/// The load commands this needs.
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_BUILD_VERSION: u32 = 0x32;
/// The size of LC_CODE_SIGNATURE, of a section of a 64-bit segment, and of a segment's command
/// before its sections.
const SIGNATURE_COMMAND_BYTES: usize = 16;
const SECTION_BYTES: usize = 80;
const SEGMENT_BYTES: usize = 72;
/// The magic numbers of a signature's superblob and code directory (big-endian).
const SUPERBLOB_MAGIC: u32 = 0xfade_0cc0;
const CODE_DIRECTORY_MAGIC: u32 = 0xfade_0c02;
/// The slots of the superblob's index for those blobs.
const SLOT_CODE_DIRECTORY: u32 = 0;
const SLOT_REQUIREMENTS: u32 = 2;
const SLOT_SIGNATURE: u32 = 0x1_0000;
/// The code directory: its version with a runtime version, its size up to the identifier at that
/// version, its flags (CS_ADHOC and CS_RUNTIME), its special slots (-1 the Info.plist, none here,
/// and -2 the requirements), and the flag of a main program's executable segment.
const CODE_DIRECTORY_VERSION: u32 = 0x2_0500;
const CODE_DIRECTORY_BYTES: usize = 96;
const AD_HOC_WITH_RUNTIME: u32 = 0x0001_0002;
const SPECIAL_SLOTS: usize = 2;
const EXECUTABLE_SEGMENT_MAIN: u64 = 1;
/// The code directory's hash type for SHA-256, that hash's size, and the pages it hashes.
const SHA256_TYPE: u8 = 2;
const SHA256_BYTES: usize = 32;
const PAGE_SHIFT: u8 = 12;
const PAGE_BYTES: usize = 1 << PAGE_SHIFT;
/// The empty set of requirements (magic 0xfade0c01, its length, no requirement) and the empty CMS
/// wrapper (magic 0xfade0b01, its length) of an ad-hoc signature.
const REQUIREMENTS: [u8; 12] = [0xfa, 0xde, 0x0c, 0x01, 0, 0, 0, 12, 0, 0, 0, 0];
const BLOB_WRAPPER: [u8; 8] = [0xfa, 0xde, 0x0b, 0x01, 0, 0, 0, 8];

pub(crate) fn run(arguments: &[String]) -> Result<(), Failure> {
    let [program] = arguments else {
        return Err(Failure(
            "usage: cargo xtask macos-binary <program>".to_owned(),
        ));
    };
    let path = Path::new(program);
    let identifier = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Failure(format!("{program}: no file name to sign it with")))?;
    let bytes = std::fs::read(path).map_err(|error| at(path, error))?;
    let bytes = normalise(bytes, identifier).map_err(|why| Failure(format!("{program}: {why}")))?;
    std::fs::write(path, &bytes).map_err(|error| at(path, error))?;
    println!(
        "{program}: UUID {}, signed ad hoc with the hardened runtime",
        hex(&uuid_of(&bytes)?)
    );
    Ok(())
}

/// Where the parts this needs lie in a program, as offsets into its file.
struct Layout {
    /// The end of the load commands, and the first byte of a section after them.
    commands_end: usize,
    first_section: usize,
    uuid: usize,
    /// LC_CODE_SIGNATURE's command, if the program has one.
    signature_command: Option<usize>,
    /// __LINKEDIT's command; __TEXT's offset and size in the file.
    linkedit: usize,
    text: (u64, u64),
    /// The SDK the program was built with, as its LC_BUILD_VERSION or LC_VERSION_MIN_MACOSX says.
    sdk: u32,
    /// The size of a memory page of its processor, to which a segment's size in memory is rounded.
    memory_page: u64,
}

/// Gives `bytes`, a 64-bit Mach-O program, its UUID from its contents and a new ad-hoc signature
/// with the hardened runtime, under `identifier`.
fn normalise(mut bytes: Vec<u8>, identifier: &str) -> Result<Vec<u8>, String> {
    let layout = layout(&bytes)?;
    // The program without its signature: the linker's, or one this wrote before.
    let command = match layout.signature_command {
        Some(command) => {
            let start = little(&bytes, command + 8)? as usize;
            let size = little(&bytes, command + 12)? as usize;
            if start.checked_add(size) != Some(bytes.len()) {
                return Err("the signature is not at the end of the file".to_owned());
            }
            bytes.truncate(start);
            command
        }
        None => {
            let command = layout.commands_end;
            let room = command + SIGNATURE_COMMAND_BYTES;
            if room > layout.first_section || bytes[command..room].iter().any(|&byte| byte != 0) {
                return Err("no room after the load commands for LC_CODE_SIGNATURE".to_owned());
            }
            let count = little(&bytes, 16)? + 1;
            let commands = little(&bytes, 20)? + SIGNATURE_COMMAND_BYTES as u32;
            put_little(&mut bytes, 16, count);
            put_little(&mut bytes, 20, commands);
            put_little(&mut bytes, command, LC_CODE_SIGNATURE);
            put_little(&mut bytes, command + 4, SIGNATURE_COMMAND_BYTES as u32);
            command
        }
    };
    let linkedit_start = long(&bytes, layout.linkedit + 40)?;
    let linkedit_end = linkedit_start.saturating_add(long(&bytes, layout.linkedit + 48)?);
    if linkedit_start > bytes.len() as u64 || linkedit_end < bytes.len() as u64 {
        return Err("__LINKEDIT does not end the file".to_owned());
    }
    let start = bytes.len().next_multiple_of(16);
    bytes.resize(start, 0);
    let size = signature_bytes(start, identifier).next_multiple_of(16);
    put_little(&mut bytes, command + 8, word_of(start)?);
    put_little(&mut bytes, command + 12, word_of(size)?);
    let linkedit_size = (start + size) as u64 - linkedit_start;
    put_long(&mut bytes, layout.linkedit + 48, linkedit_size);
    put_long(
        &mut bytes,
        layout.linkedit + 32,
        linkedit_size.next_multiple_of(layout.memory_page),
    );
    bytes[layout.uuid..layout.uuid + 16].fill(0);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&Sha256::digest(&bytes)[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    bytes[layout.uuid..layout.uuid + 16].copy_from_slice(&uuid);
    let signature = signature(&bytes, identifier, layout.text, layout.sdk)?;
    bytes.extend_from_slice(&signature);
    bytes.resize(start + size, 0);
    Ok(bytes)
}

/// The size of the signature of a program of `code_limit` bytes before it.
fn signature_bytes(code_limit: usize, identifier: &str) -> usize {
    let directory = CODE_DIRECTORY_BYTES
        + identifier.len()
        + 1
        + (SPECIAL_SLOTS + code_limit.div_ceil(PAGE_BYTES)) * SHA256_BYTES;
    12 + 3 * 8 + directory + REQUIREMENTS.len() + BLOB_WRAPPER.len()
}

/// The superblob of the ad-hoc signature with the hardened runtime of `code`, all the bytes before
/// it.
fn signature(code: &[u8], identifier: &str, text: (u64, u64), sdk: u32) -> Result<Vec<u8>, String> {
    let pages = code.len().div_ceil(PAGE_BYTES);
    let identifier_offset = CODE_DIRECTORY_BYTES;
    let hash_offset = identifier_offset + identifier.len() + 1 + SPECIAL_SLOTS * SHA256_BYTES;
    let directory_bytes = hash_offset + pages * SHA256_BYTES;
    let mut directory = Vec::with_capacity(directory_bytes);
    for word in [
        CODE_DIRECTORY_MAGIC,
        word_of(directory_bytes)?,
        CODE_DIRECTORY_VERSION,
        AD_HOC_WITH_RUNTIME,
        word_of(hash_offset)?,
        word_of(identifier_offset)?,
        word_of(SPECIAL_SLOTS)?,
        word_of(pages)?,
        word_of(code.len())?,
    ] {
        directory.extend_from_slice(&word.to_be_bytes());
    }
    directory.extend_from_slice(&[SHA256_BYTES as u8, SHA256_TYPE, 0, PAGE_SHIFT]);
    // The second spare word, the scatter, team and third spare words, then the 64-bit code limit,
    // which a code limit of 32 bits leaves 0.
    directory.resize(56 + 8, 0);
    for long in [text.0, text.1, EXECUTABLE_SEGMENT_MAIN] {
        directory.extend_from_slice(&long.to_be_bytes());
    }
    // The runtime version, then the offset of encrypted pages, which this program has none of.
    directory.extend_from_slice(&sdk.to_be_bytes());
    directory.extend_from_slice(&0u32.to_be_bytes());
    directory.extend_from_slice(identifier.as_bytes());
    directory.push(0);
    directory.extend_from_slice(&Sha256::digest(REQUIREMENTS));
    directory.extend_from_slice(&[0; SHA256_BYTES]);
    for page in code.chunks(PAGE_BYTES) {
        directory.extend_from_slice(&Sha256::digest(page));
    }
    let blobs: [(u32, &[u8]); 3] = [
        (SLOT_CODE_DIRECTORY, &directory),
        (SLOT_REQUIREMENTS, &REQUIREMENTS),
        (SLOT_SIGNATURE, &BLOB_WRAPPER),
    ];
    let total = 12 + 8 * blobs.len() + blobs.iter().map(|(_, blob)| blob.len()).sum::<usize>();
    let mut superblob = Vec::with_capacity(total);
    for word in [SUPERBLOB_MAGIC, word_of(total)?, blobs.len() as u32] {
        superblob.extend_from_slice(&word.to_be_bytes());
    }
    let mut offset = 12 + 8 * blobs.len();
    for (slot, blob) in &blobs {
        superblob.extend_from_slice(&slot.to_be_bytes());
        superblob.extend_from_slice(&word_of(offset)?.to_be_bytes());
        offset += blob.len();
    }
    for (_, blob) in &blobs {
        superblob.extend_from_slice(blob);
    }
    Ok(superblob)
}

fn uuid_of(bytes: &[u8]) -> Result<[u8; 16], Failure> {
    let start = layout(bytes).map_err(Failure)?.uuid;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[start..start + 16]);
    Ok(uuid)
}

/// Reads the header and the load commands this needs.
fn layout(bytes: &[u8]) -> Result<Layout, String> {
    if little(bytes, 0)? != MH_MAGIC_64 {
        return Err("not a 64-bit little-endian Mach-O program".to_owned());
    }
    let memory_page = match little(bytes, 4)? {
        CPU_TYPE_ARM64 => 0x4000,
        CPU_TYPE_X86_64 => 0x1000,
        _ => return Err("a program for neither x86-64 nor ARM64".to_owned()),
    };
    if little(bytes, 12)? != MH_EXECUTE {
        return Err("not a program (MH_EXECUTE)".to_owned());
    }
    let commands = little(bytes, 16)?;
    let mut offset = HEADER_BYTES;
    let (mut uuid, mut signature_command, mut linkedit, mut text, mut sdk) =
        (None, None, None, None, None);
    let mut first_section = usize::MAX;
    for _ in 0..commands {
        let (command, size) = (little(bytes, offset)?, little(bytes, offset + 4)? as usize);
        if size < 8 {
            return Err("a load command is shorter than its header".to_owned());
        }
        match command {
            LC_UUID if size < 24 => return Err("LC_UUID is shorter than its UUID".to_owned()),
            LC_UUID => uuid = Some(offset + 8),
            LC_CODE_SIGNATURE => signature_command = Some(offset),
            LC_BUILD_VERSION => sdk = Some(little(bytes, offset + 16)?),
            LC_VERSION_MIN_MACOSX => sdk = Some(little(bytes, offset + 12)?),
            LC_SEGMENT_64 => {
                let name = bytes.get(offset + 8..offset + 24).unwrap_or_default();
                let fields = (long(bytes, offset + 40)?, long(bytes, offset + 48)?);
                if name.starts_with(b"__TEXT\0") {
                    text = Some(fields);
                } else if name.starts_with(b"__LINKEDIT\0") {
                    linkedit = Some(offset);
                }
                for section in 0..little(bytes, offset + 64)? as usize {
                    let at = offset + SEGMENT_BYTES + section * SECTION_BYTES + 48;
                    match little(bytes, at)? as usize {
                        0 => {}
                        start => first_section = first_section.min(start),
                    }
                }
            }
            _ => {}
        }
        offset = offset
            .checked_add(size)
            .ok_or("the load commands overflow")?;
    }
    let uuid = uuid.ok_or("the program has no UUID")?;
    if uuid + 16 > bytes.len() {
        return Err("the UUID lies beyond the end of the file".to_owned());
    }
    Ok(Layout {
        commands_end: offset,
        first_section,
        uuid,
        signature_command,
        linkedit: linkedit.ok_or("the program has no __LINKEDIT")?,
        text: text.ok_or("the program has no __TEXT")?,
        sdk: sdk.ok_or("the program names no SDK version")?,
        memory_page,
    })
}

fn word_of(value: usize) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| "the program is larger than a signature can cover".to_owned())
}

fn little(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .and_then(|word| word.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "the file ends inside its load commands".to_owned())
}

fn long(bytes: &[u8], at: usize) -> Result<u64, String> {
    bytes
        .get(at..at + 8)
        .and_then(|word| word.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "the file ends inside its load commands".to_owned())
}

fn put_little(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_long(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parts of a program that the tests change.
    const UUID: usize = HEADER_BYTES + 2 * (SEGMENT_BYTES + SECTION_BYTES) + 24 + 8;
    const LINKEDIT: usize = HEADER_BYTES + SEGMENT_BYTES + SECTION_BYTES;
    const SIGNATURE_COMMAND: usize = UUID + 16;
    const CODE: usize = 8192;
    const SDK: u32 = 0x000e_0000;

    fn command(bytes: &mut Vec<u8>, words: &[u32]) {
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }

    fn segment(bytes: &mut Vec<u8>, name: &[u8], file: (u64, u64), section: u32) {
        command(
            bytes,
            &[LC_SEGMENT_64, (SEGMENT_BYTES + SECTION_BYTES) as u32],
        );
        let mut padded = [0u8; 16];
        padded[..name.len()].copy_from_slice(name);
        bytes.extend_from_slice(&padded);
        for long in [0, file.1, file.0, file.1] {
            bytes.extend_from_slice(&u64::to_le_bytes(long));
        }
        command(bytes, &[7, 5, 1, 0]);
        let mut sections = [0u8; SECTION_BYTES];
        sections[48..52].copy_from_slice(&section.to_le_bytes());
        bytes.extend_from_slice(&sections);
    }

    /// An ARM64 program: two 4 KiB pages of __TEXT whose first section starts at 1 KiB, 16 bytes of
    /// __LINKEDIT and, when `signed`, an old signature of 100 bytes after them.
    fn program(uuid: [u8; 16], signed: bool) -> Vec<u8> {
        let old = if signed { 100 } else { 0 };
        let mut bytes = Vec::new();
        let commands = if signed { 5 } else { 4 };
        let sizes = 2 * (SEGMENT_BYTES + SECTION_BYTES) + 24 + 24 + if signed { 16 } else { 0 };
        command(
            &mut bytes,
            &[
                MH_MAGIC_64,
                CPU_TYPE_ARM64,
                0,
                MH_EXECUTE,
                commands,
                sizes as u32,
                0,
                0,
            ],
        );
        segment(&mut bytes, b"__TEXT", (0, CODE as u64), 1024);
        segment(&mut bytes, b"__LINKEDIT", (CODE as u64, 16 + old), 0);
        command(&mut bytes, &[LC_BUILD_VERSION, 24, 1, 0x000b_0000, SDK, 0]);
        command(&mut bytes, &[LC_UUID, 24]);
        bytes.extend_from_slice(&uuid);
        if signed {
            command(
                &mut bytes,
                &[LC_CODE_SIGNATURE, 16, CODE as u32 + 16, old as u32],
            );
        }
        bytes.resize(CODE, 0);
        bytes[4096..4100].copy_from_slice(b"code");
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.resize(bytes.len() + old as usize, 0xee);
        bytes
    }

    fn big(bytes: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn programs_that_differ_in_their_uuid_alone_become_the_same() {
        let first = normalise(program([1; 16], true), "mhfe").unwrap();
        let second = normalise(program([2; 16], true), "mhfe").unwrap();
        assert_eq!(first, second);
        let uuid = uuid_of(&first).unwrap();
        assert_eq!(
            (uuid[6] >> 4, uuid[8] >> 6),
            (8, 0b10),
            "version 8, RFC 9562 variant"
        );
        // Run again, it changes nothing.
        assert_eq!(normalise(first.clone(), "mhfe").unwrap(), first);
    }

    /// The signature reads as `codesign --sign - --options runtime` writes one: a code directory
    /// with the hardened runtime over every page before it, the empty requirements and the empty
    /// CMS blob, all inside __LINKEDIT at the end of the file.
    #[test]
    fn the_signature_is_ad_hoc_with_the_hardened_runtime() {
        let bytes = normalise(program([3; 16], true), "mhfe").unwrap();
        let start = little(&bytes, SIGNATURE_COMMAND + 8).unwrap() as usize;
        let size = little(&bytes, SIGNATURE_COMMAND + 12).unwrap() as usize;
        assert_eq!((start, start + size), (CODE + 16, bytes.len()));
        assert_eq!(long(&bytes, LINKEDIT + 48).unwrap(), 16 + size as u64);
        assert_eq!(long(&bytes, LINKEDIT + 32).unwrap(), 0x4000);
        let signature = &bytes[start..];
        assert_eq!(
            [0, 4, 8].map(|at| big(signature, at)),
            [SUPERBLOB_MAGIC, signature_bytes(start, "mhfe") as u32, 3]
        );
        let blob = |index: usize| {
            let (slot, offset) = (
                big(signature, 12 + 8 * index),
                big(signature, 16 + 8 * index),
            );
            (slot, &signature[offset as usize..])
        };
        let (slot, directory) = blob(0);
        assert_eq!(slot, 0);
        assert_eq!(
            [0, 8, 12, 24, 28, 32, 88].map(|at| big(directory, at)),
            [
                CODE_DIRECTORY_MAGIC,
                0x2_0500,
                0x1_0002,
                2,
                3,
                start as u32,
                SDK
            ]
        );
        assert_eq!(&directory[36..40], &[32, SHA256_TYPE, 0, 12]);
        let execution =
            [64, 72, 80].map(|at| u64::from_be_bytes(directory[at..at + 8].try_into().unwrap()));
        assert_eq!(execution, [0, CODE as u64, 1]);
        assert_eq!(&directory[96..101], b"mhfe\0");
        let hashes = big(directory, 16) as usize;
        let requirements: [u8; 32] = Sha256::digest(REQUIREMENTS).into();
        assert_eq!(directory[hashes - 64..hashes - 32], requirements);
        assert_eq!(directory[hashes - 32..hashes], [0; 32]);
        for (page, code) in bytes[..start].chunks(PAGE_BYTES).enumerate() {
            let expected: [u8; 32] = Sha256::digest(code).into();
            assert_eq!(
                directory[hashes + 32 * page..hashes + 32 * (page + 1)],
                expected
            );
        }
        assert_eq!((blob(1).0, &blob(1).1[..12]), (2, &REQUIREMENTS[..]));
        assert_eq!((blob(2).0, &blob(2).1[..8]), (0x1_0000, &BLOB_WRAPPER[..]));
    }

    /// The Intel program has no signature: it gets one, and the same bytes as a program that had
    /// one in the same place.
    #[test]
    fn a_program_without_a_signature_gets_the_same_one() {
        let unsigned = normalise(program([4; 16], false), "mhfe").unwrap();
        let signed = normalise(program([5; 16], true), "mhfe").unwrap();
        assert_eq!(unsigned, signed);
    }

    #[test]
    fn a_program_out_of_shape_is_refused() {
        let refused = |change: &dyn Fn(&mut Vec<u8>), why: &str| {
            let mut bytes = program([0; 16], true);
            change(&mut bytes);
            let error = normalise(bytes, "mhfe").unwrap_err();
            assert!(error.contains(why), "{error}");
        };
        refused(&|bytes| bytes.push(0), "not at the end of the file");
        refused(&|bytes| put_little(bytes, 12, 6), "MH_EXECUTE");
        refused(&|bytes| put_little(bytes, 4, 7), "neither x86-64 nor ARM64");
        refused(
            &|bytes| put_little(bytes, UUID - 24 - 8, 0x99),
            "no SDK version",
        );
        refused(&|bytes| bytes[LINKEDIT + 10] = b'X', "no __LINKEDIT");
        refused(
            &|bytes| put_long(bytes, LINKEDIT + 48, 4),
            "does not end the file",
        );
        refused(
            &|bytes| put_little(bytes, UUID - 4, 16),
            "shorter than its UUID",
        );
        // No room for the command: the first section starts right after the load commands.
        let mut bytes = program([0; 16], false);
        let end = SIGNATURE_COMMAND as u32;
        put_little(&mut bytes, HEADER_BYTES + SEGMENT_BYTES + 48, end);
        assert!(normalise(bytes, "mhfe").unwrap_err().contains("no room"));
        assert!(normalise(vec![0; 64], "mhfe").is_err());
    }
}
