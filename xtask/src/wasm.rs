//! `cargo xtask wasm <step>`: the steps of `scripts/build-wasm.sh` between the compilers, for the
//! browser package:
//!
//! - `remove-network-code argon2|glue FILE…` (`wasm/network.rs`): the network loaders of the
//!   Emscripten builds or of the wasm-bindgen glue become stubs that throw.
//! - `stamp-build-id DIR` (`wasm/stamp.rs`): the package's build, stamped into its parts.
//! - `package-manifest DIR` (`wasm/manifest.rs`): the package's `modules.json` and `README.md`.
//! - `verify DIR` (`wasm/verify.rs`): the checks of the built package that need no JavaScript
//!   engine.
//!
//! The paths are taken as given, from the folder the task runs in: `build-wasm.sh` runs at the
//! root.

mod manifest;
mod network;
mod other_build;
mod stamp;
mod verify;

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{Failure, at};

pub(crate) use other_build::{OTHER_BUILD, stamp_other_build};
pub(crate) use verify::vector_texts;

/// The custom section of `runtime/mhfe.wasm` that names the build; web/worker-runtime.js reads it.
const BUILD_SECTION: &str = "mhfe-build";
/// The id of a WebAssembly custom section.
const CUSTOM_SECTION_ID: u8 = 0;
/// The start of every WebAssembly module: the magic number `\0asm` and version 1.
const PREAMBLE: &[u8; 8] = b"\0asm\x01\0\0\0";
/// The most bytes of an unsigned LEB128 number of 32 bits, as WebAssembly's sizes.
const MOST_LEB128_BYTES: usize = 5;
const USAGE: &str = "usage: cargo xtask wasm <remove-network-code argon2|glue FILE… | \
                     stamp-build-id DIR | package-manifest DIR | verify DIR>";

/// Runs the step that `arguments` name.
pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    match arguments {
        [step, kind, files @ ..] if step == "remove-network-code" && !files.is_empty() => {
            network::run(kind, files)
        }
        [step, folder] if step == "stamp-build-id" => {
            let build = stamp::run(Path::new(folder))?;
            println!("Stamped build {build} into the package.");
            Ok(())
        }
        [step, folder] if step == "package-manifest" => manifest::run(root, Path::new(folder)),
        [step, folder] if step == "verify" => verify::run(root, Path::new(folder)),
        _ => Err(Failure(USAGE.to_owned())),
    }
}

/// The bytes of `path`.
fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|error| at(path, error))
}

/// The text of `path`, which must be UTF-8.
fn text(path: &Path) -> Result<String, Failure> {
    String::from_utf8(read(path)?).map_err(|error| at(path, error))
}

/// Writes `bytes` into `path`.
fn write(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(), Failure> {
    std::fs::write(path, bytes).map_err(|error| at(path, error))
}

/// The SHA-256 of `bytes` in lowercase hex, as `sha256sum` prints it.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The contents of the custom sections `name` of the WebAssembly module `module`, in their order;
/// `path` names the file in a failure. The module is read section by section: the preamble, then
/// for each section its id, its size and its bytes, a custom section starting with its name. It is
/// not validated further: every browser check instantiates it.
fn custom_sections<'a>(
    module: &'a [u8],
    name: &str,
    path: &Path,
) -> Result<Vec<&'a [u8]>, Failure> {
    let malformed = || Failure(format!("{} is not a WebAssembly module", path.display()));
    let mut rest = module.strip_prefix(PREAMBLE).ok_or_else(malformed)?;
    let mut found = Vec::new();
    while let Some((&id, after)) = rest.split_first() {
        let (size, after) = leb128_read(after).ok_or_else(malformed)?;
        let (section, after) = after.split_at_checked(size).ok_or_else(malformed)?;
        rest = after;
        if id == CUSTOM_SECTION_ID {
            let (length, named) = leb128_read(section).ok_or_else(malformed)?;
            let (own, content) = named.split_at_checked(length).ok_or_else(malformed)?;
            if own == name.as_bytes() {
                found.push(content);
            }
        }
    }
    Ok(found)
}

/// The unsigned LEB128 number that starts `bytes`, and the bytes after it, or None when no number
/// of five bytes at most, as WebAssembly's sizes take, starts there.
fn leb128_read(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0;
    for (index, &byte) in bytes.iter().enumerate().take(MOST_LEB128_BYTES) {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, bytes.get(index + 1..)?));
        }
    }
    None
}

/// `value` as an unsigned LEB128 number, as WebAssembly encodes sizes: seven bits a byte, low bits
/// first.
fn leb128(value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut rest = value;
    loop {
        let low = rest.to_le_bytes()[0] & 0x7f;
        rest >>= 7;
        if rest == 0 {
            bytes.push(low);
            return bytes;
        }
        bytes.push(low | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_numbers_are_written_and_read_back() {
        for (value, encoded) in [
            (0, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (624_485, &[0xe5, 0x8e, 0x26]),
        ] {
            assert_eq!(leb128(value), encoded);
            assert_eq!(leb128_read(encoded), Some((value, &[][..])));
        }
        assert_eq!(leb128_read(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]), None);
    }

    #[test]
    fn the_custom_sections_of_a_name_are_found_past_other_sections() {
        let mut module = PREAMBLE.to_vec();
        // A type section with no types, then two custom sections.
        module.extend([1, 1, 0]);
        for (name, content) in [
            ("other", "x"),
            (BUILD_SECTION, "0123"),
            (BUILD_SECTION, "4567"),
        ] {
            let mut body = leb128(name.len());
            body.extend(name.as_bytes());
            body.extend(content.as_bytes());
            module.push(CUSTOM_SECTION_ID);
            module.extend(leb128(body.len()));
            module.extend(body);
        }
        let path = Path::new("m.wasm");
        let found = custom_sections(&module, BUILD_SECTION, path).ok();
        assert_eq!(found, Some(vec![&b"0123"[..], &b"4567"[..]]));
        assert_eq!(custom_sections(&module, "none", path).ok(), Some(vec![]));
        assert!(custom_sections(&module[..module.len() - 1], "none", path).is_err());
        assert!(custom_sections(b"\0asm\x02\0\0\0", "none", path).is_err());
    }
}
