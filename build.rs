//! Compiles the vendored reference Argon2 code for native builds.
//!
//! The browser package does not use this: it compiles the same C code with Emscripten
//! (`scripts/build-argon2-wasm.sh`) and the WebAssembly core calls it through JavaScript. Both
//! take the vendored files they share from one list, [`SOURCES`].

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

// The flag that runs the SSSE3 copy of the Argon2 core; src/engine/ffi.rs sets it.
#[path = "src/engine/ssse3_flag.rs"]
mod ssse3_flag;

const ARGON2_DIR: &str = "vendor/phc-winner-argon2";
/// Our own C file, not vendored: chooses the SSE2 or the SSSE3 copy of opt.c on x86-64.
const SIMD_CHOICE: &str = "src/engine/argon2_simd.c";
/// The vendored files of every build and the portable core, with the part each belongs to.
const SOURCES: &str = "src/engine/argon2-sources.txt";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SOURCES}");
    println!("cargo:rerun-if-changed=src/engine/ssse3_flag.rs");
    println!("cargo:rerun-if-changed={ARGON2_DIR}");
    println!("cargo:rerun-if-changed={SIMD_CHOICE}");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .map_err(|error| format!("Cargo sets no target architecture: {error}"))?;
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_arch == "wasm32" {
        return Ok(());
    }

    let list = fs::read_to_string(SOURCES).map_err(|error| format!("{SOURCES}: {error}"))?;
    let argon2 = Path::new(ARGON2_DIR);
    let mut build = cc::Build::new();
    build
        .include(argon2.join("include"))
        .include(argon2.join("src"))
        .files(files_of(&list, "common")?)
        // Always optimize the engine, also in debug and test builds: an unoptimized
        // Argon2 would make even small test runs slow.
        .opt_level(3)
        // The vendored code is kept unmodified, so its compiler warnings are not ours to fix.
        .warnings(false);

    if target_arch == "x86_64" {
        // One program for every 64-bit x86 processor: opt.c is compiled twice, with SSE2, part of
        // the x86-64 baseline, and with SSSE3, 7 to 10% faster, and src/engine/argon2_simd.c picks
        // one for every call from the processor's features. SSSE3 is never assumed: a program
        // that used it unconditionally would stop with "Illegal instruction" on common virtual
        // CPUs (upstream issue #308) and on AMD processors made before 2011. AVX2 is never used.
        //
        // Microsoft's cl takes no -m options (warning D9002) and needs none: it compiles SSE2 and
        // SSSE3 intrinsics as they are. It never defines __SSSE3__, though, which is what selects
        // the SSSE3 code in opt.c, so cl gets that macro directly. clang-cl takes -m options.
        let compiler = build.get_compiler();
        let microsoft_cl = compiler.is_like_msvc() && !compiler.is_like_clang_cl();
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo sets no OUT_DIR")?);
        for (variant, flag, cl_macro) in [
            ("sse2", "-msse2", None),
            ("ssse3", "-mssse3", Some("__SSSE3__")),
        ] {
            let renamed = format!("mhfe_fill_segment_{variant}");
            let mut copy = cc::Build::new();
            copy.include(argon2.join("include"))
                .include(argon2.join("src"))
                .file(argon2.join("src/opt.c"))
                // opt.c's only global function; the two copies need two names.
                .define("fill_segment", Some(renamed.as_str()))
                .opt_level(3)
                .warnings(false)
                // Each copy in its own folder: both object files would otherwise be named opt.o.
                .out_dir(out_dir.join(format!("argon2-{variant}")));
            if !microsoft_cl {
                copy.flag(flag);
            } else if let Some(name) = cl_macro {
                copy.define(name, None);
            }
            build.objects(copy.compile_intermediates());
        }
        let ssse3_flag = format!("UINT32_C({:#x})", ssse3_flag::MHFE_FLAG_SSSE3);
        build
            .file(SIMD_CHOICE)
            .define("MHFE_FLAG_SSSE3", Some(ssse3_flag.as_str()));
        if !microsoft_cl {
            build.flag("-msse2");
        }
    } else {
        // ARM64, including Apple M-series, and every other architecture use the portable code.
        build.files(files_of(&list, "portable")?);
    }

    if target_family == "unix" {
        // The four Argon2 lanes run on POSIX threads (Win32 threads on Windows).
        build.flag("-pthread");
    }

    build.compile("argon2");
    Ok(())
}

/// The files that `list`, the text of [`SOURCES`], gives for `part`, in the order listed. Every
/// line other than a blank line or a `#` comment must be `common <path>` or `portable <path>`.
fn files_of<'a>(list: &'a str, part: &str) -> Result<Vec<&'a str>, String> {
    let mut files = Vec::new();
    for line in list
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
    {
        match line.split_whitespace().collect::<Vec<&str>>()[..] {
            [line_part @ ("common" | "portable"), path] if line_part == part => files.push(path),
            ["common" | "portable", _] => {}
            _ => {
                return Err(format!(
                    "{SOURCES}: not \"common <path>\" or \"portable <path>\": {line}"
                ))
            }
        }
    }
    Ok(files)
}
