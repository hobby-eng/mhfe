//! Compiles the vendored reference Argon2 code for native builds.
//!
//! The browser package does not use this: it compiles the same C code with Emscripten
//! (`scripts/build-argon2-wasm.sh`) and the WebAssembly core calls it through JavaScript.

use std::env;
use std::path::{Path, PathBuf};

const ARGON2_DIR: &str = "vendor/phc-winner-argon2";
/// Our own C file, not vendored: chooses the SSE2 or the SSSE3 copy of opt.c on x86-64.
const SIMD_CHOICE: &str = "src/engine/argon2_simd.c";

/// Library sources that every native build needs. The SIMD or the portable core is added below.
const COMMON_SOURCES: [&str; 5] = [
    "src/argon2.c",
    "src/core.c",
    "src/encoding.c",
    "src/thread.c",
    "src/blake2/blake2b.c",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={ARGON2_DIR}");
    println!("cargo:rerun-if-changed={SIMD_CHOICE}");

    let target_arch =
        env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets the target architecture");
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_arch == "wasm32" {
        return;
    }

    let argon2 = Path::new(ARGON2_DIR);
    let mut build = cc::Build::new();
    build
        .include(argon2.join("include"))
        .include(argon2.join("src"))
        .files(COMMON_SOURCES.iter().map(|source| argon2.join(source)))
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
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
        for (variant, flag) in [("sse2", "-msse2"), ("ssse3", "-mssse3")] {
            let renamed = format!("mhfe_fill_segment_{variant}");
            let objects = cc::Build::new()
                .include(argon2.join("include"))
                .include(argon2.join("src"))
                .file(argon2.join("src/opt.c"))
                // opt.c's only global function; the two copies need two names.
                .define("fill_segment", Some(renamed.as_str()))
                .flag(flag)
                .opt_level(3)
                .warnings(false)
                // Each copy in its own folder: both object files would otherwise be named opt.o.
                .out_dir(out_dir.join(format!("argon2-{variant}")))
                .compile_intermediates();
            build.objects(objects);
        }
        build.file(SIMD_CHOICE);
        build.flag("-msse2");
    } else {
        // ARM64, including Apple M-series, and every other architecture use the portable code.
        build.file(argon2.join("src/ref.c"));
    }

    if target_family == "unix" {
        // The four Argon2 lanes run on POSIX threads (Win32 threads on Windows).
        build.flag("-pthread");
    }

    build.compile("argon2");
}
