//! Compiles the vendored reference Argon2 code for native builds.
//!
//! The browser package does not use this: it compiles the same C code with Emscripten
//! (`scripts/build-argon2-wasm.sh`) and the WebAssembly core calls it through JavaScript.

use std::env;
use std::path::Path;

const ARGON2_DIR: &str = "vendor/phc-winner-argon2";

/// Library sources that every native build needs. The SIMD or portable core is added below.
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
        // SSE2 is part of the x86-64 baseline, so this runs on every 64-bit x86 processor.
        // SSSE3 is not enabled by default: it crashes with "Illegal instruction" on common
        // virtual CPUs (upstream issue #308) and gains only about 5%. AVX2 is never used.
        build.file(argon2.join("src/opt.c"));
        build.flag_if_supported("-msse2");
        // Opt-in with `--features ssse3` for computers known to have SSSE3.
        if env::var_os("CARGO_FEATURE_SSSE3").is_some() {
            build.flag_if_supported("-mssse3");
        }
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
