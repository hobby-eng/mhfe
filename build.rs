//! Compiles the vendored reference Argon2 code for native builds, and cuts the password cases
//! out of the suite 3 validation fixture for every build.
//!
//! The browser package does not use this: it compiles the same C code with Emscripten
//! (`scripts/build-argon2-wasm.sh`) and the WebAssembly core calls it through JavaScript.

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

const ARGON2_DIR: &str = "vendor/phc-winner-argon2";
/// Our own C files, not vendored: one chooses the SSE2 or the SSSE3 copy of opt.c on x86-64, the
/// other holds ref.c elsewhere; both clear the stack a segment's fill leaves (argon2_stack.h).
const SIMD_CHOICE: &str = "src/engine/argon2_simd.c";
const PORTABLE_FILL: &str = "src/engine/argon2_ref.c";
const STACK_CLEAR: &str = "src/engine/argon2_stack.h";

/// Library sources that every native build needs. The SIMD or the portable core is added below.
const COMMON_SOURCES: [&str; 5] = [
    "src/argon2.c",
    "src/core.c",
    "src/encoding.c",
    "src/thread.c",
    "src/blake2/blake2b.c",
];

/// The suite 3 validation fixture, whose `passwords` section the passwords module reads alone.
const VALIDATION_FIXTURE: &str = "tests/fixtures/validation-cases.json";

/// Writes the `passwords` section of [`VALIDATION_FIXTURE`] as a fixture of its own to
/// `OUT_DIR/validation-passwords.json`, so that a build with the passwords module alone carries
/// the password cases and none of the cases of the formats check (AUD-023-BLD009). The fixture is
/// written with two spaces per level, so the section ends at the first `]` at its own level.
fn write_password_cases(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={VALIDATION_FIXTURE}");
    let fixture = std::fs::read_to_string(VALIDATION_FIXTURE)
        .map_err(|error| format!("{VALIDATION_FIXTURE}: {error}"))?;
    let start = fixture
        .find("\n  \"passwords\": [")
        .ok_or("the fixture has no passwords section")?;
    let length = fixture[start..]
        .find("\n  ]")
        .ok_or("the passwords section does not end")?
        + "\n  ]".len();
    std::fs::write(
        out_dir.join("validation-passwords.json"),
        format!("{{{}\n}}\n", &fixture[start..start + length]),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo sets no OUT_DIR")?);
    write_password_cases(&out_dir)?;
    println!("cargo:rerun-if-changed={ARGON2_DIR}");
    println!("cargo:rerun-if-changed={SIMD_CHOICE}");
    println!("cargo:rerun-if-changed={PORTABLE_FILL}");
    println!("cargo:rerun-if-changed={STACK_CLEAR}");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_arch == "wasm32" {
        return Ok(());
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
        //
        // Microsoft's cl takes no -m options (warning D9002) and needs none: it compiles SSE2 and
        // SSSE3 intrinsics as they are. It never defines __SSSE3__, though, which is what selects
        // the SSSE3 code in opt.c, so cl gets that macro directly. clang-cl takes -m options.
        let compiler = build.get_compiler();
        let microsoft_cl = compiler.is_like_msvc() && !compiler.is_like_clang_cl();
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
        build.file(SIMD_CHOICE);
        if !microsoft_cl {
            build.flag("-msse2");
        }
    } else {
        // ARM64, including Apple M-series, and every other architecture use the portable code.
        build.file(PORTABLE_FILL);
    }

    if target_family == "unix" {
        // The four Argon2 lanes run on POSIX threads (Win32 threads on Windows).
        build.flag("-pthread");
    }

    build.compile("argon2");
    Ok(())
}
