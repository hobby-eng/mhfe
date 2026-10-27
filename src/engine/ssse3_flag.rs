//! MHFE's own bit in `argon2_context.flags`: run the copy of opt.c compiled with SSSE3 instead of
//! the SSE2 one, on x86-64. This file is its one source for both languages: src/engine/ffi.rs sets
//! it, and build.rs, which includes this file, gives its value to src/engine/argon2_simd.c as the C
//! macro of the same name. The vendored code reads only the two lowest bits of the flags.

/// Bit 31, far from the two bits include/argon2.h defines.
pub(super) const MHFE_FLAG_SSSE3: u32 = 1 << 31;
