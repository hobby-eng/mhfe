/*
 * Chooses, for every Argon2 call on x86-64, between two compilations of the vendored opt.c: one
 * with SSE2, which every 64-bit x86 processor has, and one with SSSE3, 7 to 10% faster. build.rs
 * compiles opt.c twice and renames the two copies of its only global function, fill_segment, to
 * the names below; core.c calls fill_segment, which is this function.
 *
 * The choice travels in the context of the call, so two calls never share any state: src/engine/
 * ffi.rs sets MHFE_FLAG_SSSE3 in argon2_context.flags when the processor has SSSE3. The vendored
 * code reads only the two lowest bits of the flags (ARGON2_FLAG_CLEAR_PASSWORD and
 * ARGON2_FLAG_CLEAR_SECRET in include/argon2.h) and passes the context through unchanged.
 */

#include "core.h"

/* Must equal MHFE_FLAG_SSSE3 in src/engine/ffi.rs. */
#define MHFE_FLAG_SSSE3 (UINT32_C(1) << 31)

void mhfe_fill_segment_sse2(const argon2_instance_t *instance, argon2_position_t position);
void mhfe_fill_segment_ssse3(const argon2_instance_t *instance, argon2_position_t position);

void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
    if (instance->context_ptr->flags & MHFE_FLAG_SSSE3) {
        mhfe_fill_segment_ssse3(instance, position);
    } else {
        mhfe_fill_segment_sse2(instance, position);
    }
}
