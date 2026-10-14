/*
 * The vendored portable fill, ref.c, under another name, and the fill_segment that core.c calls:
 * the vendored one, then a clear of the stack it leaves (argon2_stack.h, AUD-024-SEC002). Used
 * natively on every processor but x86-64, and by both browser builds (scripts/build-argon2-wasm.sh).
 * ref.c is included unchanged; its own includes resolve beside it, in the vendored src folder.
 */

#define fill_segment mhfe_vendored_fill_segment
#include "ref.c"
#undef fill_segment

#include "argon2_stack.h"

void fill_segment(const argon2_instance_t *instance, argon2_position_t position);

void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
    /* Called through a volatile pointer, so that the vendored fill is never inlined here and its
     * frame lies where the clear's frame comes after it. */
    void (*volatile vendored)(const argon2_instance_t *, argon2_position_t) =
        mhfe_vendored_fill_segment;
    vendored(instance, position);
    mhfe_clear_stack();
}
