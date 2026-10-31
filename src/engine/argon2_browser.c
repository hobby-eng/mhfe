/*
 * MHFE's own C code around the vendored reference Argon2 code in the browser builds, which stays
 * unchanged. The bridge (web/argon2-engine.js) calls mhfe_argon2id_hash_raw(), never
 * argon2id_hash_raw(), and the vendored core.c calls the fill_segment() of this file, which runs a
 * renamed copy of the vendored one (src/engine/argon2-sources.txt). Both then clear the stack the
 * vendored code used: it holds values derived from the password, such as H0, the BLAKE2b state of
 * initial_hash() and the blocks a segment computes on the stack.
 *
 * mhfe_clear_stack() and fill_segment() are a deliberate copy of src/engine/argon2_wrap.c of
 * mhfe-core: the Emscripten stage of the canonical build runs before Cargo fetches that package,
 * and a later core drops the file. A change goes to both.
 */

#include <stddef.h>
#include <stdint.h>

#include "core.h"

/*
 * More than the deepest the vendored code writes in one call or one segment, about 5 KiB in the
 * single-threaded build, with a margin.
 */
#define MHFE_STACK_CLEAR_BYTES (16 * 1024)

/* The vendored fill_segment() of ref.c, renamed. */
void mhfe_fill_segment_ref(const argon2_instance_t *instance, argon2_position_t position);

/*
 * Not inlined, so that its array lies below the caller's frame, where the frames of the calls the
 * caller made before lay. Volatile stores, and a barrier the compiler cannot see through, keep the
 * writes, although nothing reads the array again.
 */
static __attribute__((noinline)) void mhfe_clear_stack(void) {
    volatile uint8_t stack[MHFE_STACK_CLEAR_BYTES];
    size_t at;
    for (at = 0; at < sizeof stack; at++) {
        stack[at] = 0;
    }
    __asm__ __volatile__("" : : "r"(stack) : "memory");
}

/*
 * The fill_segment() that core.c calls, on the calling thread in the single-threaded build and on
 * each lane's own thread in the threaded one: the vendored one fills one segment, then the stack
 * it used is cleared, as a lane thread's stack goes back to the heap unwiped when the thread exits.
 */
void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
    mhfe_fill_segment_ref(instance, position);
    mhfe_clear_stack();
}

int mhfe_argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                           const uint32_t parallelism, const void *pwd, const size_t pwdlen,
                           const void *salt, const size_t saltlen, void *hash,
                           const size_t hashlen) {
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash,
                                   hashlen);
    mhfe_clear_stack();
    return result;
}
