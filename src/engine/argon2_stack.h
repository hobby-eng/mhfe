/*
 * Clears the stack below the caller after Argon2 fills a segment (AUD-024-SEC002). The vendored
 * fill_block keeps its two working blocks on the stack (ref.c: blockR and block_tmp; opt.c: state
 * and block_XY) and never wipes them, so the last block of each lane would stay on the stack of
 * the thread that filled it, and the call's output, a round key, can be rebuilt from those blocks
 * with one BLAKE2b. Our fill_segment calls this after the vendored one returns, on the same
 * thread: its frame starts where the vendored one's did and covers more than its depth (5,136
 * bytes were measured in the browser). The vendored files stay as they are.
 */

#ifndef MHFE_ARGON2_STACK_H
#define MHFE_ARGON2_STACK_H

#include <stddef.h>

#if defined(_MSC_VER)
#define MHFE_NOINLINE __declspec(noinline)
#else
#define MHFE_NOINLINE __attribute__((noinline))
#endif

/* Bytes cleared below the caller's frame: three times the deepest stack the fill was measured to
 * leave. */
#define MHFE_STACK_CLEARED 16384

static MHFE_NOINLINE void mhfe_clear_stack(void) {
    /* Volatile, so that the compiler keeps every write to an array that is never read. */
    volatile unsigned char area[MHFE_STACK_CLEARED];
    size_t i;
    for (i = 0; i < sizeof area; i++) {
        area[i] = 0;
    }
}

#endif
