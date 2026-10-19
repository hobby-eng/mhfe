/* AUD-028: public C calls only; no Rust FFI or production-cost claim. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argon2.h"

static void *allocation;
static size_t allocation_bytes;
static int allocations, frees, dirty_free, refuse_allocation;

static int allocate_area(uint8_t **memory, size_t bytes) {
    if (refuse_allocation) { *memory = NULL; return -1; }
    if (allocation || bytes > 1024 * 1024) return -1;
    allocation = malloc(bytes);
    if (!allocation) return -1;
    allocation_bytes = bytes;
    allocations++;
    *memory = allocation;
    return 0;
}

static void free_area(uint8_t *memory, size_t bytes) {
    if (memory != allocation || bytes != allocation_bytes) abort();
    for (size_t i = 0; i < bytes; i++) dirty_free |= memory[i] != 0;
    free(memory);
    allocation = NULL;
    allocation_bytes = 0;
    frees++;
}

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(2); }
}

static void layout(void) {
    require(sizeof(argon2_context) == 120, "C context size differs");
    require(_Alignof(argon2_context) == 8, "C context alignment differs");
#define FIELD(name, offset) require(offsetof(argon2_context, name) == offset, "C offset: " #name)
    FIELD(out, 0); FIELD(outlen, 8); FIELD(pwd, 16); FIELD(pwdlen, 24);
    FIELD(salt, 32); FIELD(saltlen, 40); FIELD(secret, 48); FIELD(secretlen, 56);
    FIELD(ad, 64); FIELD(adlen, 72); FIELD(t_cost, 76); FIELD(m_cost, 80);
    FIELD(lanes, 84); FIELD(threads, 88); FIELD(version, 92);
    FIELD(allocate_cbk, 96); FIELD(free_cbk, 104); FIELD(flags, 112);
#undef FIELD
    puts("C ABI: size120 align8; 18 literal field offsets match recorded Rust layout");
}

static argon2_context rfc_context(uint8_t out[32], uint32_t threads) {
    /* RFC 9106 section 5.3: literal public input bytes. */
    static uint8_t password[32], salt[16], secret[8], ad[12];
    memset(password, 1, sizeof password); memset(salt, 2, sizeof salt);
    memset(secret, 3, sizeof secret); memset(ad, 4, sizeof ad);
    argon2_context context = {
        out, 32, password, 32, salt, 16, secret, 8, ad, 12,
        3, 32, 4, threads, ARGON2_VERSION_13, NULL, NULL, 0
    };
    return context;
}

static void known_answers(uint32_t flags, int wrong_expected) {
    /* RFC 9106 section5.3 and existing MHFE startup vector, independently literal. */
    const uint8_t rfc[32] = {
        0x0d,0x64,0x0d,0xf5,0x8d,0x78,0x76,0x6c,0x08,0xc0,0x37,0xa3,0x4a,0x8b,0x53,0xc9,
        0xd0,0x1e,0xf0,0x45,0x2d,0x75,0xb6,0x5e,0xb5,0x25,0x20,0xe9,0x6b,0x01,0xe6,0x59
    };
    const uint8_t mhfe[32] = {
        0xe0,0xe8,0xeb,0xa3,0x3f,0x14,0x04,0xa8,0x3c,0x91,0x1a,0x32,0x4d,0x9b,0x49,0xdb,
        0x83,0xda,0xe7,0x55,0xf2,0xbd,0xfb,0x4b,0x63,0x04,0x3c,0xa5,0xb7,0x12,0x5d,0xf2
    };
    for (uint32_t threads = 1; threads <= 4; threads += 3) {
        for (int custom = 0; custom < 2; custom++) {
            for (int vector = 0; vector < 2; vector++) {
                uint8_t output[32], expected[32];
                argon2_context context = rfc_context(output, threads);
                if (vector) {
                    context.pwd = (uint8_t *)"public test password";
                    context.pwdlen = 20;
                    context.salt = (uint8_t *)"0123456789abcdef";
                    context.saltlen = 16; context.secret = NULL; context.secretlen = 0;
                    context.ad = NULL; context.adlen = 0;
                    context.t_cost = 1; context.m_cost = 1024;
                }
                context.flags = flags;
                if (custom) { context.allocate_cbk = allocate_area; context.free_cbk = free_area; }
                memcpy(expected, vector ? mhfe : rfc, sizeof expected);
                if (wrong_expected) expected[0] ^= 1;
                int old_allocations = allocations, old_frees = frees;
                require(argon2_ctx(&context, Argon2_id) == ARGON2_OK, "Argon2 context failed");
                require(memcmp(output, expected, sizeof output) == 0, "tag mismatch");
                require(!allocation && !dirty_free, "C work area was not wiped before free");
                require(allocations == old_allocations + custom && frees == old_frees + custom,
                        "C allocator callback counts differ");
            }
        }
    }
    puts("PASS: 2 literal tags x threads1/4 x default/custom allocator; zero-before-free");
}

static void refusals(void) {
    uint8_t output[32];
    argon2_context context = rfc_context(output, 1), invalid;
    invalid = context; invalid.t_cost = 0;
    require(argon2_ctx(&invalid, Argon2_id) == ARGON2_TIME_TOO_SMALL, "time0 refusal differs");
    invalid = context; invalid.m_cost = 31;
    require(argon2_ctx(&invalid, Argon2_id) == ARGON2_MEMORY_TOO_LITTLE, "memory31 refusal differs");
    invalid = context; invalid.out = NULL;
    require(argon2_ctx(&invalid, Argon2_id) == ARGON2_OUTPUT_PTR_NULL, "null output refusal differs");
    invalid = context; invalid.allocate_cbk = allocate_area;
    require(argon2_ctx(&invalid, Argon2_id) == ARGON2_FREE_MEMORY_CBK_NULL, "callback refusal differs");
    invalid.free_cbk = free_area; refuse_allocation = 1;
    require(argon2_ctx(&invalid, Argon2_id) == ARGON2_MEMORY_ALLOCATION_ERROR, "allocator refusal differs");
    refuse_allocation = 0;
    require(!allocation && !dirty_free, "failed allocation retained a work area");
    puts("PASS: 5 exact public-C refusal codes");
}

int main(int argc, char **argv) {
    layout();
    int wrong = argc == 2 && strcmp(argv[1], "--wrong-expected") == 0;
    require(argc == 1 || wrong, "unknown audit harness operand");
    known_answers(0, wrong);
#if defined(MHFE_AUDIT_SIMD) && defined(__x86_64__)
    if (__builtin_cpu_supports("ssse3")) {
        known_answers(UINT32_C(1) << 31, wrong);
        puts("PASS: SSSE3 dispatch selected by actual host CPU support");
    } else puts("NOT RUN: SSSE3 unsupported by this CPU");
#endif
    refusals();
    return 0;
}
