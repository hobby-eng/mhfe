/*
 * AUD-024 gap-1-browser-argon2-heap-residue, native counterpart (reduced cost, public data only).
 *
 * Links the libargon2.a that `cargo build --release` of b6fca69 compiles from the vendored code
 * (build.rs: opt.c twice, SSE2 and SSSE3, chosen by src/engine/argon2_simd.c through bit 31 of
 * flags, as src/engine/ffi.rs sets it) and calls argon2_ctx exactly as ffi.rs does: four lanes on
 * four threads, version 0x13, the work area handed out by an allocation callback and kept by a
 * no-op free callback.
 *
 * 1. Reference: FLAG_clear_internal_memory = 0, so the work area keeps its blocks; the last block of
 *    each lane is read from it (RFC 9106 3.2: the tag is H'(XOR of the lanes' last blocks)).
 * 2. "Secret" call with the same inputs and FLAG_clear_internal_memory = 1, as in production; the
 *    work area is checked to be all zero.
 * 3. Every readable, writable private mapping of the process other than the work area is searched
 *    for each lane's last block, directly (opt.c keeps it in fill_segment's `state`) and as the XOR
 *    of two 1024-byte windows (ref.c's blockR and block_tmp).
 * 4. The tag is rebuilt from the bytes found and compared with the secret call's output.
 * 5. The search is repeated after a later call with other inputs (the 1 MiB known answer's), and
 *    after an unrelated thread has run.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "core.h"

extern int FLAG_clear_internal_memory;
int blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen);

#define BLOCK 1024
#define LANES 4
#define MHFE_FLAG_SSSE3 (UINT32_C(1) << 31)

static uint8_t *area;
static size_t area_bytes;

static int hand_out(uint8_t **memory, size_t bytes) {
    *memory = bytes <= area_bytes ? area : NULL;
    return 0;
}
static void keep(uint8_t *memory, size_t bytes) { (void)memory; (void)bytes; }

static int call(const char *password, const uint8_t salt[16], uint32_t kib, uint32_t passes,
                uint8_t out[32]) {
    argon2_context context;
    memset(&context, 0, sizeof context);
    context.out = out;
    context.outlen = 32;
    context.pwd = (uint8_t *)password;
    context.pwdlen = (uint32_t)strlen(password);
    context.salt = (uint8_t *)salt;
    context.saltlen = 16;
    context.t_cost = passes;
    context.m_cost = kib;
    context.lanes = LANES;
    context.threads = LANES;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = hand_out;
    context.free_cbk = keep;
    context.flags = __builtin_cpu_supports("ssse3") ? MHFE_FLAG_SSSE3 : 0;
    return argon2_ctx(&context, Argon2_id);
}

struct hits { int direct[LANES]; int pair[LANES]; uint8_t found[LANES][BLOCK]; char where[LANES][200]; };

/* Every buffer of this probe that holds a lane block lies in this one mapping, which the search
   skips, so that only the copies Argon2 left are counted. */
struct mine { uint8_t last[LANES][BLOCK]; struct hits hits; uint8_t x[BLOCK]; };
static struct mine *mine;

static int skipped(uintptr_t address, size_t length) {
    uintptr_t m = (uintptr_t)mine, a = (uintptr_t)area;
    return (address < m + sizeof *mine && m < address + length) ||
           (address < a + area_bytes && a < address + length);
}

/* glibc on this kernel installs thread-stack guards with MADV_GUARD_INSTALL, which /proc/self/maps
   shows as rw-p; reading through /proc/self/mem skips such pages instead of faulting. */
static void search(uint8_t (*last)[BLOCK], struct hits *hits) {
    memset(hits, 0, sizeof *hits);
    uintptr_t starts[512], ends[512];
    char names[512][64];
    int count = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    while (count < 512 && fgets(line, sizeof line, maps)) {
        uintptr_t start, end;
        char perms[5];
        char rest[400] = "";
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %*s %*s %*s %399[^\n]", &start, &end, perms,
                   rest) < 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        starts[count] = start;
        ends[count] = end;
        snprintf(names[count], sizeof names[count], "%s", rest[0] ? rest : "anonymous");
        count++;
    }
    fclose(maps);
    int mem = open("/proc/self/mem", O_RDONLY);
    long page = sysconf(_SC_PAGESIZE);
    for (int index = 0; index < count; index++) {
        size_t size = ends[index] - starts[index];
        uint8_t *copy = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (copy == MAP_FAILED) continue;
        for (size_t at = 0; at < size; at += (size_t)page) {
            if (skipped(starts[index] + at, (size_t)page) ||
                pread(mem, copy + at, (size_t)page, (off_t)(starts[index] + at)) != page)
                memset(copy + at, 0, (size_t)page);
        }
        for (size_t at = 0; at + 2 * BLOCK <= size; at += 8) {
            for (int lane = 0; lane < LANES; lane++) {
                if (memcmp(copy + at, last[lane], BLOCK) == 0) {
                    if (hits->direct[lane]++ == 0) {
                        memcpy(hits->found[lane], copy + at, BLOCK);
                        snprintf(hits->where[lane], sizeof hits->where[lane],
                                 "direct at 0x%" PRIxPTR " in the %zu KiB rw-p mapping at 0x%" PRIxPTR " (%s)",
                                 starts[index] + at, size / 1024, starts[index], names[index]);
                    }
                }
                uint64_t a, b, want;
                memcpy(&a, copy + at, 8);
                memcpy(&b, copy + at + BLOCK, 8);
                memcpy(&want, last[lane], 8);
                if ((a ^ b) == want) {
                    int whole = 1;
                    for (int i = 0; i < BLOCK && whole; i++)
                        whole = (uint8_t)(copy[at + i] ^ copy[at + BLOCK + i]) == last[lane][i];
                    if (whole && hits->pair[lane]++ == 0 && hits->direct[lane] == 0) {
                        for (int i = 0; i < BLOCK; i++)
                            hits->found[lane][i] = copy[at + i] ^ copy[at + BLOCK + i];
                        snprintf(hits->where[lane], sizeof hits->where[lane],
                                 "XOR pair at 0x%" PRIxPTR " in the %zu KiB rw-p mapping at 0x%" PRIxPTR " (%s)",
                                 starts[index] + at, size / 1024, starts[index], names[index]);
                    }
                }
            }
        }
        munmap(copy, size);
    }
    close(mem);
}

static int report(const char *when, uint8_t (*last)[BLOCK], const uint8_t tag[32]) {
    struct hits *h = &mine->hits;
    search(last, h);
    int all = 1;
    printf("%s:\n", when);
    for (int lane = 0; lane < LANES; lane++) {
        printf("  lane %d: direct copies %d, XOR pairs %d%s%s\n", lane, h->direct[lane],
               h->pair[lane], h->direct[lane] || h->pair[lane] ? "; first " : "",
               h->direct[lane] || h->pair[lane] ? h->where[lane] : "");
        all = all && (h->direct[lane] || h->pair[lane]);
    }
    if (all) {
        uint8_t rebuilt[32];
        memset(mine->x, 0, BLOCK);
        for (int lane = 0; lane < LANES; lane++)
            for (int i = 0; i < BLOCK; i++) mine->x[i] ^= h->found[lane][i];
        blake2b_long(rebuilt, 32, mine->x, BLOCK);
        int equal = memcmp(rebuilt, tag, 32) == 0;
        printf("  tag rebuilt from these bytes alone equals the secret call's output: %s\n",
               equal ? "YES" : "no");
        return equal;
    }
    printf("  tag cannot be rebuilt: not every lane's last block was found\n");
    return 0;
}

static void *unrelated(void *arg) {
    volatile uint8_t scratch[16384];
    memset((void *)scratch, 0x5a, sizeof scratch);
    return arg;
}

int main(int argc, char **argv) {
    uint32_t kib = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 32768;
    uint32_t passes = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) : 1;
    const char *password = "aud024-gap1-native-secret-password";
    uint8_t salt[16];
    for (int i = 0; i < 16; i++) salt[i] = (uint8_t)(0xa0 + i);
    area_bytes = (size_t)kib * 1024;
    area = aligned_alloc(16, area_bytes);
    mine = mmap(NULL, sizeof *mine, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!area || mine == MAP_FAILED) return 2;
    printf("cost %u KiB, %u pass(es), SSSE3 copy: %s\n", kib, passes,
           __builtin_cpu_supports("ssse3") ? "yes" : "no");

    /* 1. Reference run that keeps its blocks. */
    uint8_t tag_ref[32], tag[32];
    memset(area, 0, area_bytes);
    FLAG_clear_internal_memory = 0;
    if (call(password, salt, kib, passes, tag_ref) != ARGON2_OK) return 3;
    uint32_t lane_length = (uint32_t)(area_bytes / BLOCK / LANES);
    uint8_t (*last)[BLOCK] = mine->last;
    for (int lane = 0; lane < LANES; lane++)
        memcpy(last[lane], area + ((size_t)lane * lane_length + lane_length - 1) * BLOCK, BLOCK);
    uint8_t check[32];
    memset(mine->x, 0, BLOCK);
    for (int lane = 0; lane < LANES; lane++)
        for (int i = 0; i < BLOCK; i++) mine->x[i] ^= last[lane][i];
    blake2b_long(check, 32, mine->x, BLOCK);
    printf("reference: the tag is H'(XOR of the lanes' last blocks): %s\n",
           memcmp(check, tag_ref, 32) == 0 ? "yes" : "NO");

    /* Clear every copy the reference run left, so that only the secret call's can be found: run
       an unrelated call first, then wipe the area. */
    FLAG_clear_internal_memory = 1;
    uint8_t other[32];
    uint8_t salt2[16] = "0123456789abcdef";
    call("public test password", salt2, 1024, 1, other);
    memset(area, 0, area_bytes);
    report("before the secret call (after an unrelated 1 MiB call)", last, tag_ref);

    /* 2. The secret call, as production runs it. */
    if (call(password, salt, kib, passes, tag) != ARGON2_OK) return 4;
    int wiped = 1;
    for (size_t i = 0; i < area_bytes && wiped; i++) wiped = area[i] == 0;
    printf("secret call: output equals reference %s; work area all zero after the call: %s\n",
           memcmp(tag, tag_ref, 32) == 0 ? "yes" : "NO", wiped ? "yes" : "NO");
    int leaked = report("after the secret call returned (lane threads joined)", last, tag);

    /* 5. A later call with other inputs: the 1 MiB known answer's. */
    call("public test password", salt2, 1024, 1, other);
    report("after a later 1 MiB call with public inputs", last, tag);

    pthread_t thread;
    pthread_create(&thread, NULL, unrelated, NULL);
    pthread_join(thread, NULL);
    report("after an unrelated thread ran", last, tag);
    /* The check: no call's output may be rebuilt from memory once the call has returned. */
    printf(leaked ? "FAIL: the secret call's output was rebuilt from its lane-thread stacks\n"
                  : "PASS: nothing rebuilt\n");
    return leaked ? 1 : 0;
}
