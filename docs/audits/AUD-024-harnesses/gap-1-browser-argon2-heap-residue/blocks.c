/*
 * AUD-024 gap-1-browser-argon2-heap-residue: reference blocks of one Argon2id call, computed natively
 * from the vendored portable code (ref.c, single-threaded: -DARGON2_NO_THREADS), with
 * FLAG_clear_internal_memory = 0 so that the work area keeps its blocks. Prints one JSON object:
 * the tag, the last block of each lane (RFC 9106 3.2: the tag is H'^T(XOR of them)), and the
 * first, second and middle block of each lane, which a wiped work area must not hold.
 *
 *   blocks <password hex> <salt hex> <memory KiB> <passes>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "core.h"

extern int FLAG_clear_internal_memory;
static uint8_t *area;
static size_t area_bytes;
static int hand_out(uint8_t **memory, size_t bytes) {
    *memory = bytes <= area_bytes ? area : NULL;
    return 0;
}
static void keep(uint8_t *memory, size_t bytes) { (void)memory; (void)bytes; }

static size_t unhex(const char *text, uint8_t *out) {
    size_t n = strlen(text) / 2;
    for (size_t i = 0; i < n; i++) sscanf(text + 2 * i, "%2hhx", &out[i]);
    return n;
}
static void hex(const uint8_t *bytes, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", bytes[i]);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    uint8_t password[4096], salt[64], tag[32];
    size_t password_len = unhex(argv[1], password), salt_len = unhex(argv[2], salt);
    uint32_t kib = (uint32_t)strtoul(argv[3], NULL, 10), passes = (uint32_t)strtoul(argv[4], NULL, 10);
    area_bytes = (size_t)kib * 1024;
    area = calloc(1, area_bytes);
    argon2_context c;
    memset(&c, 0, sizeof c);
    c.out = tag;
    c.outlen = 32;
    c.pwd = password;
    c.pwdlen = (uint32_t)password_len;
    c.salt = salt;
    c.saltlen = (uint32_t)salt_len;
    c.t_cost = passes;
    c.m_cost = kib;
    c.lanes = 4;
    c.threads = 1;
    c.version = ARGON2_VERSION_13;
    c.allocate_cbk = hand_out;
    c.free_cbk = keep;
    FLAG_clear_internal_memory = 0;
    int code = argon2_ctx(&c, Argon2_id);
    if (code != ARGON2_OK) return 3;
    uint32_t lane_length = (uint32_t)(area_bytes / 1024 / 4);
    printf("{\"tag\":\"");
    hex(tag, 32);
    printf("\",\"last\":[");
    for (uint32_t l = 0; l < 4; l++) {
        printf(l ? ",\"" : "\"");
        hex(area + ((size_t)l * lane_length + lane_length - 1) * 1024, 1024);
        printf("\"");
    }
    printf("],\"inner\":[");
    int first = 1;
    for (uint32_t l = 0; l < 4; l++) {
        uint32_t picks[3] = {0, 1, lane_length / 2};
        for (int p = 0; p < 3; p++) {
            printf(first ? "\"" : ",\"");
            first = 0;
            hex(area + ((size_t)l * lane_length + picks[p]) * 1024, 1024);
            printf("\"");
        }
    }
    printf("]}\n");
    return 0;
}
