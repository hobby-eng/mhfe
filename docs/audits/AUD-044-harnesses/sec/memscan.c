/*
 * AUD-044 SEC probe: where the bytes of public test secrets lie in a running mhfe. Loaded with
 * LD_PRELOAD into the unchanged program; it changes no protection of the program, and it needs
 * none switched off, since it reads the memory from inside the process.
 *
 *  - free() and a realloc() that moves a block: scans the block that goes back to the allocator
 *    for every needle, and logs "free <label> <size>", so a plain copy of a secret shows.
 *  - SIGUSR1: scans every readable and writable mapping, the dead part of the stacks included,
 *    but the program's secret memory, and logs "scan <region> <label> <count>"; the driver sends it
 *    at a chosen prompt. The same scan runs when the process ends through exit().
 *
 * Needles: file named by MEMSCAN_NEEDLES, one "<label> <hex>" per line. Log: descriptor 9, which the
 * driver opens before it starts the program, so that the isolation's refusal of new files does not
 * matter. Public test data only.
 *
 *   cc -shared -fPIC -O2 -o memscan.so memscan.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <malloc.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

extern void __libc_free(void *);
extern void *__libc_realloc(void *, size_t);

#define LOG_FD 9
#define MAX_NEEDLES 96
#define MAX_BYTES 96

static struct {
    char label[32];
    unsigned char bytes[MAX_BYTES];
    size_t length;
} needles[MAX_NEEDLES];
static int needle_count;

static void put(const char *text) { (void)!write(LOG_FD, text, strlen(text)); }

static void put_number(size_t value) {
    char digits[24];
    int at = sizeof digits;
    digits[--at] = 0;
    do {
        digits[--at] = '0' + value % 10;
        value /= 10;
    } while (value);
    put(digits + at);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

void memscan_on_signal(int signal);

/* The same scan when the process ends by exit(): what a finished command leaves. */
__attribute__((destructor)) static void scan_at_exit(void) {
    if (!needle_count) return;
    put("=== scan at: process exit\n");
    memscan_on_signal(0);
}

__attribute__((constructor)) static void load_needles(void) {
    static char text[32768];
    const char *path = getenv("MEMSCAN_NEEDLES");
    if (!path) return;
    int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) return;
    ssize_t size = read(file, text, sizeof text - 1);
    close(file);
    if (size <= 0) return;
    char *line = text;
    while (*line && needle_count < MAX_NEEDLES) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        char *gap = strchr(line, ' ');
        if (gap) {
            *gap = 0;
            size_t n = strlen(line);
            if (n >= sizeof needles[0].label) n = sizeof needles[0].label - 1;
            memcpy(needles[needle_count].label, line, n);
            size_t length = 0;
            for (char *at = gap + 1; at[0] && at[1] && length < MAX_BYTES; at += 2)
                needles[needle_count].bytes[length++] =
                    (unsigned char)(hex_value(at[0]) * 16 + hex_value(at[1]));
            needles[needle_count].length = length;
            needle_count++;
        }
        memset(line, 0, strlen(line));
        if (!end) break;
        line = end + 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = memscan_on_signal;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, 0);
}

static void scan_block(const void *block, size_t size, const char *what) {
    for (int i = 0; i < needle_count; i++) {
        if (memmem(block, size, needles[i].bytes, needles[i].length)) {
            put(what);
            put(" ");
            put(needles[i].label);
            put(" ");
            put_number(size);
            put("\n");
        }
    }
}

void free(void *block) {
    if (block && needle_count) scan_block(block, malloc_usable_size(block), "free");
    __libc_free(block);
}

void *realloc(void *block, size_t size) {
    if (!block || !needle_count) return __libc_realloc(block, size);
    size_t old = malloc_usable_size(block);
    static __thread unsigned char copy[65536];
    size_t kept = old < sizeof copy ? old : sizeof copy;
    memcpy(copy, block, kept);
    void *moved = __libc_realloc(block, size);
    if (moved != block) scan_block(copy, kept, "realloc-moved");
    memset(copy, 0, kept);
    return moved;
}

static uintptr_t parse_hex(const char **at) {
    uintptr_t value = 0;
    for (;;) {
        int digit = hex_value(**at);
        if (digit < 0) return value;
        value = value * 16 + digit;
        (*at)++;
    }
}

/* Read through process_vm_readv, not directly: a thread's stack holds guard pages that its mapping
 * does not show (MADV_GUARD_INSTALL), and such a read reports them instead of ending the process. */
#define WINDOW_BYTES (1 << 20)
static unsigned char window[WINDOW_BYTES + MAX_BYTES];

static int inside(uintptr_t address, const void *start, size_t size) {
    return address >= (uintptr_t)start && address < (uintptr_t)start + size;
}

static void scan_region(uintptr_t start, size_t size, const char *region) {
    static size_t counts[MAX_NEEDLES];
    memset(counts, 0, sizeof counts);
    uintptr_t at = start, end = start + size;
    size_t carry = 0;
    while (at < end) {
        size_t want = end - at < WINDOW_BYTES ? end - at : WINDOW_BYTES;
        struct iovec local = {window + carry, want}, remote = {(void *)at, want};
        ssize_t got = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        if (got <= 0) {
            at += 4096;
            carry = 0;
            continue;
        }
        size_t total = carry + (size_t)got;
        uintptr_t base = at - carry;
        for (int i = 0; i < needle_count; i++) {
            const unsigned char *from = window, *stop = window + total;
            while (from < stop) {
                const unsigned char *hit =
                    memmem(from, stop - from, needles[i].bytes, needles[i].length);
                if (!hit) break;
                from = hit + 1;
                /* A hit wholly inside the carried bytes was counted in the window before. */
                if ((size_t)(hit - window) + needles[i].length <= carry) continue;
                uintptr_t address = base + (size_t)(hit - window);
                if (inside(address, needles, sizeof needles) || inside(address, window, sizeof window))
                    continue;
                counts[i]++;
            }
        }
        carry = total < MAX_BYTES - 1 ? total : MAX_BYTES - 1;
        memmove(window, window + total - carry, carry);
        at += (size_t)got;
    }
    for (int i = 0; i < needle_count; i++) {
        if (counts[i]) {
            put("scan ");
            put(region);
            put(" ");
            put(needles[i].label);
            put(" ");
            put_number(counts[i]);
            put("\n");
        }
    }
}

void memscan_on_signal(int signal) {
    (void)signal;
    static char maps[1 << 20];
    int file = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (file < 0) {
        put("scan-failed\n");
        return;
    }
    size_t used = 0;
    for (;;) {
        ssize_t got = read(file, maps + used, sizeof maps - 1 - used);
        if (got <= 0) break;
        used += got;
    }
    close(file);
    maps[used] = 0;
    put("scan-begin\n");
    const char *line = maps;
    while (*line) {
        const char *at = line;
        const char *end = strchr(line, '\n');
        uintptr_t first = parse_hex(&at);
        at++;
        uintptr_t last = parse_hex(&at);
        at++;
        int writable = at[0] == 'r' && at[1] == 'w';
        size_t length = end ? (size_t)(end - line) : strlen(line);
        const char *region = "anonymous";
        if (memmem(line, length, "[heap]", 6)) region = "heap";
        else if (memmem(line, length, "[stack]", 7)) region = "main-stack";
        else if (memmem(line, length, "secretmem", 9)) region = "secretmem";
        else if (memmem(line, length, " /", 2)) region = "file";
        /* Secret memory is not read: a page never written would have to be faulted in, against
         * RLIMIT_MEMLOCK, which on this kernel ends the process with SIGBUS. */
        if (writable && (last - first) < (1ULL << 33) && strcmp(region, "secretmem") != 0)
            scan_region(first, last - first, region);
        if (!end) break;
        line = end + 1;
    }
    put("scan-end\n");
}
