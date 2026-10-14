/* AUD-024, role verify-chosen-word-unlocked, commit b6fca69.
 *
 * An LD_PRELOAD shim for the mhfe binary. It records every mlock and munlock the program makes
 * (page by page), and each time the program is about to block in read() on standard input it
 * scans its own writable memory for a marker (the chosen word, typed in a mixed case that no
 * word list holds) and writes one line per scan to an already opened log: each hit's address,
 * whether its page is locked, whether it lies in the buffer the standard library reads standard
 * input into, and the allocator's size word in front of it when the hit starts a heap chunk.
 *
 * Environment: PROBE_LOG (log path, opened before the program isolates itself), PROBE_MARKER_HEX
 * (the marker in hex, so that the environment itself holds no copy of it).
 * Nothing else changes: the real read, mlock and munlock run as usual.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

static ssize_t (*real_read)(int, void *, size_t);
static int (*real_mlock)(const void *, size_t);
static int (*real_munlock)(const void *, size_t);

static int log_fd = -1;
static int maps_fd = -1;
static unsigned char marker[64];
static size_t marker_len;
static uintptr_t page_size = 4096;

#define MAX_PAGES 65536
static uintptr_t locked_pages[MAX_PAGES];
static size_t locked_count;

static uintptr_t stdin_buffer;
static size_t stdin_capacity;
static unsigned long scans;
static char maps[1 << 20];
static char line[4096];
static unsigned char window[1 << 16];

/* The shim's own buffers, which hold copies of what it scans. */
static int own(uintptr_t at) {
    return (at >= (uintptr_t)window && at < (uintptr_t)window + sizeof window)
        || (at >= (uintptr_t)maps && at < (uintptr_t)maps + sizeof maps)
        || (at >= (uintptr_t)line && at < (uintptr_t)line + sizeof line)
        || (at >= (uintptr_t)marker && at < (uintptr_t)marker + sizeof marker);
}

static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

__attribute__((constructor)) static void start(void) {
    real_read = dlsym(RTLD_NEXT, "read");
    real_mlock = dlsym(RTLD_NEXT, "mlock");
    real_munlock = dlsym(RTLD_NEXT, "munlock");
    page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    const char *path = getenv("PROBE_LOG");
    const char *text = getenv("PROBE_MARKER_HEX");
    if (path) log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    maps_fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (text) {
        size_t n = strlen(text) / 2;
        if (n > sizeof marker) n = sizeof marker;
        for (size_t i = 0; i < n; i++) marker[i] = (unsigned char)(hex(text[2 * i]) * 16 + hex(text[2 * i + 1]));
        marker_len = n;
    }
}

static int is_locked(uintptr_t page) {
    for (size_t i = 0; i < locked_count; i++)
        if (locked_pages[i] == page) return 1;
    return 0;
}

int mlock(const void *address, size_t length) {
    int result = real_mlock(address, length);
    if (result == 0 && length > 0) {
        uintptr_t first = (uintptr_t)address / page_size;
        uintptr_t last = ((uintptr_t)address + length - 1) / page_size;
        for (uintptr_t page = first; page <= last; page++)
            if (!is_locked(page) && locked_count < MAX_PAGES) locked_pages[locked_count++] = page;
    }
    return result;
}

int munlock(const void *address, size_t length) {
    int result = real_munlock(address, length);
    if (length > 0) {
        uintptr_t first = (uintptr_t)address / page_size;
        uintptr_t last = ((uintptr_t)address + length - 1) / page_size;
        for (uintptr_t page = first; page <= last; page++)
            for (size_t i = 0; i < locked_count; i++)
                if (locked_pages[i] == page) { locked_pages[i] = locked_pages[--locked_count]; break; }
    }
    return result;
}

static void put(const char *text) {
    if (log_fd >= 0) { ssize_t ignored = write(log_fd, text, strlen(text)); (void)ignored; }
}

static void scan(size_t count) {
    if (maps_fd < 0 || marker_len == 0) return;
    size_t size = 0;
    for (;;) {
        ssize_t got = pread(maps_fd, maps + size, sizeof maps - 1 - size, (off_t)size);
        if (got <= 0) break;
        size += (size_t)got;
    }
    maps[size] = 0;
    char head[256];
    snprintf(head, sizeof head, "scan %lu: read(0, count %zu), locked pages %zu, hits:", ++scans, count, locked_count);
    put(head);
    int hits = 0;
    char *cursor = maps;
    while (*cursor) {
        char *end = strchr(cursor, '\n');
        if (!end) break;
        *end = 0;
        unsigned long from, to;
        char perms[8] = {0};
        if (sscanf(cursor, "%lx-%lx %7s", &from, &to, perms) == 3 && perms[0] == 'r' && perms[1] == 'w'
            && !strstr(cursor, "locked_scan")) {
            /* Read through process_vm_readv, which reports a page that cannot be read instead of
             * faulting, in windows that overlap by the marker's length. */
            for (uintptr_t base = from; base < to; base += sizeof window - marker_len) {
                size_t want = to - base < sizeof window ? to - base : sizeof window;
                struct iovec local = {window, want}, remote = {(void *)base, want};
                ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
                if (got <= 0) continue;
                for (size_t i = 0; i + marker_len <= (size_t)got; i++) {
                    if (window[i] != marker[0] || memcmp(window + i, marker, marker_len) != 0) continue;
                    uintptr_t at = base + i;
                    if (own(at)) continue;
                    if (i + marker_len > (size_t)got) continue;
                    int in_stdin = stdin_capacity && at >= stdin_buffer && at < stdin_buffer + stdin_capacity;
                    unsigned long size_word = 0;
                    if ((at % 16) == 0 && i >= 8) memcpy(&size_word, window + i - 8, 8);
                    const char *region = strchr(cursor, '[') ? strchr(cursor, '[') : (strchr(cursor, '/') ? "file" : "anonymous");
                    snprintf(line, sizeof line, " [%#lx %s%s chunk-size-word=%#lx region=%s]", (unsigned long)at,
                             is_locked(at / page_size) ? "LOCKED" : "UNLOCKED", in_stdin ? " stdin-buffer" : "",
                             size_word, region);
                    put(line);
                    hits++;
                }
                if (want < sizeof window) break;
            }
        }
        cursor = end + 1;
    }
    snprintf(line, sizeof line, " total %d\n", hits);
    put(line);
}

ssize_t read(int fd, void *buffer, size_t count) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    if (fd == 0) {
        stdin_buffer = (uintptr_t)buffer;
        stdin_capacity = count;
        scan(count);
    }
    return real_read(fd, buffer, count);
}
