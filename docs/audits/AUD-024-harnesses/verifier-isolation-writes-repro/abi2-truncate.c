/* AUD-024 verifier: applies the Landlock mask that src/bin/mhfe/protect/landlock.rs:48-60 builds
 * when the kernel reports ABI 2 (Linux 5.19 to 6.1; ABI 1 is the same without REFER) and the ABI 3
 * mask it builds on Linux 6.2+, each in a forked child, then tries open(O_WRONLY) and
 * truncate(path, 0). Exits 1 if truncate gets through the ABI-2 mask. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct attr { uint64_t fs; };
static int child(const char *label, uint64_t mask, const char *path) {
    struct attr a = { mask };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 2;
    long fd = syscall(SYS_landlock_create_ruleset, &a, sizeof a, 0);
    if (fd < 0) return 3;
    if (syscall(SYS_landlock_restrict_self, (int)fd, 0)) return 4;
    close((int)fd);
    int w = open(path, O_WRONLY | O_CLOEXEC); int ew = errno; if (w >= 0) close(w);
    int t = truncate(path, 0); int et = errno;
    printf("%s: open O_WRONLY %s; truncate(path, 0) %s\n", label,
           w >= 0 ? "ALLOWED" : strerror(ew), t == 0 ? "ALLOWED" : strerror(et));
    fflush(stdout);
    return t == 0 ? 1 : 0;
}
int main(int argc, char **argv) {
    const uint64_t base = (1ull<<1)|(1ull<<4)|(1ull<<5)|(1ull<<6)|(1ull<<7)|(1ull<<8)|(1ull<<9)|(1ull<<10)|(1ull<<11)|(1ull<<12);
    const uint64_t abi2 = base | (1ull<<13), abi3 = abi2 | (1ull<<14);
    char path[4096]; snprintf(path, sizeof path, "%s/abi2-truncate-%d.txt", argc > 1 ? argv[1] : "/tmp", getpid());
    setvbuf(stdout, NULL, _IONBF, 0);
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, 1);
    printf("kernel Landlock ABI: %ld\n", abi);
    int rc_abi2 = 0;
    struct { const char *label; uint64_t mask; } cases[] = {{"mask of ABI 1-2 (Linux 5.13-6.1)", abi2}, {"mask of ABI 3+ (Linux 6.2+)", abi3}};
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(path, "w"); fputs("public test content\n", f); fclose(f);
        pid_t p = fork();
        if (p == 0) _exit(child(cases[i].label, cases[i].mask, path));
        int st; waitpid(p, &st, 0);
        struct stat s; stat(path, &s);
        printf("  size afterwards: %lld (was 20)\n", (long long)s.st_size);
        if (i == 0) rc_abi2 = WIFEXITED(st) ? WEXITSTATUS(st) : 9;
    }
    unlink(path);
    printf(rc_abi2 == 1 ? "FAIL: truncate by path gets through the ABI 1-2 mask\n" : "PASS\n");
    return rc_abi2 == 1;
}
