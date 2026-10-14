/* AUD-024 verifier probe (scratch). LD_PRELOAD into the real mhfe release binary at b6fca69.
 * On the first read() of standard input, which a secret command makes only after
 * protect::isolate (main.rs:302) has applied no_new_privs, the namespace, Landlock and seccomp,
 * it tries from inside the isolated process: the tool's own /dev/null probe, a UDP socket,
 * opening the scratch file for writing, then setxattr / fsetxattr (on a descriptor opened
 * read-only) holding the public BIP39 test phrase, chmod, utimensat and truncate. Results go to
 * standard error; nothing else is changed. Public data only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static const char PHRASE[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static int done = 0;

static void say(const char *what, int rc, int err) {
    char line[256];
    int n;
    if (rc == 0) n = snprintf(line, sizeof line, "[probe] %s: ALLOWED\n", what);
    else n = snprintf(line, sizeof line, "[probe] %s: refused, errno %d (%s)\n", what, err, strerror(err));
    (void)!write(2, line, n);
}

static void status_lines(void) {
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[8192];
    ssize_t n = 0, r;
    while ((r = syscall(0 /* SYS_read */, fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    for (char *l = strtok(buf, "\n"); l; l = strtok(NULL, "\n"))
        if (!strncmp(l, "NoNewPrivs", 10) || !strncmp(l, "Seccomp", 7)) {
            char out[128];
            int m = snprintf(out, sizeof out, "[probe] /proc/self/status %s\n", l);
            (void)!write(2, out, m);
        }
}

static void probes(void) {
    const char *file = getenv("AUD024_PROBE_FILE");
    if (!file) return;
    status_lines();
    int fd, rc, e;
    fd = open("/dev/null", O_WRONLY | O_CLOEXEC); e = errno;
    say("open /dev/null for writing (the tool's own probe)", fd >= 0 ? 0 : -1, e); if (fd >= 0) close(fd);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); e = errno;
    say("socket(AF_INET, SOCK_DGRAM)", fd >= 0 ? 0 : -1, e); if (fd >= 0) close(fd);
    fd = open(file, O_WRONLY | O_CLOEXEC); e = errno;
    say("open the scratch file for writing", fd >= 0 ? 0 : -1, e); if (fd >= 0) close(fd);
    rc = setxattr(file, "user.aud024-verify-path", PHRASE, strlen(PHRASE), 0); e = errno;
    say("setxattr by path (test phrase)", rc, e);
    fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { rc = fsetxattr(fd, "user.aud024-verify-fd", PHRASE, strlen(PHRASE), 0); e = errno; close(fd); }
    else { rc = -1; e = errno; }
    say("fsetxattr on a descriptor opened read-only (test phrase)", rc, e);
    rc = chmod(file, 0644); e = errno; say("chmod 0644", rc, e);
    struct timespec t[2] = {{1000000000, 0}, {1000000000, 0}};
    rc = utimensat(AT_FDCWD, file, t, 0); e = errno; say("utimensat to 2001-09-09", rc, e);
    rc = truncate(file, 0); e = errno; say("truncate to 0 bytes", rc, e);
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real)(int, void *, size_t) = NULL;
    if (!real) real = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    if (fd == 0 && !done) { done = 1; probes(); }
    return real(fd, buf, count);
}
