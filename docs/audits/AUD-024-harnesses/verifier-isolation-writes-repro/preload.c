/* AUD-024 verifier probe (reproduction lens). Preloaded into the real mhfe binary, it stands for
 * code running inside an isolated command (a compromised dependency). On the first write() or
 * writev() after the process has PR_SET_NO_NEW_PRIVS set (the first step of
 * protect::isolate_thread), it tries the file-system changes Landlock does not handle, on the file
 * named by AUD024_TARGET, and reports each result on file descriptor 2 with a raw system call.
 * Public data only: the attribute holds the BIP39 test phrase. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static const char PHRASE[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static int done;

static void say(const char *text) { syscall(SYS_write, 2, text, strlen(text)); }

static void result(const char *what, long r, int err) {
    char line[300];
    snprintf(line, sizeof line, "[aud024-probe] %s: %s\n", what,
             r >= 0 ? "ALLOWED" : (err == EACCES ? "refused (EACCES)" : strerror(err)));
    say(line);
}

static void status_line(const char *key) {
    char buffer[4096];
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    long n = read(fd, buffer, sizeof buffer - 1);
    close(fd);
    if (n <= 0) return;
    buffer[n] = 0;
    char *at = strstr(buffer, key);
    if (!at) return;
    char *end = strchr(at, '\n');
    char line[200];
    snprintf(line, sizeof line, "[aud024-probe] %.*s\n", (int)(end ? end - at : 60), at);
    say(line);
}

static void probe(void) {
    if (done || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return;
    done = 1;
    const char *path = getenv("AUD024_TARGET");
    if (!path) { say("[aud024-probe] AUD024_TARGET unset\n"); return; }
    say("[aud024-probe] isolated now (no_new_privs 1); trying writes\n");
    status_line("NoNewPrivs:");
    status_line("Seccomp:");
    {
        /* An empty uid_map: the process is in a user namespace of its own (and so its own network
         * namespace), as protect::namespace::enter_empty_network leaves a command started directly. */
        char map[256]; int fd = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC);
        long n = fd >= 0 ? read(fd, map, sizeof map - 1) : -1; if (fd >= 0) close(fd);
        say(n == 0 ? "[aud024-probe] uid_map empty: own user and network namespace\n"
                   : "[aud024-probe] uid_map not empty: no namespace of its own\n");
    }
    long r; int e;
    errno = 0; r = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); e = errno; if (r >= 0) close((int)r);
    result("socket(AF_INET, SOCK_DGRAM) (control: seccomp)", r, e);
    errno = 0; r = open("/dev/null", O_WRONLY | O_CLOEXEC); e = errno; if (r >= 0) close((int)r);
    result("open /dev/null O_WRONLY (the tool's own probe)", r, e);
    errno = 0; r = open(path, O_WRONLY | O_CLOEXEC); e = errno; if (r >= 0) close((int)r);
    result("open target O_WRONLY (control: Landlock WRITE_FILE)", r, e);
    char created[4096];
    snprintf(created, sizeof created, "%s.new", path);
    errno = 0; r = open(created, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); e = errno; if (r >= 0) close((int)r);
    result("create a new file (control: Landlock MAKE_REG)", r, e);
    errno = 0; r = setxattr(path, "user.aud024-path", PHRASE, sizeof PHRASE - 1, 0); e = errno;
    result("setxattr user.aud024-path = test phrase", r, e);
    errno = 0; r = chmod(path, 0644); e = errno;
    result("chmod 0644", r, e);
    struct timespec times[2] = {{1000000000, 0}, {1000000000, 0}};
    errno = 0; r = utimensat(AT_FDCWD, path, times, 0); e = errno;
    result("utimensat to 1000000000 (2001-09-09)", r, e);
    errno = 0; r = truncate(path, 7); e = errno;
    result("truncate by path to 7 bytes (Landlock TRUNCATE, ABI 3+)", r, e);
    int rfd = open(path, O_RDONLY | O_CLOEXEC);
    errno = 0; r = fsetxattr(rfd, "user.aud024-fd", PHRASE, sizeof PHRASE - 1, 0); e = errno;
    result("fsetxattr through a read-only descriptor", r, e);
    errno = 0; r = fchmod(rfd, 0640); e = errno;
    result("fchmod 0640 through a read-only descriptor", r, e);
    if (rfd >= 0) close(rfd);
    say("[aud024-probe] done\n");
}

ssize_t write(int fd, const void *buf, size_t count) {
    probe();
    return syscall(SYS_write, fd, buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    probe();
    return syscall(SYS_writev, fd, iov, iovcnt);
}
