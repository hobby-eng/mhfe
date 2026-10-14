// AUD-024 harness (verify-reproduction), commit b6fca69: an LD_PRELOAD shim for mhfe.
// Default mode: every write to file descriptor 2 fails with ENOSPC, as on /dev/full, and the bytes
// the program tried to write there are copied to the file named by SHIM_LOG, opened before main.
// SHIM_MODE=watch: every write goes through, and one to descriptor 1 or 2 that fails is logged with
// its errno and bytes. mhfe sets PR_SET_DUMPABLE 0, which keeps a tracer such as strace from
// reading its memory, so this is how the text of a failing write, the default panic hook's
// message with its source location included, is seen.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int log_fd = -1;

__attribute__((constructor)) static void shim_open(void) {
    const char *path = getenv("SHIM_LOG");
    if (path != NULL) {
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd >= 0) {
            log_fd = fcntl(fd, F_DUPFD_CLOEXEC, 200);
            close(fd);
        }
    }
}

static void log_bytes(const void *buf, size_t count) {
    if (log_fd < 0) {
        return;
    }
    char head[64];
    int length = snprintf(head, sizeof head, "\n[fd2 write of %zu bytes -> ENOSPC] ", count);
    syscall(SYS_write, log_fd, head, (size_t)length);
    syscall(SYS_write, log_fd, buf, count);
}

static int watch_only(void) {
    const char *mode = getenv("SHIM_MODE");
    return mode != NULL && strcmp(mode, "watch") == 0;
}

// In watch mode every write goes through; one to descriptor 1 or 2 that fails is logged with its
// errno and its bytes, so that the panic text written after a failure shows where it came from.
static void log_failure(int fd, const void *buf, size_t count, int error) {
    if (log_fd < 0) {
        return;
    }
    char head[96];
    int length = snprintf(head, sizeof head, "\n[fd%d write of %zu bytes failed, errno %d] ", fd,
                          count, error);
    syscall(SYS_write, log_fd, head, (size_t)length);
    syscall(SYS_write, log_fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (fd == 2 && !watch_only()) {
        log_bytes(buf, count);
        errno = ENOSPC;
        return -1;
    }
    long result = syscall(SYS_write, fd, buf, count);
    if (result < 0 && (fd == 1 || fd == 2) && watch_only()) {
        int error = errno;
        log_failure(fd, buf, count, error);
        errno = error;
    }
    return result;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (fd == 2 && !watch_only()) {
        for (int i = 0; i < iovcnt; i++) {
            log_bytes(iov[i].iov_base, iov[i].iov_len);
        }
        errno = ENOSPC;
        return -1;
    }
    long result = syscall(SYS_writev, fd, iov, iovcnt);
    if (result < 0 && (fd == 1 || fd == 2) && watch_only()) {
        int error = errno;
        for (int i = 0; i < iovcnt; i++) {
            log_failure(fd, iov[i].iov_base, iov[i].iov_len, error);
        }
        errno = error;
    }
    return result;
}
