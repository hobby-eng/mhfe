/*
 * AUD-044 SEC probe: what the isolation of a command refuses, tried from inside the unchanged
 * program. Loaded with LD_PRELOAD; when the process ends through exit(), that is after
 * Isolation::enter, it makes each call once on a file of its own folder, and logs the call and its
 * error to descriptor 9. A public test folder only: PROBE_DIR holds a file "target" made for this.
 *
 *   cc -shared -fPIC -O2 -o isolation-probe.so isolation-probe.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

static void report(const char *name, long result) {
    char line[160];
    int n = snprintf(line, sizeof line, "%-28s %s\n", name,
                     result < 0 ? strerror(errno) : "ALLOWED");
    (void)!write(9, line, n);
}

__attribute__((destructor)) static void probe(void) {
    const char *dir = getenv("PROBE_DIR");
    if (!dir) return;
    char target[512], other[512];
    snprintf(target, sizeof target, "%s/target", dir);
    snprintf(other, sizeof other, "%s/other", dir);
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    report("open read-only", fd);
    report("open O_WRONLY", open(target, O_WRONLY));
    report("open O_RDWR", open(target, O_RDWR));
    report("open O_CREAT", open(other, O_CREAT | O_WRONLY | O_EXCL, 0600));
    report("open O_TMPFILE", open(dir, O_TMPFILE | O_RDWR, 0600));
    report("creat", creat(other, 0600));
    report("mkdir", mkdir(other, 0700));
    report("mknod fifo", mknod(other, S_IFIFO | 0600, 0));
    report("link", link(target, other));
    report("symlink", symlink(target, other));
    report("rename", rename(target, other));
    report("unlink", unlink(target));
    report("truncate", truncate(target, 0));
    report("chmod", chmod(target, 0644));
    report("fchmod on read-only fd", fchmod(fd, 0644));
    report("chown", chown(target, getuid(), getgid()));
    struct timespec times[2] = {{0, UTIME_OMIT}, {0, UTIME_NOW}};
    report("utimensat", utimensat(AT_FDCWD, target, times, 0));
    report("setxattr", setxattr(target, "user.audit", "x", 1, 0));
    report("fsetxattr on read-only fd", fsetxattr(fd, "user.audit", "x", 1, 0));
    report("removexattr", removexattr(target, "user.audit"));
    int flags = 0;
    report("ioctl FS_IOC_SETFLAGS", ioctl(fd, FS_IOC_SETFLAGS, &flags));
    report("ioctl FIONREAD", ioctl(fd, FIONREAD, &flags));
    char byte = 'x';
    report("ioctl TIOCSTI", ioctl(0, TIOCSTI, &byte));
    report("mount tmpfs", mount("none", dir, "tmpfs", 0, 0));
    report("socket AF_INET", socket(AF_INET, SOCK_STREAM, 0));
    report("socket AF_UNIX", socket(AF_UNIX, SOCK_STREAM, 0));
    int pair[2];
    report("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    report("io_uring_setup", syscall(SYS_io_uring_setup, 1, (void *)0));
    report("ptrace TRACEME", syscall(SYS_ptrace, 0, 0, 0, 0));
    report("process_vm_writev", syscall(SYS_process_vm_writev, getppid(), 0, 0, 0, 0, 0));
    report("pidfd_getfd", syscall(SYS_pidfd_getfd, -1, 0, 0));
    report("fallocate on read-only fd", fallocate(fd, 0, 0, 1));
    report("openat2", syscall(SYS_openat2, AT_FDCWD, target, (void *)0, 0));
    report("memfd_create", syscall(SYS_memfd_create, "x", 0));
    report("unshare CLONE_NEWNS", unshare(CLONE_NEWNS));
    report("call beyond the table", syscall(999));
}
