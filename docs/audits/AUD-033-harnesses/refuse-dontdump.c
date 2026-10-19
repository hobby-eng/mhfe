/* Public process-local fault injection: refuse only MADV_DONTDUMP. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
int madvise(void *address, size_t bytes, int advice) {
    if (advice == MADV_DONTDUMP) {
        static const char marker[] = "public-probe: MADV_DONTDUMP refused\n";
        ssize_t written = write(STDERR_FILENO, marker, sizeof(marker) - 1);
        (void)written;
        errno = EACCES;
        return -1;
    }
    int (*next)(void *, size_t, int) = dlsym(RTLD_NEXT, "madvise");
    if (next == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return next(address, bytes, advice);
}
