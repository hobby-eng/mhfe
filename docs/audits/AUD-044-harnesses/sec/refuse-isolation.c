/*
 * AUD-044 SEC probe: a kernel without seccomp filters or Landlock, as far as mhfe can tell. Loaded
 * with LD_PRELOAD into the unchanged program, it answers EINVAL to PR_SET_SECCOMP and ENOSYS to
 * landlock_create_ruleset, as such a kernel does, so that what the program says then can be read.
 *
 *   cc -shared -fPIC -O2 -o refuse-isolation.so refuse-isolation.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

int prctl(int option, ...) {
    va_list list;
    va_start(list, option);
    unsigned long a = va_arg(list, unsigned long), b = va_arg(list, unsigned long),
                  c = va_arg(list, unsigned long), d = va_arg(list, unsigned long);
    va_end(list);
    if (option == PR_SET_SECCOMP) {
        errno = EINVAL;
        return -1;
    }
    int (*real)(int, ...) = dlsym(RTLD_NEXT, "prctl");
    return real(option, a, b, c, d);
}

long syscall(long number, ...) {
    va_list list;
    va_start(list, number);
    long a = va_arg(list, long), b = va_arg(list, long), c = va_arg(list, long),
         d = va_arg(list, long), e = va_arg(list, long), f = va_arg(list, long);
    va_end(list);
    if (number == SYS_landlock_create_ruleset) {
        errno = ENOSYS;
        return -1;
    }
    long (*real)(long, ...) = dlsym(RTLD_NEXT, "syscall");
    return real(number, a, b, c, d, e, f);
}
