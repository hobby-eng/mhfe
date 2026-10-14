/*
 * Audit AUD-024 probe at commit b6fca69: does the vendored Argon2 C code (argon2_ctx, which
 * src/engine/ffi.rs calls) join a thread it has already joined when a thread creation fails?
 *
 * Linked with -Wl,--wrap=pthread_create,--wrap=pthread_join, so the unmodified vendored
 * thread.c calls the wrappers below. The create wrapper fails the Nth creation with EAGAIN, as a
 * pids or process limit would. The join wrapper records every joined handle and, instead of
 * joining a handle that was already joined and not handed out again by a later creation (a
 * second pthread_join of one thread, undefined behaviour under POSIX), counts it and returns
 * ESRCH, so the probe itself stays defined.
 *
 * Public, non-secret inputs only (a counter password and salt). About 64 KiB of memory per run.
 * Exit 0 when no case joins a thread twice, 1 when one does, 2 when a case's return code or
 * creation count is not the expected one.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "argon2.h"

int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg);
int __real_pthread_join(pthread_t thread, void **result);

static int creates;
static int fail_at;
static int joins;
static int double_joins;
static pthread_t joined[65536];
static int joined_count;

static void forget(pthread_t thread) {
    for (int i = 0; i < joined_count; ++i) {
        if (pthread_equal(joined[i], thread)) {
            joined[i] = joined[--joined_count];
            return;
        }
    }
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg) {
    ++creates;
    if (fail_at != 0 && creates == fail_at) {
        return EAGAIN;
    }
    int rc = __real_pthread_create(thread, attr, start, arg);
    if (rc == 0) {
        /* A new thread may get the handle of one joined before: it is a live thread now. */
        forget(*thread);
    }
    return rc;
}

int __wrap_pthread_join(pthread_t thread, void **result) {
    ++joins;
    for (int i = 0; i < joined_count; ++i) {
        if (pthread_equal(joined[i], thread)) {
            ++double_joins;
            return ESRCH;
        }
    }
    int rc = __real_pthread_join(thread, result);
    if (joined_count < (int)(sizeof joined / sizeof joined[0])) {
        joined[joined_count++] = thread;
    }
    return rc;
}

struct probe_case {
    const char *name;
    uint32_t lanes;
    uint32_t threads;
    int fail_at;
    int expected_code;
    int expected_creates; /* -1: not checked */
};

int main(void) {
    static const struct probe_case cases[] = {
        /* The shapes MHFE passes: threads == lanes (native.rs, rfc_inputs) or threads == 1. */
        {"lanes 4, threads 4, no failure", 4, 4, 0, ARGON2_OK, 16},
        {"lanes 4, threads 4, 3rd creation fails", 4, 4, 3, ARGON2_THREAD_FAIL, 3},
        {"lanes 4, threads 4, 7th creation fails", 4, 4, 7, ARGON2_THREAD_FAIL, 7},
        {"lanes 4, threads 1, no failure", 4, 1, 0, ARGON2_OK, 0},
        {"lanes 4, threads 1, 1st creation would fail", 4, 1, 1, ARGON2_OK, 0},
        {"lanes 3, threads 1, 1st creation would fail", 3, 1, 1, ARGON2_OK, 0},
        {"lanes 2, threads 2, 2nd creation fails", 2, 2, 2, ARGON2_THREAD_FAIL, 2},
        /* Shapes argon2id accepts but no caller passes: 1 < threads < lanes. */
        {"lanes 4, threads 2, no failure", 4, 2, 0, ARGON2_OK, 16},
        {"lanes 4, threads 2, 3rd creation fails", 4, 2, 3, ARGON2_THREAD_FAIL, 3},
        {"lanes 4, threads 2, 4th creation fails", 4, 2, 4, ARGON2_THREAD_FAIL, 4},
        {"lanes 4, threads 2, 7th creation fails", 4, 2, 7, ARGON2_THREAD_FAIL, 7},
        {"lanes 4, threads 3, 4th creation fails", 4, 3, 4, ARGON2_THREAD_FAIL, 4},
        {"lanes 3, threads 2, 3rd creation fails", 3, 2, 3, ARGON2_THREAD_FAIL, 3},
    };
    int any_double = 0;
    int any_unexpected = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        const struct probe_case *c = &cases[i];
        uint8_t out[32];
        uint8_t pwd[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t salt[16] = {0};
        argon2_context ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.out = out;
        ctx.outlen = sizeof out;
        ctx.pwd = pwd;
        ctx.pwdlen = sizeof pwd;
        ctx.salt = salt;
        ctx.saltlen = sizeof salt;
        ctx.t_cost = 1;
        ctx.m_cost = 64;
        ctx.lanes = c->lanes;
        ctx.threads = c->threads;
        ctx.version = ARGON2_VERSION_13;
        ctx.flags = ARGON2_DEFAULT_FLAGS;
        creates = 0;
        joins = 0;
        double_joins = 0;
        joined_count = 0;
        fail_at = c->fail_at;
        int code = argon2_ctx(&ctx, Argon2_id);
        int unexpected = code != c->expected_code ||
                         (c->expected_creates >= 0 && creates != c->expected_creates);
        printf("%-46s code %3d (%s), creations %2d, joins %2d, second joins %d%s\n", c->name,
               code, argon2_error_message(code), creates, joins, double_joins,
               unexpected ? "  UNEXPECTED" : "");
        any_double |= double_joins != 0;
        any_unexpected |= unexpected;
    }
    if (any_unexpected) {
        printf("FAIL: a case returned another code or creation count than expected\n");
        return 2;
    }
    if (any_double) {
        printf("FAIL: argon2_ctx joined a thread it had already joined after a failed "
               "creation\n");
        return 1;
    }
    printf("PASS: no case joined a thread twice\n");
    return 0;
}
