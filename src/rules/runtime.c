#define _GNU_SOURCE
#include <stdio.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "../runner.h"

/*
 * Rule for language runtimes that need threads (JVM, Node.js, Go, Rust std::thread, PyPy).
 *
 * Threads are allowed, creating processes and executing other programs are not.
 * Forbidden calls fail with an errno instead of killing the calling thread: SCMP_ACT_KILL only kills
 * the thread, which may let a multi-threaded runtime exit silently with code 0 (e.g. the JVM).
 */
int runtime_seccomp_rules(struct config *_config) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        return LOAD_SECCOMP_FAILED;
    }
    // loaded in the judged process right before execve, so this is the pid of the program
    scmp_datum_t self = (scmp_datum_t) getpid();

#define ADD(action, syscall, ...) \
    if (seccomp_rule_add(ctx, action, syscall, __VA_ARGS__) != 0) { \
        seccomp_release(ctx); \
        return LOAD_SECCOMP_FAILED; \
    }

    // processes: clone is only allowed for threads
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0));
    // clone3 passes its flags in a struct seccomp cannot inspect, ENOSYS makes glibc fall back to clone
    ADD(SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fork), 0);
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(vfork), 0);
    // only the initial execve of the program itself
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t) (_config->exe_path)));
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execveat), 0);

    // signals: every submission runs as the same uid, only allow signalling itself
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kill), 1, SCMP_A0(SCMP_CMP_NE, self));
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(tgkill), 1, SCMP_A0(SCMP_CMP_NE, self));
    ADD(SCMP_ACT_ERRNO(EPERM), SCMP_SYS(tkill), 0);

    // network: glibc probes nscd with an AF_UNIX socket and falls back to files on error
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 0);

    // files may only be opened for reading (stdin/stdout/stderr are opened by the judger)
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY));
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR));
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY));
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR));
    ADD(SCMP_ACT_ERRNO(EACCES), SCMP_SYS(creat), 0);
    // openat2 passes its flags in a struct, ENOSYS makes callers fall back to openat
    ADD(SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(openat2), 0);

#undef ADD

    if (seccomp_load(ctx) != 0) {
        seccomp_release(ctx);
        return LOAD_SECCOMP_FAILED;
    }
    seccomp_release(ctx);
    return 0;
}
