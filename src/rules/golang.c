#include <stdio.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "../runner.h"


int golang_seccomp_rules(struct config *_config) {
    int syscalls_blacklist[] = {SCMP_SYS(fork), SCMP_SYS(vfork),
                                SCMP_SYS(kill), 
#ifdef __NR_execveat
                                SCMP_SYS(execveat)
#endif
                               };
    int syscalls_blacklist_length = sizeof(syscalls_blacklist) / sizeof(int);
    scmp_filter_ctx ctx = NULL;
    // load seccomp rules
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        return LOAD_SECCOMP_FAILED;
    }
    for (int i = 0; i < syscalls_blacklist_length; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscalls_blacklist[i], 0) != 0) {
            return LOAD_SECCOMP_FAILED;
        }
    }
    // socket fails with EACCES instead of killing the thread: glibc probes nscd via an AF_UNIX socket
    // when resolving users (e.g. the JVM at startup) and falls back to /etc/passwd on error
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 0) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    // do not allow "w" and "rw" using open
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    // do not allow "w" and "rw" using openat
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0) {
        return LOAD_SECCOMP_FAILED;
    }

    if (seccomp_load(ctx) != 0) {
        return LOAD_SECCOMP_FAILED;
    }
    seccomp_release(ctx);
    return 0;
}
