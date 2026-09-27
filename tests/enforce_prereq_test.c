#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * B1/B3 privilege-identity and prerequisite honesty regression (Linux, needs the
 * enforced prerequisites).
 *
 * Every case asserts a create()/policy decision, so it is deterministic without
 * running a workload:
 *
 *   B1  drop_uid=0 / drop_gid=0 cannot establish ENFORCED (fail closed);
 *   B1  uid/gid values that do not round-trip through uid_t/gid_t are rejected
 *       (truncation to a different, possibly privileged, identity is refused);
 *   B1  a workload identity that owns/can-write the delegated cgroup hierarchy
 *       cannot establish ENFORCED;
 *   B3  an unusable protected record store cannot establish ENFORCED;
 *   B1  a normal unprivileged identity still establishes ENFORCED;
 *   B1  drop_uid=0 under ALLOW_BEST_EFFORT creates a domain but never at ENFORCED.
 *
 * The pre-B1/B3 backend fails these: it accepts drop_uid=0 and truncating
 * values, runs them at ENFORCED, and ignores the delegated-hierarchy hazard.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATE_DIR "/var/lib/procd"

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

static int level_of(procd_domain *d) {
    procd_domain_status st;
    if (procd_domain_status_get(d, &st) != 0) return -1;
    return (int)st.process_tree_termination;
}
static void own_cgroup(char *out, size_t n) {
    char b[512] = {0};
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (r < 0) r = 0;
    b[r] = 0;
    b[strcspn(b, "\n")] = 0;
    const char *rel = strrchr(b, ':') ? strrchr(b, ':') + 1 : "/";
    snprintf(out, n, "/sys/fs/cgroup%s", strcmp(rel, "/") == 0 ? "" : rel);
}

/* create with an explicit policy; returns status, fills *lvl when a domain was
 * made (and releases it). */
static procd_status try_create(procd_enforcement mode, int64_t uid, int64_t gid, int *lvl) {
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = mode;
    pol.drop_uid = uid;
    pol.drop_gid = gid;
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    if (lvl) *lvl = -1;
    if (rc == PROCD_OK && d) {
        if (lvl) *lvl = level_of(d);
        procd_domain_release(d);
    }
    return rc;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    const int64_t two32 = 1LL << 32;

    /* ---- B1: unsafe privileged identities cannot run ENFORCED ---- */
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, 0, 65534, NULL) == PROCD_E_UNSUPPORTED_ENFORCEMENT,
          "B1: drop_uid=0 refused under REQUIRE_ENFORCED");
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, 65534, 0, NULL) == PROCD_E_UNSUPPORTED_ENFORCEMENT,
          "B1: drop_gid=0 refused under REQUIRE_ENFORCED");

    /* ---- B1: non-representable (truncating) values are rejected ---- */
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, two32, 65534, NULL) == PROCD_E_INVALID_ARGUMENT,
          "B1: drop_uid=2^32 (would truncate to 0) rejected");
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, two32 + 1000, 65534, NULL) == PROCD_E_INVALID_ARGUMENT,
          "B1: drop_uid=2^32+1000 (would truncate to 1000) rejected");
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, 65534, two32, NULL) == PROCD_E_INVALID_ARGUMENT,
          "B1: drop_gid=2^32 rejected");
    /* even best-effort must not accept a non-representable identity */
    CHECK(try_create(PROCD_ALLOW_BEST_EFFORT, two32, 65534, NULL) == PROCD_E_INVALID_ARGUMENT,
          "B1: non-representable identity rejected even under ALLOW_BEST_EFFORT");

    /* ---- B1: normal unprivileged identity still qualifies ENFORCED ---- */
    int lvl = -1;
    CHECK(try_create(PROCD_REQUIRE_ENFORCED, 65534, 65534, &lvl) == PROCD_OK,
          "B1: default unprivileged identity creates an ENFORCED domain");
    CHECK(lvl == PROCD_CAP_ENFORCED, "B1: that domain's runtime level is ENFORCED");

    /* ---- B1: drop_uid=0 under best-effort creates, but never at ENFORCED ---- */
    lvl = -1;
    procd_status be = try_create(PROCD_ALLOW_BEST_EFFORT, 0, 0, &lvl);
    CHECK(be == PROCD_OK, "B1: drop_uid=0 accepted under ALLOW_BEST_EFFORT");
    CHECK(lvl != PROCD_CAP_ENFORCED, "B1: best-effort drop_uid=0 domain is NOT ENFORCED");

    /* ---- B3: unusable protected record store cannot run ENFORCED ---- */
    /* Make a domain first so the store exists, then make it world-writable. */
    (void)try_create(PROCD_REQUIRE_ENFORCED, 65534, 65534, NULL);
    struct stat sst;
    if (stat(STATE_DIR, &sst) == 0) {
        mode_t orig = sst.st_mode & 07777;
        CHECK(chmod(STATE_DIR, 0777) == 0, "B3: record store made world-writable for the check");
        CHECK(try_create(PROCD_REQUIRE_ENFORCED, 65534, 65534, NULL) == PROCD_E_PREREQUISITE,
              "B3: unusable (world-writable) record store refuses ENFORCED");
        chmod(STATE_DIR, orig);
        /* recovery restored */
        CHECK(try_create(PROCD_REQUIRE_ENFORCED, 65534, 65534, NULL) == PROCD_OK,
              "B3: ENFORCED works again once the store is restored");
    } else {
        printf("note: %s absent; skipping record-store case\n", STATE_DIR);
    }

    /* ---- B1: workload identity owning the delegated hierarchy cannot run ENFORCED ---- */
    char cg[512];
    own_cgroup(cg, sizeof cg);
    char deleg[600];
    snprintf(deleg, sizeof deleg, "%s/procd_deleg", cg);
    if (mkdir(deleg, 0755) == 0 && chown(deleg, 1000, 1000) == 0) {
        int pp[2];
        if (pipe(pp) == 0) {
            pid_t ch = fork();
            if (ch == 0) {
                close(pp[0]);
                /* place ourselves in the delegated cgroup (as root) so our
                 * /proc/self/cgroup - and thus the invocation cgroup's parent -
                 * is a hierarchy owned by uid 1000. */
                char procs[700];
                snprintf(procs, sizeof procs, "%s/cgroup.procs", deleg);
                char me[16];
                int n = snprintf(me, sizeof me, "%d", (int)getpid());
                int fd = open(procs, O_WRONLY | O_CLOEXEC);
                int moved = (fd >= 0 && write(fd, me, (size_t)n) == n);
                if (fd >= 0) close(fd);
                procd_status rc =
                    moved ? try_create(PROCD_REQUIRE_ENFORCED, 1000, 1000, NULL) : PROCD_E_IO;
                char r = (char)(moved && rc == PROCD_E_UNSUPPORTED_ENFORCEMENT ? 1 : 0);
                ssize_t w = write(pp[1], &r, 1);
                (void)w;
                _exit(0);
            }
            close(pp[1]);
            char r = 0;
            ssize_t rn = read(pp[0], &r, 1);
            close(pp[0]);
            waitpid(ch, NULL, 0);
            CHECK(rn == 1 && r == 1,
                  "B1: identity owning the delegated hierarchy refused ENFORCED");
        }
        rmdir(deleg);
    } else {
        printf("note: could not set up delegated hierarchy; skipping that case\n");
        rmdir(deleg);
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all prereq/identity checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: Linux-only prerequisite/identity regression\n");
    return 77;
}
#endif
