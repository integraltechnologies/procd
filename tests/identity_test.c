#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Workload identity regression (Linux, cgroup-v2 lifecycle host).
 *
 * procd does not choose a workload identity. The task runs with the caller's
 * credentials unless an explicit run-as uid/gid is requested, and the lifecycle
 * level never depends on it. Checked independently of procd via the live
 * /proc/<pid>/status of the spawned workload:
 *
 *   - default policy (-1/-1): real/effective/saved/fs uid and gid equal the
 *     caller's, and the domain is ENFORCED whatever the caller's uid is;
 *   - uid/gid values that do not round-trip through uid_t/gid_t (or are
 *     negative other than -1) are rejected at create in either mode;
 *   - as root, an explicit run-as 4321:4321 is fully applied (all four ids) and
 *     root's supplementary groups are dropped;
 *   - as a non-root caller, a run-as it cannot establish fails the spawn and
 *     runs nothing.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
/* Parse the numbers after "<key>:" in /proc/<pid>/status (4 for Uid/Gid,
 * 0.. for Groups). Returns how many were read, -1 if unreadable. */
static int status_ids(pid_t pid, const char *key, long v[], int max) {
    char p[64], buf[4096];
    snprintf(p, sizeof p, "/proc/%d/status", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (r <= 0) return -1;
    buf[r] = 0;
    char k[32];
    snprintf(k, sizeof k, "\n%s:", key);
    char *s = strstr(buf, k);
    if (!s) return -1;
    s += strlen(k);
    int n = 0;
    while (n < max) {
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s < '0' || *s > '9') break;
        v[n++] = strtol(s, &s, 10);
    }
    return n;
}
static int all_eq(const long v[4], long want) {
    return v[0] == want && v[1] == want && v[2] == want && v[3] == want;
}
static procd_status create(procd_enforcement mode, int64_t uid, int64_t gid, procd_domain **d) {
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = mode;
    pol.drop_uid = uid;
    pol.drop_gid = gid;
    *d = NULL;
    return procd_create_domain(&pol, d);
}
static void finish(procd_domain *d) {
    procd_termination_evidence ev;
    procd_domain_terminate(d, 5000, &ev);
    procd_domain_release(d);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: cgroup-v2 lifecycle domain unavailable (%s)\n", strict ? "FAIL" : "SKIP",
               c.detail);
        return strict ? 1 : 77;
    }
    const char *sleeper[] = {"sleep", "30", NULL};
    procd_domain *d = NULL;
    long u[4], g[4], groups[64];

    /* ---- representability: nothing narrows to a different identity ---- */
    const int64_t two32 = 1LL << 32;
    CHECK(create(PROCD_REQUIRE_ENFORCED, two32, -1, &d) == PROCD_E_INVALID_ARGUMENT,
          "uid 2^32 (would truncate to 0) rejected");
    CHECK(create(PROCD_REQUIRE_ENFORCED, two32 + 1000, -1, &d) == PROCD_E_INVALID_ARGUMENT,
          "uid 2^32+1000 (would truncate to 1000) rejected");
    CHECK(create(PROCD_ALLOW_BEST_EFFORT, -1, two32, &d) == PROCD_E_INVALID_ARGUMENT,
          "gid 2^32 rejected, also under ALLOW_BEST_EFFORT");
    CHECK(create(PROCD_REQUIRE_ENFORCED, -2, -1, &d) == PROCD_E_INVALID_ARGUMENT,
          "negative uid other than -1 rejected");

    /* ---- default: the caller's credentials, at ENFORCED ---- */
    CHECK(create(PROCD_REQUIRE_ENFORCED, -1, -1, &d) == PROCD_OK && d,
          "default policy creates an ENFORCED domain for this caller");
    if (d) {
        int64_t pid = -1;
        CHECK(procd_domain_spawn(d, sleeper, &pid) == PROCD_OK, "spawned with default policy");
        nap(100);
        CHECK(status_ids((pid_t)pid, "Uid", u, 4) == 4 && all_eq(u, (long)getuid()),
              "workload uid (real/eff/saved/fs) equals the caller's");
        CHECK(status_ids((pid_t)pid, "Gid", g, 4) == 4 && all_eq(g, (long)getgid()),
              "workload gid (real/eff/saved/fs) equals the caller's");
        finish(d);
    }

    if (geteuid() == 0) {
        /* ---- explicit run-as, applied and read back ---- */
        CHECK(create(PROCD_REQUIRE_ENFORCED, 4321, 4321, &d) == PROCD_OK && d,
              "explicit run-as 4321:4321 domain is ENFORCED");
        if (d) {
            int64_t pid = -1;
            CHECK(procd_domain_spawn(d, sleeper, &pid) == PROCD_OK, "spawned with run-as");
            nap(100);
            CHECK(status_ids((pid_t)pid, "Uid", u, 4) == 4 && all_eq(u, 4321),
                  "run-as uid applied to real/eff/saved/fs");
            CHECK(status_ids((pid_t)pid, "Gid", g, 4) == 4 && all_eq(g, 4321),
                  "run-as gid applied to real/eff/saved/fs");
            CHECK(status_ids((pid_t)pid, "Groups", groups, 64) == 0,
                  "root's supplementary groups dropped");
            finish(d);
        }
        /* ---- explicit uid 0 is an ordinary identity: lifecycle unaffected ---- */
        CHECK(create(PROCD_REQUIRE_ENFORCED, 0, 0, &d) == PROCD_OK && d,
              "explicit run-as 0:0 is still an ENFORCED lifecycle domain");
        if (d) finish(d);
    } else {
        /* ---- a run-as this caller cannot establish fails the spawn ---- */
        CHECK(create(PROCD_REQUIRE_ENFORCED, 0, -1, &d) == PROCD_OK && d,
              "domain with an unattainable run-as is created");
        if (d) {
            int64_t pid = -1;
            procd_status rc = procd_domain_spawn(d, sleeper, &pid);
            CHECK(rc == PROCD_E_PERMISSION && pid == -1,
                  "spawn fails with PERMISSION and runs nothing");
            procd_domain_status st;
            procd_domain_status_get(d, &st);
            CHECK(st.population == PROCD_POP_EMPTY, "nothing was left in the domain");
            finish(d);
        }
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all identity checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only identity regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
