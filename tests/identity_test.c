#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Workload identity / privilege-transition regression (Linux, enforced host).
 *
 * Area 1: the workload must actually run with the intended FINAL credentials,
 * not merely have setuid() called. A sleeper workload is launched into an
 * ENFORCED domain with a non-default identity (uid/gid 4321) and its live
 * /proc/<pid>/status is read INDEPENDENTLY of procd to confirm every credential
 * transition took effect:
 *   - real, effective, saved AND fs uid are all 4321 (setresuid, not just euid);
 *   - real, effective, saved AND fs gid are all 4321;
 *   - no supplementary groups remain;
 *   - the effective (and permitted/inheritable) capability sets are empty;
 *   - no_new_privs is set;
 *   - CapBnd (bounding set) is empty, so no capability can ever be acquired.
 *
 * A backend that relied on setuid() alone, or skipped the bounding-set / group /
 * securebits work, would leave one of these fields non-final and fail here.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WUID 4321
#define WGID 4321

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

/* Read /proc/<pid>/status into buf. Returns 1 on success. */
static int read_status(pid_t pid, char *buf, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/status", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r <= 0) return 0;
    buf[r] = 0;
    return 1;
}
/* Parse the four ids of a "Key:\tr\te\ts\tfs" line. Returns 1 on success. */
static int four_ids(const char *status, const char *key, long v[4]) {
    const char *l = strstr(status, key);
    if (!l) return 0;
    return sscanf(l + strlen(key), "%ld\t%ld\t%ld\t%ld", &v[0], &v[1], &v[2], &v[3]) == 4;
}
/* Value of a single hex field like "CapEff:\t0000000000000000". */
static int hex_field(const char *status, const char *key, unsigned long long *out) {
    const char *l = strstr(status, key);
    if (!l) return 0;
    return sscanf(l + strlen(key), "%llx", out) == 1;
}
static int int_field(const char *status, const char *key, long *out) {
    const char *l = strstr(status, key);
    if (!l) return 0;
    return sscanf(l + strlen(key), "%ld", out) == 1;
}
/* Number of supplementary groups on the "Groups:" line. */
static int ngroups(const char *status) {
    const char *l = strstr(status, "\nGroups:");
    if (!l) return -1;
    l += strlen("\nGroups:");
    int n = 0;
    long g;
    int adv;
    while (sscanf(l, "%ld%n", &g, &adv) == 1) {
        n++;
        l += adv;
    }
    return n;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "10", 1);

    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
    pol.drop_uid = WUID;
    pol.drop_gid = WGID;
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created ENFORCED domain with identity 4321:4321");
    if (rc != PROCD_OK) return 1;

    /* "leaf" is a pure bounded sleeper: it runs the workload image and does
     * nothing but wait, so its /proc/<pid>/status reflects the credentials procd
     * established before exec. */
    const char *av[] = {adv, "leaf", NULL};
    int64_t pid = -1;
    rc = procd_domain_spawn(d, av, &pid);
    CHECK(rc == PROCD_OK && pid > 0, "spawned the workload");

    if (pid > 0) {
        nap(200);
        char st[8192];
        CHECK(read_status((pid_t)pid, st, sizeof st), "read workload /proc/<pid>/status");

        long uid[4] = {-1, -1, -1, -1}, gid[4] = {-1, -1, -1, -1};
        CHECK(four_ids(st, "\nUid:", uid), "status has a Uid line");
        CHECK(uid[0] == WUID && uid[1] == WUID && uid[2] == WUID && uid[3] == WUID,
              "real+effective+saved+fs uid are all the configured identity");
        CHECK(four_ids(st, "\nGid:", gid), "status has a Gid line");
        CHECK(gid[0] == WGID && gid[1] == WGID && gid[2] == WGID && gid[3] == WGID,
              "real+effective+saved+fs gid are all the configured identity");

        CHECK(ngroups(st) == 0, "no supplementary groups remain");

        unsigned long long capeff = ~0ULL, capprm = ~0ULL, capbnd = ~0ULL;
        CHECK(hex_field(st, "\nCapEff:", &capeff) && capeff == 0,
              "effective capability set is empty");
        CHECK(hex_field(st, "\nCapPrm:", &capprm) && capprm == 0,
              "permitted capability set is empty");
        CHECK(hex_field(st, "\nCapBnd:", &capbnd) && capbnd == 0,
              "capability bounding set is empty (no capability can be acquired)");

        long nnp = -1;
        CHECK(int_field(st, "\nNoNewPrivs:", &nnp) && nnp == 1, "no_new_privs is set");
    }

    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 5000, &ev);
    CHECK(rc == PROCD_OK && ev.enforced && ev.final_state == PROCD_STATE_EMPTY,
          "domain terminates with enforced/empty evidence");
    if (pid > 0) {
        for (int i = 0; i < 100 && kill((pid_t)pid, 0) == 0; i++)
            nap(10);
        CHECK(kill((pid_t)pid, 0) != 0, "workload is gone after termination");
    }
    procd_domain_release(d);

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all identity checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only workload-identity regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
