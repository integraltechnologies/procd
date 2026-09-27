#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Forced credential-transition failure (Linux, enforced host).
 *
 * Area 1 requires that if child-side credential setup fails, the failure is
 * communicated to the parent BEFORE the workload begins, spawn() fails, and no
 * workload code runs. Forcing a real credential failure as root is impractical,
 * so this links the TEST-ONLY negative-control variant (libprocd_nc) which
 * exposes PROCD_NC_FAIL_CREDS=1: the child reports the transition as failed at
 * exactly the point child_drop_priv would, exercising the real failure-
 * propagation path.
 *
 * It also proves the failed spawn does NOT kill the domain's already-running
 * workloads (I-2): a first workload is spawned successfully, then a second spawn
 * is forced to fail, and the first must remain alive and contained.
 *
 * Independent oracle: the first workload's pid (kill(pid,0)) and the witness
 * directory (a forced-fail spawn writes no "root" witness because it never
 * exec'd).
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "witness.h"
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
static int alive(long pid) {
    return pid > 0 && kill((pid_t)pid, 0) == 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "10", 1);
    unsetenv("PROCD_NC_FAIL_CREDS");
    unsetenv("PROCD_NC_WEAKEN");

    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    char wd[64];
    if (w_dir_create(wd, sizeof wd) != 0) {
        printf("FAIL: cannot create witness dir\n");
        return 1;
    }
    setenv(W_ENV, wd, 1);

    procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created ENFORCED domain");
    if (rc != PROCD_OK) {
        w_dir_remove(wd);
        return 1;
    }

    /* 1. A first workload spawns successfully (credentials NOT forced to fail). */
    const char *av[] = {adv, "child", NULL};
    int64_t pid1 = -1;
    rc = procd_domain_spawn(d, av, &pid1);
    CHECK(rc == PROCD_OK && pid1 > 0, "first workload spawned");
    nap(150);
    CHECK(alive(pid1), "first workload is running");

    /* 2. Force the credential transition to fail; the second spawn must fail
     *    closed, run no workload, and NOT disturb the first. */
    setenv("PROCD_NC_FAIL_CREDS", "1", 1);
    w_rec before[W_MAX];
    int nbefore = w_read(wd, before, W_MAX);
    int64_t pid2 = -1;
    rc = procd_domain_spawn(d, av, &pid2);
    CHECK(rc != PROCD_OK, "forced-credential-failure spawn is REFUSED");
    CHECK(pid2 == -1, "refused spawn reports no pid");
    CHECK(rc == PROCD_E_PERMISSION, "credential failure surfaces as PERMISSION");

    /* The forced-fail child never exec'd, so no new witness should appear. */
    nap(150);
    w_rec after[W_MAX];
    int nafter = w_read(wd, after, W_MAX);
    CHECK(nafter == nbefore, "forced-fail spawn executed no workload (no new witness)");

    /* I-2: the failed spawn must not have killed the domain's running workload. */
    CHECK(alive(pid1), "first workload still alive after the failed second spawn");

    setenv("PROCD_NC_FAIL_CREDS", "0", 1);

    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 5000, &ev);
    CHECK(rc == PROCD_OK && ev.enforced && ev.final_state == PROCD_STATE_EMPTY,
          "domain terminates with enforced/empty evidence");
    for (int i = 0; i < 100 && alive(pid1); i++)
        nap(10);
    CHECK(!alive(pid1), "first workload is gone after termination");

    procd_domain_release(d);
    setenv(W_ENV, "", 1);
    unsetenv(W_ENV);
    w_dir_remove(wd);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all credential-failure checks passed",
           fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only credential-failure regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
