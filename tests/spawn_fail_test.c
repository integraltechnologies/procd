#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Failed-spawn isolation regression (Linux, cgroup-v2 lifecycle host).
 *
 * A spawn that fails before the workload runs must fail cleanly, run nothing,
 * and leave the domain's already-running workloads alone -- it must never
 * terminate the whole domain. Uses an ordinary exec failure (a nonexistent
 * program), not a test-only hook.
 *
 * Independent oracle: the first workload's witness record (pid + start time),
 * the domain's own population, and the absence of any witness from the failed
 * spawn.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "witness.h"
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

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: cgroup-v2 lifecycle domain unavailable (%s)\n", strict ? "FAIL" : "SKIP",
               c.detail);
        return strict ? 1 : 77;
    }
    setenv("PROCD_ADV_TTL", "15", 1);
    char wd[64];
    if (w_dir_create(wd, sizeof wd) != 0) {
        printf("FAIL: cannot create witness directory\n");
        return 1;
    }
    setenv(W_ENV, wd, 1);

    procd_policy pol = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    CHECK(procd_create_domain(&pol, &d) == PROCD_OK, "created ENFORCED domain");
    if (!d) return 1;

    /* first workload: a child tree that keeps running */
    const char *first[] = {adv, "grandchild", NULL};
    int64_t root = -1;
    CHECK(procd_domain_spawn(d, first, &root) == PROCD_OK, "first workload spawned");
    static w_rec w[W_MAX];
    int n = 0;
    for (int i = 0; i < 150 && !w_find(w, n, "grandchild"); i++) {
        nap(20);
        n = w_read(wd, w, W_MAX);
    }
    const w_rec *r = w_find(w, n, "root");
    CHECK(r && r->pid == (long)root && w_find(w, n, "grandchild"),
          "first workload's tree witnessed (root + grandchild)");

    /* second spawn fails at exec */
    const char *missing[] = {"/nonexistent/procd-no-such-program", NULL};
    int64_t pid2 = -1;
    procd_status rc = procd_domain_spawn(d, missing, &pid2);
    CHECK(rc != PROCD_OK && pid2 == -1, "spawn of a missing program fails and reports no pid");
    nap(200);

    int n2 = w_read(wd, w, W_MAX);
    CHECK(n2 == n, "failed spawn produced no witness (no workload ran)");
    int alive = 0;
    for (int i = 0; i < n2; i++)
        alive += w_alive(&w[i]);
    CHECK(n2 > 0 && alive == n2, "every process of the first workload is still alive");
    procd_domain_status st;
    procd_domain_status_get(d, &st);
    CHECK(st.state == PROCD_STATE_ACTIVE && st.population == PROCD_POP_POPULATED,
          "domain still ACTIVE and populated");

    /* the domain still terminates normally afterwards */
    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 5000, &ev);
    CHECK(rc == PROCD_OK && ev.emptiness_proven && ev.final_state == PROCD_STATE_EMPTY,
          "terminate afterwards proves emptiness");
    int left = n2;
    for (int t = 0; t < 50 && left; t++) { /* allow reparented children to be reaped */
        left = 0;
        for (int i = 0; i < n2; i++)
            left += w_alive(&w[i]);
        if (left) nap(20);
    }
    CHECK(left == 0, "no witnessed process survives termination");

    procd_domain_release(d);
    unsetenv(W_ENV);
    w_dir_remove(wd);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all failed-spawn checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only failed-spawn regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
