#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS tracked-domain regressions that the shared matrix does not cover.
 *
 *   A. The caller reaps the task's leader (as an embedding runtime's SIGCHLD
 *      handling may): the leader's pid, and so its process group id, are no
 *      longer attributable, yet the orphaned descendant is still the task's and
 *      is still found and killed (domain marker + remembered generation).
 *   B. An unrelated process that shares procd's own process group and session
 *      (a sibling of the leader, started without procd) is never signalled.
 *   C. Honesty: status and probe agree (BEST_EFFORT); population is never
 *      authoritative; termination never claims proven emptiness or EMPTY.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include "witness.h"
#include <signal.h>
#include <sys/wait.h>
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

static const w_rec *wait_role(const char *wd, const char *role, w_rec *w, int *n) {
    for (int i = 0; i < 250; i++) {
        *n = w_read(wd, w, W_MAX);
        const w_rec *r = w_find(w, *n, role);
        if (r && w_alive(r)) return r;
        nap(20);
    }
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "20", 1);
    procd_capabilities c;
    procd_capabilities_probe(&c);

    char wd[64], ud[64];
    if (w_dir_create(wd, sizeof wd) != 0 || w_dir_create(ud, sizeof ud) != 0) {
        printf("FAIL: witness directories\n");
        return 1;
    }

    /* B's unrelated sibling: same process group and session as this test (and
     * so as procd's caller), started without procd */
    pid_t sib = fork();
    if (sib == 0) {
        setenv(W_ENV, ud, 1);
        execl(adv, adv, "grandchild", (char *)NULL);
        _exit(127);
    }

    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    CHECK(procd_create_domain(&pol, &d) == PROCD_OK, "best-effort tracked domain created");
    if (!d) return 1;
    setenv(W_ENV, wd, 1);
    const char *av[] = {adv, "leader-exit", NULL};
    int64_t leader = -1;
    CHECK(procd_domain_spawn(d, av, &leader) == PROCD_OK, "spawn leader-exit");
    unsetenv(W_ENV);

    static w_rec w[W_MAX], u[W_MAX];
    int n = 0, un = 0;
    const w_rec *o = wait_role(wd, "orphan", w, &n);
    w_rec orphan;
    if (o) orphan = *o;
    const w_rec *ug = wait_role(ud, "grandchild", u, &un);
    CHECK(o && o->pgid == (long)leader, "A: orphan witnessed in the leader's process group");
    CHECK(ug != NULL, "B: unrelated sibling tree witnessed");
    if (!o || !ug) {
        kill(sib, SIGKILL);
        return 1;
    }

    /* A: the embedding caller reaps procd's leader */
    CHECK(waitpid((pid_t)leader, NULL, 0) == (pid_t)leader, "A: caller reaped the leader");

    procd_domain_status st;
    procd_domain_status_get(d, &st);
    CHECK(st.process_tree_termination == c.process_tree_termination &&
              st.process_tree_termination == PROCD_CAP_BEST_EFFORT,
          "C: status and probe agree (BEST_EFFORT)");
    CHECK(!st.population_is_authoritative, "C: population is never authoritative");
    CHECK(st.population == PROCD_POP_POPULATED, "A: orphan still attributed to the domain");

    procd_termination_evidence ev;
    procd_status rc = procd_domain_terminate(d, 5000, &ev);
    printf("   terminate -> %s: %s\n", procd_status_name(rc), ev.detail ? ev.detail : "");
    CHECK(rc == PROCD_OK, "A: terminate succeeds");
    nap(100);
    CHECK(!w_alive(&orphan), "A: orphan of a caller-reaped leader was killed");
    CHECK(!ev.emptiness_proven && !ev.enforced && ev.final_state == PROCD_STATE_UNRESOLVED,
          "C: scan-based cleanup is not reported as proven emptiness");
    procd_domain_status_get(d, &st);
    CHECK(st.population == PROCD_POP_EMPTY && !st.population_is_authoritative,
          "C: status afterwards: empty by scan, not authoritative");

    un = w_read(ud, u, W_MAX);
    int ualive = 0;
    for (int i = 0; i < un; i++)
        ualive += w_alive(&u[i]);
    CHECK(un >= 3 && ualive == un && waitpid(sib, NULL, WNOHANG) == 0,
          "B: unrelated same-group sibling tree untouched");

    for (int i = 0; i < un; i++)
        w_kill(&u[i]);
    kill(sib, SIGKILL);
    waitpid(sib, NULL, 0);
    w_kill(&orphan);
    procd_domain_release(d);
    w_dir_remove(wd);
    w_dir_remove(ud);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all macOS tracking checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only tracked-domain regression\n");
    return 77;
}
#endif
