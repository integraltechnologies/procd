#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS unrelated-process safety regression (B8).
 *
 * The best-effort backend signals a process group only while it can confirm
 * that the group's leader generation (pid + kernel start time) still holds the
 * group id. The fixture is the adversary's "leader-exit" mode: the leader exits
 * at once, leaving an orphan that stays in the leader's process group.
 *
 *   A. Leader exited but NOT reaped (zombie still holds its pid): continuity is
 *      confirmed, so terminate signals the group and the orphan dies.
 *   B. Leader REAPED by the caller: the group id is no longer attributable to
 *      the domain (it could be reused by an unrelated group). terminate must
 *      refuse to signal (PROCD_E_NOT_FOUND, UNRESOLVED) and the orphan - which
 *      stands in for "whatever now owns that id" - must NOT be signalled;
 *      status must report population UNKNOWN rather than attributing the group.
 *   C. Status and capabilities agree: ProcessTreeTermination UNSUPPORTED, and
 *      population is never authoritative.
 *
 * Not reproduced: an actual reuse of the leader's pid by an unrelated process
 * group. Forcing a specific pid to be reallocated is not deterministic in a
 * bounded test; case B exercises the exact validation that prevents it (the
 * same check fires whether the id was reused or not).
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

/* spawn leader-exit; return domain with the orphan's witness in *orphan */
static procd_domain *setup(const char *adv, char *wd, size_t wn, w_rec *orphan, int64_t *leader) {
    if (w_dir_create(wd, wn) != 0) return NULL;
    setenv(W_ENV, wd, 1);
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) return NULL;
    const char *av[] = {adv, "leader-exit", NULL};
    if (procd_domain_spawn(d, av, leader) != PROCD_OK) {
        procd_domain_release(d);
        return NULL;
    }
    for (int i = 0; i < 250; i++) {
        nap(20);
        w_rec w[W_MAX];
        int n = w_read(wd, w, W_MAX);
        const w_rec *o = w_find(w, n, "orphan");
        if (o && w_alive(o) && o->pgid == (long)*leader) {
            *orphan = *o;
            return d;
        }
    }
    procd_domain_release(d);
    return NULL;
}

static void cleanup(procd_domain *d, const char *wd, const w_rec *o) {
    if (w_alive(o)) kill((pid_t)o->pid, SIGKILL); /* exact generation only */
    procd_domain_release(d);
    unsetenv(W_ENV);
    w_dir_remove(wd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "20", 1);
    procd_capabilities c;
    procd_capabilities_probe(&c);

    /* ---- A: zombie leader keeps the id: signal is safe and happens ---- */
    {
        char wd[64];
        w_rec o;
        int64_t leader = -1;
        procd_domain *d = setup(adv, wd, sizeof wd, &o, &leader);
        if (!d) {
            printf("SKIP: fixture did not establish leader-exit topology\n");
            return 77;
        }
        procd_domain_status st;
        procd_domain_status_get(d, &st);
        CHECK(st.process_tree_termination == c.process_tree_termination &&
                  st.process_tree_termination == PROCD_CAP_UNSUPPORTED,
              "C: status and probe agree (ProcessTreeTermination UNSUPPORTED)");
        CHECK(!st.population_is_authoritative, "C: population is never authoritative");
        CHECK(st.population == PROCD_POP_POPULATED, "A: confirmed group reported populated");
        procd_termination_evidence ev;
        procd_status rc = procd_domain_terminate(d, 3000, &ev);
        CHECK(rc == PROCD_OK, "A: terminate signals a generation-confirmed group");
        CHECK(!w_alive(&o), "A: orphan in the confirmed group was killed");
        CHECK(!ev.emptiness_proven && !ev.enforced && ev.final_state == PROCD_STATE_UNRESOLVED,
              "A: killpg success is not reported as emptiness");
        cleanup(d, wd, &o);
        waitpid((pid_t)leader, NULL, 0);
    }

    /* ---- B: leader reaped: group id no longer attributable: never signal ---- */
    {
        char wd[64];
        w_rec o;
        int64_t leader = -1;
        procd_domain *d = setup(adv, wd, sizeof wd, &o, &leader);
        if (!d) {
            printf("SKIP: fixture did not establish leader-exit topology\n");
            return 77;
        }
        CHECK(waitpid((pid_t)leader, NULL, 0) == (pid_t)leader, "B: caller reaped the leader");
        procd_domain_status st;
        procd_domain_status_get(d, &st);
        CHECK(st.population == PROCD_POP_UNKNOWN,
              "B: status does not attribute a stale group id to the domain");
        procd_termination_evidence ev;
        procd_status rc = procd_domain_terminate(d, 1000, &ev);
        printf("   terminate -> %s: %s\n", procd_status_name(rc), ev.detail ? ev.detail : "");
        CHECK(rc == PROCD_E_NOT_FOUND, "B: terminate refuses to signal an unconfirmed group");
        CHECK(ev.final_state == PROCD_STATE_UNRESOLVED && !ev.emptiness_proven,
              "B: outcome is UNRESOLVED");
        nap(200);
        CHECK(w_alive(&o), "B: process holding the stale group id was NOT signalled");
        cleanup(d, wd, &o);
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all macOS pgid-safety checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only process-group safety regression\n");
    return 77;
}
#endif
