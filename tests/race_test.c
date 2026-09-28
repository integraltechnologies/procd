#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Spawn-vs-terminate concurrency regression (Linux cgroup-v2 host; root not needed).
 *
 * Repeatedly races a spawn against a terminate on the same domain, started
 * together at a barrier, and independently verifies the invariant:
 *
 *   once termination begins, admission is permanently closed, and a successful
 *   termination leaves no owned process and no stranded invocation cgroup.
 *
 * Independent evidence: the workload leader pid (dead after the race), and the
 * invocation cgroup path (removed, read from the domain identity before the
 * race). Also checks the explicit ordering rule: a spawn issued AFTER a full
 * termination must fail and run nothing.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else if (verbose)                                                                        \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

static int verbose = 0;
static int alive(pid_t p) {
    return p > 0 && kill(p, 0) == 0;
}

static void path_from_identity(const char *id, char *out, size_t n) {
    const char *last = strrchr(id, ':');
    snprintf(out, n, "%s", last ? last + 1 : "");
}

struct spawn_arg {
    procd_domain *d;
    const char *adv;
    pthread_barrier_t *bar;
    procd_status rc;
    int64_t pid;
};
static void *spawn_thread(void *v) {
    struct spawn_arg *a = v;
    const char *argv[] = {a->adv, "child", NULL};
    pthread_barrier_wait(a->bar);
    a->rc = procd_domain_spawn(a->d, argv, &a->pid);
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    if (getenv("PROCD_RACE_VERBOSE")) verbose = 1;
    setenv("PROCD_ADV_TTL", "3", 1); /* bounded: nothing survives even on a bug */

    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    const int iters = 150;
    int spawn_ok = 0, spawn_refused = 0;
    for (int i = 0; i < iters; i++) {
        procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
        procd_domain *d = NULL;
        if (procd_create_domain(&pol, &d) != PROCD_OK) {
            printf("FAIL: create failed at iter %d\n", i);
            fails++;
            break;
        }
        char id[PROCD_IDENTITY_MAX], path[600];
        procd_domain_identity(d, id, sizeof id);
        path_from_identity(id, path, sizeof path);

        pthread_barrier_t bar;
        pthread_barrier_init(&bar, NULL, 2);
        struct spawn_arg a = {d, adv, &bar, PROCD_E_INTERNAL, -1};
        pthread_t th;
        pthread_create(&th, NULL, spawn_thread, &a);

        procd_termination_evidence ev;
        memset(&ev, 0, sizeof ev);
        pthread_barrier_wait(&bar); /* fire spawn and terminate together */
        procd_status trc = procd_domain_terminate(d, 3000, &ev);
        pthread_join(th, NULL);
        pthread_barrier_destroy(&bar);

        if (a.rc == PROCD_OK)
            spawn_ok++;
        else
            spawn_refused++;

        /* Invariant 1: a spawn that succeeded must have been killed by the
         * terminate that necessarily ran after it (lock ordering). */
        if (a.rc == PROCD_OK) {
            /* give the kill a moment if terminate proved empty */
            for (int k = 0; k < 50 && alive((pid_t)a.pid); k++) {
                struct timespec ts = {0, 10 * 1000 * 1000};
                nanosleep(&ts, NULL);
            }
            CHECK(!alive((pid_t)a.pid), "raced spawn's workload is not alive after terminate");
        }
        /* Invariant 2: terminate established authoritative emptiness. */
        CHECK(trc == PROCD_OK && ev.final_state == PROCD_STATE_EMPTY && ev.emptiness_proven,
              "terminate proved emptiness");
        /* Invariant 3: no stranded invocation cgroup. */
        CHECK(access(path, F_OK) != 0, "invocation cgroup removed (not stranded)");

        procd_domain_release(d);
        CHECK(access(path, F_OK) != 0, "cgroup gone after release");
    }
    printf("raced %d iterations: %d spawn-admitted, %d spawn-refused-by-closed-admission\n", iters,
           spawn_ok, spawn_refused);

    /* Explicit ordering rule: spawn AFTER a completed terminate must fail. */
    {
        procd_policy pol = PROCD_POLICY_INIT;
        procd_domain *d = NULL;
        if (procd_create_domain(&pol, &d) == PROCD_OK) {
            procd_termination_evidence ev;
            procd_domain_terminate(d, 3000, &ev);
            const char *av[] = {adv, "child", NULL};
            int64_t pid = -1;
            procd_status rc = procd_domain_spawn(d, av, &pid);
            CHECK(rc != PROCD_OK && pid == -1, "spawn after termination is refused, runs nothing");
            procd_domain_release(d);
        }
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all race checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: Linux-only spawn/terminate race regression\n");
    return 77;
}
#endif
