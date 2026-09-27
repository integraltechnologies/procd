#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS escape demonstration.
 *
 * This is the evidence behind ProcessTreeTermination = UNSUPPORTED on macOS. It
 * proves the escape probe actually detects escape: a best-effort process-group
 * domain is terminated with killpg, yet a double-forked / setsid descendant
 * SURVIVES (it left the process group). Observing the survivor confirms that
 * process groups are not containment, justifying the honest UNSUPPORTED report.
 *
 * On non-Apple platforms this is a no-op skip. The descendant is bounded
 * (PROCD_ADV_TTL) and is killed explicitly at the end regardless.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int read_pid(const char *pf, int *pid) {
    for (int i = 0; i < 200; i++) {
        FILE *f = fopen(pf, "r");
        if (f) {
            int v = 0;
            int ok = fscanf(f, "%d", &v);
            fclose(f);
            if (ok == 1 && v) {
                *pid = v;
                return 1;
            }
        }
        struct timespec t = {0, 10 * 1000000};
        nanosleep(&t, NULL);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "15", 1);
    char pidfile[] = "/tmp/procd_macos_escape.pid";
    unlink(pidfile);
    setenv("PROCD_ADV_PIDFILE", pidfile, 1);

    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        printf("SKIP: no best-effort domain\n");
        return 77;
    }

    const char *av[] = {adv, "double-fork", NULL};
    if (procd_domain_spawn(d, av, NULL) != PROCD_OK) {
        printf("FAIL: spawn\n");
        return 1;
    }

    int escaped_pid = 0;
    if (!read_pid(pidfile, &escaped_pid)) {
        printf("SKIP: descendant pid not observed\n");
        procd_domain_release(d);
        return 77;
    }

    struct timespec t = {0, 300 * 1000000};
    nanosleep(&t, NULL);
    procd_termination_evidence ev;
    procd_domain_terminate(d, 3000, &ev);
    nanosleep(&t, NULL);

    int alive = (kill(escaped_pid, 0) == 0);
    printf("escaped descendant pid=%d alive after killpg=%d; domain emptiness_proven=%d\n",
           escaped_pid, alive, ev.emptiness_proven);

    /* clean up the bounded survivor */
    if (alive) kill(escaped_pid, SIGKILL);
    procd_domain_release(d);
    unlink(pidfile);

    if (!alive) {
        printf("FAIL: expected the double-forked descendant to ESCAPE killpg on macOS, "
               "but it did not — escape probe is not actually detecting escape\n");
        return 1;
    }
    if (ev.emptiness_proven) {
        printf("FAIL: macOS reported emptiness_proven while a descendant survived\n");
        return 1;
    }
    printf("PASS: process-group containment is escapable on macOS (justifies UNSUPPORTED); "
           "procd truthfully never claims emptiness here\n");
    return 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only escape demonstration\n");
    return 77;
}
#endif
