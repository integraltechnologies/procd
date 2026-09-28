#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * procd CLI. Thin exerciser over the library; it must not distort the library.
 *
 *   procd capabilities            - print statically-discovered capabilities
 *   procd qualify [--require-enforced] [adversary]
 *                                 - run the qualification matrix
 *   procd run [--require-enforced] -- <cmd> [args...]
 *                                 - supervise <cmd> in a lifecycle domain
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "../tests/qualify.h"
#include "procd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static void nap_ms(int ms) {
    Sleep((DWORD)ms);
}
#define PATHSEP '\\'
#else
#include <time.h>
#include <unistd.h>
static void nap_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}
#define PATHSEP '/'
#endif

static void print_caps(const procd_capabilities *c) {
    printf("backend:                    %s\n", c->backend);
    printf("ProcessTreeTermination:     %s\n", procd_capability_name(c->process_tree_termination));
    printf("PreExecutionContainment:    %s\n", procd_capability_name(c->pre_execution_containment));
    printf("DescendantContainment:      %s\n", procd_capability_name(c->descendant_containment));
    printf("TopologyEscapeResistance:   %s\n",
           procd_capability_name(c->topology_escape_resistance));
    printf("DomainEmptinessProof:       %s\n", procd_capability_name(c->domain_emptiness_proof));
    printf("SafeRecovery:               %s\n", procd_capability_name(c->safe_recovery));
    const char *cb =
        c->crash_behavior == PROCD_CRASH_AUTOMATIC_DESTRUCTION   ? "AUTOMATIC_DESTRUCTION"
        : c->crash_behavior == PROCD_CRASH_DURABLE_REACQUISITION ? "DURABLE_REACQUISITION"
                                                                 : "UNRESOLVED_ON_AUTHORITY_LOSS";
    printf("CrashBehavior:              %s\n", cb);
    printf("detail:                     %s\n", c->detail ? c->detail : "");
}

/* derive "<dir of argv0>/procd-adversary[.exe]" */
static void sibling_adversary(const char *argv0, char *out, size_t n) {
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", argv0);
    char *slash = strrchr(dir, PATHSEP);
    const char *exe =
#if defined(_WIN32)
        "procd-adversary.exe";
#else
        "procd-adversary";
#endif
    if (slash) {
        *slash = 0;
        snprintf(out, n, "%s%c%s", dir, PATHSEP, exe);
    } else
        snprintf(out, n, "%s", exe);
}

static int cmd_qualify(const char *argv0, int argc, char **argv) {
    int require = 0;
    if (argc > 0 && strcmp(argv[0], "--require-enforced") == 0) {
        require = 1;
        argc--, argv++;
    }
    char adv[1100];
    if (argc > 0)
        snprintf(adv, sizeof adv, "%s", argv[0]);
    else
        sibling_adversary(argv0, adv, sizeof adv);

    static q_case cases[Q_MAX_CASES];
    int n = 0;
    int fails = procd_qualify_run(adv, cases, Q_MAX_CASES, &n);
    int pass = 0, skip = 0;
    for (int i = 0; i < n; i++) {
        printf("[%-4s] %-18s %s\n", q_result_name(cases[i].result), cases[i].name, cases[i].detail);
        if (cases[i].result == Q_PASS)
            pass++;
        else if (cases[i].result == Q_SKIP)
            skip++;
    }
    printf("---- %d PASS, %d SKIP, %d FAIL ----\n", pass, skip, fails);
    if (require) {
        char why[256];
        int bad = procd_qualify_enforced_verdict(cases, n, why, sizeof why);
        printf("ENFORCED qualification: %s: %s\n", bad ? "FAIL" : "PASS", why);
        return bad ? 1 : 0;
    }
    return fails ? 1 : 0;
}

static int cmd_run(int argc, char **argv) {
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    int i = 0;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--require-enforced") == 0)
            pol.enforcement = PROCD_REQUIRE_ENFORCED;
        else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else
            break;
    }
    if (i >= argc) {
        fprintf(stderr, "usage: procd run [--require-enforced] -- <cmd> [args...]\n");
        return 2;
    }

    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    if (rc == PROCD_E_UNSUPPORTED_ENFORCEMENT) {
        fprintf(stderr,
                "procd: REFUSED: ProcessTreeTermination cannot be ENFORCED on this host "
                "(fail-closed). Re-run without --require-enforced to accept a weaker level.\n");
        return 3;
    }
    if (rc != PROCD_OK) {
        fprintf(stderr, "procd: create_domain: %s\n", procd_status_name(rc));
        return 1;
    }

    procd_domain_status st;
    procd_domain_status_get(d, &st);
    fprintf(stderr, "procd: domain runtime level = %s\n",
            procd_capability_name(st.process_tree_termination));

    int64_t pid = -1;
    rc = procd_domain_spawn(d, (const char *const *)&argv[i], &pid);
    if (rc != PROCD_OK) {
        fprintf(stderr, "procd: spawn: %s\n", procd_status_name(rc));
        procd_domain_release(d);
        return 1;
    }
    fprintf(stderr, "procd: launched pid=%lld (diagnostic)\n", (long long)pid);

    /* Supervise: poll authoritative population until empty. */
    for (;;) {
        nap_ms(100);
        procd_domain_status_get(d, &st);
        if (st.population == PROCD_POP_EMPTY) break;
        if (st.population == PROCD_POP_UNKNOWN && !st.population_is_authoritative) {
            /* best-effort backends: fall back to a short bounded wait */
            nap_ms(200);
        }
    }
    procd_termination_evidence ev;
    procd_domain_terminate(d, 5000, &ev);
    fprintf(stderr, "procd: final=%s emptiness_proven=%d enforced=%d (%s)\n",
            procd_state_name(ev.final_state), ev.emptiness_proven, ev.enforced,
            ev.detail ? ev.detail : "");
    procd_domain_release(d);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: procd <capabilities|qualify|run> ...\n");
        return 2;
    }
    if (strcmp(argv[1], "capabilities") == 0) {
        procd_capabilities c;
        procd_capabilities_probe(&c);
        print_caps(&c);
        return 0;
    }
    if (strcmp(argv[1], "qualify") == 0) return cmd_qualify(argv[0], argc - 2, &argv[2]);
    if (strcmp(argv[1], "run") == 0) return cmd_run(argc - 2, &argv[2]);
    fprintf(stderr, "procd: unknown subcommand '%s'\n", argv[1]);
    return 2;
}
