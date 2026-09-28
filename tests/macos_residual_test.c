#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS known-residual stress: measures the documented observation race.
 *
 * Each round supervises the fixture's `escape-storm` task: the task repeatedly
 * forks a child that execs with an EMPTY environment, starts a new session,
 * double-forks and exits, so the grandchild is reparented to launchd with no
 * domain marker, no member ancestry and no member process group. procd then
 * terminates the domain while attempts are still in flight.
 *
 * Witnesses (pid + kernel start time, so pid reuse cannot fake a result):
 *   storm-mid      an attempt started (env-less exec happened)
 *   storm-escapee  the escape topology completed: written by the grandchild
 *                  only after it observed its reparenting; its record carries
 *                  the kernel's ppid/sid at that moment
 * Escapees witnessed before terminate began are "pre-established"; the rest
 * completed while terminate raced them. A pre-established escapee's exec-time
 * environment is also read from the kernel to confirm it carries no marker.
 *
 * An unrelated same-user tree runs beside every round: any casualty FAILS.
 * Escapes are reported, never failed, unless PROCD_RESIDUAL_REQUIRE_ZERO=1.
 * PROCD_RESIDUAL_ROUNDS (default 20) scales the run.
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
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 1 if pid's kernel exec-time argv/env carries any procd domain marker, 0 if
 * not, -1 if unreadable */
static int carries_marker(long pid) {
    static char buf[1 << 20];
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    size_t len = sizeof buf;
    if (sysctl(mib, 3, buf, &len, NULL, 0) != 0 || len < sizeof(int)) return -1;
    for (size_t i = sizeof(int); i < len;) {
        size_t sl = strnlen(buf + i, len - i);
        if (sl >= 13 && memcmp(buf + i, "PROCD_DOMAIN_", 13) == 0) return 1;
        i += sl + 1;
    }
    return 0;
}

static unsigned long long g_watch[3];
/* watcher statistics from the termination detail (no extra API) */
static void watch_parse(const char *detail, unsigned long long v[3]) {
    const char *p = detail ? strstr(detail, "event-assisted tracking: ") : NULL;
    unsigned long long e = 0, r = 0;
    double ms = 0;
    if (p &&
        sscanf(p, "event-assisted tracking: %llu fork/exec events, %llu reconciliations, %lfms", &e,
               &r, &ms) == 3)
        v[0] = e, v[1] = r, v[2] = (unsigned long long)(ms * 1e6);
    else
        v[0] = v[1] = v[2] = 0;
}

static int has_pid(const long *v, int n, long pid) {
    for (int i = 0; i < n; i++)
        if (v[i] == pid) return 1;
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    const char *rs = getenv("PROCD_RESIDUAL_ROUNDS");
    int rounds = rs ? atoi(rs) : 20;
    if (rounds <= 0) rounds = 20;
    int require_zero = getenv("PROCD_RESIDUAL_REQUIRE_ZERO") != NULL;
    setenv("PROCD_ADV_TTL", "15", 1);

    procd_capabilities c;
    procd_capabilities_probe(&c);
    printf("backend=%s ProcessTreeTermination=%s rounds=%d\n", c.backend,
           procd_capability_name(c.process_tree_termination), rounds);

    long attempts = 0, established = 0, pre = 0, pre_esc = 0, raced = 0, raced_esc = 0;
    long marker_free = 0, members_survived = 0, casualties = 0, term_fail = 0;
    static const int offsets[] = {0, 3, 8, 15, 30};
    static w_rec w[W_MAX], u[W_MAX];

    for (int r = 0; r < rounds; r++) {
        char wd[64], ud[64];
        if (w_dir_create(wd, sizeof wd) != 0 || w_dir_create(ud, sizeof ud) != 0) {
            printf("FAIL: witness directories\n");
            return 1;
        }
        /* unrelated same-user tree, started without procd */
        pid_t ctl = fork();
        if (ctl == 0) {
            setenv(W_ENV, ud, 1);
            execl(adv, adv, "grandchild", (char *)NULL);
            _exit(127);
        }
        procd_policy pol = PROCD_POLICY_INIT;
        pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
        procd_domain *d = NULL;
        if (procd_create_domain(&pol, &d) != PROCD_OK) {
            printf("FAIL: create domain\n");
            return 1;
        }
        setenv(W_ENV, wd, 1);
        const char *av[] = {adv, "escape-storm", NULL};
        int64_t leader = -1;
        procd_status sr = procd_domain_spawn(d, av, &leader);
        unsetenv(W_ENV);
        if (sr != PROCD_OK) {
            printf("FAIL: spawn escape-storm: %s\n", procd_status_name(sr));
            return 1;
        }

        /* let the first escape complete, then terminate at a varying offset
         * while later attempts are still in flight */
        int n = 0;
        for (long long end = mono_ms() + 5000; mono_ms() < end; nap(1)) {
            n = w_read(wd, w, W_MAX);
            if (w_count(w, n, "storm-escapee") > 0) break;
        }
        nap(offsets[r % 5]);
        n = w_read(wd, w, W_MAX);
        long before[W_MAX];
        int nb = 0;
        for (int i = 0; i < n; i++)
            if (!strcmp(w[i].role, "storm-escapee")) {
                before[nb++] = w[i].pid;
                if (w_alive(&w[i]) && carries_marker(w[i].pid) == 0) marker_free++;
            }

        procd_termination_evidence ev;
        procd_status rc = procd_domain_terminate(d, 5000, &ev);
        if (rc != PROCD_OK) term_fail++;
        nap(150); /* in-flight grandchildren finish reparenting and witness */

        n = w_read(wd, w, W_MAX);
        int ra = 0, re = 0, rx = 0, other = 0;
        for (int i = 0; i < n; i++) {
            int alive = w_alive(&w[i]);
            if (!strcmp(w[i].role, "storm-mid")) {
                ra++;
                other += alive;
            } else if (!strcmp(w[i].role, "storm-escapee")) {
                /* the topology evidence: reparented to launchd, own session */
                if (w[i].ppid != 1 || w[i].sid == (long)leader) continue;
                re++;
                rx += alive;
                if (has_pid(before, nb, w[i].pid))
                    pre++, pre_esc += alive;
                else
                    raced++, raced_esc += alive;
            } else
                other += alive; /* the task root */
        }
        attempts += ra, established += re, members_survived += other;

        int un = w_read(ud, u, W_MAX), ualive = 0;
        for (int i = 0; i < un; i++)
            ualive += w_alive(&u[i]);
        int lost = (un >= 3 ? un - ualive : 3) + (waitpid(ctl, NULL, WNOHANG) != 0);
        casualties += lost;
        printf("round %2d: offset=%2dms attempts=%2d established=%2d escaped=%2d "
               "(pre-established %d) unrelated-lost=%d terminate=%s\n",
               r + 1, offsets[r % 5], ra, re, rx, nb, lost, procd_status_name(rc));

        for (int i = 0; i < n; i++)
            w_kill(&w[i]);
        for (int i = 0; i < un; i++)
            w_kill(&u[i]);
        kill(ctl, SIGKILL);
        waitpid(ctl, NULL, 0);
        unsigned long long ws[3];
        watch_parse(ev.detail, ws);
        for (int k = 0; k < 3; k++)
            g_watch[k] += ws[k];
        procd_domain_release(d);
        w_dir_remove(wd);
        w_dir_remove(ud);
    }

    long escaped = pre_esc + raced_esc;
    printf("RESIDUAL: attempts=%ld established=%ld captured=%ld escaped=%ld | "
           "pre-established %ld (escaped %ld, marker-free verified %ld) | "
           "raced-termination %ld (escaped %ld) | ordinary-member survivors=%ld "
           "unrelated casualties=%ld terminate-failures=%ld\n",
           attempts, established, established - escaped, escaped, pre, pre_esc, marker_free, raced,
           raced_esc, members_survived, casualties, term_fail);
    if (g_watch[1])
        printf("WATCH: fork/exec events=%llu reconciliations=%llu watcher-cpu=%.1fms\n", g_watch[0],
               g_watch[1], (double)g_watch[2] / 1e6);
    int fail = 0;
    if (established == 0) printf("FAIL: escape topology never established (vacuous)\n"), fail = 1;
    if (casualties) printf("FAIL: unrelated processes were killed\n"), fail = 1;
    if (members_survived) printf("FAIL: ordinary task members survived\n"), fail = 1;
    if (term_fail) printf("FAIL: terminate did not return OK\n"), fail = 1;
    if (require_zero && escaped)
        printf("FAIL: escapes with PROCD_RESIDUAL_REQUIRE_ZERO\n"), fail = 1;
    if (!fail)
        printf("%s\n", escaped ? "KNOWN RESIDUAL reproduced (reported, not failed)"
                               : "no escape observed (not a proof)");
    return fail;
}
#else
int main(void) {
    printf("SKIP: macOS-only residual stress\n");
    return 77;
}
#endif
