#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS shared-watcher and reconciliation regressions.
 *
 *   procd-macos-watcher-test <adversary> stress
 *     (production library) the process-wide watcher serving many domains:
 *     A. 16 simultaneously live domains with forking workloads beside an
 *        unrelated fork-heavy tree; terminated one at a time, each must leave
 *        no survivor while every other domain and the unrelated tree stay
 *        intact (no cross-domain membership, pid+start-time identities);
 *     B. 6 threads x 40 concurrent create/spawn/status/terminate/release
 *        cycles, a quarter of them released WITHOUT terminate while fork
 *        events are still pending (destroy vs in-flight reconciliation);
 *     C. 300 rapid create/release cycles and 60 spawn-then-release cycles.
 *
 *   procd-macos-status-reap-test <adversary> status-reap
 *     (negative-control library, watcher disabled with PROCD_NC_NO_WATCH=1)
 *     `sh -c 'sleep & sleep & exit'` with status polled from the moment of
 *     spawn: status must never reap the exited leader before a scan has
 *     attributed its background jobs through the leader's process group. The
 *     jobs are Apple platform binaries, whose environment (and so the domain
 *     marker) the kernel hides; the watcher would otherwise mask this.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include "witness.h"
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
static pthread_mutex_t fail_mu = PTHREAD_MUTEX_INITIALIZER;
#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            pthread_mutex_lock(&fail_mu);                                                          \
            printf("FAIL: " __VA_ARGS__);                                                          \
            printf("\n");                                                                          \
            fails++;                                                                               \
            pthread_mutex_unlock(&fail_mu);                                                        \
        }                                                                                          \
    } while (0)

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *g_adv;
/* spawn serializes the process environment (setenv is not thread-safe) */
static pthread_mutex_t env_mu = PTHREAD_MUTEX_INITIALIZER;

static procd_domain *new_domain(void) {
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    return procd_create_domain(&pol, &d) == PROCD_OK ? d : NULL;
}

static int spawn_adv(procd_domain *d, const char *wd, const char *mode) {
    const char *av[] = {g_adv, mode, NULL};
    pthread_mutex_lock(&env_mu);
    setenv(W_ENV, wd, 1);
    int64_t pid;
    procd_status rc = procd_domain_spawn(d, av, &pid);
    unsetenv(W_ENV);
    pthread_mutex_unlock(&env_mu);
    return rc == PROCD_OK;
}

/* witnessed records alive now (roles in `skip` excluded) */
static int alive_count(const char *wd, const char *skip) {
    static __thread w_rec w[W_MAX];
    int n = w_read(wd, w, W_MAX), a = 0;
    for (int i = 0; i < n; i++)
        if ((!skip || strcmp(w[i].role, skip)) && w_alive(&w[i])) a++;
    return a;
}

static void kill_all(const char *wd) {
    static __thread w_rec w[W_MAX];
    int n = w_read(wd, w, W_MAX);
    for (int i = 0; i < n; i++)
        w_kill(&w[i]);
}

/* ---------------- A. many live domains ---------------- */

static const char *MODES[] = {"multi",  "double-fork", "grandchild", "churn",
                              "setsid", "reparent",    "env-clear",  "leader-exit"};
#define NMODES ((int)(sizeof MODES / sizeof MODES[0]))
#define ND 16

static void phase_many(void) {
    char wd[ND][64], ud[64];
    procd_domain *d[ND];
    int base[ND];
    CHECK(w_dir_create(ud, sizeof ud) == 0, "witness dir");
    /* unrelated fork-heavy tree (never in a domain): its forks are not watched
     * and it must survive everything */
    pid_t ctl = fork();
    if (ctl == 0) {
        setenv(W_ENV, ud, 1);
        execl(g_adv, g_adv, "multi", (char *)NULL);
        _exit(127);
    }
    for (int i = 0; i < ND; i++) {
        CHECK(w_dir_create(wd[i], sizeof wd[i]) == 0, "witness dir");
        d[i] = new_domain();
        CHECK(d[i] && spawn_adv(d[i], wd[i], MODES[i % NMODES]), "A: domain %d spawn", i);
    }
    /* let every topology establish (witnesses stop growing) */
    for (long long end = mono_ms() + 3000; mono_ms() < end; nap(100)) {
        procd_domain_status st;
        for (int i = 0; i < ND; i++)
            if (d[i]) procd_domain_status_get(d[i], &st);
    }
    int ubase = alive_count(ud, NULL);
    CHECK(ubase >= 9, "A: unrelated tree witnessed (%d alive)", ubase);
    for (int i = 0; i < ND; i++) {
        base[i] = alive_count(wd[i], "churn");
        /* churn (children excluded) and leader-exit keep one long-lived role */
        int want =
            (!strcmp(MODES[i % NMODES], "churn") || !strcmp(MODES[i % NMODES], "leader-exit")) ? 1
                                                                                               : 2;
        CHECK(base[i] >= want, "A: domain %d (%s) established (%d alive)", i, MODES[i % NMODES],
              base[i]);
    }
    int survivors = 0, disturbed = 0;
    for (int k = 0; k < ND; k++) {
        int v = (k * 5) % ND; /* rotating termination order */
        procd_termination_evidence ev;
        procd_status rc = procd_domain_terminate(d[v], 5000, &ev);
        CHECK(rc == PROCD_OK, "A: terminate domain %d: %s", v, procd_status_name(rc));
        nap(50);
        int left = alive_count(wd[v], NULL);
        survivors += left;
        CHECK(left == 0, "A: domain %d (%s) left %d survivor(s)", v, MODES[v % NMODES], left);
        procd_domain_release(d[v]);
        d[v] = NULL;
        for (int j = 0; j < ND; j++)
            if (d[j]) {
                int a = alive_count(wd[j], "churn");
                /* churn's root and every other role live for the TTL */
                if (a < base[j]) {
                    disturbed++;
                    CHECK(0, "A: terminating domain %d disturbed domain %d (%d/%d alive)", v, j, a,
                          base[j]);
                }
            }
        int ua = alive_count(ud, NULL);
        CHECK(ua == ubase && waitpid(ctl, NULL, WNOHANG) == 0,
              "A: unrelated tree disturbed after terminating domain %d (%d/%d)", v, ua, ubase);
    }
    printf("A: %d live domains terminated one at a time: %d survivors, %d cross-domain "
           "disturbances, unrelated tree %s\n",
           ND, survivors, disturbed, alive_count(ud, NULL) == ubase ? "intact" : "DISTURBED");
    kill_all(ud);
    kill(ctl, SIGKILL);
    waitpid(ctl, NULL, 0);
    for (int i = 0; i < ND; i++)
        w_dir_remove(wd[i]);
    w_dir_remove(ud);
}

/* ---------------- B. concurrent domain churn ---------------- */

static long b_cycles, b_survivors, b_released_live;
static pthread_mutex_t b_mu = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    int t = (int)(long)arg;
    unsigned seed = (unsigned)t * 2654435761u;
    for (int i = 0; i < 40; i++) {
        char wd[64];
        if (w_dir_create(wd, sizeof wd) != 0) continue;
        procd_domain *d = new_domain();
        if (!d) {
            CHECK(0, "B: create failed");
            continue;
        }
        const char *mode = MODES[(t + i) % NMODES];
        CHECK(spawn_adv(d, wd, mode), "B: spawn %s", mode);
        seed = seed * 1103515245u + 12345u;
        int delay = (int)(seed >> 16) % 40;
        for (long long end = mono_ms() + delay; mono_ms() < end; nap(2)) {
            procd_domain_status st;
            procd_domain_status_get(d, &st);
        }
        int release_live = (i % 4) == 3;
        if (!release_live) {
            procd_termination_evidence ev;
            procd_status rc = procd_domain_terminate(d, 5000, &ev);
            CHECK(rc == PROCD_OK, "B: terminate %s: %s", mode, procd_status_name(rc));
        }
        procd_domain_release(d); /* destroy while fork events may be pending */
        nap(release_live ? 20 : 60);
        int left = release_live ? 0 : alive_count(wd, NULL);
        CHECK(left == 0, "B: thread %d cycle %d (%s): %d survivor(s)", t, i, mode, left);
        kill_all(wd); /* released-without-terminate leftovers: hygiene */
        w_dir_remove(wd);
        pthread_mutex_lock(&b_mu);
        b_cycles++;
        b_survivors += left;
        b_released_live += release_live;
        pthread_mutex_unlock(&b_mu);
    }
    return NULL;
}

static void phase_concurrent(void) {
    pthread_t th[6];
    for (long i = 0; i < 6; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);
    for (int i = 0; i < 6; i++)
        pthread_join(th[i], NULL);
    printf("B: %ld concurrent cycles on 6 threads (%ld released while running): %ld survivors\n",
           b_cycles, b_released_live, b_survivors);
}

/* ---------------- C. rapid create/destroy ---------------- */

static void phase_rapid(void) {
    for (int i = 0; i < 300; i++) {
        procd_domain *d = new_domain();
        CHECK(d != NULL, "C: create %d", i);
        if (d) procd_domain_release(d);
    }
    int n = 0;
    for (int i = 0; i < 60; i++) {
        char wd[64];
        if (w_dir_create(wd, sizeof wd) != 0) continue;
        procd_domain *d = new_domain();
        if (d && spawn_adv(d, wd, "churn")) n++;
        if (d) procd_domain_release(d); /* registry removal racing fork events */
        nap(5);
        kill_all(wd);
        w_dir_remove(wd);
    }
    printf("C: 300 create/release and %d spawn-then-release cycles completed\n", n);
}

/* ---------------- status-reap regression ---------------- */

static int read_pid(const char *path, long *pid, unsigned long long *mtime_us) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int ok = fscanf(f, "%ld", pid) == 1;
    fclose(f);
    struct stat st;
    if (!ok || stat(path, &st) != 0) return -1;
    *mtime_us = (unsigned long long)st.st_mtimespec.tv_sec * 1000000ULL +
                (unsigned long long)st.st_mtimespec.tv_nsec / 1000;
    return 0;
}

static int status_reap(void) {
    setenv("PROCD_NC_NO_WATCH", "1", 1);
    int leaks = 0, jobs = 0, fallback = 0;
    const int N = 30;
    for (int it = 0; it < N; it++) {
        char dir[] = "/tmp/procd_reap.XXXXXX";
        if (!mkdtemp(dir)) return 1;
        procd_domain *d = new_domain();
        if (!d) return 1;
        const char *av[] = {"/bin/sh", "-c",
                            "sleep 30 & echo $! > \"$0/a\"; sleep 30 & echo $! > \"$0/b\"; exit 0",
                            dir, NULL};
        int64_t leader;
        procd_domain_spawn(d, av, &leader);
        procd_domain_status st;
        for (int i = 0; i < 8; i++) { /* polled from the moment of spawn */
            procd_domain_status_get(d, &st);
            nap(i < 4 ? 0 : 20);
        }
        procd_termination_evidence ev;
        procd_domain_terminate(d, 5000, &ev);
        fallback += ev.detail && strstr(ev.detail, "event-assisted tracking unavailable") != NULL;
        procd_domain_release(d);
        nap(100);
        for (int k = 0; k < 2; k++) {
            char p[64];
            snprintf(p, sizeof p, "%s/%c", dir, "ab"[k]);
            long pid;
            unsigned long long mt;
            if (read_pid(p, &pid, &mt) != 0) continue;
            jobs++;
            struct proc_bsdinfo bi;
            if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi &&
                bi.pbi_status != SZOMB &&
                (unsigned long long)bi.pbi_start_tvsec * 1000000ULL + bi.pbi_start_tvusec <=
                    mt + 1000) {
                leaks++;
                printf("  leaked background job pid=%ld (%s)\n", pid, bi.pbi_name);
                kill((pid_t)pid, SIGKILL);
            }
            unlink(p);
        }
        rmdir(dir);
    }
    printf("status-reap: %d/%d background jobs leaked across %d immediate-status cycles; "
           "reconciliation-only supervision in %d/%d\n",
           leaks, jobs, N, fallback, N);
    CHECK(jobs >= N, "status-reap: background jobs were not created (%d)", jobs);
    CHECK(fallback == N, "status-reap: watcher was not disabled (%d/%d)", fallback, N);
    CHECK(leaks == 0, "status-reap: status reaped the leader before its group was scanned");
    return fails ? 1 : 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        printf("usage: %s <adversary> stress|status-reap\n", argv[0]);
        return 2;
    }
    g_adv = argv[1];
    setenv("PROCD_ADV_TTL", "12", 1);
    if (!strcmp(argv[2], "status-reap")) return status_reap();
    phase_many();
    phase_concurrent();
    phase_rapid();
    printf("%s (%d failures)\n", fails ? "FAILURES" : "shared watcher checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only watcher regression\n");
    return 77;
}
#endif
