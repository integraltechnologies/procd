#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS spawn-count regression (production library).
 *
 * A domain accepts any number of procd_domain_spawn calls: the backend keeps
 * bookkeeping only for direct children that can still hold their pid and
 * drops it once they are reaped. (Earlier it used a fixed 64-entry array and
 * refused the 65th spawn with PROCD_E_STATE.)
 *
 *   A. 300 sequential spawns in ONE domain, each verified to have actually run
 *      (its own witness record names the pid spawn returned) and to finish,
 *      with status polling reaping it; interleaved with failing spawns of a
 *      missing program (PROCD_E_NOT_FOUND) and of a non-executable file
 *      (PROCD_E_PERMISSION) that must report no pid and run nothing.
 *   B. after that, 24 concurrently live spawns (each with a child) in the same
 *      domain, all witnessed alive, then terminated with no survivor.
 *   C. no zombie children of this process remain, and an unrelated process
 *      survives everything.
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
#include <signal.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: " __VA_ARGS__);                                                          \
            printf("\n");                                                                          \
            fails++;                                                                               \
        }                                                                                          \
    } while (0)

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}

/* is `pid` running (not a zombie)? */
static int running(long pid) {
    struct proc_bsdinfo bi;
    return proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi &&
           bi.pbi_status != SZOMB;
}

/* zombie children of this process */
static int zombies(void) {
    pid_t kids[4096];
    int n = proc_listchildpids(getpid(), kids, (int)sizeof kids);
    int z = 0;
    for (int i = 0; i < n / (int)sizeof(pid_t) && i < 4096; i++) {
        struct proc_bsdinfo bi;
        if (proc_pidinfo(kids[i], PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi &&
            bi.pbi_status == SZOMB)
            z++;
    }
    return z;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "20", 1);

    char wd[64], ud[64];
    if (w_dir_create(wd, sizeof wd) != 0 || w_dir_create(ud, sizeof ud) != 0) {
        printf("FAIL: witness directories\n");
        return 1;
    }
    /* unrelated process, started without procd */
    pid_t ctl = fork();
    if (ctl == 0) {
        setenv(W_ENV, ud, 1);
        execl(adv, adv, "child", (char *)NULL);
        _exit(127);
    }
    /* a file that exists but is not executable */
    char nxdir[] = "/tmp/procd_noexec.XXXXXX", noexec[96];
    if (!mkdtemp(nxdir)) {
        printf("FAIL: temp directory\n");
        return 1;
    }
    snprintf(noexec, sizeof noexec, "%s/not-executable", nxdir);
    FILE *f = fopen(noexec, "w");
    if (f) fputs("#!/bin/sh\nexit 0\n", f), fclose(f);
    chmod(noexec, 0644);

    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        printf("FAIL: create domain\n");
        return 1;
    }
    setenv(W_ENV, wd, 1);

    /* A. sequential spawns, each proven to have run, plus failing spawns */
    const int N = 300;
    int ok = 0, ran = 0, notfound = 0, perm = 0;
    for (int i = 0; i < N; i++) {
        const char *av[] = {adv, "exit", NULL}; /* witnesses "root", then exits */
        int64_t pid = -1;
        procd_status rc = procd_domain_spawn(d, av, &pid);
        CHECK(rc == PROCD_OK && pid > 0, "A: spawn %d returned %s", i + 1, procd_status_name(rc));
        if (rc != PROCD_OK) break;
        ok++;
        char rec[128];
        snprintf(rec, sizeof rec, "%s/root.%lld", wd, (long long)pid);
        struct stat st;
        int seen = 0;
        for (int t = 0; t < 500 && !(seen = stat(rec, &st) == 0); t++)
            nap(2);
        CHECK(seen, "A: spawn %d (pid %lld) never ran", i + 1, (long long)pid);
        ran += seen;
        unlink(rec);
        for (int t = 0; t < 500 && running((long)pid); t++)
            nap(2);
        procd_domain_status s;
        procd_domain_status_get(d, &s); /* reaps the finished leader */

        if (i % 10 == 5) {
            const char *missing[] = {"/nonexistent/procd-no-such-program", NULL};
            int64_t mp = 0;
            rc = procd_domain_spawn(d, missing, &mp);
            CHECK(rc == PROCD_E_NOT_FOUND && mp == -1, "A: missing program -> %s (pid %lld)",
                  procd_status_name(rc), (long long)mp);
            notfound += rc == PROCD_E_NOT_FOUND;
            const char *nx[] = {noexec, NULL};
            rc = procd_domain_spawn(d, nx, &mp);
            CHECK(rc == PROCD_E_PERMISSION && mp == -1, "A: non-executable file -> %s (pid %lld)",
                  procd_status_name(rc), (long long)mp);
            perm += rc == PROCD_E_PERMISSION;
        }
    }
    static w_rec w[W_MAX];
    CHECK(w_read(wd, w, W_MAX) == 0, "A: a failed spawn left a witness (a workload ran)");
    printf("A: %d/%d sequential spawns succeeded, %d proven to have run; %d missing-program -> "
           "NOT_FOUND, %d non-executable -> PERMISSION\n",
           ok, N, ran, notfound, perm);

    /* B. concurrently live spawns in the same domain */
    const int L = 24;
    int live_ok = 0;
    for (int i = 0; i < L; i++) {
        const char *av[] = {adv, "child", NULL}; /* root + child, both live for the TTL */
        live_ok += procd_domain_spawn(d, av, NULL) == PROCD_OK;
    }
    int n = 0;
    for (int t = 0; t < 250; t++) {
        n = w_read(wd, w, W_MAX);
        if (w_count(w, n, "root") == L && w_count(w, n, "child") == L) break;
        nap(20);
    }
    int alive = 0;
    for (int i = 0; i < n; i++)
        alive += w_alive(&w[i]);
    CHECK(live_ok == L && n == 2 * L && alive == n, "B: %d/%d live spawns, %d/%d witnessed alive",
          live_ok, L, alive, 2 * L);
    procd_termination_evidence ev;
    procd_status rc = procd_domain_terminate(d, 5000, &ev);
    CHECK(rc == PROCD_OK, "B: terminate: %s", procd_status_name(rc));
    nap(100);
    int left = 0;
    for (int i = 0; i < n; i++)
        left += w_alive(&w[i]);
    CHECK(left == 0, "B: %d survivor(s) after terminate", left);
    printf("B: %d concurrently live spawns (%d processes witnessed) terminated, %d survivors\n",
           live_ok, n, left);

    /* C. nothing retained, nothing unrelated touched */
    procd_domain_release(d);
    unsetenv(W_ENV);
    int z = zombies();
    CHECK(z == 0, "C: %d zombie child(ren) left behind", z);
    int un = w_read(ud, w, W_MAX), ua = 0;
    for (int i = 0; i < un; i++)
        ua += w_alive(&w[i]);
    CHECK(un >= 2 && ua == un && waitpid(ctl, NULL, WNOHANG) == 0,
          "C: unrelated process tree disturbed (%d/%d alive)", ua, un);
    printf("C: zombies=%d, unrelated tree %d/%d alive\n", z, ua, un);

    for (int i = 0; i < un; i++)
        w_kill(&w[i]);
    kill(ctl, SIGKILL);
    waitpid(ctl, NULL, 0);
    unlink(noexec);
    rmdir(nxdir);
    w_dir_remove(wd);
    w_dir_remove(ud);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "macOS spawn checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only spawn regression\n");
    return 77;
}
#endif
