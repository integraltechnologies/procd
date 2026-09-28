#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Negative control.
 *
 * For every backend that claims a lifecycle guarantee, we must prove the test
 * harness can OBSERVE the failure the mechanism prevents. The weakened phase
 * links the TEST-ONLY negative-control library variant (libprocd_nc), which
 * exposes a switch (PROCD_NC_WEAKEN=1). On Windows, the production comparison
 * runs in a fresh helper linked to the real production library, so test-only
 * process-global state cannot contaminate the comparison.
 *
 *   Phase A (weakened):   run the SAME workload against weakened supervision
 *                         and assert a descendant SURVIVES termination. If we
 *                         cannot observe that, the harness cannot prove it
 *                         detects the failure -> FAIL.
 *   Phase B (production): run the SAME workload against the production
 *                         mechanism and assert termination removes it.
 *
 *   Linux:   weakened = process-group termination; the workload's descendant
 *            detaches with setsid / a double fork (ordinary topology changes).
 *   Windows: weakened = a Job that permits breakaway.
 *
 * Each phase counts only if the workload's topology was independently witnessed,
 * and survival is judged by (pid, start time), not by procd.
 *
 * Bounded: every adversary process self-terminates (PROCD_ADV_TTL). On hosts
 * lacking the enforced prerequisites the test exits 77 (ctest "skipped") with a
 * structured reason, never a false PASS; with PROCD_REQUIRE_ENFORCED=1 it
 * fails instead.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(_WIN32)
static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (v)
        setenv(k, v, 1);
    else
        unsetenv(k);
#endif
}
#endif

/* ================= Linux ================= */
#if defined(__linux__)
#include "witness.h"
#include <signal.h>
#include <time.h>
#include <unistd.h>

/*
 * Lifecycle negative control. The weakened phase replaces cgroup termination
 * with process-group termination of the spawned leader (PROCD_NC_WEAKEN=1 in
 * the test-only library). The workload then makes an ORDINARY topology change:
 * a setsid'd child, or a double-forked daemon. Process-group termination must
 * leave that descendant running (proving the oracle can see a survivor), and
 * production cgroup termination must remove the very same topology.
 */
static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#define NC_TTL_S 15

/* 1 = the detached descendant survived termination, 0 = it was terminated,
 * -1 = inconclusive (topology not witnessed, or oracle too close to the
 * fixtures' natural lifetime). */
static int run_phase(int weaken, const char *adv, const char *mode, const char *role, char *reason,
                     size_t rn) {
    set_env("PROCD_NC_WEAKEN", weaken ? "1" : NULL);
    set_env("PROCD_ADV_TTL", "15"); /* NC_TTL_S */

    procd_policy pol = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        snprintf(reason, rn, "create failed");
        return -1;
    }
    char wd[64];
    if (w_dir_create(wd, sizeof wd) != 0) {
        snprintf(reason, rn, "cannot create witness dir");
        procd_domain_release(d);
        return -1;
    }
    set_env(W_ENV, wd);

    const char *argv[] = {adv, mode, NULL};
    int64_t root = -1;
    int result = -1;
    long long t0 = mono_ms();
    procd_termination_evidence ev;
    memset(&ev, 0, sizeof ev);
    static w_rec w[W_MAX];
    int n = 0;
    const w_rec *r = NULL, *det = NULL;
    if (procd_domain_spawn(d, argv, &root) != PROCD_OK) {
        snprintf(reason, rn, "spawn failed");
        goto out;
    }
    /* wait (bounded) until the detached descendant is witnessed in its own session */
    for (int i = 0; i < 250 && !det; i++) {
        nap(20);
        n = w_read(wd, w, W_MAX);
        r = w_find(w, n, "root");
        det = w_find(w, n, role);
        if (det && (!r || det->sid == r->sid || !w_live(det))) det = NULL; /* kernel agrees */
    }
    if (!r || r->pid != (long)root || !det) {
        snprintf(reason, rn, "detached '%s' descendant NOT observed", role);
        procd_domain_terminate(d, 3000, &ev);
        goto out;
    }

    procd_domain_terminate(d, weaken ? 1000 : 5000, &ev);
    int alive = w_alive(det);
    for (int i = 0; i < 50 && alive; i++) { /* allow the kill / reaping to land */
        nap(20);
        alive = w_alive(det);
    }
    if (mono_ms() - t0 + 2000 >= NC_TTL_S * 1000) {
        snprintf(reason, rn, "ORACLE INCONCLUSIVE: termination outlasted the fixture lifetime");
        goto out;
    }
    snprintf(reason, rn,
             "%s: descendant pid=%ld sid=%ld (leader sid=%ld) alive after terminate=%d; "
             "emptiness_proven=%d final=%s",
             mode, det->pid, det->sid, r->sid, alive, ev.emptiness_proven,
             procd_state_name(ev.final_state));
    result = alive ? 1 : 0;

out:
    n = w_read(wd, w, W_MAX); /* hygiene: never leave a fixture behind */
    for (int i = 0; i < n; i++)
        if (w_alive(&w[i])) kill((pid_t)w[i].pid, SIGKILL);
    if (weaken) procd_domain_terminate(d, 3000, &ev);
    procd_domain_release(d);
    set_env(W_ENV, NULL);
    set_env("PROCD_NC_WEAKEN", NULL);
    w_dir_remove(wd);
    return result;
}

int main(int argc, char **argv) {
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
    static const char *const cases[][2] = {{"setsid", "setsid"}, {"double-fork", "df-grandchild"}};
    int bad = 0;
    for (int i = 0; i < 2; i++) {
        char ra[320], rb[320];
        int a = run_phase(1, adv, cases[i][0], cases[i][1], ra, sizeof ra);
        int b = run_phase(0, adv, cases[i][0], cases[i][1], rb, sizeof rb);
        printf("process-group termination: %s -> %s\n", ra,
               a == 1   ? "SURVIVED (expected)"
               : a == 0 ? "terminated"
                        : "INCONCLUSIVE");
        printf("cgroup termination       : %s -> %s\n", rb,
               b == 0   ? "terminated (expected)"
               : b == 1 ? "SURVIVED!"
                        : "INCONCLUSIVE");
        if (a != 1) {
            printf("FAIL: harness did not observe the %s survivor under process-group "
                   "termination\n",
                   cases[i][0]);
            bad = 1;
        }
        if (b != 0) {
            printf("FAIL: cgroup termination did not remove the same %s topology\n", cases[i][0]);
            bad = 1;
        }
    }
    if (bad) return 1;
    printf("PASS: process-group termination leaves detached descendants; the cgroup domain "
           "removes them\n");
    return 0;
}

/* ================= Windows ================= */
#elif defined(_WIN32)
#include <windows.h>

/* Bounded interval we allow for a just-terminated process object to reach the
 * signaled state after Job termination before ruling on survival (see the
 * asynchronous-rundown note in run_phase). */
#define NC_KILL_WAIT_MS 5000

/* Creation time of a process, used to bind a retained handle to the exact
 * process object the launcher created (PID + creation time), so a later PID
 * reuse cannot alias it. Matches the launcher's own GetProcessTimes reading. */
static unsigned long long process_created(HANDLE h) {
    FILETIME create, exit, kernel, user;
    if (!h || !GetProcessTimes(h, &create, &exit, &kernel, &user)) return 0;
    return ((unsigned long long)create.dwHighDateTime << 32) | create.dwLowDateTime;
}

static DWORD read_pidfile(const char *pf) {
    for (int i = 0; i < 200; i++) {
        FILE *f = fopen(pf, "r");
        if (f) {
            unsigned long v = 0;
            int ok = fscanf(f, "%lu", &v);
            fclose(f);
            if (ok == 1 && v) return (DWORD)v;
        }
        Sleep(10);
    }
    return 0;
}

static int read_outcome(const char *path, DWORD child, int *requested, DWORD *request_error,
                        unsigned long long *created) {
    for (int i = 0; i < 200; i++) {
        FILE *f = fopen(path, "r");
        if (f) {
            char route[40] = {0};
            unsigned long pid = 0, error = 0;
            unsigned long long ct = 0;
            int n = fscanf(f, "%39s %lu %lu %llu", route, &pid, &error, &ct);
            fclose(f);
            if (n == 4 && pid == child) {
                *request_error = (DWORD)error;
                *created = ct;
                if (strcmp(route, "requested-breakaway") == 0)
                    *requested = 1;
                else if (strcmp(route, "contained-fallback") == 0)
                    *requested = 0;
                else
                    *requested = -1;
                return 1;
            }
        }
        Sleep(10);
    }
    return 0;
}
static int proc_alive(HANDLE h) {
    return h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
}
/* Bounded liveness verdict. TerminateJobObject and the Job's active-process
 * accounting are asynchronous with respect to an individual process object
 * transitioning to the signaled (terminated) state, so a correct "ceased
 * execution" oracle waits a bounded interval for the retained handle to become
 * signaled rather than sampling it once. Returns 1 iff the process is observed
 * to have exited within timeout ms; a genuine escapee stays unsignaled. */
static int proc_dead_within(HANDLE h, DWORD timeout) {
    return h && WaitForSingleObject(h, timeout) == WAIT_OBJECT_0;
}
static void kill_process(HANDLE h) {
    if (h) {
        if (proc_alive(h)) TerminateProcess(h, 0);
        WaitForSingleObject(h, 2000);
    }
}

static int run_phase(int weaken, const char *adv, int *requested, char *reason, size_t rn) {
    set_env("PROCD_NC_WEAKEN", weaken ? "1" : NULL);
    set_env("PROCD_ADV_TTL", "15");
    char pf[MAX_PATH];
    GetTempPathA((DWORD)sizeof pf, pf);
    char pidfile[MAX_PATH * 2];
    snprintf(pidfile, sizeof pidfile, "%sprocd_nc_%d.pid", pf, weaken);
    char outcome_file[MAX_PATH * 2];
    snprintf(outcome_file, sizeof outcome_file, "%sprocd_nc_%d.outcome", pf, weaken);
    DeleteFileA(pidfile);
    DeleteFileA(outcome_file);
    set_env("PROCD_ADV_PIDFILE", pidfile);
    set_env("PROCD_ADV_OUTCOME_FILE", outcome_file);

    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        snprintf(reason, rn, "create failed");
        return -1;
    }
    const char *argv[] = {adv, "breakaway", NULL};
    if (procd_domain_spawn(d, argv, NULL) != PROCD_OK) {
        snprintf(reason, rn, "spawn failed");
        procd_domain_release(d);
        return -1;
    }

    DWORD child = read_pidfile(pidfile);
    DWORD request_error = 0;
    unsigned long long outcome_created = 0;
    int outcome_seen =
        child && read_outcome(outcome_file, child, requested, &request_error, &outcome_created);
    /* Open and retain the exact process object before termination, and bind the
     * verdict to the creation time the launcher recorded for it: the retained
     * handle is a durable identity oracle that later PID reuse cannot fool. */
    HANDLE child_process = NULL;
    if (child) {
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                               FALSE, child);
        if (h && outcome_seen && outcome_created && process_created(h) != outcome_created)
            CloseHandle(h); /* PID was reused: not the launched process */
        else
            child_process = h;
    }
    int witnessed_alive = proc_alive(child_process);
    Sleep(300);
    procd_termination_evidence ev;
    procd_domain_terminate(d, 8000, &ev);
    /* Survival after termination is asynchronous from the test's perspective:
     * procd_domain_terminate waits for the Job's active-process count to reach
     * zero, but a contained process object can transition to signaled a moment
     * later. Measure ACTUAL execution survival with a bounded wait for the
     * retained handle to become signaled -- never a single instantaneous
     * sample, which races the OS rundown and would misreport a contained but
     * still-dying process as alive. An escapee stays unsignaled for the whole
     * interval, so the discrimination is preserved. */
    int alive_after = -1;
    if (child_process) alive_after = proc_dead_within(child_process, NC_KILL_WAIT_MS) ? 0 : 1;
    snprintf(reason, rn,
             "route=%s request_error=%lu child_pid=%lu witnessed_alive_before=%d "
             "emptiness_proven=%d alive_after_kill=%d",
             outcome_seen ? (*requested == 1   ? "requested-breakaway"
                             : *requested == 0 ? "contained-fallback"
                                               : "creation-failed")
                          : "unwitnessed",
             (unsigned long)request_error, child, witnessed_alive, ev.emptiness_proven,
             alive_after);
    if (child_process) {
        kill_process(child_process);
        CloseHandle(child_process);
    }
    procd_domain_release(d);
    DeleteFileA(pidfile);
    DeleteFileA(outcome_file);
    set_env("PROCD_ADV_PIDFILE", NULL);
    set_env("PROCD_ADV_OUTCOME_FILE", NULL);
    if (!child || !witnessed_alive || !outcome_seen) return -1;
    return alive_after; /* 1 = escaped/survived, 0 = contained/killed */
}

#if defined(PROCD_NC_PRODUCTION_HELPER)
int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary.exe";
    char reason[256];
    int requested = -1;
    int result = run_phase(0, adv, &requested, reason, sizeof reason);
    printf("production helper (linked to production procd): %s -> %s\n", reason,
           result == 0 && requested == 0 ? "contained fallback observed (expected)" : "FAIL");
    return result == 0 && requested == 0 ? 0 : 1;
}
#else
static int run_production_helper(const char *helper, const char *adv) {
    char cmd[MAX_PATH * 4];
    snprintf(cmd, sizeof cmd, "\"%s\" \"%s\"", helper, adv);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return -1;
    CloseHandle(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    if (wait == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    return wait == WAIT_OBJECT_0 && code == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary.exe";
    const char *production_helper = (argc > 2) ? argv[2] : NULL;
    char ra[256];
    int requested = -1;
    int a = run_phase(1, adv, &requested, ra, sizeof ra); /* weakened: expect escape */
    int production_ok = production_helper ? run_production_helper(production_helper, adv) : -1;
    const char *weakened_result = "INCONCLUSIVE";
    if (a == 1 && requested == 1)
        weakened_result = "ESCAPE OBSERVED (expected)";
    else if (a == 0)
        weakened_result = "no escape";
    printf("weakened  : %s -> %s\n", ra, weakened_result);
    printf("production: separately executed production-linked helper -> %s\n",
           production_ok == 0 ? "contained (expected)" : "FAIL/INCONCLUSIVE");
    if (a != 1 || requested != 1) {
        printf("FAIL: harness could not observe breakaway escape under weakened Job\n");
        return 1;
    }
    if (production_ok != 0) {
        printf("FAIL: production-linked helper did not demonstrate contained fallback\n");
        return 1;
    }
    printf("PASS: harness detects breakaway escape; production Job prevents it\n");
    return 0;
}
#endif

/* ================= macOS / other ================= */
#else
int main(void) {
    /* No backend on this platform claims ENFORCED ProcessTreeTermination, so
     * there is no hard guarantee for a negative control to falsify. */
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: no ENFORCED backend on this platform; negative control not applicable\n",
           strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
