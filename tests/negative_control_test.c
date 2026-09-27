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
 * For every backend that claims a hard guarantee, we must prove the test
 * harness can OBSERVE the escape it claims to prevent. The weakened phase
 * links the TEST-ONLY negative-control library variant (libprocd_nc), which
 * exposes a switch (PROCD_NC_WEAKEN=1). On Windows, the production comparison
 * runs in a fresh helper linked to the real production library, so test-only
 * process-global state cannot contaminate the comparison.
 *
 *   Phase A (weakened):   run the SAME adversarial strategy against a weakened
 *                         boundary and assert the descendant ESCAPES and
 *                         survives domain termination. If we cannot observe the
 *                         escape, the harness cannot prove it detects escape ->
 *                         the whole negative control is meaningless -> FAIL.
 *   Phase B (production): run the SAME strategy against the production boundary
 *                         and assert the escape is PREVENTED and termination
 *                         catches all owned execution.
 *
 * Each phase counts only if the adversarial action itself was independently
 * witnessed (the attempt and its outcome), and survival is judged by
 * (pid, start time) plus the escape cgroup's own membership, not by procd.
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
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
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
#define NC_TTL_S 15
/* independent oracle: is `pid` listed in cgroup `cg`? (-1 unreadable) */
static int cg_has(const char *cg, long pid) {
    char p[700], b[4096];
    snprintf(p, sizeof p, "%s/cgroup.procs", cg);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r < 0) return -1;
    b[r] = 0;
    for (char *s = b; *s;) {
        if (strtol(s, &s, 10) == pid) return 1;
        while (*s == '\n')
            s++;
    }
    return 0;
}
static int cg_nprocs(const char *cg) {
    char p[700], b[4096];
    snprintf(p, sizeof p, "%s/cgroup.procs", cg);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r < 0) return -1;
    int n = 0;
    for (ssize_t i = 0; i < r; i++)
        n += b[i] == '\n';
    return n;
}

/*
 * Returns 1 if the migrate attempt was witnessed to SUCCEED and the migrated
 * process demonstrably survived domain termination; 0 if the attempt was
 * witnessed to be DENIED and the attacker demonstrably died with the domain;
 * -1 if the adversarial action was not observed (inconclusive, never a pass).
 */
static int run_phase(int weaken, const char *adv, char *reason, size_t rn) {
    set_env("PROCD_NC_WEAKEN", weaken ? "1" : NULL);
    set_env("PROCD_ADV_TTL", "15"); /* NC_TTL_S */

    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_REQUIRE_ENFORCED;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        snprintf(reason, rn, "enforced create failed");
        return -1;
    }

    char id[PROCD_IDENTITY_MAX];
    procd_domain_identity(d, id, sizeof id);
    /* identity ends with the cgroup path; escape target = sibling cgroup */
    char parent[512];
    snprintf(parent, sizeof parent, "%s", strrchr(id, ':') + 1);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = 0;
    char escape[600];
    snprintf(escape, sizeof escape, "%s/procd_escape_%s", parent, weaken ? "A" : "B");
    mkdir(escape, 0755); /* root-owned; workload (nobody) cannot write in prod */
    set_env("PROCD_ADV_ESCAPE_CGROUP", escape);

    char wd[64];
    if (w_dir_create(wd, sizeof wd) != 0) {
        snprintf(reason, rn, "cannot create witness dir");
        procd_domain_release(d);
        rmdir(escape);
        return -1;
    }
    set_env(W_ENV, wd);

    const char *argv[] = {adv, "migrate", NULL};
    int64_t root = -1;
    int result = -1;
    long long t0 = mono_ms();
    if (procd_domain_spawn(d, argv, &root) != PROCD_OK) {
        snprintf(reason, rn, "spawn failed");
        goto out;
    }

    /* wait (bounded) until the migrate attempt and its outcome are witnessed */
    w_rec w[W_MAX];
    int n = 0;
    const w_rec *ok = NULL, *denied = NULL, *r = NULL;
    for (int i = 0; i < 250 && !ok && !denied; i++) {
        nap(20);
        n = w_read(wd, w, W_MAX);
        r = w_find(w, n, "root");
        ok = w_find(w, n, "migrate-ok");
        denied = w_find(w, n, "migrate-denied");
    }
    const w_rec *att = ok ? ok : denied;
    if (!r || r->pid != (long)root || !att || att->ppid != r->pid) {
        snprintf(reason, rn, "adversarial migrate attempt NOT observed (root=%d attempt=%d)", !!r,
                 !!att);
        procd_termination_evidence ev;
        procd_domain_terminate(d, 8000, &ev);
        goto out;
    }
    int in_escape_before = cg_has(escape, att->pid);

    procd_termination_evidence ev;
    procd_domain_terminate(d, 8000, &ev);
    nap(100);

    int alive = w_alive(att);
    int in_escape_after = cg_has(escape, att->pid);
    /* "attacker dead" only means "killed" well inside its bounded lifetime */
    if (mono_ms() - t0 + 2000 >= NC_TTL_S * 1000) {
        snprintf(reason, rn, "ORACLE INCONCLUSIVE: termination outlasted the fixture lifetime");
        goto out;
    }
    snprintf(reason, rn,
             "attempt=%s; attacker in escape cgroup before=%d after=%d; attacker alive after "
             "domain termination=%d; domain emptiness_proven=%d",
             ok ? "SUCCEEDED" : "DENIED", in_escape_before, in_escape_after, alive,
             ev.emptiness_proven);
    if (ok && in_escape_before == 1 && in_escape_after == 1 && alive)
        result = 1; /* escape demonstrated end to end */
    else if (denied && in_escape_before == 0 && !alive && cg_nprocs(escape) == 0)
        result = 0; /* escape attempted, denied, attacker terminated with the domain */
    if (att && w_alive(att)) kill((pid_t)att->pid, SIGKILL);

out:
    /* cleanup escape cgroup regardless of outcome (bounded anyway) */
    {
        char kp[700];
        snprintf(kp, sizeof kp, "%s/cgroup.kill", escape);
        int fd = open(kp, O_WRONLY);
        if (fd >= 0) {
            ssize_t wr = write(fd, "1", 1);
            (void)wr;
            close(fd);
        }
    }
    for (int i = 0; i < 100 && cg_nprocs(escape) > 0; i++)
        nap(10);
    rmdir(escape);
    procd_domain_release(d);
    set_env(W_ENV, NULL);
    w_dir_remove(wd);
    return result;
}

static int strict(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    return v && strcmp(v, "1") == 0;
}

int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (c.process_tree_termination != PROCD_CAP_ENFORCED || geteuid() != 0) {
        printf("%s: linux enforced prerequisites unavailable (%s, euid=%d)\n",
               strict() ? "FAIL" : "SKIP", c.detail, (int)geteuid());
        return strict() ? 1 : 77;
    }
    char ra[256], rb[256];
    int a = run_phase(1, adv, ra, sizeof ra); /* weakened: expect escape */
    int b = run_phase(0, adv, rb, sizeof rb); /* production: expect no escape */
    printf("weakened  : %s -> %s\n", ra,
           a == 1   ? "ESCAPE OBSERVED (expected)"
           : a == 0 ? "no escape"
                    : "INCONCLUSIVE");
    printf("production: %s -> %s\n", rb,
           b == 0   ? "escape PREVENTED (expected)"
           : b == 1 ? "ESCAPE!"
                    : "INCONCLUSIVE");
    if (a != 1) {
        printf("FAIL: harness could not observe escape under weakened boundary\n");
        return 1;
    }
    if (b != 0) {
        printf("FAIL: production boundary did not demonstrably prevent the same escape\n");
        return 1;
    }
    printf("PASS: harness detects escape; production prevents it\n");
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
