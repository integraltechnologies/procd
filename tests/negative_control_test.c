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
 * harness can OBSERVE the escape it claims to prevent. This test links the
 * TEST-ONLY negative-control library variant (libprocd_nc), which exposes a
 * switch (PROCD_NC_WEAKEN=1) that deliberately weakens the containment
 * boundary.
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
    char buf[1024];
    snprintf(buf, sizeof buf, "%s=%s", k, v ? v : "");
    _putenv(buf);
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
static int proc_alive(HANDLE h) {
    return h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
}
static void kill_process(HANDLE h) {
    if (h) {
        if (proc_alive(h)) TerminateProcess(h, 0);
        WaitForSingleObject(h, 2000);
    }
}

static int run_phase(int weaken, const char *adv, char *reason, size_t rn) {
    set_env("PROCD_NC_WEAKEN", weaken ? "1" : NULL);
    set_env("PROCD_ADV_TTL", "15");
    char pf[MAX_PATH];
    GetTempPathA((DWORD)sizeof pf, pf);
    char pidfile[MAX_PATH * 2];
    snprintf(pidfile, sizeof pidfile, "%sprocd_nc_%d.pid", pf, weaken);
    DeleteFileA(pidfile);
    set_env("PROCD_ADV_PIDFILE", pidfile);

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
    /* Open and retain the exact process object before termination. The verdict
     * cannot be fooled by later PID reuse. */
    HANDLE child_process =
        child ? OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                            FALSE, child)
              : NULL;
    int witnessed_alive = proc_alive(child_process);
    Sleep(300);
    procd_termination_evidence ev;
    procd_domain_terminate(d, 8000, &ev);
    int alive_after = child_process ? proc_alive(child_process) : -1;
    snprintf(reason, rn,
             "child_pid=%lu witnessed_alive_before=%d emptiness_proven=%d alive_after_kill=%d",
             child, witnessed_alive, ev.emptiness_proven, alive_after);
    if (child_process) {
        kill_process(child_process);
        CloseHandle(child_process);
    }
    procd_domain_release(d);
    DeleteFileA(pidfile);
    if (!child || !witnessed_alive) return -1;
    return alive_after; /* 1 = escaped/survived, 0 = contained/killed */
}

int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary.exe";
    char ra[160], rb[160];
    int a = run_phase(1, adv, ra, sizeof ra); /* weakened breakaway: expect survive */
    int b = run_phase(0, adv, rb, sizeof rb); /* production: expect killed */
    printf("weakened  : %s -> %s\n", ra,
           a == 1   ? "ESCAPE OBSERVED (expected)"
           : a == 0 ? "no escape"
                    : "INCONCLUSIVE");
    printf("production: %s -> %s\n", rb,
           b == 0   ? "contained (expected)"
           : b == 1 ? "ESCAPE!"
                    : "INCONCLUSIVE");
    if (a != 1) {
        printf("FAIL: harness could not observe breakaway escape under weakened Job\n");
        return 1;
    }
    if (b != 0) {
        printf("FAIL: production Job allowed breakaway escape\n");
        return 1;
    }
    printf("PASS: harness detects breakaway escape; production Job prevents it\n");
    return 0;
}

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
