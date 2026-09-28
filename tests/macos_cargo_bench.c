#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS supervision cost / cancellation bench on a real, fork-heavy Cargo
 * build (not part of ctest: needs a crate whose dependencies are cached).
 *
 *   procd-macos-cargo-bench <Cargo.toml> <scratch> full
 *       one supervised fresh `cargo build` to natural completion, with
 *       agentctl-like status polling every 100ms: wall time, host CPU, and the
 *       shared watcher's fork events, reconciliations and CPU (from the
 *       termination detail)
 *   procd-macos-cargo-bench <Cargo.toml> <scratch> cancel <ms> [<ms>...]
 *       fresh builds cancelled <ms> after spawn; any process still carrying
 *       the harness tag (cargo, rustc, build scripts expose their environment)
 *       after termination is a survivor
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <libproc.h>
#include <signal.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

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

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static double cpu_ms(void) {
    struct rusage r;
    getrusage(RUSAGE_SELF, &r);
    return (r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1e3 +
           (r.ru_utime.tv_usec + r.ru_stime.tv_usec) / 1e3;
}

/* running same-user processes whose exec env carries SOAK_TAG=<tag> */
static int tagged_alive(const char *tag, int kill_them) {
    static pid_t pids[16384];
    static char buf[1 << 20];
    char want[96];
    int wl = snprintf(want, sizeof want, "SOAK_TAG=%s", tag), found = 0;
    int n = proc_listallpids(pids, (int)sizeof pids);
    for (int i = 0; i < n; i++) {
        struct proc_bsdinfo bi;
        if (pids[i] <= 1 || pids[i] == getpid() ||
            proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi ||
            bi.pbi_status == SZOMB || bi.pbi_uid != getuid())
            continue;
        int mib[3] = {CTL_KERN, KERN_PROCARGS2, pids[i]};
        size_t len = sizeof buf;
        if (sysctl(mib, 3, buf, &len, NULL, 0) != 0) continue;
        for (size_t k = sizeof(int); k < len;) {
            size_t sl = strnlen(buf + k, len - k);
            if (sl == (size_t)wl && !memcmp(buf + k, want, (size_t)wl)) {
                found++;
                printf("  SURVIVOR pid=%d comm=%s ppid=%d\n", pids[i], bi.pbi_name, bi.pbi_ppid);
                if (kill_them) kill(pids[i], SIGKILL);
                break;
            }
            k += sl + 1;
        }
    }
    return found;
}

static int run(const char *manifest, const char *scratch, int seq, int cancel_ms) {
    char target[600], tag[64], cmd[1400];
    snprintf(target, sizeof target, "%s/bench-t%d-%d", scratch, (int)getpid(), seq);
    snprintf(tag, sizeof tag, "bench-%d-%d", (int)getpid(), seq);
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) return -1;
    setenv("CARGO_TARGET_DIR", target, 1);
    setenv("SOAK_TAG", tag, 1);
    const char *argv[] = {"/bin/sh", "-c",
                          "cargo build --locked --offline --quiet --manifest-path \"$0\" "
                          ">/dev/null 2>&1",
                          manifest, NULL};
    double c0 = cpu_ms();
    long long t0 = mono_ms();
    int64_t leader;
    procd_status rc = procd_domain_spawn(d, argv, &leader);
    unsetenv("CARGO_TARGET_DIR");
    unsetenv("SOAK_TAG");
    if (rc != PROCD_OK) return -1;
    procd_domain_status st;
    for (;;) {
        nap(100);
        procd_domain_status_get(d, &st);
        if (cancel_ms > 0 ? mono_ms() - t0 >= cancel_ms : st.population == PROCD_POP_EMPTY) break;
    }
    long long wall = mono_ms() - t0;
    procd_termination_evidence ev;
    long long k0 = mono_ms();
    rc = procd_domain_terminate(d, 5000, &ev);
    long long term = mono_ms() - k0;
    double host_cpu = cpu_ms() - c0;
    nap(300);
    int surv = tagged_alive(tag, 1);
    unsigned long long w[3];
    watch_parse(ev.detail, w);
    printf("%s%-6d wall=%lldms terminate=%lldms(%s) host-cpu=%.0fms events=%llu "
           "reconciliations=%llu watcher-cpu=%.0fms survivors=%d\n",
           cancel_ms > 0 ? "cancel@" : "full  ", cancel_ms, wall, term, procd_status_name(rc),
           host_cpu, w[0], w[1], (double)w[2] / 1e6, surv);
    procd_domain_release(d);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", target);
    if (system(cmd) != 0) printf("  (could not remove %s)\n", target);
    return surv;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 4) {
        printf("usage: %s <Cargo.toml> <scratch> full | cancel <ms>...\n", argv[0]);
        return 2;
    }
    int surv = 0;
    if (!strcmp(argv[3], "full"))
        surv = run(argv[1], argv[2], 0, 0);
    else
        for (int i = 4; i < argc; i++)
            surv += run(argv[1], argv[2], i, atoi(argv[i]));
    return surv ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: macOS-only bench\n");
    return 77;
}
#endif
