#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Lifecycle-domain establishment regression (Linux; root is needed only to SET
 * UP each environment, the checks themselves run in child processes).
 *
 * ENFORCED depends on whether procd can actually create and operate a cgroup-v2
 * domain, not on who the caller is:
 *
 *   A. read-only cgroup hierarchy -> not ENFORCED; REQUIRE_ENFORCED is refused
 *      and ALLOW_BEST_EFFORT creates nothing (no fabricated domain).
 *   B. unprivileged caller WITHOUT a delegated subtree (its cgroup is
 *      root-owned) -> not ENFORCED; both modes create nothing.
 *   C. unprivileged caller WITH a delegated subtree (directory and cgroup.procs
 *      chowned to it, as systemd delegation does) -> ENFORCED: the workload is
 *      spawned with the caller's own uid, a double-forked setsid descendant is
 *      grouped with it, and termination proves emptiness with no survivor.
 *   D. a recovered handle whose domain controls are no longer usable (read-only
 *      mount) is reported below ENFORCED and never claims proven emptiness.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define UNPRIV 65533

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

/* Results a child scenario reports back. -1 = not reached. */
typedef struct {
    int setup_ok;
    int ptt;        /* capabilities.process_tree_termination */
    int req_rc;     /* REQUIRE_ENFORCED create status */
    int allow_rc;   /* ALLOW_BEST_EFFORT create status */
    int level;      /* runtime level of the created / recovered domain */
    int spawn_rc;   /* spawn status */
    int uid_ok;     /* workload ran with the caller's uid */
    int grouped;    /* the setsid'd grandchild was in the domain */
    int pop_auth;   /* status.population_is_authoritative */
    int proven;     /* terminate evidence.emptiness_proven */
    int final;      /* terminate evidence.final_state */
    int survivors;  /* processes of the workload alive after terminate */
    int recover_rc; /* recovery outcome */
} scen;

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static int write_str(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t w = write(fd, s, strlen(s));
    close(fd);
    return w < 0 ? -1 : 0;
}
/* absolute path of this process's cgroup-v2 cgroup (the "0::" line) */
static void own_cgroup(char *out, size_t n) {
    char b[4096] = {0};
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    b[r > 0 ? r : 0] = 0;
    const char *rel = "/";
    for (char *line = strtok(b, "\n"); line; line = strtok(NULL, "\n"))
        if (strncmp(line, "0::", 3) == 0) rel = line + 3;
    snprintf(out, n, "/sys/fs/cgroup%s", strcmp(rel, "/") == 0 ? "" : rel);
}
static int make_cgroup_readonly(void) {
    if (unshare(CLONE_NEWNS) != 0) return 0;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return 0;
    /* per-mount read-only bind remount: the parent's view is unaffected */
    if (mount("/sys/fs/cgroup", "/sys/fs/cgroup", NULL, MS_BIND, NULL) != 0) return 0;
    if (mount(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) != 0) return 0;
    struct statvfs v;
    return statvfs("/sys/fs/cgroup", &v) == 0 && (v.f_flag & ST_RDONLY);
}
/* move into cgroup dir `cg` (if given) and become UNPRIV with no groups */
static int become_unprivileged(const char *cg) {
    if (cg) {
        char procs[700], me[16];
        snprintf(procs, sizeof procs, "%s/cgroup.procs", cg);
        snprintf(me, sizeof me, "%d", (int)getpid());
        if (write_str(procs, me) != 0) return 0;
    }
    return setgroups(0, NULL) == 0 && setresgid(UNPRIV, UNPRIV, UNPRIV) == 0 &&
           setresuid(UNPRIV, UNPRIV, UNPRIV) == 0 && geteuid() == UNPRIV;
}
/* executing (exists and is not a zombie awaiting its reaper) */
static int executing(long pid) {
    char p[64], b[512];
    snprintf(p, sizeof p, "/proc/%ld/stat", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (r <= 0) return 0;
    b[r] = 0;
    char *e = strrchr(b, ')');
    return e && e[1] == ' ' && e[2] != 'Z' && e[2] != 'X';
}
static long uid_of(pid_t pid) {
    char p[64], b[2048];
    snprintf(p, sizeof p, "/proc/%d/status", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (r <= 0) return -1;
    b[r] = 0;
    char *u = strstr(b, "\nUid:");
    return u ? strtol(u + 5, NULL, 10) : -1;
}

/* Probe + create in both modes; releases anything created. */
static void probe_and_create(scen *s) {
    procd_capabilities c;
    procd_capabilities_probe(&c);
    s->ptt = (int)c.process_tree_termination;
    procd_policy p = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    s->req_rc = (int)procd_create_domain(&p, &d);
    if (d) procd_domain_release(d);
    p.enforcement = PROCD_ALLOW_BEST_EFFORT;
    d = NULL;
    s->allow_rc = (int)procd_create_domain(&p, &d);
    if (d) procd_domain_release(d);
}

/* C: full lifecycle as the delegated unprivileged caller. */
static void delegated_lifecycle(scen *s) {
    procd_policy p = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    s->req_rc = (int)procd_create_domain(&p, &d);
    if (!d) return;
    procd_domain_status st;
    procd_domain_status_get(d, &st);
    s->level = (int)st.process_tree_termination;
    /* a leader plus a setsid'd, double-forked (reparented) descendant */
    const char *av[] = {"/bin/sh", "-c",
                        "setsid sh -c 'sleep 30 & echo $! > /tmp/procd_est_gc' &"
                        " exec sleep 30",
                        NULL};
    int64_t pid = -1;
    unlink("/tmp/procd_est_gc");
    s->spawn_rc = (int)procd_domain_spawn(d, av, &pid);
    long gc = 0;
    for (int i = 0; i < 100 && gc <= 0; i++) {
        nap(20);
        FILE *f = fopen("/tmp/procd_est_gc", "r");
        if (f) {
            if (fscanf(f, "%ld", &gc) != 1) gc = 0;
            fclose(f);
        }
    }
    s->uid_ok = uid_of((pid_t)pid) == UNPRIV;
    if (gc > 0) {
        char p2[64], b[4096];
        snprintf(p2, sizeof p2, "/proc/%ld/cgroup", gc);
        int fd = open(p2, O_RDONLY | O_CLOEXEC);
        ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (fd >= 0) close(fd);
        b[r > 0 ? r : 0] = 0;
        s->grouped = strstr(b, "0::") && strstr(b, "/procd.") ? 1 : 0;
    }
    procd_termination_evidence ev;
    procd_domain_terminate(d, 5000, &ev);
    s->proven = ev.emptiness_proven;
    s->final = (int)ev.final_state;
    for (int i = 0; i < 50; i++) {
        s->survivors = (gc > 0 && executing(gc)) + (pid > 0 && executing((long)pid));
        if (!s->survivors) break;
        nap(20);
    }
    procd_domain_release(d);
    unlink("/tmp/procd_est_gc");
}

/* D: recover `id` under a read-only mount and inspect the reported level. */
static void downgraded_recovery(const char *id, scen *s) {
    procd_recovery_outcome o = PROCD_UNRESOLVED;
    procd_domain *rd = NULL;
    procd_recover(id, &o, &rd);
    s->recover_rc = (int)o;
    if (!rd) return;
    procd_domain_status st;
    procd_domain_status_get(rd, &st);
    s->level = (int)st.process_tree_termination;
    s->pop_auth = st.population_is_authoritative;
    procd_termination_evidence ev;
    procd_domain_terminate(rd, 1000, &ev);
    s->proven = ev.emptiness_proven;
    s->final = (int)ev.final_state;
    procd_domain_release(rd);
}

/* which: 'A' read-only, 'B' non-delegated, 'C' delegated, 'D' recovery. */
static int run(char which, const char *arg, scen *out) {
    int pp[2];
    if (pipe(pp) != 0) return -1;
    pid_t ch = fork();
    if (ch == 0) {
        close(pp[0]);
        scen s;
        memset(&s, 0xff, sizeof s); /* every field -1 = not reached */
        if (which == 'A') {
            s.setup_ok = make_cgroup_readonly();
            if (s.setup_ok) probe_and_create(&s);
        } else if (which == 'B') {
            s.setup_ok = become_unprivileged(NULL);
            if (s.setup_ok) probe_and_create(&s);
        } else if (which == 'C') {
            s.setup_ok = become_unprivileged(arg);
            if (s.setup_ok) {
                procd_capabilities c;
                procd_capabilities_probe(&c);
                s.ptt = (int)c.process_tree_termination;
                delegated_lifecycle(&s);
            }
        } else {
            s.setup_ok = make_cgroup_readonly();
            if (s.setup_ok) downgraded_recovery(arg, &s);
        }
        ssize_t w = write(pp[1], &s, sizeof s);
        (void)w;
        _exit(0);
    }
    close(pp[1]);
    ssize_t r = read(pp[0], out, sizeof *out);
    close(pp[0]);
    waitpid(ch, NULL, 0);
    return r == (ssize_t)sizeof *out ? 0 : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: needs root to set up the environments and a cgroup-v2 host (%s)\n",
               strict ? "FAIL" : "SKIP", c.detail);
        return strict ? 1 : 77;
    }
    scen s;

    /* ---- A ---- */
    if (run('A', NULL, &s) != 0 || s.setup_ok != 1) {
        CHECK(0, "A: could not set up a read-only cgroup mount");
    } else {
        CHECK(s.ptt != PROCD_CAP_ENFORCED, "A: read-only hierarchy is not ENFORCED");
        CHECK(s.req_rc == PROCD_E_UNSUPPORTED_ENFORCEMENT, "A: REQUIRE_ENFORCED refused");
        CHECK(s.allow_rc != PROCD_OK, "A: ALLOW_BEST_EFFORT creates no domain");
    }

    /* ---- B ---- */
    if (run('B', NULL, &s) != 0 || s.setup_ok != 1) {
        CHECK(0, "B: could not become an unprivileged caller");
    } else {
        CHECK(s.ptt != PROCD_CAP_ENFORCED, "B: non-delegated unprivileged caller is not ENFORCED");
        CHECK(s.req_rc == PROCD_E_UNSUPPORTED_ENFORCEMENT, "B: REQUIRE_ENFORCED refused");
        CHECK(s.allow_rc != PROCD_OK, "B: ALLOW_BEST_EFFORT creates no domain");
    }

    /* ---- C ---- */
    char cg[512], deleg[600], f[700];
    own_cgroup(cg, sizeof cg);
    snprintf(deleg, sizeof deleg, "%s/procd_est_deleg", cg);
    mkdir(deleg, 0755);
    int delegated = chown(deleg, UNPRIV, UNPRIV) == 0;
    const char *files[] = {"cgroup.procs", "cgroup.subtree_control", "cgroup.threads"};
    for (int i = 0; i < 3; i++) {
        snprintf(f, sizeof f, "%s/%s", deleg, files[i]);
        delegated = delegated && chown(f, UNPRIV, UNPRIV) == 0;
    }
    if (!delegated || run('C', deleg, &s) != 0 || s.setup_ok != 1) {
        CHECK(0, "C: could not set up a delegated unprivileged caller");
    } else {
        CHECK(s.ptt == PROCD_CAP_ENFORCED, "C: delegated unprivileged caller probes ENFORCED");
        CHECK(s.req_rc == PROCD_OK && s.level == PROCD_CAP_ENFORCED,
              "C: REQUIRE_ENFORCED domain created at ENFORCED without root");
        CHECK(s.spawn_rc == PROCD_OK && s.uid_ok == 1, "C: workload runs with the caller's uid");
        CHECK(s.grouped == 1, "C: setsid'd background descendant is in the domain");
        CHECK(s.proven == 1 && s.final == PROCD_STATE_EMPTY && s.survivors == 0,
              "C: termination proves emptiness and nothing survives");
    }
    rmdir(deleg);

    /* ---- D ---- */
    procd_policy p = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    char id[PROCD_IDENTITY_MAX] = "";
    if (procd_create_domain(&p, &d) == PROCD_OK) {
        const char *av[] = {"sleep", "30", NULL};
        procd_domain_spawn(d, av, NULL);
        procd_domain_identity(d, id, sizeof id);
    }
    if (!d || run('D', id, &s) != 0 || s.setup_ok != 1) {
        CHECK(0, "D: could not set up a recovered handle under a read-only mount");
    } else {
        CHECK(s.recover_rc == PROCD_RECOVERED, "D: domain recovered");
        CHECK(s.level != PROCD_CAP_ENFORCED, "D: unusable controls lower the recovered level");
        CHECK(s.pop_auth == 0, "D: population not reported as authoritative");
        CHECK(s.proven == 0 && s.final != PROCD_STATE_EMPTY,
              "D: termination does not claim proven emptiness");
    }
    if (d) {
        procd_termination_evidence ev;
        procd_domain_terminate(d, 5000, &ev);
        CHECK(ev.emptiness_proven, "D: the original handle still terminates the domain");
        procd_domain_release(d);
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all establishment checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only establishment regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
