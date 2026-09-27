/*
 * macOS backend.
 *
 * Honest status: no supported macOS mechanism (tested on macOS 26.4 arm64)
 * establishes the hard invariant. Process groups alone are escapable via
 * setpgid/setsid/double-fork; escaped descendants survive killpg of the
 * original group. EVFILT_PROC|NOTE_TRACK returned ENOTSUP; coalitions do not
 * provide kill-all-members-now; audit tokens give process-generation identity
 * but not complete membership; Endpoint Security is observation, not
 * containment; launchd can create executable work outside the caller's
 * process group. Therefore:
 *
 *   ProcessTreeTermination = UNSUPPORTED  (aggregate hard invariant; reported
 *                                          identically by probe and status)
 *
 * We DO NOT fake lifecycle identity with Seatbelt. Under PROCD_REQUIRE_ENFORCED
 * we fail closed. Under PROCD_ALLOW_BEST_EFFORT each spawn gets its own process
 * group that a *cooperating* workload stays in (DescendantContainment =
 * BEST_EFFORT); population is a non-authoritative group scan and termination
 * always ends UNRESOLVED.
 *
 * Unrelated-process safety. A process-group id is just a number: once the
 * group is gone its id can be reused by an unrelated group, and killpg() on a
 * stale id would kill unrelated work. The strongest generation identity macOS
 * exposes here is (pid, kernel start time) of the group's leader, read with
 * sysctl KERN_PROC_PID, which also reports zombies. While that exact leader
 * generation still holds its pid (running, or an unreaped zombie), no other
 * process group can carry that id: group ids are the pids of the processes
 * that created them, and the kernel never allocates a pid still in use. So we
 * signal a group only after confirming its leader's generation; once the
 * leader has been reaped (e.g. by the caller) continuity can no longer be
 * established and we refuse to signal, reporting UNRESOLVED. killpg success is
 * never treated as emptiness.
 *
 * Residual (unavoidable without pidfd-style handles): a reap AND a reuse of
 * the leader's pid as a new group leader between the confirmation and killpg.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#if defined(__APPLE__)

#include "backend.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAC_MAX_GROUPS 32

/* A group leader's generation identity. The group id equals leader.pid. */
typedef struct {
    pid_t pid;
    struct timeval start;
} mac_leader;

typedef struct {
    mac_leader leaders[MAC_MAX_GROUPS]; /* one process group per spawn */
    int n;
    char detail[256]; /* per-domain termination detail (not shared) */
} mac_impl;

static void mac_probe(procd_capabilities *out) {
    out->backend = "macos-none";
    out->process_tree_termination = PROCD_CAP_UNSUPPORTED;
    out->pre_execution_containment = PROCD_CAP_UNSUPPORTED;
    out->descendant_containment = PROCD_CAP_BEST_EFFORT;     /* pgid, escapable */
    out->topology_escape_resistance = PROCD_CAP_UNSUPPORTED; /* setsid/double-fork escape */
    out->domain_emptiness_proof = PROCD_CAP_UNSUPPORTED;     /* scan is not authoritative */
    out->safe_recovery = PROCD_CAP_UNSUPPORTED;              /* no durable authority */
    out->crash_behavior = PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS;
    out->detail = "no supported macOS mechanism establishes inherited, "
                  "non-escapable, authoritatively-terminable domains; process groups are "
                  "best-effort and only signalled while their leader's generation is confirmed";
}

/* Kernel view of pid (zombies included). 0 on success, -1 if no such process. */
static int kproc(pid_t pid, struct timeval *start, pid_t *pgid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
    struct kinfo_proc kp;
    size_t len = sizeof kp;
    memset(&kp, 0, sizeof kp);
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len != sizeof kp || kp.kp_proc.p_pid != pid)
        return -1;
    *start = kp.kp_proc.p_starttime;
    *pgid = kp.kp_eproc.e_pgid;
    return 0;
}

/* Does this exact leader generation still hold its pid (and so the group id)? */
static int leader_holds(const mac_leader *l) {
    struct timeval st;
    pid_t pg;
    if (kproc(l->pid, &st, &pg) != 0) return 0;
    return st.tv_sec == l->start.tv_sec && st.tv_usec == l->start.tv_usec;
}

/* best-effort, NON-authoritative: running (non-zombie) members of a group */
static int group_live(pid_t pgid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PGRP, (int)pgid};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return -1;
    if (len == 0) return 0;
    len += 16 * sizeof(struct kinfo_proc); /* room for concurrent forks */
    struct kinfo_proc *kp = malloc(len);
    if (!kp) return -1;
    if (sysctl(mib, 4, kp, &len, NULL, 0) != 0) {
        free(kp);
        return -1;
    }
    int live = 0;
    for (size_t i = 0; i < len / sizeof *kp; i++)
        if (kp[i].kp_proc.p_stat != SZOMB) live++;
    free(kp);
    return live;
}

/* reap procd's own direct children (the group leaders it forked) that have
 * exited, so a best-effort domain never leaves procd-owned zombies. */
static void mac_reap(mac_impl *im, int blocking) {
    for (int i = 0; i < im->n; i++) {
        if (im->leaders[i].pid <= 0) continue;
        pid_t r = waitpid(im->leaders[i].pid, NULL, blocking ? 0 : WNOHANG);
        if (r == im->leaders[i].pid || (r < 0 && errno == ECHILD)) im->leaders[i].pid = 0;
    }
}

static procd_status mac_create(procd_domain *d) {
    if (d->policy.enforcement == PROCD_REQUIRE_ENFORCED)
        return PROCD_E_UNSUPPORTED_ENFORCEMENT; /* fail closed; never fake it */
    mac_impl *im = calloc(1, sizeof(*im));
    if (!im) return PROCD_E_INTERNAL;
    d->impl = im;
    /* the hard invariant is not offered: same level as the probe reports */
    d->runtime_level = PROCD_CAP_UNSUPPORTED;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

static procd_status mac_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    mac_impl *im = d->impl;
    if (im->n >= MAC_MAX_GROUPS) return PROCD_E_STATE;
    int go[2];
    if (pipe(go) != 0) return PROCD_E_IO;
    fcntl(go[0], F_SETFD, FD_CLOEXEC);
    fcntl(go[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid < 0) {
        close(go[0]);
        close(go[1]);
        return PROCD_E_IO;
    }
    if (pid == 0) {
        /* new process group; cooperating descendants inherit it. Wait until
         * the parent has recorded our generation identity. */
        close(go[1]);
        setpgid(0, 0);
        char b = 0;
        if (read(go[0], &b, 1) != 1 || b != 1) _exit(127);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(go[0]);
    setpgid(pid, pid); /* race-free: also set from parent */
    /* The child is blocked on `go` and unreaped, so its pid cannot have been
     * reused: record the generation identity of the group's leader. */
    mac_leader l = {pid, {0, 0}};
    pid_t pg = 0;
    char b = 1;
    if (kproc(pid, &l.start, &pg) != 0 || pg != pid || write(go[1], &b, 1) != 1) {
        kill(pid, SIGKILL); /* our own blocked, unreaped child: nothing ran */
        close(go[1]);
        waitpid(pid, NULL, 0);
        return PROCD_E_INTERNAL;
    }
    close(go[1]);
    im->leaders[im->n++] = l;
    if (out_pid) *out_pid = pid;
    d->state = PROCD_STATE_ACTIVE;
    return PROCD_OK;
}

static procd_status mac_status(procd_domain *d, procd_domain_status *out) {
    mac_impl *im = d->impl;
    out->process_tree_termination = d->runtime_level;
    out->population_is_authoritative = 0; /* group scan cannot prove emptiness */
    int live = 0, unknown = 0;
    for (int i = 0; i < im->n; i++) {
        if (!leader_holds(&im->leaders[i])) {
            unknown = 1; /* group id can no longer be attributed to this domain */
            continue;
        }
        int g = group_live(im->leaders[i].pid);
        if (g < 0)
            unknown = 1;
        else
            live += g;
    }
    out->population = live > 0  ? PROCD_POP_POPULATED
                      : unknown ? PROCD_POP_UNKNOWN
                                : PROCD_POP_EMPTY;
    out->state = d->state;
    return PROCD_OK;
}

static procd_status mac_terminate(procd_domain *d, int timeout_ms,
                                  procd_termination_evidence *out) {
    mac_impl *im = d->impl;
    char *detail = im->detail; /* per-domain: not shared across handles */
    size_t dcap = sizeof im->detail;
    out->detail = detail;
    d->state = PROCD_STATE_TERMINATING;
    out->admission_closed = 0;   /* cannot truly close admission */
    out->authority_directed = 0; /* killpg targets a discovered group, not authority */

    int refused = 0;
    for (int i = 0; i < im->n; i++) {
        if (leader_holds(&im->leaders[i]))
            killpg(im->leaders[i].pid, SIGKILL);
        else
            refused++; /* stale id: signalling it could hit unrelated processes */
    }

    if (timeout_ms <= 0) timeout_ms = 2000;
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (int t = 0; t < timeout_ms / 20; t++) {
        int live = 0;
        for (int i = 0; i < im->n; i++)
            if (leader_holds(&im->leaders[i]) && group_live(im->leaders[i].pid) > 0) live = 1;
        if (!live) break;
        nanosleep(&ts, NULL);
    }

    /* emptiness here is best-effort and MUST NOT be reported as proven: an
     * escaped descendant (setsid/double-fork) is invisible to the group scan. */
    out->emptiness_proven = 0;
    out->enforced = 0;
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    if (refused) {
        mac_reap(im, 0);
        snprintf(detail, dcap,
                 "refused to signal %d process group(s): leader generation no longer "
                 "established (reaped), so the group id may belong to unrelated processes",
                 refused);
        return PROCD_E_NOT_FOUND;
    }
    mac_reap(im, 0);
    snprintf(detail, dcap,
             "best-effort killpg of generation-confirmed group(s); emptiness NOT "
             "authoritative on macOS");
    return PROCD_OK;
}

static procd_status mac_identity(procd_domain *d, char *buf, size_t n) {
    mac_impl *im = d->impl;
    int w = snprintf(buf, n, "macos-none:1:pgid=%d", im->n ? (int)im->leaders[0].pid : 0);
    return (w > 0 && (size_t)w < n) ? PROCD_OK : PROCD_E_INVALID_ARGUMENT;
}

static void mac_destroy(procd_domain *d) {
    mac_impl *im = d->impl;
    if (im) {
        mac_reap(im, 0);
        free(im);
    }
    d->impl = NULL;
}

static procd_status mac_recover(const char *identity, procd_recovery_outcome *outcome,
                                procd_domain **out_domain) {
    (void)identity;
    (void)out_domain;
    /* No durable, generation-safe authority exists; refuse to guess. PID/pgid
     * reuse means we cannot confirm destruction or safely reacquire. */
    *outcome = PROCD_UNRESOLVED;
    return PROCD_OK;
}

static const struct procd_backend BACKEND = {
    .name = "macos-none",
    .probe = mac_probe,
    .create = mac_create,
    .spawn = mac_spawn,
    .status = mac_status,
    .terminate = mac_terminate,
    .identity = mac_identity,
    .destroy = mac_destroy,
    .recover = mac_recover,
};
const struct procd_backend *procd_active_backend(void) {
    return &BACKEND;
}

#else
typedef int procd_backend_macos_translation_unit_nonempty;
#endif /* __APPLE__ */
