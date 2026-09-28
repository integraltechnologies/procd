/*
 * macOS backend: tracked lifecycle domains.
 *
 * macOS has no unprivileged kernel lifecycle domain comparable to a cgroup or a
 * Job Object (tested natively: process groups are left by setpgid/setsid and
 * double-fork; EVFILT_PROC NOTE_TRACK returns ENOTSUP; coalitions need
 * entitlements to create; Endpoint Security needs a system extension). procd
 * therefore supervises a task with several independent, ordinary-user
 * mechanisms, each covering what another misses:
 *
 *   1. Domain marker. Every spawned process starts with a per-domain
 *      environment variable (PROCD_DOMAIN_<128-bit nonce>=1). Ordinary process
 *      creation inherits the environment through fork, exec, posix_spawn,
 *      setsid, setpgid, double-fork and reparenting to launchd, and tools such
 *      as shells, cargo, rustc, build scripts, test harnesses, Python and Node
 *      pass it on. procd reads each same-user process's exec-time environment
 *      with sysctl KERN_PROCARGS2 (no privilege needed).
 *   2. Ancestry. Any process whose parent is a member is a member, on every
 *      scan, so a descendant that cleared its environment is still found while
 *      its ancestry reaches the task.
 *   3. Generations. Every member ever seen is remembered as (pid, kernel start
 *      time), so a member that later clears its environment by exec AND is
 *      reparented is still recognised; pid reuse cannot alias a generation.
 *   4. Process groups. Each spawn leads its own process group; members of that
 *      group are members while the leader's generation still holds the id.
 *
 * Termination closes admission, then repeatedly scans and SIGSTOPs every member
 * (stopped processes cannot fork, so the set converges even while the task is
 * spawning), SIGKILLs the frozen set, and rescans until no member is running or
 * the timeout expires. Every signal is sent only after re-confirming the
 * target's generation. Unrelated processes -- other tasks, other users, the
 * caller -- carry neither the nonce nor a member ancestry and are never signalled.
 *
 * Honest level: BEST_EFFORT. Membership is procd bookkeeping, not a kernel
 * domain, so emptiness is a scan (never "proven") and final_state stays
 * UNRESOLVED; a successful terminate (PROCD_OK) means every member procd could
 * find is gone and a final scan found none. Known residual: a descendant that
 * discards its whole environment AND detaches from the tree (setsid + double
 * fork) before any scan observes it; such a process is not found. Crash
 * behavior: nothing kills the task if the supervisor dies (UNRESOLVED), and
 * recovery is not offered.
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
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MAC_MAX_LEADERS 64

/* A process generation: pid plus kernel start time. */
typedef struct {
    pid_t pid;
    struct timeval start;
} mac_gen;

typedef struct {
    mac_gen *v;
    int n, cap;
} mac_set;

typedef struct {
    char marker[64];                  /* "PROCD_DOMAIN_<hex>=1" */
    mac_gen leaders[MAC_MAX_LEADERS]; /* procd's own children, one group each */
    int nleaders;
    mac_set known;  /* every member generation ever observed */
    mac_set others; /* generations confirmed NOT to carry the marker */
    char detail[256];
} mac_impl;

static int gen_eq(const mac_gen *a, const mac_gen *b) {
    return a->pid == b->pid && a->start.tv_sec == b->start.tv_sec &&
           a->start.tv_usec == b->start.tv_usec;
}

static int set_has(const mac_set *s, const mac_gen *g) {
    for (int i = 0; i < s->n; i++)
        if (gen_eq(&s->v[i], g)) return 1;
    return 0;
}

static int set_add(mac_set *s, const mac_gen *g) {
    if (set_has(s, g)) return 0;
    if (s->n == s->cap) {
        int cap = s->cap ? s->cap * 2 : 64;
        mac_gen *v = realloc(s->v, (size_t)cap * sizeof *v);
        if (!v) return -1;
        s->v = v;
        s->cap = cap;
    }
    s->v[s->n++] = *g;
    return 1;
}

static void mac_probe(procd_capabilities *out) {
    out->backend = "macos-tracked";
    out->process_tree_termination = PROCD_CAP_BEST_EFFORT;
    out->pre_execution_containment = PROCD_CAP_BEST_EFFORT;  /* marked+tracked before exec */
    out->descendant_containment = PROCD_CAP_BEST_EFFORT;     /* marker + ancestry, not kernel */
    out->topology_escape_resistance = PROCD_CAP_BEST_EFFORT; /* survives setsid/double-fork */
    out->domain_emptiness_proof = PROCD_CAP_BEST_EFFORT;     /* exhaustive scan, not proof */
    out->safe_recovery = PROCD_CAP_UNSUPPORTED;
    out->crash_behavior = PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS;
    out->detail = "no unprivileged macOS kernel lifecycle domain; members are tracked by an "
                  "inherited per-domain environment marker, ancestry, process generations and "
                  "process groups, then frozen and killed; emptiness is a scan, not a proof";
}

/* Kernel view of one pid (zombies included). 0 on success. */
static int kproc(pid_t pid, mac_gen *g, int *zombie) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
    struct kinfo_proc kp;
    size_t len = sizeof kp;
    memset(&kp, 0, sizeof kp);
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len != sizeof kp || kp.kp_proc.p_pid != pid)
        return -1;
    g->pid = pid;
    g->start = kp.kp_proc.p_starttime;
    if (zombie) *zombie = kp.kp_proc.p_stat == SZOMB;
    return 0;
}

/* Is this exact generation still an executing (non-zombie) process? */
static int gen_running(const mac_gen *g) {
    mac_gen now;
    int z = 0;
    return kproc(g->pid, &now, &z) == 0 && !z && gen_eq(&now, g);
}

/* Does this exact generation still hold its pid (running or unreaped zombie)?
 * While it does, no other process can own that pid or a group with that id. */
static int gen_holds(const mac_gen *g) {
    mac_gen now;
    return kproc(g->pid, &now, NULL) == 0 && gen_eq(&now, g);
}

/* Signal a generation only after re-confirming it still holds its pid. */
static void gen_signal(const mac_gen *g, int sig) {
    if (g->pid > 1 && g->pid != getpid() && gen_running(g)) kill(g->pid, sig);
}

/* Does `pid`'s exec-time environment carry `marker`? 1 yes, 0 no, -1 unknown. */
static int has_marker(pid_t pid, const char *marker, char *buf, size_t cap) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    size_t len = cap;
    if (sysctl(mib, 3, buf, &len, NULL, 0) != 0 || len < sizeof(int)) return -1;
    size_t ml = strlen(marker);
    /* layout: int argc, exec path, NUL padding, argv[], envp[] -- all NUL
     * separated. Compare every string: argv never carries the nonce. */
    for (size_t i = sizeof(int); i < len;) {
        size_t sl = strnlen(buf + i, len - i);
        if (sl == ml && memcmp(buf + i, marker, ml) == 0) return 1;
        i += sl + 1;
    }
    return 0;
}

typedef struct {
    mac_gen g;
    pid_t ppid, pgid;
    uid_t uid;
    int member;
} mac_proc;

/* Snapshot every running process. Caller frees. */
static mac_proc *snapshot(int *count) {
    int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *kp = NULL;
    size_t len = 0;
    for (int tries = 0; tries < 8; tries++) {
        if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) return NULL;
        len += len / 4 + 64 * sizeof *kp; /* room for concurrent forks */
        struct kinfo_proc *nk = realloc(kp, len);
        if (!nk) break;
        kp = nk;
        if (sysctl(mib, 3, kp, &len, NULL, 0) == 0) {
            int n = (int)(len / sizeof *kp), m = 0;
            mac_proc *out = calloc((size_t)n + 1, sizeof *out);
            if (!out) break;
            for (int i = 0; i < n; i++) {
                if (kp[i].kp_proc.p_stat == SZOMB) continue; /* not executing */
                out[m].g.pid = kp[i].kp_proc.p_pid;
                out[m].g.start = kp[i].kp_proc.p_starttime;
                out[m].ppid = kp[i].kp_eproc.e_ppid;
                out[m].pgid = kp[i].kp_eproc.e_pgid;
                out[m].uid = kp[i].kp_eproc.e_ucred.cr_uid;
                m++;
            }
            free(kp);
            *count = m;
            return out;
        }
        if (errno != ENOMEM) break;
    }
    free(kp);
    return NULL;
}

/* Find every running member of the domain. Returns count, or -1 if the process
 * table could not be read. Newly observed members are remembered. */
static int scan(mac_impl *im, mac_gen **out) {
    int n = 0;
    mac_proc *p = snapshot(&n);
    if (!p) return -1;
    pid_t self = getpid();
    uid_t me = getuid();
    static size_t argmax;
    if (!argmax) {
        int mib[2] = {CTL_KERN, KERN_ARGMAX};
        int am = 0;
        size_t l = sizeof am;
        argmax = (sysctl(mib, 2, &am, &l, NULL, 0) == 0 && am > 0) ? (size_t)am : 1 << 20;
    }
    char *buf = malloc(argmax);
    int weak = procd_nc_weaken_containment(); /* test-only: process groups alone */

    for (int i = 0; i < n; i++) {
        mac_proc *q = &p[i];
        if (q->g.pid <= 1 || q->g.pid == self) continue;
        if (!weak && set_has(&im->known, &q->g)) {
            q->member = 1;
            continue;
        }
        for (int l = 0; l < im->nleaders && !q->member; l++)
            if (im->leaders[l].pid > 0 && q->pgid == im->leaders[l].pid &&
                gen_holds(&im->leaders[l]))
                q->member = 1; /* the leader's generation still holds the group id */
        if (q->member || weak || q->uid != me || !buf) continue;
        if (set_has(&im->others, &q->g)) continue;
        int m = has_marker(q->g.pid, im->marker, buf, argmax);
        if (m == 1)
            q->member = 1;
        else if (m == 0)
            set_add(&im->others, &q->g); /* exec-time env of a generation never changes */
    }
    /* ancestry: children of members are members (fixpoint over the snapshot) */
    for (int changed = 1; changed && !weak;) {
        changed = 0;
        for (int i = 0; i < n; i++) {
            if (p[i].member || p[i].g.pid <= 1 || p[i].g.pid == self) continue;
            for (int j = 0; j < n; j++)
                if (p[j].member && p[j].g.pid == p[i].ppid) {
                    p[i].member = changed = 1;
                    break;
                }
        }
    }
    int m = 0;
    for (int i = 0; i < n; i++)
        if (p[i].member) {
            if (!weak) set_add(&im->known, &p[i].g);
            p[m++].g = p[i].g;
        }
    mac_gen *res = NULL;
    if (out && m) {
        res = malloc((size_t)m * sizeof *res);
        if (res)
            for (int i = 0; i < m; i++)
                res[i] = p[i].g;
        else
            m = -1;
    }
    free(buf);
    free(p);
    if (out) *out = res;
    return m;
}

/* reap procd's own direct children (the leaders) that have exited */
static void mac_reap(mac_impl *im) {
    for (int i = 0; i < im->nleaders; i++) {
        pid_t pid = im->leaders[i].pid;
        if (pid <= 0) continue;
        pid_t r = waitpid(pid, NULL, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) im->leaders[i].pid = 0;
    }
}

static procd_status mac_create(procd_domain *d) {
    if (d->policy.enforcement == PROCD_REQUIRE_ENFORCED)
        return PROCD_E_UNSUPPORTED_ENFORCEMENT; /* fail closed; never fake it */
    mac_impl *im = calloc(1, sizeof *im);
    if (!im) return PROCD_E_INTERNAL;
    unsigned char nonce[16];
    arc4random_buf(nonce, sizeof nonce);
    int w = snprintf(im->marker, sizeof im->marker, "PROCD_DOMAIN_");
    for (size_t i = 0; i < sizeof nonce; i++)
        w += snprintf(im->marker + w, sizeof im->marker - (size_t)w, "%02x", nonce[i]);
    snprintf(im->marker + w, sizeof im->marker - (size_t)w, "=1");
    d->impl = im;
    d->runtime_level = PROCD_CAP_BEST_EFFORT;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

static procd_status mac_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    mac_impl *im = d->impl;
    if (im->nleaders >= MAC_MAX_LEADERS) return PROCD_E_STATE;

    /* child environment = ours + the domain marker, built before fork */
    size_t ne = 0;
    while (environ && environ[ne])
        ne++;
    char **envp = calloc(ne + 2, sizeof *envp);
    if (!envp) return PROCD_E_INTERNAL;
    for (size_t i = 0; i < ne; i++)
        envp[i] = environ[i];
    envp[ne] = im->marker;

    /* go channel: a socketpair whose parent end never raises SIGPIPE in the
     * host process if the child has already died */
    int go[2], st[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, go) != 0) {
        free(envp);
        return PROCD_E_IO;
    }
    if (pipe(st) != 0) {
        close(go[0]);
        close(go[1]);
        free(envp);
        return PROCD_E_IO;
    }
    for (int i = 0; i < 2; i++) {
        fcntl(go[i], F_SETFD, FD_CLOEXEC);
        fcntl(st[i], F_SETFD, FD_CLOEXEC);
    }
    int one = 1;
    setsockopt(go[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    pid_t pid = fork();
    if (pid < 0) {
        close(go[0]), close(go[1]), close(st[0]), close(st[1]);
        free(envp);
        return PROCD_E_IO;
    }
    if (pid == 0) {
        /* own process group; wait until the parent has recorded our generation */
        close(go[1]);
        close(st[0]);
        setpgid(0, 0);
        char b = 0;
        if (read(go[0], &b, 1) != 1 || b != 1) _exit(127);
        environ = envp;
        execvp(argv[0], (char *const *)argv);
        int e = errno;
        (void)!write(st[1], &e, sizeof e);
        _exit(127);
    }
    free(envp); /* the child has its own copy */
    close(go[0]);
    close(st[1]);
    setpgid(pid, pid); /* race-free: also set from the parent */

    /* The child is blocked on `go` and unreaped: its pid cannot be reused, so
     * its generation is exact. Record it before any workload code runs. */
    mac_gen g;
    int z = 0;
    char b = 1;
    if (kproc(pid, &g, &z) != 0 || z) {
        close(go[1]); /* EOF: the child exits without running anything */
        close(st[0]);
        waitpid(pid, NULL, 0);
        return PROCD_E_INTERNAL;
    }
    im->leaders[im->nleaders++] = g;
    set_add(&im->known, &g);
    ssize_t wr = write(go[1], &b, 1);
    close(go[1]);
    int err = 0;
    ssize_t r;
    do
        r = read(st[0], &err, sizeof err);
    while (r < 0 && errno == EINTR);
    close(st[0]);
    if (wr != 1 || r != 0) {
        /* exec failed (or the go signal was lost): only this child is affected;
         * everything else in the domain keeps running */
        waitpid(pid, NULL, 0);
        im->nleaders--;
        return (r == (ssize_t)sizeof err && (err == ENOENT || err == ENOTDIR)) ? PROCD_E_NOT_FOUND
               : (r == (ssize_t)sizeof err && err == EACCES)                   ? PROCD_E_PERMISSION
                                                                               : PROCD_E_IO;
    }
    if (out_pid) *out_pid = pid;
    d->state = PROCD_STATE_ACTIVE;
    return PROCD_OK;
}

static procd_status mac_status(procd_domain *d, procd_domain_status *out) {
    mac_impl *im = d->impl;
    out->process_tree_termination = d->runtime_level;
    out->population_is_authoritative = 0; /* a scan cannot prove emptiness */
    mac_reap(im);
    int live = scan(im, NULL);
    out->population = live < 0 ? PROCD_POP_UNKNOWN : live ? PROCD_POP_POPULATED : PROCD_POP_EMPTY;
    out->state = d->state;
    return PROCD_OK;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nap(int ms) {
    struct timespec ts = {0, (long)ms * 1000000};
    nanosleep(&ts, NULL);
}

static procd_status mac_terminate(procd_domain *d, int timeout_ms,
                                  procd_termination_evidence *out) {
    mac_impl *im = d->impl;
    out->detail = im->detail;
    d->state = PROCD_STATE_TERMINATING;
    out->admission_closed = 1;   /* procd admits nothing more; members are frozen */
    out->authority_directed = 0; /* signals target discovered members, not a kernel domain */
    if (timeout_ms <= 0) timeout_ms = 5000;
    long long deadline = now_ms() + timeout_ms;

    /* 1. freeze: SIGSTOP every member until a scan finds none unstopped */
    mac_set stopped = {0};
    int rounds = 0, unreadable = 0;
    for (;; rounds++) {
        mac_gen *m = NULL;
        int n = scan(im, &m);
        if (n < 0) {
            unreadable = 1;
            break;
        }
        int fresh = 0;
        for (int i = 0; i < n; i++)
            if (set_add(&stopped, &m[i]) == 1) {
                gen_signal(&m[i], SIGSTOP);
                fresh++;
            }
        free(m);
        if (!fresh || now_ms() > deadline) break;
    }
    /* 2. kill the frozen set */
    for (int i = 0; i < stopped.n; i++)
        gen_signal(&stopped.v[i], SIGKILL);
    /* 3. rescan and kill until nothing runs */
    int remaining = -1;
    for (;;) {
        mac_reap(im);
        mac_gen *m = NULL;
        int n = scan(im, &m);
        if (n >= 0) remaining = n;
        for (int i = 0; i < n; i++)
            gen_signal(&m[i], SIGKILL);
        free(m);
        if (n == 0 || now_ms() > deadline) break;
        nap(5);
    }
    mac_reap(im);
    int killed = stopped.n;
    free(stopped.v);

    /* a scan is not proof: never EMPTY, never proven */
    out->emptiness_proven = 0;
    out->enforced = 0;
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    if (unreadable || remaining < 0) {
        snprintf(im->detail, sizeof im->detail, "process table unreadable; outcome unknown");
        return PROCD_E_IO;
    }
    if (remaining > 0) {
        snprintf(im->detail, sizeof im->detail,
                 "timed out: %d tracked member(s) still running after %d freeze round(s)",
                 remaining, rounds + 1);
        return PROCD_E_TIMEOUT;
    }
    snprintf(im->detail, sizeof im->detail,
             "froze and killed %d tracked member(s) in %d round(s); final scan found none "
             "(scan-based, not a kernel emptiness proof)",
             killed, rounds + 1);
    return PROCD_OK;
}

static procd_status mac_identity(procd_domain *d, char *buf, size_t n) {
    mac_impl *im = d->impl;
    int w = snprintf(buf, n, "macos-tracked:1:%.45s", im->marker + 13);
    return (w > 0 && (size_t)w < n) ? PROCD_OK : PROCD_E_INVALID_ARGUMENT;
}

static void mac_destroy(procd_domain *d) {
    mac_impl *im = d->impl;
    if (im) {
        mac_reap(im);
        free(im->known.v);
        free(im->others.v);
        free(im);
    }
    d->impl = NULL;
}

static procd_status mac_recover(const char *identity, procd_recovery_outcome *outcome,
                                procd_domain **out_domain) {
    (void)identity;
    (void)out_domain;
    /* No durable kernel authority survives the supervisor; refuse to guess. */
    *outcome = PROCD_UNRESOLVED;
    return PROCD_OK;
}

static const struct procd_backend BACKEND = {
    .name = "macos-tracked",
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
