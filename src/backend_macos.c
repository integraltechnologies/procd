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
 *      with sysctl KERN_PROCARGS2 (no privilege needed). The kernel hides the
 *      environment of Apple platform binaries (/bin/sh, /bin/sleep, perl, ...)
 *      from other processes, so for those only 2-4 apply.
 *   2. Ancestry. Any process whose parent is a member is a member, on every
 *      scan, so a descendant that cleared its environment is still found while
 *      its ancestry reaches the task.
 *   3. Generations. Every member ever seen is remembered as (pid, kernel start
 *      time), so a member that later clears its environment by exec AND is
 *      reparented is still recognised; pid reuse cannot alias a generation.
 *   4. Process groups. Each spawn leads its own process group; members of that
 *      group are members while the leader's generation still holds the id
 *      (status reaps an exited leader only after a scan has used its group).
 *
 * Reconciliation (a scan applying 1-4 and remembering every member found) runs
 * on status and terminate, and continuously: a process-wide watcher (one
 * kqueue, one thread, all domains) registers EVFILT_PROC NOTE_FORK|NOTE_EXEC
 * on every member it knows of -- including each leader before it runs any
 * workload code -- and reconciles that domain as soon as a member forks,
 * posix_spawns (which posts NOTE_FORK) or execs (a fresh image is the moment a
 * member starts creating its own children; exit events are not used: an
 * exited member's children are already orphaned).
 * A new child is therefore usually remembered while its ancestry still links
 * it to the task, before it can detach, clear its environment or be
 * reparented. The event carries no child identity; it only triggers the scan.
 * If the watcher cannot start, status/terminate reconciliation still works.
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
 * find is gone and a final scan found none. Known residual (why this is not
 * ENFORCED): fork notification is asynchronous and names no child, so a
 * descendant whose marker is absent or hidden and that detaches (new session,
 * parent exit / double fork) before the triggered scan completes is not found.
 * The watcher narrows that window to roughly one scan; it cannot remove it. Crash
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

#include <pthread.h>
#include <stdint.h>
#include <sys/event.h>

extern char **environ;

/* A process generation: pid plus kernel start time. */
typedef struct {
    pid_t pid;
    struct timeval start;
} mac_gen;

typedef struct {
    mac_gen *v;
    int n, cap;
} mac_set;

typedef struct mac_impl {
    char marker[64]; /* "PROCD_DOMAIN_<hex>=1" */
    /* procd's own direct children (one process group each) that may still hold
     * their pid: running, or exited and not yet reaped. An entry is dropped as
     * soon as its child is reaped (by procd, or by the embedding program), so
     * the set holds only live bookkeeping and spawns are not limited. */
    mac_set leaders;
    mac_set known;  /* running member generations observed so far */
    mac_set others; /* running generations confirmed NOT to carry the marker */
    char detail[384];

    /* Membership state (leaders, known, others, watched, recons, cpu_ns) is
     * guarded by mu: the domain's own operations and the shared watcher both
     * reconcile. */
    pthread_mutex_t mu;
    mac_set watched; /* members registered with the watcher's kqueue */
    unsigned long long recons, cpu_ns;

    /* Watcher registry fields, guarded by the watcher lock (W.mu). */
    uint64_t wid;           /* never-reused id carried by this domain's kevents; 0 = none */
    struct mac_impl *wnext; /* registry link */
    int wrefs;              /* watcher reconciliations in flight */
    int wpending, woff;     /* reconcile requested; no more reconciliations */
    unsigned long long wevents;
    int kq; /* the watcher's kqueue while registered, else -1 */
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

/* remove element i (order is not preserved) */
static void set_del(mac_set *s, int i) {
    s->v[i] = s->v[--s->n];
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
                  "process groups, reconciled continuously on fork events and on status/"
                  "terminate, then frozen and killed; fork events name no child, so a fast "
                  "enough detach can still be missed; emptiness is a scan, not a proof";
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
    int member, other;
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

static size_t argmax;
static pthread_once_t argmax_once = PTHREAD_ONCE_INIT;
static void argmax_init(void) {
    int mib[2] = {CTL_KERN, KERN_ARGMAX};
    int am = 0;
    size_t l = sizeof am;
    argmax = (sysctl(mib, 2, &am, &l, NULL, 0) == 0 && am > 0) ? (size_t)am : 1 << 20;
}

/* Find every running member of the domain. Returns count, or -1 if the process
 * table could not be read. Newly observed members are remembered. Caller holds
 * im->mu. Remembered generations that are no longer running are forgotten: a
 * (pid, start time) pair never recurs, so they can never match again, and
 * continuous reconciliation must not grow the sets without bound. */
static int scan(mac_impl *im, mac_gen **out) {
    int n = 0;
    mac_proc *p = snapshot(&n);
    if (!p) return -1;
    pid_t self = getpid();
    uid_t me = getuid();
    pthread_once(&argmax_once, argmax_init);
    char *buf = malloc(argmax);
    int weak = procd_nc_weaken_containment(); /* test-only: process groups alone */

    for (int i = 0; i < n; i++) {
        mac_proc *q = &p[i];
        if (q->g.pid <= 1 || q->g.pid == self) continue;
        if (!weak && set_has(&im->known, &q->g)) {
            q->member = 1;
            continue;
        }
        for (int l = 0; l < im->leaders.n && !q->member; l++)
            if (q->pgid == im->leaders.v[l].pid && gen_holds(&im->leaders.v[l]))
                q->member = 1; /* the leader's generation still holds the group id */
        if (q->member || weak || q->uid != me || !buf) continue;
        if (set_has(&im->others, &q->g)) {
            q->other = 1;
            continue;
        }
        int m = has_marker(q->g.pid, im->marker, buf, argmax);
        if (m == 1)
            q->member = 1;
        else if (m == 0)
            q->other = 1; /* exec-time env of a generation never changes */
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
    /* both sets now hold exactly the running generations they describe */
    im->known.n = im->others.n = 0;
    int m = 0;
    for (int i = 0; i < n; i++)
        if (p[i].member) {
            if (!weak) set_add(&im->known, &p[i].g);
            p[m++].g = p[i].g;
        } else if (p[i].other)
            set_add(&im->others, &p[i].g);
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

/* A leader's state: 0 running, 1 exited but unreaped (still holds its pid and
 * group id), -1 no longer holds its pid (already reaped, possibly by the
 * embedding program; the pid may now belong to an unrelated process). */
static int leader_state(const mac_gen *g) {
    mac_gen now;
    int z = 0;
    if (kproc(g->pid, &now, &z) != 0 || !gen_eq(&now, g)) return -1;
    return z ? 1 : 0;
}

/* Reap procd's own direct children that have exited and forget leaders that
 * no longer hold their pid. waitpid is only called on a pid whose exact
 * generation is still our unreaped child, never on a reused pid. Caller holds
 * im->mu. */
static void mac_reap(mac_impl *im) {
    for (int i = im->leaders.n - 1; i >= 0; i--) {
        mac_gen *g = &im->leaders.v[i];
        int st = leader_state(g);
        if (st < 0 || (st == 1 && waitpid(g->pid, NULL, WNOHANG) == g->pid))
            set_del(&im->leaders, i);
    }
}

/* ---------------- shared event-assisted watcher ----------------
 *
 * One process-wide kqueue and one thread serve every macOS domain; they start
 * with the first domain and live for the rest of the process.
 *
 * Locking (two locks, never nested):
 *   W.mu   guards the registry: the domain list, each domain's wid, wrefs,
 *          wpending, woff and wevents, and the watcher's own state. It is held
 *          only for list/flag updates -- never across a scan, a kevent call or
 *          while any im->mu is held.
 *   im->mu guards one domain's membership state. The domain's status,
 *          terminate and spawn take it around their reconciliation; the
 *          watcher takes it only while it holds a registry reference.
 * Lifetime: the watcher only reaches a domain through the registry, and takes
 * a reference (wrefs) under W.mu before releasing W.mu. mac_destroy unlinks the
 * domain under W.mu and waits (W.idle) until wrefs is 0, so the watcher never
 * touches freed memory. kevents carry the domain's never-reused 64-bit wid, not
 * a pointer: a stale event (member of a destroyed domain, or of a domain that
 * has begun terminating) finds nothing and is dropped.
 * Contamination: an event only marks the domain named by its wid for
 * reconciliation; membership is decided by that domain's own evidence in
 * scan(). A misdirected event can cost a scan, never add a member.
 * Failure: if the kqueue or thread cannot be created (or the thread's kevent
 * fails), domains simply are not watched; status/terminate reconciliation is
 * unchanged. The termination detail says which applied.
 * fork(): the child does not inherit the thread or the kqueue; an atfork
 * handler takes W.mu across fork and resets the watcher in the child. */
static struct {
    pthread_mutex_t mu;
    pthread_cond_t idle; /* broadcast when a domain's wrefs drops to 0 */
    int kq;              /* valid while state == 1 */
    int state;           /* 0 not started, 1 running, -1 unavailable */
    uint64_t next_id;
    mac_impl *head;
} W = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, -1, 0, 1, NULL};

static void w_prepare(void) {
    pthread_mutex_lock(&W.mu);
}
static void w_parent(void) {
    pthread_mutex_unlock(&W.mu);
}
static void w_child(void) {
    static const pthread_mutex_t m0 = PTHREAD_MUTEX_INITIALIZER;
    static const pthread_cond_t c0 = PTHREAD_COND_INITIALIZER;
    W.mu = m0; /* plain stores: no watcher thread exists in the child */
    W.idle = c0;
    W.kq = -1;
    W.state = 0;
    W.head = NULL;
}
static pthread_once_t w_atfork_once = PTHREAD_ONCE_INIT;
static void w_atfork(void) {
    pthread_atfork(w_prepare, w_parent, w_child);
}

static unsigned long long thread_cpu_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* Register every running member not yet watched and forget watches of
 * generations no longer among the members. Caller holds im->mu. */
static void track(mac_impl *im, const mac_gen *m, int n) {
    if (im->kq < 0 || n < 0) return;
    int keep = 0;
    for (int i = 0; i < im->watched.n; i++)
        for (int j = 0; j < n; j++)
            if (gen_eq(&im->watched.v[i], &m[j])) {
                im->watched.v[keep++] = im->watched.v[i];
                break;
            }
    im->watched.n = keep;
    for (int i = 0; i < n; i++) {
        if (set_has(&im->watched, &m[i])) continue;
        struct kevent ev;
        EV_SET(&ev, (uintptr_t)m[i].pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_FORK | NOTE_EXEC, 0,
               (void *)(uintptr_t)im->wid);
        /* ESRCH: already gone. A reused pid is harmless: the event only
         * triggers a reconciliation that re-derives membership. */
        if (kevent(im->kq, &ev, 1, NULL, 0, NULL) == 0) set_add(&im->watched, &m[i]);
    }
}

/* One reconciliation on behalf of the watcher (caller holds a reference). */
static void reconcile(mac_impl *im) {
    unsigned long long c0 = thread_cpu_ns();
    pthread_mutex_lock(&im->mu);
    mac_gen *m = NULL;
    int n = scan(im, &m);
    track(im, m, n);
    im->recons++;
    im->cpu_ns += thread_cpu_ns() - c0;
    pthread_mutex_unlock(&im->mu);
    free(m);
}

static void *watch_main(void *arg) {
    int kq = (int)(intptr_t)arg;
    struct kevent ev[128];
    for (;;) {
        int n = kevent(kq, NULL, 0, ev, 128, NULL);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;
        /* coalesce: every queued event marks its domain; each marked domain
         * is then reconciled once, however many of its members forked */
        pthread_mutex_lock(&W.mu);
        for (int i = 0; i < n; i++) {
            uint64_t id = (uint64_t)(uintptr_t)ev[i].udata;
            for (mac_impl *d = W.head; d; d = d->wnext)
                if (d->wid == id) {
                    d->wevents++;
                    d->wpending = 1;
                    break;
                }
        }
        pthread_mutex_unlock(&W.mu);
        for (;;) {
            mac_impl *im = NULL;
            pthread_mutex_lock(&W.mu);
            for (mac_impl *d = W.head; d && !im; d = d->wnext)
                if (d->wpending && !d->woff) {
                    d->wpending = 0;
                    d->wrefs++;
                    im = d;
                }
            pthread_mutex_unlock(&W.mu);
            if (!im) break;
            reconcile(im);
            pthread_mutex_lock(&W.mu);
            if (--im->wrefs == 0) pthread_cond_broadcast(&W.idle);
            pthread_mutex_unlock(&W.mu);
        }
    }
    pthread_mutex_lock(&W.mu); /* degrade to reconciliation-only supervision */
    W.state = -1;
    for (mac_impl *d = W.head; d; d = d->wnext)
        d->wpending = 0;
    pthread_mutex_unlock(&W.mu);
    return NULL;
}

/* TEST-ONLY (negative-control library variant, never production): with
 * PROCD_NC_NO_WATCH=1 a new domain does not join the watcher, so tests can
 * exercise reconciliation-only supervision (the fallback when the watcher is
 * unavailable) and regressions the watcher would otherwise mask. */
static int watch_disabled_for_test(void) {
#ifdef PROCD_ENABLE_NEGATIVE_CONTROL
    const char *v = getenv("PROCD_NC_NO_WATCH");
    return v && strcmp(v, "1") == 0;
#else
    return 0;
#endif
}

/* Join the shared watcher (starting it on first use). Never fails the domain. */
static void watch_register(mac_impl *im) {
    pthread_once(&w_atfork_once, w_atfork);
    im->kq = -1;
    if (watch_disabled_for_test()) return;
    pthread_mutex_lock(&W.mu);
    if (W.state == 0) {
        W.state = -1;
        int kq = kqueue();
        pthread_attr_t a;
        pthread_t th;
        if (kq >= 0 && pthread_attr_init(&a) == 0) {
            pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
            if (pthread_create(&th, &a, watch_main, (void *)(intptr_t)kq) == 0) {
                W.kq = kq;
                W.state = 1;
            }
            pthread_attr_destroy(&a);
        }
        if (W.state != 1 && kq >= 0) close(kq);
    }
    if (W.state == 1) {
        im->wid = W.next_id++;
        im->kq = W.kq;
        im->wnext = W.head;
        W.head = im;
    }
    pthread_mutex_unlock(&W.mu);
}

/* Stop watcher reconciliations of this domain; with `unlink`, also leave the
 * registry and wait until no watcher reconciliation is using it. */
static void watch_quiesce(mac_impl *im, int unlink) {
    pthread_mutex_lock(&W.mu);
    im->woff = 1;
    im->wpending = 0;
    if (unlink) {
        for (mac_impl **pp = &W.head; *pp; pp = &(*pp)->wnext)
            if (*pp == im) {
                *pp = im->wnext;
                break;
            }
        while (im->wrefs > 0)
            pthread_cond_wait(&W.idle, &W.mu);
    }
    pthread_mutex_unlock(&W.mu);
}

/* "; ..." suffix for the termination detail */
static void watch_describe(mac_impl *im, char *buf, size_t n) {
    pthread_mutex_lock(&W.mu);
    unsigned long long ev = im->wevents;
    int state = W.state, reg = im->wid != 0;
    pthread_mutex_unlock(&W.mu);
    if (reg && state == 1)
        snprintf(buf, n,
                 "; event-assisted tracking: %llu fork/exec events, %llu reconciliations, %.1fms",
                 ev, im->recons, (double)im->cpu_ns / 1e6);
    else
        snprintf(buf, n,
                 "; event-assisted tracking unavailable (reconciliation on status/"
                 "terminate only)");
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
    if (pthread_mutex_init(&im->mu, NULL) != 0) {
        free(im);
        return PROCD_E_INTERNAL;
    }
    watch_register(im);
    d->impl = im;
    d->runtime_level = PROCD_CAP_BEST_EFFORT;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

static procd_status mac_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    mac_impl *im = d->impl;

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
    pthread_mutex_lock(&im->mu);
    if (set_add(&im->leaders, &g) < 0) {
        pthread_mutex_unlock(&im->mu);
        close(go[1]); /* EOF: the child exits without running anything */
        close(st[0]);
        waitpid(pid, NULL, 0);
        return PROCD_E_INTERNAL;
    }
    set_add(&im->known, &g);
    track(im, &g, 1); /* before the workload runs: every fork of the leader is seen */
    pthread_mutex_unlock(&im->mu);
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
        pthread_mutex_lock(&im->mu);
        for (int i = 0; i < im->leaders.n; i++)
            if (gen_eq(&im->leaders.v[i], &g)) {
                set_del(&im->leaders, i);
                break;
            }
        pthread_mutex_unlock(&im->mu);
        /* r == sizeof err: the child reported exec's errno; anything else is
         * a lost handshake */
        return (r == (ssize_t)sizeof err && (err == ENOENT || err == ENOTDIR)) ? PROCD_E_NOT_FOUND
               : (r == (ssize_t)sizeof err && (err == EACCES || err == EPERM)) ? PROCD_E_PERMISSION
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
    /* Reap only leaders that were already exited when this scan began: an
     * unreaped exited leader still holds its process-group id, so the scan
     * attributes (and remembers) group members whose parent has exited and
     * whose environment the kernel hides (Apple platform binaries such as
     * /bin/sleep). A leader that exits during the scan is reaped next time. */
    pthread_mutex_lock(&im->mu);
    mac_set exited = {0};
    for (int i = im->leaders.n - 1; i >= 0; i--) {
        int st = leader_state(&im->leaders.v[i]);
        if (st < 0)
            set_del(&im->leaders, i); /* reaped elsewhere: holds nothing any more */
        else if (st == 1 && set_add(&exited, &im->leaders.v[i]) < 0)
            break; /* allocation failure: reap these on a later call */
    }
    mac_gen *m = NULL;
    int live = scan(im, &m);
    track(im, m, live);
    for (int i = im->leaders.n - 1; i >= 0; i--) {
        mac_gen *g = &im->leaders.v[i];
        if (set_has(&exited, g) && waitpid(g->pid, NULL, WNOHANG) == g->pid)
            set_del(&im->leaders, i);
    }
    pthread_mutex_unlock(&im->mu);
    free(exited.v);
    free(m);
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
    /* teardown runs its own freeze/kill loop; the watcher stops helping, and
     * each step below holds im->mu only for its scan so a watcher
     * reconciliation already in flight never waits out the whole teardown */
    watch_quiesce(im, 0);
    out->admission_closed = 1;   /* procd admits nothing more; members are frozen */
    out->authority_directed = 0; /* signals target discovered members, not a kernel domain */
    if (timeout_ms <= 0) timeout_ms = 5000;
    long long deadline = now_ms() + timeout_ms;

    /* 1. freeze: SIGSTOP every member until a scan finds none unstopped */
    mac_set stopped = {0};
    int rounds = 0, unreadable = 0;
    for (;; rounds++) {
        mac_gen *m = NULL;
        pthread_mutex_lock(&im->mu);
        int n = scan(im, &m);
        pthread_mutex_unlock(&im->mu);
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
        mac_gen *m = NULL;
        pthread_mutex_lock(&im->mu);
        mac_reap(im);
        int n = scan(im, &m);
        pthread_mutex_unlock(&im->mu);
        if (n >= 0) remaining = n;
        for (int i = 0; i < n; i++)
            gen_signal(&m[i], SIGKILL);
        free(m);
        if (n == 0 || now_ms() > deadline) break;
        nap(5);
    }
    pthread_mutex_lock(&im->mu);
    mac_reap(im);
    pthread_mutex_unlock(&im->mu);
    int killed = stopped.n;
    char wd[160];
    watch_describe(im, wd, sizeof wd);
    free(stopped.v);

    /* a scan is not proof: never EMPTY, never proven */
    out->emptiness_proven = 0;
    out->enforced = 0;
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    if (unreadable || remaining < 0) {
        snprintf(im->detail, sizeof im->detail, "process table unreadable; outcome unknown%s", wd);
        return PROCD_E_IO;
    }
    if (remaining > 0) {
        snprintf(im->detail, sizeof im->detail,
                 "timed out: %d tracked member(s) still running after %d freeze round(s)%s",
                 remaining, rounds + 1, wd);
        return PROCD_E_TIMEOUT;
    }
    snprintf(im->detail, sizeof im->detail,
             "froze and killed %d tracked member(s) in %d round(s); final scan found none "
             "(scan-based, not a kernel emptiness proof)%s",
             killed, rounds + 1, wd);
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
        watch_quiesce(im, 1); /* after this the watcher cannot reach im */
        /* drop this domain's remaining watches (members still running) */
        for (int i = 0; im->kq >= 0 && i < im->watched.n; i++)
            if (gen_running(&im->watched.v[i])) {
                struct kevent ev;
                EV_SET(&ev, (uintptr_t)im->watched.v[i].pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
                kevent(im->kq, &ev, 1, NULL, 0, NULL);
            }
        free(im->watched.v);
        pthread_mutex_destroy(&im->mu);
        mac_reap(im);
        free(im->leaders.v);
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
