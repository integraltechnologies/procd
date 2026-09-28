/*
 * Linux backend: cgroup v2 lifecycle domains.
 *
 * procd supervises the lifecycle of ordinary task workloads; it is NOT a
 * sandbox. The caller is trusted and the workload is not assumed to try to
 * defeat supervision.
 *
 *   - Each domain is a fresh cgroup ("procd.<16 hex>") created as a child of
 *     procd's OWN cgroup-v2 cgroup (the "0::" line of /proc/self/cgroup). procd
 *     may run as root or as an ordinary user with a writable (delegated)
 *     cgroup-v2 subtree; it needs no other privilege.
 *   - The initial process is admitted to the cgroup BEFORE it executes the
 *     workload, its membership is verified, and only then is it allowed to exec.
 *     The kernel places every descendant it creates -- fork, exec, setsid,
 *     setpgid, double-fork, reparenting, leader exit -- in the same cgroup, so
 *     grouping is independent of PID, process-group and session topology.
 *   - Termination writes cgroup.kill (kernel >= 5.14), which kills every
 *     process in the cgroup including ones forked while the kill is in progress,
 *     then waits for cgroup.events "populated 0". It never signals a discovered
 *     PID list.
 *   - Durable identity = a random nonce naming a root-owned record in
 *     PROCD_STATE_DIR (boot id, cgroup-namespace view, cgroup path and inode,
 *     established level). Recovery trusts only that record, so a stale or
 *     corrupted token can never redirect termination to another cgroup; anything
 *     that cannot be verified is UNRESOLVED. Records need root, so domains
 *     created by an unprivileged caller are usable but not recoverable.
 *
 * ENFORCED here means OS-enforced lifecycle grouping of ordinary descendants, as
 * above. Out of scope: a workload deliberately moving itself to another cgroup,
 * work handed to external services (systemd, cron, container daemons, ...),
 * and descriptors the caller deliberately hands the workload. discover() is a
 * cheap preflight; create() establishes the level on the actual domain.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#if defined(__linux__)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "backend.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#define CG_ROOT "/sys/fs/cgroup"

/* Root-owned directory of durable domain records. Only root can create or
 * modify records, so a record is trustworthy evidence that procd created the
 * exact domain it describes. Not configurable at runtime. */
#ifndef PROCD_STATE_DIR
#define PROCD_STATE_DIR "/var/lib/procd"
#endif

#define NONCE_HEX 32
#define LEAF_HEX 16
#define MAX_LEADERS 64

/* A direct child procd forked. The pidfd (when available) lets procd reap
 * exactly that child even if the embedder already reaped it and the pid was
 * reused; the pid alone is the fallback. */
typedef struct {
    pid_t pid;
    int pidfd;
} lx_leader;

typedef struct {
    char path[512];         /* absolute path of invocation cgroup */
    char rel[384];          /* path relative to cgroup mount, for /proc/<pid>/cgroup compare */
    unsigned long long ino; /* cgroup id (inode), generation-safe within a boot */
    char boot_id[64];
    char nonce[NONCE_HEX + 1];     /* names the durable record */
    unsigned long long cgns_ino;   /* cgroup namespace the path is relative to */
    unsigned long long cgroot_ino; /* cgroup at the CG_ROOT mount (view identity) */
    int level;                     /* level established at create(), as recorded */
    int set_uid, set_gid;          /* explicit run-as requested (else caller's credentials) */
    uid_t uid;
    gid_t gid;
    int removed;      /* directory has actually been rmdir'd */
    int proven_empty; /* this handle observed populated==0 at ENFORCED */
    lx_leader leaders[MAX_LEADERS];
    int nleaders;
    char detail[256]; /* per-domain termination detail (not shared) */
} linux_impl;

/* Fields shared by the durable record and the identity token. uid/gid are the
 * requested run-as identity (-1 = the spawning caller's credentials). */
typedef struct {
    char nonce[NONCE_HEX + 1];
    char boot[64];
    unsigned long long cgns_ino;
    unsigned long long cgroot_ino;
    unsigned long long ino;
    int level;
    long uid;
    long gid;
    char path[512];
} lx_record;

/* -------- small file helpers -------- */
static int read_file(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r] = 0;
    return (int)r;
}
static int write_str(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t w = write(fd, s, strlen(s));
    close(fd);
    return (w < 0) ? -1 : 0;
}
static void join(char *dst, size_t n, const char *dir, const char *leaf) {
    snprintf(dst, n, "%s/%s", dir, leaf);
}
static int file_exists(const char *dir, const char *leaf) {
    char p[600];
    join(p, sizeof p, dir, leaf);
    return access(p, F_OK) == 0;
}
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Extract the cgroup-v2 (unified) path -- the "0::<path>" line -- from a
 * /proc/<pid>/cgroup file. On a hybrid v1/v2 host such a file has several lines
 * and only this one describes the unified hierarchy procd operates in; the
 * leading v1 controller lines describe unrelated hierarchies and their paths
 * would place (or appear to place) the invocation cgroup outside procd's own
 * cgroup. The whole file is read and required to be complete: a truncated
 * view could name a different cgroup, so it is refused rather than guessed.
 * Returns 0 on success. */
static int read_v2_cgroup(const char *proc_path, char *out, size_t n) {
    int fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[8192];
    size_t len = 0;
    int complete = 0;
    for (;;) {
        if (len >= sizeof buf - 1) break; /* overflow: view is not complete */
        ssize_t r = read(fd, buf + len, sizeof buf - 1 - len);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) {
            complete = 1;
            break;
        }
        len += (size_t)r;
    }
    close(fd);
    if (!complete) return -1; /* a truncated cgroup view is not trustworthy */
    buf[len] = 0;
    for (char *line = buf; line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        /* the unified hierarchy is the entry with an empty controller list: "0::" */
        if (line[0] == '0' && line[1] == ':' && line[2] == ':') {
            const char *path = line + 3;
            if (path[0] != '/') return -1; /* not an absolute cgroup path */
            size_t pl = strlen(path);
            if (pl >= n) return -1; /* would truncate: refuse */
            memcpy(out, path, pl + 1);
            return 0;
        }
        line = nl ? nl + 1 : NULL;
    }
    return -1; /* no unified (cgroup2) hierarchy for this process */
}
static int self_v2_cgroup(char *out, size_t n) {
    return read_v2_cgroup("/proc/self/cgroup", out, n);
}

/* populated flag from cgroup.events; returns 1 populated, 0 empty, -1 unknown */
static int cg_populated(const char *cgpath) {
    char p[600], buf[256];
    join(p, sizeof p, cgpath, "cgroup.events");
    if (read_file(p, buf, sizeof buf) < 0) return -1;
    /* cgroup.events has multiple lines, e.g. "populated 0\nfrozen 1\n".
     * Parse the populated field's own value; do NOT scan past its line (the
     * frozen line's digit must not be mistaken for the populated count). */
    char *pos = strstr(buf, "populated");
    if (!pos) return -1;
    pos += strlen("populated");
    while (*pos == ' ' || *pos == '\t')
        pos++;
    return (*pos == '0') ? 0 : 1;
}

/* -------- identity field validation -------- */
static int is_hex_n(const char *s, size_t n) {
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}
/* boot_id is a lowercase UUID: 8-4-4-4-12 */
static int is_boot_id(const char *s) {
    if (strlen(s) != 36) return 0;
    for (int i = 0; i < 36; i++) {
        int dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? s[i] != '-' : !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    }
    return 1;
}
/* strict unsigned decimal, no sign/space, fits in 64 bits */
static int parse_u64(const char *s, unsigned long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 20) return 0;
    unsigned long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        unsigned long long d = (unsigned long long)(s[i] - '0');
        if (v > (~0ULL - d) / 10) return 0;
        v = v * 10 + d;
    }
    *out = v;
    return 1;
}
/* A procd domain path: absolute, canonical, on CG_ROOT, leaf "procd.<16 hex>". */
static int is_domain_path(const char *p) {
    size_t n = strlen(p);
    size_t rl = strlen(CG_ROOT);
    if (n >= 512 || n <= rl + 1 || strncmp(p, CG_ROOT "/", rl + 1) != 0) return 0;
    if (strstr(p, "//") || strstr(p, "/./") || strstr(p, "/../") || strchr(p, '\n')) return 0;
    const char *leaf = strrchr(p, '/') + 1;
    if (strncmp(leaf, "procd.", 6) != 0 || !is_hex_n(leaf + 6, LEAF_HEX)) return 0;
    return 1;
}

static int read_boot_id(char *out, size_t n) {
    if (read_file("/proc/sys/kernel/random/boot_id", out, n) <= 0) return -1;
    for (char *c = out; *c; ++c)
        if (*c == '\n') {
            *c = 0;
            break;
        }
    return is_boot_id(out) ? 0 : -1;
}

static int ino_of(const char *path, unsigned long long *out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = (unsigned long long)st.st_ino;
    return 0;
}
/* The namespace/mount view that cgroup paths are interpreted in. */
static int current_view(unsigned long long *cgns, unsigned long long *cgroot) {
    if (ino_of("/proc/self/ns/cgroup", cgns) != 0) return -1;
    return ino_of(CG_ROOT, cgroot);
}

static int make_nonce(char out[NONCE_HEX + 1]) {
    unsigned char r[NONCE_HEX / 2];
    size_t got = 0;
    while (got < sizeof r) {
        ssize_t k = getrandom(r + got, sizeof r - got, 0);
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)k;
    }
    for (size_t i = 0; i < sizeof r; i++)
        snprintf(out + 2 * i, 3, "%02x", r[i]);
    return 0;
}

/* -------- protected durable record store -------- */
/* root-owned directory not writable by group/other, not a symlink */
static int secure_dir(const char *p) {
    struct stat st;
    if (lstat(p, &st) != 0) return -1;
    return (S_ISDIR(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 022)) ? 0 : -1;
}
/* 0 if the record store (and every ancestor) is root-protected. With create,
 * a missing store is created 0700. */
static int state_dir_ready(int create) {
    char buf[256];
    snprintf(buf, sizeof buf, "%s", PROCD_STATE_DIR);
    if (buf[0] != '/') return -1;
    /* every proper ancestor must be root-protected */
    for (char *s = strchr(buf + 1, '/'); s; s = strchr(s + 1, '/')) {
        *s = 0;
        int bad = secure_dir(buf) != 0;
        *s = '/';
        if (bad) return -1;
    }
    if (secure_dir("/") != 0) return -1;
    struct stat st;
    if (lstat(buf, &st) != 0) {
        if (errno != ENOENT) return -1;
        if (!create) return 0; /* would be created securely on demand */
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
    }
    return secure_dir(buf);
}
static void record_path(const char *nonce, const char *ext, char *out, size_t n) {
    snprintf(out, n, "%s/%s.%s", PROCD_STATE_DIR, nonce, ext);
}
static int write_record(const lx_record *r) {
    if (state_dir_ready(1) != 0) return -1;
    char tmp[320], fin[320], buf[1024];
    record_path(r->nonce, "tmp", tmp, sizeof tmp);
    record_path(r->nonce, "rec", fin, sizeof fin);
    /* Record v3 also carries the requested run-as uid/gid (-1 = caller's). */
    int n = snprintf(buf, sizeof buf,
                     "procd-record 3\nnonce=%s\nboot=%s\ncgns=%llu\ncgroot=%llu\nino=%llu\n"
                     "level=%d\nuid=%ld\ngid=%ld\npath=%s\n",
                     r->nonce, r->boot, r->cgns_ino, r->cgroot_ino, r->ino, r->level, r->uid,
                     r->gid, r->path);
    if (n <= 0 || (size_t)n >= sizeof buf) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int ok = write(fd, buf, (size_t)n) == n && fsync(fd) == 0;
    close(fd);
    /* link() refuses to replace an existing record */
    if (!ok || link(tmp, fin) != 0) {
        unlink(tmp);
        return -1;
    }
    unlink(tmp);
    int dfd = open(PROCD_STATE_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
    return 0;
}

/* split next ':'-terminated field of *s into out; 0 on success */
static int next_field(const char **s, char *out, size_t n) {
    const char *c = strchr(*s, ':');
    if (!c || c == *s || (size_t)(c - *s) >= n) return -1;
    memcpy(out, *s, (size_t)(c - *s));
    out[c - *s] = 0;
    *s = c + 1;
    return 0;
}
static int valid_record_fields(const lx_record *r) {
    return is_hex_n(r->nonce, NONCE_HEX) && is_boot_id(r->boot) && r->level >= 0 &&
           r->level <= PROCD_CAP_ENFORCED && is_domain_path(r->path);
}
/* identity: linux-cgroup2:2:<nonce>:<boot>:<cgns>:<cgroot>:<ino>:<level>:<path> */
static int parse_identity(const char *s, lx_record *r) {
    static const char pfx[] = "linux-cgroup2:2:";
    if (strncmp(s, pfx, sizeof pfx - 1) != 0) return -1;
    s += sizeof pfx - 1;
    char a[32], b[32], c[32], lv[4];
    if (next_field(&s, r->nonce, sizeof r->nonce) || next_field(&s, r->boot, sizeof r->boot) ||
        next_field(&s, a, sizeof a) || next_field(&s, b, sizeof b) || next_field(&s, c, sizeof c) ||
        next_field(&s, lv, sizeof lv))
        return -1;
    if (!parse_u64(a, &r->cgns_ino) || !parse_u64(b, &r->cgroot_ino) || !parse_u64(c, &r->ino))
        return -1;
    if (strlen(lv) != 1 || lv[0] < '0' || lv[0] > '2') return -1;
    r->level = lv[0] - '0';
    if (strlen(s) >= sizeof r->path) return -1;
    snprintf(r->path, sizeof r->path, "%s", s);
    r->uid = r->gid = -1; /* the token does not carry the run-as policy; the record does */
    return valid_record_fields(r) ? 0 : -1;
}
/* 0 ok; -1 absent (ENOENT); -2 present but unreadable/untrusted/malformed.
 * Accepts v3 (with run-as uid/gid) and legacy v2 (uid/gid -1: caller's). */
static int read_record(const char *nonce, lx_record *r) {
    char p[320], buf[1024];
    record_path(nonce, "rec", p, sizeof p);
    int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? -1 : -2;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
        close(fd);
        return -2;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0 || (size_t)n >= sizeof buf - 1) return -2;
    buf[n] = 0;
    char cgns[32], cgroot[32], ino[32];
    int used = 0;
    r->uid = r->gid = -1;
    if (sscanf(buf,
               "procd-record 3\nnonce=%32[0-9a-f]\nboot=%63[0-9a-f-]\ncgns=%31[0-9]\n"
               "cgroot=%31[0-9]\nino=%31[0-9]\nlevel=%d\nuid=%ld\ngid=%ld\npath=%511[^\n]\n%n",
               r->nonce, r->boot, cgns, cgroot, ino, &r->level, &r->uid, &r->gid, r->path,
               &used) == 9 &&
        used == (int)n) {
        /* v3 */
    } else if (sscanf(buf,
                      "procd-record 2\nnonce=%32[0-9a-f]\nboot=%63[0-9a-f-]\ncgns=%31[0-9]\n"
                      "cgroot=%31[0-9]\nino=%31[0-9]\nlevel=%d\npath=%511[^\n]\n%n",
                      r->nonce, r->boot, cgns, cgroot, ino, &r->level, r->path, &used) == 7 &&
               used == (int)n) {
        r->uid = r->gid = -1; /* legacy: no run-as policy recorded */
    } else {
        return -2;
    }
    if (!parse_u64(cgns, &r->cgns_ino) || !parse_u64(cgroot, &r->cgroot_ino) ||
        !parse_u64(ino, &r->ino) || !valid_record_fields(r) || strcmp(r->nonce, nonce) != 0)
        return -2;
    return 0;
}

/* -------- direct-child bookkeeping (reaping) -------- */
static int pidfd_of(pid_t pid) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0); /* pidfds are always close-on-exec */
#else
    (void)pid;
    return -1;
#endif
}
/* Non-blocking reap of one tracked child; 1 once the slot is free. Only ever
 * waits on procd's own child: through its pidfd when available, so a pid the
 * embedder already reaped (and the kernel reused) is never touched. */
static int reap_one(lx_leader *l) {
    if (l->pid <= 0) return 1;
    int done;
    if (l->pidfd >= 0) {
        siginfo_t si;
        memset(&si, 0, sizeof si);
        int r = waitid((idtype_t)P_PIDFD, (id_t)l->pidfd, &si, WEXITED | WNOHANG);
        done = (r == 0 && si.si_pid != 0) || (r < 0 && errno == ECHILD);
    } else {
        pid_t r = waitpid(l->pid, NULL, WNOHANG);
        done = r == l->pid || (r < 0 && errno == ECHILD);
    }
    if (done) {
        if (l->pidfd >= 0) close(l->pidfd);
        l->pid = 0;
        l->pidfd = -1;
    }
    return done;
}
/* Reap without blocking; returns the number of children still pending. */
static int reap_leaders(linux_impl *im) {
    int pending = 0;
    for (int i = 0; i < im->nleaders; i++)
        pending += !reap_one(&im->leaders[i]);
    return pending;
}
/* Reap until nothing is pending or the deadline passes (never blocks past it). */
static void reap_leaders_until(linux_impl *im, long long deadline) {
    while (reap_leaders(im) > 0 && now_ms() < deadline) {
        struct timespec ts = {0, 1000 * 1000}; /* 1ms */
        nanosleep(&ts, NULL);
    }
}
static void track_leader(linux_impl *im, pid_t pid) {
    reap_leaders(im); /* recycle slots from exited leaders first */
    lx_leader *slot = NULL;
    for (int i = 0; i < im->nleaders && !slot; i++)
        if (im->leaders[i].pid == 0) slot = &im->leaders[i];
    if (!slot && im->nleaders < MAX_LEADERS) slot = &im->leaders[im->nleaders++];
    /* If full, cgroup.kill still terminates the process; only its reaping is
     * left to the embedder (a bounded number of zombies until then). */
    if (!slot) return;
    slot->pid = pid;
    slot->pidfd = pidfd_of(pid); /* pid is our unreaped child: cannot be reused yet */
}

/* -------- lifecycle-domain establishment -------- */
static int cgroup2_mounted(void) {
    struct statfs sf;
    if (statfs(CG_ROOT, &sf) != 0) return 0;
    return sf.f_type == CGROUP2_SUPER_MAGIC;
}
static int cgroup_root_ro(void) {
    struct statvfs v;
    if (statvfs(CG_ROOT, &v) != 0) return 1; /* cannot tell -> treat as unusable */
    return (v.f_flag & ST_RDONLY) ? 1 : 0;
}

/* The invocation cgroup exposes the controls spawn/status/terminate use. */
static int invocation_controls_ok(const char *path) {
    char f[600];
    join(f, sizeof f, path, "cgroup.kill");
    if (access(f, W_OK) != 0) return 0;
    join(f, sizeof f, path, "cgroup.procs");
    if (access(f, W_OK) != 0) return 0;
    join(f, sizeof f, path, "cgroup.events");
    if (access(f, R_OK) != 0) return 0;
    return cg_populated(path) >= 0;
}

/* uid/gid must round-trip exactly through the platform type (no narrowing). */
static int uid_repr(int64_t v, uid_t *out) {
    if (v < 0) return 0;
    uid_t u = (uid_t)v;
    if ((int64_t)u != v) return 0;
    *out = u;
    return 1;
}
static int gid_repr(int64_t v, gid_t *out) {
    if (v < 0) return 0;
    gid_t g = (gid_t)v;
    if ((int64_t)g != v) return 0;
    *out = g;
    return 1;
}
/* Resolve a requested run-as policy: -1 keeps the caller's credentials. */
static int resolve_identity(int64_t uv, int64_t gv, linux_impl *im) {
    im->set_uid = uv != -1;
    im->set_gid = gv != -1;
    if (im->set_uid && !uid_repr(uv, &im->uid)) return -1;
    if (im->set_gid && !gid_repr(gv, &im->gid)) return -1;
    return 0;
}

/* Preflight: can this process host a domain here? Conservative and cheap;
 * create() confirms on the actual invocation cgroup. */
static procd_capability discover(char *detail, size_t dn) {
    if (!cgroup2_mounted()) {
        snprintf(detail, dn, "cgroup v2 not mounted at %s", CG_ROOT);
        return PROCD_CAP_UNSUPPORTED;
    }
    if (cgroup_root_ro()) {
        snprintf(detail, dn, "cgroup v2 mount at %s is read-only", CG_ROOT);
        return PROCD_CAP_UNSUPPORTED;
    }
    char rel[384];
    if (self_v2_cgroup(rel, sizeof rel) != 0) {
        snprintf(detail, dn, "cannot read this process's cgroup-v2 path");
        return PROCD_CAP_UNSUPPORTED;
    }
    char own[512], procs[600];
    snprintf(own, sizeof own, "%s%s", CG_ROOT, strcmp(rel, "/") == 0 ? "" : rel);
    join(procs, sizeof procs, own, "cgroup.procs");
    if (access(own, W_OK) != 0 || access(procs, W_OK) != 0) {
        snprintf(detail, dn,
                 "own cgroup %.120s is not writable by this process (no delegated cgroup-v2 "
                 "subtree): cannot create a lifecycle domain",
                 own);
        return PROCD_CAP_UNSUPPORTED;
    }
    /* A real root cgroup never exposes cgroup.kill; any other cgroup does on
     * kernels that support it. The created domain is checked either way. */
    if (strcmp(rel, "/") != 0 && !file_exists(own, "cgroup.kill")) {
        snprintf(detail, dn, "cgroup.kill absent (needs kernel >= 5.14)");
        return PROCD_CAP_UNSUPPORTED;
    }
    snprintf(detail, dn,
             "cgroup v2 lifecycle domain under own cgroup: ordinary descendants stay grouped "
             "regardless of process topology; terminate via cgroup.kill, emptiness via "
             "cgroup.events (lifecycle supervision, not a sandbox)");
    return PROCD_CAP_ENFORCED;
}

static void lx_probe(procd_capabilities *out) {
    static char detail[256];
    procd_capability lvl = discover(detail, sizeof detail);
    out->backend = "linux-cgroup2";
    out->process_tree_termination = lvl;
    out->pre_execution_containment = lvl; /* admitted before exec */
    out->descendant_containment = lvl;
    out->topology_escape_resistance = lvl;
    out->domain_emptiness_proof = lvl;
    /* Recovery needs the root-owned record store; without it no record can
     * prove a domain existed, so recovery could only be UNRESOLVED. */
    out->safe_recovery = (lvl == PROCD_CAP_ENFORCED && geteuid() == 0 && state_dir_ready(0) == 0)
                             ? PROCD_CAP_ENFORCED
                             : PROCD_CAP_UNSUPPORTED;
    out->crash_behavior = (out->safe_recovery == PROCD_CAP_ENFORCED)
                              ? PROCD_CRASH_DURABLE_REACQUISITION
                              : PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS;
    out->detail = detail;
}

/* -------- create -------- */
static procd_status lx_create(procd_domain *d) {
    /* Linux has no weaker lifecycle mechanism to fall back to: without a usable
     * cgroup-v2 domain nothing is created (never a fabricated directory). */
    procd_status refuse = (d->policy.enforcement == PROCD_REQUIRE_ENFORCED)
                              ? PROCD_E_UNSUPPORTED_ENFORCEMENT
                              : PROCD_E_PREREQUISITE;
    char detail[256];
    if (discover(detail, sizeof detail) != PROCD_CAP_ENFORCED) return refuse;

    linux_impl *im = calloc(1, sizeof(*im));
    if (!im) return PROCD_E_INTERNAL;
    if (resolve_identity(d->policy.drop_uid, d->policy.drop_gid, im) != 0) {
        free(im);
        return PROCD_E_INVALID_ARGUMENT;
    }

    /* The parent is procd's own cgroup-v2 cgroup, never a v1 controller line. */
    char rel_buf[512];
    if (self_v2_cgroup(rel_buf, sizeof rel_buf) != 0) {
        free(im);
        return PROCD_E_IO;
    }
    const char *rel = rel_buf;

    if (make_nonce(im->nonce) != 0 || read_boot_id(im->boot_id, sizeof im->boot_id) != 0 ||
        current_view(&im->cgns_ino, &im->cgroot_ino) != 0) {
        free(im);
        return PROCD_E_IO;
    }
    char leaf[64];
    snprintf(leaf, sizeof leaf, "procd.%.*s", LEAF_HEX, im->nonce);

    /* Build rel (as in /proc/<pid>/cgroup) and the absolute path with explicit
     * bounds: a truncated path would name some other cgroup, so refuse. */
    int is_root = strcmp(rel, "/") == 0;
    const char *pre = is_root ? "" : rel;
    size_t pl = strlen(pre), ll = strlen(leaf);
    size_t rl = strlen(CG_ROOT);
    if (pl + 1 + ll >= sizeof im->rel || rl + pl + 1 + ll >= sizeof im->path) {
        free(im);
        return PROCD_E_IO;
    }
    memcpy(im->rel, pre, pl);
    im->rel[pl] = '/';
    memcpy(im->rel + pl + 1, leaf, ll + 1);
    memcpy(im->path, CG_ROOT, rl);
    memcpy(im->path + rl, im->rel, pl + 1 + ll + 1);

    if (mkdir(im->path, 0755) != 0) {
        int e = errno;
        free(im);
        return (e == EACCES || e == EPERM)   ? PROCD_E_PERMISSION
               : (e == ENOENT || e == EROFS) ? PROCD_E_PREREQUISITE
                                             : PROCD_E_IO;
    }
    if (!is_domain_path(im->path) || ino_of(im->path, &im->ino) != 0) {
        rmdir(im->path);
        free(im);
        return PROCD_E_IO;
    }
    /* Establish on the actual domain: it must expose the controls we use. */
    if (!invocation_controls_ok(im->path)) {
        rmdir(im->path);
        free(im);
        return refuse;
    }

    /* Durable record (root only). Without it the domain works normally but
     * cannot be recovered after authority loss (recovery reports UNRESOLVED). */
    im->level = PROCD_CAP_ENFORCED;
    if (geteuid() == 0) {
        lx_record rec;
        memset(&rec, 0, sizeof rec);
        snprintf(rec.nonce, sizeof rec.nonce, "%s", im->nonce);
        snprintf(rec.boot, sizeof rec.boot, "%s", im->boot_id);
        rec.cgns_ino = im->cgns_ino;
        rec.cgroot_ino = im->cgroot_ino;
        rec.ino = im->ino;
        rec.level = im->level;
        rec.uid = im->set_uid ? (long)im->uid : -1;
        rec.gid = im->set_gid ? (long)im->gid : -1;
        snprintf(rec.path, sizeof rec.path, "%s", im->path);
        (void)write_record(&rec);
    }

    d->impl = im;
    d->runtime_level = PROCD_CAP_ENFORCED;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

/* verify the child landed in exactly our cgroup (its "0::" line) */
static int verify_membership(linux_impl *im, pid_t pid) {
    char p[64], rel[512];
    snprintf(p, sizeof p, "/proc/%d/cgroup", (int)pid);
    if (read_v2_cgroup(p, rel, sizeof rel) != 0) return 0;
    return strcmp(rel, im->rel) == 0;
}

/* async-signal-safe decimal conversion for use in the post-fork child */
static int as_pid(char *buf, long v) {
    char t[24];
    int n = 0;
    if (v <= 0) {
        buf[0] = '0';
        buf[1] = 0;
        return 1;
    }
    while (v > 0 && n < (int)sizeof t) {
        t[n++] = (char)('0' + v % 10);
        v /= 10;
    }
    int m = 0;
    while (n > 0)
        buf[m++] = t[--n];
    buf[m] = 0;
    return m;
}

/* Close every inherited descriptor except stdio and `keep` (the exec-status
 * pipe), so caller pipes/sockets do not leak into the task (a leaked pipe held
 * by a background descendant is a classic cause of a supervisor never seeing
 * EOF). Runs in the post-fork/pre-exec child. */
static void close_inherited(int keep) {
#ifdef __NR_close_range
    int ok = 1;
    if (keep > 3 && syscall(__NR_close_range, 3u, (unsigned)(keep - 1), 0u) != 0) ok = 0;
    if (syscall(__NR_close_range, (unsigned)(keep + 1), ~0u, 0u) != 0) ok = 0;
    if (ok) return;
#endif
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        int dfd = dirfd(dir);
        struct dirent *e;
        while ((e = readdir(dir))) {
            int fd = atoi(e->d_name);
            if (fd > 2 && fd != keep && fd != dfd) close(fd);
        }
        closedir(dir);
        return;
    }
    long hi = sysconf(_SC_OPEN_MAX);
    if (hi < 3 || hi > 1048576) hi = 1048576;
    for (long fd = 3; fd < hi; fd++)
        if (fd != (long)keep) close((int)fd);
}

/* Optional explicit run-as identity, applied in the child before exec. Plain
 * checked system calls plus a read-back; any failure fails the spawn. */
static int child_set_identity(const linux_impl *im) {
    if (!im->set_uid && !im->set_gid) return 0; /* keep the caller's credentials */
    int was_root = geteuid() == 0;
    if (was_root && setgroups(0, NULL) != 0) return -1; /* no root supplementary groups */
    if (im->set_gid && setresgid(im->gid, im->gid, im->gid) != 0) return -1;
    if (im->set_uid && setresuid(im->uid, im->uid, im->uid) != 0) return -1;
    if (im->set_gid) {
        gid_t r, e, s;
        if (getresgid(&r, &e, &s) != 0 || r != im->gid || e != im->gid || s != im->gid) return -1;
    }
    if (im->set_uid) {
        uid_t r, e, s;
        if (getresuid(&r, &e, &s) != 0 || r != im->uid || e != im->uid || s != im->uid) return -1;
    }
    if (was_root && getgroups(0, NULL) != 0) return -1;
    return 0;
}

static procd_status lx_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    linux_impl *im = d->impl;
    if (im->removed) return PROCD_E_STATE;
    reap_leaders(im); /* opportunistically reap earlier leaders that exited */
    if (access(im->path, F_OK) != 0) return PROCD_E_STATE;
    if (d->runtime_level == PROCD_CAP_ENFORCED && !invocation_controls_ok(im->path))
        return PROCD_E_STATE;

    char cgprocs[600];
    join(cgprocs, sizeof cgprocs, im->path, "cgroup.procs");

    /* admit: child->parent "admitted"; go: parent->child "verified, exec" (a
     * socket so the parent's send cannot raise SIGPIPE if the child died);
     * status: child->parent failure byte, or EOF once exec succeeded. */
    int admit[2] = {-1, -1}, go[2] = {-1, -1}, status[2] = {-1, -1};
    if (pipe2(admit, O_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, go) != 0 ||
        pipe2(status, O_CLOEXEC) != 0) {
        int all[6] = {admit[0], admit[1], go[0], go[1], status[0], status[1]};
        for (int i = 0; i < 6; i++)
            if (all[i] >= 0) close(all[i]);
        return PROCD_E_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(admit[0]);
        close(admit[1]);
        close(go[0]);
        close(go[1]);
        close(status[0]);
        close(status[1]);
        return PROCD_E_IO;
    }

    if (pid == 0) {
        /* ---- child: has NOT executed the workload ----
         * Post-fork/pre-exec: only async-signal-safe calls, except the /proc
         * fallback in close_inherited and execvp's PATH search. Drop the parent's
         * ends first so a parent that dies is seen as EOF, not a hang. */
        close(admit[0]);
        close(go[0]);
        close(status[0]);
        char me[24];
        as_pid(me, (long)getpid());
        int ok = (write_str(cgprocs, me) == 0);
        char b = ok ? 1 : 0;
        ssize_t wn = write(admit[1], &b, 1);
        (void)wn;
        if (!ok) _exit(127);
        char g = 0;
        if (read(go[1], &g, 1) != 1 || g != 1) _exit(127); /* parent refused or died */

        close_inherited(status[1]);
        /* TEST-ONLY negative control: model process-group supervision. */
        if (procd_nc_weaken_containment()) setpgid(0, 0);
        if (child_set_identity(im) != 0) {
            char e = 'P';
            ssize_t x = write(status[1], &e, 1);
            (void)x;
            _exit(126);
        }
        execvp(argv[0], (char *const *)argv);
        /* exec failed: report 'X' plus exec's errno in one atomic pipe write */
        int en = errno;
        char msg[1 + sizeof en];
        msg[0] = 'X';
        memcpy(msg + 1, &en, sizeof en);
        ssize_t x = write(status[1], msg, sizeof msg);
        (void)x;
        _exit(127);
    }

    /* ---- parent: admit, verify, then permit exec ---- */
    close(admit[1]);
    close(go[1]);
    close(status[1]); /* only the child holds a writer, so EOF == exec succeeded */

    char b = 0;
    ssize_t rn = read(admit[0], &b, 1);
    close(admit[0]);
    if (rn != 1 || b != 1) {
        /* Admission failed; the child exits on its own (or on EOF from go). */
        close(go[0]);
        close(status[0]);
        waitpid(pid, NULL, 0);
        return PROCD_E_IO;
    }

    /* A failed spawn only ever kills its OWN unreaped child (its pid cannot
     * have been reused), never the domain: other workloads keep running. */
    char g = 1;
    if (!verify_membership(im, pid) || send(go[0], &g, 1, MSG_NOSIGNAL) != 1) {
        close(go[0]);
        close(status[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return PROCD_E_IO;
    }
    close(go[0]);

    /* Status channel (close-on-exec in the child): EOF with no data = exec
     * succeeded; 'P' = the run-as identity could not be established; 'X' +
     * errno = exec failed; anything else = a lost handshake. */
    char msg[1 + sizeof(int)];
    size_t got = 0;
    for (;;) {
        ssize_t sn = read(status[0], msg + got, sizeof msg - got);
        if (sn < 0 && errno == EINTR) continue;
        if (sn <= 0) break;
        got += (size_t)sn;
        if (got == sizeof msg) break;
    }
    close(status[0]);
    if (got != 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (msg[0] == 'P') return PROCD_E_PERMISSION;
        if (msg[0] == 'X' && got == sizeof msg) {
            int en;
            memcpy(&en, msg + 1, sizeof en);
            if (en == ENOENT || en == ENOTDIR) return PROCD_E_NOT_FOUND;
            if (en == EACCES || en == EPERM) return PROCD_E_PERMISSION;
        }
        return PROCD_E_IO;
    }

    track_leader(im, pid);
    if (out_pid) *out_pid = pid; /* diagnostic metadata only */
    d->state = PROCD_STATE_ACTIVE;
    return PROCD_OK;
}

static procd_status lx_status(procd_domain *d, procd_domain_status *out) {
    linux_impl *im = d->impl;
    out->process_tree_termination = d->runtime_level;
    /* cgroup.events speaks for the domain only at ENFORCED (e.g. a recovered
     * handle whose controls are no longer usable is reported below it). */
    int authoritative = (d->runtime_level == PROCD_CAP_ENFORCED);
    if (im->removed) {
        out->population = PROCD_POP_EMPTY;
        out->population_is_authoritative = authoritative;
        if (d->state == PROCD_STATE_RELEASED)
            out->state = PROCD_STATE_RELEASED;
        else if (d->runtime_level == PROCD_CAP_ENFORCED)
            out->state = PROCD_STATE_EMPTY;
        else
            out->state = d->state;
        return PROCD_OK;
    }
    int pop = cg_populated(im->path);
    if (pop < 0) {
        out->population = PROCD_POP_UNKNOWN;
        out->population_is_authoritative = 0;
    } else {
        out->population = pop ? PROCD_POP_POPULATED : PROCD_POP_EMPTY;
        out->population_is_authoritative = authoritative;
    }
    out->state = d->state;
    return PROCD_OK;
}

static procd_status lx_terminate(procd_domain *d, int timeout_ms, procd_termination_evidence *out) {
    linux_impl *im = d->impl;
    char *detail = im->detail;
    size_t dcap = sizeof im->detail;
    out->detail = detail;
    if (timeout_ms <= 0) timeout_ms = 5000;
    long long deadline = now_ms() + timeout_ms;

    if (im->removed || access(im->path, F_OK) != 0) {
        /* Idempotent only if THIS handle already proved the domain empty. A
         * path that vanished otherwise was not observed empty by us. */
        int p = im->proven_empty;
        out->admission_closed = p;
        out->authority_directed = p;
        out->emptiness_proven = p;
        out->enforced = p && d->runtime_level == PROCD_CAP_ENFORCED;
        out->final_state = p ? PROCD_STATE_EMPTY : PROCD_STATE_UNRESOLVED;
        d->state = out->final_state;
        reap_leaders(im);
        snprintf(detail, dcap, "%s",
                 p ? "domain already removed; emptiness previously proven"
                   : "domain path vanished without this handle proving emptiness");
        return PROCD_OK;
    }

    d->state = PROCD_STATE_TERMINATING;
    out->admission_closed = 1; /* this handle admits nothing from now on */

    char kp[600];
    join(kp, sizeof kp, im->path, "cgroup.kill");
    int killed;
    if (procd_nc_weaken_containment()) {
        /* TEST-ONLY negative control: process-group termination instead of the
         * cgroup, to show what the lifecycle domain adds over it. */
        for (int i = 0; i < im->nleaders; i++)
            if (im->leaders[i].pid > 0) killpg(im->leaders[i].pid, SIGKILL);
        killed = 0;
    } else {
        killed = (write_str(kp, "1") == 0);
        if (!killed) {
            snprintf(detail, dcap, "cgroup.kill write failed: %s", strerror(errno));
            out->final_state = PROCD_STATE_UNRESOLVED;
            d->state = PROCD_STATE_UNRESOLVED;
            return PROCD_E_IO;
        }
    }
    out->authority_directed = killed;

    /* cgroup.kill also kills processes forked while it runs, so "populated 0"
     * afterwards means the domain is empty. If the directory then cannot be
     * removed, re-check instead of trusting the earlier observation: a process
     * admitted in between (e.g. through another handle) is killed too. */
    int pop = 1, gone = 0;
    for (;;) {
        pop = cg_populated(im->path);
        if (pop == 0) {
            if (rmdir(im->path) == 0 || errno == ENOENT) {
                gone = 1;
                break;
            }
            if ((pop = cg_populated(im->path)) == 0) break; /* empty, just not removable */
            if (killed) write_str(kp, "1");
        }
        if (now_ms() >= deadline) break;
        struct timespec ts = {0, 5 * 1000 * 1000}; /* 5ms */
        nanosleep(&ts, NULL);
    }
    im->removed = gone;
    reap_leaders_until(im, deadline); /* non-blocking, bounded by the timeout */

    if (pop != 0) {
        out->emptiness_proven = 0;
        out->enforced = 0;
        out->final_state = PROCD_STATE_UNRESOLVED;
        d->state = PROCD_STATE_UNRESOLVED;
        snprintf(detail, dcap, "timed out waiting for cgroup.events populated 0");
        return PROCD_E_TIMEOUT;
    }
    if (d->runtime_level == PROCD_CAP_ENFORCED) {
        im->proven_empty = 1;
        out->emptiness_proven = 1;
        out->enforced = 1;
        out->final_state = PROCD_STATE_EMPTY;
        d->state = PROCD_STATE_EMPTY;
        snprintf(detail, dcap, "%s; cgroup.events populated 0; cgroup %s",
                 killed ? "cgroup.kill issued" : "process-group kill (test-only)",
                 gone ? "removed" : "empty but NOT removed (rmdir failed)");
    } else {
        /* Below ENFORCED the empty cgroup is reported, but not as proof that
         * no owned work remains. */
        out->emptiness_proven = 0;
        out->enforced = 0;
        out->final_state = PROCD_STATE_UNRESOLVED;
        d->state = PROCD_STATE_UNRESOLVED;
        snprintf(detail, dcap,
                 "cgroup.events populated 0, but owned-work emptiness is not established below "
                 "ENFORCED; cgroup %s",
                 gone ? "removed" : "empty but NOT removed (rmdir failed)");
    }
    return PROCD_OK;
}

static procd_status lx_identity(procd_domain *d, char *buf, size_t n) {
    linux_impl *im = d->impl;
    int w = snprintf(buf, n, "linux-cgroup2:2:%s:%s:%llu:%llu:%llu:%d:%s", im->nonce, im->boot_id,
                     im->cgns_ino, im->cgroot_ino, im->ino, im->level, im->path);
    return (w > 0 && (size_t)w < n) ? PROCD_OK : PROCD_E_INVALID_ARGUMENT;
}

static void lx_destroy(procd_domain *d) {
    linux_impl *im = d->impl;
    if (im) {
        /* Release without killing (durable reacquisition). Reap what already
         * exited, drop the rest to the embedder, reclaim an empty directory. */
        reap_leaders(im);
        for (int i = 0; i < im->nleaders; i++)
            if (im->leaders[i].pidfd >= 0) close(im->leaders[i].pidfd);
        if (!im->removed && access(im->path, F_OK) == 0 && cg_populated(im->path) == 0 &&
            rmdir(im->path) == 0)
            im->removed = 1;
        free(im);
    }
    d->impl = NULL;
}

static procd_status lx_recover(const char *identity, procd_recovery_outcome *outcome,
                               procd_domain **out_domain) {
    /*
     * Every conclusion comes from the root-owned record, never from the token
     * alone; the token must match the record exactly. Anything unverifiable
     * stays UNRESOLVED (preset by the dispatcher).
     */
    lx_record id, rec;
    memset(&id, 0, sizeof id);
    memset(&rec, 0, sizeof rec);
    if (parse_identity(identity, &id) != 0) return PROCD_E_INVALID_ARGUMENT;

    if (geteuid() != 0) return PROCD_E_PERMISSION; /* the record store is root-only */
    if (state_dir_ready(0) != 0) return PROCD_E_PREREQUISITE;

    int rr = read_record(id.nonce, &rec);
    if (rr == -1) return PROCD_OK; /* no evidence the domain ever existed */
    if (rr != 0) return PROCD_E_IO;
    if (strcmp(id.boot, rec.boot) != 0 || id.cgns_ino != rec.cgns_ino ||
        id.cgroot_ino != rec.cgroot_ino || id.ino != rec.ino || id.level != rec.level ||
        strcmp(id.path, rec.path) != 0)
        return PROCD_OK; /* token disagrees with the record: never redirect */

    char cur_boot[64];
    if (read_boot_id(cur_boot, sizeof cur_boot) != 0) return PROCD_E_IO;
    if (strcmp(cur_boot, rec.boot) != 0) {
        /* A reboot ended every process of the recorded domain. */
        *outcome = PROCD_CONFIRMED_DESTROYED;
        return PROCD_OK;
    }

    /* Same boot: the path is only meaningful in the view it was recorded in. */
    if (!cgroup2_mounted()) return PROCD_E_PREREQUISITE;
    unsigned long long cgns = 0, cgroot = 0;
    if (current_view(&cgns, &cgroot) != 0) return PROCD_E_IO;
    if (cgns != rec.cgns_ino || cgroot != rec.cgroot_ino) return PROCD_OK;

    /* A vanished cgroup (cgroups cannot be renamed; rmdir needs it empty) or a
     * new cgroup at the same path proves this domain's destruction only if the
     * domain grouped all owned work, i.e. was recorded at ENFORCED. */
    int enforced_record = rec.level == PROCD_CAP_ENFORCED;
    int fd = open(rec.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT) return PROCD_E_IO;
        if (enforced_record) *outcome = PROCD_CONFIRMED_DESTROYED;
        return PROCD_OK;
    }
    struct statfs sf;
    struct stat st;
    int ok = fstatfs(fd, &sf) == 0 && sf.f_type == CGROUP2_SUPER_MAGIC && fstat(fd, &st) == 0;
    close(fd);
    if (!ok) return PROCD_E_IO;
    if ((unsigned long long)st.st_ino != rec.ino) {
        if (enforced_record) *outcome = PROCD_CONFIRMED_DESTROYED;
        return PROCD_OK;
    }

    /* exact generation still present: reacquire */
    linux_impl *im = calloc(1, sizeof(*im));
    if (!im) return PROCD_E_INTERNAL;
    {
        size_t plen = strlen(rec.path);
        const char *r = rec.path + strlen(CG_ROOT);
        size_t rlen = strlen(r);
        if (plen >= sizeof im->path || rlen >= sizeof im->rel) {
            free(im);
            return PROCD_E_INVALID_ARGUMENT;
        }
        memcpy(im->path, rec.path, plen + 1);
        memcpy(im->rel, r, rlen + 1);
    }
    im->ino = rec.ino;
    snprintf(im->boot_id, sizeof im->boot_id, "%s", rec.boot);
    snprintf(im->nonce, sizeof im->nonce, "%s", rec.nonce);
    im->cgns_ino = rec.cgns_ino;
    im->cgroot_ino = rec.cgroot_ino;
    im->level = rec.level;
    /* restore the recorded run-as policy (validated by read_record) */
    if (resolve_identity(rec.uid, rec.gid, im) != 0) {
        free(im);
        return PROCD_E_IO;
    }
    procd_domain *d = calloc(1, sizeof(*d));
    if (!d) {
        free(im);
        return PROCD_E_INTERNAL;
    }
    d->backend = procd_active_backend();
    d->impl = im;
    d->state = PROCD_STATE_ACTIVE;
    /* Never promote; lower the level if this domain's controls are no longer
     * usable from here (e.g. a read-only cgroup mount). */
    procd_capability was = (procd_capability)rec.level;
    int usable = !cgroup_root_ro() && invocation_controls_ok(im->path);
    d->runtime_level = usable ? was : (was < PROCD_CAP_BEST_EFFORT ? was : PROCD_CAP_BEST_EFFORT);
    procd_policy pol = PROCD_POLICY_INIT;
    d->policy = pol;
    *out_domain = d;
    *outcome = PROCD_RECOVERED;
    return PROCD_OK;
}

static const struct procd_backend BACKEND = {
    .name = "linux-cgroup2",
    .probe = lx_probe,
    .create = lx_create,
    .spawn = lx_spawn,
    .status = lx_status,
    .terminate = lx_terminate,
    .identity = lx_identity,
    .destroy = lx_destroy,
    .recover = lx_recover,
};
const struct procd_backend *procd_active_backend(void) {
    return &BACKEND;
}

#else
typedef int procd_backend_linux_translation_unit_nonempty;
#endif /* __linux__ */
