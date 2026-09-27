/*
 * Linux backend: cgroup v2 lifecycle domains.
 *
 * Design (independently re-established, not copied from any prototype):
 *   - A protected invocation-specific cgroup is created under procd's own
 *     cgroup. Its directory and cgroup.procs are root-owned.
 *   - The workload is admitted to the cgroup BEFORE it executes, then dropped
 *     to an unprivileged uid with no_new_privs. Because every cgroup.procs
 *     outside the invocation cgroup is root-owned and the workload is not root,
 *     the workload cannot migrate itself or any descendant out of the domain
 *     (writing another cgroup's cgroup.procs is denied). It also cannot create
 *     sub-cgroups (the invocation directory is not delegated to it).
 *   - Termination freezes then issues cgroup.kill against the AUTHORITY (the
 *     cgroup), not a PID list, and waits for cgroup.events populated==0 as
 *     authoritative proof of emptiness.
 *   - Durable identity = a random nonce naming a root-owned record in
 *     PROCD_STATE_DIR, written at create() and holding the authoritative
 *     (boot_id, cgroup-namespace view, cgroup path, cgroup inode, established
 *     level). The identity token is only a reference: recovery takes every
 *     authority-bearing field from the protected record, requires the token to
 *     match it exactly, and requires the path to be a procd cgroup on the
 *     verified cgroup2 mount. Editing a token can therefore never redirect a
 *     kill; anything that cannot be verified is UNRESOLVED, never guessed.
 *
 * ENFORCED conditions. discover() reports cheap host/mechanism POTENTIAL and is
 * a preflight only; create() independently establishes the invocation-specific
 * boundary and fails closed (REQUIRE_ENFORCED) or honestly downgrades
 * (ALLOW_BEST_EFFORT) if any of these does not actually hold. ENFORCED is never
 * inferred from euid==0 + a cgroup2 mount + cgroup.kill alone:
 *   - /sys/fs/cgroup is a cgroup2 mount and is NOT read-only (B3);
 *   - the kernel exposes cgroup.kill (>= 5.14);
 *   - euid == 0 AND this process actually holds the effective capabilities
 *     (CAP_SETUID/CAP_SETGID/CAP_SETPCAP) needed to drop the workload's identity
 *     -- a container root without them cannot, so it is not ENFORCED;
 *   - procd's OWN cgroup-v2 path is read from the "0::" line of /proc/self/cgroup
 *     (never a v1 controller line on a hybrid host, which would place the domain
 *     outside procd's cgroup and make the ancestor check meaningless -- I-1), and
 *     the invocation cgroup is created as a child of it;
 *   - the invocation cgroup actually exposes writable cgroup.kill / cgroup.procs
 *     and a readable cgroup.events populated flag where they are used (B3);
 *   - the workload identity is exactly representable and is not uid 0 / gid 0 (B1);
 *   - no ancestor cgroup (its directory or cgroup.procs) is reachable by the
 *     workload identity, so it cannot create a sibling cgroup or migrate a
 *     process up and out of the domain (B1);
 *   - the protected recovery record store is usable (safe recovery is part of
 *     the ENFORCED claim);
 * and at spawn time (revalidate prerequisites; fail the launch and run no
 * workload otherwise):
 *   - for an ENFORCED domain the controls and the ancestor-safety relationship
 *     are re-checked, so a domain that became unsafe after create() does not
 *     launch (I-4);
 *   - every inherited descriptor except stdio and procd's own O_CLOEXEC
 *     exec-status pipe is closed before exec, so the workload cannot act through
 *     a privileged descriptor the caller left open (B2);
 *   - the child deliberately establishes AND verifies every credential
 *     transition -- no_new_privs, capability-bounding-set drop, ambient clear,
 *     KEEPCAPS off, securebits locked, setgroups(0), setresgid, setresuid -- and
 *     reads back uid/gid (real+effective+saved), supplementary groups and the
 *     permitted/effective capability sets, reporting any failure to the parent so
 *     spawn cannot report success when the boundary was not established (B1, I-5).
 *
 * Honest reporting: the emptiness proof, the authoritative-population flag and
 * the crash/recovery behavior are tied to the level actually established, not to
 * the mere presence of a cgroup2 mount, so a downgraded (BEST_EFFORT) invocation
 * never claims proven owned-emptiness or durable reacquisition (B-1).
 *
 * ENFORCED does NOT claim protection against same-user execution brokers that a
 * shared drop identity might reach; it establishes cgroup-lifecycle authority,
 * so a dedicated unprivileged identity with no delegated cgroup authority is the
 * intended configuration (validated: no ancestor is reachable by the identity).
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
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/securebits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
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

#define CG_ROOT "/sys/fs/cgroup"

/* Root-owned directory of durable domain records. Only root can create or
 * modify records, so a record is protected evidence that procd established the
 * exact domain it describes. Not configurable at runtime: a caller-supplied
 * location would itself be editable metadata able to redirect authority. */
#ifndef PROCD_STATE_DIR
#define PROCD_STATE_DIR "/var/lib/procd"
#endif

#define NONCE_HEX 32
#define LEAF_HEX 16

typedef struct {
    char path[512];         /* absolute path of invocation cgroup */
    char rel[384];          /* path relative to cgroup mount, for /proc/<pid>/cgroup compare */
    unsigned long long ino; /* cgroup id (inode), generation-safe within a boot */
    char boot_id[64];
    char nonce[NONCE_HEX + 1];     /* names the protected durable record */
    unsigned long long cgns_ino;   /* cgroup namespace the path is relative to */
    unsigned long long cgroot_ino; /* cgroup at the CG_ROOT mount (view identity) */
    int level;                     /* level established at create(), as recorded */
    uid_t resolved_uid;            /* validated workload uid used at spawn (B1) */
    gid_t resolved_gid;            /* validated workload gid used at spawn (B1) */
    int spawn_allowed;             /* recovered handles without policy cannot spawn */
    int removed;                   /* directory has actually been rmdir'd */
    int proven_empty;              /* we have observed populated==0 at least once */
    pid_t leaders[64];             /* direct children procd forked (for reaping) */
    int nleaders;
    char detail[256]; /* per-domain termination detail (not shared) */
} linux_impl;

/* Authority-bearing fields shared by the durable record and the identity token.
 * uid/gid carry the security-relevant spawn policy so recovery can restore it. */
typedef struct {
    char nonce[NONCE_HEX + 1];
    char boot[64];
    unsigned long long cgns_ino;
    unsigned long long cgroot_ino;
    unsigned long long ino;
    int level;
    long uid; /* -1 when the record predates policy capture */
    long gid;
    char path[512];
} lx_record;

/* reap any of procd's own direct children that have already exited (no hang) */
static void reap_leaders(linux_impl *im, int blocking) {
    for (int i = 0; i < im->nleaders; i++) {
        if (im->leaders[i] <= 0) continue;
        pid_t r = waitpid(im->leaders[i], NULL, blocking ? 0 : WNOHANG);
        if (r == im->leaders[i] || (r < 0 && errno == ECHILD)) im->leaders[i] = 0;
    }
}
static void track_leader(linux_impl *im, pid_t pid) {
    reap_leaders(im, 0); /* recycle slots from exited leaders first */
    for (int i = 0; i < im->nleaders; i++)
        if (im->leaders[i] == 0) {
            im->leaders[i] = pid;
            return;
        }
    if (im->nleaders < (int)(sizeof im->leaders / sizeof im->leaders[0]))
        im->leaders[im->nleaders++] = pid;
    /* If full (>64 concurrent leaders in one domain), cgroup.kill still reaps
     * the processes; a few zombies may persist until release, bounded. */
}

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
 * cgroup (I-1). The whole file is read and required to be complete: a truncated
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
    /* Record v3 carries the security-relevant spawn policy (uid/gid) so a
     * recovered domain restores exactly what was established, not a default. */
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
    r->uid = r->gid = -1; /* token does not carry policy; it comes from the record */
    return valid_record_fields(r) ? 0 : -1;
}
/* 0 ok; -1 absent (ENOENT); -2 present but unreadable/untrusted/malformed.
 * Accepts v3 (with uid/gid policy) and legacy v2 (uid/gid left as -1). */
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
        r->uid = r->gid = -1; /* legacy: no policy captured */
    } else {
        return -2;
    }
    if (!parse_u64(cgns, &r->cgns_ino) || !parse_u64(cgroot, &r->cgroot_ino) ||
        !parse_u64(ino, &r->ino) || !valid_record_fields(r) || strcmp(r->nonce, nonce) != 0)
        return -2;
    return 0;
}

/* -------- B1/B2/B3 authority + privilege establishment -------- */

/* B3: a read-only cgroup mount cannot host a controllable protected hierarchy. */
static int cgroup_root_ro(void) {
    struct statvfs v;
    if (statvfs(CG_ROOT, &v) != 0) return 1; /* cannot tell -> treat as unusable */
    return (v.f_flag & ST_RDONLY) ? 1 : 0;
}

/* B3: the created invocation cgroup actually exposes the controls we use. Note
 * access() does not see mount read-only-ness, so this complements cgroup_root_ro
 * and the mkdir/EROFS check rather than replacing them. */
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

/* B1: uid/gid must round-trip exactly through the platform type (no narrowing). */
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

/* 1 if `path` is writable by identity (u,g) via its owner/group/other bits;
 * -1 if it cannot be stat'd (treated as unsafe by the caller). */
static int writable_by(const char *path, uid_t u, gid_t g) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (st.st_mode & S_IWOTH) return 1;
    if (st.st_uid == u && (st.st_mode & S_IWUSR)) return 1;
    if (st.st_gid == g && (st.st_mode & S_IWGRP)) return 1;
    return 0;
}

/* B1: no ancestor cgroup (its directory, allowing sub-cgroup creation, or its
 * cgroup.procs, allowing migration upward) may be reachable by the workload
 * identity. Otherwise owned execution could leave the invocation domain. */
static int hierarchy_safe_for(const char *invocation_path, uid_t u, gid_t g, char *why, size_t wn) {
    char p[512];
    snprintf(p, sizeof p, "%s", invocation_path);
    char *sl = strrchr(p, '/');
    if (!sl || sl == p) {
        snprintf(why, wn, "no parent cgroup");
        return 0;
    }
    *sl = 0; /* parent of the invocation cgroup */
    size_t rl = strlen(CG_ROOT);
    for (;;) {
        int dw = writable_by(p, u, g);
        char procs[600];
        join(procs, sizeof procs, p, "cgroup.procs");
        int pw = writable_by(procs, u, g);
        if (dw != 0 || pw != 0) {
            snprintf(why, wn, "ancestor %s reachable by workload identity (dir=%d procs=%d)", p, dw,
                     pw);
            return 0;
        }
        if (strlen(p) <= rl) break; /* checked up to and including CG_ROOT */
        char *s = strrchr(p, '/');
        if (!s || (size_t)(s - p) < rl) break;
        *s = 0;
    }
    return 1;
}

static int cap_last(void) {
    char b[32];
    if (read_file("/proc/sys/kernel/cap_last_cap", b, sizeof b) > 0) {
        int v = atoi(b);
        if (v >= 0 && v < 256) return v;
    }
    return 40; /* conservative fallback */
}

/* Can THIS process actually perform the workload privilege drop it will require
 * at spawn (set*gid/set*uid + capability/securebits locking)? euid 0 is NOT
 * sufficient: a container root can run with a reduced bounding/effective set and
 * be unable to drop deliberately. CAP_SETUID(7)/CAP_SETGID(6)/CAP_SETPCAP(8) all
 * live in the first 32-bit capability word. Used so an ENFORCED claim is never
 * inferred from euid==0 alone. */
static int have_effective_caps_for_drop(void) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset(&hdr, 0, sizeof hdr);
    memset(data, 0, sizeof data);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) != 0) return 0;
    unsigned needed = (1u << CAP_SETUID) | (1u << CAP_SETGID) | (1u << CAP_SETPCAP);
    return (data[0].effective & needed) == needed;
}

/* B2: close every inherited descriptor except stdio and `keep` (the O_CLOEXEC
 * exec-status pipe). Runs in the post-fork/pre-exec child. */
static void close_inherited(int keep) {
#ifdef __NR_close_range
    int ok = 1;
    if (keep > 3 && syscall(__NR_close_range, 3u, (unsigned)(keep - 1), 0u) != 0) ok = 0;
    if (syscall(__NR_close_range, (unsigned)(keep + 1), ~0u, 0u) != 0) ok = 0;
    if (ok) return;
#endif
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *e;
        while ((e = readdir(d))) {
            int fd = atoi(e->d_name);
            if (fd > 2 && fd != keep && fd != dfd) close(fd);
        }
        closedir(d);
        return;
    }
    long hi = sysconf(_SC_OPEN_MAX);
    if (hi < 3 || hi > 1048576) hi = 1048576;
    for (long fd = 3; fd < hi; fd++)
        if (fd != (long)keep) close((int)fd);
}

/* B1: establish the full privilege boundary in the child before any workload
 * code, deliberately and step by step -- setuid() alone is NOT assumed to be
 * sufficient. Every required transition is applied AND then read back; the
 * function returns 0 only if every one is confirmed to have taken effect, so a
 * silent failure of any step makes spawn() fail closed. Runs post-fork/pre-exec
 * using async-signal-safe syscalls only. */
static int child_drop_priv(uid_t u, gid_t g) {
    /* 1. no_new_privs: no later execve (e.g. of a setuid binary) can regain
     *    privileges. Set, then confirm. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return -1;

    /* 2. Empty the capability bounding set so no capability can ever be acquired. */
    int last = cap_last();
    for (int c = 0; c <= last; c++)
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) != 0 && errno != EINVAL) return -1;

    /* 3. KEEPCAPS off so leaving euid 0 clears permitted/effective caps; clear
     *    any ambient capabilities that would otherwise survive the uid change. */
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0) return -1;
#ifdef PR_CAP_AMBIENT
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) return -1;
#endif

        /* 4. Lock the credential regime with securebits while we still hold
         *    CAP_SETPCAP (before the uid change). We deliberately do NOT set
         *    SECBIT_NO_SETUID_FIXUP: the capability clearing on the uid change in
         *    step 6 is exactly the behavior we rely on. */
#ifdef PR_SET_SECUREBITS
    {
        unsigned long want = SECBIT_KEEP_CAPS_LOCKED;
#if defined(SECBIT_NO_CAP_AMBIENT_RAISE) && defined(SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)
        want |= SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
#endif
        if (u != 0) want |= SECBIT_NOROOT | SECBIT_NOROOT_LOCKED; /* dropping off root */
        if (prctl(PR_SET_SECUREBITS, want, 0, 0, 0) != 0) return -1;
    }
#endif

    /* 5. Drop supplementary-group authority. */
    if (setgroups(0, NULL) != 0) return -1;

    /* 6. Set gid then uid -- real, effective AND saved -- so no set*id back to a
     *    privileged id is possible. gid before uid, because after the uid change
     *    we may no longer have the privilege to change gids. */
    if (g != 0 && setresgid(g, g, g) != 0) return -1;
    if (u != 0 && setresuid(u, u, u) != 0) return -1;

    /* 7. Verify EVERY transition actually took effect. */
    if (g != 0) {
        gid_t rg = 0, eg = 0, sg = 0;
        if (getresgid(&rg, &eg, &sg) != 0 || rg != g || eg != g || sg != g) return -1;
    }
    if (u != 0) {
        uid_t ru = 0, eu = 0, su = 0;
        if (getresuid(&ru, &eu, &su) != 0 || ru != u || eu != u || su != u) return -1;
    }
    int ng = getgroups(0, NULL);
    if (ng > 0) {
        if (ng > 1) return -1;
        gid_t only = 0;
        if (getgroups(1, &only) != 1 || only != g) return -1;
    }
    /* When we dropped off root, no capability may remain in the permitted or
     * effective set: that is the whole point of the boundary. */
    if (u != 0) {
        struct __user_cap_header_struct hdr;
        struct __user_cap_data_struct data[2];
        memset(&hdr, 0, sizeof hdr);
        memset(data, 0, sizeof data);
        hdr.version = _LINUX_CAPABILITY_VERSION_3;
        hdr.pid = 0;
        if (syscall(SYS_capget, &hdr, data) != 0) return -1;
        if ((data[0].effective | data[1].effective | data[0].permitted | data[1].permitted) != 0)
            return -1;
    }
    /* no_new_privs must still be set going into execve. */
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return -1;
    return 0;
}

/* -------- prerequisite discovery -------- */
static int cgroup2_mounted(void) {
    struct statfs sf;
    if (statfs(CG_ROOT, &sf) != 0) return 0;
    return sf.f_type == CGROUP2_SUPER_MAGIC;
}
/* returns capability level achievable for termination; fills detail */
static procd_capability discover(char *detail, size_t dn) {
    if (!cgroup2_mounted()) {
        snprintf(detail, dn, "cgroup v2 not mounted at %s", CG_ROOT);
        return PROCD_CAP_UNSUPPORTED;
    }
    if (cgroup_root_ro()) {
        snprintf(detail, dn, "cgroup v2 mount at %s is read-only: cannot create/control cgroups",
                 CG_ROOT);
        return PROCD_CAP_BEST_EFFORT;
    }
    if (!file_exists(CG_ROOT, "cgroup.kill")) {
        snprintf(detail, dn, "cgroup.kill absent (needs kernel >= 5.14)");
        return PROCD_CAP_BEST_EFFORT;
    }
    if (geteuid() != 0) {
        snprintf(detail, dn,
                 "cgroup v2 + cgroup.kill present, but euid!=0: cannot establish "
                 "root-owned protected hierarchy + privilege drop");
        return PROCD_CAP_BEST_EFFORT;
    }
    if (!have_effective_caps_for_drop()) {
        snprintf(detail, dn,
                 "euid 0 but missing CAP_SETUID/CAP_SETGID/CAP_SETPCAP: cannot establish the "
                 "workload privilege drop, so ENFORCED is not inferred from euid 0 alone");
        return PROCD_CAP_BEST_EFFORT;
    }
    snprintf(detail, dn,
             "cgroup v2 + cgroup.kill + privilege drop: owned work cannot leave the domain via "
             "process topology or cgroup migration by the drop identity; ASSUMES a dedicated drop "
             "identity with no other execution authority (not verified here)");
    return PROCD_CAP_ENFORCED;
}

static void lx_probe(procd_capabilities *out) {
    static char detail[256];
    procd_capability lvl = discover(detail, sizeof detail);
    out->backend = "linux-cgroup2";
    out->process_tree_termination = lvl;
    out->pre_execution_containment = lvl; /* admit-before-exec */
    out->descendant_containment = lvl;
    out->topology_escape_resistance = lvl; /* migration denied by privilege boundary */
    /* Emptiness proof is a claim about OWNED work, not merely the tracked cgroup
     * object. cgroup.events proves the cgroup is empty, but that only proves no
     * owned work remains when the workload could not leave the cgroup -- i.e. at
     * ENFORCED. Below that, the cgroup-empty fact does not prove owned emptiness,
     * so the proof level equals the containment level (B-1). */
    out->domain_emptiness_proof = lvl;
    /* Safe recovery needs the root-protected record store: without it no
     * record can prove a domain existed, so recovery could only be UNRESOLVED. */
    out->safe_recovery = (cgroup2_mounted() && geteuid() == 0 && state_dir_ready(0) == 0)
                             ? PROCD_CAP_ENFORCED
                             : PROCD_CAP_UNSUPPORTED;
    /* The cgroup survives authority loss, but "durable REACQUISITION" is only
     * truthful when recovery can authoritatively re-identify it. Without the
     * protected record store the fate cannot be established after authority
     * loss, so report that honestly rather than claiming reacquisition. */
    out->crash_behavior = (out->safe_recovery == PROCD_CAP_ENFORCED)
                              ? PROCD_CRASH_DURABLE_REACQUISITION
                              : PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS;
    out->detail = detail;
}

/* -------- create -------- */
static procd_status lx_create(procd_domain *d) {
    char detail[256];
    procd_capability lvl = discover(detail, sizeof detail);

    if (d->policy.enforcement == PROCD_REQUIRE_ENFORCED && lvl != PROCD_CAP_ENFORCED)
        return PROCD_E_UNSUPPORTED_ENFORCEMENT; /* fail closed; nothing created */

    /* The Linux backend hosts domains in cgroup v2. Without a cgroup2 mount at
     * CG_ROOT there is no hierarchy to create a domain in: refuse rather than
     * fabricate a directory on whatever filesystem happens to be mounted there
     * (e.g. the tmpfs of a v1/hybrid host), which would masquerade as a domain
     * and then fail confusingly at spawn. This keeps an unusable environment from
     * yielding a bogus domain even under ALLOW_BEST_EFFORT (area 3). */
    if (!cgroup2_mounted()) return PROCD_E_PREREQUISITE;

    linux_impl *im = calloc(1, sizeof(*im));
    if (!im) return PROCD_E_INTERNAL;

    /* Create invocation cgroup under procd's own cgroup so the parent is not
     * writable by the (soon unprivileged) workload. The parent MUST be procd's
     * own cgroup-v2 path: on a hybrid host the first /proc/self/cgroup line is a
     * v1 controller whose path would place the domain elsewhere (I-1). */
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

    /* Build the relative path (as in /proc/<pid>/cgroup) and the absolute path
     * with explicit bounds checks. A truncated path would name some other
     * cgroup, so refuse instead. memcpy (not snprintf) keeps the bound provable
     * to the compiler as well as at runtime. */
    int is_root = strcmp(rel, "/") == 0;
    const char *pre = is_root ? "" : rel;
    size_t pl = strlen(pre), ll = strlen(leaf);
    size_t rl = strlen(CG_ROOT);
    if (pl + 1 + ll >= sizeof im->rel || rl + pl + 1 + ll >= sizeof im->path) {
        free(im);
        return PROCD_E_IO;
    }
    /* rel = pre + "/" + leaf */
    memcpy(im->rel, pre, pl);
    im->rel[pl] = '/';
    memcpy(im->rel + pl + 1, leaf, ll + 1);
    /* path = CG_ROOT + rel */
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

    /* B1: resolve + validate the workload identity before it is ever used. A
     * value that does not round-trip through uid_t/gid_t (e.g. 2^32) would
     * narrow to a different, possibly privileged, identity: reject it. */
    int64_t uv = (d->policy.drop_uid == -1) ? 65534 : d->policy.drop_uid;
    int64_t gv = (d->policy.drop_gid == -1) ? 65534 : d->policy.drop_gid;
    uid_t ru;
    gid_t rg;
    if (!uid_repr(uv, &ru) || !gid_repr(gv, &rg)) {
        rmdir(im->path);
        free(im);
        return PROCD_E_INVALID_ARGUMENT;
    }
    im->resolved_uid = ru;
    im->resolved_gid = rg;
    im->spawn_allowed = 1; /* freshly created domains carry their own policy */

    /* B1/B3: an ENFORCED claim is only valid if THIS invocation actually
     * establishes the boundary: the invocation cgroup exposes the controls we
     * use, the workload identity is a real unprivileged identity, and no
     * ancestor cgroup is reachable by that identity. Otherwise fail closed
     * under REQUIRE_ENFORCED, or honestly downgrade under ALLOW_BEST_EFFORT. */
    if (lvl == PROCD_CAP_ENFORCED) {
        char why[256] = "";
        int ok = invocation_controls_ok(im->path) && ru != 0 && rg != 0 &&
                 hierarchy_safe_for(im->path, ru, rg, why, sizeof why);
        if (!ok) {
            if (d->policy.enforcement == PROCD_REQUIRE_ENFORCED) {
                rmdir(im->path);
                free(im);
                return PROCD_E_UNSUPPORTED_ENFORCEMENT; /* nothing executed */
            }
            lvl = PROCD_CAP_BEST_EFFORT;
        }
    }

    /* Durable identity: only root can write the protected record. Without one
     * the domain is still usable but can never be recovered (UNRESOLVED). A
     * REQUIRE_ENFORCED domain must have it: safe recovery is part of the claim. */
    im->level = (int)lvl;
    if (geteuid() == 0) {
        lx_record rec;
        memset(&rec, 0, sizeof rec);
        snprintf(rec.nonce, sizeof rec.nonce, "%s", im->nonce);
        snprintf(rec.boot, sizeof rec.boot, "%s", im->boot_id);
        rec.cgns_ino = im->cgns_ino;
        rec.cgroot_ino = im->cgroot_ino;
        rec.ino = im->ino;
        rec.level = im->level;
        rec.uid = (long)im->resolved_uid; /* capture the spawn policy for recovery */
        rec.gid = (long)im->resolved_gid;
        snprintf(rec.path, sizeof rec.path, "%s", im->path);
        if (write_record(&rec) != 0 && d->policy.enforcement == PROCD_REQUIRE_ENFORCED) {
            rmdir(im->path);
            free(im);
            return PROCD_E_PREREQUISITE;
        }
    }

    d->impl = im;
    d->runtime_level = lvl;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

/* verify child landed in exactly our cgroup by reading its cgroup-v2 (0::) path.
 * Uses the same robust parser as create(), so on a hybrid host it compares the
 * unified path (not a v1 controller line) and refuses a truncated view. */
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

static procd_status lx_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    linux_impl *im = d->impl;
    if (!im->spawn_allowed) return PROCD_E_STATE; /* recovered w/o policy: cannot spawn safely */
    if (im->removed) return PROCD_E_STATE;
    reap_leaders(im, 0); /* opportunistically reap earlier workloads that exited */
    /* revalidate authority still exists */
    if (access(im->path, F_OK) != 0) return PROCD_E_STATE;

    /* Launch invariant: revalidate prerequisites. For an ENFORCED domain confirm
     * the controls termination/status depend on are still present AND that no
     * ancestor cgroup became reachable by the workload identity since create()
     * (I-4). If the domain is no longer safe, refuse and run nothing rather than
     * launch workload into it. */
    if (d->runtime_level == PROCD_CAP_ENFORCED) {
        char why[256];
        if (!invocation_controls_ok(im->path) ||
            !hierarchy_safe_for(im->path, im->resolved_uid, im->resolved_gid, why, sizeof why))
            return PROCD_E_STATE;
    }

    char cgprocs[600];
    join(cgprocs, sizeof cgprocs, im->path, "cgroup.procs");

    /* sync_admit: child->parent "admitted"; sync_go: parent->child "verified,
     * proceed"; sync_status: child->parent exec result (B1). */
    int sync_admit[2], sync_go[2], sync_status[2];
    if (pipe2(sync_admit, O_CLOEXEC) != 0) return PROCD_E_IO;
    if (pipe2(sync_go, O_CLOEXEC) != 0) {
        close(sync_admit[0]);
        close(sync_admit[1]);
        return PROCD_E_IO;
    }
    if (pipe2(sync_status, O_CLOEXEC) != 0) {
        close(sync_admit[0]);
        close(sync_admit[1]);
        close(sync_go[0]);
        close(sync_go[1]);
        return PROCD_E_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sync_admit[0]);
        close(sync_admit[1]);
        close(sync_go[0]);
        close(sync_go[1]);
        close(sync_status[0]);
        close(sync_status[1]);
        return PROCD_E_IO;
    }

    if (pid == 0) {
        /* ---- child: privileged, has NOT executed workload ----
         * Everything here runs post-fork/pre-exec and is kept to
         * async-signal-safe operations (raw syscalls + hand-rolled integer
         * formatting) so a multithreaded embedder's fork is safe; the residual
         * non-AS-safe calls (close_inherited's /proc fallback, execvp's PATH
         * search) are documented at the top of this file. */
        char me[24];
        as_pid(me, (long)getpid());
        int ok = (write_str(cgprocs, me) == 0);
        /* notify parent: 1=admitted, 0=failed */
        char b = ok ? 1 : 0;
        ssize_t wn = write(sync_admit[1], &b, 1);
        (void)wn;
        if (!ok) _exit(127);
        /* block until parent verifies containment and permits execution */
        char go = 0;
        if (read(sync_go[0], &go, 1) != 1 || go != 1) _exit(127);

        /* B2: drop every inherited descriptor (arbitrary caller fds, privileged
         * cgroup fds) except stdio and the O_CLOEXEC exec-status pipe. This does
         * NOT depend on the caller having set FD_CLOEXEC. The status pipe closes
         * on a successful execvp, signalling success by EOF. */
        close_inherited(sync_status[1]);

        /* B1: establish the full privilege boundary before any workload code.
         * TEST-ONLY negative control skips it so the workload stays root and CAN
         * migrate out of the domain (the harness must observe that escape). A
         * separate TEST-ONLY knob forces the transition to be reported as failed
         * so the failure-propagation path (below) can be exercised: the workload
         * must NOT execute and spawn() must fail. Both compile to 0 in production. */
        if (!procd_nc_weaken_containment()) {
            int drop_failed = procd_nc_fail_credentials()
                                  ? -1
                                  : child_drop_priv(im->resolved_uid, im->resolved_gid);
            if (drop_failed != 0) {
                char e = 'P';
                ssize_t x = write(sync_status[1], &e, 1);
                (void)x;
                _exit(126); /* required privilege transition failed; do not exec */
            }
        }
        execvp(argv[0], (char *const *)argv);
        {
            char e = 'X';
            ssize_t x = write(sync_status[1], &e, 1);
            (void)x;
        }
        _exit(127);
    }

    /* ---- parent (procd, root): enforce launch ordering ---- */
    close(sync_admit[1]);
    close(sync_go[0]);
    close(sync_status[1]); /* only the child may hold a writer, so EOF == exec ok */

    char b = 0;
    ssize_t rn = read(sync_admit[0], &b, 1);
    close(sync_admit[0]);
    if (rn != 1 || b != 1) {
        /* Admission failed; the child has exited or will on EOF. Do NOT write to
         * sync_go -- the child may already have closed its read end (SIGPIPE);
         * closing our end signals EOF to a child still blocked on it. */
        close(sync_go[1]);
        close(sync_status[0]);
        waitpid(pid, NULL, 0);
        return PROCD_E_IO; /* admission failed; nothing executed */
    }

    /* verify containment: child is in exactly our cgroup */
    if (!verify_membership(im, pid)) {
        /* Deny the go signal by closing our end: the child, still blocked on the
         * go read, sees EOF and exits WITHOUT execing, leaving the cgroup on its
         * own. Kill only this child, never the whole domain: a failed spawn must
         * not terminate workloads already running in the domain (I-2). */
        close(sync_go[1]);
        close(sync_status[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return PROCD_E_INTERNAL; /* containment unverified; workload never ran */
    }

    /* identity already captured at create(); permit execution */
    char go = 1;
    if (write(sync_go[1], &go, 1) != 1) {
        /* child is blocked on read(go); closing our end gives it EOF -> it exits
         * without execing. Kill only this child, not the domain (I-2). */
        close(sync_go[1]);
        close(sync_status[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return PROCD_E_IO;
    }
    close(sync_go[1]);

    /* B1: spawn succeeds only if the child established the boundary and exec'd.
     * A byte means the pre-exec privilege transition ('P') or exec ('X') failed;
     * EOF (read returns 0) means execvp succeeded and closed the O_CLOEXEC status
     * pipe. A read ERROR must NOT be treated as success: retry EINTR, and treat
     * anything other than a clean EOF as failure (I-5). */
    char sb = 0;
    ssize_t sn;
    do {
        sn = read(sync_status[0], &sb, 1);
    } while (sn < 0 && errno == EINTR);
    close(sync_status[0]);
    if (sn != 0) {
        /* The child did not exec (a failure byte, or we could not confirm exec).
         * Kill only this child; earlier workloads in the domain are untouched. */
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return (sn > 0 && sb == 'P') ? PROCD_E_PERMISSION : PROCD_E_IO;
    }

    track_leader(im, pid);       /* procd reaps this direct child (terminate/destroy) */
    if (out_pid) *out_pid = pid; /* diagnostic metadata only */
    d->state = PROCD_STATE_ACTIVE;
    return PROCD_OK;
}

static procd_status lx_status(procd_domain *d, procd_domain_status *out) {
    linux_impl *im = d->impl;
    out->process_tree_termination = d->runtime_level;
    /* The cgroup.events populated flag is an authoritative OS mechanism, but it
     * is only authoritative about OWNED WORK when the workload cannot leave the
     * cgroup -- i.e. at ENFORCED. Below that the flag is real but says nothing
     * about work the workload may have placed outside the cgroup, so we do not
     * mark the population authoritative (B-1). */
    int authoritative = (d->runtime_level == PROCD_CAP_ENFORCED);
    if (im->removed) {
        out->population = PROCD_POP_EMPTY;
        out->population_is_authoritative = authoritative;
        /* Only ENFORCED may report EMPTY (owned work proven gone). A downgraded
         * domain whose cgroup object is gone stays UNRESOLVED as terminate set. */
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
    char *detail = im->detail; /* per-domain: concurrent domains never share this */
    size_t dcap = sizeof im->detail;
    out->detail = detail;

    if (im->removed || access(im->path, F_OK) != 0) {
        /* Idempotent only if THIS handle already killed the domain and proved
         * it empty. A path that vanished otherwise (e.g. another handle
         * reclaimed it) was neither killed nor observed empty by us. */
        int p = im->proven_empty;
        out->admission_closed = p;
        out->authority_directed = p;
        out->emptiness_proven = p;
        out->enforced = p && d->runtime_level == PROCD_CAP_ENFORCED;
        out->final_state = p ? PROCD_STATE_EMPTY : PROCD_STATE_UNRESOLVED;
        d->state = out->final_state;
        reap_leaders(im, 0);
        snprintf(detail, dcap, "%s",
                 p ? "domain authority already released; emptiness previously proven"
                   : "domain path vanished without this handle proving emptiness");
        return PROCD_OK;
    }

    d->state = PROCD_STATE_TERMINATING;

    /* close admission first: freeze halts execution/forks, then kill authority */
    char fp[600];
    join(fp, sizeof fp, im->path, "cgroup.freeze");
    write_str(fp, "1"); /* best-effort; not all configs expose freeze */
    out->admission_closed = 1;

    char kp[600];
    join(kp, sizeof kp, im->path, "cgroup.kill");
    int killed = (write_str(kp, "1") == 0);
    out->authority_directed = killed;
    if (!killed) {
        snprintf(detail, dcap, "cgroup.kill write failed: %s", strerror(errno));
        out->final_state = PROCD_STATE_UNRESOLVED;
        d->state = PROCD_STATE_UNRESOLVED;
        return PROCD_E_IO;
    }

    if (timeout_ms <= 0) timeout_ms = 5000;
    long long deadline = now_ms() + timeout_ms;
    int pop = 1;
    while (now_ms() < deadline) {
        pop = cg_populated(im->path);
        if (pop == 0) break;
        struct timespec ts = {0, 5 * 1000 * 1000}; /* 5ms */
        nanosleep(&ts, NULL);
    }

    if (pop == 0) {
        reap_leaders(im, 1); /* our direct children are dead now; reap them */
        int gone = (rmdir(im->path) == 0) || (access(im->path, F_OK) != 0);
        im->removed = gone;
        if (d->runtime_level == PROCD_CAP_ENFORCED) {
            /* ENFORCED: owned work cannot leave the cgroup, so cgroup.events
             * populated==0 proves NO owned executable work remains. */
            im->proven_empty = 1;
            out->emptiness_proven = 1;
            out->enforced = 1;
            out->final_state = PROCD_STATE_EMPTY;
            d->state = PROCD_STATE_EMPTY;
            snprintf(detail, dcap,
                     "cgroup.kill issued against authority; cgroup.events populated==0 "
                     "(authoritative); cgroup object %s",
                     gone ? "removed" : "empty but NOT removed (rmdir failed)");
        } else {
            /* Below ENFORCED: the kernel object drained and was killed, but the
             * workload could have placed owned work outside the cgroup, so owned
             * emptiness is NOT proven. Report the cgroup-empty fact honestly and
             * leave the lifecycle UNRESOLVED rather than claim EMPTY (B-1). */
            im->proven_empty = 0;
            out->emptiness_proven = 0;
            out->enforced = 0;
            out->final_state = PROCD_STATE_UNRESOLVED;
            d->state = PROCD_STATE_UNRESOLVED;
            snprintf(
                detail, dcap,
                "best-effort: cgroup.kill issued and cgroup.events populated==0, but owned-work "
                "emptiness is not proven below ENFORCED; cgroup object %s",
                gone ? "removed" : "empty but NOT removed (rmdir failed)");
        }
        return PROCD_OK;
    }

    out->emptiness_proven = 0;
    out->enforced = 0;
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    snprintf(detail, dcap, "timed out waiting for populated==0");
    return PROCD_E_TIMEOUT;
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
        /* reap any of procd's own direct children that have exited, so releasing
         * a domain never leaves procd-owned zombies behind */
        reap_leaders(im, 0);
        /* release authority handle; do NOT kill (crash behavior is durable
         * reacquisition). Only reclaim the directory if already empty. */
        if (!im->removed && access(im->path, F_OK) == 0) {
            if (cg_populated(im->path) == 0) {
                if (rmdir(im->path) == 0) im->removed = 1;
            }
        }
        free(im);
    }
    d->impl = NULL;
}

static procd_status lx_recover(const char *identity, procd_recovery_outcome *outcome,
                               procd_domain **out_domain) {
    /*
     * Every conclusion is drawn from the root-protected record, never from the
     * token alone. The token must be well-formed and match the record exactly;
     * otherwise its claims are unverifiable and the outcome stays UNRESOLVED
     * (preset by the dispatcher). CONFIRMED_DESTROYED is only returned when the
     * record proves the exact domain existed AND native semantics make its
     * destruction unavoidable.
     */
    lx_record id, rec;
    memset(&id, 0, sizeof id);
    memset(&rec, 0, sizeof rec);
    if (parse_identity(identity, &id) != 0) return PROCD_E_INVALID_ARGUMENT;

    /* Only root can read the protected store or hold cgroup authority. */
    if (geteuid() != 0) return PROCD_E_PERMISSION;
    if (state_dir_ready(0) != 0) return PROCD_E_PREREQUISITE;

    int rr = read_record(id.nonce, &rec);
    if (rr == -1) return PROCD_OK; /* no protected evidence the domain ever existed */
    if (rr != 0) return PROCD_E_IO;
    if (strcmp(id.boot, rec.boot) != 0 || id.cgns_ino != rec.cgns_ino ||
        id.cgroot_ino != rec.cgroot_ino || id.ino != rec.ino || id.level != rec.level ||
        strcmp(id.path, rec.path) != 0)
        return PROCD_OK; /* token disagrees with the record: tampered, never redirect */

    char cur_boot[64];
    if (read_boot_id(cur_boot, sizeof cur_boot) != 0) return PROCD_E_IO;
    if (strcmp(cur_boot, rec.boot) != 0) {
        /* The record proves the domain existed in another boot; cgroups do not
         * survive a reboot. */
        *outcome = PROCD_CONFIRMED_DESTROYED;
        return PROCD_OK;
    }

    /* Same boot: the path is only meaningful in the view it was recorded in. */
    if (!cgroup2_mounted()) return PROCD_E_PREREQUISITE;
    unsigned long long cgns = 0, cgroot = 0;
    if (current_view(&cgns, &cgroot) != 0) return PROCD_E_IO;
    if (cgns != rec.cgns_ino || cgroot != rec.cgroot_ino) return PROCD_OK;

    int fd = open(rec.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            /* cgroup v2 forbids renaming a cgroup and rmdir requires it to be
             * empty, so in the recorded view a vanished path means the exact
             * domain was destroyed. */
            *outcome = PROCD_CONFIRMED_DESTROYED;
            return PROCD_OK;
        }
        return PROCD_E_IO;
    }
    struct statfs sf;
    struct stat st;
    int ok = fstatfs(fd, &sf) == 0 && sf.f_type == CGROUP2_SUPER_MAGIC && fstat(fd, &st) == 0;
    close(fd);
    if (!ok) return PROCD_E_IO;
    if ((unsigned long long)st.st_ino != rec.ino) {
        /* a different cgroup generation now holds the path; ours was removed */
        *outcome = PROCD_CONFIRMED_DESTROYED;
        return PROCD_OK;
    }

    /* exact generation still present: safe to reacquire */
    linux_impl *im = calloc(1, sizeof(*im));
    if (!im) return PROCD_E_INTERNAL;
    /* rec.path is validated (is_domain_path, < sizeof path). Copy with explicit
     * bounds so the relative part cannot silently truncate. */
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
    /* Restore the security-relevant spawn policy that was actually established
     * for this domain (record v3). A legacy record without it (uid<0) cannot be
     * spawned into safely: recovery still reacquires for status/terminate, but
     * spawn is refused rather than substituting a default identity. For an
     * ENFORCED domain the restored identity must remain valid (non-zero,
     * representable), else the recovered handle is not spawn-capable. */
    if (rec.uid >= 0 && rec.gid >= 0) {
        uid_t ru;
        gid_t rg;
        int repr = uid_repr(rec.uid, &ru) && gid_repr(rec.gid, &rg);
        int safe_for_level = repr && (rec.level != PROCD_CAP_ENFORCED || (ru != 0 && rg != 0));
        if (repr && safe_for_level) {
            im->resolved_uid = ru;
            im->resolved_gid = rg;
            im->spawn_allowed = 1;
        } else {
            im->spawn_allowed = 0; /* recorded policy is not safe to reuse */
        }
    } else {
        im->spawn_allowed = 0; /* legacy record without captured policy */
    }
    procd_domain *d = calloc(1, sizeof(*d));
    if (!d) {
        free(im);
        return PROCD_E_INTERNAL;
    }
    d->backend = procd_active_backend();
    d->impl = im;
    d->state = PROCD_STATE_ACTIVE;
    {
        /* Never promote: the level is what was established for THIS domain,
         * lowered further if the host can no longer support it. */
        char dbuf[256];
        procd_capability now = discover(dbuf, sizeof dbuf);
        procd_capability was = (procd_capability)rec.level;
        d->runtime_level = (now < was) ? now : was;
    }
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
