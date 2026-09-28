#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Recovery regression test (Linux, needs the enforced prerequisites).
 *
 * Each case is a concrete stale/corrupted-token or wrong-target case for durable
 * recovery. The independent
 * oracle is the test's own child processes (reaped with waitpid, so a zombie is
 * never mistaken for a survivor) and cgroups the test itself created:
 *
 *   - forged tokens aimed at an unrelated cgroup (old and current format) must
 *     not be RECOVERED, and the unrelated process must survive;
 *   - forged tokens aimed at an ordinary directory must not be RECOVERED or
 *     CONFIRMED_DESTROYED;
 *   - a live domain's token with an edited boot id, path, inode or level must
 *     not become CONFIRMED_DESTROYED or RECOVERED (it disagrees with the
 *     protected record);
 *   - a domain created by an unprivileged caller (no protected record) is never
 *     recovered;
 *   - a missing cgroup is CONFIRMED_DESTROYED only for a domain recorded at
 *     ENFORCED; a record below ENFORCED stays UNRESOLVED (its cgroup being gone
 *     does not prove the task's processes are gone);
 *   - the genuine token recovers the exact domain at its established level, the
 *     recovered handle can spawn into and terminate it, and afterwards the
 *     genuine token is CONFIRMED_DESTROYED.
 *
 * Exits 77 when the enforced prerequisites are unavailable.
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

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
static void write_file(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, s, strlen(s));
    (void)w;
    close(fd);
}
static unsigned long long ino_of(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (unsigned long long)st.st_ino : 0;
}
/* absolute path of this process's cgroup-v2 cgroup (the "0::" line) */
static void own_cgroup(char *out, size_t n) {
    char b[4096] = {0};
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (r < 0) r = 0;
    b[r] = 0;
    const char *rel = "/";
    for (char *line = strtok(b, "\n"); line; line = strtok(NULL, "\n"))
        if (strncmp(line, "0::", 3) == 0) rel = line + 3;
    snprintf(out, n, "/sys/fs/cgroup%s", strcmp(rel, "/") == 0 ? "" : rel);
}
/* bounded sleeper child of this test, placed into cgroup cg */
static pid_t sleeper_in(const char *cg) {
    pid_t p = fork();
    if (p == 0) {
        execlp("sleep", "sleep", "30", (char *)NULL);
        _exit(127);
    }
    char procs[700], s[16];
    snprintf(procs, sizeof procs, "%s/cgroup.procs", cg);
    snprintf(s, sizeof s, "%d", (int)p);
    write_str(procs, s);
    return p;
}
/* independent liveness oracle: our own child, not reaped yet */
static int alive(pid_t p) {
    return waitpid(p, NULL, WNOHANG) == 0;
}
static int killed_by_signal(pid_t p) {
    int st = 0;
    for (int i = 0; i < 200; i++) {
        pid_t w = waitpid(p, &st, WNOHANG);
        if (w == p) return WIFSIGNALED(st);
        nap(10);
    }
    return 0;
}
/* "did not survive": the child is gone. Accepts ECHILD, because procd now owns
 * reaping of the leaders IT spawned (cleanup item 3) - a leader that procd
 * already reaped is, by construction, one it killed via cgroup.kill. */
static int gone(pid_t p) {
    for (int i = 0; i < 200; i++) {
        int st = 0;
        pid_t w = waitpid(p, &st, WNOHANG);
        if (w == p || w < 0) return 1; /* reaped now, or already reaped by procd */
        nap(10);
    }
    return kill(p, 0) != 0;
}

/* Field positions of the token the library emitted. The test edits whatever
 * format the library produces, so it is meaningful against older formats too:
 *   v1: linux-cgroup2:1:<boot>:<ino>:<path>
 *   v2: linux-cgroup2:2:<nonce>:<boot>:<cgns>:<cgroot>:<ino>:<level>:<path> */
static int F_BOOT, F_INO, F_LEVEL, F_PATH;
static void set_format(const char *id) {
    if (strncmp(id, "linux-cgroup2:1:", 16) == 0) {
        F_BOOT = 2, F_INO = 3, F_LEVEL = -1, F_PATH = 4;
    } else {
        F_BOOT = 3, F_INO = 6, F_LEVEL = 7, F_PATH = 8;
    }
}
/* replace field f of id with v into out */
static void with_field(const char *id, int f, const char *v, char *out, size_t n) {
    const char *s = id;
    for (int i = 0; i < f; i++)
        s = strchr(s, ':') + 1;
    const char *e = (f == F_PATH) ? s + strlen(s) : strchr(s, ':');
    snprintf(out, n, "%.*s%s%s", (int)(s - id), id, v, e);
}
static void get_field(const char *id, int f, char *out, size_t n) {
    const char *s = id;
    for (int i = 0; i < f; i++)
        s = strchr(s, ':') + 1;
    const char *e = (f == F_PATH) ? s + strlen(s) : strchr(s, ':');
    snprintf(out, n, "%.*s", (int)(e - s), s);
}

static procd_recovery_outcome try_recover(const char *id, const char *what) {
    procd_recovery_outcome o = PROCD_RECOVERED;
    procd_domain *rd = NULL;
    procd_status rc = procd_recover(id, &o, &rd);
    printf("   recover(%s) -> %s/%s\n", what, procd_status_name(rc), procd_recovery_name(o));
    if (rd) {
        procd_domain_status st;
        procd_domain_status_get(rd, &st);
        printf("   recovered level %s\n", procd_capability_name(st.process_tree_termination));
        procd_domain_release(rd); /* release only; never terminate a forged target */
    }
    return o;
}

/* A domain created by a non-root user in a subtree delegated to it (the
 * directory and its cgroup.procs chowned, as systemd delegation does). Such a
 * caller cannot write the root-owned record store, so the domain has no record. */
static int unprivileged_identity(const char *parent_cg, char *id, size_t n, char *leaf_dir,
                                 size_t ln) {
    char deleg[600], f[700];
    snprintf(deleg, sizeof deleg, "%s/procd_rt_deleg", parent_cg);
    mkdir(deleg, 0755);
    if (chown(deleg, 65533, 65533) != 0) return -1;
    snprintf(f, sizeof f, "%s/cgroup.procs", deleg);
    if (chown(f, 65533, 65533) != 0) return -1;
    int pp[2];
    if (pipe(pp) != 0) return -1;
    pid_t c = fork();
    if (c == 0) {
        close(pp[0]);
        char s[16];
        snprintf(s, sizeof s, "%d", (int)getpid());
        if (write_str(f, s) != 0 || setgroups(0, NULL) != 0 || setgid(65533) != 0 ||
            setuid(65533) != 0)
            _exit(1);
        procd_policy pol = PROCD_POLICY_INIT;
        procd_domain *d = NULL;
        char buf[PROCD_IDENTITY_MAX] = {0};
        if (procd_create_domain(&pol, &d) != PROCD_OK) _exit(2);
        procd_domain_identity(d, buf, sizeof buf);
        ssize_t w = write(pp[1], buf, strlen(buf));
        (void)w;
        _exit(0); /* keep the cgroup; do not release */
    }
    close(pp[1]);
    ssize_t r = read(pp[0], id, n - 1);
    close(pp[0]);
    int st = 0;
    waitpid(c, &st, 0);
    if (r <= 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    id[r] = 0;
    snprintf(leaf_dir, ln, "%s", deleg);
    return 0;
}

/* Rewrite the recorded level of the domain named by id (test-only, as root). */
static int set_record_level(const char *id, char level) {
    char nonce[40], p[256], b[1024];
    snprintf(nonce, sizeof nonce, "%.32s", id + strlen("linux-cgroup2:2:"));
    snprintf(p, sizeof p, "/var/lib/procd/%s.rec", nonce);
    int fd = open(p, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, b, sizeof b - 1);
    char *lv = r > 0 ? (b[r] = 0, strstr(b, "\nlevel=")) : NULL;
    int ok = lv && pwrite(fd, &level, 1, (lv - b) + 7) == 1;
    close(fd);
    return ok ? 0 : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED ||
        c.safe_recovery != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced recovery prerequisites unavailable (%s, euid=%d)\n",
               strict ? "FAIL" : "SKIP", c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }
    char cg[512];
    own_cgroup(cg, sizeof cg);

    /* ---- a live enforced domain with a bounded member ---- */
    procd_policy pol = PROCD_POLICY_INIT;
    procd_domain *d = NULL;
    if (procd_create_domain(&pol, &d) != PROCD_OK) {
        printf("FAIL: enforced create\n");
        return 1;
    }
    const char *av[] = {"sleep", "30", NULL};
    int64_t member = -1;
    CHECK(procd_domain_spawn(d, av, &member) == PROCD_OK, "spawn member into live domain");
    char id[PROCD_IDENTITY_MAX];
    procd_domain_identity(d, id, sizeof id);
    printf("   identity %s\n", id);
    set_format(id);
    char path[512], boot[64], ino[32];
    get_field(id, F_PATH, path, sizeof path);
    get_field(id, F_BOOT, boot, sizeof boot);
    get_field(id, F_INO, ino, sizeof ino);

    /* ---- B4: unrelated cgroup that merely looks like a procd domain ---- */
    char victim[600];
    snprintf(victim, sizeof victim, "%s/procd.0123456789abcdef", cg);
    mkdir(victim, 0755);
    pid_t vp = sleeper_in(victim);
    char vino[32], forged[1200];
    snprintf(vino, sizeof vino, "%llu", ino_of(victim));

    snprintf(forged, sizeof forged, "linux-cgroup2:1:%s:%s:%s", boot, vino, victim);
    CHECK(try_recover(forged, "v1 token -> unrelated cgroup") == PROCD_UNRESOLVED,
          "B4: old-format forged token is UNRESOLVED");
    snprintf(forged, sizeof forged,
             "linux-cgroup2:2:00000000000000000000000000000000:%s:1:1:%s:2:%s", boot, vino, victim);
    CHECK(try_recover(forged, "unknown nonce -> unrelated cgroup") == PROCD_UNRESOLVED,
          "B4: token without a protected record is UNRESOLVED");
    {
        char t1[1200], t2[1200];
        with_field(id, F_PATH, victim, t1, sizeof t1);
        with_field(t1, F_INO, vino, t2, sizeof t2);
        CHECK(try_recover(t2, "genuine nonce, path+ino -> unrelated cgroup") == PROCD_UNRESOLVED,
              "B4: genuine nonce redirected to unrelated cgroup is UNRESOLVED");
    }
    CHECK(alive(vp), "B4 oracle: unrelated process in the look-alike cgroup survived");

    /* ---- B4: ordinary directory posing as a cgroup ---- */
    mkdir("/tmp/procd_rt_fakecg", 0755);
    write_file("/tmp/procd_rt_fakecg/cgroup.events", "populated 0\n");
    write_file("/tmp/procd_rt_fakecg/cgroup.kill", "");
    snprintf(forged, sizeof forged, "linux-cgroup2:1:%s:%llu:/tmp/procd_rt_fakecg", boot,
             ino_of("/tmp/procd_rt_fakecg"));
    {
        procd_recovery_outcome o = try_recover(forged, "v1 token -> ordinary dir");
        CHECK(o == PROCD_UNRESOLVED, "B4: ordinary directory (old format) is UNRESOLVED");
    }
    {
        char t[1200], v[32];
        snprintf(v, sizeof v, "%llu", ino_of("/tmp/procd_rt_fakecg"));
        with_field(id, F_PATH, "/tmp/procd_rt_fakecg", forged, sizeof forged);
        with_field(forged, F_INO, v, t, sizeof t);
        CHECK(try_recover(t, "genuine nonce -> ordinary dir") == PROCD_UNRESOLVED,
              "B4: ordinary directory (current format) is UNRESOLVED");
    }

    /* ---- B5: edited fields of a live domain's token ---- */
    {
        char t[1200], b2[64];
        snprintf(b2, sizeof b2, "%s", boot);
        b2[0] = (b2[0] == 'a') ? 'b' : 'a';
        with_field(id, F_BOOT, b2, t, sizeof t);
        CHECK(try_recover(t, "edited boot id") == PROCD_UNRESOLVED,
              "B5: edited boot id on live domain is UNRESOLVED (not CONFIRMED_DESTROYED)");
        char p2[600];
        snprintf(p2, sizeof p2, "%s", path);
        p2[strlen(p2) - 1] = (p2[strlen(p2) - 1] == '0') ? '1' : '0';
        with_field(id, F_PATH, p2, t, sizeof t);
        CHECK(try_recover(t, "edited path") == PROCD_UNRESOLVED,
              "B5: edited path on live domain is UNRESOLVED (not CONFIRMED_DESTROYED)");
        snprintf(p2, sizeof p2, "%s/x", path);
        with_field(id, F_PATH, p2, t, sizeof t);
        CHECK(try_recover(t, "path with trailing component") == PROCD_UNRESOLVED,
              "B5: malformed path on live domain is UNRESOLVED");
        char i2[40];
        snprintf(i2, sizeof i2, "%s1", ino);
        with_field(id, F_INO, i2, t, sizeof t);
        CHECK(try_recover(t, "edited inode") == PROCD_UNRESOLVED,
              "B5: edited inode on live domain is UNRESOLVED");
        if (F_LEVEL >= 0) {
            with_field(id, F_LEVEL, "1", t, sizeof t);
            CHECK(try_recover(t, "edited level") == PROCD_UNRESOLVED,
                  "B5: edited level on live domain is UNRESOLVED");
        }
        CHECK(alive((pid_t)member), "B5 oracle: live domain member untouched");
    }

    /* ---- a domain without a protected record is never recovered ---- */
    {
        char uid[PROCD_IDENTITY_MAX], deleg[600];
        if (unprivileged_identity(cg, uid, sizeof uid, deleg, sizeof deleg) == 0) {
            printf("   unprivileged identity %s\n", uid);
            procd_recovery_outcome o = try_recover(uid, "unprivileged domain, as root");
            CHECK(o == PROCD_UNRESOLVED, "domain without a protected record is UNRESOLVED");
            char bp[600];
            snprintf(bp, sizeof bp, "%s", strrchr(uid, ':') + 1);
            rmdir(bp);
        } else {
            CHECK(0, "could not create a domain as an unprivileged delegated user");
        }
        rmdir(deleg);
    }

    /* ---- genuine recovery of the exact domain ---- */
    {
        procd_recovery_outcome o;
        procd_domain *rd = NULL;
        procd_recover(id, &o, &rd);
        CHECK(o == PROCD_RECOVERED && rd, "genuine token RECOVERS the live domain");
        if (rd) {
            procd_domain_status st;
            procd_domain_status_get(rd, &st);
            CHECK(st.process_tree_termination == PROCD_CAP_ENFORCED,
                  "recovered level equals established level");
            char rid[PROCD_IDENTITY_MAX];
            procd_domain_identity(rd, rid, sizeof rid);
            CHECK(strcmp(rid, id) == 0, "recovered handle re-emits the same identity");
            int64_t m2 = -1;
            CHECK(procd_domain_spawn(rd, av, &m2) == PROCD_OK,
                  "recovered handle can spawn into the exact domain");
            CHECK(alive((pid_t)member), "failed/successful spawn did not kill existing member");
            procd_termination_evidence ev;
            procd_status rc = procd_domain_terminate(rd, 5000, &ev);
            CHECK(rc == PROCD_OK && ev.enforced && ev.final_state == PROCD_STATE_EMPTY,
                  "recovered handle terminates with enforced evidence");
            CHECK(killed_by_signal((pid_t)member), "oracle: original member was killed");
            /* m2 is a leader procd spawned into the recovered handle, so procd
             * reaps it during terminate; verify it did not survive rather than
             * racing procd for its exit status. */
            if (m2 > 0) CHECK(gone((pid_t)m2), "oracle: recovered-spawned member did not survive");
            procd_domain_release(rd);
        }
        CHECK(alive(vp), "oracle: unrelated process still alive after domain termination");
    }

    /* ---- after destruction: genuine token is CONFIRMED_DESTROYED ---- */
    CHECK(try_recover(id, "genuine token after termination") == PROCD_CONFIRMED_DESTROYED,
          "genuine token of a destroyed domain is CONFIRMED_DESTROYED");

    /* ---- a record below ENFORCED never yields CONFIRMED_DESTROYED ---- */
    {
        char t[1200];
        with_field(id, F_LEVEL, "1", t, sizeof t);
        CHECK(set_record_level(id, '1') == 0, "record rewritten to BEST_EFFORT (test setup)");
        CHECK(try_recover(t, "vanished BEST_EFFORT domain") == PROCD_UNRESOLVED,
              "vanished domain recorded BEST_EFFORT is UNRESOLVED, not CONFIRMED_DESTROYED");
    }

    procd_domain_release(d);
    kill(vp, SIGKILL);
    waitpid(vp, NULL, 0);
    nap(50);
    rmdir(victim);
    unlink("/tmp/procd_rt_fakecg/cgroup.events");
    unlink("/tmp/procd_rt_fakecg/cgroup.kill");
    rmdir("/tmp/procd_rt_fakecg");
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all recovery checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only recovery regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
