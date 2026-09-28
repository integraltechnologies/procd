#if !defined(_WIN32)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* realpath */
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Real Cargo lifecycle qualification: the agentctl failure class procd exists
 * to prevent (cargo / rustc / build-script / test processes outliving their
 * task).
 *
 *   procd domain -> shell -> cargo -> { rustc | build script | test binary }
 *                                        -> children, grandchildren and a
 *                                           detached, orphaned daemon
 *
 * The fixture crate (tests/cargo_fixture) stalls in one of three places, chosen
 * by PROCD_CARGO_PHASE:
 *   rustc  - a proc macro sleeps inside the compiler (rustc itself is running);
 *   build  - build.rs runs with an attached child and a detached daemon whose
 *            parent has exited;
 *   test   - an integration test runs with a child, a grandchild and a detached
 *            daemon whose parent has exited.
 *
 * For each run the test waits until every fixture witness exists, proves the
 * chain from the spawned shell through a process named cargo down to the
 * stalled process from the kernel's process table, snapshots the whole live
 * descendant tree, terminates the domain, and requires every recorded process
 * (judged by pid + start time, never by procd) to be gone within the bound.
 * A second, concurrently running Cargo task in its own domain and an unrelated
 * same-user process must survive every one of those terminations. After all
 * runs no process whose executable lies under this test's scratch tree may
 * exist (no accumulated build scripts, test binaries or helpers).
 *
 * Exits 77 (skipped) without cargo or without a usable domain, unless
 * PROCD_REQUIRE_CARGO=1, which turns every skip into a failure.
 *
 * usage: procd-cargo-test <fixture Cargo.toml> <scratch dir>
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include "witness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>

#include <tlhelp32.h>
#define PATH_SEP '\\'
static void nap(int ms) {
    Sleep((DWORD)ms);
}
static long long mono_ms(void) {
    return (long long)GetTickCount64();
}
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/sysctl.h>
#endif
#define PATH_SEP '/'
static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

#define TERM_TIMEOUT_MS 10000
#define TERM_BOUND_MS 12000
#define PHASE_WAIT_MS 300000 /* first compile of the fixture on a cold runner */
#define MAXP 8192
#define MAXID 512

static int fails = 0;
static int strict_cargo(void) {
    const char *v = getenv("PROCD_REQUIRE_CARGO");
    return v && strcmp(v, "1") == 0;
}
#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: ");                                                                      \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: ");                                                                        \
        printf(__VA_ARGS__);                                                                       \
        printf("\n");                                                                              \
    } while (0)

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

/* ---------------- process table ---------------- */

#define PROC_NAME_LEN 64 /* process names, and the identity labels copied from them */

typedef struct {
    long pid, ppid;
    unsigned long long start;
    char name[PROC_NAME_LEN];
    char exe[512];
} proc_t;

static proc_t g_procs[MAXP];

#if defined(__linux__)
static int snapshot(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while (n < MAXP && (e = readdir(d)) != NULL) {
        long pid = strtol(e->d_name, NULL, 10);
        if (pid <= 0) continue;
        char p[64], b[1024];
        snprintf(p, sizeof p, "/proc/%ld/stat", pid);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t r = read(fd, b, sizeof b - 1);
        close(fd);
        if (r <= 0) continue;
        b[r] = 0;
        char *lp = strchr(b, '('), *rp = strrchr(b, ')');
        if (!lp || !rp || rp[1] != ' ' || rp[2] == 'Z') continue;
        proc_t *q = &g_procs[n];
        memset(q, 0, sizeof *q);
        size_t nl = (size_t)(rp - lp - 1);
        if (nl >= sizeof q->name) nl = sizeof q->name - 1;
        memcpy(q->name, lp + 1, nl);
        q->pid = pid;
        q->ppid = strtol(rp + 4, NULL, 10);
        q->start = w_start_time(pid);
        if (!q->start) continue;
        snprintf(p, sizeof p, "/proc/%ld/exe", pid);
        ssize_t l = readlink(p, q->exe, sizeof q->exe - 1);
        if (l > 0) q->exe[l] = 0;
        n++;
    }
    closedir(d);
    return n;
}
#elif defined(__APPLE__)
static int snapshot(void) {
    int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) return 0;
    len += len / 4;
    struct kinfo_proc *kp = malloc(len);
    if (!kp) return 0;
    if (sysctl(mib, 3, kp, &len, NULL, 0) != 0) {
        free(kp);
        return 0;
    }
    int n = 0;
    for (size_t i = 0; i < len / sizeof *kp && n < MAXP; i++) {
        if (kp[i].kp_proc.p_stat == SZOMB) continue;
        proc_t *q = &g_procs[n];
        memset(q, 0, sizeof *q);
        q->pid = kp[i].kp_proc.p_pid;
        q->ppid = kp[i].kp_eproc.e_ppid;
        snprintf(q->name, sizeof q->name, "%s", kp[i].kp_proc.p_comm);
        q->start = w_start_time(q->pid);
        if (!q->start) continue;
        if (proc_pidpath((int)q->pid, q->exe, sizeof q->exe) <= 0) q->exe[0] = 0;
        n++;
    }
    free(kp);
    return n;
}
#elif defined(_WIN32)
static int snapshot(void) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 e;
    e.dwSize = sizeof e;
    int n = 0;
    for (BOOL ok = Process32First(s, &e); ok && n < MAXP; ok = Process32Next(s, &e)) {
        proc_t *q = &g_procs[n];
        memset(q, 0, sizeof *q);
        q->pid = (long)e.th32ProcessID;
        q->ppid = (long)e.th32ParentProcessID;
        snprintf(q->name, sizeof q->name, "%s", e.szExeFile);
        if (q->pid <= 4) continue;
        q->start = w_start_time(q->pid);
        if (!q->start) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)q->pid);
        if (h) {
            DWORD sz = (DWORD)sizeof q->exe;
            if (!QueryFullProcessImageNameA(h, 0, q->exe, &sz)) q->exe[0] = 0;
            CloseHandle(h);
        }
        n++;
    }
    CloseHandle(s);
    return n;
}
#endif

static const proc_t *find_proc(int n, long pid) {
    for (int i = 0; i < n; i++)
        if (g_procs[i].pid == pid) return &g_procs[i];
    return NULL;
}

static int path_under(const char *p, const char *root) {
    size_t l = strlen(root);
#if defined(_WIN32)
    return _strnicmp(p, root, l) == 0 && (p[l] == '\\' || p[l] == 0);
#else
    return strncmp(p, root, l) == 0 && (p[l] == '/' || p[l] == 0);
#endif
}

static int name_is(const char *name, const char *want) {
    size_t l = strlen(want);
#if defined(_WIN32)
    return _strnicmp(name, want, l) == 0 && (name[l] == 0 || _stricmp(name + l, ".exe") == 0);
#else
    return strncmp(name, want, l) == 0 && name[l] == 0;
#endif
}

/* ---------------- identities ---------------- */

typedef struct {
    w_rec r[MAXID];
    char what[MAXID][PROC_NAME_LEN]; /* a role or a proc_t name: always fits */
    int n;
} idset;

static void id_add(idset *s, long pid, unsigned long long start, const char *what) {
    if (!start || s->n >= MAXID) return;
    for (int i = 0; i < s->n; i++)
        if (s->r[i].pid == pid && s->r[i].start == start) return;
    memset(&s->r[s->n], 0, sizeof s->r[s->n]);
    s->r[s->n].pid = pid;
    s->r[s->n].start = start;
    snprintf(s->what[s->n], sizeof s->what[s->n], "%s", what);
    s->n++;
}

static int id_alive(const idset *s, char *who, size_t wn) {
    int a = 0;
    who[0] = 0;
    for (int i = 0; i < s->n; i++)
        if (w_alive(&s->r[i])) {
            a++;
            size_t l = strlen(who);
            if (l + 60 < wn) snprintf(who + l, wn - l, " %s(%ld)", s->what[i], s->r[i].pid);
        }
    return a;
}

static void id_kill(const idset *s) {
    for (int i = 0; i < s->n; i++)
        w_kill(&s->r[i]);
}

/* Cargo fixture witnesses are "<role> <pid>"; resolve each to (pid, start). */
static int read_fixture_witness(const char *dir, const char *role, long *pid) {
#if defined(_WIN32)
    char pat[MAX_PATH * 2];
    snprintf(pat, sizeof pat, "%s\\%s.*", dir, role);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    long v = strtol(fd.cFileName + strlen(role) + 1, NULL, 10);
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d) return 0;
    long v = 0;
    struct dirent *e;
    size_t rl = strlen(role);
    while ((e = readdir(d)) != NULL)
        if (strncmp(e->d_name, role, rl) == 0 && e->d_name[rl] == '.') {
            v = strtol(e->d_name + rl + 1, NULL, 10);
            break;
        }
    closedir(d);
#endif
    if (v <= 0) return 0;
    *pid = v;
    return 1;
}

/* ---------------- one Cargo task ---------------- */

typedef struct {
    const char *phase;
    procd_domain *d;
    int64_t root;
    char wd[1024], target[1024];
    idset ids;    /* every recorded process of this task */
    int observed; /* all witnesses + the cargo chain were seen */
    char why[256];
} task;

static const char *const ROLES_RUSTC[] = {"rustc", NULL};
static const char *const ROLES_BUILD[] = {"build-script", "build-child", "build-mid",
                                          "build-daemon", NULL};
static const char *const ROLES_TEST[] = {"test",     "child",       "grandchild",
                                         "test-mid", "test-daemon", NULL};

static const char *const *roles_for(const char *phase) {
    return !strcmp(phase, "rustc")   ? ROLES_RUSTC
           : !strcmp(phase, "build") ? ROLES_BUILD
                                     : ROLES_TEST;
}

static int make_dir(const char *p) {
#if defined(_WIN32)
    return CreateDirectoryA(p, NULL) ? 0 : -1;
#else
    return mkdir(p, 0755);
#endif
}

static int task_start(task *t, const char *phase, const char *manifest, const char *scratch,
                      int seq, int ttl) {
    memset(t, 0, sizeof *t);
    t->phase = phase;
    snprintf(t->wd, sizeof t->wd, "%.960s%cw%d-%s", scratch, PATH_SEP, seq, phase);
    snprintf(t->target, sizeof t->target, "%.960s%ct%d-%s", scratch, PATH_SEP, seq, phase);
    if (make_dir(t->wd) != 0) {
        snprintf(t->why, sizeof t->why, "cannot create %.200s", t->wd);
        return 0;
    }
    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = caps.process_tree_termination == PROCD_CAP_ENFORCED ? PROCD_REQUIRE_ENFORCED
                                                                          : PROCD_ALLOW_BEST_EFFORT;
    procd_status rc = procd_create_domain(&pol, &t->d);
    if (rc != PROCD_OK) {
        snprintf(t->why, sizeof t->why, "create_domain: %s", procd_status_name(rc));
        t->d = NULL;
        return -1;
    }
    char ttls[16];
    snprintf(ttls, sizeof ttls, "%d", ttl);
    set_env("PROCD_CARGO_PHASE", phase);
    set_env("PROCD_CARGO_WITNESS", t->wd);
    set_env("PROCD_CARGO_TTL", ttls);
    set_env("CARGO_TARGET_DIR", t->target);
    const char *sub = !strcmp(phase, "test") ? "test" : "build";
#if defined(_WIN32)
    const char *argv[] = {"cmd.exe",  "/d",        "/c",      "cargo",           sub,
                          "--locked", "--offline", "--quiet", "--manifest-path", manifest,
                          NULL};
#else
    char script[256];
    snprintf(script, sizeof script, "cargo %s --locked --offline --quiet --manifest-path \"$0\"",
             sub);
    const char *argv[] = {"/bin/sh", "-c", script, manifest, NULL};
#endif
    rc = procd_domain_spawn(t->d, argv, &t->root);
    set_env("PROCD_CARGO_PHASE", NULL);
    set_env("PROCD_CARGO_WITNESS", NULL);
    set_env("PROCD_CARGO_TTL", NULL);
    set_env("CARGO_TARGET_DIR", NULL);
    if (rc != PROCD_OK) {
        snprintf(t->why, sizeof t->why, "spawn: %s", procd_status_name(rc));
        return 0;
    }
    return 1;
}

/* Wait for every witness, then record the task's identities: the witnessed
 * fixture processes, the kernel-visible chain shell -> cargo -> anchor, and the
 * whole live descendant tree of the spawned shell. */
static void task_observe(task *t) {
    const char *const *roles = roles_for(t->phase);
    long pids[8] = {0};
    long long t0 = mono_ms();
    int all = 0;
    while (!all && mono_ms() - t0 < PHASE_WAIT_MS) {
        all = 1;
        for (int i = 0; roles[i]; i++)
            if (!pids[i] && !read_fixture_witness(t->wd, roles[i], &pids[i])) all = 0;
        if (!all) nap(100);
    }
    if (!all) {
        snprintf(t->why, sizeof t->why, "fixture witnesses incomplete after %ds",
                 PHASE_WAIT_MS / 1000);
        return;
    }
    nap(300); /* let the "-mid" launchers finish exiting */
    int n = snapshot();
    const proc_t *anchor = NULL;
    for (int i = 0; roles[i]; i++) {
        int is_mid = strstr(roles[i], "-mid") != NULL;
        const proc_t *p = find_proc(n, pids[i]);
        if (is_mid) {
            if (p) {
                snprintf(t->why, sizeof t->why, "'%s' did not exit (daemon not orphaned)",
                         roles[i]);
                return;
            }
            continue;
        }
        if (!p) {
            snprintf(t->why, sizeof t->why, "witnessed '%s' (pid %ld) not running", roles[i],
                     pids[i]);
            return;
        }
        id_add(&t->ids, p->pid, p->start, roles[i]);
        if (i == 0) anchor = p;
    }
    /* chain from the stalled process up to the spawned shell, through cargo */
    int saw_cargo = 0, depth = 0, reached = 0;
    char chain[256] = "";
    for (const proc_t *p = anchor; p && depth < 16; depth++) {
        size_t l = strlen(chain);
        snprintf(chain + l, sizeof chain - l, "%s%s", l ? " <- " : "", p->name);
        id_add(&t->ids, p->pid, p->start, p->name);
        if (name_is(p->name, "cargo")) saw_cargo = 1;
        if (p->pid == (long)t->root) {
            reached = 1;
            break;
        }
        const proc_t *up = find_proc(n, p->ppid);
        if (up && up->start > p->start) up = NULL; /* recycled parent pid */
        p = up;
    }
    if (!reached || !saw_cargo) {
        snprintf(t->why, sizeof t->why, "no kernel chain spawned-shell -> cargo -> %s: [%.180s]",
                 roles[0], chain);
        return;
    }
    if (!strcmp(t->phase, "rustc") && !name_is(anchor->name, "rustc")) {
        snprintf(t->why, sizeof t->why, "stalled compiler is '%s', not rustc", anchor->name);
        return;
    }
    /* whole live descendant tree of the spawned shell */
    for (int pass = 0, grew = 1; grew && pass < 32; pass++) {
        grew = 0;
        for (int i = 0; i < n; i++) {
            const proc_t *q = &g_procs[i];
            int in = q->pid == (long)t->root;
            for (int j = 0; j < t->ids.n && !in; j++)
                if (t->ids.r[j].pid == q->ppid && t->ids.r[j].start <= q->start) in = 1;
            int before = t->ids.n;
            if (in) id_add(&t->ids, q->pid, q->start, q->name);
            if (t->ids.n != before) grew = 1;
        }
    }
    snprintf(t->why, sizeof t->why, "[%.200s], %d live task processes", chain, t->ids.n);
    t->observed = 1;
}

/* Terminate one task and verify it is gone. Returns 1 when clean. */
static int task_terminate(task *t, const char *label) {
    procd_domain_status st;
    int status_ok =
        procd_domain_status_get(t->d, &st) == PROCD_OK && st.population == PROCD_POP_POPULATED;
    long long t0 = mono_ms();
    procd_termination_evidence ev;
    procd_status rc = procd_domain_terminate(t->d, TERM_TIMEOUT_MS, &ev);
    long long ms = mono_ms() - t0;
    char who[1024];
    int alive = id_alive(&t->ids, who, sizeof who);
    for (int i = 0; i < 100 && alive; i++) {
        nap(20);
        alive = id_alive(&t->ids, who, sizeof who);
    }
    CHECK(status_ok, "%s: status reported the running Cargo task as populated", label);
    CHECK(rc == PROCD_OK, "%s: terminate -> %s (%s)", label, procd_status_name(rc),
          ev.detail ? ev.detail : "");
    CHECK(ms <= TERM_BOUND_MS, "%s: termination took %lldms (bound %dms)", label, ms,
          TERM_BOUND_MS);
    CHECK(alive == 0, "%s: %d/%d recorded task processes remain%s", label, alive, t->ids.n,
          alive ? who : "");
    id_kill(&t->ids); /* hygiene only */
    return status_ok && rc == PROCD_OK && ms <= TERM_BOUND_MS && alive == 0;
}

static void task_release(task *t) {
    if (t->d) procd_domain_release(t->d);
    t->d = NULL;
}

/* ---------------- unrelated control ---------------- */

typedef struct {
    w_rec r;
#if defined(_WIN32)
    HANDLE h;
#else
    pid_t pid;
#endif
} control;

static int control_start(control *c) {
    memset(c, 0, sizeof *c);
#if defined(_WIN32)
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, (LPSTR) "ping.exe -n 900 127.0.0.1", NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    CloseHandle(pi.hThread);
    c->h = pi.hProcess;
    c->r.pid = (long)pi.dwProcessId;
#else
    c->pid = fork();
    if (c->pid == 0) {
        execlp("sleep", "sleep", "900", (char *)NULL);
        _exit(127);
    }
    if (c->pid < 0) return 0;
    c->r.pid = (long)c->pid;
#endif
    for (int i = 0; i < 100 && !c->r.start; i++) {
        c->r.start = w_start_time(c->r.pid);
        if (!c->r.start) nap(10);
    }
    return c->r.start != 0;
}

static int control_alive(const control *c) {
#if defined(_WIN32)
    return c->h && WaitForSingleObject(c->h, 0) == WAIT_TIMEOUT;
#else
    return c->pid > 0 && waitpid(c->pid, NULL, WNOHANG) == 0 && w_alive(&c->r);
#endif
}

static void control_stop(control *c) {
#if defined(_WIN32)
    if (c->h) {
        TerminateProcess(c->h, 0);
        CloseHandle(c->h);
    }
#else
    if (c->pid > 0) {
        kill(c->pid, SIGKILL);
        waitpid(c->pid, NULL, 0);
    }
#endif
}

/* ---------------- main ---------------- */

static int cargo_available(void) {
#if defined(_WIN32)
    return system("cargo --version >NUL 2>&1") == 0;
#else
    return system("cargo --version >/dev/null 2>&1") == 0;
#endif
}

static void remove_tree(const char *p) {
    char cmd[1200];
#if defined(_WIN32)
    snprintf(cmd, sizeof cmd, "rmdir /s /q \"%s\" >NUL 2>&1", p);
#else
    snprintf(cmd, sizeof cmd, "rm -rf \"%s\"", p);
#endif
    if (system(cmd) != 0) printf("note: could not remove %s\n", p);
}

static int skip(const char *why) {
    int strict = strict_cargo();
    printf("%s: %s\n", strict ? "FAIL" : "SKIP", why);
    return strict ? 1 : 77;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        printf("usage: procd-cargo-test <fixture Cargo.toml> <scratch dir>\n");
        return 2;
    }
    if (!cargo_available()) return skip("cargo is not available on PATH");

    char manifest[4096], scratch[1024], base[4096];
#if defined(_WIN32)
    char tmp[4096];
    if (!GetFullPathNameA(argv[1], sizeof manifest, manifest, NULL) ||
        !GetFullPathNameA(argv[2], sizeof tmp, tmp, NULL) ||
        !GetLongPathNameA(tmp, base, sizeof base))
        return skip("cannot resolve paths");
#else
    if (!realpath(argv[1], manifest) || !realpath(argv[2], base))
        return skip("cannot resolve paths");
#endif
#if defined(_WIN32)
    long self = (long)GetCurrentProcessId();
#else
    long self = (long)getpid();
#endif
    snprintf(scratch, sizeof scratch, "%.900s%cprocd-cargo-%ld", base, PATH_SEP, self);
    if (make_dir(scratch) != 0) return skip("cannot create scratch directory");

    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    printf("backend %s, ProcessTreeTermination %s\n", caps.backend,
           procd_capability_name(caps.process_tree_termination));

    control ctl;
    int have_ctl = control_start(&ctl);
    CHECK(have_ctl, "unrelated same-user control process started");

    /* another agentctl task: a Cargo build stalled in its build script, in its
     * own domain, running across every termination below */
    task other;
    int s = task_start(&other, "build", manifest, scratch, 0, 300);
    if (s < 0) {
        control_stop(&ctl);
        remove_tree(scratch);
        return skip(other.why);
    }
    if (s > 0) task_observe(&other);
    CHECK(s > 0 && other.observed, "concurrent Cargo task B observed: %s", other.why);
    if (!other.observed) {
        if (other.d) {
            procd_termination_evidence ev;
            procd_domain_terminate(other.d, TERM_TIMEOUT_MS, &ev);
        }
        id_kill(&other.ids);
        task_release(&other);
        control_stop(&ctl);
        remove_tree(scratch);
        printf("FAILURES (%d)\n", fails);
        return 1;
    }

    static const char *const phases[] = {"rustc", "build", "test", "test", "build", "test"};
    int clean = 0, runs = (int)(sizeof phases / sizeof phases[0]);
    for (int i = 0; i < runs; i++) {
        task t;
        char label[64];
        snprintf(label, sizeof label, "run %d/%d (%s phase)", i + 1, runs, phases[i]);
        long long t0 = mono_ms();
        if (task_start(&t, phases[i], manifest, scratch, i + 1, 120) > 0) task_observe(&t);
        CHECK(t.observed, "%s observed after %llds: %s", label, (mono_ms() - t0) / 1000, t.why);
        if (!t.observed) {
            if (t.d) {
                procd_termination_evidence ev;
                procd_domain_terminate(t.d, TERM_TIMEOUT_MS, &ev);
            }
            id_kill(&t.ids);
            task_release(&t);
            continue;
        }
        clean += task_terminate(&t, label);
        task_release(&t);
        char who[1024];
        int oalive = id_alive(&other.ids, who, sizeof who);
        CHECK(oalive == other.ids.n, "%s: concurrent Cargo task B untouched (%d/%d alive)", label,
              oalive, other.ids.n);
        CHECK(!have_ctl || control_alive(&ctl), "%s: unrelated control process alive", label);
    }

    /* task B is cleaned up too */
    task_terminate(&other, "task B (build phase)");
    task_release(&other);

    /* nothing launched from this test's scratch tree may remain */
    nap(300);
    int n = snapshot(), leaked = 0;
    for (int i = 0; i < n; i++)
        if (g_procs[i].exe[0] && path_under(g_procs[i].exe, scratch)) {
            printf("   leaked: pid %ld %s\n", g_procs[i].pid, g_procs[i].exe);
            leaked++;
        }
    CHECK(leaked == 0, "no process from the Cargo scratch tree remains after %d runs (%d found)",
          runs + 1, leaked);
    CHECK(clean == runs, "%d/%d Cargo task terminations were clean", clean, runs);
    CHECK(!have_ctl || control_alive(&ctl), "unrelated control process survived everything");

    control_stop(&ctl);
    remove_tree(scratch);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all Cargo lifecycle checks passed", fails);
    return fails ? 1 : 0;
}
