#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * macOS normal-workload lifecycle soak.
 *
 * Question: across many realistic engineering-task lifecycles, how often does
 * procd leave a task process alive after cancellation? Workloads are ordinary
 * software on this machine -- sh/bash pipelines, background jobs, nested
 * shells, xargs -P, a process-creating loop, Python subprocess/multiprocessing,
 * Node child_process, and real Cargo (rustc in a proc macro, a build script
 * with helpers, a test binary with helpers, plain `cargo check`). Nothing here
 * clears its environment to hide from procd; that belongs to the residual test.
 *
 * Oracle (independent of procd): every task carries a harness-only tag
 * SOAK_TAG=<run>-<task> in its environment. Before termination the harness
 * snapshots every same-user process whose kernel exec-time environment
 * carries the tag, as (pid, start time); fixture roles also witness
 * themselves (<role>.<pid> files), and a role counts only if that pid is
 * running and carries the tag. After termination a survivor is any snapshot
 * identity, witness, or newly tagged process still running (zombies excluded).
 *
 * A lifecycle is ESTABLISHED only when every expected role was witnessed alive
 * (and, for leader-exit workloads, the leader had exited) before termination;
 * cancellations before that are counted separately, never as topology evidence.
 * Cancellation points rotate deterministically: immediately after spawn, while
 * descendants are being created, at establishment, +500ms, +2000ms. Every 25th
 * cycle runs three concurrent domains (Cargo / Python / nested shells),
 * terminates one and requires the other two intact. An unrelated same-user
 * process must survive the whole soak.
 *
 * usage: procd-macos-soak-test <fixture Cargo.toml> <scratch dir>
 * env:   PROCD_SOAK_CYCLES (default 30), PROCD_REQUIRE_CARGO=1
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <dirent.h>
#include <libproc.h>
#include <signal.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
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

/* ---------------- independent process-table oracle ---------------- */

typedef struct {
    long pid, ppid, pgid, sid;
    unsigned long long start;
    char comm[48];
    int marker; /* exec env carries a procd domain marker */
} pinfo;

static int kinfo(long pid, pinfo *o) {
    struct proc_bsdinfo bi;
    if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi) return -1;
    if (bi.pbi_status == SZOMB) return -1;
    memset(o, 0, sizeof *o);
    o->pid = pid;
    o->ppid = bi.pbi_ppid;
    o->pgid = bi.pbi_pgid;
    o->sid = getsid((pid_t)pid);
    o->start = (unsigned long long)bi.pbi_start_tvsec * 1000000ULL + bi.pbi_start_tvusec;
    snprintf(o->comm, sizeof o->comm, "%s", bi.pbi_name[0] ? bi.pbi_name : bi.pbi_comm);
    return bi.pbi_uid == getuid() ? 0 : -1;
}

static int alive(long pid, unsigned long long start) {
    pinfo p;
    return kinfo(pid, &p) == 0 && p.start == start;
}

/* 1 if the exec-time env carries "SOAK_TAG=<tag>" ; sets *marker */
static int tagged(long pid, const char *tag, int *marker) {
    static char buf[1 << 20];
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, (int)pid};
    size_t len = sizeof buf;
    if (sysctl(mib, 3, buf, &len, NULL, 0) != 0 || len < sizeof(int)) return 0;
    char want[96];
    int wl = snprintf(want, sizeof want, "SOAK_TAG=%s", tag);
    int hit = 0;
    *marker = 0;
    for (size_t i = sizeof(int); i < len;) {
        size_t sl = strnlen(buf + i, len - i);
        if (sl == (size_t)wl && memcmp(buf + i, want, (size_t)wl) == 0) hit = 1;
        if (sl >= 13 && memcmp(buf + i, "PROCD_DOMAIN_", 13) == 0) *marker = 1;
        i += sl + 1;
    }
    return hit;
}

#define MAXP 512
typedef struct {
    pinfo v[MAXP];
    int n;
} pset;

static int pset_has(const pset *s, long pid, unsigned long long st) {
    for (int i = 0; i < s->n; i++)
        if (s->v[i].pid == pid && s->v[i].start == st) return 1;
    return 0;
}

/* every running same-user process carrying the tag (added to *s) */
static void sweep(const char *tag, pset *s) {
    static pid_t pids[16384];
    int n = proc_listallpids(pids, (int)sizeof pids);
    for (int i = 0; i < n; i++) {
        pinfo p;
        if (pids[i] <= 1 || pids[i] == getpid() || kinfo(pids[i], &p) != 0) continue;
        int mk = 0;
        if (!tagged(pids[i], tag, &mk)) continue;
        p.marker = mk;
        if (!pset_has(s, p.pid, p.start) && s->n < MAXP) s->v[s->n++] = p;
    }
}

/* ---------------- workloads ---------------- */

typedef struct {
    const char *name;
    int cargo;         /* 0 none; else a Cargo phase */
    const char *phase; /* PROCD_CARGO_PHASE, NULL for plain check */
    int leader_exits;  /* established requires the leader to be gone */
    const char *roles[8];
    const char *script; /* /bin/sh -c; $0 = scratch dir */
} workload;

static const workload LIGHT[] = {
    {"sh-pipeline",
     0,
     NULL,
     0,
     {"p1", "p2", "p3"},
     "$SOAK_WX p1 sleep 60 | $SOAK_WX p2 cat | $SOAK_WX p3 sort"},
    {"sh-bg-leader-exit",
     0,
     NULL,
     1,
     {"bg1", "bg2"},
     "$SOAK_WX bg1 sleep 60 & $SOAK_WX bg2 sleep 60 & exit 0"},
    {"nested-shells",
     0,
     NULL,
     0,
     {"n1", "n2", "n3"},
     "bash -c '$SOAK_WX n2 sleep 60 & sh -c \"\\$SOAK_WX n3 sleep 60\"; wait' & "
     "$SOAK_WX n1 sleep 60"},
    {"subshell-reparent",
     0,
     NULL,
     0,
     {"rp0", "rp1"},
     "( $SOAK_WX rp1 sleep 60 & ); $SOAK_WX rp0 sleep 60"},
    {"xargs-parallel",
     0,
     NULL,
     0,
     {"xa-1", "xa-2", "xa-3", "xa-4"},
     "seq 1 4 | xargs -P 4 -I{} $SOAK_WX xa-{} sleep 60"},
    {"spawn-loop",
     0,
     NULL,
     0,
     {"churn-anchor"},
     "$SOAK_WX churn-anchor sleep 60 & i=0; while [ $i -lt 3000 ]; do sleep 0.2 & sleep 0.01; "
     "i=$((i+1)); done"},
    {"python-detached-exit",
     0,
     NULL,
     1,
     {"pyd-helper"},
     "exec python3 -c \"import os,subprocess; "
     "d=subprocess.Popen(['/bin/sleep','60'], start_new_session=True); "
     "open(os.environ['SOAK_W']+'/pyd-helper.'+str(d.pid),'w').close()\""},
    {"node-detached-exit",
     0,
     NULL,
     1,
     {"nd-helper"},
     "exec node -e \"const d=require('child_process').spawn('/bin/sh',['-c','sleep 60; :'],"
     "{detached:true,stdio:'ignore'}); d.unref(); "
     "require('fs').writeFileSync(process.env.SOAK_W+'/nd-helper.'+d.pid,'')\""},
    {"python",
     0,
     NULL,
     0,
     {"py-main", "py-sub", "py-session", "py-mp", "py-mpchild"},
     "exec python3 \"$0/soak_py.py\""},
    {"node",
     0,
     NULL,
     0,
     {"node-main", "node-spawn", "node-detached", "node-fork", "node-forkchild"},
     "exec node \"$0/soak_node.js\""},
};
#define NLIGHT ((int)(sizeof LIGHT / sizeof LIGHT[0]))

static const workload CARGO[] = {
    {"cargo-rustc", 1, "rustc", 0, {"rustc"}, NULL},
    {"cargo-build-script", 1, "build", 0, {"build-script", "build-child", "build-daemon"}, NULL},
    {"cargo-test", 1, "test", 0, {"test", "child", "grandchild", "test-daemon"}, NULL},
    {"cargo-check", 1, NULL, 0, {NULL}, NULL}, /* established: a tagged rustc was running */
};

static const char *PY = "import os, subprocess, multiprocessing as mp, time\n"
                        "W = os.environ['SOAK_W']\n"
                        "def w(r, p=None):\n"
                        "    p = p or os.getpid()\n"
                        "    open(f'{W}/{r}.{p}', 'w').close()\n"
                        "def worker():\n"
                        "    c = subprocess.Popen(['sleep', '60'])\n"
                        "    w('py-mpchild', c.pid)\n"
                        "    w('py-mp')\n"
                        "    time.sleep(60)\n"
                        "if __name__ == '__main__':\n"
                        "    s = subprocess.Popen(['sleep', '60'])\n"
                        "    w('py-sub', s.pid)\n"
                        "    d = subprocess.Popen(['sleep', '60'], start_new_session=True)\n"
                        "    w('py-session', d.pid)\n"
                        "    p = mp.Process(target=worker)\n"
                        "    p.start()\n"
                        "    w('py-main')\n"
                        "    time.sleep(60)\n";

static const char *NODE =
    "const cp = require('child_process'), fs = require('fs');\n"
    "const W = process.env.SOAK_W;\n"
    "const w = (r, p = process.pid) => fs.writeFileSync(`${W}/${r}.${p}`, '');\n"
    "const q = {stdio: 'ignore'};\n"
    "if (process.argv[2] === 'child') {\n"
    "  const s = cp.spawn('sleep', ['60'], q); w('node-forkchild', s.pid); w('node-fork');\n"
    "  setTimeout(() => {}, 60000);\n"
    "} else {\n"
    "  const s = cp.spawn('sleep', ['60'], q); w('node-spawn', s.pid);\n"
    "  const d = cp.spawn('sleep', ['60'], {stdio: 'ignore', detached: true}); d.unref();\n"
    "  w('node-detached', d.pid);\n"
    "  cp.fork(__filename, ['child'], {stdio: ['ignore', 'ignore', 'ignore', 'ipc']});\n"
    "  w('node-main'); setTimeout(() => {}, 60000);\n"
    "}\n";

/* ---------------- task ---------------- */

enum { AT_IMMEDIATE, AT_CREATING, AT_ESTABLISHED, AT_EST_500, AT_EST_2000, AT_N };
static const char *AT_NAME[] = {"immediate", "creating", "established", "est+500ms", "est+2000ms"};

typedef struct {
    const workload *w;
    char tag[64], wd[512], target[512];
    procd_domain *d;
    int64_t leader;
    int established, spawned;
    pset pre;
    unsigned long long spawn_us;
} task;

static const char *g_manifest, *g_scratch;
static char g_run[16], g_wx[600];
static int g_seq;

static int rm_rf(const char *p) {
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", p);
    return system(cmd);
}

/* witnessed pid of role (0 if none) */
static long witness_pid(const char *wd, const char *role) {
    DIR *dd = opendir(wd);
    if (!dd) return 0;
    struct dirent *e;
    long pid = 0;
    size_t rl = strlen(role);
    while ((e = readdir(dd))) {
        if (e->d_name[0] == '.') continue;
        if (!strncmp(e->d_name, role, rl) && e->d_name[rl] == '.') pid = atol(e->d_name + rl + 1);
    }
    closedir(dd);
    return pid;
}

static unsigned long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ULL + (unsigned long long)ts.tv_nsec / 1000;
}

/* The witnessed process, as a running identity: the pid named by the witness
 * file, started no later than the file was written and no earlier than the
 * task was spawned, so a reused pid cannot stand in for it. Apple platform
 * binaries (/bin/sh, /bin/sleep, ...) hide their environment from other
 * processes, so identity never depends on seeing the tag. 0 on success. */
static int witness_identity(const char *wd, const char *role, unsigned long long since,
                            pinfo *out) {
    long pid = witness_pid(wd, role);
    if (!pid) return -1;
    char f[700];
    snprintf(f, sizeof f, "%s/%s.%ld", wd, role, pid);
    struct stat st;
    if (stat(f, &st) != 0 || kinfo(pid, out) != 0) return -1;
    unsigned long long wt = (unsigned long long)st.st_mtimespec.tv_sec * 1000000ULL +
                            (unsigned long long)st.st_mtimespec.tv_nsec / 1000;
    return (out->start <= wt + 1000 && out->start + 1000 >= since) ? 0 : -1;
}

static int any_witness(const char *wd) {
    DIR *dd = opendir(wd);
    if (!dd) return 0;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(dd)))
        if (e->d_name[0] != '.') n++;
    closedir(dd);
    return n;
}

static int task_start(task *t, const workload *w) {
    memset(t, 0, sizeof *t);
    t->w = w;
    int seq = g_seq++;
    snprintf(t->tag, sizeof t->tag, "%s-%d", g_run, seq);
    snprintf(t->wd, sizeof t->wd, "%s/w%d", g_scratch, seq);
    snprintf(t->target, sizeof t->target, "%s/t%d", g_scratch, seq);
    if (mkdir(t->wd, 0755) != 0) return 0;
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    if (procd_create_domain(&pol, &t->d) != PROCD_OK) return 0;
    setenv("SOAK_TAG", t->tag, 1);
    setenv("SOAK_W", t->wd, 1);
    setenv("SOAK_WX", g_wx, 1);
    const char *argv[5] = {"/bin/sh", "-c", NULL, NULL, NULL};
    if (w->cargo) {
        if (w->phase) setenv("PROCD_CARGO_PHASE", w->phase, 1);
        setenv("PROCD_CARGO_WITNESS", t->wd, 1);
        setenv("PROCD_CARGO_TTL", "60", 1);
        setenv("CARGO_TARGET_DIR", t->target, 1);
        argv[2] =
            !w->phase
                ? "cargo check --locked --offline --quiet --manifest-path \"$0\" >/dev/null 2>&1"
            : !strcmp(w->phase, "test")
                ? "cargo test --locked --offline --quiet --manifest-path \"$0\" >/dev/null 2>&1"
                : "cargo build --locked --offline --quiet --manifest-path \"$0\" >/dev/null 2>&1";
        argv[3] = g_manifest;
    } else {
        argv[2] = w->script;
        argv[3] = g_scratch;
    }
    t->spawn_us = now_us();
    procd_status rc = procd_domain_spawn(t->d, argv, &t->leader);
    unsetenv("SOAK_TAG");
    unsetenv("SOAK_W");
    unsetenv("SOAK_WX");
    unsetenv("PROCD_CARGO_PHASE");
    unsetenv("PROCD_CARGO_WITNESS");
    unsetenv("PROCD_CARGO_TTL");
    unsetenv("CARGO_TARGET_DIR");
    t->spawned = rc == PROCD_OK;
    return t->spawned;
}

/* has the task begun creating descendants? */
static int task_creating(task *t) {
    if (any_witness(t->wd)) return 1;
    pset s = {.n = 0};
    sweep(t->tag, &s);
    for (int i = 0; i < s.n; i++)
        if (s.v[i].pid != t->leader) return 1;
    return 0;
}

static int task_is_established(task *t) {
    const workload *w = t->w;
    if (w->cargo && !w->phase) { /* plain check: a tagged rustc is running */
        pset s = {.n = 0};
        sweep(t->tag, &s);
        for (int i = 0; i < s.n; i++)
            if (!strcmp(s.v[i].comm, "rustc")) return 1;
        return 0;
    }
    for (int i = 0; w->roles[i]; i++) {
        pinfo p;
        if (witness_identity(t->wd, w->roles[i], t->spawn_us, &p) != 0) return 0;
    }
    if (w->leader_exits) {
        pinfo p;
        if (kinfo((long)t->leader, &p) == 0) return 0; /* still running */
    }
    return 1;
}

/* why a task did not establish: each expected role's witness and kernel view */
static void task_diag(task *t) {
    for (int i = 0; t->w->roles[i]; i++) {
        long pid = witness_pid(t->wd, t->w->roles[i]);
        int mk = 0, tg = pid ? tagged(pid, t->tag, &mk) : 0;
        pinfo p;
        int k = pid ? kinfo(pid, &p) : -1;
        int id = witness_identity(t->wd, t->w->roles[i], t->spawn_us, &p) == 0;
        printf("    role %-14s pid=%ld running=%d identity=%d tag-visible=%d\n", t->w->roles[i],
               pid, k == 0, id, tg);
    }
}

/* agentctl-like supervision: poll the domain's status every 100ms */
static void poll_status(task *t, long long *next) {
    if (mono_ms() < *next) return;
    *next = mono_ms() + 100;
    procd_domain_status st;
    procd_domain_status_get(t->d, &st);
}

/* wait for the cancellation point; returns the point actually reached */
static void task_wait(task *t, int at) {
    long long limit = mono_ms() + (t->w->cargo ? 120000 : 15000);
    if (at == AT_IMMEDIATE) return;
    long long next_status = 0;
    while (mono_ms() < limit) {
        if (at == AT_CREATING ? task_creating(t) : task_is_established(t)) break;
        poll_status(t, &next_status);
        nap(at == AT_CREATING ? 1 : 10);
    }
    if (at != AT_CREATING) {
        t->established = task_is_established(t);
        int extra = !t->established ? 0 : at == AT_EST_500 ? 500 : at == AT_EST_2000 ? 2000 : 0;
        for (long long end = mono_ms() + extra; mono_ms() < end; nap(10))
            poll_status(t, &next_status);
    }
}

/* snapshot identities for the oracle: tagged processes + witnessed roles */
static void task_snapshot(task *t) {
    t->pre.n = 0;
    sweep(t->tag, &t->pre);
    for (int i = 0; t->w->roles[i]; i++) {
        pinfo p;
        if (witness_identity(t->wd, t->w->roles[i], t->spawn_us, &p) == 0 &&
            !pset_has(&t->pre, p.pid, p.start) && t->pre.n < MAXP)
            t->pre.v[t->pre.n++] = p;
    }
    /* plus every running descendant of those (untagged platform binaries) */
    static pid_t pids[16384];
    int n = proc_listallpids(pids, (int)sizeof pids);
    for (int changed = 1; changed;) {
        changed = 0;
        for (int i = 0; i < n; i++) {
            pinfo p;
            if (pids[i] <= 1 || kinfo(pids[i], &p) != 0 || pset_has(&t->pre, p.pid, p.start))
                continue;
            for (int j = 0; j < t->pre.n; j++)
                if (t->pre.v[j].pid == p.ppid && t->pre.n < MAXP) {
                    int mk;
                    tagged(p.pid, t->tag, &mk);
                    p.marker = mk;
                    t->pre.v[t->pre.n++] = p;
                    changed = 1;
                    break;
                }
        }
    }
}

/* ---------------- stats ---------------- */

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
#define MAXW 32
static struct {
    const char *name;
    long tasks;
    unsigned long long ev, scans, cpu_ns;
} WS[MAXW];

/* per-workload lifecycle outcome (established lifecycles only) */
static struct {
    const char *name;
    long est, clean;
} PW[MAXW];

static void workload_account(const workload *w, int established, int clean) {
    if (!established) return;
    for (int i = 0; i < MAXW; i++)
        if (!PW[i].name || !strcmp(PW[i].name, w->name)) {
            PW[i].name = w->name;
            PW[i].est++;
            PW[i].clean += clean;
            return;
        }
}

static void watch_account(const task *t, const char *detail) {
    unsigned long long v[3];
    watch_parse(detail, v);
    for (int i = 0; i < MAXW; i++)
        if (!WS[i].name || !strcmp(WS[i].name, t->w->name)) {
            WS[i].name = t->w->name;
            WS[i].tasks++;
            WS[i].ev += v[0], WS[i].scans += v[1], WS[i].cpu_ns += v[2];
            return;
        }
}

static struct {
    long cycles, launched, terminations, clean, dirty, survivors, casualties, iso_runs, iso_fail,
        established, est_clean, early, early_clean, not_est, term_err;
    long lat[20000];
    int nlat;
    long per_point[AT_N], per_point_clean[AT_N];
} S;

static int cmp_long(const void *a, const void *b) {
    long x = *(const long *)a, y = *(const long *)b;
    return x < y ? -1 : x > y;
}

/* terminate and judge; returns survivors */
static int task_finish(task *t, const char *point) {
    procd_termination_evidence ev;
    long long t0 = mono_ms();
    procd_status rc = procd_domain_terminate(t->d, 5000, &ev);
    long ms = (long)(mono_ms() - t0);
    S.terminations++;
    if (S.nlat < 20000) S.lat[S.nlat++] = ms;
    if (rc != PROCD_OK) {
        S.term_err++;
        printf("  terminate %s: %s (%s)\n", t->w->name, procd_status_name(rc),
               ev.detail ? ev.detail : "");
    }
    /* settle: a SIGKILLed process may take a moment to leave the table */
    pset left = {.n = 0};
    for (long long end = mono_ms() + 1500; mono_ms() < end; nap(20)) {
        left.n = 0;
        for (int i = 0; i < t->pre.n; i++)
            if (alive(t->pre.v[i].pid, t->pre.v[i].start) && left.n < MAXP)
                left.v[left.n++] = t->pre.v[i];
        sweep(t->tag, &left);
        if (left.n == 0) break;
    }
    for (int i = 0; i < left.n; i++) {
        pinfo *p = &left.v[i];
        pinfo now;
        int mk = 0, tg = tagged(p->pid, t->tag, &mk);
        kinfo(p->pid, &now);
        char path[PROC_PIDPATHINFO_MAXSIZE] = "";
        proc_pidpath((int)p->pid, path, sizeof path);
        printf("  SURVIVOR workload=%s at=%s pid=%ld start=%llu comm=%s path=%s ppid=%ld pgid=%ld "
               "sid=%ld leader=%lld procd-marker=%d tag=%d in-pre-snapshot=%d\n",
               t->w->name, point, p->pid, p->start, now.comm, path, now.ppid, now.pgid, now.sid,
               (long long)t->leader, mk, tg, pset_has(&t->pre, p->pid, p->start));
        kill((pid_t)p->pid, SIGKILL); /* hygiene, after recording */
    }
    watch_account(t, ev.detail);
    S.survivors += left.n;
    if (left.n)
        S.dirty++;
    else
        S.clean++;
    procd_domain_release(t->d);
    t->d = NULL;
    rm_rf(t->wd);
    if (t->w->cargo) rm_rf(t->target);
    return left.n;
}

static int control_ok(pid_t ctl, unsigned long long cst) {
    return alive(ctl, cst) && waitpid(ctl, NULL, WNOHANG) == 0;
}

static void one_cycle(const workload *w, int at) {
    task t;
    S.cycles++;
    if (!task_start(&t, w)) {
        printf("  launch failed: %s\n", w->name);
        if (t.d) procd_domain_release(t.d);
        return;
    }
    S.launched++;
    task_wait(&t, at);
    if (at >= AT_ESTABLISHED && !t.established) task_diag(&t);
    task_snapshot(&t);
    int surv = task_finish(&t, AT_NAME[at]);
    S.per_point[at]++;
    if (!surv) S.per_point_clean[at]++;
    if (at == AT_IMMEDIATE || at == AT_CREATING) {
        S.early++;
        S.early_clean += !surv;
    } else if (t.established) {
        S.established++;
        S.est_clean += !surv;
        workload_account(w, 1, !surv);
    } else {
        S.not_est++;
        printf("  not established: %s at %s (vacuous, not counted)\n", w->name, AT_NAME[at]);
    }
}

static const workload *light(const char *name) {
    for (int i = 0; i < NLIGHT; i++)
        if (!strcmp(LIGHT[i].name, name)) return &LIGHT[i];
    abort();
}

/* three concurrent domains; terminate one; the others must be intact */
static void iso_cycle(int k) {
    const workload *ws[3] = {&CARGO[k % 3], light("python"), light("nested-shells")};
    task t[3];
    S.iso_runs++;
    int ok = 1;
    for (int i = 0; i < 3; i++) {
        S.cycles++;
        if (!task_start(&t[i], ws[i])) {
            printf("  iso launch failed: %s\n", ws[i]->name);
            ok = 0;
        } else
            S.launched++;
    }
    for (int i = 0; i < 3; i++)
        if (t[i].spawned) task_wait(&t[i], AT_ESTABLISHED);
    for (int i = 0; i < 3; i++)
        if (t[i].spawned) task_snapshot(&t[i]);
    int victim = k % 3;
    if (!ok || !t[0].established || !t[1].established || !t[2].established) {
        printf("  iso %d: not all domains established (vacuous)\n", k);
    }
    int surv = task_finish(&t[victim], "iso-victim");
    int all_est = t[0].established && t[1].established && t[2].established;
    if (all_est) {
        S.established++, S.est_clean += !surv;
        workload_account(ws[victim], 1, !surv);
    }
    for (int i = 0; i < 3 && all_est; i++) {
        if (i == victim) continue;
        for (int r = 0; ws[i]->roles[r]; r++) {
            long pid = witness_pid(t[i].wd, ws[i]->roles[r]);
            pinfo p;
            int good = witness_identity(t[i].wd, ws[i]->roles[r], t[i].spawn_us, &p) == 0 &&
                       pset_has(&t[i].pre, p.pid, p.start);
            if (!good) {
                printf("  ISOLATION FAILURE: terminating %s disturbed %s role %s (pid %ld)\n",
                       ws[victim]->name, ws[i]->name, ws[i]->roles[r], pid);
                ok = 0;
            }
        }
    }
    if (!ok && all_est) S.iso_fail++;
    for (int i = 0; i < 3; i++)
        if (i != victim && t[i].spawned) {
            int s2 = task_finish(&t[i], "iso-rest");
            if (all_est) {
                S.established++, S.est_clean += !s2;
                workload_account(ws[i], 1, !s2);
            }
        }
}

/* PROCD_SOAK_SKIP: comma-separated workload names to leave out (scoping only) */
static int skip_named(const char *name) {
    const char *s = getenv("PROCD_SOAK_SKIP");
    size_t n = strlen(name);
    for (const char *p = s; p && *p;) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && !strncmp(p, name, n)) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        printf("usage: %s <fixture Cargo.toml> <scratch dir>\n", argv[0]);
        return 2;
    }
    g_manifest = argv[1];
    static char scratch[512];
    snprintf(scratch, sizeof scratch, "%s/soak-%d", argv[2], (int)getpid());
    mkdir(argv[2], 0755);
    if (mkdir(scratch, 0755) != 0) {
        printf("FAIL: scratch %s\n", scratch);
        return 1;
    }
    g_scratch = scratch;
    snprintf(g_run, sizeof g_run, "%08x", arc4random());
    const char *cs = getenv("PROCD_SOAK_CYCLES");
    int cycles = cs ? atoi(cs) : 30;
    if (cycles <= 0) cycles = 30;
    int have_cargo = system("cargo --version >/dev/null 2>&1") == 0;
    int have_py = system("python3 -c 1 >/dev/null 2>&1") == 0;
    int have_node = system("node -e 1 >/dev/null 2>&1") == 0;
    if (!have_cargo && getenv("PROCD_REQUIRE_CARGO")) {
        printf("FAIL: cargo required\n");
        return 1;
    }
    char p[600];
    snprintf(p, sizeof p, "%s/soak_py.py", scratch);
    FILE *f = fopen(p, "w");
    if (f) fputs(PY, f), fclose(f);
    snprintf(p, sizeof p, "%s/soak_node.js", scratch);
    f = fopen(p, "w");
    if (f) fputs(NODE, f), fclose(f);

    /* witness helper: record "<role>.<pid>", then become the command (same pid) */
    snprintf(g_wx, sizeof g_wx, "%s/wx.sh", scratch);
    f = fopen(g_wx, "w");
    if (f) fputs("#!/bin/sh\n: > \"$SOAK_W/$1.$$\"\nshift\nexec \"$@\"\n", f), fclose(f);
    chmod(g_wx, 0755);

    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    printf("backend=%s ProcessTreeTermination=%s cycles=%d cargo=%d python=%d node=%d\n",
           caps.backend, procd_capability_name(caps.process_tree_termination), cycles, have_cargo,
           have_py, have_node);

    /* unrelated same-user control, started without procd */
    pid_t ctl = fork();
    if (ctl == 0) {
        execl("/bin/sleep", "sleep", "86400", (char *)NULL);
        _exit(127);
    }
    nap(50);
    pinfo cp;
    unsigned long long cst = kinfo(ctl, &cp) == 0 ? cp.start : 0;

    struct rusage r0;
    getrusage(RUSAGE_SELF, &r0);
    long long t_start = mono_ms();
    int iso_k = 0;
    for (int i = 0; i < cycles; i++) {
        if (i % 25 == 24 && have_cargo && have_py) {
            iso_cycle(iso_k++);
        } else {
            int slot = i % (NLIGHT + 1), block = i / (NLIGHT + 1);
            const workload *w = slot < NLIGHT ? &LIGHT[slot] : &CARGO[block % 4];
            if (skip_named(w->name)) continue;
            if ((w->cargo && !have_cargo) || (!strcmp(w->name, "python") && !have_py) ||
                (!strcmp(w->name, "node") && !have_node))
                continue;
            one_cycle(w, block % AT_N);
        }
        if (!control_ok(ctl, cst)) {
            printf("CASUALTY: unrelated control process killed after cycle %d\n", i + 1);
            S.casualties++;
            break;
        }
        if ((i + 1) % 50 == 0)
            printf("... %d cycles: %ld terminations, %ld survivors, %ld casualties, %ld isolation "
                   "failures\n",
                   i + 1, S.terminations, S.survivors, S.casualties, S.iso_fail);
    }
    long long wall = mono_ms() - t_start;
    kill(ctl, SIGKILL);
    waitpid(ctl, NULL, 0);
    rm_rf(scratch);

    qsort(S.lat, (size_t)S.nlat, sizeof S.lat[0], cmp_long);
    long p50 = S.nlat ? S.lat[S.nlat / 2] : 0, p90 = S.nlat ? S.lat[S.nlat * 9 / 10] : 0,
         p99 = S.nlat ? S.lat[S.nlat * 99 / 100] : 0, mx = S.nlat ? S.lat[S.nlat - 1] : 0;
    printf("\nSOAK: cycles=%ld launched=%ld terminations=%ld clean=%ld with-survivors=%ld "
           "survivors=%ld casualties=%ld terminate-errors=%ld wall=%llds\n",
           S.cycles, S.launched, S.terminations, S.clean, S.dirty, S.survivors, S.casualties,
           S.term_err, wall / 1000);
    printf("ESTABLISHED lifecycles: %ld/%ld clean | early cancellations (immediate/creating): "
           "%ld/%ld clean | not established (vacuous): %ld\n",
           S.est_clean, S.established, S.early_clean, S.early, S.not_est);
    for (int a = 0; a < AT_N; a++)
        printf("  at %-11s %ld/%ld clean\n", AT_NAME[a], S.per_point_clean[a], S.per_point[a]);
    printf("ISOLATION: %ld runs, %ld failures\n", S.iso_runs, S.iso_fail);
    printf("LATENCY ms: p50=%ld p90=%ld p99=%ld max=%ld\n", p50, p90, p99, mx);
    for (int i = 0; i < MAXW && PW[i].name; i++)
        printf("  workload %-20s established %4ld clean %4ld\n", PW[i].name, PW[i].est,
               PW[i].clean);
    for (int i = 0; i < MAXW && WS[i].name; i++)
        printf("WATCH %-20s tasks=%4ld events/task=%7.1f reconciliations/task=%7.1f "
               "watcher-cpu/task=%6.2fms\n",
               WS[i].name, WS[i].tasks, (double)WS[i].ev / WS[i].tasks,
               (double)WS[i].scans / WS[i].tasks, (double)WS[i].cpu_ns / 1e6 / WS[i].tasks);
    int fail = S.dirty || S.casualties || S.iso_fail || S.term_err || S.established == 0;
    printf("%s\n", fail ? "SOAK FAILED" : "SOAK PASSED");
    return fail;
}
#else
int main(void) {
    printf("SKIP: macOS-only soak\n");
    return 77;
}
#endif
