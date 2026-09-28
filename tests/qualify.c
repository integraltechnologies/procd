#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Qualification matrix, shared by `procd qualify` and the ctest suite, on
 * Linux, macOS and Windows.
 *
 * Each lifecycle scenario runs a bounded fixture topology inside a domain,
 * waits until that topology is independently OBSERVED (fixture witnesses cross-
 * checked against the kernel, never procd's own view), checks that status does
 * not call the domain empty, terminates the domain, and judges the result with
 * an independent survivor oracle over (pid, start time):
 *
 *   PASS - the topology was witnessed, termination returned success within its
 *          bound, and no witnessed process is still running. A backend that
 *          reports ENFORCED must additionally prove emptiness (final EMPTY).
 *   SKIP - a prerequisite was unavailable, the topology was not observed (e.g.
 *          the workload never executed), or the oracle ran too close to the
 *          fixtures' natural lifetime to tell a kill from an exit. Never success.
 *   FAIL - a witnessed ordinary task process survived termination, termination
 *          failed or overran its bound, status claimed emptiness while a task
 *          process ran, or an ENFORCED claim was not upheld.
 *
 * Survivors of ORDINARY topology are a FAIL at every capability level: the
 * matrix measures whether procd actually cleans up the task, not merely whether
 * the reported level is honest. Probes of documented residual limitations are
 * reported separately (q_case.residual) and never counted as requirements.
 *
 * Every fixture process is independently bounded (PROCD_ADV_TTL), so a broken
 * implementation cannot leave indefinitely running processes.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "qualify.h"
#include "procd.h"
#include "witness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static void nap_ms(int ms) {
    Sleep((DWORD)ms);
}
static long long mono_ms(void) {
    return (long long)GetTickCount64();
}
#else
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static void nap_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

#define WD_MAX 300
#define TERM_TIMEOUT_MS 8000
#define TERM_SLACK_MS 2000

const char *q_result_name(q_result r) {
    switch (r) {
    case Q_PASS:
        return "PASS";
    case Q_FAIL:
        return "FAIL";
    case Q_SKIP:
        return "SKIP";
    }
    return "?";
}

int procd_qualify_strict(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    return v && strcmp(v, "1") == 0;
}

int procd_qualify_require_cleanup(void) {
    const char *v = getenv("PROCD_REQUIRE_CLEANUP");
    return v && strcmp(v, "1") == 0;
}

/* progress on stderr, so a stuck scenario is visible while the matrix runs */
static void progress(const q_case *c) {
    if (c) fprintf(stderr, "  ... %-18s %s\n", c->name, q_result_name(c->result));
}

static q_case *emit(q_case *out, int max, int *n, const char *name) {
    if (*n > 0) progress(&out[*n - 1]);
    if (*n >= max) return NULL;
    q_case *c = &out[*n];
    (*n)++;
    memset(c, 0, sizeof *c);
    snprintf(c->name, sizeof c->name, "%s", name);
    return c;
}

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

static long long ttl_ms(void) {
    const char *t = getenv("PROCD_ADV_TTL");
    long long v = t ? atoll(t) : 20;
    return (v > 0 ? v : 20) * 1000;
}

/* An unrelated same-user fixture started OUTSIDE procd with its own witnesses. */
typedef struct {
#if defined(_WIN32)
    HANDLE h;
#else
    pid_t pid;
#endif
    char wd[WD_MAX];
} unrelated;

static int unrelated_start(unrelated *u, const char *adv, const char *mode) {
    memset(u, 0, sizeof *u);
    if (w_dir_create(u->wd, sizeof u->wd) != 0) return 0;
#if defined(_WIN32)
    char *old = getenv(W_ENV) ? _strdup(getenv(W_ENV)) : NULL;
    set_env(W_ENV, u->wd);
    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof cmd, "\"%s\" %s", adv, mode);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    set_env(W_ENV, old);
    free(old);
    if (!ok) return 0;
    CloseHandle(pi.hThread);
    u->h = pi.hProcess;
    return 1;
#else
    pid_t p = fork();
    if (p == 0) {
        setenv(W_ENV, u->wd, 1);
        execl(adv, adv, mode, (char *)NULL);
        _exit(127);
    }
    u->pid = p;
    return p > 0;
#endif
}

static void unrelated_stop(unrelated *u) {
    static w_rec w[W_MAX];
    int n = w_read(u->wd, w, W_MAX);
    for (int i = 0; i < n; i++)
        w_kill(&w[i]);
#if defined(_WIN32)
    if (u->h) {
        TerminateProcess(u->h, 0);
        CloseHandle(u->h);
    }
#else
    if (u->pid > 0) {
        kill(u->pid, SIGKILL);
        waitpid(u->pid, NULL, 0);
    }
#endif
    w_dir_remove(u->wd);
}

/* all witnessed processes of an unrelated fixture still running? */
static int all_alive(const char *wd, int *count) {
    static w_rec w[W_MAX];
    int n = w_read(wd, w, W_MAX), live = 0;
    for (int i = 0; i < n; i++)
        live += w_alive(&w[i]);
    *count = n;
    return n > 0 && live == n;
}

#define NEED(cond, msg)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            snprintf(why, wn, "%s", msg);                                                          \
            return 0;                                                                              \
        }                                                                                          \
    } while (0)

static int live_children(const w_rec *w, int n, const char *role, long parent) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (!strcmp(w[i].role, role) && w[i].ppid == parent && w_live(&w[i])) c++;
    return c;
}

/* Did the scenario's topology independently occur, and is the part that must be
 * running at termination time actually running? */
static int precondition(const char *mode, long spawned, const w_rec *w, int n, char *why,
                        size_t wn) {
    const w_rec *r = w_find(w, n, "root");
    NEED(r, "workload never executed (no root witness)");
    NEED(spawned <= 0 || r->pid == spawned, "root witness is not the spawned process");
    if (!strcmp(mode, "exit")) {
        NEED(!w_alive(r), "finished task still running");
    } else if (!strcmp(mode, "child")) {
        const w_rec *c = w_find(w, n, "child");
        NEED(c && c->pid != r->pid && c->ppid == r->pid, "no child of the root witnessed");
        NEED(w_live(r) && w_live(c), "root/child not running as witnessed");
    } else if (!strcmp(mode, "grandchild")) {
        const w_rec *c = w_find(w, n, "child"), *g = w_find(w, n, "grandchild");
        NEED(c && g && c->pid != r->pid && g->pid != c->pid && c->ppid == r->pid &&
                 g->ppid == c->pid,
             "no grandchild chain witnessed");
        NEED(w_live(c) && w_live(g), "child/grandchild not running as witnessed");
    } else if (!strcmp(mode, "multi")) {
        int kids = live_children(w, n, "multi-child", r->pid), grand = 0;
        for (int i = 0; i < n; i++)
            if (!strcmp(w[i].role, "multi-child") && w[i].ppid == r->pid)
                grand += live_children(w, n, "multi-grandchild", w[i].pid);
        NEED(kids >= 4 && grand >= 4, "4 live children each with a live grandchild not witnessed");
    } else if (!strcmp(mode, "leader-exit")) {
        const w_rec *o = w_find(w, n, "orphan");
#if defined(_WIN32)
        NEED(o && o->pid != r->pid && o->ppid == r->pid, "descendant of the leader not witnessed");
#else
        NEED(o && o->pid != r->pid && o->ppid != r->pid, "orphaned descendant not witnessed");
#endif
        NEED(!w_alive(r) && w_live(o), "leader not exited / descendant not running as witnessed");
    } else if (!strcmp(mode, "background")) {
        const w_rec *b = w_find(w, n, "bg");
        NEED(b && b->pid != r->pid && b->ppid != r->pid,
             "shell background job (parent != root) not witnessed");
#if defined(_WIN32)
        NEED(w_live(b) && w_live(r), "background job / root not running as witnessed");
#else
        NEED(!w_alive(r) && w_live(b), "shell not exited / background job not running");
#endif
    } else if (!strcmp(mode, "churn")) {
        /* process creation racing termination: many distinct live children */
        int live = live_children(w, n, "churn", r->pid);
        NEED(live >= 16, "fewer than 16 live churn children confirmed");
        NEED(w_live(r), "churning root not running as witnessed");
#if defined(_WIN32)
    } else if (!strcmp(mode, "detached")) {
        const w_rec *d = w_find(w, n, "detached");
        NEED(d && d->ppid == r->pid,
             "DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP child not witnessed");
        NEED(w_live(d), "detached child not running as witnessed");
    } else if (!strcmp(mode, "double-fork")) {
        const w_rec *m = w_find(w, n, "df-middle"), *g = w_find(w, n, "df-grandchild");
        NEED(m && g && m->ppid == r->pid && g->ppid == m->pid,
             "detached middle + detached grandchild not witnessed");
        NEED(!w_alive(m) && w_live(g), "middle not exited / grandchild not running as witnessed");
    } else if (!strcmp(mode, "breakaway-request")) {
        const w_rec *b = w_find(w, n, "breakaway"), *f = w_find(w, n, "breakaway-fallback");
        NEED(b || f, "breakaway request outcome not witnessed");
        NEED(w_live(b ? b : f), "requested child not running as witnessed");
        snprintf(why, wn, "%s", b ? "breakaway was GRANTED" : "breakaway refused; fell back");
        return 1;
#else
    } else if (!strcmp(mode, "exec")) {
        const w_rec *a = w_find(w, n, "exec-pre"), *b = w_find(w, n, "exec-post");
        NEED(a && b && a->pid != r->pid && a->pid == b->pid && a->ppid == r->pid &&
                 a->start == b->start,
             "exec of a new image not witnessed");
        NEED(w_live(b), "exec'd image not running as witnessed");
        NEED(w_cmdline_has(b->pid, "exec-post") != 0, "kernel shows no exec of a new image");
    } else if (!strcmp(mode, "setsid")) {
        const w_rec *s = w_find(w, n, "setsid");
        NEED(s && s->pid != r->pid && s->ppid == r->pid && s->sid == s->pid && s->sid != r->sid,
             "new session not witnessed");
        NEED(w_live(s) && w_live(r), "setsid child not running as witnessed");
    } else if (!strcmp(mode, "setpgid")) {
        const w_rec *s = w_find(w, n, "setpgid");
        NEED(s && s->pid != r->pid && s->ppid == r->pid && s->pgid == s->pid &&
                 s->pgid != r->pgid && s->sid == r->sid,
             "new process group not witnessed");
        NEED(w_live(s) && w_live(r), "setpgid child not running as witnessed");
    } else if (!strcmp(mode, "double-fork")) {
        const w_rec *m = w_find(w, n, "df-middle"), *g = w_find(w, n, "df-grandchild");
        NEED(m && g && m->pid != r->pid && g->pid != m->pid && m->ppid == r->pid &&
                 m->sid == m->pid && m->sid != r->sid && g->sid == m->pid && g->ppid != m->pid,
             "setsid + double-fork + reparent not witnessed");
        NEED(!w_alive(m) && w_live(g), "middle not exited / daemon not running as witnessed");
    } else if (!strcmp(mode, "reparent")) {
        const w_rec *m = w_find(w, n, "rp-middle"), *g = w_find(w, n, "rp-grandchild");
        NEED(m && g && m->pid != r->pid && g->pid != m->pid && m->ppid == r->pid &&
                 g->ppid != m->pid,
             "reparented grandchild not witnessed");
        NEED(!w_alive(m) && w_live(g), "middle not exited / grandchild not running as witnessed");
    } else if (!strcmp(mode, "env-clear")) {
        const w_rec *c = w_find(w, n, "clean-child"), *g = w_find(w, n, "clean-grandchild");
        NEED(c && g && c->ppid == r->pid && g->ppid == c->pid,
             "environment-less child + grandchild not witnessed");
        NEED(w_live(c) && w_live(g), "environment-less descendants not running as witnessed");
    } else if (!strcmp(mode, "env-clear-daemon")) {
        const w_rec *d = w_find(w, n, "clean-daemon");
        NEED(d && d->ppid != r->pid && d->sid != r->sid,
             "environment-less, re-sessioned, reparented daemon not witnessed");
        NEED(w_live(d), "environment-less daemon not running as witnessed");
#endif
    } else {
        NEED(0, "unknown scenario");
    }
    snprintf(why, wn, "precondition observed");
    return 1;
}

static int survivors(const w_rec *w, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += w_alive(&w[i]);
    return s;
}

static int domain_policy(procd_policy *pol) {
    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    *pol = (procd_policy)PROCD_POLICY_INIT;
    pol->enforcement = caps.process_tree_termination == PROCD_CAP_ENFORCED
                           ? PROCD_REQUIRE_ENFORCED
                           : PROCD_ALLOW_BEST_EFFORT;
    return caps.process_tree_termination;
}

/* A running scenario: domain + witnessed topology. */
typedef struct {
    procd_domain *d;
    char wd[WD_MAX];
    long long t0;
    int64_t pid;
    int pre;
    char why[160];
    int finished;    /* the workload is expected to have exited already */
    int skip;        /* prerequisite unavailable */
    procd_status rc; /* create/spawn status */
} run;

/* Create a domain, spawn `mode`, and wait (bounded) for its topology. */
static void run_start(run *x, const char *adv, const char *mode) {
    memset(x, 0, sizeof *x);
    x->finished = !strcmp(mode, "exit");
    procd_policy pol;
    domain_policy(&pol);
    x->rc = procd_create_domain(&pol, &x->d);
    if (x->rc == PROCD_E_UNSUPPORTED_ENFORCEMENT || x->rc == PROCD_E_PREREQUISITE ||
        x->rc == PROCD_E_PERMISSION) {
        x->skip = 1;
        snprintf(x->why, sizeof x->why, "prerequisite unavailable (%s)", procd_status_name(x->rc));
        x->d = NULL;
        return;
    }
    if (x->rc != PROCD_OK) {
        snprintf(x->why, sizeof x->why, "create failed: %s", procd_status_name(x->rc));
        x->d = NULL;
        return;
    }
    if (w_dir_create(x->wd, sizeof x->wd) != 0) {
        x->skip = 1;
        snprintf(x->why, sizeof x->why, "cannot create witness directory");
        return;
    }
    set_env(W_ENV, x->wd);
    x->t0 = mono_ms();
    const char *argv[] = {adv, mode, NULL};
    x->rc = procd_domain_spawn(x->d, argv, &x->pid);
    set_env(W_ENV, NULL);
    if (x->rc != PROCD_OK) {
        snprintf(x->why, sizeof x->why, "spawn refused/failed: %s", procd_status_name(x->rc));
        return;
    }
    static w_rec w[W_MAX];
    for (int i = 0; i < 300 && !x->pre; i++) {
        nap_ms(20);
        int n = w_read(x->wd, w, W_MAX);
        x->pre = precondition(mode, (long)x->pid, w, n, x->why, sizeof x->why);
    }
}

typedef struct {
    int witnessed, alive, status_lied, oracle_valid, bound_ok, post_status_ok;
    procd_population pre_pop;
    long long term_ms;
    procd_status rc;
    procd_termination_evidence ev;
    procd_capability level;
} outcome;

/* Terminate a started run and collect every fact the verdict needs. */
static void run_finish(run *x, int timeout_ms, outcome *o) {
    memset(o, 0, sizeof *o);
    static w_rec w[W_MAX];
    procd_domain_status st;
    if (procd_domain_status_get(x->d, &st) == PROCD_OK) {
        o->level = st.process_tree_termination;
        o->pre_pop = st.population;
        /* a witnessed task process is running: "empty" here would be a lie */
        o->status_lied = x->pre && !x->finished && st.population == PROCD_POP_EMPTY;
    }
    long long t = mono_ms();
    o->rc = procd_domain_terminate(x->d, timeout_ms, &o->ev);
    o->term_ms = mono_ms() - t;
    o->bound_ok = o->term_ms <= timeout_ms + TERM_SLACK_MS;

    int n = w_read(x->wd, w, W_MAX);
    o->witnessed = n;
    o->alive = survivors(w, n);
    for (int i = 0; i < 50 && o->alive; i++) {
        nap_ms(20);
        o->alive = survivors(w, n);
    }
    o->oracle_valid = mono_ms() - x->t0 + 2000 < ttl_ms();
    o->post_status_ok =
        procd_domain_status_get(x->d, &st) == PROCD_OK && st.population != PROCD_POP_POPULATED;
    for (int i = 0; i < n; i++) /* hygiene: never leave a survivor behind */
        w_kill(&w[i]);
}

static void run_release(run *x) {
    if (x->d) procd_domain_release(x->d);
    if (x->wd[0]) w_dir_remove(x->wd);
    x->d = NULL;
    x->wd[0] = 0;
}

/* Judge a finished run into `c`. */
static void judge(q_case *c, const run *x, const outcome *o) {
    char *d = c->detail;
    size_t dn = sizeof c->detail;
    if (!x->pre) {
        c->result = Q_SKIP;
        snprintf(d, dn,
                 "PRECONDITION NOT OBSERVED (%.100s): scenario not exercised [terminate %s in "
                 "%lldms: %.60s]",
                 x->why, procd_status_name(o->rc), o->term_ms, o->ev.detail ? o->ev.detail : "");
    } else if (!o->oracle_valid) {
        c->result = Q_SKIP;
        snprintf(d, dn, "ORACLE INCONCLUSIVE: too close to the fixture lifetime");
    } else if (o->alive) {
        c->result = Q_FAIL;
        snprintf(d, dn, "%d of %d witnessed task process(es) SURVIVED termination (%s: %s)",
                 o->alive, o->witnessed, procd_status_name(o->rc),
                 o->ev.detail ? o->ev.detail : "");
    } else if (o->status_lied) {
        c->result = Q_FAIL;
        snprintf(d, dn, "status reported the domain EMPTY while witnessed processes ran");
    } else if (o->rc != PROCD_OK) {
        c->result = Q_FAIL;
        snprintf(d, dn, "terminate returned %s: %s", procd_status_name(o->rc),
                 o->ev.detail ? o->ev.detail : "");
    } else if (!o->bound_ok) {
        c->result = Q_FAIL;
        snprintf(d, dn, "termination took %lldms, over its bound", o->term_ms);
    } else if (!o->post_status_ok) {
        c->result = Q_FAIL;
        snprintf(d, dn, "status still POPULATED after successful termination");
    } else if (o->level == PROCD_CAP_ENFORCED &&
               !(o->ev.authority_directed && o->ev.emptiness_proven &&
                 o->ev.final_state == PROCD_STATE_EMPTY)) {
        c->result = Q_FAIL;
        snprintf(d, dn, "claimed ENFORCED but emptiness was not proven (%s)",
                 o->ev.detail ? o->ev.detail : "");
    } else {
        c->result = Q_PASS;
        snprintf(d, dn, "%s; %d witnessed, 0 survivors; terminated in %lldms (level %s%s)", x->why,
                 o->witnessed, o->term_ms, procd_capability_name(o->level),
                 o->ev.emptiness_proven ? ", emptiness proven" : "");
    }
}

static void scenario(q_case *c, const char *adv, const char *mode, int timeout_ms,
                     int deadline_ms) {
    c->adversarial = 1;
    run x;
    run_start(&x, adv, mode);
    if (!x.d || x.rc != PROCD_OK || x.skip) {
        c->result = x.skip ? Q_SKIP : Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "%s", x.why);
        if (x.d && x.rc != PROCD_OK) {
            procd_termination_evidence ev;
            procd_domain_terminate(x.d, 2000, &ev);
        }
        run_release(&x);
        return;
    }
    if (deadline_ms > 0) nap_ms(deadline_ms); /* the task runs until its deadline */
    outcome o;
    run_finish(&x, timeout_ms, &o);
    judge(c, &x, &o);
    run_release(&x);
}

/* A task that already finished: status must say so and cleanup must be quick
 * (agentctl terminates every task, including ones that completed normally). */
static void finished_task(q_case *c, const char *adv) {
    c->adversarial = 1;
    run x;
    run_start(&x, adv, "exit");
    if (!x.d || x.rc != PROCD_OK || x.skip) {
        c->result = x.skip ? Q_SKIP : Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "%s", x.why);
        run_release(&x);
        return;
    }
    outcome o;
    run_finish(&x, TERM_TIMEOUT_MS, &o);
    judge(c, &x, &o);
    if (c->result == Q_PASS && o.pre_pop == PROCD_POP_POPULATED) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "status POPULATED although the task had finished");
    } else if (c->result == Q_PASS && o.term_ms > 1000) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "cleanup of a finished task took %lldms", o.term_ms);
    }
    run_release(&x);
}

/* A probe of a documented residual limitation: reported, never required. */
static void residual(q_case *c, const char *adv, const char *mode) {
    scenario(c, adv, mode, TERM_TIMEOUT_MS, 0);
    c->adversarial = 0;
    c->residual = 1;
    if (c->result == Q_FAIL) {
        c->result = Q_SKIP;
        char tmp[256];
        snprintf(tmp, sizeof tmp, "KNOWN RESIDUAL reproduced: %.200s", c->detail);
        snprintf(c->detail, sizeof c->detail, "%s", tmp);
    }
}

/* Repeated create/spawn/terminate cycles on fresh domains. */
static void repeat_cycles(q_case *c, const char *adv, const char *mode, int cycles) {
    c->adversarial = 1;
    int pass = 0;
    long long worst = 0;
    for (int i = 0; i < cycles; i++) {
        q_case one;
        memset(&one, 0, sizeof one);
        run x;
        run_start(&x, adv, mode);
        if (!x.d || x.rc != PROCD_OK || x.skip) {
            c->result = x.skip ? Q_SKIP : Q_FAIL;
            snprintf(c->detail, sizeof c->detail, "cycle %d: %s", i, x.why);
            run_release(&x);
            return;
        }
        outcome o;
        run_finish(&x, TERM_TIMEOUT_MS, &o);
        judge(&one, &x, &o);
        run_release(&x);
        if (o.term_ms > worst) worst = o.term_ms;
        if (one.result != Q_PASS) {
            c->result = one.result;
            snprintf(c->detail, sizeof c->detail, "cycle %d/%d: %.200s", i + 1, cycles, one.detail);
            return;
        }
        pass++;
    }
    c->result = Q_PASS;
    snprintf(c->detail, sizeof c->detail,
             "%d/%d %s cycles cleaned up with 0 survivors; slowest termination %lldms", pass,
             cycles, mode, worst);
}

/* A failed spawn must not kill (or detach supervision from) the running task. */
static void spawn_failure(q_case *c, const char *adv) {
    c->adversarial = 1;
    run x;
    run_start(&x, adv, "grandchild");
    if (!x.d || x.rc != PROCD_OK || x.skip || !x.pre) {
        c->result = (x.skip || (x.d && x.rc == PROCD_OK && !x.pre)) ? Q_SKIP : Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "%s", x.why);
        if (x.d && x.rc == PROCD_OK) {
            outcome o;
            run_finish(&x, TERM_TIMEOUT_MS, &o);
        }
        run_release(&x);
        return;
    }
    const char *bad[] = {
#if defined(_WIN32)
        "C:\\procd-no-such-dir\\procd-no-such-program.exe",
#else
        "/nonexistent/procd-no-such-program",
#endif
        NULL};
    int64_t bp = -1;
    procd_status brc = procd_domain_spawn(x.d, bad, &bp);
    nap_ms(300);
    static w_rec w[W_MAX];
    int n = w_read(x.wd, w, W_MAX), alive = survivors(w, n);
    char why[160];
    int still = precondition("grandchild", (long)x.pid, w, n, why, sizeof why);
    outcome o;
    run_finish(&x, TERM_TIMEOUT_MS, &o);
    if (brc == PROCD_OK) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "spawn of a nonexistent program reported OK");
    } else if (!still || alive != n) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail,
                 "failed spawn (%s) disturbed the running task: %d/%d alive",
                 procd_status_name(brc), alive, n);
    } else {
        judge(c, &x, &o);
        if (c->result == Q_PASS) {
            char tmp[256];
            snprintf(tmp, sizeof tmp,
                     "failed spawn returned %s; running task untouched (%d alive); then "
                     "cleaned up with 0 survivors",
                     procd_status_name(brc), n);
            snprintf(c->detail, sizeof c->detail, "%s", tmp);
        }
    }
    run_release(&x);
}

/* Terminating one task must not touch another task's domain or unrelated work. */
static void isolation(q_case *c, const char *adv) {
    c->adversarial = 1;
    const char *mode_a = "double-fork";
    run a, b;
    unrelated u;
    run_start(&a, adv, mode_a);
    run_start(&b, adv, "grandchild");
    int ustarted = unrelated_start(&u, adv, "grandchild");
    int ucount = 0;
    for (int i = 0; i < 250 && ustarted; i++) {
        static w_rec w[W_MAX];
        char why[160];
        int n = w_read(u.wd, w, W_MAX);
        if (precondition("grandchild", -1, w, n, why, sizeof why)) break;
        nap_ms(20);
    }
    if (!a.d || !b.d || a.skip || b.skip || a.rc != PROCD_OK || b.rc != PROCD_OK || !a.pre ||
        !b.pre || !ustarted || !all_alive(u.wd, &ucount) || ucount < 3) {
        c->result = (a.skip || b.skip) ? Q_SKIP : Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "setup: A=%.100s | B=%.100s | unrelated=%d/%d", a.why,
                 b.why, ustarted, ucount);
        if (a.d && a.rc == PROCD_OK) {
            outcome o;
            run_finish(&a, TERM_TIMEOUT_MS, &o);
        }
        if (b.d && b.rc == PROCD_OK) {
            outcome o;
            run_finish(&b, TERM_TIMEOUT_MS, &o);
        }
        run_release(&a);
        run_release(&b);
        if (ustarted) unrelated_stop(&u);
        return;
    }
    outcome oa, ob;
    run_finish(&a, TERM_TIMEOUT_MS, &oa);
    nap_ms(300);
    int b_count = 0, u_count = 0;
    int b_ok = all_alive(b.wd, &b_count);
    int u_ok = all_alive(u.wd, &u_count);
    procd_domain_status bst;
    int b_status =
        procd_domain_status_get(b.d, &bst) == PROCD_OK && bst.population == PROCD_POP_POPULATED;
    run_finish(&b, TERM_TIMEOUT_MS, &ob);
    judge(c, &a, &oa);
    if (c->result == Q_PASS) {
        q_case cb;
        memset(&cb, 0, sizeof cb);
        judge(&cb, &b, &ob);
        if (!b_ok || !u_ok || !b_status) {
            c->result = Q_FAIL;
            snprintf(c->detail, sizeof c->detail,
                     "terminating task A affected others: task B %s (%d witnessed, status %s), "
                     "unrelated %s (%d witnessed)",
                     b_ok ? "intact" : "HIT", b_count, b_status ? "populated" : "WRONG",
                     u_ok ? "intact" : "HIT", u_count);
        } else if (cb.result != Q_PASS) {
            c->result = cb.result;
            snprintf(c->detail, sizeof c->detail, "task B afterwards: %.200s", cb.detail);
        } else {
            snprintf(c->detail, sizeof c->detail,
                     "task A (%s) cleaned; concurrent task B (%d procs) and unrelated same-user "
                     "tree (%d procs) untouched; then task B cleaned",
                     mode_a, b_count, u_count);
        }
    }
    run_release(&a);
    run_release(&b);
    unrelated_stop(&u);
}

int procd_qualify_run(const char *adv, q_case *out, int max, int *n) {
    *n = 0;
    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    if (!getenv("PROCD_ADV_TTL")) set_env("PROCD_ADV_TTL", "20");

    /* Case 0: report probe (informational, always PASS). */
    q_case *p = emit(out, max, n, "probe");
    if (p) {
        p->result = Q_PASS;
        snprintf(p->detail, sizeof p->detail,
                 "backend=%s ptt=%s descendants=%s escape=%s emptiness=%s recovery=%s",
                 caps.backend, procd_capability_name(caps.process_tree_termination),
                 procd_capability_name(caps.descendant_containment),
                 procd_capability_name(caps.topology_escape_resistance),
                 procd_capability_name(caps.domain_emptiness_proof),
                 procd_capability_name(caps.safe_recovery));
    }

    /* Case 1: fail-closed. If the backend cannot enforce, REQUIRE_ENFORCED must
     * be refused (never silently downgraded). If it can enforce, SKIP. */
    q_case *fc = emit(out, max, n, "fail-closed");
    if (fc) {
        procd_policy pol = PROCD_POLICY_INIT;
        pol.enforcement = PROCD_REQUIRE_ENFORCED;
        procd_domain *d = NULL;
        procd_status rc = procd_create_domain(&pol, &d);
        if (caps.process_tree_termination != PROCD_CAP_ENFORCED) {
            if (rc == PROCD_OK) {
                fc->result = Q_FAIL; /* silent upgrade/downgrade */
                snprintf(fc->detail, sizeof fc->detail,
                         "created a domain despite non-enforcing host");
                procd_domain_release(d);
            } else {
                fc->result = Q_PASS;
                snprintf(fc->detail, sizeof fc->detail, "REQUIRE_ENFORCED refused (%s)",
                         procd_status_name(rc));
            }
        } else if (rc == PROCD_OK) {
            fc->result = Q_SKIP;
            snprintf(fc->detail, sizeof fc->detail,
                     "host supports enforcement; refusal path not exercised");
            procd_domain_release(d);
        } else {
            fc->result = Q_FAIL;
            snprintf(fc->detail, sizeof fc->detail, "enforcing host unexpectedly refused: %s",
                     procd_status_name(rc));
        }
    }

    /* Ordinary task topologies. */
    const char *modes[] = {"child",    "grandchild",  "leader-exit",       "background", "multi",
#if defined(_WIN32)
                           "detached", "double-fork", "breakaway-request",
#else
                           "exec",      "setsid",     "setpgid",     "double-fork", "reparent",
                           "env-clear",
#endif
                           "churn"};
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        q_case *c = emit(out, max, n, modes[i]);
        if (!c) break;
        scenario(c, adv, modes[i], TERM_TIMEOUT_MS, 0);
    }

    /* Timeout-style cancellation: the task runs to its deadline, then is torn
     * down with a short termination budget. */
    q_case *fin = emit(out, max, n, "finished-task");
    if (fin) finished_task(fin, adv);

    q_case *to = emit(out, max, n, "timeout");
    if (to) scenario(to, adv, "multi", 3000, 1000);

    q_case *rp = emit(out, max, n, "repeat-x10");
    if (rp) repeat_cycles(rp, adv, "double-fork", 10);

    q_case *sf = emit(out, max, n, "spawn-failure");
    if (sf) spawn_failure(sf, adv);

    q_case *iso = emit(out, max, n, "isolation");
    if (iso) isolation(iso, adv);

#if !defined(_WIN32)
    /* Documented residual: a descendant that discards its whole environment
     * AND detaches from the tree before procd observes it. */
    q_case *res = emit(out, max, n, "env-clear-daemon");
    if (res) residual(res, adv, "env-clear-daemon");
#endif

    /* Recovery honesty: recover on a stale/malformed identity must never guess. */
    q_case *r1 = emit(out, max, n, "recover-malformed");
    if (r1) {
        procd_recovery_outcome o;
        procd_domain *rd = NULL;
        procd_status rc = procd_recover("not-a-valid-identity", &o, &rd);
        if (o == PROCD_UNRESOLVED && rd == NULL) {
            r1->result = Q_PASS;
            snprintf(r1->detail, sizeof r1->detail, "no guessing: %s/%s", procd_status_name(rc),
                     procd_recovery_name(o));
        } else {
            r1->result = Q_FAIL;
            snprintf(r1->detail, sizeof r1->detail, "malformed identity yielded %s",
                     procd_recovery_name(o));
            if (rd) procd_domain_release(rd);
        }
    }

    if (*n > 0) progress(&out[*n - 1]);
    int fails = 0;
    for (int i = 0; i < *n; i++)
        if (out[i].result == Q_FAIL) fails++;
    return fails;
}

static int all_adversarial_pass(const q_case *cases, int n, char *why, size_t wn) {
    int adversarial = 0;
    for (int i = 0; i < n; i++) {
        if (cases[i].result == Q_FAIL) {
            snprintf(why, wn, "case '%s' FAILED", cases[i].name);
            return 1;
        }
        if (cases[i].adversarial) {
            adversarial++;
            if (cases[i].result != Q_PASS) {
                snprintf(why, wn, "lifecycle scenario '%s' did not PASS (%s)", cases[i].name,
                         q_result_name(cases[i].result));
                return 1;
            }
        }
    }
    if (adversarial == 0) {
        snprintf(why, wn, "no lifecycle scenario ran");
        return 1;
    }
    snprintf(why, wn, "all %d lifecycle scenarios PASSED with observed preconditions", adversarial);
    return 0;
}

int procd_qualify_practical_verdict(const q_case *cases, int n, char *why, size_t wn) {
    return all_adversarial_pass(cases, n, why, wn);
}

int procd_qualify_enforced_verdict(const q_case *cases, int n, char *why, size_t wn) {
    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    if (caps.process_tree_termination != PROCD_CAP_ENFORCED) {
        snprintf(why, wn, "ProcessTreeTermination is %s, not ENFORCED (%s)",
                 procd_capability_name(caps.process_tree_termination), caps.detail);
        return 1;
    }
    return all_adversarial_pass(cases, n, why, wn);
}
