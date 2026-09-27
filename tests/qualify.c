#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Qualification matrix, shared by `procd qualify` and the ctest suite.
 *
 * The matrix distinguishes three outcomes explicitly:
 *   PASS - the claimed guarantee was demonstrated on this host: the scenario's
 *          adversarial precondition was independently OBSERVED (fixture
 *          witnesses, not procd's view), procd proved emptiness, AND the
 *          independent survivor oracle found no witnessed process still running;
 *   SKIP - a prerequisite was unavailable, the precondition was not observed
 *          (e.g. the workload never executed), OR the backend truthfully does not
 *          claim the guarantee; recorded with a reason, never treated as success;
 *   FAIL - the backend claimed a guarantee that was NOT upheld (e.g. a witnessed
 *          process survived enforced termination, or a silent downgrade).
 *
 * Every adversary process is independently bounded (PROCD_ADV_TTL), so a
 * broken implementation cannot leave indefinitely running processes.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "qualify.h"
#include "procd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
static void nap_ms(int ms) {
    Sleep((DWORD)ms);
}
#else
#include "witness.h"
#include <signal.h>
#include <time.h>
static void nap_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}
#endif

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

static q_case *emit(q_case *out, int max, int *n, const char *name) {
    if (*n >= max) return NULL;
    q_case *c = &out[*n];
    (*n)++;
    memset(c, 0, sizeof *c);
    snprintf(c->name, sizeof c->name, "%s", name);
    return c;
}

#if !defined(_WIN32)
#define NEED(cond, msg)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            snprintf(why, wn, "%s", msg);                                                          \
            return 0;                                                                              \
        }                                                                                          \
    } while (0)

/* Did the scenario's adversarial topology independently occur, and is the part
 * that must be running at termination time actually running? */
static int precondition(const char *mode, long spawned, const w_rec *w, int n, char *why,
                        size_t wn) {
    const w_rec *r = w_find(w, n, "root");
    NEED(r, "workload never executed (no root witness)");
    NEED(spawned <= 0 || r->pid == spawned, "root witness is not the spawned process");
    if (!strcmp(mode, "child")) {
        const w_rec *c = w_find(w, n, "child");
        NEED(c && c->pid != r->pid && c->ppid == r->pid, "no child of the root witnessed");
        NEED(w_live(r) && w_live(c), "root/child not running as witnessed");
    } else if (!strcmp(mode, "grandchild")) {
        const w_rec *c = w_find(w, n, "child"), *g = w_find(w, n, "grandchild");
        NEED(c && g && c->pid != r->pid && g->pid != c->pid && c->ppid == r->pid &&
                 g->ppid == c->pid,
             "no grandchild chain witnessed");
        NEED(w_live(c) && w_live(g), "child/grandchild not running as witnessed");
    } else if (!strcmp(mode, "exec")) {
        const w_rec *a = w_find(w, n, "exec-pre"), *b = w_find(w, n, "exec-post");
        NEED(a && b && a->pid != r->pid && a->pid == b->pid && a->ppid == r->pid &&
                 a->start == b->start,
             "exec of a new image not witnessed");
        NEED(w_live(b), "exec'd image not running as witnessed");
        /* the kernel must show the NEW image's argv, i.e. an exec happened */
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
    } else if (!strcmp(mode, "leader-exit")) {
        const w_rec *o = w_find(w, n, "orphan");
        NEED(o && o->pid != r->pid && o->ppid != r->pid, "orphaned descendant not witnessed");
        NEED(!w_alive(r) && w_live(o), "leader not exited / descendant not running as witnessed");
    } else if (!strcmp(mode, "churn")) {
        /* forks racing termination: many distinct children of the root that
         * the kernel confirms are running right now */
        int live = 0;
        for (int i = 0; i < n; i++)
            if (!strcmp(w[i].role, "churn") && w[i].pid != r->pid && w[i].ppid == r->pid &&
                w_live(&w[i]))
                live++;
        NEED(live >= 16, "fewer than 16 live churn children confirmed");
        NEED(w_live(r), "churning root not running as witnessed");
    } else {
        NEED(0, "unknown scenario");
    }
    snprintf(why, wn, "precondition observed");
    return 1;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int survivors(const w_rec *w, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += w_alive(&w[i]);
    return s;
}
#endif

static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    char buf[1024];
    snprintf(buf, sizeof buf, "%s=%s", k, v ? v : "");
    _putenv(buf);
#else
    if (v)
        setenv(k, v, 1);
    else
        unsetenv(k);
#endif
}

/* Run adversary `mode`, terminate the domain, and evaluate the guarantee. */
static void scenario(q_case *c, const char *adv, const char *mode,
                     procd_capability escape_resistance) {
    c->adversarial = 1;
    procd_policy pol = PROCD_POLICY_INIT;
    /* Prefer the strongest establishable level. */
    pol.enforcement = (escape_resistance == PROCD_CAP_ENFORCED) ? PROCD_REQUIRE_ENFORCED
                                                                : PROCD_ALLOW_BEST_EFFORT;

    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    if (rc == PROCD_E_UNSUPPORTED_ENFORCEMENT || rc == PROCD_E_PREREQUISITE ||
        rc == PROCD_E_PERMISSION) {
        c->result = Q_SKIP;
        snprintf(c->detail, sizeof c->detail,
                 "prerequisite unavailable (%s): enforced path not exercised",
                 procd_status_name(rc));
        return;
    }
    if (rc != PROCD_OK) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "create failed: %s", procd_status_name(rc));
        return;
    }

#if defined(_WIN32)
    /* No independent witness on Windows: nothing here can PASS. */
    const char *argv[] = {adv, mode, NULL};
    rc = procd_domain_spawn(d, argv, NULL);
    nap_ms(400);
    procd_termination_evidence ev;
    procd_domain_terminate(d, 8000, &ev);
    c->result = Q_SKIP;
    snprintf(c->detail, sizeof c->detail,
             "no independent precondition witness on this platform; escape-resistance=%s (%s)",
             procd_capability_name(escape_resistance), procd_status_name(rc));
    procd_domain_release(d);
#else
    char wd[64];
    if (w_dir_create(wd, sizeof wd) != 0) {
        c->result = Q_SKIP;
        snprintf(c->detail, sizeof c->detail, "cannot create witness directory");
        procd_domain_release(d);
        return;
    }
    set_env(W_ENV, wd);

    /* Fixtures die of old age after PROCD_ADV_TTL seconds. The survivor oracle
     * only means something if it runs well inside that lifetime: otherwise a
     * termination that merely outlasted the fixtures would look like a kill. */
    const char *ttl_s = getenv("PROCD_ADV_TTL");
    long long ttl_ms = (ttl_s ? atoll(ttl_s) : 20) * 1000;
    long long t0 = mono_ms();
    const char *argv[] = {adv, mode, NULL};
    int64_t pid = -1;
    rc = procd_domain_spawn(d, argv, &pid);
    if (rc != PROCD_OK) {
        c->result = Q_FAIL;
        snprintf(c->detail, sizeof c->detail, "spawn refused/failed: %s", procd_status_name(rc));
        procd_domain_release(d);
        set_env(W_ENV, NULL);
        w_dir_remove(wd);
        return;
    }

    /* Wait (bounded) until the adversarial topology is independently observed. */
    static w_rec w[W_MAX];
    int n = 0, pre = 0;
    char why[128] = "not evaluated";
    for (int i = 0; i < 250 && !pre; i++) {
        nap_ms(20);
        n = w_read(wd, w, W_MAX);
        pre = precondition(mode, (long)pid, w, n, why, sizeof why);
    }

    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 8000, &ev);

    /* Independent survivor oracle over every witnessed process. */
    n = w_read(wd, w, W_MAX);
    int alive = survivors(w, n);
    for (int i = 0; i < 50 && alive; i++) {
        nap_ms(20);
        alive = survivors(w, n);
    }
    long long oracle_age = mono_ms() - t0;
    int oracle_valid = oracle_age + 2000 < ttl_ms;
    for (int i = 0; i < n; i++) /* hygiene: never leave a survivor behind */
        if (w_alive(&w[i])) kill((pid_t)w[i].pid, SIGKILL);

    if (!pre) {
        c->result = Q_SKIP;
        snprintf(c->detail, sizeof c->detail,
                 "PRECONDITION NOT OBSERVED (%s): scenario not exercised", why);
    } else if (!oracle_valid) {
        c->result = Q_SKIP;
        snprintf(c->detail, sizeof c->detail,
                 "ORACLE INCONCLUSIVE: survivors checked %lldms after spawn, too close to the "
                 "%lldms fixture lifetime to distinguish a kill from natural exit",
                 oracle_age, ttl_ms);
    } else if (escape_resistance == PROCD_CAP_ENFORCED) {
        /* Backend claims the hard property: emptiness must be proven AND no
         * witnessed process may still be running. */
        if (rc == PROCD_OK && ev.authority_directed && ev.emptiness_proven &&
            ev.final_state == PROCD_STATE_EMPTY && alive == 0) {
            c->result = Q_PASS;
            snprintf(c->detail, sizeof c->detail,
                     "precondition observed (%d witnessed); emptiness proven; 0 survivors", n);
        } else {
            c->result = Q_FAIL;
            snprintf(c->detail, sizeof c->detail,
                     "claimed ENFORCED but %d witnessed process(es) survive / %s / %s", alive,
                     procd_status_name(rc), ev.detail ? ev.detail : "");
        }
    } else {
        /* Backend does NOT claim escape resistance: known-unsupported probe.
         * Record honestly as SKIP, reporting what the oracle saw. */
        c->result = Q_SKIP;
        snprintf(c->detail, sizeof c->detail,
                 "escape-resistance=%s (not claimed); precondition observed; %d witnessed "
                 "process(es) survived best-effort termination",
                 procd_capability_name(escape_resistance), alive);
    }
    procd_domain_release(d);
    set_env(W_ENV, NULL);
    w_dir_remove(wd);
#endif
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
                 "backend=%s ptt=%s escape=%s emptiness=%s recovery=%s", caps.backend,
                 procd_capability_name(caps.process_tree_termination),
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
            if (rc == PROCD_E_UNSUPPORTED_ENFORCEMENT) {
                fc->result = Q_PASS;
                snprintf(fc->detail, sizeof fc->detail,
                         "REQUIRE_ENFORCED correctly refused on non-enforcing host");
            } else if (rc == PROCD_OK) {
                fc->result = Q_FAIL; /* silent upgrade/downgrade */
                snprintf(fc->detail, sizeof fc->detail,
                         "created a domain despite non-enforcing host");
                procd_domain_release(d);
            } else {
                fc->result = Q_PASS;
                snprintf(fc->detail, sizeof fc->detail, "refused (%s)", procd_status_name(rc));
            }
        } else {
            if (rc == PROCD_OK) {
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
    }

    /* Adversarial termination scenarios. */
    const char *modes[] = {"child",       "grandchild", "exec",        "setsid", "setpgid",
                           "double-fork", "reparent",   "leader-exit", "churn"};
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        q_case *c = emit(out, max, n, modes[i]);
        if (!c) break;
        scenario(c, adv, modes[i], caps.topology_escape_resistance);
    }

    /* Recovery honesty: recover on a stale/malformed identity must never guess. */
    q_case *r1 = emit(out, max, n, "recover-malformed");
    if (r1) {
        procd_recovery_outcome o;
        procd_domain *rd = NULL;
        procd_status rc = procd_recover("not-a-valid-identity", &o, &rd);
        /* A malformed token proves nothing about any domain: the only honest
         * outcome is UNRESOLVED (CONFIRMED_DESTROYED would be a guess). */
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

    int fails = 0;
    for (int i = 0; i < *n; i++)
        if (out[i].result == Q_FAIL) fails++;
    return fails;
}

int procd_qualify_enforced_verdict(const q_case *cases, int n, char *why, size_t wn) {
    procd_capabilities caps;
    procd_capabilities_probe(&caps);
    if (caps.process_tree_termination != PROCD_CAP_ENFORCED) {
        snprintf(why, wn, "ProcessTreeTermination is %s, not ENFORCED (%s)",
                 procd_capability_name(caps.process_tree_termination), caps.detail);
        return 1;
    }
    int adversarial = 0;
    for (int i = 0; i < n; i++) {
        if (cases[i].result == Q_FAIL) {
            snprintf(why, wn, "case '%s' FAILED", cases[i].name);
            return 1;
        }
        if (cases[i].adversarial) {
            adversarial++;
            if (cases[i].result != Q_PASS) {
                snprintf(why, wn, "adversarial scenario '%s' did not PASS (%s)", cases[i].name,
                         q_result_name(cases[i].result));
                return 1;
            }
        }
    }
    if (adversarial == 0) {
        snprintf(why, wn, "no adversarial scenario ran");
        return 1;
    }
    snprintf(why, wn, "all %d adversarial scenarios PASSED with observed preconditions",
             adversarial);
    return 0;
}
