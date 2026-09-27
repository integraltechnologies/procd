#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Honest capability establishment regression (Linux, enforced host).
 *
 * Area 3: ENFORCED must be ESTABLISHED per invocation, never inferred from
 * euid==0 + a cgroup2 mount + cgroup.kill. Each case mutates one prerequisite in
 * a child process (its own mount namespace or capability set, so the parent and
 * other tests are unaffected) and asserts procd is conservative:
 *
 *   A. read-only cgroup hierarchy  -> capabilities not ENFORCED, and a
 *      REQUIRE_ENFORCED create is refused (fails closed).
 *   B. euid 0 but no CAP_SETUID    -> capabilities not ENFORCED (the privilege
 *      drop cannot be established), and REQUIRE_ENFORCED is refused.
 *   C. a DOWNGRADED (best-effort) invocation reports honestly: its status
 *      population is not authoritative, and terminating it never claims proven
 *      emptiness or a final EMPTY state (B-1).
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

/* Results a child scenario reports back to the parent. -1 = not attempted. */
typedef struct {
    int setup_ok;    /* the environment mutation succeeded */
    int ptt;         /* capabilities.process_tree_termination */
    int emptiness;   /* capabilities.domain_emptiness_proof */
    int req_rc;      /* status of a REQUIRE_ENFORCED create */
    int be_ok;       /* best-effort create succeeded */
    int be_level;    /* runtime level of the best-effort domain */
    int pop_auth;    /* status.population_is_authoritative on the be domain */
    int empt_proven; /* terminate evidence.emptiness_proven */
    int final;       /* terminate evidence.final_state */
    int enforced;    /* terminate evidence.enforced */
} scen;

static int make_cgroup_readonly(void) {
    if (unshare(CLONE_NEWNS) != 0) return 0;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return 0;
    /* per-mount read-only via bind-remount, so we do not touch the shared
     * cgroup2 superblock (which would affect the parent). */
    if (mount(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) != 0) {
        if (mount(NULL, "/sys/fs/cgroup", "cgroup2", MS_REMOUNT | MS_RDONLY, NULL) != 0) return 0;
    }
    struct statvfs v;
    if (statvfs("/sys/fs/cgroup", &v) != 0) return 0;
    return (v.f_flag & ST_RDONLY) ? 1 : 0;
}

static int drop_cap_setuid(void) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset(&hdr, 0, sizeof hdr);
    memset(data, 0, sizeof data);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &hdr, data) != 0) return 0;
    data[0].effective &= ~(1u << CAP_SETUID);
    data[0].permitted &= ~(1u << CAP_SETUID); /* also drop permitted: cannot be re-raised */
    if (syscall(SYS_capset, &hdr, data) != 0) return 0;
    return 1;
}

/* Run one scenario in a child and collect its results. which: 0=readonly, 1=caps. */
static int run_scenario(int which, scen *out) {
    int pp[2];
    if (pipe(pp) != 0) return -1;
    pid_t ch = fork();
    if (ch == 0) {
        close(pp[0]);
        scen s;
        memset(&s, 0, sizeof s);
        s.setup_ok = which == 0 ? make_cgroup_readonly() : drop_cap_setuid();
        s.req_rc = s.be_ok = s.be_level = s.pop_auth = s.empt_proven = s.final = s.enforced = -1;
        if (s.setup_ok) {
            procd_capabilities c;
            procd_capabilities_probe(&c);
            s.ptt = (int)c.process_tree_termination;
            s.emptiness = (int)c.domain_emptiness_proof;

            procd_policy rp = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
            procd_domain *rd = NULL;
            s.req_rc = (int)procd_create_domain(&rp, &rd);
            if (rd) procd_domain_release(rd);

            /* Case C (caps scenario only): the cgroup is still writable, so a
             * best-effort domain can be made and its reporting inspected. Under a
             * read-only hierarchy the cgroup cannot be created, so skip. */
            if (which == 1) {
                procd_policy bp = PROCD_POLICY_INIT;
                bp.enforcement = PROCD_ALLOW_BEST_EFFORT;
                procd_domain *bd = NULL;
                if (procd_create_domain(&bp, &bd) == PROCD_OK && bd) {
                    s.be_ok = 1;
                    procd_domain_status st;
                    procd_domain_status_get(bd, &st);
                    s.be_level = (int)st.process_tree_termination;
                    s.pop_auth = st.population_is_authoritative;
                    procd_termination_evidence ev;
                    procd_domain_terminate(bd, 3000, &ev);
                    s.empt_proven = ev.emptiness_proven;
                    s.final = (int)ev.final_state;
                    s.enforced = ev.enforced;
                    procd_domain_release(bd);
                } else {
                    s.be_ok = 0;
                }
            }
        }
        ssize_t w = write(pp[1], &s, sizeof s);
        (void)w;
        close(pp[1]);
        _exit(0);
    }
    close(pp[1]);
    ssize_t r = read(pp[0], out, sizeof *out);
    close(pp[0]);
    int wst = 0;
    waitpid(ch, &wst, 0);
    return (r == (ssize_t)sizeof *out) ? 0 : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    /* ---- A: read-only cgroup hierarchy ---- */
    scen ro;
    if (run_scenario(0, &ro) == 0 && ro.setup_ok) {
        printf("   [ro] ptt=%d emptiness=%d req_rc=%d\n", ro.ptt, ro.emptiness, ro.req_rc);
        CHECK(ro.ptt != PROCD_CAP_ENFORCED,
              "A: read-only hierarchy is NOT ENFORCED in capabilities");
        CHECK(ro.emptiness != PROCD_CAP_ENFORCED,
              "A: read-only hierarchy does not claim ENFORCED emptiness proof");
        CHECK(ro.req_rc == PROCD_E_UNSUPPORTED_ENFORCEMENT,
              "A: REQUIRE_ENFORCED refused on a read-only hierarchy");
    } else {
        printf("note: could not make the cgroup hierarchy read-only; skipping case A\n");
    }

    /* ---- B & C: euid 0 without CAP_SETUID ---- */
    scen cap;
    if (run_scenario(1, &cap) == 0 && cap.setup_ok) {
        printf("   [caps] ptt=%d emptiness=%d req_rc=%d be_ok=%d be_level=%d pop_auth=%d "
               "empt_proven=%d final=%d enforced=%d\n",
               cap.ptt, cap.emptiness, cap.req_rc, cap.be_ok, cap.be_level, cap.pop_auth,
               cap.empt_proven, cap.final, cap.enforced);
        /* B: no ENFORCED inferred from euid 0 alone. */
        CHECK(cap.ptt != PROCD_CAP_ENFORCED,
              "B: euid 0 without CAP_SETUID is NOT ENFORCED (not inferred from euid 0 alone)");
        CHECK(cap.req_rc == PROCD_E_UNSUPPORTED_ENFORCEMENT,
              "B: REQUIRE_ENFORCED refused when the privilege drop cannot be established");
        /* C: a downgraded invocation reports honestly. */
        if (cap.be_ok == 1) {
            CHECK(cap.be_level != PROCD_CAP_ENFORCED, "C: best-effort domain is not ENFORCED");
            CHECK(cap.pop_auth == 0, "C: best-effort status population is NOT authoritative (B-1)");
            CHECK(cap.empt_proven == 0,
                  "C: best-effort termination does not claim proven emptiness (B-1)");
            CHECK(cap.final != PROCD_STATE_EMPTY,
                  "C: best-effort termination does not report a final EMPTY state (B-1)");
            CHECK(cap.enforced == 0, "C: best-effort termination is not 'enforced'");
        } else {
            printf(
                "note: best-effort create did not succeed under reduced caps; skipping case C\n");
        }
    } else {
        printf("note: could not drop CAP_SETUID; skipping cases B/C\n");
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all establishment checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only establishment regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
