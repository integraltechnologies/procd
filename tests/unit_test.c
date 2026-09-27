/*
 * Portable unit tests: contract-level invariants that hold on every platform.
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

int main(void) {
    procd_capabilities c;
    CHECK(procd_capabilities_probe(&c) == PROCD_OK, "probe returns OK");
    CHECK(c.backend != NULL && c.backend[0] != 0, "probe reports a backend name");

    /* enum name helpers are total */
    CHECK(strcmp(procd_capability_name(PROCD_CAP_ENFORCED), "ENFORCED") == 0, "cap name ENFORCED");
    CHECK(strcmp(procd_state_name(PROCD_STATE_EMPTY), "EMPTY") == 0, "state name EMPTY");
    CHECK(strcmp(procd_status_name(PROCD_OK), "OK") == 0, "status name OK");
    CHECK(strcmp(procd_recovery_name(PROCD_UNRESOLVED), "UNRESOLVED") == 0,
          "recovery name UNRESOLVED");

    /* argument validation / null-safety */
    CHECK(procd_capabilities_probe(NULL) == PROCD_E_INVALID_ARGUMENT, "probe(NULL) rejected");
    procd_policy vpol = PROCD_POLICY_INIT;
    CHECK(procd_create_domain(&vpol, NULL) == PROCD_E_INVALID_ARGUMENT,
          "create_domain(out=NULL) rejected");

    /* recovery must never fabricate success from a malformed identity */
    procd_recovery_outcome o;
    procd_domain *rd = NULL;
    procd_status rc = procd_recover("garbage", &o, &rd);
    CHECK(o == PROCD_UNRESOLVED, "recover(garbage) is UNRESOLVED (never RECOVERED/DESTROYED)");
    CHECK(rd == NULL, "recover(garbage) yields no domain handle");

    /* A best-effort domain must be creatable everywhere (or explicitly refuse),
     * and must never report a runtime level above what the backend claims. */
    procd_policy pol = PROCD_POLICY_INIT;
    pol.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *d = NULL;
    rc = procd_create_domain(&pol, &d);
    if (rc == PROCD_OK) {
        procd_domain_status st;
        CHECK(procd_domain_status_get(d, &st) == PROCD_OK, "status on fresh domain");
        CHECK(st.state == PROCD_STATE_CREATED, "fresh domain is CREATED");
        CHECK(!(st.process_tree_termination == PROCD_CAP_ENFORCED &&
                c.process_tree_termination != PROCD_CAP_ENFORCED),
              "domain never reports ENFORCED on a non-enforcing host");
        char id[PROCD_IDENTITY_MAX];
        CHECK(procd_domain_identity(d, id, sizeof id) == PROCD_OK, "identity emitted");
        /* The domain is alive right now: recovery may reacquire it or refuse
         * to decide, but must never confirm its destruction. */
        procd_domain *ld = NULL;
        rc = procd_recover(id, &o, &ld);
        CHECK(o != PROCD_CONFIRMED_DESTROYED, "recover(live identity) never CONFIRMED_DESTROYED");
        CHECK((o == PROCD_RECOVERED) == (ld != NULL), "recover handle iff RECOVERED");
        if (ld) {
            procd_domain_status rs;
            procd_domain_status_get(ld, &rs);
            CHECK(rs.process_tree_termination <= st.process_tree_termination,
                  "recovered level never exceeds established level");
            procd_domain_release(ld);
        }
        /* Evidence and status may never be stronger than the capabilities. */
        CHECK(!(st.population_is_authoritative && c.domain_emptiness_proof != PROCD_CAP_ENFORCED),
              "status population authoritative only with ENFORCED emptiness proof");
        procd_termination_evidence ev;
        procd_domain_terminate(d, 2000, &ev);
        CHECK(!(ev.enforced && c.process_tree_termination != PROCD_CAP_ENFORCED),
              "termination never 'enforced' without ENFORCED ProcessTreeTermination");
        CHECK(!(ev.emptiness_proven && c.domain_emptiness_proof != PROCD_CAP_ENFORCED),
              "emptiness never 'proven' without ENFORCED DomainEmptinessProof");
        CHECK(!(ev.final_state == PROCD_STATE_EMPTY && !ev.emptiness_proven),
              "final state EMPTY only with proven emptiness");
        CHECK(procd_domain_release(d) == PROCD_OK, "release OK");
    } else {
        printf("note: best-effort create returned %s (acceptable on this host)\n",
               procd_status_name(rc));
    }

#if defined(_WIN32)
    /* A Job Object keeps ordinary descendants and proves the JOB empty, but the
     * workload can create work outside it (parent-process attribute, brokers,
     * handle duplication): none of the full properties may be claimed, and a
     * duplicated Job handle means controller loss is not automatic destruction. */
    CHECK(c.process_tree_termination == PROCD_CAP_BEST_EFFORT, "windows: aggregate BEST_EFFORT");
    CHECK(c.descendant_containment != PROCD_CAP_ENFORCED,
          "windows: descendant containment not ENFORCED");
    CHECK(c.topology_escape_resistance != PROCD_CAP_ENFORCED,
          "windows: escape resistance not ENFORCED");
    CHECK(c.domain_emptiness_proof != PROCD_CAP_ENFORCED,
          "windows: Job emptiness is not domain emptiness proof");
    CHECK(c.crash_behavior != PROCD_CRASH_AUTOMATIC_DESTRUCTION,
          "windows: KILL_ON_JOB_CLOSE not claimed as automatic destruction");
    CHECK(c.safe_recovery == PROCD_CAP_UNSUPPORTED, "windows: no safe recovery");
#endif

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all unit checks passed", fails);
    return fails ? 1 : 0;
}
