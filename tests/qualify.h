/* Shared qualification harness. SPDX-License-Identifier: MPL-2.0 */
#ifndef PROCD_QUALIFY_H
#define PROCD_QUALIFY_H
#include <stddef.h>

typedef enum { Q_PASS = 0, Q_FAIL = 1, Q_SKIP = 2 } q_result;
typedef struct {
    char name[64];
    q_result result;
    int adversarial; /* a lifecycle scenario that must clean up (vs. probe/policy checks) */
    int residual;    /* a probe of a documented residual limitation; never a requirement */
    char detail[256];
} q_case;

/* Runs the platform-appropriate qualification matrix using `adversary_path`.
 * Fills up to `max` cases; returns count via *n. Returns the number of FAILs. */
int procd_qualify_run(const char *adversary_path, q_case *out, int max, int *n);

/* ENFORCED qualification verdict: 0 only if the host reports
 * ProcessTreeTermination = ENFORCED, no case FAILed, and EVERY adversarial
 * scenario PASSed (a SKIP - e.g. an unobserved precondition - is not evidence).
 * Otherwise nonzero with the reason in `why`. */
int procd_qualify_enforced_verdict(const q_case *cases, int n, char *why, size_t wn);

/* PRACTICAL (agentctl) verdict, independent of the reported level: 0 only if no
 * case FAILed and EVERY lifecycle scenario PASSed -- its topology was witnessed,
 * every witnessed process was gone after termination, termination returned
 * success within its bound, and status never reported the domain empty while a
 * witnessed process ran. Otherwise nonzero with the reason in `why`. */
int procd_qualify_practical_verdict(const q_case *cases, int n, char *why, size_t wn);

/* True when PROCD_REQUIRE_ENFORCED=1: tests must fail rather than skip. */
int procd_qualify_strict(void);

/* True when PROCD_REQUIRE_CLEANUP=1: the practical verdict must hold. */
int procd_qualify_require_cleanup(void);

#define Q_MAX_CASES 64

const char *q_result_name(q_result r);

#endif
