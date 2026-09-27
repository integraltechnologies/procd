/*
 * TEST-ONLY negative-control switch. Compiled into a separate library variant
 * (libprocd_nc) built with -DPROCD_ENABLE_NEGATIVE_CONTROL. The production
 * library uses the no-op in procd.c that always returns 0, so production
 * containment can never be weakened.
 *
 * When active, the boundary is weakened iff the environment variable
 * PROCD_NC_WEAKEN=1 is set. This lets qualification prove the harness can
 * OBSERVE the escape it claims to prevent: same adversarial strategy, weakened
 * vs. production boundary.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#ifdef PROCD_ENABLE_NEGATIVE_CONTROL
#include <stdlib.h>
#include <string.h>

int procd_nc_weaken_containment(void) {
    const char *v = getenv("PROCD_NC_WEAKEN");
    return (v && strcmp(v, "1") == 0) ? 1 : 0;
}

/* When set, the child reports a credential-transition failure to the parent
 * before running the workload. This lets qualification prove the launch fails
 * closed and no workload executes when the privilege boundary cannot be
 * established. */
int procd_nc_fail_credentials(void) {
    const char *v = getenv("PROCD_NC_FAIL_CREDS");
    return (v && strcmp(v, "1") == 0) ? 1 : 0;
}
#endif
