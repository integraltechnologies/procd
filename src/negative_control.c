/*
 * TEST-ONLY negative-control switch. Compiled into a separate library variant
 * (libprocd_nc) built with -DPROCD_ENABLE_NEGATIVE_CONTROL. The production
 * library uses the no-op in procd.c that always returns 0, so production
 * containment can never be weakened.
 *
 * When active, supervision is weakened iff the environment variable
 * PROCD_NC_WEAKEN=1 is set, so qualification can show the harness observes the
 * failure the production mechanism prevents: on Linux, process-group
 * termination instead of the cgroup (an ordinary setsid/double-fork descendant
 * survives); on Windows, a Job that permits breakaway.
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
#endif
