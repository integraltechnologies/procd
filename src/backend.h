/*
 * Internal backend contract. This is a language-neutral C vtable, not a
 * language-specific interface: each native backend fills in a procd_backend
 * with function pointers. The public C ABI in <procd.h> dispatches to exactly
 * one backend selected at compile time for the target OS.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef PROCD_BACKEND_H
#define PROCD_BACKEND_H

#include "procd.h"

/*
 * Per-domain lock. The public dispatch layer (procd.c) serializes every
 * operation on a single domain handle with this lock, so backends never see two
 * of their own callbacks run concurrently on the same domain. A small
 * cross-platform wrapper keeps the dependency minimal (pthreads on POSIX, a
 * critical section on Windows).
 */
#if defined(_WIN32)
#include <windows.h>
typedef CRITICAL_SECTION procd_lock;
static inline void procd_lock_init(procd_lock *l) {
    InitializeCriticalSection(l);
}
static inline void procd_lock_acquire(procd_lock *l) {
    EnterCriticalSection(l);
}
static inline void procd_lock_release(procd_lock *l) {
    LeaveCriticalSection(l);
}
static inline void procd_lock_fini(procd_lock *l) {
    DeleteCriticalSection(l);
}
#else
#include <pthread.h>
typedef pthread_mutex_t procd_lock;
static inline void procd_lock_init(procd_lock *l) {
    pthread_mutex_init(l, NULL);
}
static inline void procd_lock_acquire(procd_lock *l) {
    pthread_mutex_lock(l);
}
static inline void procd_lock_release(procd_lock *l) {
    pthread_mutex_unlock(l);
}
static inline void procd_lock_fini(procd_lock *l) {
    pthread_mutex_destroy(l);
}
#endif

/* Concrete domain object. Backends embed their own state via `impl`. */
struct procd_domain {
    const struct procd_backend *backend;
    void *impl;
    procd_policy policy;
    procd_lifecycle_state state;
    procd_capability runtime_level; /* level actually established for this domain */
    procd_lock lock;                /* serializes all ops on this handle */
    int lock_ready;                 /* lock has been initialized */
    int admission_closed;           /* set once terminate begins; permanent */
};

struct procd_backend {
    const char *name;

    /* Static discovery. Must not require creating a domain. */
    void (*probe)(procd_capabilities *out);

    /* Revalidate prerequisites and establish authority. Fail closed under
     * PROCD_REQUIRE_ENFORCED. On success sets d->impl, d->runtime_level. */
    procd_status (*create)(procd_domain *d);

    /* Launch invariant. */
    procd_status (*spawn)(procd_domain *d, const char *const *argv, int64_t *out_pid);

    procd_status (*status)(procd_domain *d, procd_domain_status *out);
    procd_status (*terminate)(procd_domain *d, int timeout_ms, procd_termination_evidence *out);
    procd_status (*identity)(procd_domain *d, char *buf, size_t buflen);
    void (*destroy)(procd_domain *d); /* free impl; does not necessarily kill */

    procd_status (*recover)(const char *identity, procd_recovery_outcome *outcome,
                            procd_domain **out_domain);
};

/* Selected at compile time; defined by exactly one backend TU. */
const struct procd_backend *procd_active_backend(void);

/*
 * TEST-ONLY negative-control knobs. Production builds compile these to no-ops
 * that always return 0. Builds configured with PROCD_ENABLE_NEGATIVE_CONTROL
 * expose real switches so qualification can prove (a) the harness detects the
 * escape it claims to prevent, and (b) a failed workload credential transition
 * fails the launch closed and runs no workload. See tests/.
 */
int procd_nc_weaken_containment(void);
int procd_nc_fail_credentials(void);

#endif /* PROCD_BACKEND_H */
