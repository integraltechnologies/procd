/*
 * Public ABI dispatch + shared, OS-neutral logic. This layer owns no
 * containment mechanism; it enforces the semantic contract (state transitions,
 * argument validation, fail-closed policy) and forwards to the active backend.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "backend.h"

#include <stdlib.h>
#include <string.h>

#ifndef PROCD_ENABLE_NEGATIVE_CONTROL
int procd_nc_weaken_containment(void) {
    return 0;
}
int procd_nc_fail_credentials(void) {
    return 0;
}
#endif

procd_status procd_capabilities_probe(procd_capabilities *out) {
    if (!out) return PROCD_E_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    procd_active_backend()->probe(out);
    return PROCD_OK;
}

procd_status procd_create_domain(const procd_policy *policy, procd_domain **out_domain) {
    if (!out_domain) return PROCD_E_INVALID_ARGUMENT;
    *out_domain = NULL;

    procd_policy p = PROCD_POLICY_INIT;
    if (policy) p = *policy;

    procd_domain *d = calloc(1, sizeof(*d));
    if (!d) return PROCD_E_INTERNAL;
    d->backend = procd_active_backend();
    d->policy = p;
    d->state = PROCD_STATE_CREATED;
    d->runtime_level = PROCD_CAP_UNSUPPORTED;

    /* Backend independently revalidates prerequisites and fails closed under
     * REQUIRE_ENFORCED even if the caller never called probe(). */
    procd_status rc = d->backend->create(d);
    if (rc != PROCD_OK) {
        free(d);
        return rc;
    }
    procd_lock_init(&d->lock);
    d->lock_ready = 1;
    d->admission_closed = 0;
    *out_domain = d;
    return PROCD_OK;
}

procd_status procd_domain_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    if (out_pid) *out_pid = -1;
    if (!d || !argv || !argv[0]) return PROCD_E_INVALID_ARGUMENT;
    procd_lock_acquire(&d->lock);
    /* Admission is permanently closed once termination has begun: a spawn that
     * loses the race must fail here and run no workload. */
    procd_status rc;
    if (d->admission_closed || (d->state != PROCD_STATE_CREATED && d->state != PROCD_STATE_ACTIVE))
        rc = PROCD_E_STATE;
    else
        rc = d->backend->spawn(d, argv, out_pid);
    procd_lock_release(&d->lock);
    return rc;
}

procd_status procd_domain_status_get(procd_domain *d, procd_domain_status *out) {
    if (!d || !out) return PROCD_E_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    procd_lock_acquire(&d->lock);
    procd_status rc = d->backend->status(d, out);
    procd_lock_release(&d->lock);
    return rc;
}

procd_status procd_domain_terminate(procd_domain *d, int timeout_ms,
                                    procd_termination_evidence *out) {
    if (!d || !out) return PROCD_E_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    procd_lock_acquire(&d->lock);
    procd_status rc;
    if (d->state == PROCD_STATE_RELEASED) {
        rc = PROCD_E_STATE;
    } else {
        /* Close admission BEFORE the backend acts: any concurrent spawn that has
         * not already admitted+exec'd its workload (it would hold this lock) will
         * observe admission_closed and fail. */
        d->admission_closed = 1;
        rc = d->backend->terminate(d, timeout_ms, out);
    }
    procd_lock_release(&d->lock);
    return rc;
}

procd_status procd_domain_identity(procd_domain *d, char *buf, size_t buflen) {
    if (!d || !buf || buflen == 0) return PROCD_E_INVALID_ARGUMENT;
    procd_lock_acquire(&d->lock);
    procd_status rc = d->backend->identity(d, buf, buflen);
    procd_lock_release(&d->lock);
    return rc;
}

procd_status procd_domain_release(procd_domain *d) {
    if (!d) return PROCD_E_INVALID_ARGUMENT;
    /* Contract: the caller must ensure no other operation on this handle is in
     * flight or will start after release. We take the lock to drain an operation
     * that began before release, then tear the handle down. */
    procd_lock_acquire(&d->lock);
    d->backend->destroy(d);
    d->state = PROCD_STATE_RELEASED;
    procd_lock_release(&d->lock);
    procd_lock_fini(&d->lock);
    free(d);
    return PROCD_OK;
}

procd_status procd_recover(const char *identity, procd_recovery_outcome *outcome,
                           procd_domain **out_domain) {
    if (!identity || !outcome || !out_domain) return PROCD_E_INVALID_ARGUMENT;
    *out_domain = NULL;
    *outcome = PROCD_UNRESOLVED;
    procd_status rc = procd_active_backend()->recover(identity, outcome, out_domain);
    if (rc == PROCD_OK && *out_domain) {
        procd_lock_init(&(*out_domain)->lock);
        (*out_domain)->lock_ready = 1;
        (*out_domain)->admission_closed = 0;
    }
    return rc;
}

const char *procd_capability_name(procd_capability c) {
    switch (c) {
    case PROCD_CAP_UNSUPPORTED:
        return "UNSUPPORTED";
    case PROCD_CAP_BEST_EFFORT:
        return "BEST_EFFORT";
    case PROCD_CAP_ENFORCED:
        return "ENFORCED";
    }
    return "?";
}
const char *procd_state_name(procd_lifecycle_state s) {
    switch (s) {
    case PROCD_STATE_CREATED:
        return "CREATED";
    case PROCD_STATE_ACTIVE:
        return "ACTIVE";
    case PROCD_STATE_TERMINATING:
        return "TERMINATING";
    case PROCD_STATE_EMPTY:
        return "EMPTY";
    case PROCD_STATE_RELEASED:
        return "RELEASED";
    case PROCD_STATE_UNRESOLVED:
        return "UNRESOLVED";
    }
    return "?";
}
const char *procd_status_name(procd_status s) {
    switch (s) {
    case PROCD_OK:
        return "OK";
    case PROCD_E_UNSUPPORTED_ENFORCEMENT:
        return "UNSUPPORTED_ENFORCEMENT";
    case PROCD_E_PREREQUISITE:
        return "PREREQUISITE_MISSING";
    case PROCD_E_INVALID_ARGUMENT:
        return "INVALID_ARGUMENT";
    case PROCD_E_PERMISSION:
        return "PERMISSION";
    case PROCD_E_NOT_FOUND:
        return "NOT_FOUND";
    case PROCD_E_ALREADY:
        return "ALREADY";
    case PROCD_E_IO:
        return "IO";
    case PROCD_E_STATE:
        return "STATE";
    case PROCD_E_TIMEOUT:
        return "TIMEOUT";
    case PROCD_E_INTERNAL:
        return "INTERNAL";
    }
    return "?";
}
const char *procd_recovery_name(procd_recovery_outcome o) {
    switch (o) {
    case PROCD_RECOVERED:
        return "RECOVERED";
    case PROCD_CONFIRMED_DESTROYED:
        return "CONFIRMED_DESTROYED";
    case PROCD_UNRESOLVED:
        return "UNRESOLVED";
    }
    return "?";
}
