/*
 * procd - cross-platform process lifecycle ownership and supervision.
 *
 * This header is the canonical, OS-neutral semantic contract for procd.
 * It is intentionally a small, stable C ABI so that the lifecycle-domain
 * semantics live in a language-neutral boundary rather than in any single
 * implementation language. Native backends (Linux cgroup v2, Windows Job
 * Objects, macOS) sit beneath this contract; thin language bindings sit above
 * it. No implementation language is architecturally privileged.
 *
 * North-star semantic:
 *   If procd reports ProcessTreeTermination = ENFORCED for an invocation
 *   domain, then after a successful enforced termination no executable process
 *   owned by that invocation may remain running merely because it forked,
 *   exec'd, detached, changed process groups/sessions, reparented,
 *   double-forked, or otherwise manipulated ordinary process topology.
 *
 * Guiding principles encoded by this ABI:
 *   - Authority beats discovery.       (terminate targets authority, not PIDs)
 *   - PID ancestry is not containment.
 *   - PID alone is not durable identity.
 *   - Uncertainty must remain uncertainty. (UNRESOLVED is a first-class result)
 *   - A truthful UNSUPPORTED is preferable to a false ENFORCED.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef PROCD_H
#define PROCD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * v0 ABI STABILITY BOUNDARY.
 *   - This is a v0 interface. The struct layouts below (procd_policy,
 *     procd_capabilities, procd_domain_status, procd_termination_evidence) may
 *     gain fields before v1 and carry no size/version discriminator yet, so a
 *     caller MUST compile against the exact header matching the library it links
 *     and MUST NOT persist these structs across a version boundary.
 *
 * THREAD-SAFETY.
 *   - Distinct procd_domain handles are independent and may be used from
 *     different threads concurrently.
 *   - Operations on a SINGLE handle are serialized internally, so calling
 *     spawn/status/terminate/identity on the same handle from multiple threads
 *     is safe; calls simply take turns.
 *   - Once procd_domain_terminate begins on a handle, admission is permanently
 *     closed: any spawn that has not already made its workload executable fails
 *     and runs no workload.
 *
 * HANDLE LIFETIME.
 *   - procd_domain_release frees the handle. Using a handle after release, or
 *     releasing it twice, is undefined behavior; procd does not attempt to make
 *     that safe. The caller must ensure no other operation on the handle is in
 *     flight when it calls release.
 */

#if defined(_WIN32) && defined(PROCD_SHARED)
#ifdef PROCD_BUILD
#define PROCD_API __declspec(dllexport)
#else
#define PROCD_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && defined(PROCD_SHARED) && defined(PROCD_BUILD)
#define PROCD_API __attribute__((visibility("default")))
#else
#define PROCD_API
#endif

/* ------------------------------------------------------------------ */
/* Result / error codes                                               */
/* ------------------------------------------------------------------ */
typedef enum procd_status {
    PROCD_OK = 0,
    /* The caller requested ENFORCED semantics but the backend could not
     * establish every prerequisite for the hard invariant. The launch or
     * domain creation was REFUSED. Nothing untrusted was executed. This is a
     * success of the fail-closed policy, not a bug. */
    PROCD_E_UNSUPPORTED_ENFORCEMENT = 1,
    /* Host prerequisites (mounts, permissions, kernel features) were absent.
     * Distinct from a runtime failure: the environment cannot host the path. */
    PROCD_E_PREREQUISITE = 2,
    PROCD_E_INVALID_ARGUMENT = 3,
    PROCD_E_PERMISSION = 4,
    PROCD_E_NOT_FOUND = 5,
    PROCD_E_ALREADY = 6,
    PROCD_E_IO = 7,
    PROCD_E_STATE = 8, /* operation invalid for the current lifecycle state */
    PROCD_E_TIMEOUT = 9,
    PROCD_E_INTERNAL = 10
} procd_status;

/* ------------------------------------------------------------------ */
/* Capability model                                                   */
/* ------------------------------------------------------------------ */
/*
 * A capability level describes how strongly a backend can establish a given
 * property. These are ordered: UNSUPPORTED < BEST_EFFORT < ENFORCED.
 *
 *   ENFORCED    - The OS itself guarantees the property against an adversarial
 *                 workload that manipulates process topology. Backend-specific
 *                 prerequisites for the hard invariant are all established.
 *   BEST_EFFORT - The backend attempts the property using ordinary mechanisms
 *                 that a cooperating workload will respect, but which an
 *                 adversarial workload can defeat.
 *   UNSUPPORTED - No supported mechanism establishes the property. procd will
 *                 not pretend otherwise.
 *
 * Every level describes the FULL property for all executable work the
 * invocation owns, never the narrower behavior of an underlying mechanism. For
 * example, "ordinary descendants stay in the Job" is not ENFORCED descendant
 * containment if the workload has other ways to create work outside the Job.
 */
typedef enum procd_capability {
    PROCD_CAP_UNSUPPORTED = 0,
    PROCD_CAP_BEST_EFFORT = 1,
    PROCD_CAP_ENFORCED = 2
} procd_capability;

/*
 * Crash / authority-loss behavior is modeled separately from the positive
 * capabilities because it describes what happens to the domain when the
 * controlling authority disappears (e.g. the supervisor process dies).
 */
typedef enum procd_crash_behavior {
    /* Loss of authority causes the OS to destroy the domain and everything in
     * it, and nothing the workload does can prevent that. */
    PROCD_CRASH_AUTOMATIC_DESTRUCTION = 0,
    /* The exact domain survives authority loss and can be safely reacquired
     * using authoritative, generation-safe identity (e.g. a persistent Linux
     * cgroup directory addressed by (boot generation, cgroup id)). */
    PROCD_CRASH_DURABLE_REACQUISITION = 1,
    /* The fate of the domain cannot be authoritatively established after
     * authority loss. procd will report UNRESOLVED rather than guess. */
    PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS = 2
} procd_crash_behavior;

typedef struct procd_capabilities {
    /* The aggregate security claim. ENFORCED here means the full launch
     * invariant + authoritative termination + emptiness proof all hold. */
    procd_capability process_tree_termination;
    /* No untrusted workload code executes before containment exists. */
    procd_capability pre_execution_containment;
    /* ALL work the workload causes to exist after launch remains inside the
     * domain, by whatever creation path (not only ordinary child creation). */
    procd_capability descendant_containment;
    /* The domain resists topology-escape tricks (setsid/setpgid/double-fork/
     * reparent/detach/exec/broker-mediated spawn). */
    procd_capability topology_escape_resistance;
    /* The backend can obtain OS-backed proof that NO invocation-owned
     * executable work remains (not merely "a scan found nothing", and not
     * merely "the kernel object we track is empty"). */
    procd_capability domain_emptiness_proof;
    /* Recovery after authority loss is authoritative and never PID-guessed. */
    procd_capability safe_recovery;

    procd_crash_behavior crash_behavior;

    /* Stable backend identifier, e.g. "linux-cgroup2", "windows-job",
     * "macos-none". NUL-terminated, owned by the library, valid for process
     * lifetime. */
    const char *backend;
    /* Human-readable, one-line note on why levels are what they are on this
     * host. Diagnostic METADATA only; never authority. */
    const char *detail;
} procd_capabilities;

/*
 * Report the *statically discoverable* capabilities of the current host.
 *
 * IMPORTANT: This is discovery, not establishment. A backend MUST independently
 * revalidate every prerequisite at domain-creation time and fail closed even
 * if the caller skipped procd_capabilities(). Runtime establishment is what
 * gates an ENFORCED claim, not this call.
 */
PROCD_API procd_status procd_capabilities_probe(procd_capabilities *out);

/* ------------------------------------------------------------------ */
/* Policy                                                             */
/* ------------------------------------------------------------------ */
typedef enum procd_enforcement {
    /* Fail closed: if ProcessTreeTermination cannot be ENFORCED on this host,
     * REFUSE domain creation / launch. Never silently downgrade. */
    PROCD_REQUIRE_ENFORCED = 0,
    /* Permit the strongest available level, which may be BEST_EFFORT or even
     * UNSUPPORTED. The resulting domain's true level is reported by
     * procd_domain_status(); the caller must inspect it. */
    PROCD_ALLOW_BEST_EFFORT = 1
} procd_enforcement;

typedef struct procd_policy {
    procd_enforcement enforcement;
    /* Optional label for diagnostics; copied by the library. May be NULL. */
    const char *label;
    /* Drop to this uid/gid before workload execution where the backend
     * supports a privilege boundary (Linux). -1 means "no change". Ignored by
     * backends without a privilege model. */
    int64_t drop_uid;
    int64_t drop_gid;
} procd_policy;

#define PROCD_POLICY_INIT                                                                          \
    { PROCD_REQUIRE_ENFORCED, NULL, -1, -1 }

/* ------------------------------------------------------------------ */
/* Lifecycle + population state                                       */
/* ------------------------------------------------------------------ */
/*
 * Lifecycle state describes the authority/administrative status of the domain.
 * Population state (below) is deliberately kept distinct: a domain can be
 * ACTIVE-with-no-processes transiently, and EMPTY is a proven-empty terminal-
 * ish state established by the OS, not merely "we saw zero processes once".
 */
typedef enum procd_lifecycle_state {
    PROCD_STATE_CREATED = 0,     /* authority established, admission open, nothing admitted yet */
    PROCD_STATE_ACTIVE = 1,      /* workload admitted / executing, admission open */
    PROCD_STATE_TERMINATING = 2, /* admission closed, kill issued, draining */
    PROCD_STATE_EMPTY = 3,       /* OS-proven: no owned executable work remains */
    PROCD_STATE_RELEASED = 4,    /* authority released by caller */
    PROCD_STATE_UNRESOLVED = 5   /* fate cannot be authoritatively established */
} procd_lifecycle_state;

typedef enum procd_population {
    PROCD_POP_UNKNOWN = 0,   /* not authoritatively determined */
    PROCD_POP_POPULATED = 1, /* OS reports the domain holds >=1 process */
    PROCD_POP_EMPTY = 2      /* 0 processes observed; authoritative ONLY if
                              * population_is_authoritative is set */
} procd_population;

typedef struct procd_domain_status {
    procd_lifecycle_state state;
    procd_population population;
    /* The level actually established for THIS domain at runtime. For a domain
     * created under PROCD_ALLOW_BEST_EFFORT this may be below ENFORCED and the
     * caller is expected to honor it. */
    procd_capability process_tree_termination;
    /* Whether population is backed by an authoritative OS mechanism
     * (e.g. cgroup.events populated flag) as opposed to a best-effort scan. */
    int population_is_authoritative;
} procd_domain_status;

/* ------------------------------------------------------------------ */
/* Termination evidence                                               */
/* ------------------------------------------------------------------ */
/*
 * "Kill request succeeded" is insufficient. "Root PID exited" is insufficient.
 * "A process scan found nothing" is insufficient. Enforced termination requires
 * authoritative, OS-backed evidence that no owned executable work remains.
 */
typedef struct procd_termination_evidence {
    /* Admission was closed before killing (no new work could join the race). */
    int admission_closed;
    /* The kill was directed at lifecycle AUTHORITY (e.g. cgroup.kill), not at a
     * discovered list of PIDs. */
    int authority_directed;
    /* The OS authoritatively confirmed the domain is empty afterwards
     * (e.g. cgroup.events populated == 0, or JOB active-process count == 0). */
    int emptiness_proven;
    /* True only if all of the above hold AND the domain's runtime level was
     * ENFORCED: the hard invariant is satisfied. */
    int enforced;
    procd_lifecycle_state final_state;
    const char *detail; /* diagnostic METADATA, owned by domain, valid until release */
} procd_termination_evidence;

/* ------------------------------------------------------------------ */
/* Durable identity + recovery                                        */
/* ------------------------------------------------------------------ */
/*
 * A durable identity is a generation-safe reference to an exact lifecycle
 * domain. It is emphatically NOT a PID, and it is NOT itself authority: the
 * token is caller-editable metadata. On Linux it names a root-owned record
 * written when the domain was created; recovery takes every authority-bearing
 * fact (boot generation, cgroup namespace view, cgroup path and inode,
 * established level) from that protected record and requires the token to
 * match it exactly. A token that is malformed, unknown, or disagrees with the
 * record yields UNRESOLVED, so editing it can never redirect a termination.
 *
 * The identity is a printable, NUL-terminated token owned by the caller after
 * procd_domain_identity() copies it into the caller's buffer.
 */
#define PROCD_IDENTITY_MAX 512

typedef enum procd_recovery_outcome {
    /* The exact domain still exists and authority was safely reacquired. */
    PROCD_RECOVERED = 0,
    /* Authoritative evidence shows the exact domain was destroyed. */
    PROCD_CONFIRMED_DESTROYED = 1,
    /* The exact fate cannot be established. procd refuses to guess. This is a
     * truthful result, not a failure to be papered over. */
    PROCD_UNRESOLVED = 2
} procd_recovery_outcome;

/* ------------------------------------------------------------------ */
/* Opaque handles                                                     */
/* ------------------------------------------------------------------ */
typedef struct procd_domain procd_domain;

/*
 * Create a lifecycle domain per policy.
 *
 * Fail-closed contract: under PROCD_REQUIRE_ENFORCED the backend revalidates
 * every prerequisite for the hard invariant and returns
 * PROCD_E_UNSUPPORTED_ENFORCEMENT (creating no domain, executing nothing) if
 * any prerequisite is missing. This revalidation is independent of
 * procd_capabilities_probe().
 */
PROCD_API procd_status procd_create_domain(const procd_policy *policy, procd_domain **out_domain);

/*
 * Spawn a command inside the domain honoring the LAUNCH INVARIANT:
 *
 *   revalidate prerequisites
 *   establish lifecycle authority
 *   create the initial process WITHOUT permitting workload execution
 *   admit/bind it to the domain
 *   verify containment
 *   establish required exact identity
 *   prevent workload inheritance of privileged lifecycle authority
 *   register supervision
 *   permit workload execution
 *
 * If required containment cannot be established, the launch is REFUSED and no
 * workload code runs. argv is NULL-terminated. out_pid receives the OS process
 * id for DIAGNOSTICS only (it is metadata, never used as authority or identity
 * for termination). May be NULL.
 */
PROCD_API procd_status procd_domain_spawn(procd_domain *domain, const char *const *argv,
                                          int64_t *out_pid);

PROCD_API procd_status procd_domain_status_get(procd_domain *domain, procd_domain_status *out);

/*
 * Terminate the domain by AUTHORITY. Closes admission first, directs the kill
 * at lifecycle authority, then waits (bounded by timeout_ms; <=0 means a
 * backend default) for authoritative emptiness. Idempotent where the backend
 * can keep proving the result. Fills evidence describing exactly what was
 * established.
 */
PROCD_API procd_status procd_domain_terminate(procd_domain *domain, int timeout_ms,
                                              procd_termination_evidence *out);

/* Copy the domain's durable, generation-safe identity token into buf. */
PROCD_API procd_status procd_domain_identity(procd_domain *domain, char *buf, size_t buflen);

/* Release authority/handles. Does not by itself kill the domain unless the
 * backend's crash behavior is AUTOMATIC_DESTRUCTION. Frees the handle. */
PROCD_API procd_status procd_domain_release(procd_domain *domain);

/*
 * Attempt to reacquire a domain from a durable identity token. Never guesses:
 * uses only authoritative, generation-safe evidence. Returns via *outcome one
 * of RECOVERED / CONFIRMED_DESTROYED / UNRESOLVED. On RECOVERED, *out_domain is
 * a usable handle whose level never exceeds the level established for that
 * domain at creation; otherwise it is NULL.
 *
 * *outcome is UNRESOLVED whenever the return status is not PROCD_OK (malformed
 * token, insufficient privilege, I/O failure) and whenever the token cannot be
 * verified. CONFIRMED_DESTROYED is reported only with protected evidence that
 * the exact domain existed and that native semantics make its destruction
 * unavoidable.
 */
PROCD_API procd_status procd_recover(const char *identity, procd_recovery_outcome *outcome,
                                     procd_domain **out_domain);

/* Utility: human-readable names (owned by library, static storage). */
PROCD_API const char *procd_capability_name(procd_capability c);
PROCD_API const char *procd_state_name(procd_lifecycle_state s);
PROCD_API const char *procd_status_name(procd_status s);
PROCD_API const char *procd_recovery_name(procd_recovery_outcome o);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROCD_H */
