# API reference

The public API is the C header [`include/procd.h`](../include/procd.h); it is
authoritative. This document explains each symbol, how the calls fit
together, and what differs by platform. For concepts see
[architecture.md](architecture.md); for platform mechanisms see
[platform-support.md](platform-support.md).

- [Call sequence](#call-sequence)
- [Status codes](#status-codes)
- [Capabilities](#capabilities)
- [Policy](#policy)
- [procd_create_domain](#procd_create_domain)
- [procd_domain_spawn](#procd_domain_spawn)
- [procd_domain_status_get](#procd_domain_status_get)
- [procd_domain_terminate](#procd_domain_terminate)
- [procd_domain_release](#procd_domain_release)
- [procd_domain_identity and procd_recover](#procd_domain_identity-and-procd_recover)
- [Name helpers](#name-helpers)
- [Thread safety and handle lifetime](#thread-safety-and-handle-lifetime)
- [ABI and compatibility](#abi-and-compatibility)
- [Examples](#examples)

## Call sequence

```
procd_capabilities_probe   (optional discovery; never required)
procd_create_domain        -> procd_domain *            state CREATED
procd_domain_spawn         (one or more)                state ACTIVE
procd_domain_status_get    (any time, any number)
procd_domain_terminate     (admission closes)           state EMPTY or UNRESOLVED
procd_domain_release       (handle freed)
```

`procd_domain_terminate` may be called at any point after creation, including
while a task is still starting children. Always terminate before release when
the task's processes must not outlive it: release alone kills nothing on
Linux and macOS.

## Status codes

Every function except the name helpers returns `procd_status`.

| Code | Meaning |
|------|---------|
| `PROCD_OK` | Success. |
| `PROCD_E_UNSUPPORTED_ENFORCEMENT` | `PROCD_REQUIRE_ENFORCED` was requested and `ENFORCED` cannot be established on this host. Nothing was created or run. |
| `PROCD_E_PREREQUISITE` | The host cannot provide the backend's mechanism (e.g. no usable cgroup v2 domain on Linux, Job creation failed on Windows), or a recovery prerequisite is missing. |
| `PROCD_E_INVALID_ARGUMENT` | A required pointer was NULL, a buffer too small, an identity token malformed, or run-as ids not representable. |
| `PROCD_E_PERMISSION` | The OS refused the operation (e.g. cannot create the cgroup, executable not permitted, run-as identity not establishable, recovery without root on Linux). |
| `PROCD_E_NOT_FOUND` | The executable was not found. |
| `PROCD_E_ALREADY` | Defined but not currently returned by any backend. |
| `PROCD_E_IO` | An OS call failed (process table or Job accounting unreadable, `cgroup.kill` write failed, ...). |
| `PROCD_E_STATE` | The operation is invalid in the current state (e.g. spawn after terminate began). |
| `PROCD_E_TIMEOUT` | Termination did not reach emptiness within its bound. |
| `PROCD_E_INTERNAL` | Allocation failure or an internal invariant (e.g. placement could not be verified). |

## Capabilities

```c
procd_status procd_capabilities_probe(procd_capabilities *out);
```

Fills `*out` with the **statically discoverable** capabilities of the current
host. Returns `PROCD_E_INVALID_ARGUMENT` if `out` is NULL, otherwise
`PROCD_OK`. It creates nothing and is never required: domain creation
revalidates everything itself and fails closed regardless of discovery.

`procd_capability` is ordered `PROCD_CAP_UNSUPPORTED < PROCD_CAP_BEST_EFFORT <
PROCD_CAP_ENFORCED`.

| Field | Property |
|-------|----------|
| `process_tree_termination` | The aggregate claim. `ENFORCED` means pre-execution placement, OS-grouped descendants, domain-directed termination and OS-observed emptiness all hold. |
| `pre_execution_containment` | The task's first process is in the domain before it runs task code. |
| `descendant_containment` | Descendants created by fork, spawn or exec belong to the domain. |
| `topology_escape_resistance` | That grouping survives `setsid`, `setpgid`, double fork, reparenting, leader exit and detached background children. |
| `domain_emptiness_proof` | The OS reports when the domain holds no process, not merely "a scan found nothing". |
| `safe_recovery` | Recovery after authority loss is authoritative and never PID-guessed. |
| `crash_behavior` | What happens to the domain when the supervisor dies (below). |
| `backend` | `"linux-cgroup2"`, `"windows-job"` or `"macos-tracked"`. Static storage. |
| `detail` | One-line diagnostic explaining the levels. Static storage. Metadata, never authority. |

`procd_crash_behavior`:

| Value | Meaning | Reported by |
|-------|---------|-------------|
| `PROCD_CRASH_AUTOMATIC_DESTRUCTION` | Losing the supervisor destroys the domain and everything in it. | Windows |
| `PROCD_CRASH_DURABLE_REACQUISITION` | The domain survives and can be reacquired with `procd_recover`. | Linux, when running as root with the protected record store available |
| `PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS` | The domain's fate after supervisor loss cannot be established. | Linux otherwise, macOS |

Per-platform values are listed in
[platform-support.md](platform-support.md#capability-summary).

## Policy

```c
typedef struct procd_policy {
    procd_enforcement enforcement;
    const char *label;
    int64_t drop_uid;
    int64_t drop_gid;
} procd_policy;

#define PROCD_POLICY_INIT { PROCD_REQUIRE_ENFORCED, NULL, -1, -1 }
```

Always start from `PROCD_POLICY_INIT`.

- `enforcement`
  - `PROCD_REQUIRE_ENFORCED` (default): refuse creation unless
    `ProcessTreeTermination` can be `ENFORCED`.
  - `PROCD_ALLOW_BEST_EFFORT`: accept the strongest available level. The
    domain's actual level is reported by `procd_domain_status_get` and the
    caller is expected to honor it.
- `label`: optional diagnostic label, or NULL. `procd_create_domain` copies
  the string, so the caller's buffer need not outlive the call; the copy is
  freed by `procd_domain_release`. The label does not affect behavior.
- `drop_uid`, `drop_gid`: optional run-as identity for spawned workloads,
  honored by the **Linux** backend only (macOS and Windows ignore them). `-1`
  keeps the caller's credentials. Other values are applied in the child with
  checked `set*id` calls (dropping supplementary groups when the caller is
  root) and read back; if they cannot be established the spawn fails and
  nothing runs. Values that do not fit the platform `uid_t`/`gid_t`, or are
  negative other than `-1`, make `procd_create_domain` return
  `PROCD_E_INVALID_ARGUMENT`. This is a convenience, not isolation; the
  lifecycle level does not depend on it.

## procd_create_domain

```c
procd_status procd_create_domain(const procd_policy *policy, procd_domain **out_domain);
```

Creates a lifecycle domain. `policy` may be NULL (equivalent to
`PROCD_POLICY_INIT`); it is read during the call, and the domain keeps its
own copy of `label`. On success `*out_domain`
is a new handle owned by the caller, in state `PROCD_STATE_CREATED`; on any
failure it is set to NULL and nothing was created or run.

| Result | When |
|--------|------|
| `PROCD_OK` | Domain created. Its level is available from `procd_domain_status_get`. |
| `PROCD_E_UNSUPPORTED_ENFORCEMENT` | `PROCD_REQUIRE_ENFORCED` and the backend cannot establish `ENFORCED` (macOS always; Linux without a usable cgroup v2 domain; Windows if Job setup fails). |
| `PROCD_E_PREREQUISITE` | `PROCD_ALLOW_BEST_EFFORT`, but the backend has no mechanism at all on this host (Linux without a usable cgroup v2 domain; Windows if Job setup fails). Linux and Windows never fall back to a weaker mechanism. |
| `PROCD_E_PERMISSION`, `PROCD_E_IO` | Linux: the domain cgroup could not be created or verified. |
| `PROCD_E_INVALID_ARGUMENT` | `out_domain` is NULL, or run-as ids are invalid (Linux). |
| `PROCD_E_INTERNAL` | Allocation failure (including copying `label`). |

The established level per platform: Linux and Windows `ENFORCED`; macOS
`BEST_EFFORT` (only obtainable with `PROCD_ALLOW_BEST_EFFORT`).

## procd_domain_spawn

```c
procd_status procd_domain_spawn(procd_domain *domain, const char *const *argv,
                                 int64_t *out_pid);
```

Starts one process in the domain. `argv` is a NULL-terminated argument vector
with `argv[0]` the program; it is only read during the call. A domain may
hold several spawned processes. The sequence is: create the process without
letting it run workload code, place it in the domain and verify membership,
apply descriptor hygiene and the optional run-as identity, register
supervision, then let it execute. A failure at any step fails the spawn, runs
no workload code, and leaves the rest of the domain untouched; the domain
stays usable for further spawns. There is no limit on the number of spawns
per domain. Exec failures are reported synchronously with the same codes on
every platform: a missing program (`ENOENT`/`ENOTDIR`, or Windows file/path
not found) is `PROCD_E_NOT_FOUND`; a program the caller may not execute
(`EACCES`/`EPERM`, or Windows access denied) is `PROCD_E_PERMISSION`.

`out_pid` (optional) receives the OS process id, or `-1` on failure. It is
diagnostic metadata only; procd never uses a PID as authority, and the caller
should not use it to signal the task.

| Result | When |
|--------|------|
| `PROCD_OK` | The process was placed in the domain and started. State becomes `PROCD_STATE_ACTIVE`. |
| `PROCD_E_INVALID_ARGUMENT` | `domain` or `argv` is NULL, or `argv[0]` is NULL. |
| `PROCD_E_STATE` | Termination has begun on this handle, or the domain is no longer usable (Linux: its cgroup was removed or its controls are unusable). |
| `PROCD_E_NOT_FOUND` | The executable was not found. |
| `PROCD_E_PERMISSION` | The executable could not be executed (permission denied), or (Linux) the run-as identity could not be established. |
| `PROCD_E_IO` | Process creation or placement failed, or exec failed for another reason (e.g. an invalid executable format). |
| `PROCD_E_INTERNAL` | Allocation failure, or placement could not be verified. |

What the process inherits:

| | Linux | macOS | Windows |
|---|---|---|---|
| Program lookup | `execvp` (`PATH` search) | `execvp` (`PATH` search) | `argv` joined into a command line with MSVC quoting rules; `CreateProcessW` search rules |
| Environment, working directory | the caller's | the caller's, plus the domain marker variable `PROCD_DOMAIN_<nonce>=1` | the caller's |
| Descriptors / handles | stdin/stdout/stderr only; procd closes every other descriptor before exec | the caller's descriptors not marked close-on-exec, including stdin/stdout/stderr | no handles are inherited; created with `CREATE_NO_WINDOW` |
| Credentials | the caller's, or the policy run-as identity | the caller's | the caller's |

procd has no parameter for stdio redirection, environment, working directory
or resource limits.

POSIX note: procd reaps the processes it spawns directly. An embedding
program that reaps children itself (e.g. `waitpid(-1, ...)` in a `SIGCHLD`
handler) may reap them first; procd tolerates this (Linux tracks its children
by pidfd where available, and macOS remembers the process's generation).

## procd_domain_status_get

```c
procd_status procd_domain_status_get(procd_domain *domain, procd_domain_status *out);
```

Fills `*out` with the domain's current view. Returns
`PROCD_E_INVALID_ARGUMENT` if either pointer is NULL, otherwise `PROCD_OK`.

| Field | Meaning |
|-------|---------|
| `state` | `procd_lifecycle_state` (below). |
| `population` | `procd_population`: `PROCD_POP_POPULATED`, `PROCD_POP_EMPTY` or `PROCD_POP_UNKNOWN`. |
| `population_is_authoritative` | Nonzero only when `population` comes from an OS mechanism (Linux `cgroup.events`, Windows Job accounting) at `ENFORCED`. Always 0 on macOS. |
| `process_tree_termination` | The level actually established for this domain. |

`PROCD_POP_EMPTY` with `population_is_authoritative == 0` means "a scan found
no member", not proof. On macOS each status call also reconciles membership
(and reaps exited processes procd spawned), so periodic status polling
strengthens tracking.

Lifecycle states:

| State | Meaning |
|-------|---------|
| `PROCD_STATE_CREATED` | Domain established, nothing spawned yet. |
| `PROCD_STATE_ACTIVE` | At least one spawn succeeded (also the state of a recovered handle). |
| `PROCD_STATE_TERMINATING` | Set while `procd_domain_terminate` runs. Operations on a handle are serialized, so status on the same handle does not observe it. |
| `PROCD_STATE_EMPTY` | The OS proved the domain empty. Reached only after a successful termination at `ENFORCED` (Linux, Windows). |
| `PROCD_STATE_UNRESOLVED` | After termination, when emptiness could not be proven: always on macOS, and on any platform after a timeout or I/O failure. |
| `PROCD_STATE_RELEASED` | Defined by the contract; not observable through the API, since release frees the handle. |

Population is kept separate from state: a domain can be `ACTIVE` while its
population is momentarily empty.

## procd_domain_terminate

```c
procd_status procd_domain_terminate(procd_domain *domain, int timeout_ms,
                                    procd_termination_evidence *out);
```

Terminates everything the domain holds. Admission closes first: any spawn on
this handle that has not already made its workload executable fails with
`PROCD_E_STATE` and runs nothing, now and later. procd then kills the domain
and waits up to `timeout_ms` (a value `<= 0` means the backend default,
5000 ms) for emptiness. `out` is required and is always filled.

| Result | Meaning |
|--------|---------|
| `PROCD_OK` | Linux/Windows: the OS proved the domain empty. macOS: every member procd could find was killed and a final scan found none. |
| `PROCD_E_TIMEOUT` | Emptiness was not reached within `timeout_ms`. |
| `PROCD_E_IO` | The kill or the emptiness check failed at the OS level. |
| `PROCD_E_INVALID_ARGUMENT` | `domain` or `out` is NULL. |

`procd_termination_evidence`:

| Field | Meaning |
|-------|---------|
| `admission_closed` | Admission was closed before killing. |
| `authority_directed` | The kill targeted the OS lifecycle object (`cgroup.kill`, `TerminateJobObject`) rather than a list of discovered PIDs. 0 on macOS. |
| `emptiness_proven` | The OS confirmed the domain empty afterwards. 0 on macOS. |
| `enforced` | All of the above held and the domain's level was `ENFORCED`: the hard invariant is satisfied. |
| `final_state` | `PROCD_STATE_EMPTY` when emptiness was proven at `ENFORCED`; otherwise `PROCD_STATE_UNRESOLVED` (always on macOS). |
| `detail` | Diagnostic text owned by the domain; valid until the next terminate on the handle or its release. On macOS it also reports whether the event-assisted watcher was active and its activity for this domain. |

Treat `ev.enforced` as the signal that the strong guarantee held for this
termination. Calling terminate again on the same handle re-checks the domain
and reports again; on Linux and Windows it succeeds when this handle already
proved the domain empty.

## procd_domain_release

```c
procd_status procd_domain_release(procd_domain *domain);
```

Frees the handle and its backend resources. Returns
`PROCD_E_INVALID_ARGUMENT` for NULL, otherwise `PROCD_OK`. It waits for an
operation that began before it, but the caller must ensure no operation is in
flight or will start afterwards; using or releasing a handle again after
release is undefined behavior.

Effect on processes still in the domain:

- **Windows**: closing the Job handle kills them (`KILL_ON_JOB_CLOSE`).
- **Linux**: they keep running in the domain's cgroup; procd removes the
  cgroup only if it is already empty. The domain can later be reacquired with
  `procd_recover` only if it was created by root (see below).
- **macOS**: they keep running and are no longer tracked.

## procd_domain_identity and procd_recover

```c
#define PROCD_IDENTITY_MAX 512
procd_status procd_domain_identity(procd_domain *domain, char *buf, size_t buflen);
procd_status procd_recover(const char *identity, procd_recovery_outcome *outcome,
                           procd_domain **out_domain);
```

`procd_domain_identity` copies a printable, NUL-terminated identity token into
`buf` (use at least `PROCD_IDENTITY_MAX` bytes). It returns
`PROCD_E_INVALID_ARGUMENT` for NULL arguments, `buflen == 0`, or a buffer too
small for the token. The token is not a PID and not authority; it is
caller-editable metadata.

`procd_recover` tries to reacquire a domain from a token after the original
handle or supervisor is gone. It never guesses. `*outcome` is one of:

- `PROCD_RECOVERED`: the exact domain still exists; `*out_domain` is a new
  handle (state `ACTIVE`, default policy, level never above the level recorded
  at creation, lowered if the domain's controls are no longer usable).
- `PROCD_CONFIRMED_DESTROYED`: protected evidence shows the exact domain
  existed at `ENFORCED` and no longer does.
- `PROCD_UNRESOLVED`: anything else. `*out_domain` is NULL.

`*outcome` is `PROCD_UNRESOLVED` whenever the return status is not
`PROCD_OK`. All three pointers are required (`PROCD_E_INVALID_ARGUMENT`
otherwise).

| Platform | Behavior |
|----------|----------|
| Linux | Supported only when running as root. The token names a root-owned record in `/var/lib/procd` written at creation (records are only written for domains created by root); every fact used (boot id, cgroup namespace view, path, inode, level) comes from that record, and the token must match it exactly, so an edited token cannot redirect termination. Errors: `PROCD_E_INVALID_ARGUMENT` (malformed token), `PROCD_E_PERMISSION` (not root), `PROCD_E_PREREQUISITE` (record store or cgroup v2 unavailable), `PROCD_E_IO`. |
| Windows | Always `PROCD_UNRESOLVED` (an unnamed Job cannot be reacquired; the token is not unique per domain). A token without the `windows-job:` prefix returns `PROCD_E_INVALID_ARGUMENT`. |
| macOS | Always `PROCD_OK` with `PROCD_UNRESOLVED`; no durable authority exists. |

A recovered handle is a second handle to the domain. The header's rule
applies: a domain should have one owning handle at a time, and admission is
tracked per handle.

## Name helpers

```c
const char *procd_capability_name(procd_capability c);    /* "ENFORCED", ... */
const char *procd_state_name(procd_lifecycle_state s);    /* "EMPTY", ... */
const char *procd_status_name(procd_status s);            /* "OK", "TIMEOUT", ... */
const char *procd_recovery_name(procd_recovery_outcome o);/* "RECOVERED", ... */
```

Return static strings owned by the library; `"?"` for values outside the
enumeration. `procd_status_name(PROCD_E_PREREQUISITE)` is
`"PREREQUISITE_MISSING"`; the others match the enumerator suffix.

## Thread safety and handle lifetime

From the header:

- Distinct handles are independent and may be used from different threads
  concurrently.
- Operations on a single handle are serialized internally; spawn, status,
  terminate and identity on the same handle from several threads take turns.
- Once terminate begins on a handle, admission is permanently closed.
- A domain is expected to have one owning handle at a time.
- `procd_domain_release` must not race other operations on the handle, and
  the handle must not be used after release.

`procd_capabilities_probe`, `procd_recover` and the name helpers take no
handle. The header states no further thread-safety guarantee for them.

On macOS, creating the first domain starts one background watcher thread that
serves every macOS domain in the process and runs until the process exits.
procd registers `pthread_atfork` handlers so a forked child starts without
the watcher state (see [architecture.md](architecture.md#the-macos-watcher)).

## ABI and compatibility

This is the v0 interface. The structs (`procd_policy`, `procd_capabilities`,
`procd_domain_status`, `procd_termination_evidence`) may gain fields before
v1 and carry no size or version field. Compile against the exact header that
matches the library you link, and do not persist these structs across
versions. No long-term ABI stability is promised yet.

The build currently produces a static library. The header's `PROCD_API`
export macro recognizes `PROCD_SHARED`/`PROCD_BUILD`, but the provided build
does not produce a shared library.

## Examples

### Capability check

```c
procd_capabilities caps;
procd_capabilities_probe(&caps);
printf("%s: ProcessTreeTermination=%s (%s)\n", caps.backend,
       procd_capability_name(caps.process_tree_termination), caps.detail);
```

Discovery is advisory. To require the strong guarantee, rely on creation:

```c
procd_policy pol = PROCD_POLICY_INIT; /* PROCD_REQUIRE_ENFORCED */
procd_domain *d = NULL;
procd_status rc = procd_create_domain(&pol, &d);
if (rc == PROCD_E_UNSUPPORTED_ENFORCEMENT) {
    /* this host cannot provide ENFORCED; nothing was created or run */
}
```

### Run a task to completion

```c
const char *const argv[] = {"/bin/sh", "-c", "make -j8", NULL};
if (procd_domain_spawn(d, argv, NULL) == PROCD_OK) {
    procd_domain_status st;
    do {
        sleep_ms(100); /* your own sleep */
        procd_domain_status_get(d, &st);
    } while (st.population != PROCD_POP_EMPTY);
}
/* Terminate anyway: it confirms emptiness (and on macOS kills anything a
 * scan finds) before the handle goes away. */
procd_termination_evidence ev;
procd_domain_terminate(d, 0, &ev);
procd_domain_release(d);
```

On macOS `PROCD_POP_EMPTY` is scan-based (`population_is_authoritative == 0`).

### Cancellation or timeout

```c
procd_termination_evidence ev;
procd_status rc = procd_domain_terminate(d, 10000, &ev);
if (rc == PROCD_OK && ev.enforced) {
    /* Linux/Windows: OS-proven that no process of the task remains */
} else if (rc == PROCD_OK) {
    /* macOS BEST_EFFORT: no tracked member remains (final state UNRESOLVED) */
} else {
    /* PROCD_E_TIMEOUT / PROCD_E_IO: report ev.detail; the domain may still
     * hold processes. Terminate can be called again. */
    fprintf(stderr, "terminate: %s: %s\n", procd_status_name(rc), ev.detail);
}
procd_domain_release(d);
```

### Spawn failure

```c
const char *const argv[] = {"no-such-program", NULL};
int64_t pid;
procd_status rc = procd_domain_spawn(d, argv, &pid);
/* rc == PROCD_E_NOT_FOUND, pid == -1. Nothing ran, processes already in
 * the domain were not affected, and the domain stays usable. */
```
