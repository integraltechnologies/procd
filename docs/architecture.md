# Architecture

This document describes how procd is structured and what it is responsible
for. The API itself is in [api.md](api.md); per-platform mechanisms are in
[platform-support.md](platform-support.md).

## Why not PID trees

A supervisor that records the PID of the process it launched, and later walks
the process table to find and kill that PID's descendants, depends on
information that ordinary software changes:

- a process that calls `setsid` or `setpgid` leaves the original session or
  process group;
- a parent that exits reparents its children (to `init`/launchd on Unix), so
  ancestry no longer leads back to the task;
- double-forked daemons and shell background jobs routinely end up in exactly
  that state;
- PIDs are reused, so a remembered PID can name an unrelated process later;
- processes keep forking while the supervisor walks the tree.

procd therefore treats the **lifecycle domain**, not a PID, as the unit of
supervision. Where the OS provides a lifecycle grouping (a cgroup on Linux, a
Job Object on Windows), the domain *is* that OS object, and termination is
directed at it. Where it does not (macOS), procd builds the best practical
approximation and reports it as `BEST_EFFORT`.

The guiding rules, as stated in `include/procd.h`:

- authority beats discovery: terminate the OS lifecycle object, not a
  discovered PID list, wherever one exists;
- PID ancestry is not containment, and a PID alone is not identity;
- uncertainty stays uncertainty (`UNRESOLVED` is a first-class result);
- a truthful `UNSUPPORTED` is preferable to a false `ENFORCED`.

## Lifecycle domains

A domain is created empty (`PROCD_STATE_CREATED`). Each successful
`procd_domain_spawn` starts one process inside it (`PROCD_STATE_ACTIVE`); a
domain may hold several spawned tasks. Spawn establishes membership **before**
any workload code runs:

- Linux: the child is moved into the domain's cgroup and its membership is
  verified before it may `exec`.
- Windows: the process is created suspended, assigned to the Job, verified,
  then resumed.
- macOS: while the child is held before `exec`, procd records its
  (pid, start time) generation as a domain member and registers it with the
  watcher; the child then execs with the domain marker in its environment.

If placement cannot be established, the spawn fails and nothing runs. A
failed spawn never terminates other work already in the domain.

`procd_domain_terminate` closes admission first (no later spawn on that
handle can run a workload), then terminates the domain and reports
**evidence**: whether the kill was directed at OS authority and whether the OS
proved the domain empty. On Linux and Windows a successful termination proves
emptiness (`PROCD_STATE_EMPTY`). On macOS emptiness is a scan, never a proof,
so the final state is `PROCD_STATE_UNRESOLVED` even when termination succeeds.

`procd_domain_release` frees the handle. Whether the domain's remaining
processes are killed at release depends on the platform's crash behavior
(Windows: yes; Linux and macOS: no). Release is not a substitute for
terminate.

## Responsibilities

| The caller | procd |
|-----------|-------|
| Decides when a task starts and when it must end (cancel, timeout, failure, shutdown). | Places the task in a domain before it runs. |
| Chooses the policy: require `ENFORCED`, or accept a weaker level and honor the level reported. | Establishes the level on the actual domain at creation and fails closed when required. |
| Calls `procd_domain_terminate` before `procd_domain_release` whenever the task's processes must not outlive it. | Keeps ordinary descendants associated with the domain and terminates them together. |
| Owns the handle: one owner at a time, no use after release. | Never signals processes outside the domain. |
| Runs trusted, ordinary workloads. | Reports what it could and could not establish, including `UNRESOLVED`. |

This is the integration model for a supervisor such as `agentctl`: one domain
per task, `procd_domain_terminate` on every exit path of the task, and
`procd_domain_release` afterwards. procd does not depend on any particular
supervisor.

procd does not provide stdio redirection, working-directory, environment or
resource-limit parameters. The spawned task inherits the caller's environment
and working directory; see [api.md](api.md#procd_domain_spawn) for
per-platform descriptor and handle inheritance.

## Capability reporting

Capabilities are reported at two points:

1. **Discovery** (`procd_capabilities_probe`): a cheap, static preflight of the
   host. It fills six properties (`process_tree_termination`,
   `pre_execution_containment`, `descendant_containment`,
   `topology_escape_resistance`, `domain_emptiness_proof`, `safe_recovery`)
   plus the crash behavior, a backend name and a diagnostic detail string.
2. **Establishment** (`procd_create_domain`): the backend revalidates every
   prerequisite on the real domain, independently of discovery. The level
   actually established is reported per domain by `procd_domain_status_get`.

Under `PROCD_REQUIRE_ENFORCED` a domain that cannot be `ENFORCED` is refused
(`PROCD_E_UNSUPPORTED_ENFORCEMENT`, nothing created, nothing run). Under
`PROCD_ALLOW_BEST_EFFORT` the caller receives the strongest available level
and must inspect it. A backend never reports a level it did not establish.

## Code structure

```
include/procd.h        public C ABI: the OS-neutral contract
src/procd.c            dispatch layer: argument checks, per-handle lock,
                       admission state, fail-closed policy
src/backend.h          internal backend vtable
src/backend_linux.c    cgroup v2 backend
src/backend_windows.c  Job Object backend
src/backend_macos.c    tracked-domain backend with the shared watcher
cli/main.c             the `procd` CLI
tests/                 unit, qualification, platform and workload tests
```

Exactly one backend is compiled in for the target OS; each backend source file
is empty on the others. The dispatch layer owns no containment mechanism. It
serializes every operation on one handle with a per-domain lock, enforces the
admission rule (once terminate begins, spawn fails with `PROCD_E_STATE`), and
forwards to the backend.

## Concurrency

Guaranteed by the header:

- Distinct handles are independent and may be used from different threads.
- Operations on one handle are serialized; concurrent spawn, status,
  terminate and identity calls on the same handle take turns.
- Once terminate begins on a handle, any spawn that has not already made its
  workload executable fails and runs nothing.
- The caller must not release a handle while another operation on it is in
  flight, or use it after release.

### The macOS watcher

On macOS the backend runs one process-wide watcher: a single `kqueue` and a
single background thread shared by every macOS domain in the process. It
starts with the first domain and lives for the rest of the process.

Each domain registers its known members with the watcher. When a member
forks, calls `posix_spawn` or execs, the watcher marks that domain and
reconciles it: it rescans the process table with the domain's own membership
evidence and remembers any new member. Events that arrive together are
coalesced into one reconciliation per domain.

The watcher only accelerates discovery. The kernel event names no child and
proves nothing about membership; membership is always derived from the
domain's own evidence, so an event for one domain cannot add members to
another. The watcher reaches a domain only through a registry and holds a
reference while reconciling it; `procd_domain_release` removes the domain
from the registry and waits for any in-flight reconciliation to finish before
freeing it. If the watcher cannot start, domains still reconcile on every
status and terminate call, and the termination detail says the watcher was
unavailable.

See [platform-support.md](platform-support.md#macos) for the membership
evidence and why this remains `BEST_EFFORT`.
