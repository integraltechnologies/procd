# Platform support

procd has one backend per operating system, selected at compile time. The
backends share the API and the capability model, but not their kernel
mechanisms: Linux and Windows group a task's descendants in the kernel, while
macOS has no unprivileged mechanism that does, so procd tracks membership
itself.

- [Capability summary](#capability-summary)
- [Linux](#linux)
- [Windows](#windows)
- [macOS](#macos)

## Capability summary

Values reported by `procd_capabilities_probe`:

| Property | Linux (usable host) | Linux (no usable cgroup v2 domain) | Windows | macOS |
|----------|---------------------|------------------------------------|---------|-------|
| `backend` | `linux-cgroup2` | `linux-cgroup2` | `windows-job` | `macos-tracked` |
| `process_tree_termination` | ENFORCED | UNSUPPORTED | ENFORCED | BEST_EFFORT |
| `pre_execution_containment` | ENFORCED | UNSUPPORTED | ENFORCED | BEST_EFFORT |
| `descendant_containment` | ENFORCED | UNSUPPORTED | ENFORCED | BEST_EFFORT |
| `topology_escape_resistance` | ENFORCED | UNSUPPORTED | ENFORCED | BEST_EFFORT |
| `domain_emptiness_proof` | ENFORCED | UNSUPPORTED | ENFORCED | BEST_EFFORT |
| `safe_recovery` | ENFORCED as root with the record store, else UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED |
| `crash_behavior` | `DURABLE_REACQUISITION` as root with the record store, else `UNRESOLVED_ON_AUTHORITY_LOSS` | `UNRESOLVED_ON_AUTHORITY_LOSS` | `AUTOMATIC_DESTRUCTION` | `UNRESOLVED_ON_AUTHORITY_LOSS` |

Behavior on release and supervisor loss:

| | Linux | Windows | macOS |
|---|---|---|---|
| `procd_domain_release` with processes still running | they keep running in the cgroup | they are killed | they keep running, untracked |
| Supervisor process dies | the cgroup and its processes survive | the kernel kills the Job's processes | the processes keep running |
| `procd_recover` | root only, from a protected record | always `UNRESOLVED` | always `UNRESOLVED` |

## Linux

**Mechanism.** Each domain is a new cgroup v2 directory, `procd.<16 hex>`,
created as a child of the calling process's own cgroup (the `0::` entry of
`/proc/self/cgroup`) under `/sys/fs/cgroup`.

**Prerequisites** (checked by discovery and again at creation):

- cgroup v2 mounted at `/sys/fs/cgroup`, not read-only;
- the caller's own cgroup and its `cgroup.procs` writable by the caller: root,
  or an ordinary user that owns a delegated cgroup v2 subtree (as provided by,
  for example, a systemd unit with delegation);
- `cgroup.kill` available (Linux ≥ 5.14), and `cgroup.events` readable on the
  created domain.

If any prerequisite is missing, discovery reports `UNSUPPORTED` and no domain
is created: `PROCD_E_UNSUPPORTED_ENFORCEMENT` under `PROCD_REQUIRE_ENFORCED`,
`PROCD_E_PREREQUISITE` under `PROCD_ALLOW_BEST_EFFORT`. There is no weaker
Linux fallback. Root is not required; the workload runs with the caller's
credentials unless the policy's run-as uid/gid is set.

**Spawn.** The child writes itself into the domain's `cgroup.procs`, the
parent verifies the child's cgroup, and only then may the child close
inherited descriptors (all except stdin, stdout and stderr), apply the
optional run-as identity and `execvp` the workload. Any failure kills that
not-yet-executed child only.

**Membership.** The kernel places every process the task creates in the same
cgroup, whatever it does with sessions, process groups or its parent. Grouping
does not depend on PIDs.

**Termination.** Writes `1` to `cgroup.kill`, which kills every process in the
cgroup including ones forked during the kill, waits for `cgroup.events` to
report `populated 0`, and removes the directory. The result is proven
emptiness (`PROCD_STATE_EMPTY`, `enforced = 1`). procd never signals a
discovered PID list on Linux.

**Status.** `population` comes from `cgroup.events` and is authoritative.

**Recovery.** When the domain is created by root, procd writes a record
(boot id, cgroup namespace view, cgroup path and inode, level, run-as ids) to
`/var/lib/procd`, a root-owned directory that must not be writable by group
or other, created on demand with mode 0700. `procd_recover` (root only) trusts
only this record and requires the token to match it exactly:

- same boot, same cgroup inode present: `PROCD_RECOVERED`;
- cgroup gone, or replaced by a different inode, for a domain recorded at
  `ENFORCED`: `PROCD_CONFIRMED_DESTROYED`;
- anything unverifiable: `PROCD_UNRESOLVED`.

Domains created by an unprivileged caller work normally but have no record
and cannot be recovered.

**Known limitations.** A workload that moves itself into another cgroup it
can write to, or hands work to an external service (systemd, cron, container
daemons), leaves the domain; both are outside the contract. Descriptors the
caller deliberately passes as stdin/stdout/stderr are inherited.

## Windows

**Mechanism.** One unnamed Job Object per domain, created with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and without `BREAKAWAY_OK` or
`SILENT_BREAKAWAY_OK`. The Job handle is not inheritable. Job creation needs
no special privilege; if it fails, no domain is created.

**Spawn.** `argv` is joined into a command line using MSVC quoting rules. The
process is created with `CREATE_SUSPENDED | CREATE_NO_WINDOW` and without
handle inheritance, assigned to the Job, verified with `IsProcessInJob`, and
only then resumed. Nothing of it runs before it is in the Job.

**Membership.** Job membership is inherited by the kernel. Descendants stay in
the Job regardless of creation flags (`DETACHED_PROCESS`,
`CREATE_NEW_PROCESS_GROUP`, new consoles, `start /b`), parent exit, or nested
Jobs created by tools such as Cargo. A child created with
`CREATE_BREAKAWAY_FROM_JOB` fails to start.

**Termination.** Admission is closed at the OS level first (an active-process
limit of 1, so a process joining from then on is terminated as it is created).
Then `TerminateJobObject` is repeated until the kernel's `ActiveProcesses`
count for the Job is 0, which is proven emptiness.

**Status.** `population` comes from the Job's kernel accounting and is
authoritative.

**Supervisor loss and release.** When the supervisor exits or dies, or
releases the domain, the last Job handle closes and `KILL_ON_JOB_CLOSE` kills
every process still in the Job.

**Recovery.** Not supported. An unnamed Job cannot be reacquired by another
process, and the identity token is process-local; `procd_recover` always
reports `PROCD_UNRESOLVED`.

**Known limitations.** Out of contract and not contained (the native
qualification reproduces these and reports them separately, never as passes):

- creating a process with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at a
  process outside the Job;
- duplicating the supervisor's Job handle to keep the Job alive;
- execution brokered through system services (WMI/CIM, Task Scheduler, SCM,
  out-of-process COM servers).

## macOS

**Why not a kernel domain.** macOS offers no unprivileged mechanism that
groups a process tree independently of topology: process groups and sessions
are left by `setsid`/`setpgid` and double forks, `EVFILT_PROC` `NOTE_TRACK`
returns `ENOTSUP`, resource coalitions cannot be created without
entitlements, and Endpoint Security requires root, a restricted entitlement
and user approval. procd therefore tracks domain membership itself and
reports `BEST_EFFORT`.

**Membership evidence.** A process is a member if any of these holds:

1. **Domain marker.** Every spawned process starts with the environment
   variable `PROCD_DOMAIN_<128-bit random nonce>=1`, which ordinary process
   creation inherits and which shells, Cargo, rustc, build scripts, test
   harnesses, Python and Node pass on. procd reads each same-user process's
   exec-time environment with `sysctl(KERN_PROCARGS2)`. The kernel hides that
   environment for Apple platform binaries (`/bin/sh`, `/bin/sleep`, `perl`,
   ...), so the marker is never the only evidence.
2. **Ancestry.** A process whose parent is a member is a member.
3. **Remembered generations.** Every member found is remembered as
   (pid, kernel start time). A remembered member stays a member after it
   clears its environment, changes session or process group, or is
   reparented. PID reuse cannot alias a generation; generations that are no
   longer running are forgotten.
4. **Process groups.** Each spawned process leads its own process group;
   members of that group are members while the spawned process still holds
   the group id (running, or exited but not yet reaped). `status` reaps an
   exited spawned process only after a scan has used its group.

**Reconciliation.** A reconciliation is one scan of the process table
applying the evidence above and remembering what it finds. It runs:

- on every `procd_domain_status_get` and throughout `procd_domain_terminate`;
- continuously, through one process-wide watcher: a single `kqueue` and a
  single background thread shared by all macOS domains in the process. The
  watcher registers `EVFILT_PROC` `NOTE_FORK | NOTE_EXEC` on every known
  member, including each spawned process before it runs workload code
  (`posix_spawn` also posts `NOTE_FORK`). When a member forks or execs, the
  watcher reconciles that domain immediately; events that arrive together are
  coalesced into one reconciliation per domain.

The watcher lets procd remember a new child while its ancestry still links it
to the task, before it can detach or be reparented. This is what covers
ordinary detached helpers, such as Python `subprocess` with
`start_new_session=True` or Node `spawn(..., {detached: true})` running an
Apple platform binary, whose parent then exits. The kernel event names no
child and is not itself evidence; membership always comes from the scan. If
the watcher cannot start, supervision continues with status/terminate
reconciliation, and the termination detail says so.

**Spawn.** The child is placed in its own process group and held before
`exec` until procd has recorded its generation and registered it with the
watcher; it then `execvp`s with the caller's environment plus the marker.
Descriptors not marked close-on-exec are inherited. The policy's run-as
fields are ignored. procd keeps bookkeeping for a spawned process only while
it can still hold its pid (running, or exited and not yet reaped) and drops
it once the process is reaped, so a domain accepts any number of spawns.
procd only reaps a process whose exact (pid, start time) is still its own
unreaped child.

**Termination.** Admission closes; watcher reconciliation for the domain
stops; procd then repeatedly scans and sends `SIGSTOP` to every member until a
scan finds no new member (stopped processes cannot fork, so the set
converges), sends `SIGKILL` to the frozen set, and rescans and kills until no
member runs or the timeout expires. Every signal is sent only after
re-confirming the target's (pid, start time), so a reused PID is never
signalled. Processes that carry neither the marker nor member ancestry, group
or generation (other tasks, other users, the caller) are never signalled.

**Status and results.** Population is a scan and never authoritative.
`PROCD_OK` from terminate means every member procd found was killed and a
final scan found none; `emptiness_proven` and `enforced` are 0 and the final
state is `PROCD_STATE_UNRESOLVED`.

**Supervisor loss, release, recovery.** Nothing kills the task if the
supervisor dies or releases the domain without terminating it. Recovery is
not offered (`PROCD_UNRESOLVED`).

**Why BEST_EFFORT.** Fork and exec notifications are asynchronous and do not
identify the child. A descendant whose marker is absent or hidden, and that
detaches (new session, then parent exit or a double fork) faster than the
triggered reconciliation observes it, is not found. The watcher narrows this
window to roughly one reconciliation; it cannot close it, so macOS cannot
truthfully report `ENFORCED`. Ordinary workloads qualify cleanly (see
[testing.md](testing.md)); the purpose-built boundary test that deliberately
races this window is described there and is not a normal failure rate.
