# Limitations

**procd provides lifecycle supervision. It is not a security boundary.**

procd assumes the caller is trusted and the workload is ordinary software that
is not trying to defeat supervision. It keeps a task's ordinary process
creation associated with the task's domain and terminates that domain. It
does not contain a workload that has, or obtains, independent authority to
create or relocate execution outside the domain, and it does not restrict
what the workload can access (files, network, credentials, other processes).
Use a sandbox, container or separate user account for that.

This page lists where the guarantees stop. Mechanisms are described in
[platform-support.md](platform-support.md).

## Outside the contract on every platform

- **Deliberately leaving the domain**: for example, a workload moving itself
  into another cgroup it can write to (Linux), or creating a process under an
  outside parent with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (Windows).
- **Brokered execution**: work handed to a separate service runs as that
  service's process, not the task's: systemd, cron, launchd, container
  daemons, WMI/CIM, Task Scheduler, SCM, out-of-process COM servers.
- **Cooperating processes**: a same-user process outside the domain that runs
  work on the task's behalf.
- **Authority given by the caller**: descriptors or handles the caller passes
  to the workload (on POSIX, stdin/stdout/stderr are always inherited).

## macOS: the observation race

macOS is `BEST_EFFORT`. procd recognizes a process as a task member through
an inherited environment marker, ancestry, the spawned process's process
group, and remembered (pid, start time) members, and reconciles on every
status and terminate call and whenever a known member forks or execs.

Fork and exec notifications are asynchronous and do not identify the child.
A descendant whose marker is absent (it cleared its environment) or hidden
(Apple platform binaries hide their environment), and that detaches (new
session, then parent exit or a double fork) faster than the triggered
reconciliation observes it, is not found and survives termination. The
shared watcher narrows this window to roughly one reconciliation; it cannot
close it.

Ordinary workloads, including detached helpers whose parent exits, qualify
cleanly; the purpose-built test that deliberately races this window, and why
its escape count is not a normal failure rate, are described in
[testing.md](testing.md#boundary-testing).

Also on macOS:

- `PROCD_OK` from terminate means no member procd could find is still
  running; it is never reported as proven emptiness (final state
  `UNRESOLVED`).
- The policy's run-as uid/gid are ignored.
- Descriptors not marked close-on-exec are inherited by the task.

## Supervisor loss and recovery

| Platform | If the supervisor dies or releases without terminating | Recovery |
|----------|--------------------------------------------------------|----------|
| Windows | The kernel kills the task (`KILL_ON_JOB_CLOSE`). | Not supported. |
| Linux | The task keeps running in its cgroup. | Root only, for domains created by root, from the protected record in `/var/lib/procd`. |
| macOS | The task keeps running. | Not supported. |

A restarted supervisor on Linux (without root recovery) or macOS has no handle
to a previous task. If tasks must not outlive the supervisor there, run the
supervisor itself under a service manager that stops its whole process tree,
or ensure the supervisor always terminates its domains before exiting.

## Prerequisites and failure modes

- **Linux** requires cgroup v2 mounted read-write at `/sys/fs/cgroup`,
  `cgroup.kill` (kernel ≥ 5.14), and a writable own cgroup (root or a
  delegated subtree). Without them no domain is created; there is no weaker
  Linux fallback.
- **Termination can time out.** `PROCD_E_TIMEOUT` means emptiness was not
  reached within the bound; processes may remain, and terminate can be
  called again.
- **`PROCD_OK` differs by level.** At `ENFORCED` it is OS-proven emptiness
  (`ev.enforced`). At `BEST_EFFORT` it is not; callers that need the proof
  should check `ev.enforced` or create domains with `PROCD_REQUIRE_ENFORCED`.

## API stability

This is the v0 C ABI. Structs may gain fields before v1 and carry no version
field; compile against the header matching the library you link. See
[api.md](api.md#abi-and-compatibility).
