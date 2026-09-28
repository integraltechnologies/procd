# procd

Cross-platform process **lifecycle ownership and supervision**.

`procd` establishes an *invocation domain* for a task, so that a supervisor can
later terminate the task's whole process tree with OS-backed evidence that
**none of its processes remain** — even if the task forked, exec'd, detached,
changed process groups or sessions, reparented, double-forked, or otherwise
changed ordinary process topology — without reconstructing a PID tree and
without touching unrelated processes.

`procd` is lifecycle supervision, **not a sandbox**. The caller is trusted and
the workload is not assumed to try to defeat supervision; deliberately leaving
the domain (e.g. rewriting cgroup membership), work handed to external services
(systemd, cron, launchd, container daemons, SCM/WMI), and authority the caller
deliberately hands the workload are outside the contract.

Its guiding principles:

- **Authority beats discovery.** Termination targets the OS lifecycle authority
  (a cgroup, a Job Object), never a discovered list of PIDs.
- **PID ancestry is not containment. PID is not durable identity.**
- **Uncertainty stays uncertainty.** Recovery returns `RECOVERED`,
  `CONFIRMED_DESTROYED`, or `UNRESOLVED`; it never guesses.
- **A truthful `UNSUPPORTED` is preferable to a false `ENFORCED`.** A backend
  fails closed rather than silently downgrading a requested guarantee.

## Architecture

The canonical product is an OS-neutral **semantic contract**, expressed as a
small, stable **C ABI** in [`include/procd.h`](include/procd.h). No
implementation language is privileged: native backends sit beneath the contract
and thin language bindings can sit above it. This v0 ships one binding (the C
ABI itself) plus a tiny CLI; adding a Rust/Swift/Python/Go binding later does
not require re-designing the lifecycle semantics.

```
        OS-neutral lifecycle-domain contract   (include/procd.h)
                          |
        native lifecycle implementation        (src/backend_*.c)
                          |
              language / API bindings           (C ABI today)
```

## Capability model

Each property is reported as `ENFORCED` (an OS lifecycle-domain mechanism
provides it directly: ordinary descendants stay grouped independently of
PID/process-group/session topology, and procd terminates and observes the
domain itself), `BEST_EFFORT` (approximated with weaker mechanisms, e.g.
process groups, that ordinary topology changes such as `setsid` can defeat), or
`UNSUPPORTED`. `ProcessTreeTermination` is the aggregate claim and is only
`ENFORCED` when the backend establishes it on the actual domain **at runtime**;
it fails closed rather than silently downgrading, even if the caller skipped
capability discovery.

## Platform status

| Platform | Mechanism | `ProcessTreeTermination` | Notes |
|----------|-----------|--------------------------|-------|
| **Linux** | cgroup v2 child of procd's own cgroup, `cgroup.kill`, `cgroup.events` | **ENFORCED** (cgroup v2 + `cgroup.kill` + a writable own cgroup: root, or an ordinary user with a delegated subtree) | Workload admitted to the cgroup and verified before exec; it runs with the caller's credentials (optional explicit run-as uid/gid). Termination writes `cgroup.kill`; emptiness via `cgroup.events` `populated 0`. Recovery (root only) trusts a root-owned record in `/var/lib/procd` (boot id, cgroup view, path, inode, level), so a stale or edited identity yields `UNRESOLVED` rather than redirecting termination. Without a usable cgroup-v2 domain nothing is created (no Linux fallback). |
| **Windows** | unnamed Job Object per domain, `KILL_ON_JOB_CLOSE`, no breakaway | **ENFORCED** | Suspended-create → assign-to-Job → verify → resume. Every ordinary descendant stays in the Job whatever its creation flags (`DETACHED_PROCESS`, new process group, `start /b`, parent exit, nested Jobs such as cargo's); a `CREATE_BREAKAWAY_FROM_JOB` request is refused. Termination closes admission (active-process limit), repeats `TerminateJobObject` until the kernel's `ActiveProcesses` is 0 (proven emptiness), and supervisor exit kills the Job. Out of contract, reproduced natively and reported separately: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with a handle to an outside process, duplicating the supervisor's Job handle, and WMI/Task Scheduler/SCM brokers. Recovery: `UNSUPPORTED`. |
| **macOS** | tracked domain: inherited per-domain environment marker + ancestry + remembered (pid, start time) generations + process groups; freeze (`SIGSTOP`) then kill | **BEST_EFFORT** | No unprivileged kernel lifecycle domain exists (process groups are left by `setsid`/`setpgid`/double fork, `NOTE_TRACK` is `ENOTSUP`, coalitions need entitlements). procd tracks members itself: the marker is inherited through fork/exec/`setsid`/double fork/reparenting and passed on by shells, cargo, rustc, build scripts and test harnesses, and is read from each same-user process's exec-time environment (`KERN_PROCARGS2`); descendants that clear their environment are still found through ancestry and remembered generations. Termination SIGSTOPs members until the set converges (stopped processes cannot fork), SIGKILLs them, and rescans until none runs; every signal re-confirms the target's generation, so unrelated processes are never signalled. Natively qualified on every ordinary topology and the Cargo workload. Emptiness is a scan, so it is never reported as proven (final state `UNRESOLVED`, `PROCD_OK` = none found). Residual: a descendant that discards its whole environment **and** detaches (new session + double fork) before procd observes it. No crash cleanup or recovery: if the supervisor dies the task keeps running. |

### Using procd from agentctl

- Call `procd_domain_terminate` on cancel, timeout, failure and shutdown; a
  `PROCD_OK` return means the task's processes are gone (Linux/Windows: proven
  by the kernel; macOS: no tracked member remains).
- Supervisor death: Windows kills the task (`KILL_ON_JOB_CLOSE`). On Linux the
  cgroup survives the supervisor (recoverable only by root); on macOS nothing
  kills the task. A restarted agentctl on those platforms has no handle to the
  old task, so run agentctl itself under a service manager that stops its
  process tree (systemd unit / launchd job), or avoid unclean supervisor exits.
- macOS: do not rely on procd for a task that deliberately runs `env -i` and
  then daemonizes; ordinary tools keep the environment and are covered.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Requires a C11 compiler and CMake ≥ 3.16. No async runtime, no package-manager
lock-in.

## CLI

```bash
procd capabilities            # print statically-discovered capabilities
procd qualify [--require-enforced] [adversary]
                              # run the adversarial qualification matrix
procd run [--require-enforced] -- <cmd> [args...]
```

`--require-enforced` refuses to launch unless `ProcessTreeTermination` can be
`ENFORCED` on the host.

## Testing & qualification

- **Portable unit tests** — contract invariants on every platform.
- **Lifecycle matrix** ([`tests/qualify.c`](tests/qualify.c)), identical on
  Linux, macOS and Windows — bounded fixtures for: direct child, grandchild,
  leader exit with a live descendant, shell background job whose shell exits,
  four children each with a grandchild, rapid churn racing termination, a
  timeout-style teardown, 10 repeated create/spawn/terminate cycles, a failed
  spawn next to a running task, and two concurrent tasks plus an unrelated
  same-user tree (terminating one task touches nothing else). Unix adds `exec`,
  `setsid`, `setpgid`, double fork, reparenting and environment-cleared
  descendants; Windows adds `DETACHED_PROCESS`/new process group, a detached
  double spawn, and a `CREATE_BREAKAWAY_FROM_JOB` request. Every fixture process
  records a witness (role, pid, ppid, pgid, sid, start time;
  [`tests/witness.h`](tests/witness.h)), so a scenario only counts once its
  topology was independently observed. A scenario `FAIL`s — at any reported
  capability level — if a witnessed process survives, termination fails or
  overruns its bound, or status called the domain empty while a task process
  ran; `ENFORCED` additionally requires proven emptiness. `SKIP` (prerequisite
  missing, topology not observed) is never success: `PROCD_REQUIRE_CLEANUP=1`
  requires every scenario to pass, `--require-enforced` /
  `PROCD_REQUIRE_ENFORCED=1` also requires `ENFORCED`. A probe of the macOS
  residual (environment cleared + detached) is reported, never counted.
- **Real Cargo workload** ([`tests/cargo_test.c`](tests/cargo_test.c),
  fixture [`tests/cargo_fixture`](tests/cargo_fixture)) — procd domain → shell
  → `cargo` → stalled `rustc` (a proc macro sleeping inside the compiler), a
  stalled build script with a child and a detached orphaned daemon, or a
  stalled integration test with a child, grandchild and detached daemon. The
  kernel-visible chain through `cargo` is verified, the whole descendant tree
  is recorded, the domain is terminated mid-flight, and every recorded process
  must be gone within the bound. A second Cargo task in its own domain and an
  unrelated process must survive all six terminations, and afterwards no
  process from the test's scratch tree may exist. `PROCD_REQUIRE_CARGO=1` makes
  a missing toolchain a failure. The same harness linked to the weakened
  (process-group) library must fail, and does: the detached Cargo daemons
  leak.
- **Negative controls**
  ([`tests/negative_control_test.c`](tests/negative_control_test.c)) — a
  test-only weakened supervision demonstrates the *same* workload surviving
  termination, proving the harness can observe the failure the production
  mechanism prevents. On Linux and macOS the weakening is process groups alone
  and the workload detaches with `setsid` or a double fork; production removes
  the same topology. On Windows it is a Job that permits breakaway. Production
  supervision can never be weakened — the switch only compiles into a separate
  test library.
- **macOS tracking regressions**
  ([`tests/macos_tracking_test.c`](tests/macos_tracking_test.c)) — a leader
  reaped by the embedding caller still has its orphan cleaned up; an unrelated
  process sharing procd's own process group and session is never signalled;
  scan-based results are never reported as proven.
- **Windows mechanism qualification**
  ([`tests/windows_qualification_test.c`](tests/windows_qualification_test.c)) —
  suspended pre-exec admission, Job-handle non-inheritance, unrelated-process
  safety, termination evidence/status consistency, termination during churn,
  recovery honesty, and supervisor loss destroying the task. Separate bounded
  probes attempt the out-of-contract escapes (Job-handle duplication,
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, WMI/CIM); they are reported as such,
  never as passes.

Every test process has its own bounded lifetime (`PROCD_ADV_TTL`), so a broken
implementation can never leave an indefinitely running process.

## CI

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- **lint** — `clang-format` + warnings-as-errors build.
- **portability** — native build and test on `ubuntu-latest`, `macos-latest`,
  and `windows-latest`; every test passes or skips for a stated reason.
- **linux-enforced-qualification** — in a privileged container with a private
  cgroup namespace: prerequisites and reported level asserted, vacuity guards
  (`/bin/true`, a missing adversary) must not qualify, the lifecycle matrix,
  negative controls, recovery, the real Cargo workload and its weakened
  negative control, and the full suite with no skips; then the lifecycle suite
  and the Cargo workload again as an ordinary unprivileged user in a delegated
  cgroup-v2 subtree.
- **macos-native-qualification** — as an ordinary user on a macOS runner:
  `BEST_EFFORT` asserted, the lifecycle matrix with `PROCD_REQUIRE_CLEANUP=1`
  (plus a vacuity guard), tracking regressions, the negative control, the real
  Cargo workload, the Cargo negative control, and the full suite.
- **windows-native-qualification** — MSVC warnings as errors; unit suite, the
  lifecycle matrix with `PROCD_REQUIRE_CLEANUP=1`, the Job mechanism
  qualification, the breakaway negative control, the real Cargo workload, and
  the full suite.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
