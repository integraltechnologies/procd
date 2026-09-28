# Testing and qualification

procd is qualified natively on each operating system it supports; nothing is
cross-compiled or emulated. This document describes the method, the test
suites, and the qualification results for this release. Per-platform
mechanisms are in [platform-support.md](platform-support.md).

## Principles

**The topology must be proven to exist.** A test that terminates a domain and
finds no survivor proves nothing if the descendant it was about the never
existed, or had already exited. Every fixture process therefore records a
**witness** (role, pid, parent pid, process group, session, start time;
[`tests/witness.h`](../tests/witness.h)), and the harness cross-checks it
against the kernel's own view before termination. A scenario whose intended
topology was not observed is `SKIP` (or "not established"), never `PASS`. The
CI jobs include vacuity guards: qualifying with `/bin/true` (or
`/usr/bin/true`) as the workload must fail.

**The oracle is independent of procd.** Survivors are judged by the witnessed
(pid, start time) identity, never by procd's own view, so PID reuse cannot
fake a kill and a zombie is never counted as alive.

**Failures are failures at every level.** A witnessed ordinary-topology
process that survives termination is a `FAIL` whatever capability level the
backend reports. `ENFORCED` additionally requires OS-proven emptiness.

**Negative controls prove the harness can see a failure.** A test-only
library variant (`procd_nc`, never production) weakens supervision on demand,
and the same harness must detect the resulting escape.

**Every test process is bounded.** Fixtures have their own lifetime
(`PROCD_ADV_TTL`), so a broken implementation cannot leave processes running
indefinitely.

## Running the tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

Tests that need prerequisites the host lacks exit with code 77 and are
reported by ctest as skipped (for example the Linux cgroup tests on a runner
without a delegated cgroup v2 subtree, or the Cargo test without `cargo`).
Stricter qualification is selected with environment variables:

| Variable | Effect |
|----------|--------|
| `PROCD_REQUIRE_CLEANUP=1` | `procd-qualify-test`: every lifecycle scenario must pass, whatever the reported level. |
| `PROCD_REQUIRE_ENFORCED=1` | Tests that honor it treat any skip as failure and require `ENFORCED`. |
| `PROCD_REQUIRE_CARGO=1` | A missing Cargo toolchain fails the Cargo tests instead of skipping. |
| `PROCD_NC_WEAKEN=1` | Test library only: weaken supervision for the negative controls. |
| `PROCD_SOAK_CYCLES=N` | macOS soak length (default 30). |
| `PROCD_RESIDUAL_ROUNDS=N` | macOS boundary test length (default 20). |

The CLI runs the same lifecycle matrix: `procd qualify [--require-enforced]
[adversary]`.

## Test suites

| ctest name | Platforms | What it establishes |
|------------|-----------|---------------------|
| `unit` | all | Contract invariants: argument validation, name helpers, a fresh domain is `CREATED`, the domain owns a copy of `policy.label` (the caller's buffer can be overwritten and freed immediately), recovery of garbage or live tokens never guesses, reported evidence never exceeds the backend's capabilities, and the expected per-platform levels. |
| `qualify` | all | The shared lifecycle matrix (below). |
| `negative_control` | all | Weakened supervision leaks a detached descendant that production removes. Linux/macOS: process groups alone vs production; Windows: a Job that permits breakaway vs production. |
| `cargo_lifecycle` | all (needs `cargo`) | Real Cargo workloads terminated mid-flight (below). |
| `recovery` | Linux | Forged, stale and edited identity tokens never recover or redirect termination; missing domains are `CONFIRMED_DESTROYED` only with protected evidence. |
| `race` | Linux | Spawn racing terminate on one handle: admission closes permanently, nothing survives, a spawn after termination runs nothing. |
| `identity` | Linux | Default workload credentials are the caller's; explicit run-as ids are fully applied or the spawn fails. |
| `fd_inherit` | Linux | A caller descriptor that is not close-on-exec is not usable by the workload. |
| `establish` | Linux | `ENFORCED` follows whether a cgroup v2 domain can actually be created: read-only hierarchy and undelegated unprivileged callers are refused, a delegated unprivileged caller is `ENFORCED`. |
| `spawn_fail` | Linux | A missing program (absolute path or not on `PATH`) is `PROCD_E_NOT_FOUND` and a non-executable file is `PROCD_E_PERMISSION`; failed spawns run nothing and leave running workloads alone; a later spawn in the same domain runs. |
| `windows_qualification` | Windows | Job mechanism properties (below). |
| `macos_spawn` | macOS | 300 sequential spawns in one domain, each proven to have run, interleaved with failing spawns (`PROCD_E_NOT_FOUND`, `PROCD_E_PERMISSION`); then 24 concurrently live spawns terminated with no survivor; no zombie left and an unrelated process untouched. |
| `macos_tracking` | macOS | A leader reaped by the embedding program still has its orphan cleaned up; an unrelated process in procd's own group and session is never signalled; scan results are never reported as proven. |
| `macos_soak` | macOS | Normal-workload soak (below). |
| `macos_watcher` | macOS | Shared-watcher concurrency (below). |
| `macos_status_reap` | macOS | Status polling from the moment of spawn never loses background jobs of an exited leader (run with the watcher disabled in the test library, so the watcher cannot mask a regression). |
| `macos_residual` | macOS | Boundary measurement; reports escapes, never fails on them (below). |

### Lifecycle matrix

[`tests/qualify.c`](../tests/qualify.c) runs identical scenarios on every
platform, each with witnessed topology, an independent survivor oracle and a
termination bound:

- direct child; grandchild; four children each with a grandchild;
- leader exit with a live descendant; shell background job whose shell exits;
- rapid process creation racing termination;
- a task that already finished (must not read as populated and must clean up
  within 1 s);
- timeout-style teardown with a short termination budget;
- 10 repeated create/spawn/terminate cycles;
- a failed spawn next to a running task: a missing program must report
  `PROCD_E_NOT_FOUND` on every platform, and the task is untouched;
- isolation: terminating one task leaves a concurrent task and an unrelated
  same-user process tree untouched.

Unix adds `exec`, `setsid`, `setpgid`, double fork, reparenting and
environment-cleared descendants. Windows adds `DETACHED_PROCESS` and new
process groups, a detached double spawn, and a `CREATE_BREAKAWAY_FROM_JOB`
request. On Unix the matrix also runs one documented-residual probe (an
environment-cleared, detached descendant); it is reported separately and
never counted as a requirement.

### Real Cargo workloads

[`tests/cargo_test.c`](../tests/cargo_test.c) with the fixture crate
[`tests/cargo_fixture`](../tests/cargo_fixture): procd domain → shell →
`cargo` → a stalled `rustc` (a proc macro sleeping inside the compiler), a
stalled build script with a child and a detached orphaned daemon, or a stalled
integration test with a child, grandchild and detached daemon. The chain
through `cargo` is verified from the kernel's process table, the descendant
tree is recorded, and the domain is terminated mid-flight six times. Every
recorded process must be gone within the bound; a second Cargo task in its
own domain and an unrelated process must survive. The same harness linked
against the weakened library must fail, and does.

### Windows mechanism qualification

[`tests/windows_qualification_test.c`](../tests/windows_qualification_test.c):
suspended pre-execution admission, Job-handle non-inheritance,
unrelated-process safety, termination evidence and status consistency,
termination during process churn, recovery honesty, and supervisor loss
destroying the task. Separate bounded probes attempt the out-of-contract
escapes (Job-handle duplication, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`,
WMI/CIM) and report them as such, never as passes.

## macOS: normal workloads vs. boundary testing

macOS is `BEST_EFFORT`, so two different questions are measured separately.

### Normal-workload qualification

*Does procd reliably terminate ordinary engineering workloads?*

[`tests/macos_soak_test.c`](../tests/macos_soak_test.c) runs realistic tasks
and cancels them at rotating points: immediately after spawn, while
descendants are being created, at establishment, 500 ms later, and 2 s later.
It polls status every 100 ms, as a supervisor would. Workloads:

- sh/bash pipelines, background jobs whose shell exits, nested shells,
  subshell reparenting, `xargs -P`, a process-creating loop;
- Python `subprocess` and `multiprocessing`; Node `child_process` spawn, fork
  and detached children;
- detached helpers whose parent exits: Python `start_new_session=True` and
  Node `detached: true` running Apple platform binaries (`/bin/sleep`,
  `/bin/sh`), whose environment macOS hides;
- real Cargo: `rustc` inside a proc macro, a build script with helpers, a test
  binary with helpers, and plain `cargo check`.

Every 25th cycle runs three concurrent domains (Cargo, Python, nested shells),
terminates one, and requires the other two intact. An unrelated control
process must survive the whole run. The oracle is independent of procd: a
harness-only environment tag plus witnessed (pid, start time) identities and
their descendants. A lifecycle counts as established only when every expected
role was witnessed alive before termination. Any survivor, casualty or
isolation failure fails the run.

[`tests/macos_watcher_test.c`](../tests/macos_watcher_test.c) exercises the
shared watcher: 16 simultaneously live domains terminated one at a time
(no cross-domain effect, unrelated fork-heavy tree intact), 6 threads
concurrently creating, terminating and releasing domains (a quarter released
while fork events are still pending), and rapid create/release cycles.

Results for this release (macOS 26.4, arm64, ordinary user):

| Run | Result |
|-----|--------|
| Soak, `PROCD_SOAK_CYCLES=1000` | 1,080 terminations: 689/689 established lifecycles clean (including 101/101 detached Python/Node helpers), 391/391 early cancellations clean; 0 survivors, 0 unrelated casualties, 0 isolation failures in 40 concurrent-domain runs |
| Soak restricted to the detached-helper workloads | 60/60 established lifecycles clean, 44/44 early cancellations clean |
| Shared-watcher stress | 16-domain, 240 concurrent-cycle and rapid create/release phases: 0 survivors, 0 cross-domain effects (also under Guard Malloc) |
| Lifecycle matrix, `PROCD_REQUIRE_CLEANUP=1` | all 17 lifecycle scenarios pass |
| Cargo lifecycle | 6/6 terminations clean; concurrent Cargo task and unrelated process untouched |
| Spawn regression | 300 sequential spawns in one domain proven to have run, 30 `NOT_FOUND` and 30 `PERMISSION` failures reported correctly, 24 concurrent live spawns terminated with no survivor, no zombies |

Termination latency in the soak was 9 ms at the median and 13 ms at the
maximum.

### Boundary testing

*Where exactly does the `BEST_EFFORT` guarantee stop?*

[`tests/macos_residual_test.c`](../tests/macos_residual_test.c) is
purpose-built to defeat observation. Its task repeatedly forks a child that
execs with an **empty** environment, starts a new session, double-forks and
exits, so the grandchild is reparented to launchd with no marker, no member
ancestry and no member process group, while procd terminates the domain.
Witnesses confirm each escape topology actually formed (reparented, own
session, kernel-visible environment without the marker).

This fixture deliberately races the window described in
[platform-support.md](platform-support.md#macos). Its escape count measures
the residual race; it is **not** a failure rate for ordinary workloads, and
escapes are reported rather than failed.

Result for this release (`PROCD_RESIDUAL_ROUNDS=100`): 383 attempts, 292
established escape topologies, 179 captured, 113 escaped, 0 unrelated
casualties.

[`tests/macos_cargo_bench.c`](../tests/macos_cargo_bench.c) (not part of
ctest) measures watcher cost and mid-build cancellation on a real Cargo
project.

## Continuous integration

GitHub Actions ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)):

- **lint**: `clang-format` check and a warnings-as-errors build.
- **portability**: native build and full ctest on Ubuntu, macOS and Windows
  runners; each test passes or skips for a stated reason.
- **linux-enforced-qualification**: in a privileged container with a private
  cgroup namespace, asserts the prerequisites and `ENFORCED`, runs the vacuity
  guards, the lifecycle matrix, negative controls, recovery, the Cargo
  workload and its negative control, and the full suite with no skips
  allowed; then repeats the lifecycle suite and the Cargo workload as an
  ordinary unprivileged user in a delegated cgroup v2 subtree.
- **macos-native-qualification**: as an ordinary user, asserts `BEST_EFFORT`,
  runs the lifecycle matrix with `PROCD_REQUIRE_CLEANUP=1` and a vacuity
  guard, the tracking regressions, the negative control, the Cargo workload
  and its negative control, and the full suite.
- **windows-native-qualification**: MSVC warnings as errors, unit suite, the
  lifecycle matrix with `PROCD_REQUIRE_CLEANUP=1`, the Job mechanism
  qualification, the breakaway negative control, the Cargo workload, and the
  full suite.
