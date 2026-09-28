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
| **Windows** | unnamed Job Object, `KILL_ON_JOB_CLOSE`, no breakaway | **BEST_EFFORT** | Suspended-create → assign-to-Job → verify → resume. Job-tracked descendant containment and emptiness (`ActiveProcesses==0`) are authoritative, but broker/parent-substitution escapes (WMI, Task Scheduler, SCM, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) are **not** closed, so the aggregate is deliberately **not** `ENFORCED`. |
| **macOS** | — | **UNSUPPORTED** | No supported mechanism (tested on macOS 26.4 arm64) provides inherited, non-escapable, authoritatively-terminable domains: process groups escape via `setpgid`/`setsid`/double-fork; `EVFILT_PROC` `NOTE_TRACK` is `ENOTSUP`; coalitions lack kill-all-now; Endpoint Security is observation, not containment. `procd` fails closed and does not fake it. |

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
- **Qualification matrix** ([`tests/qualify.c`](tests/qualify.c)) — bounded
  adversarial fixtures: child, grandchild, exec, `setsid`, `setpgid`,
  double-fork, reparent, leader-exit, rapid churn, plus recovery and
  fail-closed checks. Every fixture process records a witness (role, pid,
  ppid, pgid, sid, start time; [`tests/witness.h`](tests/witness.h)), and a
  scenario can only `PASS` once its adversarial topology was independently
  observed *and* no witnessed process survives termination (judged by pid +
  start time, not by procd). Distinguishes `PASS` / `SKIP` (prerequisite
  unavailable, precondition not observed — e.g. the workload never executed —
  or backend truthfully does not claim the guarantee) / `FAIL` (a claimed
  guarantee was not upheld). `--require-enforced` (or
  `PROCD_REQUIRE_ENFORCED=1` for the test binaries) turns every skip into a
  failure.
- **Negative controls**
  ([`tests/negative_control_test.c`](tests/negative_control_test.c)) — a
  test-only weakened supervision demonstrates the *same* workload surviving
  termination, proving the harness can observe the failure the production
  mechanism prevents. On Linux the weakening is process-group termination and
  the workload detaches a descendant with `setsid` or a double fork (ordinary
  topology changes); production cgroup termination removes the same topology.
  On Windows it is a Job that permits breakaway. Production supervision can
  never be weakened — the switch only compiles into a separate test library.
- **macOS escape demonstration**
  ([`tests/macos_escape_test.c`](tests/macos_escape_test.c)) — actively shows a
  double-forked descendant surviving `killpg`, the evidence behind
  `UNSUPPORTED`.
- **Windows native qualification**
  ([`tests/windows_qualification_test.c`](tests/windows_qualification_test.c)) —
  uses fixture witnesses plus retained process handles/creation times to test
  suspended pre-exec admission, ordinary child/grandchild containment after
  leader exit, termination during spawn churn, Job-handle non-inheritance,
  unrelated-process safety, recovery honesty, and capability/evidence
  consistency. Separate bounded probes try same-user Job-handle duplication,
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, and WMI/CIM broker creation; inability
  to establish an escape precondition is reported as `INCONCLUSIVE`, never
  relabeled `PASS`.

Every test process has its own bounded lifetime (`PROCD_ADV_TTL`), so a broken
implementation can never leave an indefinitely running process.

## CI

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- **lint** — `clang-format` + warnings-as-errors build.
- **portability** — native build and test on `ubuntu-latest`, `macos-latest`,
  and `windows-latest`. Green means "builds natively and every test passed or
  skipped for a stated reason"; it is **not** evidence of `ENFORCED` anywhere.
  Nothing is cross-compiled.
- **windows-native-qualification** — builds with MSVC warnings as errors, runs
  portable contract tests, the required Windows Job mechanism qualification,
  and a real breakaway negative control. Required mechanism cases cannot skip;
  explicitly unclaimed escape probes may remain `INCONCLUSIVE`. Green means the
  `BEST_EFFORT` model behaved as reported, not that Windows is `ENFORCED`.
- **linux-enforced-qualification** — the only job whose green means Linux
  `ENFORCED` lifecycle grouping was demonstrated. In a privileged container with
  a private cgroup namespace it asserts the prerequisites and reported level,
  checks that `/bin/true` and a non-executable adversary do **not** qualify,
  and requires every topology scenario, the negative control and the full
  suite (including root-only recovery/establishment tests) to pass with no
  skips; it then repeats the lifecycle suite as an ordinary unprivileged user
  in a delegated cgroup-v2 subtree.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
