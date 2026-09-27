# procd

Cross-platform process **lifecycle ownership and supervision**.

`procd` establishes an *invocation domain* that owns everything a launched
workload does, so that a domain can later be terminated with authoritative,
OS-backed evidence that **no owned executable work remains** — even if the
workload forked, exec'd, detached, changed process groups or sessions,
reparented, double-forked, or otherwise manipulated ordinary process topology.

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

Each property is reported as `ENFORCED` (the OS guarantees it against an
adversarial workload), `BEST_EFFORT` (a cooperating workload respects it, an
adversary can defeat it), or `UNSUPPORTED`. `ProcessTreeTermination` is the
aggregate hard claim and is only `ENFORCED` when every backend prerequisite for
the invariant is established **at runtime** — the backend revalidates
prerequisites and fails closed even if the caller skipped capability discovery.

## Platform status

| Platform | Mechanism | `ProcessTreeTermination` | Notes |
|----------|-----------|--------------------------|-------|
| **Linux** | cgroup v2 protected hierarchy, `cgroup.kill`, privilege drop | **ENFORCED** (root + cgroup v2 + `cgroup.kill`) | Workload admitted before exec; dropped to an unprivileged uid so it cannot migrate out of the domain. Emptiness proven via `cgroup.events` `populated==0`. Durable identity names a root-owned record in `/var/lib/procd`; recovery trusts only that record (boot id, cgroup view, path, inode, established level), so an edited identity yields `UNRESOLVED` rather than redirecting authority. Falls back to `BEST_EFFORT`/refusal without the prerequisites. |
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
  ([`tests/negative_control_test.c`](tests/negative_control_test.c)) — for every
  `ENFORCED` claim, a test-only weakened boundary demonstrates the *same*
  adversary **escaping** and surviving termination (the migration attempt and
  its outcome are witnessed), proving the harness can
  observe the failure it claims to prevent; the production boundary then
  prevents the escape. Production containment can never be weakened — the
  weakening switch only compiles into a separate test library.
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
  `ENFORCED` was demonstrated. It runs in a privileged container with a private
  cgroup namespace, asserts every prerequisite and the reported capability
  level up front, checks that `/bin/true` and a non-executable adversary do
  **not** qualify, then requires every adversarial scenario, the negative
  control, and the recovery regression to pass with no skips.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
