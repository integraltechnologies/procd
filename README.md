# procd

`procd` is a small cross-platform process lifecycle supervision library with a
C API.

A supervisor launches a task (a shell command, a build, a test run, a coding
agent) and later needs to stop it: on cancel, timeout, failure or shutdown.
The task may have started children, grandchildren, background jobs and
detached helpers by then. Rebuilding that PID tree and killing it is racy and
misses processes that changed session, process group or parent. procd instead
gives the supervisor one **lifecycle domain** per task: the task's first
process is placed in the domain before it runs, its ordinary descendants stay
associated with it, and the supervisor terminates the domain as a whole
without touching unrelated processes.

procd is lifecycle supervision. It is **not** a sandbox, a security boundary
or a container runtime, and it does not contain workloads that deliberately
try to leave supervision. See [docs/limitations.md](docs/limitations.md).

## Lifecycle

```
procd_create_domain          create a lifecycle domain (fails closed if the
        |                    requested level cannot be established)
procd_domain_spawn           start the task inside the domain
        |                    (keep the procd_domain handle)
procd_domain_status_get      query level, state and population as needed
        |
procd_domain_terminate       terminate everything the domain holds;
        |                    returns evidence of what was established
procd_domain_release         free the handle
```

The caller decides **when** a task ends; procd owns **how** the domain is
supervised and terminated.

## Platform support

| Platform | Mechanism | `ProcessTreeTermination` |
|----------|-----------|--------------------------|
| Linux    | cgroup v2: one child cgroup of the caller's own cgroup per domain; kill via `cgroup.kill`, emptiness via `cgroup.events` | `ENFORCED` when cgroup v2 is mounted read-write, `cgroup.kill` exists (kernel ≥ 5.14) and the caller's own cgroup is writable (root, or a delegated subtree). Otherwise `UNSUPPORTED` and no domain is created. |
| Windows  | One unnamed Job Object per domain, kill-on-close, no breakaway; kernel active-process count as emptiness | `ENFORCED` |
| macOS    | Tracked domain: inherited per-domain environment marker, ancestry, process groups and remembered (pid, start time) members, reconciled on status/terminate and continuously by a shared process-wide `kqueue` watcher on fork/exec activity; freeze then kill | `BEST_EFFORT` |

The platforms do not provide identical kernel semantics. Linux and Windows
group descendants in the kernel; macOS has no unprivileged equivalent, so
procd tracks membership itself. Details, prerequisites and recovery behavior:
[docs/platform-support.md](docs/platform-support.md).

## Capability levels

| Level | Meaning |
|-------|---------|
| `ENFORCED` | An OS lifecycle-domain mechanism provides the property: ordinary descendant creation stays associated with the domain independently of PID, process-group and session topology, and procd terminates and observes the domain itself. |
| `BEST_EFFORT` | procd provides practical supervision with weaker mechanisms, but cannot guarantee membership for every descendant topology. |
| `UNSUPPORTED` | No supported mechanism establishes the property on this host. |

`ProcessTreeTermination` is the aggregate claim. It is established per domain
at creation time, not by capability discovery: under
`PROCD_REQUIRE_ENFORCED` (the default policy) creation is refused with
`PROCD_E_UNSUPPORTED_ENFORCEMENT` rather than silently downgraded.

## Example

```c
#include <procd.h>
#include <stdio.h>

int run_task(void) {
    procd_policy policy = PROCD_POLICY_INIT;      /* defaults to PROCD_REQUIRE_ENFORCED */
    policy.enforcement = PROCD_ALLOW_BEST_EFFORT; /* also accept macOS BEST_EFFORT */

    procd_domain *domain = NULL;
    procd_status rc = procd_create_domain(&policy, &domain);
    if (rc != PROCD_OK) {
        fprintf(stderr, "procd_create_domain: %s\n", procd_status_name(rc));
        return -1;
    }

    procd_domain_status st;
    procd_domain_status_get(domain, &st);
    printf("level: %s\n", procd_capability_name(st.process_tree_termination));

    const char *const argv[] = {"cargo", "test", NULL};
    rc = procd_domain_spawn(domain, argv, NULL);
    if (rc != PROCD_OK) {
        fprintf(stderr, "procd_domain_spawn: %s\n", procd_status_name(rc));
        procd_domain_release(domain);
        return -1;
    }

    /* ... the task runs; on cancel, timeout, failure or shutdown: */
    procd_termination_evidence ev;
    rc = procd_domain_terminate(domain, 5000 /* ms */, &ev);
    printf("terminate: %s, final state %s, emptiness proven: %d (%s)\n",
           procd_status_name(rc), procd_state_name(ev.final_state),
           ev.emptiness_proven, ev.detail ? ev.detail : "");

    procd_domain_release(domain); /* ev.detail is invalid after this */
    return rc == PROCD_OK ? 0 : -1;
}
```

The complete API, including status polling, timeouts, spawn failures and
recovery, is in [docs/api.md](docs/api.md).

## Build and test

Requires CMake ≥ 3.16 and a C11 compiler (GCC/Clang on Linux and macOS, MSVC on
Windows).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The build produces the static library `procd` (target `procd`), the CLI
`procd` and the test programs. There are no install rules yet; to use the
library from another CMake project, add this repository with
`add_subdirectory` and link the `procd` target, which carries its include
directory and thread dependency.

The CLI is a thin exerciser of the library:

```bash
build/procd capabilities                              # statically discovered capabilities
build/procd run [--require-enforced] -- <cmd> ...     # supervise a command until its domain is empty
build/procd qualify [--require-enforced] [adversary]  # run the lifecycle qualification matrix
```

How procd is qualified, including native per-platform runs, negative controls
and real Cargo workloads: [docs/testing.md](docs/testing.md).

## Documentation

- [docs/architecture.md](docs/architecture.md): lifecycle domains, responsibilities, backend design
- [docs/api.md](docs/api.md): the public C API
- [docs/platform-support.md](docs/platform-support.md): per-platform mechanisms, prerequisites, recovery
- [docs/testing.md](docs/testing.md): qualification method and results
- [docs/limitations.md](docs/limitations.md): where the guarantees stop

## Status

This is the v0 C ABI. Struct layouts may gain fields before v1 and carry no
version discriminator, so compile against the header that matches the library
you link (see [docs/api.md](docs/api.md#abi-and-compatibility)).

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
