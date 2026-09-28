/*
 * Windows backend: one unnamed Job Object per lifecycle domain.
 *
 *   - Job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and NO breakaway flags
 *     (neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK), so every process created
 *     inside it -- CreateProcess with any creation flags, DETACHED_PROCESS,
 *     CREATE_NEW_PROCESS_GROUP, new consoles, `start /b`, leader exit, nested
 *     Jobs created by tools such as cargo -- stays in it. A request for
 *     CREATE_BREAKAWAY_FROM_JOB fails.
 *   - The initial process is created SUSPENDED, assigned to the Job, and its
 *     membership verified before its first thread is resumed.
 *   - The Job handle is never inheritable; the workload does not receive it.
 *   - Termination first closes admission at the OS level (active-process limit
 *     of 1: any process that would join the Job from then on is terminated as it
 *     is created), then TerminateJobObject, repeated until the Job's
 *     ActiveProcesses count is 0. That count is maintained by the kernel for
 *     every process in the Job, so it is authoritative emptiness.
 *   - Crash behavior: when the supervisor exits or dies its Job handle closes,
 *     and KILL_ON_JOB_CLOSE terminates every process in the Job.
 *
 * ENFORCED here means kernel-maintained lifecycle grouping of the task's
 * ordinary process creation, like the Linux cgroup backend. It is not a
 * sandbox. Out of scope, as in the public contract: a workload deliberately
 * creating work outside its Job (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS with a
 * handle to an outside process, or duplicating the supervisor's Job handle to
 * keep the Job alive), and work handed to external services (WMI, Task
 * Scheduler, SCM, COM out-of-process servers). The native qualification probes
 * these separately and reports them as limitations, never as passes.
 *
 * An unnamed Job cannot be reacquired by another process: recovery is
 * UNSUPPORTED and always UNRESOLVED.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#if defined(_WIN32)

#include "backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef struct {
    HANDLE job;
    int proven_empty; /* the kernel reported the Job empty after termination */
    char detail[256]; /* per-domain termination detail (not shared) */
} win_impl;

static void win_probe(procd_capabilities *out) {
    out->backend = "windows-job";
    out->process_tree_termination = PROCD_CAP_ENFORCED;
    out->pre_execution_containment = PROCD_CAP_ENFORCED;     /* suspended until in the Job */
    out->descendant_containment = PROCD_CAP_ENFORCED;        /* kernel-inherited Job membership */
    out->topology_escape_resistance = PROCD_CAP_ENFORCED;    /* no breakaway; flags don't matter */
    out->domain_emptiness_proof = PROCD_CAP_ENFORCED;        /* kernel ActiveProcesses == 0 */
    out->safe_recovery = PROCD_CAP_UNSUPPORTED;              /* unnamed Job cannot be reacquired */
    out->crash_behavior = PROCD_CRASH_AUTOMATIC_DESTRUCTION; /* KILL_ON_JOB_CLOSE */
    out->detail = "unnamed Job Object without breakaway: initial process assigned while "
                  "suspended, every ordinary descendant stays in the Job, termination closes "
                  "admission and kills the Job, the kernel's active-process count proves "
                  "emptiness, and supervisor exit kills the Job";
}

/* create the job with (or, in negative-control builds, without) breakaway */
static HANDLE make_job(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL); /* unnamed, not inheritable */
    if (!job) return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;
    memset(&eli, 0, sizeof eli);
    eli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    /* TEST-ONLY negative control: allow breakaway so a child can escape the Job
     * and survive TerminateJobObject, proving the harness detects escape. */
    if (procd_nc_weaken_containment()) {
        eli.BasicLimitInformation.LimitFlags |=
            JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    }
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof eli)) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

static procd_status win_create(procd_domain *d) {
    win_impl *im = calloc(1, sizeof *im);
    if (!im) return PROCD_E_INTERNAL;
    im->job = make_job();
    if (!im->job) {
        free(im);
        /* no Job, no domain: never fall back to something weaker */
        return d->policy.enforcement == PROCD_REQUIRE_ENFORCED ? PROCD_E_UNSUPPORTED_ENFORCEMENT
                                                               : PROCD_E_PREREQUISITE;
    }
    d->impl = im;
    d->runtime_level = PROCD_CAP_ENFORCED;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

/* Append one argument quoted so CommandLineToArgvW / the MSVC runtime parse it
 * back exactly (backslashes are literal unless they precede a quote). */
static size_t quote_arg(char *o, const char *a) {
    size_t n = 0;
    int plain = a[0] != 0 && strpbrk(a, " \t\n\v\"") == NULL;
    if (plain) {
        size_t l = strlen(a);
        if (o) memcpy(o, a, l);
        return l;
    }
    if (o) o[n] = '"';
    n++;
    for (const char *p = a;; p++) {
        size_t bs = 0;
        while (*p == '\\') {
            bs++;
            p++;
        }
        size_t reps = !*p ? bs * 2 : *p == '"' ? bs * 2 + 1 : bs;
        for (size_t i = 0; i < reps; i++) {
            if (o) o[n] = '\\';
            n++;
        }
        if (!*p) break;
        if (o) o[n] = *p;
        n++;
    }
    if (o) o[n] = '"';
    return n + 1;
}

static wchar_t *build_cmdline(const char *const *argv) {
    size_t cap = 1;
    for (int i = 0; argv[i]; i++)
        cap += quote_arg(NULL, argv[i]) + 1;
    char *a = malloc(cap);
    if (!a) return NULL;
    size_t n = 0;
    for (int i = 0; argv[i]; i++) {
        if (i) a[n++] = ' ';
        n += quote_arg(a + n, argv[i]);
    }
    a[n] = 0;
    int wn = MultiByteToWideChar(CP_UTF8, 0, a, -1, NULL, 0);
    wchar_t *w = wn > 0 ? malloc((size_t)wn * sizeof(wchar_t)) : NULL;
    if (w) MultiByteToWideChar(CP_UTF8, 0, a, -1, w, wn);
    free(a);
    return w;
}

static procd_status win_spawn(procd_domain *d, const char *const *argv, int64_t *out_pid) {
    win_impl *im = d->impl;
    wchar_t *cmd = build_cmdline(argv);
    if (!cmd) return PROCD_E_INTERNAL;

    STARTUPINFOW si;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof pi);

    /* create SUSPENDED so no workload code runs before containment is verified;
     * bInheritHandles=FALSE => workload never inherits the Job handle. */
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    DWORD cerr = ok ? 0 : GetLastError();
    free(cmd);
    if (!ok)
        return (cerr == ERROR_FILE_NOT_FOUND || cerr == ERROR_PATH_NOT_FOUND) ? PROCD_E_NOT_FOUND
               : cerr == ERROR_ACCESS_DENIED                                  ? PROCD_E_PERMISSION
                                                                              : PROCD_E_IO;

    /* admit to the Job BEFORE resume, then verify membership */
    BOOL in_job = FALSE;
    if (!AssignProcessToJobObject(im->job, pi.hProcess) ||
        !IsProcessInJob(pi.hProcess, im->job, &in_job) || !in_job) {
        /* only this never-resumed process is affected; nothing of it ran */
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return PROCD_E_INTERNAL;
    }

    /* permit execution */
    procd_status rc = PROCD_OK;
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        TerminateProcess(pi.hProcess, 1);
        rc = PROCD_E_IO;
    } else {
        if (out_pid) *out_pid = (int64_t)pi.dwProcessId;
        d->state = PROCD_STATE_ACTIVE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}

static int active_processes(HANDLE job, int *ok) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ai;
    DWORD ret = 0;
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &ai, sizeof ai,
                                   &ret)) {
        *ok = 0;
        return -1;
    }
    *ok = 1;
    return (int)ai.ActiveProcesses;
}

static procd_status win_status(procd_domain *d, procd_domain_status *out) {
    win_impl *im = d->impl;
    out->process_tree_termination = d->runtime_level;
    int ok = 0;
    int n = active_processes(im->job, &ok);
    out->population_is_authoritative = ok && d->runtime_level == PROCD_CAP_ENFORCED;
    out->population = !ok ? PROCD_POP_UNKNOWN : n > 0 ? PROCD_POP_POPULATED : PROCD_POP_EMPTY;
    out->state = d->state;
    return PROCD_OK;
}

/* OS-level admission close: from now on any process joining the Job is
 * terminated as it is created. KILL_ON_JOB_CLOSE is kept. */
static int close_admission(HANDLE job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;
    DWORD ret = 0;
    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof eli, &ret))
        return 0;
    eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    eli.BasicLimitInformation.ActiveProcessLimit = 1;
    return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof eli) ? 1
                                                                                             : 0;
}

static procd_status win_terminate(procd_domain *d, int timeout_ms,
                                  procd_termination_evidence *out) {
    win_impl *im = d->impl;
    char *detail = im->detail; /* per-domain: concurrent domains never share this */
    size_t dcap = sizeof im->detail;
    out->detail = detail;
    d->state = PROCD_STATE_TERMINATING;
    out->admission_closed = close_admission(im->job);

    if (timeout_ms <= 0) timeout_ms = 5000;
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_ms;
    int ok = 0, n = -1, kills = 0;
    BOOL killed = FALSE;
    for (;;) {
        n = active_processes(im->job, &ok);
        if (ok && n == 0) break;
        /* repeat: anything created while a previous kill was running dies too */
        if (TerminateJobObject(im->job, 1)) killed = TRUE;
        kills++;
        if (GetTickCount64() > deadline) break;
        Sleep(kills < 10 ? 1 : 10);
    }
    out->authority_directed = killed || (ok && n == 0);
    int empty = ok && n == 0;
    int enforced = d->runtime_level == PROCD_CAP_ENFORCED;
    out->emptiness_proven = empty && enforced;
    out->enforced = empty && enforced && out->admission_closed && out->authority_directed;
    if (empty) {
        im->proven_empty = 1;
        out->final_state = enforced ? PROCD_STATE_EMPTY : PROCD_STATE_UNRESOLVED;
        d->state = out->final_state;
        snprintf(detail, dcap,
                 "admission closed=%d; TerminateJobObject x%d; Job ActiveProcesses==0",
                 out->admission_closed, kills);
        return PROCD_OK;
    }
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    if (!ok) {
        snprintf(detail, dcap, "Job accounting unreadable: %lu", GetLastError());
        return PROCD_E_IO;
    }
    snprintf(detail, dcap, "timed out: Job still reports %d active process(es)", n);
    return PROCD_E_TIMEOUT;
}

static procd_status win_identity(procd_domain *d, char *buf, size_t n) {
    (void)d;
    /* Unnamed Job cannot be reacquired after our process exits; identity is
     * process-local and intentionally not durable. */
    int w = snprintf(buf, n, "windows-job:1:process-local");
    return (w > 0 && (size_t)w < n) ? PROCD_OK : PROCD_E_INVALID_ARGUMENT;
}

static void win_destroy(procd_domain *d) {
    win_impl *im = d->impl;
    if (im) {
        /* KILL_ON_JOB_CLOSE: closing the last handle kills whatever remains */
        if (im->job) CloseHandle(im->job);
        free(im);
    }
    d->impl = NULL;
}

static procd_status win_recover(const char *identity, procd_recovery_outcome *outcome,
                                procd_domain **out_domain) {
    (void)out_domain;
    if (strncmp(identity, "windows-job:", 12) != 0) return PROCD_E_INVALID_ARGUMENT;
    /* An unnamed Job cannot be reacquired, and the identity is not unique per
     * domain. Refuse to guess. */
    *outcome = PROCD_UNRESOLVED;
    return PROCD_OK;
}

static const struct procd_backend BACKEND = {
    .name = "windows-job",
    .probe = win_probe,
    .create = win_create,
    .spawn = win_spawn,
    .status = win_status,
    .terminate = win_terminate,
    .identity = win_identity,
    .destroy = win_destroy,
    .recover = win_recover,
};
const struct procd_backend *procd_active_backend(void) {
    return &BACKEND;
}

#endif /* _WIN32 */
