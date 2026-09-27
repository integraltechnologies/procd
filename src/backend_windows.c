/*
 * Windows backend: unnamed invocation Job Object.
 *
 * Implemented candidate architecture:
 *   - Unnamed Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and NO
 *     breakaway flags (neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK).
 *   - Initial process created SUSPENDED; assigned to the Job BEFORE any thread
 *     resumes; membership verified (IsProcessInJob + ActiveProcesses) before
 *     the workload is permitted to run.
 *   - The Job handle is not inheritable, so the workload never inherits
 *     lifecycle authority.
 *   - Termination targets the Job (TerminateJobObject) and waits for the
 *     Job's ActiveProcesses == 0. That proves the JOB is empty, not that the
 *     invocation owns no executable work (see below), so it is never reported
 *     as domain emptiness.
 *   - Crash behavior: UNRESOLVED_ON_AUTHORITY_LOSS. KILL_ON_JOB_CLOSE fires only
 *     when the LAST Job handle closes. A same-user workload can duplicate the
 *     controller's Job handle (PROCESS_DUP_HANDLE) and keep the Job alive, so
 *     controller death does not by itself prove destruction. The unnamed Job
 *     also cannot be reacquired, so recovery is always UNRESOLVED.
 *
 * Honest capability level:
 *   process_tree_termination = BEST_EFFORT, NOT ENFORCED.
 *
 *   A plain-user Job design does not by itself close all process-creation
 *   escapes: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS reparenting to an outside
 *   process, and execution brokers (WMI, Task Scheduler, SCM, shell/COM), can
 *   create work outside the Job. Closing these requires a restricted execution
 *   authority (restricted token / AppContainer/LPAC / broker denial) that is
 *   not established here. We therefore report the strongest defensible level
 *   and refuse ENFORCED rather than regress to "Job Object alone = ENFORCED".
 *
 *   Every capability describes the FULL procd property for the invocation,
 *   not the narrower behavior of the Job:
 *     pre_execution_containment  ENFORCED    the initial process is created
 *                                            suspended and is in the Job before
 *                                            any of its code runs;
 *     descendant_containment     BEST_EFFORT ordinary CreateProcess descendants
 *                                            stay in the Job, but the workload
 *                                            can create work outside it
 *                                            (parent-process attribute, brokers,
 *                                            same-user handle duplication);
 *     topology_escape_resistance BEST_EFFORT same escapes;
 *     domain_emptiness_proof     BEST_EFFORT ActiveProcesses==0 proves only that
 *                                            the Job is empty;
 *     safe_recovery              UNSUPPORTED unnamed Job cannot be reacquired.
 *   Status population and termination evidence follow the same rule: a Job
 *   count is reported as non-authoritative and never as proven emptiness.
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
    HANDLE proc;
    HANDLE thread;
    int job_empty;    /* Job observed empty; NOT domain emptiness */
    char detail[256]; /* per-domain termination detail (not shared) */
} win_impl;

static void win_probe(procd_capabilities *out) {
    out->backend = "windows-job";
    /* Aggregate hard invariant not established: brokers/parent-substitution
     * are not closed by an ordinary Job. */
    out->process_tree_termination = PROCD_CAP_BEST_EFFORT;
    /* initial process is in the Job before any of its code runs */
    out->pre_execution_containment = PROCD_CAP_ENFORCED;
    /* ordinary descendants stay in the Job, but PROC_THREAD_ATTRIBUTE_PARENT_
     * PROCESS, brokers (WMI, Task Scheduler, SCM, shell/COM) and same-user
     * handle duplication can create invocation work outside it */
    out->descendant_containment = PROCD_CAP_BEST_EFFORT;
    out->topology_escape_resistance = PROCD_CAP_BEST_EFFORT;
    /* ActiveProcesses==0 proves the Job empty, not the invocation */
    out->domain_emptiness_proof = PROCD_CAP_BEST_EFFORT;
    out->safe_recovery = PROCD_CAP_UNSUPPORTED; /* unnamed job cannot be reacquired */
    /* KILL_ON_JOB_CLOSE needs the LAST handle closed; a duplicated handle keeps
     * the Job alive, so authority loss does not prove destruction. */
    out->crash_behavior = PROCD_CRASH_UNRESOLVED_ON_AUTHORITY_LOSS;
    out->detail = "unnamed Job, no breakaway: initial process contained before it runs and "
                  "ordinary descendants stay in the Job, but parent-process-attribute, broker "
                  "(WMI/Task Scheduler/SCM/shell-COM) and same-user handle paths can create "
                  "invocation work outside it; Job emptiness is not domain emptiness";
}

/* create the job with (or, in negative-control builds, without) breakaway */
static HANDLE make_job(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL); /* unnamed */
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
    if (d->policy.enforcement == PROCD_REQUIRE_ENFORCED)
        return PROCD_E_UNSUPPORTED_ENFORCEMENT; /* fail closed: aggregate not ENFORCED */
    win_impl *im = calloc(1, sizeof *im);
    if (!im) return PROCD_E_INTERNAL;
    im->job = make_job();
    if (!im->job) {
        free(im);
        return PROCD_E_PREREQUISITE;
    }
    d->impl = im;
    d->runtime_level = PROCD_CAP_BEST_EFFORT;
    d->state = PROCD_STATE_CREATED;
    return PROCD_OK;
}

/* naive argv -> command line with minimal quoting */
static wchar_t *build_cmdline(const char *const *argv) {
    size_t cap = 1;
    for (int i = 0; argv[i]; i++)
        cap += strlen(argv[i]) * 2 + 3;
    char *a = malloc(cap);
    if (!a) return NULL;
    a[0] = 0;
    for (int i = 0; argv[i]; i++) {
        if (i) strcat(a, " ");
        int has_space = strchr(argv[i], ' ') != NULL;
        if (has_space) strcat(a, "\"");
        strcat(a, argv[i]);
        if (has_space) strcat(a, "\"");
    }
    int wn = MultiByteToWideChar(CP_UTF8, 0, a, -1, NULL, 0);
    wchar_t *w = malloc((size_t)wn * sizeof(wchar_t));
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
    free(cmd);
    if (!ok) return PROCD_E_IO;

    /* admit to Job BEFORE resume */
    if (!AssignProcessToJobObject(im->job, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return PROCD_E_INTERNAL; /* containment could not be established; nothing ran */
    }
    /* verify membership before permitting execution */
    BOOL in_job = FALSE;
    if (!IsProcessInJob(pi.hProcess, im->job, &in_job) || !in_job) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return PROCD_E_INTERNAL;
    }
    im->proc = pi.hProcess;
    im->thread = pi.hThread;

    /* permit execution */
    if (ResumeThread(pi.hThread) == (DWORD)-1) return PROCD_E_IO;
    if (out_pid) *out_pid = (int64_t)pi.dwProcessId;
    d->state = PROCD_STATE_ACTIVE;
    return PROCD_OK;
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
    /* The Job's count covers only Job-tracked work: a nonzero count is real
     * population, but zero does not prove the invocation owns no work. */
    out->population_is_authoritative = 0;
    out->population = !ok ? PROCD_POP_UNKNOWN : n > 0 ? PROCD_POP_POPULATED : PROCD_POP_EMPTY;
    out->state = d->state;
    return PROCD_OK;
}

static procd_status win_terminate(procd_domain *d, int timeout_ms,
                                  procd_termination_evidence *out) {
    win_impl *im = d->impl;
    char *detail = im->detail; /* per-domain: concurrent domains never share this */
    size_t dcap = sizeof im->detail;
    out->detail = detail;
    d->state = PROCD_STATE_TERMINATING;

    /* Kills every Job-tracked process; this targets the Job, not a PID list.
     * It does NOT close admission for the invocation: work created outside
     * the Job (parent-process attribute, brokers) never passed through it. */
    BOOL killed = TerminateJobObject(im->job, 1);
    out->admission_closed = 0;
    out->authority_directed = killed;
    if (!killed) {
        snprintf(detail, dcap, "TerminateJobObject failed: %lu", GetLastError());
        out->final_state = PROCD_STATE_UNRESOLVED;
        d->state = PROCD_STATE_UNRESOLVED;
        return PROCD_E_IO;
    }

    if (timeout_ms <= 0) timeout_ms = 5000;
    int ok = 0, n = 1;
    for (int i = 0; i < timeout_ms / 10; i++) {
        n = active_processes(im->job, &ok);
        if (ok && n == 0) break;
        Sleep(10);
    }

    /* Never proven emptiness and never EMPTY: the Job being empty does not
     * establish that no invocation-owned work remains outside it. */
    out->emptiness_proven = 0;
    out->enforced = 0;
    out->final_state = PROCD_STATE_UNRESOLVED;
    d->state = PROCD_STATE_UNRESOLVED;
    if (ok && n == 0) {
        im->job_empty = 1;
        snprintf(detail, dcap,
                 "Job terminated; Job ActiveProcesses==0. Invocation work created outside the "
                 "Job (parent-process attribute, brokers) is not excluded: UNRESOLVED");
        return PROCD_OK;
    }
    snprintf(detail, dcap, "timed out waiting for Job ActiveProcesses==0");
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
        if (im->thread) CloseHandle(im->thread);
        if (im->proc) CloseHandle(im->proc);
        /* KILL_ON_JOB_CLOSE fires only if this was the LAST Job handle; a
         * handle duplicated by the workload keeps the Job (and its work) alive. */
        if (im->job) CloseHandle(im->job);
        free(im);
    }
    d->impl = NULL;
}

static procd_status win_recover(const char *identity, procd_recovery_outcome *outcome,
                                procd_domain **out_domain) {
    (void)out_domain;
    if (strncmp(identity, "windows-job:", 12) != 0) return PROCD_E_INVALID_ARGUMENT;
    /* An unnamed Job cannot be reacquired, and nothing proves it is gone:
     * KILL_ON_JOB_CLOSE only fires when the last handle closes, and the
     * workload may hold a duplicated one. The identity is not even unique per
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
