/*
 * Native Windows qualification of the Job Object backend's mechanism claims
 * (pre-exec admission, handle non-inheritance, evidence consistency, churn,
 * supervisor loss), alongside the shared lifecycle matrix (tests/qualify.c).
 *
 * Required mechanism cases fail closed: a missing witness is a failure, never
 * a pass. Known escape investigations have a distinct INCONCLUSIVE result;
 * inability to reproduce an unclaimed escape cannot qualify that limitation.
 * Every process is bounded by PROCD_ADV_TTL, and process identity is checked
 * with an already-open handle plus its creation time (never a bare PID).
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef struct {
    DWORD pid;
    unsigned long long created;
    int in_job;
    DWORD creator;
    DWORD aux;
    HANDLE process;
} record;

static int failures;
static int required_passes;
static int inconclusive;

static unsigned long long process_created(HANDLE process) {
    FILETIME create, exit, kernel, user;
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) return 0;
    return ((unsigned long long)create.dwHighDateTime << 32) | create.dwLowDateTime;
}

static void required_result(const char *name, int pass, const char *detail) {
    printf("[%s] %s: %s\n", pass ? "PASS" : "FAIL", name, detail);
    if (pass)
        required_passes++;
    else
        failures++;
}

static void escape_result(const char *name, int reproduced, const char *detail) {
    printf("[%s] %s: %s\n", reproduced ? "OUT-OF-CONTRACT ESCAPE REPRODUCED" : "INCONCLUSIVE", name,
           detail);
    if (!reproduced) inconclusive++;
}

static void set_env(const char *name, const char *value) {
    _putenv_s(name, value ? value : "");
}

static void join_path(char *out, size_t n, const char *dir, const char *file) {
    size_t dn = strlen(dir), fn = strlen(file);
    if (dn + 1 + fn + 1 > n) {
        if (n) out[0] = 0;
        return;
    }
    memcpy(out, dir, dn);
    out[dn] = '\\';
    memcpy(out + dn + 1, file, fn + 1);
}

static void clear_dir(const char *dir) {
    char pattern[MAX_PATH * 2];
    WIN32_FIND_DATAA data;
    join_path(pattern, sizeof pattern, dir, "*");
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(data.cFileName, ".") && strcmp(data.cFileName, "..")) {
            char path[MAX_PATH * 2];
            join_path(path, sizeof path, dir, data.cFileName);
            DeleteFileA(path);
        }
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

static int make_dir(char *out, size_t n) {
    char temp[MAX_PATH];
    DWORD got = GetTempPathA((DWORD)sizeof temp, temp);
    if (!got || got >= (DWORD)sizeof temp) return 0;
    snprintf(out, n, "%sprocd-win-%lu-%llu", temp, (unsigned long)GetCurrentProcessId(),
             (unsigned long long)GetTickCount64());
    return CreateDirectoryA(out, NULL) ? 1 : 0;
}

static int open_identity(DWORD pid, unsigned long long created, HANDLE *out) {
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                           FALSE, pid);
    if (!h) return 0;
    if (process_created(h) != created) {
        CloseHandle(h);
        return 0;
    }
    *out = h;
    return 1;
}

static int read_record_once(const char *dir, const char *role, record *out) {
    char file[MAX_PATH * 2], leaf[128];
    snprintf(leaf, sizeof leaf, "%s.txt", role);
    join_path(file, sizeof file, dir, leaf);
    FILE *f = fopen(file, "r");
    if (!f) return 0;
    unsigned long pid = 0, creator = 0, aux = 0;
    int ok = fscanf(f, "%lu %llu %d %lu %lu", &pid, &out->created, &out->in_job, &creator, &aux);
    fclose(f);
    if (ok != 5 || !pid || !out->created) return 0;
    out->pid = (DWORD)pid;
    out->creator = (DWORD)creator;
    out->aux = (DWORD)aux;
    out->process = NULL;
    return 1;
}

static int wait_record(const char *dir, const char *role, record *out, DWORD timeout) {
    memset(out, 0, sizeof *out);
    DWORD start = GetTickCount();
    do {
        if (read_record_once(dir, role, out)) return 1;
        Sleep(20);
    } while (GetTickCount() - start < timeout);
    return 0;
}

static int attach_record(record *r) {
    return open_identity(r->pid, r->created, &r->process);
}

static int alive(HANDLE process) {
    return process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

static int dead_within(HANDLE process, DWORD timeout) {
    return process && WaitForSingleObject(process, timeout) == WAIT_OBJECT_0;
}

static void kill_and_close(HANDLE process) {
    if (!process) return;
    if (alive(process)) {
        TerminateProcess(process, 99);
        WaitForSingleObject(process, 2000);
    }
    CloseHandle(process);
}

static int spawn_direct(const char *exe, const char *args, PROCESS_INFORMATION *pi) {
    char cmd[MAX_PATH * 5];
    snprintf(cmd, sizeof cmd, "\"%s\" %s", exe, args);
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(pi, sizeof *pi);
    si.cb = sizeof si;
    return CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, pi) ? 1
                                                                                               : 0;
}

static procd_domain *new_domain(void) {
    procd_policy policy = PROCD_POLICY_INIT;
    policy.enforcement = PROCD_ALLOW_BEST_EFFORT;
    procd_domain *domain = NULL;
    if (procd_create_domain(&policy, &domain) != PROCD_OK) return NULL;
    return domain;
}

/* termination evidence and status must agree with the kernel's Job view */
static int terminate_honestly(procd_domain *domain, procd_termination_evidence *ev) {
    procd_status rc = procd_domain_terminate(domain, 8000, ev);
    procd_domain_status status;
    procd_status status_rc = procd_domain_status_get(domain, &status);
    return rc == PROCD_OK && ev->authority_directed && ev->admission_closed &&
           ev->emptiness_proven && ev->enforced && ev->final_state == PROCD_STATE_EMPTY &&
           status_rc == PROCD_OK && status.state == PROCD_STATE_EMPTY &&
           status.population == PROCD_POP_EMPTY && status.population_is_authoritative;
}

static void case_capabilities(void) {
    procd_capabilities c;
    int ok = procd_capabilities_probe(&c) == PROCD_OK && strcmp(c.backend, "windows-job") == 0 &&
             c.process_tree_termination == PROCD_CAP_ENFORCED &&
             c.pre_execution_containment == PROCD_CAP_ENFORCED &&
             c.descendant_containment == PROCD_CAP_ENFORCED &&
             c.topology_escape_resistance == PROCD_CAP_ENFORCED &&
             c.domain_emptiness_proof == PROCD_CAP_ENFORCED &&
             c.safe_recovery == PROCD_CAP_UNSUPPORTED &&
             c.crash_behavior == PROCD_CRASH_AUTOMATIC_DESTRUCTION;
    procd_policy strict = PROCD_POLICY_INIT;
    procd_domain *sd = NULL;
    int strict_ok = procd_create_domain(&strict, &sd) == PROCD_OK;
    if (sd) procd_domain_release(sd);
    ok = ok && strict_ok;
    required_result("capability/evidence consistency", ok,
                    ok ? "aggregate/pre-exec/descendant/topology/emptiness ENFORCED; recovery "
                         "UNSUPPORTED; supervisor loss AUTOMATIC_DESTRUCTION; REQUIRE_ENFORCED "
                         "domain created"
                       : "reported Windows capability tuple drifted or REQUIRE_ENFORCED refused");
}

static void case_preexec_handles_unrelated(const char *adv, const char *dir) {
    clear_dir(dir);
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    set_env("PROCD_ADV_TTL", "20");
    char controller[32];
    snprintf(controller, sizeof controller, "%lu", (unsigned long)GetCurrentProcessId());
    set_env("PROCD_WIN_CONTROLLER_PID", controller);

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE sentinel = CreateEventA(&sa, TRUE, FALSE, NULL);
    char sentinel_value[32];
    snprintf(sentinel_value, sizeof sentinel_value, "%llu",
             (unsigned long long)(ULONG_PTR)sentinel);
    set_env("PROCD_WIN_SENTINEL_HANDLE", sentinel_value);

    PROCESS_INFORMATION unrelated;
    int unrelated_started = spawn_direct(adv, "leaf 0 unrelated", &unrelated);
    if (unrelated_started) CloseHandle(unrelated.hThread);

    procd_domain *domain = new_domain();
    int64_t spawned = -1;
    const char *argv[] = {adv, "preexec", NULL};
    procd_status spawn_rc = domain ? procd_domain_spawn(domain, argv, &spawned) : PROCD_E_INTERNAL;
    record root = {0}, sent = {0}, job_handles = {0};
    int root_seen = wait_record(dir, "root", &root, 5000);
    int sent_seen = wait_record(dir, "sentinel", &sent, 2000);
    int handles_seen = wait_record(dir, "job-handle-scan", &job_handles, 2000);
    int root_open = root_seen && attach_record(&root);
    int preexec = spawn_rc == PROCD_OK && root_seen && root_open && root.pid == (DWORD)spawned &&
                  root.in_job == 1 && alive(root.process);
    required_result("initial pre-exec containment", preexec,
                    preexec
                        ? "first fixture action observed the spawned identity already in a Job"
                        : "missing/mismatched first-action witness or process was not in a Job");

    int sentinel_clean = sentinel && sent_seen && handles_seen && job_handles.aux == 0 &&
                         sent.aux != 1 && WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT;
    required_result("lifecycle handle non-inheritance", sentinel_clean,
                    sentinel_clean
                        ? "fixture found no Job handle and an intentionally inheritable sentinel "
                          "was unusable after normal launch"
                        : "fixture found a Job/controller handle or an inheritance witness was "
                          "absent");

    procd_termination_evidence ev;
    int honest = domain && terminate_honestly(domain, &ev);
    int killed = root_open && dead_within(root.process, 3000);
    int control_alive = unrelated_started && alive(unrelated.hProcess);
    required_result("unrelated process safety", killed && control_alive,
                    killed && control_alive
                        ? "Job member died while an independently launched control stayed alive"
                        : "member survived or unrelated control was affected");
    required_result("termination evidence consistency", honest,
                    honest ? "admission closed, Job killed, kernel count 0 => proven EMPTY; status "
                             "agrees and is authoritative"
                           : "termination evidence or status disagreed with the Job");

    if (root.process) CloseHandle(root.process);
    if (domain) procd_domain_release(domain);
    kill_and_close(unrelated_started ? unrelated.hProcess : NULL);
    if (sentinel) CloseHandle(sentinel);
    set_env("PROCD_WIN_SENTINEL_HANDLE", NULL);
}

static void case_ordinary(const char *adv, const char *dir) {
    clear_dir(dir);
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "ordinary", NULL};
    int64_t spawned = -1;
    procd_status rc = domain ? procd_domain_spawn(domain, argv, &spawned) : PROCD_E_INTERNAL;
    record root = {0}, child = {0}, grandchild = {0};
    int observed = wait_record(dir, "root", &root, 4000) &&
                   wait_record(dir, "child", &child, 4000) &&
                   wait_record(dir, "grandchild", &grandchild, 4000);
    int opened =
        observed && attach_record(&root) && attach_record(&child) && attach_record(&grandchild);
    int topology = opened && rc == PROCD_OK && root.pid == (DWORD)spawned &&
                   child.creator == root.pid && grandchild.creator == child.pid && root.in_job &&
                   child.in_job && grandchild.in_job && dead_within(root.process, 3000) &&
                   alive(child.process) && alive(grandchild.process);

    procd_domain_status status;
    int status_ok = domain && procd_domain_status_get(domain, &status) == PROCD_OK &&
                    status.population == PROCD_POP_POPULATED && !status.population_is_authoritative;
    procd_termination_evidence ev;
    int honest = domain && terminate_honestly(domain, &ev);
    int descendants_dead =
        opened && dead_within(child.process, 3000) && dead_within(grandchild.process, 3000);
    required_result(
        "ordinary descendant containment", topology && status_ok && honest && descendants_dead,
        topology && status_ok && honest && descendants_dead
            ? "child+grandchild remained after leader exit, were Job-observed, and died "
              "with the Job; exec replacement is not a Windows primitive"
            : "topology/witness/status/termination check failed");

    if (root.process) CloseHandle(root.process);
    if (child.process) CloseHandle(child.process);
    if (grandchild.process) CloseHandle(grandchild.process);
    if (domain) procd_domain_release(domain);
}

static int collect_churn(const char *dir, record *records, int max) {
    int n = 0;
    for (int i = 0; i < max; i++) {
        char role[64];
        snprintf(role, sizeof role, "churn-%04d", i);
        if (!read_record_once(dir, role, &records[n])) break;
        if (attach_record(&records[n])) n++;
    }
    return n;
}

static void case_churn(const char *adv, const char *dir) {
    clear_dir(dir);
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    ULONGLONG start = GetTickCount64();
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "churn", NULL};
    procd_status rc = domain ? procd_domain_spawn(domain, argv, NULL) : PROCD_E_INTERNAL;
    record root = {0}, members[64] = {0};
    int root_seen = wait_record(dir, "root", &root, 4000) && attach_record(&root);
    int n = 0;
    for (int i = 0; i < 200 && n < 8; i++) {
        for (int j = 0; j < n; j++)
            CloseHandle(members[j].process);
        n = collect_churn(dir, members, 64);
        if (n < 8) Sleep(20);
    }
    int live_before = 0;
    int all_job_observed = 1;
    for (int i = 0; i < n; i++) {
        live_before += alive(members[i].process);
        all_job_observed = all_job_observed && members[i].in_job;
    }
    procd_termination_evidence ev;
    int honest = domain && terminate_honestly(domain, &ev);
    int survivors = 0;
    for (int i = 0; i < n; i++)
        survivors += !dead_within(members[i].process, 3000);
    int witnessed_total = 0, post_survivors = 0;
    for (int i = 0; i < 256; i++) {
        char role[64];
        record later = {0};
        snprintf(role, sizeof role, "churn-%04d", i);
        if (!read_record_once(dir, role, &later)) continue;
        witnessed_total++;
        HANDLE exact = NULL;
        if (open_identity(later.pid, later.created, &exact)) {
            post_survivors += alive(exact);
            CloseHandle(exact);
        }
    }
    int bounded = GetTickCount64() - start < 15000;
    int ok = rc == PROCD_OK && root_seen && n >= 8 && live_before >= 8 && honest &&
             all_job_observed && survivors == 0 && post_survivors == 0 &&
             dead_within(root.process, 3000) && bounded;
    char detail[256];
    snprintf(detail, sizeof detail,
             "%d live members before kill; %d total witnessed; %d sampled/%d post-kill "
             "survivors; bounded=%d",
             n, witnessed_total, survivors, post_survivors, bounded);
    required_result("termination during spawn/churn", ok, detail);
    if (root.process) CloseHandle(root.process);
    for (int i = 0; i < n; i++)
        CloseHandle(members[i].process);
    if (domain) procd_domain_release(domain);
}

static void case_recovery(const char *dir) {
    (void)dir;
    procd_domain *domain = new_domain();
    char identity[PROCD_IDENTITY_MAX] = {0};
    int id_ok = domain && procd_domain_identity(domain, identity, sizeof identity) == PROCD_OK;
    procd_recovery_outcome live_out = PROCD_CONFIRMED_DESTROYED;
    procd_domain *recovered = NULL;
    procd_status live_rc =
        id_ok ? procd_recover(identity, &live_out, &recovered) : PROCD_E_INTERNAL;
    procd_recovery_outcome bad_out = PROCD_CONFIRMED_DESTROYED;
    procd_domain *bad = NULL;
    procd_status bad_rc = procd_recover("windows-job:malformed", &bad_out, &bad);
    int ok = live_rc == PROCD_OK && live_out == PROCD_UNRESOLVED && !recovered &&
             bad_rc == PROCD_OK && bad_out == PROCD_UNRESOLVED && !bad;
    required_result("recovery honesty", ok,
                    ok ? "live and malformed Windows identities remained UNRESOLVED with no handle"
                       : "recovery fabricated destruction/reacquisition or mishandled identity");
    if (domain) {
        procd_termination_evidence ev;
        procd_domain_terminate(domain, 2000, &ev);
        procd_domain_release(domain);
    }
}

static int read_escape_pid(const char *dir, const char *file, record *out) {
    memset(out, 0, sizeof *out);
    char path[MAX_PATH * 2];
    join_path(path, sizeof path, dir, file);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long pid = 0;
    int ok = fscanf(f, "%lu %llu", &pid, &out->created);
    fclose(f);
    if (ok != 2) return 0;
    out->pid = (DWORD)pid;
    out->process = NULL;
    return attach_record(out);
}

static void case_parent_escape(const char *adv, const char *dir) {
    clear_dir(dir);
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "parent-escape", NULL};
    procd_status rc = domain ? procd_domain_spawn(domain, argv, NULL) : PROCD_E_INTERNAL;
    record request = {0}, escaped = {0};
    int requested = wait_record(dir, "parent-request-ok", &request, 6000);
    int failed = requested ? 0 : wait_record(dir, "parent-request-failed", &request, 1000);
    int child = requested && read_escape_pid(dir, "parent-escape-pid.txt", &escaped);
    procd_termination_evidence ev;
    if (domain) procd_domain_terminate(domain, 8000, &ev);
    int survived = child && alive(escaped.process);
    char detail[256];
    if (survived)
        snprintf(detail, sizeof detail,
                 "effective-parent process creation succeeded outside the procd Job; survivor "
                 "identity %lu remained alive after Job termination",
                 (unsigned long)escaped.pid);
    else if (failed)
        snprintf(detail, sizeof detail,
                 "OpenProcess/attribute/CreateProcess was denied on this runner (Win32 error %lu)",
                 (unsigned long)request.aux);
    else
        snprintf(detail, sizeof detail,
                 "request/spawn did not yield a verified survivor (spawn rc=%s)",
                 procd_status_name(rc));
    escape_result("parent-process attribute escape", survived, detail);
    kill_and_close(child ? escaped.process : NULL);
    if (domain) procd_domain_release(domain);
}

static int duplicate_controller_mode(const char *adv, const char *dir) {
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    set_env("PROCD_ADV_TTL", "20");
    char controller[32];
    snprintf(controller, sizeof controller, "%lu", (unsigned long)GetCurrentProcessId());
    set_env("PROCD_WIN_CONTROLLER_PID", controller);
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "duplicate-job", NULL};
    if (!domain || procd_domain_spawn(domain, argv, NULL) != PROCD_OK) return 3;
    record result = {0};
    if (!wait_record(dir, "duplicate-ok", &result, 8000) &&
        !wait_record(dir, "duplicate-failed", &result, 500))
        return 4;
    /* Intentionally do not terminate/release: process exit closes the original
     * Job handle. A successful workload duplicate keeps the bounded member alive. */
    return 0;
}

static void case_handle_duplication(const char *self, const char *adv, const char *dir) {
    clear_dir(dir);
    char args[MAX_PATH * 5];
    snprintf(args, sizeof args, "--duplicate-controller \"%s\" \"%s\"", adv, dir);
    PROCESS_INFORMATION helper;
    int started = spawn_direct(self, args, &helper);
    if (started) CloseHandle(helper.hThread);
    record root = {0}, result = {0};
    int root_seen = wait_record(dir, "root", &root, 6000) && attach_record(&root);
    int dup_ok = wait_record(dir, "duplicate-ok", &result, 6000);
    int dup_failed = dup_ok ? 0 : wait_record(dir, "duplicate-failed", &result, 500);
    if (started) WaitForSingleObject(helper.hProcess, 10000);
    int survived = started && root_seen && dup_ok && alive(root.process);
    char detail[256];
    if (survived)
        snprintf(detail, sizeof detail,
                 "same-user workload duplicated its controller's Job handle; member %lu survived "
                 "controller authority loss until bounded cleanup",
                 (unsigned long)root.pid);
    else if (dup_failed)
        snprintf(detail, sizeof detail,
                 "PROCESS_DUP_HANDLE/enumeration/duplication unavailable (Win32 error %lu)",
                 (unsigned long)result.aux);
    else
        snprintf(detail, sizeof detail,
                 "duplicate probe did not establish its precondition (helper started=%d root=%d)",
                 started, root_seen);
    escape_result("same-user Job-handle duplication", survived, detail);
    kill_and_close(root_seen ? root.process : NULL);
    if (started) CloseHandle(helper.hProcess);
}

/* Helper process: supervise a task, then wait to be killed. */
static int controller_crash_mode(const char *adv, const char *dir) {
    set_env("PROCD_WIN_WITNESS_DIR", NULL);
    set_env("PROCD_ADV_WITNESS_DIR", dir);
    set_env("PROCD_ADV_TTL", "30");
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "grandchild", NULL};
    if (!domain || procd_domain_spawn(domain, argv, NULL) != PROCD_OK) return 3;
    Sleep(60000); /* killed by the test long before this */
    return 0;
}

static int read_witnesses(const char *dir, record *out, int max) {
    char pattern[MAX_PATH * 2];
    WIN32_FIND_DATAA data;
    join_path(pattern, sizeof pattern, dir, "*");
    HANDLE find = FindFirstFileA(pattern, &data);
    int n = 0;
    if (find == INVALID_HANDLE_VALUE) return 0;
    do {
        if (data.cFileName[0] == '.' || n >= max) continue;
        char path[MAX_PATH * 2];
        join_path(path, sizeof path, dir, data.cFileName);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char role[32];
        unsigned long pid = 0;
        long ppid = 0, pg = 0, sid = 0;
        unsigned long long created = 0;
        if (fscanf(f, "%31s %lu %ld %ld %ld %llu", role, &pid, &ppid, &pg, &sid, &created) == 6) {
            memset(&out[n], 0, sizeof out[n]);
            out[n].pid = (DWORD)pid;
            out[n].created = created;
            if (attach_record(&out[n])) n++;
        }
        fclose(f);
    } while (FindNextFileA(find, &data));
    FindClose(find);
    return n;
}

static void case_controller_loss(const char *self, const char *adv, const char *dir) {
    clear_dir(dir);
    char args[MAX_PATH * 5];
    snprintf(args, sizeof args, "--controller-crash \"%s\" \"%s\"", adv, dir);
    PROCESS_INFORMATION helper;
    int started = spawn_direct(self, args, &helper);
    if (started) CloseHandle(helper.hThread);
    record members[16];
    int n = 0;
    for (int i = 0; i < 250 && n < 3; i++) {
        for (int j = 0; j < n; j++)
            CloseHandle(members[j].process);
        n = read_witnesses(dir, members, 16);
        if (n < 3) Sleep(20);
    }
    int live = 0;
    for (int i = 0; i < n; i++)
        live += alive(members[i].process);
    /* the supervisor dies without terminating or releasing anything */
    int crashed = started && TerminateProcess(helper.hProcess, 9) &&
                  WaitForSingleObject(helper.hProcess, 5000) == WAIT_OBJECT_0;
    int dead = 0;
    for (int i = 0; i < n; i++)
        dead += dead_within(members[i].process, 5000);
    int ok = started && n >= 3 && live == n && crashed && dead == n;
    char detail[256];
    snprintf(detail, sizeof detail,
             "%d task process(es) witnessed live; supervisor killed=%d; %d died with its Job "
             "handle",
             n, crashed, dead);
    required_result("supervisor loss destroys the task", ok, detail);
    for (int i = 0; i < n; i++)
        kill_and_close(members[i].process);
    if (started) CloseHandle(helper.hProcess);
}

static void read_text(const char *dir, const char *file, char *out, size_t n) {
    char path[MAX_PATH * 2];
    join_path(path, sizeof path, dir, file);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(out, n, "no broker diagnostic");
        return;
    }
    if (!fgets(out, (int)n, f)) snprintf(out, n, "empty broker diagnostic");
    fclose(f);
    out[strcspn(out, "\r\n")] = 0;
}

static void case_broker(const char *adv, const char *dir) {
    clear_dir(dir);
    set_env("PROCD_WIN_WITNESS_DIR", dir);
    procd_domain *domain = new_domain();
    const char *argv[] = {adv, "broker-wmi", NULL};
    procd_status rc = domain ? procd_domain_spawn(domain, argv, NULL) : PROCD_E_INTERNAL;
    record escaped = {0}, request = {0};
    int child = wait_record(dir, "broker-escape", &escaped, 12000) && attach_record(&escaped);
    int requested = wait_record(dir, "broker-request-ok", &request, 1000);
    int request_failed = requested ? 0 : wait_record(dir, "broker-request-failed", &request, 1000);
    procd_termination_evidence ev;
    if (domain) procd_domain_terminate(domain, 8000, &ev);
    int survived = child && alive(escaped.process);
    char diag[160], detail[320];
    read_text(dir, "broker-result.txt", diag, sizeof diag);
    if (survived)
        snprintf(detail, sizeof detail,
                 "Win32_Process.Create produced verified survivor %lu outside the Job (%s)",
                 (unsigned long)escaped.pid, diag);
    else
        snprintf(detail, sizeof detail,
                 "stock WMI/CIM probe did not produce a verified outside-Job survivor; rc=%s "
                 "request_ok=%d request_failed=%d aux=%lu diagnostic=%s",
                 procd_status_name(rc), requested, request_failed,
                 (unsigned long)(request_failed ? request.aux : 0), diag);
    escape_result("execution broker (WMI/CIM)", survived, detail);
    kill_and_close(child ? escaped.process : NULL);
    if (domain) procd_domain_release(domain);
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--duplicate-controller") == 0)
        return duplicate_controller_mode(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "--controller-crash") == 0)
        return controller_crash_mode(argv[2], argv[3]);
    const char *adv = argc > 1 ? argv[1] : "procd-adversary.exe";
    char self[MAX_PATH], dir[MAX_PATH * 2];
    if (!GetModuleFileNameA(NULL, self, (DWORD)sizeof self) || !make_dir(dir, sizeof dir)) {
        printf("FAIL: could not establish native Windows qualification workspace\n");
        return 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Windows native qualification: Job Object mechanism evidence (ENFORCED claims); "
           "out-of-contract escape probes reported separately\n");
    case_capabilities();
    case_preexec_handles_unrelated(adv, dir);
    case_ordinary(adv, dir);
    case_churn(adv, dir);
    case_recovery(dir);
    case_controller_loss(self, adv, dir);
    case_handle_duplication(self, adv, dir);
    case_parent_escape(adv, dir);
    case_broker(adv, dir);
    clear_dir(dir);
    RemoveDirectoryA(dir);
    set_env("PROCD_WIN_WITNESS_DIR", NULL);
    printf("==== %d required PASS, %d INCONCLUSIVE out-of-contract probe(s), %d FAIL ====\n",
           required_passes, inconclusive, failures);
    return failures ? 1 : 0;
}
