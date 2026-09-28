#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Bounded adversarial workload used by qualification tests.
 *
 * CRITICAL SAFETY PROPERTY: every process spawned here has its OWN bounded
 * lifetime independent of any containment. A broken containment implementation
 * must never leave an indefinitely running CI process. The lifetime is
 * PROCD_ADV_TTL seconds (default 20, hard-capped at 120).
 *
 * Mode is taken from argv[1] (default "child"). The root process prints
 * "ADV_ROOT <pid>\n" to stdout so tests can correlate. Descendants are silent.
 *
 * When PROCD_ADV_WITNESS_DIR is set (POSIX), every fixture process records a
 * witness (tests/witness.h) once its part of the topology is in place, so the
 * harness can prove the adversarial behavior actually happened.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <stdint.h>
#include <windows.h>
static void adv_sleep(int secs) {
    Sleep((DWORD)secs * 1000);
}

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI *nt_query_system_information_fn)(ULONG, PVOID, ULONG, PULONG);

typedef struct {
    PVOID object;
    ULONG_PTR process_id;
    ULONG_PTR handle_value;
    ULONG granted_access;
    USHORT creator_backtrace_index;
    USHORT object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
} adv_system_handle;

typedef struct {
    ULONG_PTR count;
    ULONG_PTR reserved;
    adv_system_handle handles[1];
} adv_system_handles;

static unsigned long long creation_time(HANDLE process) {
    FILETIME create, exit, kernel, user;
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) return 0;
    return ((unsigned long long)create.dwHighDateTime << 32) | create.dwLowDateTime;
}

static const char *witness_dir(void) {
    const char *p = getenv("PROCD_WIN_WITNESS_DIR");
    return p && p[0] ? p : NULL;
}

static void win_witness(const char *role, DWORD creator, DWORD aux) {
    const char *dir = witness_dir();
    if (!dir) return;
    char path[MAX_PATH * 2];
    snprintf(path, sizeof path, "%s\\%s.txt", dir, role);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    BOOL in_job = FALSE;
    IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
    char line[256];
    int n = snprintf(line, sizeof line, "%lu %llu %d %lu %lu\n",
                     (unsigned long)GetCurrentProcessId(), creation_time(GetCurrentProcess()),
                     in_job ? 1 : 0, (unsigned long)creator, (unsigned long)aux);
    DWORD wrote = 0;
    WriteFile(f, line, (DWORD)n, &wrote, NULL);
    FlushFileBuffers(f);
    CloseHandle(f);
}

static void self_path(char *out, DWORD n) {
    DWORD got = GetModuleFileNameA(NULL, out, n);
    if (!got || got >= n) out[0] = 0;
}

static int spawn_self(const char *mode, const char *arg, DWORD flags, HANDLE parent,
                      PROCESS_INFORMATION *pi) {
    char self[MAX_PATH];
    self_path(self, sizeof self);
    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof cmd, "\"%s\" %s%s%s%s", self, mode, arg ? " \"" : "", arg ? arg : "",
             arg ? "\"" : "");
    ZeroMemory(pi, sizeof *pi);
    if (!parent) {
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof si);
        si.cb = sizeof si;
        return CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags | CREATE_NO_WINDOW, NULL, NULL,
                              &si, pi)
                   ? 1
                   : 0;
    }

    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!attrs) return 0;
    STARTUPINFOEXA sx;
    ZeroMemory(&sx, sizeof sx);
    sx.StartupInfo.cb = sizeof sx;
    int ok = InitializeProcThreadAttributeList(attrs, 1, 0, &bytes) &&
             UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent,
                                       sizeof parent, NULL, NULL);
    sx.lpAttributeList = attrs;
    if (ok)
        ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                            flags | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                            &sx.StartupInfo, pi)
                 ? 1
                 : 0;
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    return ok;
}

static int duplicate_controller_job(DWORD controller_pid, DWORD *error_out) {
    HANDLE controller = OpenProcess(PROCESS_DUP_HANDLE, FALSE, controller_pid);
    if (!controller) {
        *error_out = GetLastError();
        return 0;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC address = GetProcAddress(ntdll, "NtQuerySystemInformation");
    nt_query_system_information_fn query = NULL;
    memcpy(&query, &address, sizeof query);
    if (!query) {
        *error_out = ERROR_PROC_NOT_FOUND;
        CloseHandle(controller);
        return 0;
    }
    ULONG cap = 1U << 20;
    void *buf = NULL;
    NTSTATUS st;
    for (;;) {
        buf = HeapAlloc(GetProcessHeap(), 0, cap);
        if (!buf) {
            *error_out = ERROR_OUTOFMEMORY;
            CloseHandle(controller);
            return 0;
        }
        ULONG need = 0;
        st = query(64 /* SystemExtendedHandleInformation */, buf, cap, &need);
        if (st >= 0) break;
        HeapFree(GetProcessHeap(), 0, buf);
        buf = NULL;
        if (need > cap)
            cap = need + 65536;
        else
            cap *= 2;
        if (cap > (64U << 20)) {
            *error_out = ERROR_INSUFFICIENT_BUFFER;
            CloseHandle(controller);
            return 0;
        }
    }
    adv_system_handles *all = (adv_system_handles *)buf;
    int found = 0;
    for (ULONG_PTR i = 0; i < all->count; i++) {
        adv_system_handle *e = &all->handles[i];
        if (e->process_id != controller_pid) continue;
        HANDLE dup = NULL;
        if (!DuplicateHandle(controller, (HANDLE)e->handle_value, GetCurrentProcess(), &dup, 0,
                             FALSE, DUPLICATE_SAME_ACCESS))
            continue;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ai;
        BOOL member = FALSE;
        if (QueryInformationJobObject(dup, JobObjectBasicAccountingInformation, &ai, sizeof ai,
                                      NULL) &&
            IsProcessInJob(GetCurrentProcess(), dup, &member) && member) {
            /* Deliberately retain the duplicate for the rest of our bounded
             * lifetime. This is the authority-loss limitation under test. */
            found = 1;
            break;
        }
        CloseHandle(dup);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(controller);
    if (!found) *error_out = ERROR_NOT_FOUND;
    return found;
}

static DWORD own_job_handle_count(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC address = GetProcAddress(ntdll, "NtQuerySystemInformation");
    nt_query_system_information_fn query = NULL;
    memcpy(&query, &address, sizeof query);
    if (!query) return (DWORD)-1;
    ULONG cap = 1U << 20;
    void *buf = NULL;
    NTSTATUS st;
    for (;;) {
        buf = HeapAlloc(GetProcessHeap(), 0, cap);
        if (!buf) return (DWORD)-1;
        ULONG need = 0;
        st = query(64 /* SystemExtendedHandleInformation */, buf, cap, &need);
        if (st >= 0) break;
        HeapFree(GetProcessHeap(), 0, buf);
        if (need > cap)
            cap = need + 65536;
        else
            cap *= 2;
        if (cap > (64U << 20)) return (DWORD)-1;
    }
    DWORD me = GetCurrentProcessId(), count = 0;
    adv_system_handles *all = (adv_system_handles *)buf;
    for (ULONG_PTR i = 0; i < all->count; i++) {
        adv_system_handle *e = &all->handles[i];
        if (e->process_id != me) continue;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ai;
        if (QueryInformationJobObject((HANDLE)e->handle_value, JobObjectBasicAccountingInformation,
                                      &ai, sizeof ai, NULL))
            count++;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return count;
}

static void check_sentinel(void) {
    const char *v = getenv("PROCD_WIN_SENTINEL_HANDLE");
    if (!v || !v[0]) return;
    uintptr_t raw = (uintptr_t)_strtoui64(v, NULL, 0);
    BOOL signalled = SetEvent((HANDLE)raw);
    win_witness("sentinel", 0, signalled ? 1 : GetLastError());
}

static void write_breakaway_outcome(const char *route, const PROCESS_INFORMATION *pi,
                                    DWORD requested_error) {
    const char *path = getenv("PROCD_ADV_OUTCOME_FILE");
    if (!path || !path[0]) return;
    FILE *f = fopen(path, "w");
    if (!f) return;
    /* Record the launched process's creation time so the negative control can
     * bind its retained handle to the exact process object (PID + creation
     * time), not a bare PID that reuse could alias. */
    fprintf(f, "%s %lu %lu %llu\n", route, pi ? (unsigned long)pi->dwProcessId : 0,
            (unsigned long)requested_error, pi ? creation_time(pi->hProcess) : 0ULL);
    fclose(f);
}

static DWORD request_wmi_broker(void) {
    const char *dir = witness_dir();
    if (!dir) return ERROR_PATH_NOT_FOUND;
    char script[MAX_PATH * 2], result[MAX_PATH * 2], self[MAX_PATH];
    snprintf(script, sizeof script, "%s\\broker.ps1", dir);
    snprintf(result, sizeof result, "%s\\broker-result.txt", dir);
    self_path(self, sizeof self);
    const char ps[] = "param($exe,$dir,$result)\r\n"
                      "$cmd='\"'+$exe+'\" leaf-file \"'+$dir+'\" broker-escape'\r\n"
                      "try {\r\n"
                      " $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                      "-Arguments @{CommandLine=$cmd} -ErrorAction Stop\r\n"
                      " ($r.ReturnValue.ToString()+' '+$r.ProcessId.ToString()) | "
                      "Set-Content -LiteralPath $result\r\n"
                      " exit [int]$r.ReturnValue\r\n"
                      "} catch {\r\n"
                      " ('ERROR '+$_.Exception.HResult.ToString()+' '+$_.Exception.Message) | "
                      "Set-Content -LiteralPath $result\r\n"
                      " exit 125\r\n"
                      "}\r\n";
    HANDLE f = CreateFileA(script, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return GetLastError();
    DWORD wrote = 0;
    BOOL write_ok = WriteFile(f, ps, (DWORD)strlen(ps), &wrote, NULL);
    CloseHandle(f);
    if (!write_ok || wrote != (DWORD)strlen(ps)) return ERROR_WRITE_FAULT;

    char cmd[MAX_PATH * 7];
    snprintf(cmd, sizeof cmd,
             "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\" "
             "\"%s\" \"%s\" \"%s\"",
             script, self, dir, result);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return GetLastError();
    CloseHandle(pi.hThread);
    DWORD wait = WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = ERROR_TIMEOUT;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    if (wait == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
    CloseHandle(pi.hProcess);
    return code;
}
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static void adv_sleep(int secs) {
    sleep((unsigned)secs);
}
#endif

static int ttl(void) {
    const char *t = getenv("PROCD_ADV_TTL");
    int v = t ? atoi(t) : 20;
    if (v <= 0) v = 20;
    if (v > 120) v = 120;
    return v;
}

#if !defined(_WIN32)
#include "witness.h"
#include <time.h>

static const char *g_self; /* path of this binary, for the exec mode */

/* record a descendant's pid so a test can observe whether it escaped */
static void wpf(void) {
    const char *pf = getenv("PROCD_ADV_PIDFILE");
    if (!pf || !pf[0]) return;
    FILE *f = fopen(pf, "w");
    if (f) {
        fprintf(f, "%d", (int)getpid());
        fclose(f);
    }
}
static void nap_ms(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
/* bounded wait until our parent is no longer `orig` (we were reparented) */
static void await_reparent(pid_t orig) {
    for (int i = 0; i < 400 && getppid() == orig; i++)
        nap_ms(5);
}
/* witness `role`, then live out the bounded lifetime */
static void live(const char *role) {
    w_write(role);
    adv_sleep(ttl());
    _exit(0);
}

static int run_posix(const char *mode) {
    int T = ttl();
    if (strcmp(mode, "exec-post") == 0) live("exec-post"); /* new image after exec */
    w_write("root");
    if (strcmp(mode, "child") == 0) {
        if (fork() == 0) live("child");
    } else if (strcmp(mode, "grandchild") == 0) {
        if (fork() == 0) {
            if (fork() == 0) live("grandchild");
            live("child");
        }
    } else if (strcmp(mode, "setsid") == 0) {
        if (fork() == 0) {
            setsid(); /* new session: escapes pgid */
            wpf();
            live("setsid");
        }
    } else if (strcmp(mode, "setpgid") == 0) {
        if (fork() == 0) {
            setpgid(0, 0);
            live("setpgid");
        }
    } else if (strcmp(mode, "double-fork") == 0) {
        pid_t p = fork();
        if (p == 0) {
            setsid();
            w_write("df-middle");
            pid_t mid = getpid();
            if (fork() == 0) {
                await_reparent(mid); /* orphaned daemon */
                wpf();
                live("df-grandchild");
            }
            _exit(0); /* middle exits: grandchild reparents */
        }
        waitpid(p, NULL, 0);
    } else if (strcmp(mode, "reparent") == 0) {
        pid_t p = fork();
        if (p == 0) {
            w_write("rp-middle");
            pid_t mid = getpid();
            if (fork() == 0) {
                await_reparent(mid);
                live("rp-grandchild");
            }
            _exit(0); /* parent exits, grandchild reparented to subreaper/init */
        }
        waitpid(p, NULL, 0);
    } else if (strcmp(mode, "exec") == 0) {
        if (fork() == 0) {
            w_write("exec-pre");
            execl(g_self, g_self, "exec-post", (char *)NULL);
            _exit(127);
        }
    } else if (strcmp(mode, "leader-exit") == 0) {
        pid_t leader = getpid();
        if (fork() == 0) {
            await_reparent(leader);
            live("orphan"); /* descendant keeps running */
        }
        _exit(0); /* leader exits immediately */
    } else if (strcmp(mode, "churn") == 0) {
        /* keep forking for the whole bounded lifetime, so forks race with
         * termination; the first 64 children witness themselves */
        time_t end = time(NULL) + T;
        for (int i = 0; time(NULL) < end; i++) {
            pid_t p = fork();
            if (p == 0) {
                if (i < 64) w_write("churn");
                adv_sleep(1);
                _exit(0);
            }
            while (waitpid(-1, NULL, WNOHANG) > 0) {
            }
            nap_ms(5);
        }
        return 0;
    } else if (strcmp(mode, "fdwrite") == 0) {
        /* Descriptor-leak probe: write through a descriptor the caller left open
         * (PROCD_ADV_WRITE_FD). Succeeds only if that fd survived into the task. */
        const char *fs = getenv("PROCD_ADV_WRITE_FD");
        int fd = (fs && fs[0]) ? atoi(fs) : -1;
        if (fork() == 0) {
            int ok = 0;
            if (fd >= 0) {
                char me[16];
                int n = snprintf(me, sizeof me, "%d", (int)getpid());
                ok = write(fd, me, (size_t)n) == (ssize_t)n;
            }
            live(ok ? "fd-ok" : "fd-denied");
        }
    } else {
        if (fork() == 0) live("child");
    }
    adv_sleep(T);
    return 0;
}
#endif

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "child";
#if defined(_WIN32)
    DWORD creator = (argc > 2) ? strtoul(argv[2], NULL, 10) : 0;
    if (strcmp(mode, "leaf") == 0) {
        /* record our pid so the negative-control test can observe survival */
        const char *pf = getenv("PROCD_ADV_PIDFILE");
        if (pf && pf[0]) {
            FILE *f = fopen(pf, "w");
            if (f) {
                fprintf(f, "%lu", (unsigned long)GetCurrentProcessId());
                fclose(f);
            }
        }
        win_witness((argc > 3) ? argv[3] : "leaf", creator, 0);
        adv_sleep(ttl());
        return 0;
    }
    if (strcmp(mode, "leaf-file") == 0 && argc > 3) {
        _putenv_s("PROCD_WIN_WITNESS_DIR", argv[2]);
        win_witness(argv[3], 0, 0);
        adv_sleep(ttl());
        return 0;
    }
    if (strcmp(mode, "ordinary-child") == 0) {
        PROCESS_INFORMATION child_pi;
        char parent[32];
        win_witness("child", creator, 0);
        snprintf(parent, sizeof parent, "%lu", (unsigned long)GetCurrentProcessId());
        if (spawn_self("grandchild", parent, 0, NULL, &child_pi)) {
            CloseHandle(child_pi.hThread);
            CloseHandle(child_pi.hProcess);
        }
        adv_sleep(ttl());
        return 0;
    }
    if (strcmp(mode, "grandchild") == 0) {
        win_witness("grandchild", creator, 0);
        adv_sleep(ttl());
        return 0;
    }

    win_witness("root", 0, 0);
    win_witness("job-handle-scan", 0, own_job_handle_count());
    check_sentinel();
    printf("ADV_ROOT %lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    PROCESS_INFORMATION pi;
    /* breakaway mode tries to leave the Job; if the Job forbids breakaway the
     * create fails and we fall back to an in-Job child (which stays contained). */
    if (strcmp(mode, "breakaway") == 0) {
        if (spawn_self("leaf", NULL, CREATE_BREAKAWAY_FROM_JOB, NULL, &pi)) {
            write_breakaway_outcome("requested-breakaway", &pi, ERROR_SUCCESS);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            DWORD requested_error = GetLastError();
            if (spawn_self("leaf", NULL, 0, NULL, &pi)) {
                write_breakaway_outcome("contained-fallback", &pi, requested_error);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            } else {
                write_breakaway_outcome("creation-failed", NULL, requested_error);
            }
        }
    } else if (strcmp(mode, "preexec") == 0) {
        /* The root witness is intentionally the first fixture action. */
    } else if (strcmp(mode, "ordinary") == 0) {
        char parent[32];
        snprintf(parent, sizeof parent, "%lu", (unsigned long)GetCurrentProcessId());
        if (spawn_self("ordinary-child", parent, 0, NULL, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return 0; /* leader exit while descendants remain */
    } else if (strcmp(mode, "churn") == 0) {
        DWORD end = GetTickCount() + (DWORD)ttl() * 1000;
        for (unsigned i = 0; GetTickCount() < end; i++) {
            char arg[64], role[64], self[MAX_PATH], cmd[MAX_PATH * 2];
            snprintf(arg, sizeof arg, "%lu", (unsigned long)GetCurrentProcessId());
            snprintf(role, sizeof role, "churn-%04u", i);
            self_path(self, sizeof self);
            snprintf(cmd, sizeof cmd, "\"%s\" leaf %s %s", self, arg, role);
            STARTUPINFOA si;
            ZeroMemory(&si, sizeof si);
            si.cb = sizeof si;
            ZeroMemory(&pi, sizeof pi);
            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si,
                               &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            Sleep(10);
        }
        return 0;
    } else if (strcmp(mode, "parent-escape") == 0) {
        const char *v = getenv("PROCD_WIN_CONTROLLER_PID");
        DWORD controller_pid = v ? strtoul(v, NULL, 10) : 0;
        HANDLE parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, controller_pid);
        DWORD error = parent ? ERROR_SUCCESS : GetLastError();
        if (parent) {
            char arg[32];
            snprintf(arg, sizeof arg, "%lu", (unsigned long)GetCurrentProcessId());
            if (spawn_self("leaf", arg, 0, parent, &pi)) {
                /* Rewrite the default leaf witness with a distinct role by
                 * passing it as argv[3] using a direct command below is simpler
                 * for other modes; here the survivor PID is published. */
                const char *dir = witness_dir();
                if (dir) {
                    char p[MAX_PATH * 2];
                    snprintf(p, sizeof p, "%s\\parent-escape-pid.txt", dir);
                    FILE *f = fopen(p, "w");
                    if (f) {
                        fprintf(f, "%lu %llu\n", (unsigned long)pi.dwProcessId,
                                creation_time(pi.hProcess));
                        fclose(f);
                    }
                }
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                error = ERROR_SUCCESS;
            } else
                error = GetLastError();
            CloseHandle(parent);
        }
        win_witness(error == ERROR_SUCCESS ? "parent-request-ok" : "parent-request-failed", 0,
                    error);
    } else if (strcmp(mode, "duplicate-job") == 0) {
        const char *v = getenv("PROCD_WIN_CONTROLLER_PID");
        DWORD controller_pid = v ? strtoul(v, NULL, 10) : 0;
        DWORD error = 0;
        int ok = duplicate_controller_job(controller_pid, &error);
        win_witness(ok ? "duplicate-ok" : "duplicate-failed", controller_pid, error);
    } else if (strcmp(mode, "broker-wmi") == 0) {
        DWORD error = request_wmi_broker();
        win_witness(error == ERROR_SUCCESS ? "broker-request-ok" : "broker-request-failed", 0,
                    error);
    } else if (spawn_self("leaf", NULL, 0, NULL, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    adv_sleep(ttl());
    return 0;
#else
    if (strcmp(mode, "leaf") == 0) {
        adv_sleep(ttl());
        return 0;
    }
#if defined(__linux__)
    g_self = "/proc/self/exe";
#else
    g_self = argv[0];
#endif
    printf("ADV_ROOT %d\n", (int)getpid());
    fflush(stdout);
    return run_posix(mode);
#endif
}
