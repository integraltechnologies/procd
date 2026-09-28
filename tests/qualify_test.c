#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/*
 * Qualification test: runs the shared matrix against the PRODUCTION library and
 * asserts no scenario FAILs (a FAIL means a claimed guarantee was not upheld).
 * SKIPs are acceptable and expected where prerequisites are unavailable or the
 * backend truthfully does not claim the guarantee. Exits 77 (ctest "skipped")
 * if no adversarial scenario PASSed, so CI never mistakes an unexercised host
 * for a pass.
 *
 * With PROCD_REQUIRE_ENFORCED=1 (dedicated ENFORCED qualification) there is no
 * skip: exit 0 only if ProcessTreeTermination is ENFORCED and every adversarial
 * scenario PASSed with an independently observed precondition; otherwise 1.
 *
 * With PROCD_REQUIRE_CLEANUP=1 (native per-OS qualification) every lifecycle
 * scenario must PASS -- witnessed topology, zero survivors, bounded termination
 * -- whatever capability level the backend reports.
 *
 * Also verifies an unrelated same-user control process survives qualification.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include "qualify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

int main(int argc, char **argv) {
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";

    /* Unrelated same-user control process that MUST survive qualification. */
#if defined(_WIN32)
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION cpi;
    ZeroMemory(&cpi, sizeof cpi);
    BOOL have_ctrl = CreateProcessA(NULL, (LPSTR) "ping.exe -n 600 127.0.0.1", NULL, NULL, FALSE,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &cpi);
#else
    pid_t ctrl = fork();
    if (ctrl == 0) {
        /* outlives the whole matrix (killed below), so its death means procd */
        execlp("sleep", "sleep", "600", (char *)NULL);
        _exit(127);
    }
#endif

    static q_case cases[Q_MAX_CASES];
    int n = 0;
    int fails = procd_qualify_run(adv, cases, Q_MAX_CASES, &n);
    int skips = 0, passes = 0, adv_passes = 0;
    for (int i = 0; i < n; i++) {
        printf("[%-4s] %-18s %s\n", q_result_name(cases[i].result), cases[i].name, cases[i].detail);
        if (cases[i].result == Q_SKIP)
            skips++;
        else if (cases[i].result == Q_PASS) {
            passes++;
            if (cases[i].adversarial) adv_passes++;
        }
    }

    /* control process must still be alive */
    int ctrl_alive;
#if defined(_WIN32)
    DWORD ec = 0;
    ctrl_alive = have_ctrl && GetExitCodeProcess(cpi.hProcess, &ec) && ec == STILL_ACTIVE;
    if (have_ctrl) {
        TerminateProcess(cpi.hProcess, 0);
        CloseHandle(cpi.hThread);
        CloseHandle(cpi.hProcess);
    }
#else
    /* our own unreaped child: a zombie (killed) must not count as alive */
    ctrl_alive = (waitpid(ctrl, NULL, WNOHANG) == 0);
    kill(ctrl, SIGKILL);
    waitpid(ctrl, NULL, 0);
#endif
    if (!ctrl_alive) {
        printf("FAIL: unrelated control process did not survive qualification\n");
        fails++;
    } else
        printf("ok: unrelated same-user control process survived\n");

    printf("==== %d PASS (%d adversarial), %d SKIP, %d FAIL ====\n", passes, adv_passes, skips,
           fails);
    if (fails) return 1;
    if (procd_qualify_require_cleanup()) {
        char why[256];
        int bad = procd_qualify_practical_verdict(cases, n, why, sizeof why);
        printf("PRACTICAL cleanup qualification: %s: %s\n", bad ? "FAIL" : "PASS", why);
        if (bad) return 1;
    }
    if (procd_qualify_strict()) {
        char why[256];
        int bad = procd_qualify_enforced_verdict(cases, n, why, sizeof why);
        printf("ENFORCED qualification: %s: %s\n", bad ? "FAIL" : "PASS", why);
        return bad ? 1 : 0;
    }
    /* If no adversarial scenario was demonstrated, report skipped to CI. */
    if (adv_passes == 0) {
        printf("note: no adversarial scenario demonstrated (see SKIP reasons)\n");
        return 77;
    }
    return 0;
}
