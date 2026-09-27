#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * B2 inherited-descriptor escape regression (Linux, needs the enforced
 * prerequisites).
 *
 * Reproduces the verifier's exact attack: the controller holds a foreign
 * cgroup.procs open (as root, with no FD_CLOEXEC), procd spawns the workload,
 * and the workload writes its pid through that inherited descriptor. Because the
 * kernel checks the credentials captured when the descriptor was opened, a
 * surviving root-opened descriptor lets a dropped-privilege workload migrate a
 * process out of the invocation domain.
 *
 * The independent oracle is the foreign cgroup's own cgroup.procs (does the
 * escaped pid appear?) plus process liveness after termination - not procd's own
 * status. Production must:
 *   - leave the foreign cgroup empty (the descriptor was closed before exec);
 *   - terminate with enforced/empty evidence;
 *   - leave no escaped survivor.
 *
 * The pre-B2 backend (which relied on caller FD_CLOEXEC) fails this: the pid
 * appears in the foreign cgroup and survives termination.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            fails++;                                                                               \
        } else                                                                                     \
            printf("ok: %s\n", msg);                                                               \
    } while (0)

static void nap(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
static void own_cgroup(char *out, size_t n) {
    char b[512] = {0};
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    ssize_t r = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (r < 0) r = 0;
    b[r] = 0;
    b[strcspn(b, "\n")] = 0;
    const char *rel = strrchr(b, ':') ? strrchr(b, ':') + 1 : "/";
    snprintf(out, n, "/sys/fs/cgroup%s", strcmp(rel, "/") == 0 ? "" : rel);
}
/* first pid listed in cg's cgroup.procs, or 0 */
static pid_t first_pid(const char *cg) {
    char p[700], b[256];
    snprintf(p, sizeof p, "%s/cgroup.procs", cg);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r <= 0) return 0;
    b[r] = 0;
    return (pid_t)atoi(b);
}
static int alive(pid_t p) {
    return p > 0 && kill(p, 0) == 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "20", 1);

    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    char cg[512];
    own_cgroup(cg, sizeof cg);
    char foreign[600];
    snprintf(foreign, sizeof foreign, "%s/procd_fd_foreign", cg);
    mkdir(foreign, 0755); /* root-owned; a dropped workload cannot open it itself */

    /* Controller holds foreign cgroup.procs open as root, WITHOUT CLOEXEC, at a
     * fixed high fd, exactly as the verifier's exploit did. */
    char fpath[700];
    snprintf(fpath, sizeof fpath, "%s/cgroup.procs", foreign);
    int raw = open(fpath, O_WRONLY);
    CHECK(raw >= 0, "controller opened foreign cgroup.procs as root");
    if (raw < 0) {
        rmdir(foreign);
        return 1;
    }
    int escfd = 200;
    dup2(raw, escfd);
    close(raw);
    fcntl(escfd, F_SETFD, 0); /* ensure NOT close-on-exec (attacker's setup) */
    CHECK(fcntl(escfd, F_GETFD) != -1, "escape descriptor is genuinely open in the controller");
    char fds[16];
    snprintf(fds, sizeof fds, "%d", escfd);
    setenv("PROCD_ADV_ESCAPE_FD", fds, 1);

    procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created an ENFORCED domain");
    if (rc != PROCD_OK) {
        rmdir(foreign);
        return 1;
    }

    const char *av[] = {adv, "fdescape", NULL};
    rc = procd_domain_spawn(d, av, NULL);
    CHECK(rc == PROCD_OK, "spawned the fd-escape workload");

    /* let the attempt happen; watch the foreign cgroup independently */
    pid_t escaped = 0;
    for (int i = 0; i < 100 && !escaped; i++) {
        nap(20);
        escaped = first_pid(foreign);
    }
    printf("   foreign cgroup escaped pid = %d\n", (int)escaped);

    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 5000, &ev);
    nap(100);

    CHECK(escaped == 0, "B2: workload could NOT migrate through the inherited descriptor");
    CHECK(!alive(escaped), "B2: no escaped survivor after termination");
    CHECK(rc == PROCD_OK && ev.enforced && ev.final_state == PROCD_STATE_EMPTY,
          "termination reports enforced/empty");

    /* cleanup */
    if (alive(escaped)) kill(escaped, SIGKILL);
    {
        char kp[700];
        snprintf(kp, sizeof kp, "%s/cgroup.kill", foreign);
        int fd = open(kp, O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t w = write(fd, "1", 1);
            (void)w;
            close(fd);
        }
    }
    for (int i = 0; i < 100 && first_pid(foreign); i++)
        nap(10);
    close(escfd);
    procd_domain_release(d);
    rmdir(foreign);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all fd-escape checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: Linux-only fd-escape regression\n");
    return 77;
}
#endif
