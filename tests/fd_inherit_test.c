#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Explicit file-descriptor inheritance regression (Linux, enforced host).
 *
 * Area 2: a workload must not accidentally inherit arbitrary descriptors the
 * caller opened. Unlike fd_escape_test (which uses a foreign cgroup.procs to
 * prove containment is not defeated), this uses an ORDINARY writable file to
 * prove the more general property: a descriptor the controller left open -- and
 * deliberately left NOT close-on-exec -- is simply not usable by the workload,
 * because procd closes the child's inherited descriptors before exec rather than
 * relying on FD_CLOEXEC.
 *
 * Independent oracle: the file's own contents. If the descriptor survived into
 * the workload, the workload's write lands in the file; production must leave the
 * file empty. The real Linux spawn path is exercised (create + spawn + terminate),
 * not a descriptor-closing helper in isolation.
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
static long file_size(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *adv = (argc > 1) ? argv[1] : "procd-adversary";
    setenv("PROCD_ADV_TTL", "10", 1);

    procd_capabilities c;
    procd_capabilities_probe(&c);
    if (geteuid() != 0 || c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    /* The caller deliberately opens an extra writable descriptor before spawning
     * and, like a careless (or hostile) controller, leaves it NOT close-on-exec
     * at a fixed high number. */
    char tmpl[] = "/tmp/procd_fdinherit.XXXXXX";
    int src = mkstemp(tmpl);
    CHECK(src >= 0, "created a writable probe file");
    if (src < 0) return 1;
    int leakfd = 201;
    CHECK(dup2(src, leakfd) == leakfd, "duplicated the writable descriptor to a fixed number");
    close(src);
    fcntl(leakfd, F_SETFD, 0); /* NOT close-on-exec: the property must not depend on it */
    CHECK(fcntl(leakfd, F_GETFD) != -1, "probe descriptor is genuinely open in the caller");
    char fds[16];
    snprintf(fds, sizeof fds, "%d", leakfd);
    setenv("PROCD_ADV_ESCAPE_FD", fds, 1);

    procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created an ENFORCED domain");
    if (rc != PROCD_OK) {
        close(leakfd);
        unlink(tmpl);
        return 1;
    }

    /* "fdescape" writes through PROCD_ADV_ESCAPE_FD if it can; here that fd points
     * at the ordinary probe file, so a successful write would grow the file. */
    const char *av[] = {adv, "fdescape", NULL};
    rc = procd_domain_spawn(d, av, NULL);
    CHECK(rc == PROCD_OK, "spawned the fd-probe workload");

    /* Give the workload ample time to attempt the write. */
    for (int i = 0; i < 100; i++) {
        nap(20);
        if (file_size(tmpl) > 0) break;
    }
    long sz = file_size(tmpl);
    printf("   probe file size after workload = %ld\n", sz);
    CHECK(sz == 0,
          "workload could NOT write through the inherited descriptor (fd closed pre-exec)");

    procd_termination_evidence ev;
    rc = procd_domain_terminate(d, 5000, &ev);
    CHECK(rc == PROCD_OK && ev.enforced && ev.final_state == PROCD_STATE_EMPTY,
          "termination reports enforced/empty");

    /* Sanity: the descriptor really was writable, so an empty file means the
     * workload never had it -- not that writing was impossible. */
    const char probe[] = "control";
    CHECK(write(leakfd, probe, sizeof probe - 1) == (ssize_t)(sizeof probe - 1),
          "control: the caller's own descriptor is genuinely writable");

    close(leakfd);
    unlink(tmpl);
    procd_domain_release(d);
    printf("%s (%d failures)\n", fails ? "FAILURES" : "all fd-inheritance checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    const char *v = getenv("PROCD_REQUIRE_ENFORCED");
    int strict = v && strcmp(v, "1") == 0;
    printf("%s: Linux-only fd-inheritance regression\n", strict ? "FAIL" : "SKIP");
    return strict ? 1 : 77;
}
#endif
