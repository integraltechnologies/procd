#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Descriptor-leak regression (Linux, cgroup-v2 lifecycle host; root not needed).
 *
 * A task must not accidentally inherit descriptors its supervisor happened to
 * have open (pipes, sockets, files): a leaked pipe held by a background
 * descendant is a classic way for a supervisor to hang waiting for EOF. A
 * writable descriptor the caller left open -- and NOT close-on-exec -- must not
 * be usable by the workload, because procd closes the child's inherited
 * descriptors (other than stdio) before exec rather than relying on FD_CLOEXEC.
 *
 * Independent oracle: the file's own contents. If the descriptor survived into
 * the workload, the workload's write lands in the file; production must leave the
 * file empty. The real Linux spawn path is exercised (create + spawn + terminate),
 * not a descriptor-closing helper in isolation.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#include "procd.h"
#include "witness.h"
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
    if (c.process_tree_termination != PROCD_CAP_ENFORCED) {
        const char *v = getenv("PROCD_REQUIRE_ENFORCED");
        int strict = v && strcmp(v, "1") == 0;
        printf("%s: enforced prerequisites unavailable (%s, euid=%d)\n", strict ? "FAIL" : "SKIP",
               c.detail, (int)geteuid());
        return strict ? 1 : 77;
    }

    /* The caller has an extra writable descriptor open when it spawns, NOT
     * close-on-exec, at a fixed high number. */
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
    setenv("PROCD_ADV_WRITE_FD", fds, 1);

    procd_policy pol = PROCD_POLICY_INIT; /* REQUIRE_ENFORCED */
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created an ENFORCED domain");
    if (rc != PROCD_OK) {
        close(leakfd);
        unlink(tmpl);
        return 1;
    }

    /* "fdwrite" writes through PROCD_ADV_WRITE_FD if it can; that fd points at
     * the probe file, so a successful write would grow the file. The probe
     * witnesses its own attempt ("fd-ok"/"fd-denied"), so an empty file cannot
     * pass merely because the workload never ran. */
    char wd[64];
    CHECK(w_dir_create(wd, sizeof wd) == 0, "created a witness directory");
    setenv(W_ENV, wd, 1);
    const char *av[] = {adv, "fdwrite", NULL};
    rc = procd_domain_spawn(d, av, NULL);
    CHECK(rc == PROCD_OK, "spawned the fd-probe workload");

    static w_rec w[W_MAX];
    int n = 0;
    const w_rec *okw = NULL, *denied = NULL;
    for (int i = 0; i < 150 && !okw && !denied; i++) {
        nap(20);
        n = w_read(wd, w, W_MAX);
        okw = w_find(w, n, "fd-ok");
        denied = w_find(w, n, "fd-denied");
    }
    CHECK(denied && !okw, "probe ran and witnessed that the inherited descriptor was unusable");
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
    unsetenv(W_ENV);
    w_dir_remove(wd);
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
