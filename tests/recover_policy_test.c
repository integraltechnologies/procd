#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
/*
 * Recovery preserves the security-relevant spawn policy (Linux, enforced host).
 *
 *   A. A domain created with a NON-default identity (uid/gid 1000) is recovered,
 *      and a spawn into the recovered handle actually runs as 1000 - proving
 *      recovery restored the established policy rather than a default. The
 *      effective uid is read independently from /proc/<pid>/status.
 *   B. A legacy record without captured policy (v2) is recovered for
 *      status/terminate but spawn is refused, rather than substituting a default
 *      identity.
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

#define STATE_DIR "/var/lib/procd"

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
/* effective uid of pid from /proc/<pid>/status, or -1 */
static long proc_euid(pid_t pid) {
    char p[64], b[4096];
    snprintf(p, sizeof p, "/proc/%d/status", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r <= 0) return -1;
    b[r] = 0;
    char *u = strstr(b, "\nUid:");
    if (!u) return -1;
    long ruid, euid;
    if (sscanf(u, "\nUid:\t%ld\t%ld", &ruid, &euid) != 2) return -1;
    return euid;
}
static void nonce_of(const char *id, char *out, size_t n) {
    /* linux-cgroup2:2:<nonce>:... */
    const char *s = id;
    for (int i = 0; i < 2; i++)
        s = strchr(s, ':') + 1;
    const char *e = strchr(s, ':');
    snprintf(out, n, "%.*s", (int)(e - s), s);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
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

    /* ---- A: non-default identity is preserved across recovery ---- */
    procd_policy pol = PROCD_POLICY_INIT;
    pol.drop_uid = 1000;
    pol.drop_gid = 1000;
    procd_domain *d = NULL;
    procd_status rc = procd_create_domain(&pol, &d);
    CHECK(rc == PROCD_OK, "created ENFORCED domain with non-default identity 1000:1000");
    if (rc != PROCD_OK) {
        printf("FAILURES (%d)\n", ++fails);
        return 1;
    }
    char id[PROCD_IDENTITY_MAX];
    procd_domain_identity(d, id, sizeof id);

    procd_recovery_outcome o;
    procd_domain *rd = NULL;
    rc = procd_recover(id, &o, &rd);
    CHECK(rc == PROCD_OK && o == PROCD_RECOVERED && rd, "domain recovered");
    if (rd) {
        const char *av[] = {"sleep", "8", NULL};
        int64_t pid = -1;
        rc = procd_domain_spawn(rd, av, &pid);
        CHECK(rc == PROCD_OK && pid > 0, "spawn into recovered domain succeeded");
        if (pid > 0) {
            nap(150);
            long eu = proc_euid((pid_t)pid);
            printf("   recovered-spawn effective uid = %ld\n", eu);
            CHECK(eu == 1000,
                  "recovered spawn ran as the ESTABLISHED identity (1000), not default");
        }
        procd_termination_evidence ev;
        procd_domain_terminate(rd, 3000, &ev);
        procd_domain_release(rd);
    }
    procd_domain_release(d);

    /* ---- B: legacy record without policy -> recover but refuse spawn ---- */
    /* Create a fresh domain, then rewrite its record as legacy v2 (no uid/gid). */
    procd_policy pol2 = PROCD_POLICY_INIT;
    procd_domain *d2 = NULL;
    if (procd_create_domain(&pol2, &d2) == PROCD_OK) {
        char id2[PROCD_IDENTITY_MAX];
        procd_domain_identity(d2, id2, sizeof id2);
        char nonce[64];
        nonce_of(id2, nonce, sizeof nonce);
        char recp[512];
        snprintf(recp, sizeof recp, "%s/%s.rec", STATE_DIR, nonce);
        char buf[1024];
        int fd = open(recp, O_RDONLY | O_CLOEXEC);
        ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
        if (fd >= 0) close(fd);
        int rewrote = 0;
        if (n > 0) {
            buf[n] = 0;
            /* rebuild as v2: keep all lines except uid/gid, change header to 2 */
            char out[1024];
            int w = 0;
            w += snprintf(out + w, sizeof out - w, "procd-record 2\n");
            char *line = strtok(buf, "\n");
            while (line) {
                if (strncmp(line, "procd-record", 12) != 0 && strncmp(line, "uid=", 4) != 0 &&
                    strncmp(line, "gid=", 4) != 0)
                    w += snprintf(out + w, sizeof out - w, "%s\n", line);
                line = strtok(NULL, "\n");
            }
            unlink(recp);
            int wf = open(recp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (wf >= 0) {
                rewrote = (write(wf, out, (size_t)w) == w);
                close(wf);
            }
        }
        CHECK(rewrote, "rewrote record as legacy v2 (no policy)");

        procd_recovery_outcome o2;
        procd_domain *rd2 = NULL;
        rc = procd_recover(id2, &o2, &rd2);
        CHECK(rc == PROCD_OK && o2 == PROCD_RECOVERED && rd2,
              "legacy-record domain still recovers for status/terminate");
        if (rd2) {
            const char *av[] = {"sleep", "8", NULL};
            int64_t pid = -1;
            procd_status src = procd_domain_spawn(rd2, av, &pid);
            CHECK(src != PROCD_OK && pid == -1,
                  "spawn into a legacy-record domain is REFUSED (no default substituted)");
            procd_termination_evidence ev;
            procd_domain_terminate(rd2, 3000, &ev);
            procd_domain_release(rd2);
        }
        procd_domain_release(d2);
    }

    printf("%s (%d failures)\n", fails ? "FAILURES" : "all recovery-policy checks passed", fails);
    return fails ? 1 : 0;
}
#else
int main(void) {
    printf("SKIP: Linux-only recovery-policy regression\n");
    return 77;
}
#endif
