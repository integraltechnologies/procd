#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif
/* Adversarial-precondition witnesses. SPDX-License-Identifier: MPL-2.0 */
#if !defined(_WIN32)
#include "witness.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#endif

/* Kernel view of a live, non-zombie process. 0 on success. */
static int w_kernel(long pid, long *ppid, long *pgid, long *sid, unsigned long long *start) {
#if defined(__linux__)
    char p[64], b[1024];
    snprintf(p, sizeof p, "/proc/%ld/stat", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r <= 0) return -1;
    b[r] = 0;
    char *s = strrchr(b, ')'); /* comm may contain spaces/parens */
    if (!s || s[1] != ' ') return -1;
    s += 2;
    if (*s == 'Z' || *s == 'X' || *s == 'x') return -1; /* not executing */
    /* s is field 3 (state); ppid=4 pgrp=5 session=6 ... starttime=22 */
    long f[23] = {0};
    unsigned long long st = 0;
    for (int k = 4; k <= 22; k++) {
        s = strchr(s, ' ');
        if (!s) return -1;
        s++;
        if (k == 22)
            st = strtoull(s, NULL, 10);
        else
            f[k] = strtol(s, NULL, 10);
    }
    *ppid = f[4], *pgid = f[5], *sid = f[6], *start = st;
    return 0;
#elif defined(__APPLE__)
    struct proc_bsdinfo bi;
    if (proc_pidinfo((int)pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != (int)sizeof bi) return -1;
    if (bi.pbi_status == SZOMB) return -1;
    pid_t sd = getsid((pid_t)pid);
    if (sd < 0) return -1;
    *ppid = bi.pbi_ppid, *pgid = bi.pbi_pgid, *sid = sd;
    *start = (unsigned long long)bi.pbi_start_tvsec * 1000000ULL + bi.pbi_start_tvusec;
    return 0;
#else
    if (kill((pid_t)pid, 0) != 0) return -1;
    *ppid = *pgid = *sid = -1;
    *start = 1;
    return 0;
#endif
}

unsigned long long w_start_time(long pid) {
    long a, b, c;
    unsigned long long st;
    return w_kernel(pid, &a, &b, &c, &st) == 0 ? st : 0;
}

void w_write(const char *role) {
    const char *dir = getenv(W_ENV);
    if (!dir || !dir[0]) return;
    long pid = (long)getpid();
    char tmp[600], fin[600], buf[256];
    snprintf(tmp, sizeof tmp, "%s/.%s.%ld.tmp", dir, role, pid);
    snprintf(fin, sizeof fin, "%s/%s.%ld", dir, role, pid);
    int n = snprintf(buf, sizeof buf, "%s %ld %ld %ld %ld %llu\n", role, pid, (long)getppid(),
                     (long)getpgrp(), (long)getsid(0), w_start_time(pid));
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, buf, (size_t)n);
    close(fd);
    if (w == n)
        rename(tmp, fin);
    else
        unlink(tmp);
}

int w_dir_create(char *out, size_t n) {
    char t[] = "/tmp/procd_wit.XXXXXX";
    if (!mkdtemp(t)) return -1;
    /* the workload may run as an unprivileged uid; sticky keeps records apart */
    if (chmod(t, 01777) != 0) {
        rmdir(t);
        return -1;
    }
    snprintf(out, n, "%s", t);
    return 0;
}

void w_dir_remove(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char p[600];
            snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

int w_read(const char *dir, w_rec *out, int max) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue; /* ., .., in-progress tmp files */
        char p[600];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        w_rec r;
        memset(&r, 0, sizeof r);
        if (fscanf(f, "%23s %ld %ld %ld %ld %llu", r.role, &r.pid, &r.ppid, &r.pgid, &r.sid,
                   &r.start) == 6 &&
            r.pid > 0 && r.start != 0)
            out[n++] = r;
        fclose(f);
    }
    closedir(d);
    return n;
}

const w_rec *w_find(const w_rec *v, int n, const char *role) {
    for (int i = 0; i < n; i++)
        if (strcmp(v[i].role, role) == 0) return &v[i];
    return NULL;
}

int w_count(const w_rec *v, int n, const char *role) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(v[i].role, role) == 0) c++;
    return c;
}

int w_alive(const w_rec *r) {
    unsigned long long s = w_start_time(r->pid);
    return s != 0 && s == r->start;
}

int w_cmdline_has(long pid, const char *arg) {
#if defined(__linux__)
    char p[64], b[4096];
    snprintf(p, sizeof p, "/proc/%ld/cmdline", pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t r = read(fd, b, sizeof b - 1);
    close(fd);
    if (r <= 0) return 0;
    b[r] = 0;
    for (char *a = b; a < b + r; a += strlen(a) + 1)
        if (strcmp(a, arg) == 0) return 1;
    return 0;
#else
    (void)pid;
    (void)arg;
    return -1;
#endif
}

int w_live(const w_rec *r) {
    long ppid, pgid, sid;
    unsigned long long st;
    if (w_kernel(r->pid, &ppid, &pgid, &sid, &st) != 0 || st != r->start) return 0;
#if defined(__linux__) || defined(__APPLE__)
    if (ppid != r->ppid || pgid != r->pgid || sid != r->sid) return 0;
#endif
    return 1;
}
#else
typedef int procd_witness_translation_unit_nonempty;
#endif
