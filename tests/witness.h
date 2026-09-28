/*
 * Adversarial-precondition witnesses (POSIX and Windows).
 *
 * Every fixture process records who it is (role, pid, ppid, pgid, sid, process
 * start time) in a per-scenario directory. The harness reads these records and
 * cross-checks every one that must be running against the kernel's own view,
 * establishing independently of procd that the intended topology actually
 * occurred before termination, and uses (pid, start time) as a survivor oracle
 * afterwards that is immune to PID reuse and never counts zombies as alive.
 *
 * On Windows the record's start is the process creation FILETIME, ppid is the
 * creating process, and pgid/sid are 0 (no such topology).
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef PROCD_WITNESS_H
#define PROCD_WITNESS_H
#include <stddef.h>

#define W_ENV "PROCD_ADV_WITNESS_DIR"
#define W_MAX 128

typedef struct {
    char role[24];
    long pid, ppid, pgid, sid;
    unsigned long long start;
} w_rec;

/* Start time of a live, non-zombie process; 0 if dead, zombie or unknown. */
unsigned long long w_start_time(long pid);

/* Fixture side: record the calling process under `role`. No-op when W_ENV is
 * unset. Written atomically (tmp + rename). */
void w_write(const char *role);

/* Harness side. */
int w_dir_create(char *out, size_t n); /* world-writable sticky dir; 0 ok */
void w_dir_remove(const char *dir);
int w_read(const char *dir, w_rec *out, int max);
const w_rec *w_find(const w_rec *v, int n, const char *role);
int w_count(const w_rec *v, int n, const char *role);
/* Is the exact recorded process (pid AND start time) still executing? */
int w_alive(const w_rec *r);
/* w_alive AND the kernel's current ppid/pgid/sid agree with the record, so a
 * witness cannot claim a topology the kernel does not show. */
int w_live(const w_rec *r);
/* Does the kernel's argv for `pid` contain `arg`? 1/0, or -1 if this platform
 * offers no such view. Used to prove an exec really replaced the image. */
int w_cmdline_has(long pid, const char *arg);
/* Hygiene: kill the exact recorded process (pid AND start time) if it is still
 * running. Never signals a reused pid. */
void w_kill(const w_rec *r);

#endif
