/* perf 能力探针：在目标机上逐个尝试配置，打印 fd/errno 与内核帧数 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PAGES 16

static int run_cfg(const char *name, int type, uint64_t cfg, int pid, int cpu,
                   int excl_kernel, int excl_chain, int sample_ip)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = type;
    pe.size = sizeof(pe);
    pe.config = cfg;
    pe.sample_period = 500;
    pe.sample_type = (sample_ip ? PERF_SAMPLE_IP : 0) | PERF_SAMPLE_CALLCHAIN;
    pe.disabled = 1;
    pe.exclude_kernel = excl_kernel ? 1 : 0;
    pe.exclude_callchain_kernel = excl_chain ? 1 : 0;
    pe.exclude_hv = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, pid, cpu, -1, 0);
    if (fd < 0) {
        printf("[%-28s] open errno=%d\n", name, errno);
        return -1;
    }
    long pg = sysconf(_SC_PAGESIZE);
    size_t len = (size_t)pg * (1 + PAGES);
    void *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        printf("[%-28s] mmap errno=%d\n", name, errno);
        close(fd);
        return -1;
    }
    struct perf_event_mmap_page *meta = m;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    struct timespec t0, t1;
    volatile uint64_t acc = 1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        for (int i = 0; i < 2000; i++)
            acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
        (void)syscall(__NR_getpid);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if ((t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L >= 700)
            break;
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t head = meta->data_head;
    __sync_synchronize();
    uint64_t tail = meta->data_tail;
    size_t dsize = (size_t)pg * PAGES;
    unsigned char *data = (unsigned char *)m + meta->data_offset;
    int recs = 0, kern = 0;
    uint64_t first_user = 0, first_kern = 0;

    while (tail < head) {
        size_t off = (size_t)(tail % dsize);
        if (off + sizeof(struct perf_event_header) > dsize)
            break;
        struct perf_event_header h;
        memcpy(&h, data + off, sizeof(h));
        if (h.size < sizeof(h) || off + h.size > dsize)
            break;
        if (h.type == PERF_RECORD_SAMPLE) {
            recs++;
            size_t p = off + sizeof(h);
            if (sample_ip && p + 8 <= off + h.size) {
                uint64_t ip;
                memcpy(&ip, data + p, 8);
                p += 8;
                if (ip >= 0xffffff8000000000ULL && ip < 0xffffffd000000000ULL) {
                    kern++;
                    if (!first_kern) first_kern = ip;
                } else if (!first_user) {
                    first_user = ip;
                }
            }
            if (p + 8 <= off + h.size) {
                uint64_t nr;
                memcpy(&nr, data + p, 8);
                p += 8;
                for (uint64_t i = 0; i < nr && p + 8 <= off + h.size; i++) {
                    uint64_t a;
                    memcpy(&a, data + p, 8);
                    p += 8;
                    if (a >= 0xffffff8000000000ULL && a < 0xffffffd000000000ULL) {
                        kern++;
                        if (!first_kern) first_kern = a;
                    } else if (!first_user) {
                        first_user = a;
                    }
                }
            }
        }
        tail += h.size;
    }
    meta->data_tail = head;
    munmap(m, len);
    close(fd);
    printf("[%-28s] fd ok recs=%d kern=%d user0=%#llx kern0=%#llx\n",
           name, recs, kern, (unsigned long long)first_user,
           (unsigned long long)first_kern);
    return kern;
}

int main(void)
{
    FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    char buf[32] = "?";
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            char *nl = strchr(buf, '\n');
            if (nl) *nl = 0;
        }
        fclose(f);
    }
    printf("paranoid=%s uid=%d\n", buf, (int)getuid());

    run_cfg("hw-cycles exclk=1 ip+chain", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0, -1, 1, 0, 1);
    run_cfg("hw-cycles exclk=1 chain", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0, -1, 1, 0, 0);
    run_cfg("hw-cycles exclk=0 ip+chain", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0, -1, 0, 0, 1);
    run_cfg("hw-cycles exclk=0 cpu0", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, -1, 0, 0, 0, 1);
    run_cfg("sw-cpuclock exclk=0 ip+chain", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 0, -1, 0, 0, 1);
    run_cfg("sw-taskclock exclk=0 ip", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, 0, -1, 0, 0, 1);
    return 0;
}
