/* util.c — 基础设施：日志、绑核、调度、futex、ashmem */
#define _GNU_SOURCE
#include "ghost.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

ghost_ctx g = { .fd_ashmem = -1, .fd_pipe = { -1, -1 }, .verbose = 0 };

static int g_cpu_orig = -1;
static int g_cpu_bound = -1;

void g_log(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stderr);
    fputc('\n', stderr);
    fflush(stderr);
}

void g_dbg(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs("[dbg] ", stderr);
    fputs(buf, stderr);
    fputc('\n', stderr);
    fflush(stderr);
}

long g_syscall(long n, long a, long b, long c, long d, long e, long f)
{
    return syscall(n, a, b, c, d, e, f);
}

int g_read_file(const char *p, char *buf, size_t n)
{
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t r = read(fd, buf, n - 1);
    int e = errno;
    close(fd);
    if (r < 0) return -e;
    buf[r] = 0;
    /* 去掉尾部换行 */
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r')) buf[--r] = 0;
    return (int)r;
}

int g_write_file(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t r = write(fd, s, strlen(s));
    int e = errno;
    close(fd);
    return r < 0 ? -e : 0;
}

int cpubind_init(void)
{
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof(set), &set) != 0) return -errno;
    int n = CPU_COUNT(&set);
    if (n <= 0) return -1;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &set)) { g_cpu_orig = i; break; }
    }
    return n;
}

int cpubind_bind(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    /* 参考实现绑定固定 cpu（cpubind_bind(2)）；越界时回落到 0 */
    if (cpu < 0) cpu = 0;
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) return -errno;
        cpu = 0;
    }
    g_cpu_bound = cpu;
    return 0;
}

void cpubind_shutdown(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    if (g_cpu_orig >= 0) {
        CPU_SET(g_cpu_orig, &set);
        sched_setaffinity(0, sizeof(set), &set);
    }
    g_cpu_bound = -1;
}

/* 参考：syscall(178)=gettid 后 sched_setattr_tid(tid, nice)，nice=-20 提优先级 / +19 降优先级 */
struct sched_attr_local {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

int sched_setattr_tid(int tid, int policy)
{
    struct sched_attr_local a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_OTHER;
    a.sched_nice = policy;   /* 参考实现把 nice 直接塞进第二个参数 */
    /* sched_setattr(pid, attr, flags)；tid==0 表示当前线程 */
    return (int)syscall(__NR_sched_setattr, tid, &a, 0);
}

void disable_rseq_for_thread(void)
{
    /* 参考 disable_rseq_for_thread：关掉 rseq，保证 futex/竞态时序稳定 */
#ifdef SYS_rseq
    syscall(SYS_rseq, 0, 0, 0, 0);
#endif
    if (g_cpu_bound >= 0) cpubind_bind(g_cpu_bound);
}

int futex_op(uint32_t *uaddr, int op, int val, void *timeout, uint32_t *uaddr2, int val3)
{
    /* 参考 futex_op 0x6255ec：六参直通 syscall(SYS_futex, uaddr, op, val, ts, uaddr2, val3) */
    long r = syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
    return (int)r;
}

int open_ashmem_device(void)
{
    if (g.fd_ashmem >= 0) return g.fd_ashmem;
    int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
#ifdef SYS_memfd_create
        fd = (int)syscall(SYS_memfd_create, "ghost", 0);
#endif
    }
    if (fd < 0) return -errno;
    g.fd_ashmem = fd;
    return fd;
}
unsigned g_map_tasks_off = 0;

int is_kptr(uint64_t p)
{
    return p >= 0xffffff8000000000ULL && p <= 0xffffffff00000000ULL;
}