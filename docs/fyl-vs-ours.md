# 白鹿（com.FYLROOT 1.0.3）与 ExtractKit 的 EK-CORE 链路对比

素材：`C:\Users\Admin\Downloads\base.apk`、`fyl-privilege-20261109-220403.log.txt`、
`assets/ic-lpe.sh`(21,594 B)、`ic-ksu.sh`(11,449 B)、`ic-core.sh`(1,877 B)、`ic-cleanup.sh`(3,376 B)。

## 一句话结论

**同一 CVE、同一原语（POSIX CPU timer UAF → 8 字节零写），但工程路线相反：**

- 白鹿：**先有符号表**（boot.img 离线算好，编译期或 `ic-syms.txt` 喂进去），运行期**不用 tracefs 标定 base**，
  只把 tracefs 当"页释放预言机"的可选增强。
- 我们：**先有 tracefs**（`events/kmem/rss_stat/trigger` + `trace_pipe_raw` 二进制记录），
  运行期用 `call_site` 低 21 位投票标定 base，符号常量来自 `device.cfg`。

两条路的失败面完全不同：他们怕"表不对/没有表"，我们怕"tracefs 策略被拒"。

## 白鹿的 5 段式 launcher（`ic-lpe.sh`）

| 阶段 | 动作 | 依赖 |
|---|---|---|
| `[0/5]` | 零写 `panic_on_warn`（失败也继续） | 符号表给出地址；表里没有就退回 `/proc/kallsyms` |
| `[1/5]` | `ic-timer slide`：从 **`sched_blocked_reason`** 恢复 KASLR，顺带打印 `FUNCS / SELINUX_STATE / INIT_USER_NS / SIG_ENFORCE / MODULE_NOTIFY / PANIC_ON_WARN` | **不需要 tracefs** |
| `[2/5]` | 若 `vr.ko` 在 `/proc/modules`：零写 `__tracepoint_sys_exit->funcs`（"disarm"），防止 fake cred 进程第一次 syscall 就死 | 8 字节零写 |
| `[3/5]` | 原生策略时零写 **`selinux_state-7`**（只清 `enforcing` 一个字节），随后校验 `getenforce`=Permissive **且** `policyvers` 仍可读（证明 `initialized` 没被清） | 8 字节零写 |
| `[4/5]` | 零写 `sig_enforce`、截断 `module_notify_list` 头部（`MODNF+40`），为未签名 `kernelsu.ko` 开绿灯 | 8 字节零写 |
| `[5/5]` | `ic-timer` 主链：`IC_SPRAY=mcast`、`IC_REAL_INIT_USER_NS=<init_user_ns>`、`IC_SCAN_CTXMAP=u:r:ksu:s0`，成功后 drop proof 再 `ksu late-load` | 符号表 + 8 字节零写 |

零写原语：**AF_UNIX 8KB 零写**（`IC_SPRAY=unixstr`、`IC_UNXSTR_MSGS=8192`）。
喷溅：`mcast`（组播 socket）放 fake cred；`IC_PAD_POOL=4200`（=135×31+15）个 unix socket 当 slab padding，
`IC_PAD_KEEP=4185`；`IC_SKBF_MIN=8` 只丢 8 个排队 order-2 报文（注释说全丢 32320 个会把 slab 淹掉）。

## 我们的链路（`payload/src/ek-core-uid0.c`）

| 阶段 | 动作 |
|---|---|
| base | `wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:<name>")` 打开 kmem 事件，读 `per_cpu/*/trace_pipe_raw`，按 `_RET_IP_ & 0x1fffff` 对 3 个 call site 投票定 base |
| reclaim | socket 喷溅抢回被释放的 `k_itimer` 页 + slab padding |
| write | 通过 timer UAF 做 8 字节零写：`selinux_state.enforcing=0`、`panic_on_warn=0`、子进程 cred（uid/gid/caps） |
| handoff | 每次替换 `/data/adb/ksud`（原子 `cp→.new→mv`），`late-load --kmi <推> --allow-shell --package-name <所选管理器>` |
| 收尾 | 进程 `for(;;) pause()` 驻留，清理只能重启 |

## 逐项差异

| # | 维度 | 白鹿 | 我们 | 影响 |
|---|---|---|---|---|
| 1 | KASLR | `sched_blocked_reason` 采样 + 投票（`MIN_ANCHORS/MIN_VOTES`） | tracefs 记录里 `call_site` 低 21 位投票 | 他们不依赖 tracefs；我们必须在 `trigger` 可写时才能起链 |
| 2 | 内核常量 | boot.img 离线算表，**编译期钉死**；表不对拒绝执行 | 6 条内置 profile + 运行期标定 + `device.cfg` | 他们加机型=发新版；我们加机型=选 boot.img 即可 |
| 3 | 零写载体 | AF_UNIX 8K 零写（通用"任意地址清零"） | POSIX timer UAF 的 8 字节固定偏移零写 | 他们能顺手清 `sig_enforce`/`module_notify`；我们只能写 cfg 里列出的 7 个符号 |
| 4 | 假 cred | `IC_REAL_INIT_USER_NS` 让 caps 记在 init_user_ns（late-load 要 `CAP_SYS_MODULE`），并扫 ctxmap 找 `u:r:ksu:s0` | 直接改真 cred 的 uid/gid/caps，走 `u:r:ksu:s0` | 我们要保证 caps 起点算对（`credSecurity-0x50`），他们显式给了 user_ns 指针 |
| 5 | SELinux | 只清 `enforcing`（`state-7`），并校验 `policyvers` 证明 `initialized` 还在 | 写 `selinux_state.enforcing=0` | 他们的完整性校验值得我们抄（写错会 reboot） |
| 6 | 模块加载防御 | 额外清 `sig_enforce` + 截断 `module_notify_list`；检测 vivo 的 `hooks_defend.ko` | 只做 `late-load`，遇到强签策略会失败 | **这是我们缺的能力** |
| 7 | vendored disarm | 有 `vr.ko` 时清 `__tracepoint_sys_exit->funcs` | 无 | vivo 专有，我们不需要，但"先 disarm 再放行"的思路可参考 |
| 8 | late-load | 四级 fallback（`--kmi+--package` → 去 kmi → 去 package → 裸跑）+ `safe_mode` 先 disable 全部模块 + `cleanup.sh` | 单次 `late-load --package-name`；每次替换 ksud | 他们的容错更强，我们靠"包名送达"解决另一个问题 |
| 9 | 运行前置 | 硬门槛 6.1.x + vivo/iQOO，uptime>120s 提示重启 | 按 profile/标定决定，不锁机型 | 他们用门槛换稳定性；我们放开但要求素材 |
| 10 | 成功判定 | 看到 `[zero] target=` / `LPE-PROOF` 才算 | `su -c id` 含 `uid=0` 才算（7.15 起） | 我们更严；他们日志里 `[kit] 检测到 kernelsu 已加载 → 提权成功` 就是反例 |

## 他们在我们这台机器上误判的原因（证据）

`ic-lpe.sh` 注释自己写着：

> They enable the events through `events/kmem/rss_stat/trigger` because the per-event enable files are root-only.

也就是说他们**知道**正确接口是 `trigger`，但自检脚本只探了 `events/kmem/*/enable`（root-only），
于是打出 `[pre] 本设备不支持` 并 `exit 4`。同一台机器上我们走 `trigger` 起链成功（多次 `uid=0`）。
结论：他们的 pre-flight 与主链用的是两套判断，pre-flight 偏保守，属实现缺陷而非能力缺失。

## 可采纳清单（按性价比排序）

1. **模块加载防御**（第 6 项）：`sig_enforce` / `module_notify_list` 两个符号做成 cfg 的可选字段（缺省 0=不写），
   遇到强签设备时先清再 `late-load`。需要扩 `device.cfg` 布局（v3）并保持向后兼容。
2. **`late-load` 四级 fallback + `rc` 后校验 `/proc/modules`**：纯脚本改动，零风险。
3. **`safe_mode`**：late-load 前 disable 所有模块，成功后让用户手动恢复；避免坏模块导致开不了机。
4. **`cleanup` 入口**：清 `ksu/ksud/modules/modules_update/metamodule/kpm`，附"需重启"提示。
5. **SELinux 写后校验**：写完 `enforcing=0` 立刻读 `getenforce` 与 `policyvers`，异常就中止而不是继续。
6. **fresh-boot 提示**：uptime > 120 s 时在横幅提示"刚重启后成功率最高"。
7. （研究项）`sched_blocked_reason` 泄漏：可作为 `trigger` 被拒时的 base 兜底；需要逆向 `ic-timer` 的采样逻辑。

不采纳：每机型一个 `.so`（`libic98260.so` / `libic98260_iqoo12.so` / `libghostlock_pd*.so`）——体积与维护成本过高；
"模块已加载=成功"判定。

## 追加逆向（2026-11-09 第二轮）：它到底靠什么拿地址

对 `libic98260.so`（2,382,960 B，ic-timer 主程序）做字符串核对，推翻了上一轮的两个猜测：

### 1) 它不是"不碰 tracefs"，而是换了一个事件

```
/sys/kernel/tracing/events/sched/sched_blocked_reason/enable      ← slide 的真正入口
```

`slide` 走 **sched 子系统的事件**（`sched_blocked_reason`），不是 kmem。也就是说：
它同样依赖 tracefs 的事件开关，只是请求的类型不同；能不能用取决于目标机 sepolicy 对
`sched/*/enable` 的放行，与内核主版本无关。vivo 6.1.145 放行 → 它能跑；我们这台若
`sched/*/enable` 同样被拒，它的 slide 一样过不去（它自己的日志里 `[pre] kmem 事件开关不可写`
是另一道门，先被拦下了）。

### 2) 它确实读 kallsyms，但不是唯一来源，也绝不"不看版本"

```
[ksym] /proc/kallsyms unavailable
[syms] kallsyms: %u symbols, _text=%#llx _end=%#llx
[syms] ambiguous kallsyms layouts; refusing
[syms] no valid kallsyms address table
[syms] no kallsyms token table found
/data/local/tmp/ic-syms.txt
[-] fake path needs per-build addresses; push a syms table (ic-syms.txt) or run the shell path
```

地址来源有三层：`/proc/kallsyms`（多数 ROM 对 shell 关闭）→ 外部 `ic-syms.txt` →
**编译期内嵌表（按 release 精确匹配，5 条 6.1.145）**。第三层就是它"只看 6.1"的原因：
表里没有的 build 直接 `refusing`，宁可不跑。

### 3) 一套原语，多种用法（不是多个漏洞）

| 类别 | 具体 |
|---|---|
| 零写载体 | ① AF_UNIX 8KB 零写（`IC_SPRAY=unixstr`、`IC_UNXSTR_MSGS=8192`）② 主链 `IC_SPRAY=mcast` |
| 零写目标 | `panic_on_warn`、`__tracepoint_sys_exit->funcs`（vr.ko disarm）、`selinux_state-7`、`sig_enforce`、`module_notify_list` 头、fake cred 字段 |
| 可选增强 | `pfn oracle`：用 `mm_page_free` / `mm_page_alloc` 的 kmem 记录判断受害页何时释放、是否被自己喷到（`IC_PFN_ORACLE=1`，两个探针都通过才开） |
| 约束 | 每次尝试成功后**驻留不退出**（page 里有 stale timer node），必须重启清理 |

结论：**一个 bug（POSIX timer UAF）× 一个通用零写 × N 个目标**。它把"清 `sig_enforce` / 截断
`module_notify_list`"这类动作也塞进同一条链，所以看起来像"不止一种"，实际是同一原语的扩展用途。

### 4) 我们为什么只在 6.6 成功

我们的 base 来自 kmem 记录投票，前提是两条：`events/kmem/rss_stat/trigger` 可写 + **cfg 里的
ev id 与 call site 与这台机器匹配**。6.6 那台两条都满足（内置 profile 逐字段核对过）；
6.1 那几台（BVL `g84ffa64b`、AMG `g2646292`）在 base 阶段就 `candidates=0`，是"表不对"，
不是"6.1 不行"。

它能在 6.1 跑通，是因为它有那台机器的表且那台机器的 sched 事件可写；两件事我们都缺一。

### 5) 由此得到的可移植性改进（新的第 0 优先级）

若能把 **`sched_blocked_reason` 泄漏** 接进来，我们就不必依赖 kmem 记录去反推 base：
拿到 slide 后 `base = page_offset + slide`，常量仍由 profile 提供。这样"没有 kmem 权限但有
sched 权限"的机型也能跑。需要先在本机实测 `sched/*/enable` 是否可写，再决定是否实现。
