# 6.18 链：K618（key-ptr · perf 泄露 task + AIO/pipe/stream 三档回收）

> 9.146 起 6.18 支照 ma.apk 的 `assets/EK-CORE-61821/exploit-android-key-ptr`
> （73,744 B，sha256 cc47bf59…a544）一比一重写。
> 源码：`payload/src/chain_k618.c`（编译期 `-DEXTRACTKIT_CHAIN=3`）。

## 1. 与 legacy EK-CORE 的区别

6.18.21 是 android17 一代，参考实现与 6.6/6.12 的 legacy 链结构相同（同为 EK-CORE），
但**标定手段与回收策略换了代**：

| | legacy EK-CORE（6.6/6.12） | K618（6.18） |
|---|---|---|
| slide | call_site 低 21 位投票 | timer 记录投票（`[slide-cal] verified … votes=`）+ 外部 slide 兜底 |
| task/cred 泄露 | slab 直读 | perf_event_open 采样 x0/x1（`[task-perf] sample id=… x0=… x1=…`） |
| 页回收 | socketpair 8K + 半页 | stream（8K→4K 半页）→ pipe → AIO 三档，逐档回退 |
| 页未命中 | 跳过写入 | `PC98260_ABORT_PAGE_MISS` 硬中止（exit 80），绝不硬写 |
| 收尾 | rootd + ksud | 进程内 `finit_module`（`[ksu] in-process finit_module rc=…`）后 rootd |

参考实现自己在 `target.sh` 里写明 6.18 的三个硬约束：
`CHAIN_EK-CORE_REAL_CRED=1`（必须走 real_cred，不能只改 cred）、
`CHAIN_EK-CORE_ABORT_PAGE_MISS=1`（页未命中必须硬中止）、
`CHAIN_EK-CORE_WAIT_CAP=25`（等页上限 25 秒）。这三条我们照抄为默认值。

## 2. 命令行与环境开关

长选项：`--check`（只跑自检 JSON 后退出）、`--quick`、`--slide <hex>`、
`--no-selftest`、`--no-real-cred`、`--exec-ok`。
`--check` 打一行 JSON：`{"uname":…,"build_target":"6.18.21-android17","page_size":…,
"cpus":…,"mem_avail_kb":…,"tracefs":…,"trigger":…,"event":…,"selinux_enforce":…,"ksu":…}`
—— 这条 JSON 是给外部脚本判环境用的，**保留**（它不属于被去掉的「只读自检」按钮）。

环境开关（参考实现 22 个，全部实现）：`PC98260_MULTI_VICTIM`、`PC98260_TIMERS`、
`PC98260_MAX_ATTEMPTS`、`PC98260_ALLOW_SINGLE_RETRY`、`PC98260_BUDGET_S`、
`PC98260_STREAM_BUF_KB`、`PC98260_WAIT_CAP_S`、`PC98260_STREAM_FRAGS`、
`PC98260_RECLAIM_CHURN`、`PC98260_ENABLE_FALLBACK`、`PC98260_NO_FALLBACK`、
`PC98260_ABORT_ON_PAGE_MISS`、`PC98260_CAP_TRIES`、`PC98260_SELINUX_TRY`、
`PC98260_KSU`、`PC98260_ROOTD`、`PC98260_ROOT_SOCK`、`PC98260_FINIT_KO`、
`PC98260_FINIT_PARAMS`、`PC98260_FINIT_PARAMS_FILE`、`PC98260_FINIT_READY`、
`PC98260_FINIT_EXIT`。

## 3. 主链顺序（`k618_main`）

```
写 ksu 脚本 → slab baseline([slabinfo] baseline=…)
→ [selinux] enforce=…；enforcing 则先做 pre-perf 改 selinux_state（最多 4 轮）
→ k618_do_uaf（多受害者模式或单受害者循环，最多 4 次）
     one_uaf：slab → fork 受害者 → enable kmem_cache_alloc →
              collect_nth(1024) → 少于 1499 条即 [uaf] too few timers →
              pick_clean_timer_slab → disable/enable 事件 → wait_zombie →
              slab 回落 → reclaim_stream
                  [stream] page_freed → [half] 半页校验 → frag 写页 → [stream] hit pfn
                  miss 时 → prepare_catch / reclaim_pipe → AIO（除非 NO_FALLBACK）
                  全 miss → 按 ABORT_ON_PAGE_MISS 决定 exit(80) 或重试
              → [t] ready/timers/collect/reclaim/reap/total 计时 → 收割受害者
→ real_cred 时再起受害者做 [cred] takeover 与 perf 泄露 task（失败 [task] task/real-cred leak failed）
→ cap_stage：[ksu] cap plant i/8 CapEff=… bit16=1（CapEff 第 20 位 = CAP_SYS_MODULE）
→ finit_module 载入 KO（失败 [ksu] FAIL=cap_sys_module_not_achieved; finit blocked）
→ [chain] DONE load=… uid=… euid=… gid=… caps=…
→ --exec-ok 则退出，否则 [rootd] listening at … 常驻
```

失败路径全部带 `[chain] FAIL step=<uaf_618|cap|budget|...>`，报告里按 step 定位。

## 4. 判据

- 成功：`[chain] DONE` 且 `uid=0`；或载入后 rootd 通道可用。
- `[ksu] cap plant` 只是把 CapEff 打出来，**不是**拿到 CAP_SYS_MODULE。
- `[stream] hit pfn` 只说明页回收到了，写没写对还要看 `[tile] CRED` 之后的凭据。

## 5. 可审计性

```
$ python tools/check-parity.py --refdir ../refdata
[k618] 6.18 coverage=100.0% tags=45 env=22 opt=20
```

参考二进制的 33 个 tag、22 个环境开关、20 个长选项全部覆盖；
`PC98260_FINIT__` / `PC98260_FINIT_EXIT__` / `PC98260_SHUTDOWN__` 是它字符串拼接的残留，不计。

## 9.181：main 0x9d24 的 [selftest]

if (g_no_selftest || g_selftest_cred) { ok 串; g_plant_cred = 1; return 0; }
no cred alloc 串 -> k618_cleanup_mem() -> return -1，主流程 rc = 8。
样本来源：k618_cred_stage 在 uid==0 && euid==0 分支 g_selftest_cred++；
位置按参考排在 perf 泄漏之后、PC98260_KSU 处理之前。

## 9.183 — 步骤编排补齐（ref_618_keyptr / ref_61_brm_plant）

6.18：`_miss618.py` 结果显示 107 条 C 字面量全部逐字存在于参考二进制；步骤侧补上 `buffer_size_kb=4096` 写入、`[multi] trace start failed i=%d`、`[uaf] victim fork failed errno=%d`、`[uaf] timer trace init failed errno=%d`、`[slab] using clean timer idx=%d victim=%#lx`、`[triple] single-base pass base=%d (no clean slab)`、`[uaf] pipe reclaim hit`、`[uaf] reap was not SIGKILL`，并新增 `PC98260_ENABLE_FALLBACK`。产物 458,992 B sha256=`8adfd8e8…`。

6.1：`_miss601.py` 显示修前 5 条 tag 措辞与参考不符（4 条多了尾部 `\n`，1 条 `[alloc]` 参考里不存在），逐条改回/删除后，我方 6.1 已无任何字面量缺失；参考 65 个 tag 的基名全部有对应实现（唯一例外 `[]u8` 是拼接碎片）。产物 432,496 B sha256=`714a94e7…`。

自动核验：`tools/check-parity.py` honor 5.10/5.15 100%(tags=88) · brm 6.1 100%(tags=28) · k618 6.18 100%(tags=44)；`tools/check-fam.py` 六支 index/SHA256SUMS/PER_FAMILY 三方一致。

### 9.183 补记：honor 一处措辞 + 最终产物

`tools/check-honor-parity.py` 在 162 条格式串里报出 1 条 missing：`chain_honor.c:768` 打的是 `UAF-LOAD map %s bytes=%lld patched=%d/%d`，参考 `ref_510_libsysopt` 0x7e080 处原文是 `UAF-LOAD %s bytes=%lld patched=%d/%d`（没有 `map `）。已改回原文，修后 honor = 162 串 / 159 在参考 / 3 白名单 / **0 missing**。5.10/5.15 产物因此变为 472,816 B（sha256 `5fa5ef08…` / `5f6e5e61…`）。

最终 APK：`D:\deepseek work\ExtractKit-9.183-parityall.apk` 6,745,254 B sha256=`292301708f83c12271d2c0f58ae51ca80edb3da5ea83b04696f8a267cc85abed`；单测 137 pass / 0 fail / 0 err / 4 skipped / 26 suites；六支 fam 与仓库逐字节一致；dex 9.183×2、honor.map×7、perf.tbl×0。
