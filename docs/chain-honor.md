# 5.10 / 5.15 链：HONOR（posix timer UAF + AIO/io_uring 喷射）

> 9.146 起 5.10 与 5.15 两支不再复用 legacy EK-CORE 链，而是照
> 「荣耀5系提权」APK 的 `assets/libsysopt.so`（870,920 B，sha256 8dc089d4…13e6）
> 一比一重写。源码：`payload/src/chain_honor.c`（编译期 `-DEXTRACTKIT_CHAIN=1`）。

## 1. 为什么换链

参考实现自报的漏洞编号里，5 系这一段不是 EK-CORE：它整套日志是 `UAF-*` 前缀，
核心对象是 **posix_timers_cache**，喷射面是 **AIO / io_uring / skb / poolhold**，
和工作在 `kmem_cache_alloc` + `mm_page_alloc` 上的 EK-CORE 是两条不同的路。

一句话区别：

| | legacy EK-CORE（6.6/6.12） | HONOR（5.10/5.15） |
|---|---|---|
| 受害对象 | k_itimer（timerfd/timer_create 的 k_itimer 槽） | posix_timers_cache 里的 k_itimer |
| 窗口证据 | `kmem_cache_alloc` 的 ptr 与页 pfn 对页 | slab 的 objects/partial/cpu_slabs 回落 + `UAF-WINDOW` |
| 回收手段 | socketpair 写满 8K 页 + 半页重试 | AIO 提交 / io_uring mmap / skb 灌满 / poolhold 预占 |
| KASLR | `kmem_cache_alloc` 的 call_site 低 21 位投票 | perf_event 泄露 + `UAF-SLIDE` 投票 |
| 收敛 root | fake cred → ksud late-load | `UAF-WRITE` 改 cred → `UAF-LOAD` 载入 msm_perf.ko |

## 2. 命令行（一比一）

参考编排是 `assets/bootflow.sh`，它把下面这串原样喂给 libsysopt.so：

```
chain=1 reap=1 reapmax=2 attempts=4 timers=0 delays=0,100,200,400 reserve=2000
reserverounds=1 settle=0 storm=0 uring=0 spray=20 skb=0 stamp=4000 pinwave=0
tail=0 tries=24 perf=300 poolhold=1500 target=$D/perfprobe target_exit=42
load=$D/$KO loadparams= loadmap=$D/honor.map log=$LOG reservesettle=0 claimms=150
rcuwait=50 sweep=16 trace=0 seearly=1 warmwant=0 sigearly=0
```

ExtractKit 侧由 `ChainPlan.honorArgs(WORK_DIR)` 生成同一串，只把 `$D` 换成
`/data/local/tmp/extract-kit`，`$KO` 换成 `msm_perf.ko`，`$LOG` 换成
`/data/local/tmp/extract-kit/honor.log`。

**这串不能省。** payload 里所有开关默认 0，不给 `attempts=4 reserve=2000 spray=20`
它一个受害者都不起，日志只有 `UAF-BEGIN` 就结束。

## 3. 外部资产与现场生成的符号表

参考实现把利用本体和「加载什么」分开：libsysopt.so 只负责拿到写内核页的能力，
真正收敛 root 靠 `UAF-LOAD` 载入一个 LKM。9.146 把这三份一起打进 assets：

| 文件 | 大小 | 作用 |
|---|---|---|
| `payload/honor/perfprobe` | 702,304 B | `target=` 指定的受害者进程（UAF 的 de_thread 目标），`target_exit=42` |
| `payload/honor/msm_perf.ko` | 6,975,344 B | `load=` 载入的模块，载完即 uid0 持存 |
| ~~`payload/honor/perf.tbl`~~ | — | **9.159 起不再打包**：改由 `HonorMap` 按本机标定现场生成 `honor.map` |

部署由 `ExtractEngine.deployAux(ChainPlan.HONOR_ASSETS)` 完成：读 assets 现算 sha256，
与设备上比对，一致就跳过（省掉每次 6.9MB 的推送）。

### 3.1 为什么我们自己发表（9.159）

参考包的 `perf.tbl` 是它从自己那颗 `5.10.236-android12-9-g4b262e5255ed` 上
导出的 kallsyms 快照——258 行里还混着 `sprintf` / `strchrnul` / `strcpy` /
`strrchr` 这类与链无关的填充，参考脚本硬校验「正好 258 行」只是为了确认
文件没被换过。把**别人内核的地址**装进 APK，等于换一台机器就按错地址
写内核内存。

所以 9.159 起表由 `HonorMap.render(syms, kernel)` 现场生成，格式是我们的：

```
# extractkit-map v1
# kernel=6.6.118-android15-…
# nsyms=9
init_task 0xffffffc00a81bf80
init_cred 0xffffffc00a830c18
selinux_state 0xffffffc00ae84b38
…（HonorMap.NAMES 共 13 个，本机查不到的写 0x0）
```

`ExtractEngine.deployHonorMap()` 用 `ConfigGen.profileFor(本机内核)` 的符号表
渲染成 `$WORK_DIR/honor.map` 推过去（不设执行位）。payload 侧
`honor_load_map()` 解析这份表，`honor_ic()` / `honor_se()` 查表取
`init_cred` / `selinux_state`；值为 0 表示本机没这个符号，回落编译期常量
或 offsets-only，**绝不按猜测地址写**。

## 4. 阶段与日志判据

```
UAF-LOG path=… fd=…           日志落盘
UAF-BEGIN attempts=4 …        参数回显
UAF-SETTLE                   沉降
UAF-CAPS / UAF-STATE          capget / selinux 状态
UAF-ATTEMPT n delay=…        第 n 次尝试（受害者起来）
UAF-TIMER-CREATE-FAIL        timer 没建起来（这条出现即本轮必废）
UAF-HOLD / UAF-REAP / UAF-REAPED   窗口保持与收割
UAF-WINDOW / UAF-WIND-DONE   窗口证据（本次的核心判据）
UAF-STORM / UAF-STORM-STEP   喷射风暴
UAF-WRITE page=… pfn=…       往目标页写 fake cred
UAF-WRITE-HIT                写成功
UAF-READY                    凭据就位
UAF-CHAIN T=… W=… realcred=… cred=… enforce=…   链终局
UAF-LOAD map=… syms=… slide=…  载入 msm_perf.ko
UAF-CHAIN DONE load=… uid=… euid=… gid=… caps=…  成功
UAF-CHAIN FAILED step=… round=…               失败（带停在哪个阶段）
```

判定：**只认 `UAF-CHAIN DONE` 且 uid=0**，或者载入后 `su -c id` 出 uid=0。
`UAF-WRITE` 只说明写了，不说明写对了 —— 和 legacy 的 `[+] plant` 一样不算证据。

## 5. 与参考实现的对应关系（可审计）

`tools/check-parity.py` 把参考二进制的可观测面抽出来与我们的产物逐项比对：

```
$ python tools/check-parity.py --refdir ../refdata
[honor] 5.10 coverage=100.0% tags=88 opt=11 key=157
[honor] 5.15 coverage=100.0% tags=88 opt=11 key=157
```

- `tags`：所有 `UAF-*` 标记，一个都不能少（少一个就是那条分支被优化器删了或被漏写）；
- `key`：参考实现接受的 157 个 `k=v` 键名，我们的解析必须都认；
- `opt`：`--` 开头的长选项。

参考实现里 `key=` 是 `sscanf` 紧邻形式，我们改成 `strcmp` 表驱动，所以判据是
「键名以独立 token 出现」，不是「`key=` 相邻」。

## 6. 已知限制

- 参考实现跑在 5.10.236（荣耀 X50 / ALI-AN00）。我们两支都带族闸门
  （`-DEXPECT_FAMILY="5.10."` / `"5.15."`），跑错内核返回 3。
- `msm_perf.ko` 是按 5.10.236 编的模块，别的 build 上 `UAF-LOAD` 会失败；
  这种情况下链会停在 `UAF-CHAIN T=…` 之后、打印 `UAF-LOAD` 失败，不会 panic。
- `perf.tbl` 的 258 行是参考脚本的硬约束，我们照抄；改成全量 `perf_full.tbl`（5,920,666 B）
  没有被采用，因为那会改变参考实现的行为。

## 7. 共享匿名区与叶子函数（9.162 移植批次一）

参考实现 `libsysopt.so` 的 main 在 0x4078b0 建一块 **32 KiB MAP_SHARED|MAP_ANONYMOUS**
的匿名区（`.bss` 里的 `sh`），fork 出来的工作线程/子进程共享它；所有跨进程状态
（凭据、窗口轮次、区段位图）都走这块内存。9.162 起 `payload/src/chain_honor.c`
按反汇编把这套结构照搬过来（`chain_sh_map()` + `SH_OFF_*` 偏移宏）。

| 偏移 | 类型 | 语义 | 参考实现坐标 |
| --- | --- | --- | --- |
| +0x0c | u32 | barrier（sibling 自旋等待的代数） | sibling_fn 0x402728 |
| +0x10 | u64 | 窗口起始 now_us | sibling_fn |
| +0x18 | int | 窗口时长 us | sibling_fn |
| +0x38/+0x40/+0x48 | u32 | uid / euid / gid | chain_creds 0x402640 |
| +0x50 | u64 | caps | chain_creds |
| +0x58 | u64 | real_uid | chain_real_uid 0x40086c |
| +0x60 | u32 | seqlock 代数 | chain_real_uid / chain_creds |
| +0x64/+0x68 | u32 | cred 请求 / 应答 | chain_creds |
| +0x6c/+0x70 | u32 | 窗口轮次 / 应答轮次 | chain_window 0x40258c |
| +0x88 | u32 | 窗口状态（工作线程回写） | chain_window |
| +0x8c | 8192 B | 区段位图 | chain_read_self 0x402458 |

同一批次 1:1 移植的叶子函数（行为按反汇编逐条对齐，日志格式逐字相同）：

- `chain_bm64(x)` @0x400838 —— 位图第 x 项起 7 字节大端（56 位）；
- `chain_real_uid()` @0x40086c —— 200 次 seqlock 读 `sh+0x58`；
- `chain_caps()` @0x400bb4 —— `capget`（版本 0x20080522），返回
  `cap[0].effective | cap[1].effective<<32`；
- `chain_enforce()` @0x400980 / `chain_selinux_ready()` @0x400928 —— 读
  `/sys/fs/selinux/enforce` 与 `/proc/self/attr/current`，**替换掉 9.159 之前把
  `SELINUX_STATE_STATIC` 当假值打日志的做法**；
- `chain_window()` @0x40258c —— `++sh+0x6c`，500×10ms 等 `sh+0x70` 回写；
- `chain_aim(step,pc,left)` @0x401934 —— 记 pc/left 并打
  `UAF-SHOT step=%s round=%d pc=%#llx left=%#llx T=%#llx`；
- `chain_creds(...)` @0x402640 —— `sh+0x64` 发请求、500×1ms 等应答，再 seqlock 读四元组；
- `chain_decode_ranges(src,len,out,outbits)` @0x4022f8 —— `0-15,32,64-127` 形式转位图。

仍未移植（批次二）：`sibling_fn` 的 barrier/自旋 + `tgkill` 打击、
`chain_read_self`（依赖 main 里打开的 sysctl fd）、`chain_round` 的
spray/reap 编排。

> 判据不变：仍然只认 `UAF-CHAIN DONE` 且 uid=0。
