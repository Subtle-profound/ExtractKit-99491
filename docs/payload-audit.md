# payload 审计与交付线（ExtractKit）

> **本文件在 9.190 被误截断过（见文末「事故 B」）。9.190 节完整保留；9.141–9.189 各节按 APK 产物、验收脚本、`payload/baseline/` 与提交时的实测数字重建；9.104–9.140 的细节原文已丢，只保留能从产物确认的事实。凡不确定处一律标注「原文已丢」，不补写猜测。**

事实来源（可复核）：
- 产物：`D:\deepseek work\ExtractKit-<ver>-*.apk`（每个文件即当时交付，mtime 与版本线一致）
- 验收脚本：`D:\deepseek work\chk9142.py` … `chk9190.py`（每个版本一支，内含当轮的比对判据）
- 基线：`extract-kit/payload/baseline/{9104,9105,9188}/`（钉死用的字节）
- 构建器：`extract-kit/tools/build_fam.py`（`PINNED_9104/9105/9188` 的注释就是当时的理由）
- 检查器：`tools/check-parity.py`、`tools/check-honor-parity.py`、`tools/check-fam.py`

## 六支族的固定关系（全程未变）
| 族 | 源文件 | 链宏 | 需要的内核地址 |
| --- | --- | --- | --- |
| 5.10 / 5.15 | `payload/src/chain_honor.c`（被主源 include） | CHAIN_HONOR | 0 个编译期常量，2 个名字走 honor.map（init_cred / selinux_state） |
| 6.1 | `payload/src/chain_brm.c` | CHAIN_BRM | 2 个（TIMER_SITE_LOW21、SELINUX_STATE_STATIC） |
| 6.6 / 6.12 | `payload/src/chain_legacy.c`（`payload/fam-src/6.6.c` 为参照） | CHAIN_LEGACY | 8 个绝对地址 + 1 个 KASLR slide（`device_config.h:56-64`，运行期可被 device.cfg 覆盖） |
| 6.18 | `payload/src/chain_k618.c` | CHAIN_K618 | 1 个（static_timer_site），其余是结构偏移 |

## 版本线（9.141 → 9.190）
| 版本 | APK | 字节 | 本轮主题 |
| --- | --- | --- | --- |
| 9.141 | ExtractKit-9.141-base9104.apk | 6,592,644 | 回到 9.104 基线 |
| 9.142 | ExtractKit-9.142-census.apk | 6,645,488 | 步骤普查 |
| 9.143 | ExtractKit-9.143.apk | 6,645,488 | 普查清理 |
| 9.144 | ExtractKit-9.144.apk | 6,693,544 | — |
| 9.145 | ExtractKit-9.145.apk | 6,695,378 | — |
| 9.146 | ExtractKit-9.146.apk | 8,645,911 | 体积跳变（符号表/资源） |
| 9.147 | ExtractKit-9.147-trace.apk | 8,649,591 | trace 输出 |
| 9.148 | ExtractKit-9.148-claim.apk | 8,654,359 | 结果声明 |
| 9.149 | ExtractKit-9.149-hb.apk | 8,657,299 | 心跳 |
| 9.150 | ExtractKit-9.150-104.apk | 8,656,615 | 回 9.104 流程 |
| 9.151 | ExtractKit-9.151-104flow.apk | 8,654,223 | 9.104 流程对齐 |
| 9.152 | ExtractKit-9.152-zeroflow.apk | 8,654,203 | zeroflow |
| 9.153 | ExtractKit-9.153-noperm.apk | 8,654,895 | 去权限前置 |
| 9.154 | ExtractKit-9.154-104sem.apk | 8,650,179 | 9.104 语义 |
| 9.155 | ExtractKit-9.155-raw104.apk | 8,656,615 | 原始 9.104 |
| 9.156 | ExtractKit-9.156-nopre.apk | 8,656,615 | 去预热 |
| 9.157 | ExtractKit-9.157-prewarm.apk | 8,656,615 | 预热 |
| 9.158 | ExtractKit-9.158-branch.apk | 8,585,103 | 分支骨架 |
| 9.159 | ExtractKit-9.159-map.apk | 8,583,348 | honor.map |
| 9.160 | ExtractKit-9.160-load.apk | 8,584,592 | 加载路径 |
| 9.161 | ExtractKit-9.161-kallsyms.apk | 8,584,588 | kallsyms 解析 |
| 9.162 | ExtractKit-9.162-sh.apk | 8,585,620 | 脚本下发 |
| 9.163 | ExtractKit-9.163-parity.apk | 8,585,492 | 串一致性 |
| 9.164 | ExtractKit-9.164-bugfix.apk | 8,585,516 | 缺陷修正 |
| 9.165 | ExtractKit-9.165-victim.apk | 8,585,132 | victim 线程 |
| 9.166 | ExtractKit-9.166-attempt.apk | 8,586,736 | attempt |
| 9.167 | ExtractKit-9.167-reap.apk | 8,587,464 | reap_phase |
| 9.168 | ExtractKit-9.168-round.apk | 8,588,852 | chain_round |
| 9.169 | ExtractKit-9.169-aio.apk | 8,590,856 | AIO 喷 |
| 9.170 | ExtractKit-9.170-skb.apk | 8,591,436 | skb 喷 |
| 9.171 | ExtractKit-9.171-pairs.apk | 8,591,836 | skb 配对 |
| 9.172 | ExtractKit-9.172-pool.apk | 8,597,788 | 池守卫 |
| 9.173 | ExtractKit-9.173-pin.apk | 8,599,040 | pin_cpu |
| 9.174 | ExtractKit-9.174-b3b4.apk | 8,601,384 | b3/b4 槽位 |
| 9.175 | ExtractKit-9.175-pool.apk | 8,601,980 | 池回收 |
| 9.176 | ExtractKit-9.176-modsyms.apk | 8,511,140 | 模块符号 |
| 9.177 | ExtractKit-9.177-ksud.apk | 6,738,782 | msm_perf.ko 下线，改 ksud late-load |
| 9.178 | ExtractKit-9.178-parity.apk | 6,736,986 | 串 1:1 修完（133 串 / 130 参考 / 3 白名单） |
| 9.179 | ExtractKit-9.179-loadmap.apk | 6,736,914 | loadmap |
| 9.180 | ExtractKit-9.180-honormap2.apk | 6,736,914 | honor.map 14→2 |
| 9.181 | ExtractKit-9.181-parity100.apk | 6,744,974 | honor tag 100% |
| 9.182 | ExtractKit-9.182-builtincfg.apk | 6,744,974 | 内置 device.cfg |
| 9.183 | ExtractKit-9.183-parityall.apk | 6,745,254 | 全支 parity |
| 9.184 | ExtractKit-9.184-no612.apk | 6,745,254 | 摘掉 6.12 |
| 9.185 | ExtractKit-9.185-612only.apk | 6,755,234 | 只改 6.12（本轮主源被 read 截断） |
| 9.186 | ExtractKit-9.186-slide.apk | 6,755,122 | `--slide` / `.yt-slide` |
| 9.187 | ExtractKit-9.187-nocache.apk | 6,754,966 | 去缓存 |
| 9.188 | ExtractKit-9.188-brm-static.apk | 6,755,758 | 6.1 静态化 |
| 9.189 | ExtractKit-9.189-612from105.apk | 6,746,174 | 6.12 换回 9.105 二进制 |
| 9.190 | ExtractKit-9.190-612src.apk | 6,755,606 | 6.12 解钉回主源 + 内置表降序 |

## 9.188 · 6.1 静态化（五支钉死起点）

- 6.1 支把 selinux 阶段维持 log-only（与参考 6.1 一致），真正写 cred 只走 `brm_cred_stage`，它依赖 EK-CALIB 算出的 page_offset。
- 6.1 产物 434,192 B sha256 `9cb0d29b…`（含 `device.cfg` / `EXTRACTKIT_SLIDE` / `PC98260_PFNBASE` / `[cfg] TIMER=`）。
- 校验：`check-fam` 六支一致；`check-parity` honor 100% / brm 100% tags=28 / k618 100%；honor 162 串 0 missing。
- APK `D:\deepseek work\ExtractKit-9.188-brm-static.apk` 6,755,758 B，单测 fail=0 err=0。
- 9.189 起把这一版的五支（5.10 / 5.15 / 6.1 / 6.6 / 6.18）存进 `payload/baseline/9188/`，用 `PINNED_9188` 钉住，保证「只改一支」时其余不变。

## 9.189 · 6.12 换回 9.105 的二进制（用户 m08510）

用户指令（逐字）：「@ExtractKit-9.105-full.apk 直接替换这个版本的6.12吧」。

### 做法
- 从 `ExtractKit-9.105-full.apk` 取出 `assets/payload/fam/ek-core-uid0-6.12`（478,864 B，sha256 `acb85edd…`），存到 `payload/baseline/9105/ek-core-uid0-6.12`。
- `tools/build_fam.py` 新增 `BASE9105` 与 `PINNED_9105 = {"6.12": …}`：6.12 不再由主源编译（自编那支在 6.12.58-android16-6-g3a7ac1674240 上 `[5/10] plant` 之后打 panic）。
- 其余五支钉回 9.188 的字节（`payload/baseline/9188/`、`PINNED_9188`）。

### 六支产物
| 族 | 字节 | sha256（前 8） | 来源 |
| --- | --- | --- | --- |
| 5.10 | 472,944 | ea4fe089 | 9.188 |
| 5.15 | 472,944 | aeb13511 | 9.188 |
| 6.1 | 434,192 | 9cb0d29b | 9.188 |
| 6.6 | 476,048 | 66be1802 | 9.104 冻结 |
| 6.12 | 478,864 | acb85edd | 9.105（本次替换） |
| 6.18 | 459,120 | 354b7e64 | 9.188 |

6.12 那支的接口是 9.105 时代的样子：只有 `EXTRACTKIT_SLIDE`，没有 9.186 加的 `--slide` / `/data/local/tmp/.yt-slide`，也没有 9.185 加的 `EXTRACTKIT_PAGE_OFFSET`（APK 内实测 `--slide`×0、`.yt-slide`×0、`page_offset`×0、`EXTRACTKIT_SLIDE`×1）。

### 校验
- `tools/check-fam.py` [ok]：六支 index/SHA256SUMS/PER_FAMILY 三方一致。
- `tools/check-parity.py`：honor 5.10/5.15 100%（tags=88）、brm 6.1 100%（tags=28）、k618 6.18 100%（tags=44）。
- `tools/check-honor-parity.py`：162 串 / 159 在参考 / 3 白名单 / 0 missing。
- 单测 138 pass / 0 fail / 0 err / 4 skipped / 26 suites；APK 内六支与仓库逐字节一致；dex `9.189`×2、`9.188`×0、`honor.map`×7、`perf.tbl`×0。

### 事故 A（9.185 期间，主源被截断）
`read` 的 limit 是真截断：`payload/src/ek-core-uid0.c` 一度被截到 4,014 行（main 之前）。用 `extract-kit.bak-9.147` 的同名文件按行对齐拼回（两文件行号偏移 65；当前文件末尾 24 行在备份中唯一命中 4914–4937，缺的 136 行 = 备份 4939–5074），拼回后 5,151 行、可编译。
但拼回的尾部来自 9.147 时点，缺 9.148–9.188 对 main 附近逻辑的若干处改动：串集合与 9.188 产物一致（差集只有 1 条对齐噪声），指令流比对 6.1 少 20 条指令、差 92 行 diff —— 有实打实的逻辑差。因此 9.189 把五支钉在 9.188 字节上，等尾部按反汇编补回后再解钉。

### 产物
- APK `D:\deepseek work\ExtractKit-9.189-612from105.apk` 6,746,174 B sha256 `78f8745d09f35d971e98dd2a494927fb6d6e9778d2ac30eb0e40bcf81a8b123a`，versionCode 379 / versionName "9.189"。
- 验收脚本 `D:\deepseek work\chk9189.py`。


## 9.190 · 6.12 解钉回主源 + 内置表按内核版本降序（用户 m08853）

### 一、6.12 为什么必须解钉（推翻 9.189 的替换）
对照 HAPT 服务器下发的 169 份 profile 和它自己的 `exploit-android-key-ptr` 反汇编（`D:\deepseek work\hapt\61258\`，2,217,624 B，只靠 `.symtab` 的 static 符号 + NDK `llvm-objdump`，Ghidra 打 ELF 直接 provider_unavailable），确认了两件事：

1. 表是对的 —— 服务器 profile 里的 `task_cred` / `credSize` / `credUid` / 各 call site 与 `ConfigGen.kt:645-674` 的内置档案数值完全一致。
2. 流程差一步 —— 对方在 `one_uaf()` 之后有 **real_cred 四趟**：`[real_cred] pass %d/4 -> uid=%u r=%u`，全失败才打 `textbook skipped/failed; cred-only root still works`，然后才交接。

而我方 9.189 发的 6.12 是 `payload/baseline/9105` 的钉死字节（478,864 B，sha256 `acb85edd…`），**该二进制里 real_cred 命中 0 条**。6.12.58 的两个判据源 —— `/proc/<pid>/status` 的 Uid 四段、`access("/data/adb")` —— 走的都是 `task->real_cred`，所以只复制 cred 页永远读不到 uid 0。BRT-AN00 上「`[10/10] 完成` 但 `uid=2000`、`[fake] /data/adb access=denied`、`worker exit=0x100`」就是这么来的，不是偏移错。

主源 `payload/src/ek-core-uid0.c` 早在 9.186 就有双写 + 四趟（`:4902-4920`、`:4965-5017`，`OFF_TASK_CRED >= 0x800` 时同时写 `g_child_task + OFF_TASK_CRED` 与 `- 8`），只是被 pin 挡住了没发出去。

### 二、改动
1. `tools/build_fam.py`：`PINNED_9105 = {}`（6.12 回到主源编译），注释写清依据；`PINNED_9188` 仍钉 5.10/5.15/6.1/6.6/6.18。
2. `payload/src/ek-core-uid0.c`（shell_mode==4 分支，约 `:3948`）加诚实退出：先算 `denied = access("/data/adb", R_OK|X_OK)`，若 `setfsuid(0)` 回旧值非 0 且 denied，打 `[!] fake cred 未生效（fsuid 仍 %ld，/data/adb 打不开），跳过 ksud 交接` 并 `_exit(9)`。这样假 cred 没落地时链路直接判失败，不再拿 10/10 掩盖。
3. `app/src/main/kotlin/com/extractkit/app/ConfigGen.kt`：新增 `kernelRank(release)`（`a.b.c` → `a*1_000_000 + b*1_000 + c`），`PROFILES = (BUILTIN_PROFILES + ServerProfiles.list).sortedWith(compareByDescending{kernelRank} .thenBy{release} .thenBy{name})`。「已适配的内核」页（`GlassSheets.kt:468` 直接按 `PROFILES` 铺）从此按内核版本从高到低排：6.12.58 → 6.6.118 → 6.6.89 → 6.1.157 → 6.1.128 → 5.15.x → 5.10.252。
4. `app/src/test/kotlin/.../ConfigProfileTest.kt` 新增 `builtinProfilesSortedByKernelDescending`：断言首项 rank 等于全表最大值、且相邻项 rank 非递增。

### 三、六支产物
| 族 | 字节 | sha256（前 8） | 来源 |
| --- | --- | --- | --- |
| 5.10 | 472,944 | ea4fe089 | 9.188 钉 |
| 5.15 | 472,944 | aeb13511 | 9.188 钉 |
| 6.1 | 434,192 | 9cb0d29b | 9.188 钉 |
| 6.6 | 476,048 | 66be1802 | 9.104 冻结 |
| 6.12 | 496,528 | ec05ae84 | **主源自编（real_cred×6、pass %d/4×2）** |
| 6.18 | 459,120 | 354b7e64 | 9.188 钉 |

### 四、校验
- `check-fam.py` [ok] 六支三方一致；`check-parity.py` honor 100%(tags=88) / brm 100%(tags=28) / k618 100%(tags=44)；`check-honor-parity.py` 162 串 / 159 参考 / 3 白名单 / 0 missing。
- 单测 139 pass / 0 fail / 0 err / 4 skipped / 26 suites（新增的排序用例 pass）。
- APK 内六支逐字节 == 仓库；dex `9.190`×2、`9.189`×0、`honor.map`×7、`perf.tbl`×0；manifest versionName=9.190（UTF-16 命中 1 次）。

### 五、产物
- APK `D:\deepseek work\ExtractKit-9.190-612src.apk` 6,755,606 B sha256 `e735346a8b23260c9d8275f921056c6e84fa776f695f75e7e3233dbd45ebcd26`，versionCode 380 / versionName "9.190"。
- 验收脚本 `D:\deepseek work\chk9190.py`。

### 六、仍待验证（诚实）
- 6.12.58 上 real_cred 四趟能不能真的把 uid 打到 0，只有真机跑一次才知道；跑完如果仍打不到，`/data/local/tmp/extract-*.log` 里会出现新加的 `[!] fake cred 未生效` 一行，那条就是新的判据。
- 另外 9.189 的 panic 风险没有消失：解钉后回到的是 9.188 时点的主源逻辑，若在 `[5/10] plant` 之后再 panic，说明是 plant 段而非 cred 段的问题，届时按 ref_510/ref_618 的 reclaim 判据再收。

## 事故 B（本轮，docs/payload-audit.md 被我自己截断）

追加 9.190 节时我用了这样一条 Python 单行：

    io.open(p, 'w', encoding='utf-8', newline='\n').write(s + io.open(newdoc, encoding='utf-8').read())

Python 先求值对象表达式 `io.open(p, 'w')` —— 此刻文件已被截成 0 字节 —— 再求值实参，而当时 `newdoc` 文件还没写出来，抛 `FileNotFoundError`，于是原文（约 330 行，9.104–9.189 全部小节）彻底丢失。

善后：9.190 节自身在第一次调用时已写入（3,139 B），完整保留；其余各节按本文件开头的「事实来源」重建；9.104–9.140 的细节标注为「原文已丢」。

**规则（此后硬性遵守）**：追加/拼接文件必须 (1) 先确认追加源已存在，(2) 用 `s = read(p)` 读出全部，(3) 再单独一次 `write(p, s + add)`，三者分行执行，绝不在同一个表达式里同时 open-for-write 和 open-for-read。

## 9.191（事故 A 结案：主源尾部按反汇编补回，六支里五支解钉）

### 一、怎么定位丢的是哪几行
9.185 那次 `read` 截断把 `payload/src/ek-core-uid0.c` 削到 4,014 行，用 `extract-kit.bak-9.147` 按行号偏移 65 拼回 5,151 行，但拼回的尾部缺 9.148–9.188 之间新增的逻辑。定位方法：
1. 用 `D:\deepseek work\_cmp61.py`（python subprocess 列表传参，避免 PowerShell 破坏 `-DEXPECT_FAMILY="6.1."`）按 build_fam 同款 flags 编出临时 6.1 → `D:\deepseek work\_tmp61`。
2. 用 `D:\deepseek work\_diff61b.py` 做指令流比对：`llvm-objdump -d --no-show-raw-insn`，地址归一成 `0xADDR`、符号归一成 `<sym>`，再 `difflib.SequenceMatcher`。结果：**指令数 81,552 vs 81,572，差 20 条，11 个 hunk**。
3. 唯一真逻辑差是 base 在 `0x21c574` 的 15 条指令块（其余 hunk 是寄存器分配/序言搬迁噪声）。

### 二、丢的是什么（两处）
1. `main` 开头 `setvbuf(stdout, NULL, _IONBF, 0)` 之后：`signal(SIGPIPE, SIG_IGN)`（SIGPIPE=13/SIG_IGN=1，call 0x23d6f8）+ `int fl = fcntl(1, F_GETFL)` + `fcntl(1, F_SETFL, fl | O_NONBLOCK(0x800))`（call 0x225cd4），失败时 `strb 1` 写到 `.bss` 的 `0x278010`。
2. `logf` 里 stdout 分支前多了 `ldrb` 同一个字节的闸：非 0 就跳过 `vprintf`+`fflush`。

段表（自己解 ELF，`llvm-objdump -h` 没有 sh_addr 列，regex 全失败）：`.text` 0x21c300/0x18300/0x4fe80、`.rodata` 0x200310、`.data` 0x274e80、`.bss` 0x278000/0x1a710。辅助符号：0x257f10=setvbuf、0x236344/0x2362f4=open、0x2489c0/0x248970=vprintf、0x248e78/0x248e28=fflush；main 的锚是 0x21c53c 引用串 `EXTRACTKIT_DONE rc=`（.rodata 0x20191e 附近另有 `/proc/sys/kernel/osrelease`）。

### 三、改动
- `payload/src/ek-core-uid0.c:237` 后加 `static unsigned char g_stdout_nb_fail;`（参考里是 1 字节 ldrb/strb，不能用 int）。
- 同文件 `logf` 守卫（原 `:312`）改成 `if (g_stdout_live && !g_stdout_nb_fail)`。
- 同文件 `main` 里 `setvbuf(...)` 之后加 `(void)signal(SIGPIPE, SIG_IGN);` 与 `int fl = fcntl(STDOUT_FILENO, F_GETFL); if (fl >= 0 && fcntl(STDOUT_FILENO, F_SETFL, fl | O_NONBLOCK) < 0) g_stdout_nb_fail = 1;`。
- `tools/build_fam.py`：`PINNED_9188 = {"6.6": ...}`（只钉 6.6），`PINNED_9104 = []`、`PINNED_9105 = {}` 不变；注释写清 9.191 的判据。

### 四、验证（事故 A 结案的硬证据）
- 补完后自编 6.1 = 434,192 B，sha256 `9cb0d29b4ca2794181d06f5d12567e81cbda29a285c9a11f73b6a9140e2410cb`，与 `payload/baseline/9188/ek-core-uid0-6.1` **逐字节相同**；指令数 81,572/81,572、hunks=0。
- 六支重建：5.10 472,944 `ea4fe089` / 5.15 472,944 `aeb13511` / 6.1 434,192 `9cb0d29b` / 6.18 459,120 `354b7e64` 全部与 9.188 钉死字节一致 —— 证明主源确已恢复到 9.188 时点；6.6 仍 pinned 476,048 `66be1802`；6.12 自编 496,592 `c54efa88`（比 9.190 的 496,528 `ec05ae84` 多出的正是还原的这段，6.12 走同一主源，属预期）。
- 三个检查器：`check-fam` [ok]；`check-parity` honor 5.10/5.15 100%(tags=88)、brm 6.1 100%(tags=28)、k618 6.18 100%(tags=44)；`check-honor-parity` 162 串 / 159 参考 / 3 白名单 / 0 missing。
- 单测 139 pass / 0 fail / 0 err / 4 skipped / 26 suites。
- APK 内六支逐字节 == 仓库（repo-same 全 True）；dex `9.191`×2、`9.190`×0、`honor.map`×7、`perf.tbl`×0；manifest versionName=9.191（UTF-16 命中 1）。

### 五、产物
- APK `D:\deepseek work\ExtractKit-9.191-unpin.apk` 6,755,618 B sha256 `e78c412f144e75d86dca5089555ff6e30362d880c400026c9bab13a2c2358d8b`，versionCode 381 / versionName "9.191"。
- 验收脚本 `D:\deepseek work\chk9191.py`；比对工具 `D:\deepseek work\_cmp61.py`、`D:\deepseek work\_diff61b.py`、`D:\deepseek work\_elf.py`。

### 六、教训
- 中文注释写进 `tools/build_fam.py` 必须每行带 `#`，否则 `SyntaxError: invalid character '：' (U+FF1A)`。
- `run_code` 里 TypeScript 模板字符串内含反引号会被截断 → 改写数组 `join`。
- 判「丢没丢逻辑」不要看字符串集合，要看指令流：串一致但差 20 条指令的情况真实存在。
## 9.192（字面版 payload 从主源重编：补上 fake/real_cred 双写 + 诚实退出；payload SHA256SUMS 去漂移）

### 一、起因
- 用户（m09119）在 HONOR CGA-W00 / 6.1.157-android14-11-gaaa383620ebf 上跑出 `[10/10] 完成` 但 `id` 仍是 uid=2000，日志里满是 `[fake] …`、`[child] woke uid=-118 euid=-119`、`[trim] Slab: 1018412 kB -> 1018412 kB`、`[!] fake cred page held; reboot to clean`，右侧 KernelSU 显示未安装。
- 溯源方法：把 assets 下所有二进制逐串比对，`[fake] forking ksud worker` / `[child] woke` / `cred writes landed` 三串只命中 `assets/payload/ek-core-uid0`（字面版 452,144 B）与 `fam/…-6.6`、`fam/…-6.12`；6.1 分支资产里 0 命中 ⇒ 那台设备跑的是**字面版**，触发条件只有两个：`/data/local/tmp/extract-kit/use_literal` 存在，或装的 APK 早于 9.145（选择逻辑 `ExtractEngine.kt:433-457`）。
- 字面版那份二进制还停在 9.104 的字节上，`real_cred` 字符串命中 0 —— 与 9.189 的 6.12 同一病根：`cred_verify` 判据读的是 `/proc/PID/status`，而内核判权限走 `task->real_cred`，只改 `task->cred` 永远读不到 uid 0。

### 二、改动
- `tools/build_payload.py` 两处正则修正（此前跑不通，所以字面版长期没人重建）：
  - UID0 的 sha256 原来按 `id = "chain_uid0"` 定位，`Mode` 里并没有这个字段，匹配失败后落到「文本里第一个 64 位十六进制串」的兜底分支，会把 `PER_FAMILY` 的 5.10 误改。现改为精确锚 `("payload/ek-core-uid0",\s*")[0-9a-f]{64}(")`，找不到直接 `sys.exit`，拒绝猜。
  - 写 `SHA256SUMS.txt` 时的过滤原为 `if "ek-core-uid0" in line: continue`，会把六支 fam 的 sums 行一起删掉；改成只跳过路径完全等于 `payload/ek-core-uid0` 的那一行。
- 字面版重编：452,144 B → **495,696 B**，sha256 `65256ac42a04c359116cc0ba7ab6b7f2066c7f4ca84aa4735ea26349d67872b8`；实测串 `real_cred`×6、`pass %d/4`×2、`fake_cred`×2、`CHAIN_STOP:cred_verify`×1。编译参数 `-O2 -static -fno-pie -no-pie -D_GNU_SOURCE -pthread -DEXTRACTKIT_FAMILY_ID="6.6" -DEXTRACTKIT_FAMILY_INT=606`，不传 `-DEXPECT_FAMILY`（`ek-core-uid0.c:190-191` 默认空串，`:4587` 的族闸门只在非空时生效），与它「通用回落份」的定位一致。
- `PayloadCatalog.kt:16` 的 `UID0.sha256` 改成 `65256ac4…`；上方补两行注释说明它 9.192 起由 `tools/build_payload.py` 从主源重编，此前一直停在 9.104 且没有 real_cred 双写。被误改的 5.10 哈希已还原为 `ea4fe0897a01e4c24c0bc95e6fbb1b11411cb8faa9d317582ab31282afcaec3d`。
- 主源 `payload/src/ek-core-uid0.c` 的 `shell_mode == 4` 分支（约 `:3948`）加诚实退出：算出 `denied = access("/data/adb")`，若 `setfsuid(0)` 返回的旧值非 0 且 `/data/adb` 打不开，就打 `[!] fake cred 未生效（fsuid 仍 %ld，/data/adb 打不开），跳过 ksud 交接` 并 `_exit(9)`，不再让上层按 10/10 收尾。
- 新增 `tools/gen-sums.py`：按磁盘真实字节重写 `app/src/main/assets/payload/SHA256SUMS.txt`（历史位置那份，长期漂移，9.192 时 5.10/5.15/6.1/6.12/6.18 五行全是旧哈希）。权威清单仍是 `app/src/main/assets/SHA256SUMS.txt`，测试 `PayloadCatalogTest.kt:67-85` 读它、只在缺失时回退到前者。

### 三、验证
- `tools/build_fam.py` 重跑，六支不变：5.10 472,944 `ea4fe089` / 5.15 472,944 `aeb13511` / 6.1 434,192 `9cb0d29b` / 6.6 476,048 `66be1802`（9.188 基线 pinned）/ 6.12 496,592 `c54efa88` / 6.18 459,120 `354b7e64`。
- 三个检查器：`check-fam` [ok]；`check-parity` honor 5.10/5.15 100%(tags=88)、brm 6.1 100%(tags=28)、k618 6.18 100%(tags=44)；`check-honor-parity` 162 串 / 159 参考 / 3 白名单 / 0 missing。
- 单测 139 pass / 0 fail / 0 err / 4 skipped / 26 suites。
- APK 内六支 + 字面版逐字节 == 仓库（repo-same 全 True）；dex `9.192`×2、`9.191`×0、`honor.map`×7、`perf.tbl`×0；manifest versionName=9.192（UTF-16 命中 1、9.191 命中 0）。

### 四、产物
- APK `D:\deepseek work\ExtractKit-9.192-literal.apk` 6,799,218 B sha256 `e8f75ea9d860360c1063f16dccc76930b7af4576bea39fb05d179ba54e9e762d`，versionCode 382 / versionName "9.192"。
- 验收脚本 `D:\deepseek work\chk9192.py`；清单生成器 `tools/gen-sums.py`。

### 五、教训
- 认「设备跑的是哪支二进制」靠日志串反查 assets，比读代码快；同一份源码编出来的不同份，串集合能直接定位。
- 追加/改写文件必须分三步：确认追加源存在 → `s = read(p)` → 单独一次 `write(p, s + add)`。9.190 的事故 B 就是单表达式里同时 open-for-write 与 open-for-read 把 330 行文档清零。
- Kotlin 里多行字符串拼接时，行尾写成全角逗号 `，` 会让编译器在下一行报 `Expecting member declaration`；要么写注释，要么并成一行常量。

### 六、补：调试开关自带版本戳，过期自动清理（m09320「不能自动删吗」）

- 问题：`ExtractEngine.kt` 原来用 `java.io.File(...).exists()` 判 `use_fam` / `use_literal`。设备上只要有人 `touch` 过一次空的 `use_literal`，之后每次升级都强制走字面版，日志里只有一行「开关在」，看不出它已经过期两个版本 —— 这正是 6.1 那台机器跑到 9.104 字面版的原因。
- 现在的规则（`ExtractEngine.kt` 末尾新增 `debugSwitch(path): DebugSwitch`，`internal` 便于单测）：
  - 文件不存在 → 不生效、不打日志，默认路径完全不变；
  - 文件内容（trim 后）等于 `BuildConfig.VERSION_NAME` → 生效，打「调试开关 X 生效（版本戳 …）」；
  - 内容空白或别的版本号 → 视为上次调试的残留：**自动 `delete()`**，打「调试开关 X 已过期（没有版本戳 / 版本戳是 9.104，当前 9.192）：已自动删除，本次按默认规则选链」。
- 用法变成：`echo -n 9.192 > /data/local/tmp/extract-kit/use_literal`（不带版本号的旧开关一律作废）。调用点 `ExtractEngine.kt:433-445` 之外逻辑未改，`use_literal` 仍优先于 `use_fam`。
- 新增 `app/src/test/kotlin/com/extractkit/app/DebugSwitchTest.kt` 四条：不存在 / 版本戳匹配保留 / 空白被删 / 旧版本号被删。
- 重新构建：单测 **143 pass / 0 fail / 0 err / 4 skipped / 27 suites**；APK 6,799,218 B sha256 `de34f3f6c56e9fd2ad7082e140861e886a89d4510f352aeeaed6c9bf174f7ac3`（同版本号 9.192，字节以本条为准，前一条 `e8f75ea9…` 是未含本改动的构建）；dex `9.192`×3。

## 9.193（选 MapleSU 当管理器无效：ksud_like 放宽 + 6.6 解钉带上 real_cred）

### 一、用户现场
- User (m09750) 逐字：「我试过了 用我们的软件 选择maple提权后 无效」——在 ExtractKit 的「管理器」里选 MapleSU（`dev.maplesu.manager`）跑 6.6.118（PPG-AN00，荣耀 GT Pro）提权，没拿到 root。

### 二、两个独立原因（都实测确认）
1. **交接层拒人**：`payload/src/ksu_stage.sh:40` 原来是 `ksud_like() { "$1" --version 2>&1 | head -1 | grep -q ksud; }`。MapleSU 的 `lib/arm64-v8a/libksud_ksu.so`（20,943,912 B，ELF 带 `.interp`，可直接 exec）是个 Rust 版 ksud，版本串是 `KernelSU version: {}`（包内 count 1），`ksud version`=0，`--package-uid`=0，`--package-name`=1 ⇒ `--version` 首行里一个 `ksud` 字都没有，唯一候选被 `ksud_like` 否掉，日志停在「[ksu] ksud 找不到可用来源」。
2. **cred 落点错位**：`app/src/main/assets/payload/fam/ek-core-uid0-6.6` 当时还是 9.188 钉死的 476,048 B，`real_cred` 串命中 0、`pass %d/4` 命中 0 —— 与 9.190 修 6.12 时同一个病根：`/proc/<pid>/status` 的 Uid 四段和 `/data/adb` 的可访问性都走 `task->real_cred`，只改 `task->cred` 永远读不到 uid 0。PPG-AN00 这颗 6.6.118 的 `task_cred=0x820 ≥ 0x800`，主源的 real_cred 双写条件对它成立。
- 顺带实测：字面版 `real_cred`=6、fam 6.12=6、fam 6.1（brm 链）=0 且没有 `[fake]`/`[child]` 串 —— `payload/src/chain_brm.c` 全文没有 `g_mgr_env`/`EXTRACTKIT_MGR`/`late-load`/`ksud`（grep 零命中），6.1 走的是自己的 rootd 路线，不做 ksud 交接，所以「选哪个管理器」对 6.1 没有意义。

### 三、改动
- `payload/src/ksu_stage.sh:32` 的 `KNOWN` 末尾加 `dev.maplesu.manager`；`:40` 改成 `ksud_like() { "$1" --version 2>&1 | head -1 | grep -qiE 'ksud|kernelsu'; }`（附两行注释说明 MapleSU 首行是 `KernelSU version:`）。
- 跑 `tools/gen-ksu-stage.py` 重新生成 `payload/src/ksu_stage.h`（294 行 12,660 B）与 `app/src/main/assets/stage/ksu_stage.sh`（10,652 B），脚本自带校验通过。
- `app/src/main/kotlin/com/extractkit/app/GlassMainActivity.kt:67` 的 `MANAGERS`、`GlassSheets.kt:40` 的 `GLASS_MANAGERS` 各加一行 `"dev.maplesu.manager" to "MapleSU"`（插在 `com.kowx712.supermanager` 之后）。
- `tools/build_fam.py:43` 的 `PINNED_9188` 由 `{"6.6": .../9188/...}` 改为 `{}`（`:40-42` 加了 5 行理由注释）：6.6 那支必须换成带 real_cred 双写的新编译产物。
- 新增 `app/src/test/kotlin/com/extractkit/app/MapleManagerTest.kt`：`glassManagerTableKnowsMapleSu`、`bothManagerTablesListMapleSu`（`MANAGERS` 是文件私有，只能按源码文本守）、`ksudLikeAcceptsKernelSUVersionLine`（读 `assets/stage/ksu_stage.sh`，断言含 `ksud|kernelsu` 与 `dev.maplesu.manager`）。
- `app/build.gradle.kts:21-22` versionCode 382→383、versionName "9.192"→"9.193"。

### 四、验证
- 六支（`tools/build_fam.py`）：5.10 473,200 `e462ad82…`、5.15 473,200 `a0ae84dc…`、6.1 434,192 `9cb0d29b…`（未变，不含 ksu_stage）、6.6 496,720 `76cbc9014e57d04097af0f1c7047998da3e3929311b0fae393fcbb353f139c8e`、6.12 496,784 `613ef334…`、6.18 459,376 `6514b385…`。
- 字面版（`tools/build_payload.py`）：495,952 B sha256 `c5437ea1f473da7aa856ea1708cae5edee047a1543bb87c032ef95d18af7c035`；`PayloadCatalog.UID0.sha256` 与 `SHA256SUMS` 一并更新。
- 检查器：`tools/check-fam.py` [ok] 六支；`tools/check-parity.py` honor 5.10/5.15 100%(tags=88)、brm 6.1 100%(tags=28)、k618 6.18 100%(tags=44)；`tools/check-honor-parity.py` 162 串 / 159 参考 / 3 白名单 / 0 missing。
- 单测 **146 pass / 0 fail / 0 err / 4 skipped / 28 suites**（较 9.192 的 143 多出 MapleManagerTest 三条）。
- APK 内 `assets/stage/ksu_stage.sh` 实测含 `grep -qiE 'ksud|kernelsu'` 与 `KNOWN="… dev.maplesu.manager"`。

### 五、产物
- APK `D:\deepseek work\ExtractKit-9.193-maple.apk` 6,811,270 B sha256 `bd304a6a8bcdcc3d6e79224ed0c4f072a93f9162da3788db32b21d2e6238c2c7`，versionCode 383 / versionName "9.193"；APK 内六支 + index.txt 与仓库逐字节一致；dex `9.193`×3、`9.192`×0、`honor.map`×7、`perf.tbl`×0；manifest `9.193` UTF-16 命中 1。
- 验收脚本 `D:\deepseek work\chk9193.py`。

### 六、仍待真机验证
- 6.6 那支现在带 real_cred 双写，PPG-AN00（GT Pro 6.6.118-g554929766a0d-abogki54455896）上选 MapleSU 重跑，预期日志出现 `[real_cred] pass …` 与 `[ksu] KSU_LOADED`；若仍停在 `[ksu] ksud 找不到可用来源`，说明还有别的候选过滤点，取 `/data/local/tmp/extract-*.log` 再收。
- MapleSU 的 EK-CORE 路线（shark 载具）与本改动无关：其 7 支载具里只有 `libk61258.so` / `libk66127.so` 是 kallsyms 驱动，且都带编译进去的 build 白名单（`PROFILE_66118=%s` 等），我们的 `g554929766a0d-abogki54455896` 不在任何一支里。
## 9.194（late-load 只从包内取 ksud，不再碰 /data/adb）

请求：User (m09898) 逐字「late-load 一律从包内拉取 不走/data/adb/ksu/bin/ksud」。

### 改前行为（9.193 及以前）
- 候选三级：①目标管理器自己的 `$APP_ROOT/*/<pkg>*/lib/arm64` ②KNOWN 里别家管理器的同路径（cross，打警告）③`/data/local/tmp/ksud` 与 `/data/adb/ksud` 兜底（why=fallback）。
- 解析成功后还会**写**两处：原子覆盖 `/data/adb/ksud`，并在 `/data/adb/ksu/bin/ksud` 建/修软链指向它。

### 本次改动（payload/src/ksu_stage.sh，287 行 → 生成 ksu_stage.h 与 assets/stage/ksu_stage.sh）
- 删除第三级候选整个分支：`/data/local/tmp/ksud`、`/data/adb/ksud`、`/data/adb/ksu/bin/ksud` 一律不做来源。找不到就 `[resolve] why=none` + `[ksu] ksud 找不到可用来源：<mgr> 包内没有可用的 ksud…按策略不从 /data/adb 取` 并 exit 1。
- 删除覆盖 `/data/adb/ksud` 的 cp/chmod/mv 三步，删除 `mkdir -p /data/adb/ksu/bin` 与 `ln -sf /data/adb/ksud` 软链。脚本现在对 `/data/adb` 只读（safe_mode 读 modules 除外）。
- 新增第 6 步：`KSUD=$SRC` 直接指向包内那份；若 `/data/app` 被 SELinux 挡 exec，则复制到 `BIN_DIR=/data/local/tmp/extract-kit/bin/ksud`（`.new` 原子改名 + chmod 755 + is_bin/ksud_like 双检，不过就回退包内路径并删副本）。
- 头部设计要点 3/4/5 重写：3 讲只从包内取、4 讲不往 /data/adb 写、5 讲副本只落我们自己的目录。步骤序号 6(KMI)/7(已加载) 重排。
- 保留未动：cross 借 KNOWN（仍从别家**包内**取，属“包内”范畴）、`--package-name` 能力探测、dryrun 分支、safe_mode、sig_enforce 临时关、四级 flag 降级、失败后 `insmod /data/adb/ksu/lib/*kernelsu*.ko` 兜底（那是 .ko 不是 ksud，且是最后一级）。

### 新增测试 app/src/test/kotlin/com/extractkit/app/KsuStageSourceTest.kt（3 条）
- `noAdbFallbackCandidates`：脚本里不能出现 `for f in /data/local/tmp/ksud /data/adb/ksud` 或 `for f in /data/adb/ksud`。
- `neverWritesIntoAdbKsuDir`：不能出现 `cp "$SRC" /data/adb/ksud.new`、`ln -sf /data/adb/ksud`、`mkdir -p /data/adb/ksu/bin`。
- `executableCopyGoesToOwnBinDir`：必须有 `BIN_DIR=/data/local/tmp/extract-kit/bin`、`lib/arm64`、`scan_dir "$d" "$MGR" self`。

### 验证
- `python tools/gen-ksu-stage.py`：287 行 / 12,998 B / markers ok；assets/stage/ksu_stage.sh 11,028 B；clean66/ksu_stage.h 同步。
- 单测 149 pass / 0 fail / 0 err / 4 skipped / 29 suites（9.193 是 146/28）。
- check-fam [ok]；check-parity honor 5.10/5.15 100%(tags=88)、brm 6.1 100%(tags=28)、k618 6.18 100%(tags=44)；check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing。
- 六支：5.10 473,584 cb5170e0 / 5.15 473,584 74a47714 / 6.1 434,192 9cb0d29b（未变，6.1 不走 ksud 交接）/ 6.6 497,104 c05710ef / 6.12 497,168 3ed610e4 / 6.18 459,760 0551a6b3；字面版 496,400 sha256 d935849ae5f15c44b3bf82f3d11c5dd10e57afd1fa814777b53083980c2deb42（+448 B，全部来自脚本正文）。
- APK D:\deepseek work\ExtractKit-9.194-pkgksud.apk 6,812,662 B sha256=7bec223fde148ad1b2645a5a8d2f0a3cc6e58ee8b454f43ba4f8a6cd8cf13721；versionCode 384 / versionName "9.194"；APK 内六支 + index.txt repo-same 全 True；dex 9.194×3、9.193×0、honor.map×7、perf.tbl×0；manifest 9.194 utf-16le 命中 1。
- 验收脚本 D:\deepseek work\chk9194.py。

### 影响面与真机预期
- 之前靠 `/data/adb/ksud` 兜底才成功的场景（管理器包内确实没有 ksud）现在会明确失败并打 why=none，不再静默拿旧件注册。
- MapleSU 这类包内自带 Rust ksud 的管理器不受影响（self 命中）；反而少了被 `/data/adb/ksud` 旧件顶掉的风险。
- 若 `/data/app` exec 被挡，会走 `/data/local/tmp/extract-kit/bin/ksud` 副本，行为与之前等价但不污染 /data/adb。
## 9.195（每族一支独立 .c + selinux/panic 挪到 uid 验收之后 + panic 读不到不再停链）

### 起因
- User (m10065)：每支 payload 要一个独立 .c，单独改一支不用在原主源的 #if 里翻。
- PPG-AN00（6.6.118-android15-8-g554929766a0d-abogki544555896-4k，9.194 + MapleSU）真机日志：cred 与 real_cred 两处都装上了（`[+] stage fake_cred target=task+0x820`、`[+] task->real_cred installed`），但随后 selinux 零写没命中、`read_panic_on_warn()` 返回 -1 被当成「panic_on_warn=1」→ `[!] CHAIN_STOP:panic_on_warn_set -- parking without reap`，UI 停 [8/10]，从头到尾没打过一行 `[real_cred] pass` 和 `[verify] Uid`。

### 改动一：payload/src/fam/ 七份单支源（新工具 tools/split-fam.py）
- 真预处理器探针（clang -E -dM + 同族 -D）建宏表，再逐行消解 #if/#ifdef/#ifndef/#elif/#else/#endif（defined()、!、&&、||、==、!=、关系、括号、数字；未定义标识符=0；活跃分支里的对象式 #define/#undef 同步进表），生成
  payload/src/fam/510.c(5.10/510/chain 1)、515.c(5.15/515/1)、61.c(6.1/601/2)、66.c(6.6/606/0)、612.c(6.12/612/0)、618.c(6.18/618/3)、literal.c(字面版，FAMILY_ID 仍 "6.6"、INT 606、chain 0、无 EXPECT_FAMILY)。
- 文件头写死 `#define EXTRACTKIT_FAMILY_ID/_INT/_CHAIN`（+ `EXPECT_FAMILY`），所以 build 不再传这些 -D；#include 全部保留（header 里的 #ifndef 保护照旧生效）。
- tools/build_fam.py 优先编 `payload/src/fam/<id>.c`（打印 `[src] …`），文件缺失才回落主源 + 原 -D；tools/build_payload.py 编 `payload/src/fam/literal.c`。strip/族串自检/PayloadCatalog/SHA256SUMS/fam/index.txt 逻辑不变。
- 等价性证明 D:\deepseek work\_vsplit.py：同一份源分别用「主源 + 族 -D」与「fam/<id>.c 无 -D」编译，7/7 sha 完全相同。
- 新增 tools/check-split.py：七份文件在、头部三宏与 EXPECT_FAMILY 正确、只剩自己那条链的 `#include "chain_*.c"`（CHAIN_LEGACY 0 不引任何链文件，实现在主源内联）、无 `EXTRACTKIT_CHAIN ==` 残留、build 脚本已指向 fam/。当前输出 `[ok] split sources: 7 份单支源自洽`。

### 改动二：selinux 零写与 panic_on_warn 挪到 uid 验收之后
- 原顺序：cred → real_cred → selinux 零写 → panic_on_warn → 4 趟 `[real_cred] pass %d/4` → `[verify]`。前三步任何一步失败都会挡住后面「到底拿到 uid 没有」的判定。
- 现顺序：cred → real_cred → 4 趟 pass → `[verify] Uid/Gid/CapEff` → （`if (fake_stage)`）selinux 零写 → panic_on_warn → `[+] cred writes landed, waking child`。源码注释已写明这两步只为 ksud late-load 服务，不是拿 uid 的前提。
- selinux 段原样搬（`SELINUX_STATE_STATIC==0` 跳过 / `&7` 不对齐跳过 / `g_stage_verify = verify_enforce_zero` + `stage_write(SELINUX_STATE_STATIC + g_slide - 7, MODE_ZERO, "selinux")`）。

### 改动三：read_panic_on_warn 的 -1 不再当「已开启」
- 七份源统一：`fopen` 失败 → `logf("[ksu] panic_on_warn=%d\n", -2)` 并 `return -2`；读到了但解析失败仍 -1；读到了正常值原样返回。刻意复用已有格式串，不新增字符串（check-parity / check-honor-parity 串集不变）。
- 调用点：`pw==0` 跳过；`pw<0` 打 `[!] panic_on_warn 读不到（%d），跳过清零继续` 并继续跑；只有 `pw>0` 且地址对齐前提不成立时才 `CHAIN_STOP:panic_on_warn_set`。
- 这条同时解释了 6.1 CGA-W00 与 6.12 的同类现象：sysctl 读不到就等于「值为 1」是纯粹的判据错误。

### 验证
- 单测 149 pass / 0 fail / 0 err / 4 skipped / 29 suites。
- check-fam [ok]；check-parity honor 5.10/5.15 100%(tags=88)、brm 6.1 100%(tags=28)、k618 6.18 100%(tags=44)；check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing；check-split [ok]。
- 六支：5.10 473,584 cb5170e0 / 5.15 473,584 74a47714 / 6.1 434,192 9cb0d29b（6.1 链路未变）/ 6.6 497,296 4073e05b / 6.12 497,488 615227ca / 6.18 459,760 0551a6b3；字面版 496,528 060cecc1。
- APK D:\deepseek work\ExtractKit-9.195-order.apk 6,812,902 B sha256=43e19b76e84d4e0744ffcc2358f6fee3195b9fa1a4ee010c70d8592367f9bb6f；versionCode 385 / versionName "9.195"；APK 内六支 + index.txt + 字面版 repo-same 全 True；dex 9.195×3、9.194×0、honor.map×7、perf.tbl×0；manifest 9.195 utf-16le 命中 1。
- 验收脚本 D:\deepseek work\chk9195.py。

### 真机待验判据
- 下一跑必须看到 `[real_cred] pass 1/4 -> uid=?` 与 `[verify] Uid: …` 四段。若 uid 仍是 2000，说明 6.6.118 的越界写入没真正落到目标页（要查 pipe reclaim 的 off=0x288 / 0xde0 与 task+0x820 的对应）；若 uid=0 而 ksud 仍失败，就只剩 selinux 清零（`SELINUX_STATE_STATIC=0xffffffc0823ba418` 对这颗 build 是否成立）。

### 教训
- 一份源一层条件编译的代价：41 个条件块让「改一支」必须先确认自己改的是哪个分支。拆开后每支一个文件，代价是要用 sha 逐字节证明拆分是纯重构。
- python 单表达式里同时 `open(w)` 与 `open(r)` 会先把文件截成 0（9.190 事故 B 的翻版）→ 追加文档必须「确认源存在 → 读入 → 单独一次写」。
## 9.196（6.6 钉回 9.188 字节：用户 m10218「现有的 real_cred 必失败」）

### 结论先说：6.6 的改动不是 6.12 那次带出来的
- 时间线（`tools/build_fam.py` 注释与本文各节可互证）：9.189 起五支钉 `payload/baseline/9188/`；9.190 只把 `PINNED_9105` 置空（6.12 一支）；9.191 把 `PINNED_9188` 收成 `{"6.6": …}`（只钉 6.6）；**9.193 才把 `PINNED_9188` 改成 `{}`**，理由写在文件里：9.188 那支的字符串里 `real_cred` 命中 0 条，而 6.6.118 的判据走 `task->real_cred`。
- 也就是说 6.6 是被「刻意解钉」的，不是 6.12 改动的副产物；但既然真机上 real_cred 那条路走不通，就按用户要求钉回去。

### 改动
- `tools/build_fam.py`：`PINNED_9188 = {"6.6": ROOT / "payload/baseline/9188/ek-core-uid0-6.6"}`，注释记下 9.193 的来龙去脉与本次判据（476,048 B / `66be1802…a56ebbf`）。
- `app/build.gradle.kts:21-22` → versionCode 386 / versionName "9.196"。
- 别的一律不动：`payload/src/fam/66.c` 保留（9.195 的 panic -2 与 selinux/panic 重排仍在源里，等 6.6 重新解钉时直接可用）。

### 验证（这轮判据是「与 9.188 逐字节相同」）
- 六支：5.10 473,584 `cb5170e0` / 5.15 473,584 `74a47714` / 6.1 434,192 `9cb0d29b` / **6.6 476,048 `66be1802`（pinned）** / 6.12 497,488 `615227ca` / 6.18 459,760 `0551a6b3`；字面版 496,528 `060cecc1`。
- `chk9196.py` 把 APK 内 6.6 直接与 `ExtractKit-9.188-brm-static.apk` 里的同名条目做字节比较（不是只比 sha 字符串）；并在 index 旁列出「与 9.188 同支是否相同」，6.6/6.1 为 True，其余四支为 False（各有 9.194/9.195 的必然改动）。
- check-fam [ok]；check-split [ok]；check-parity honor 100%(88)/brm 100%(28)/k618 100%(44)；check-honor-parity 162/159/3/0。
- 单测 149 pass / 0 fail / 0 err / 4 skipped / 29 suites。
- APK `D:\deepseek work\ExtractKit-9.196-66pinned.apk` 6,801,514 B sha256=`7e1b3a09da5d957d5ed28e6a30741f5e29b0f239eefbfc61bcbe358545805a28`（versionCode 386 / 9.196；dex 9.196×3、honor.map×7、perf.tbl×0；manifest utf-16 命中 1）；验收脚本 `D:\deepseek work\chk9196.py`（把 APK 内 6.6 与 9.188 APK 同名条目做字节比较，结果 True）。

### 需要说清的影响
- 6.6 那支回到 9.104 时点逻辑后，**9.195 的 panic/selinux 重排与 `read_panic_on_warn` 的 -2 分支不会作用于 6.6**（它们在 `payload/src/fam/66.c` 里，但要重新解钉才编得进去）。真机上 6.6.118 会回到「装 cred、装不上 real_cred、uid 读回 2000」的老行为，这是本次改动承认的代价。
- 6.12 保持 9.190 起的解钉状态（`615227ca`），因为它的判据同样走 real_cred，且 9.105 那支解钉前已证实 real_cred 命中 0 条。

## 9.197（6.6 改 cred-only + 保留 MapleSU 修复）

用户 9.196 现场：把 6.6 钉回 9.188 字节后，real_cred 双写没了（对 PPG-AN00 6.6.118 是对的方向），
但 ksu_stage.sh 也一起退回到 9.188 —— ksud_like 还是 grep -q ksud（MapleSU 的 ksud 首行是
「KernelSU version: 32680-5」，必被拒）、且会去 /data/adb/ksud 取，于是选 MapleSU 无效。
9.197 的取法：**6.6 只改 cred（行为回 9.188），但 ksud 交接保留 9.193/9.194 的修复**。

### 改动
- payload/src/fam/66.c:12 新增 `#define EXTRACTKIT_NO_REAL_CRED 1`；两处 real_cred 写入门控改成
  `if (!EXTRACTKIT_NO_REAL_CRED && OFF_TASK_CRED >= 0x800)`；四趟循环变 `pass <= (EXTRACTKIT_NO_REAL_CRED ? 1 : 4)`；
  读 /proc 的 Uid 之前 `if (EXTRACTKIT_NO_REAL_CRED) break;`（只改 cred 时读 real_cred 必是旧值）。
- tools/build_fam.py：PINNED_9188 由 {"6.6": …} 改回 {}，注释记录 9.197 判据。
- app/build.gradle.kts:21-22 → versionCode 387 / versionName "9.197"。

### 验证
- 6.6 自编 496,272 B sha256=5d01bd5c79c39e3e1f2aad390c1d285802438f999e97685470db664ecb1c7f51。
- 6.6 串：real_cred=1（仅 stage_write 的 mode 标签字面量）、pass %d/4=0、全部 real_cred 消息串 0；
  grep -qiE=1、grep -q ksud=0、dev.maplesu.manager=1、extract-kit/bin=2、/data/adb/ksud=2、panic_on_warn=7。
- 其余五支不变：5.10 cb5170e0 / 5.15 74a47714 / 6.1 9cb0d29b / 6.12 615227ca / 6.18 0551a6b3。
- check-fam / check-split / check-parity(100%/88、100%/28、100%/44) / check-honor-parity(162/159/3/0) 全过。

### 产物
- APK D:\deepseek work\ExtractKit-9.197-credonly.apk（versionCode 387 / 9.197）。
- 验收脚本 D:\deepseek work\chk9197.py。

### 判据（下次真机）
- 6.6.118 上应看到 [payload] family=6.6、[cfg] loaded local profile、stage fake_cred 成功、
  **没有** [real_cred] pass 行，然后直接 cred writes landed → ksu_stage（选 MapleSU 时 why=self），
  最后 [verify] Uid 四段（只改 cred 时 verify 可能仍读 real_cred，若停 CHAIN_STOP:cred_verify 属已知限制）。

### 9.197 追加（verify 放行）
上面的 9.197 初版构建后发现一个自锁：verify 块读 /proc/<pid>/status 的 Uid（由 real_cred 生成），
只改 cred 时必读回旧值 -> park_forever(CHAIN_STOP:cred_verify) -> ksud 交接永远轮不到，
「6.6 只改 cred + MapleSU」就没法同时成立。改成：

```
if (!uid4 || !gid4) {
        logf("[!] cred verify: Uid/Gid 四段不全为 0（Uid=%d Gid=%d）", uid4, gid4);
        if (!EXTRACTKIT_NO_REAL_CRED)
                park_forever("CHAIN_STOP:cred_verify");
        logf("[!] 只改 cred 的支跳过 verify，继续交给 ksud");
}
```

即：6.6 不做 uid 判据（判据交给下一步 —— ksud 能否打开 /data/adb、模块是否装载），其余五支行为不变。

### 9.197 最终产物与验证
- fam 6.6 496,272 B sha256=1c71c6dfbbabb705ee9a204618e0b8a545067b9f6b5966e9fc1373fd9ad44609
  （real_cred=1 仅标签字面量、pass %d/4=0、CHAIN_STOP:cred_verify=0、跳过 verify 的日志=1、
  grep -qiE=1、grep -q ksud=0、dev.maplesu.manager=1、extract-kit/bin=2）。
- 五支未变：5.10 cb5170e0 / 5.15 74a47714 / 6.1 9cb0d29b / 6.12 615227ca / 6.18 0551a6b3；字面版 060cecc1。
- APK D:\deepseek work\ExtractKit-9.197-credonly.apk 6,812,366 B
  sha256=aad8ab70d10d72e4549fdd06c5bee10f8c94ada3da590201d343aec8a2f1f0a3；versionCode 387 / 9.197。
- 单测 149 pass / 0 fail / 0 err / 4 skipped / 29 suites；check-fam / check-split / check-parity 全过；
  chk9197.py 全部 catalog-ok=True、dex 9.197×3、honor.map×7、perf.tbl×0、manifest utf16 命中 1。

## 9.198（6.1 也交接 + 非 late-load 部分回退到 9.192 形态）

- 起因：User (m10395)「也交接  并且所有payload除了late-load payload是修改后适配maple 其余部分和192这个版本一致」。
- 9.195 的「selinux/panic 挪到 uid 验收之后」被整体回退（脚本 D:\deepseek work\_revert9195.py，删 51 行插回 verify 前），主源恢复 9.192 形态：selinux 清零 → read_panic_on_warn()!=0 分支（对齐判据 park / 失败 park）→ verify。
- 6.1 交接：payload/src/chain_brm.c 新增 brm_handoff_ksud()（写/复用 /data/local/tmp/ksu_stage.sh，envp 带 EXTRACTKIT_MGR，sh 执行、输出落 ksu_stage.out，父 waitpid 打 [ksu] worker exit）。调用点在 brm_ksu_stage() 之后、[id] uid= 之前。6.1 支由 434,192(9cb0d29b) → 446,096(9589666a)。
- cred-only：主源新增 EXTRACTKIT_NO_REAL_CRED（默认 0），tools/split-fam.py 增加 NO_REAL_CRED={"6.6":1} 并写进每份 fam 头（否则 #ifndef 的默认 0 会展开成写死 0 把 66.c 顶掉）；两处 real_cred 门控、四趟循环、verify 的 park 全部按该宏放行，6.6 打「[!] 只改 cred 的支跳过 verify，继续交给 ksud」。
- 六支与字面版：5.10 473,584 cb5170e0 / 5.15 473,584 74a47714 / 6.1 446,096 9589666a / 6.6 495,952 42510618 / 6.12 497,168 d2aeffd0 / 6.18 459,760 0551a6b3 / 字面版 496,336 f8ef823b（tools/build_fam.py 全自编，PINNED_* 全空）。
- 与 9.192 实测差异（D:\deepseek work\_d9298.py）：5.10/5.15/6.12/6.18 的字符串差集只有 ksu_stage.sh 重写部分（旧的 /data/local/tmp/ksud 与 /data/adb/ksud 兜底串被删、新增 BIN_DIR 拷贝串），+576～640 B，其余逐串一致；6.1 +11,904 B 来自 handoff；6.6 +19,904 B，因为 9.192 的 6.6 本身就是 9.104 冻结二进制（476,048 B（66be1802）），缺 device.cfg / [census] / [syms] / [rootd] / 真实 cred 页回收等 9.13x–9.19x 代码，无法「既与 192 同字节又认 MapleSU」。现按「cred 策略与 9.192 相同（只改 task->cred）+ late-load 适配 Maple」处理。
- 版本 388 / 9.198；单测 149 pass / 0 fail / 0 err / 4 skip / 29 suites；check-fam [ok]、check-parity honor 100%(88)/brm 100%(31)/k618 100%(44)、check-honor-parity 162/159/3/0、check-split [ok]。
- APK D:\deepseek work\ExtractKit-9.198-192maple.apk 6,817,394 B sha256=a067a3bae7e09241a19ca722f6236b8d5d1065a91d01e8826278550cc4d29206；APK 内六支与字面版 repo-same 全 True；dex 9.198×3、9.197×0、honor.map×7、perf.tbl×0；manifest 9.198 utf-16 命中 1。验收脚本 D:\deepseek work\chk9198.py。
- 已知回归：9.195 的 panic 判据（读不到 ≠ 1）被回退，6.6 在 PPG-AN00 上仍可能回到 CHAIN_STOP:panic_on_warn_set；需要单独做进「late-load 适配」清单才不违反本条约束。
## 9.199（6.6 钉回 9.192 原字节 + late-load 脚本改由 App 下发）

起因：User (m10548) 逐字「PPG-AN00直接panic  你肯定没还原 还是real_cred」。9.198 的 6.6 是按
「9.188 的 cred-only 行为 + 新版交接」重编的 495,952 B（sha 42510618），真机在内核
6.6.118-android15-8-g554929766a0d-abogki544555896-4k 上直接 panic。

实测澄清：真正钉回的那支 payload/baseline/9188/ek-core-uid0-6.6（476,048 B
sha256=66be18027bf0339774f6da08e3c4967df681493346874fedc2fbb1d12a56ebbf）里
real_cred 串命中 0 条，它本身不写 real_cred；panic 来自重编那支带进来的 9.148–9.198
新代码（device.cfg / [census] / [syms] / 真实 cred 页回收），那批逻辑没在这颗内核上验证过。

改动：
1. tools/build_fam.py:60 PINNED_9188 = {"6.6": payload/baseline/9188/ek-core-uid0-6.6}
   —— 6.6 恢复到 9.192 的逐字节（476,048 B 66be1802）。
2. late-load 脚本改由 App 下发：ManagerAudit.kt 的 DIR/SCRIPT 由 private 改为 const val；
   RunEnv.command 新增 stageScript 参数，输出 `EXTRACTKIT_STAGE=<path> `（贴在 payload 前）；
   ExtractEngine.run 与 runSingle 开跑前都调 ManagerAudit.deploy(ctx)，把
   assets/stage/ksu_stage.sh 推到 /data/local/tmp/extract-kit/ksu_stage.sh 并指给 payload。
   于是「旧字节 payload + 新脚本」可以并存，6.6 不必为新脚本重编。
3. RunEnvTest 新增 commandPassesStageScript；app/build.gradle.kts versionCode 389 / "9.199"。

验证：
- 六支：5.10 473,584 cb5170e0 / 5.15 473,584 74a47714 / 6.1 446,096 9589666a /
  6.6 476,048 66be1802（= 9.192） / 6.12 497,168 d2aeffd0 / 6.18 459,760 0551a6b3；
  字面版 496,336 f8ef823b。APK 内七份与仓库逐字节 same=True。
- 6.6 支实测：real_cred=0、EXTRACTKIT_STAGE=1、EXTRACTKIT_MGR=5（支持外部脚本与包名）。
- assets/stage/ksu_stage.sh（11,028 B）：grep -qiE=1、dev.maplesu.manager=1、
  extract-kit/bin=2、/data/adb/ksud=2 ⇒ MapleSU 兼容与「包内取 ksud」都在下发脚本里。
- 单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites。
- check-fam [ok]；check-split [ok]；check-parity honor 100%(88) / brm 100%(31) / k618 100%(44)；
  check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing。
- APK D:\deepseek work\ExtractKit-9.199-66pin.apk 6,806,562 B
  sha256=bfe9977879e4694d354381a8958888ec10e14aa2c768fc6e50fdf8600c19de81；
  versionCode 389 / versionName "9.199"（manifest utf-16le 命中 1）；dex 9.199×3、9.198×0、
  honor.map×7、perf.tbl×0。验收脚本 D:\deepseek work\chk9199.py。

仍待真机：9.199 在 PPG-AN00（6.6.118）要看到 [ksu] 段真正跑起来（脚本来自 assets），
BRT-AN00（6.12.58）与 CGA-W00（6.1）继续复测。

## 9.200 — XecPro(com.xecpro.kernel) late-load 识别修复

真机现场（PPG-AN00，6.6.118-...-abogki544555896-4k）：EK-CORE 链已拿到 uid=0，
但 ksu_stage.sh 把 XecPro 判成「没有自带 ksud」，跨包借了 com.sukisu.ultra 的
ksud 4.3.0-r2 去注册，late-load try=1..4 全 rc=0、/proc/modules 里 kernelsu 计数 0。

根因：XecPro 的 libxeccli.so 是 KernelSU ksud 的改名分支，--version 输出
xudc 31431-af7cca83-1-g293dba5 (uapi: 6)，既无 ksud 也无 kernelsu 字样；
9.193 的 ksud_like() 只按品牌词判，故判死。

修法：
- payload/src/ksu_stage.sh：ksud_like 增加能力判据 —— 首行命中 ksud|kernelsu 直接过，
  否则要求 --version 命中 uapi: 且 late-load --help 出现 kernelsu.ko|package-name；
  新增 run_to()/TO（timeout 5s）包住 ver_of 与 help 探测，防随机 .so 卡死。
- KNOWN/mgr 名单、GLASS_MANAGERS(GlassSheets.kt:40)、MANAGERS(GlassMainActivity.kt:67)
  各加 com.xecpro.kernel → XecPro。
- 重生成 payload/src/ksu_stage.h 与 assets/stage/ksu_stage.sh。

验证：设备上以假 app_root 造 lib/arm64/libxeccli.so 后 dryrun，输出
src=.../libxeccli.so owner=com.xecpro.kernel cross=0 why=self、
来源版本: xudc 31431-af7cca83-1-g293dba5、flag=package-name ok。

fam（9.200 重编）：5.10 474480 b551b357 / 5.15 474480 caf19cd9 / 6.1 446992 687379f9
/ 6.6 476048 66be1802(9.188 pin) / 6.12 498064 6c18f92e(解钉，主源) / 6.18 460656 39a31303。
## 9.201 — 自家 ksud 静态定案 + 副本探测 + 加载判定加等待

真机（PPG-AN00 / 6.6.118 / com.xecpro.kernel）现象：9.200 的交接脚本在 root+kernel 域跑，
XecPro 仍被判 cross，借了 com.sukisu.ultra 的 ksud 注册，XecPro 里看不到 root。

三处改动（payload/src/ksu_stage.sh，链逻辑零改动）：

1. 自家目录先静态定案：scan_dir 在 $3=self 时先按「文件内同时有 late-load 与 kernelsu 两串」
   直接接受（SRC_WHY=self_static），不再依赖 exec 探测。原因：同一二进制在 u:r:kernel:s0 下
   exec 会崩（日志里那 4 条 Segmentation fault / Illegal instruction），于是自家判空 → 跨包借件。
2. probe_ok()：非静态命中时，一律先 cp 到 /data/local/tmp/extract-kit/ksud.pick 再 exec 探测，
   避免 /data/app 私有 .so 在 kernel 域被 SELinux 挡；日志新增 [probe] <name> inplace=… copy=…。
3. try_load 判定：late-load 之后等 0.3s、最多查 3 次 /proc/modules（模块 init 有延迟，
   9.200 真机上四条全报失败、结尾又打 KSU_LOADED 就是这里）。
   另：SRC_WHY=self_static 时跳过 --help 探测，按支持 --package-name 处理。

校验：gen-ksu-stage.py → ksu_stage.h 383 行/17,641 B、assets/stage/ksu_stage.sh 15,091 B；
check-fam [ok]；check-parity honor 100%/88 tags、brm 100%/32 tags、k618 100%/45 tags；
check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing；单测 150 pass / 0 fail / 4 skipped / 29 suites。

设备：PPG-AN00 已重启（uptime 87s，/proc/modules 无 kernelsu），9.201 已 adb install -r Success。

## 9.206 — 假 cred 安装去重（重复 real_cred 块收成 fake_cred_install()）

**怎么发现的.** 6.6 主线里「装假 cred、再同步 task->real_cred」这段在 main 里出现了两遍：
第一遍是首次安装，第二遍在 pass = 1..4 的重喷分支里，而且第二遍的缩进是错乱的
（if (pass > 1) { ... } 少一层缩进，real_cred 块直接贴在 g_fake_A = fc.A; 后面）。
两份内容逐字节相同，只有注释重复，属于纯粹的历史拷贝遗留。

**改法.** 抽成单一入口 static int fake_cred_install(struct plant_res *out); 内部依次做
memset(out) -> stage_write(g_child_task + OFF_TASK_CRED, MODE_FAKE, "fake_cred", out)
-> 在 OFF_TASK_CRED >= 0x800（且未定义 EXTRACTKIT_NO_REAL_CRED）时
stage_write(g_child_task + OFF_TASK_CRED - 8, MODE_FAKE, "real_cred", &rc) 并打印
[+] task->real_cred installed A=%#llx。两个调用点变成：

- 首次：if (fake_cred_install(&fc)) park_forever("fake cred write failed");
- 重喷：if (fake_cred_install(&nf)) { logf("[!] pass %d re-plant failed; ..."); break; }
  fc = nf; g_fake_A = fc.A;

**落到哪些文件.** payload/src/ek-core-uid0.c（母本）、payload/src/fam/510.c、
515.c、61.c、66.c、612.c、618.c、literal.c，以及未参与构建的孤儿
payload/fam-src/6.6.c。脚本 D:\deepseek work\_cleandup.py，幂等（已含 helper 则跳过）。
fam/66.c 之前手工改过，脚本报 [skip-has-helper]。

**语义等价证据.** 六支 fam 逐支 -O2 -static 编译通过；重建后 5.10/5.15/6.1/6.18 四支
二进制与 9.204 逐字节相同（04e8a782 / 7b9c9195 / d05d8d51 / 78f12d82），说明这段
重构没有改变生成代码。6.12 从 501,648 B e886f6fd 变为 501,584 B a4c5cef8（-64 B，纯
布局差异）：对新旧两支做全量可打印串比对，丢失 0 条、新增 0 条。

**校验.** check-fam [ok]（六支 repo/index/SHA256SUMS/PER_FAMILY 一致，6.6 calibrated）；
check-parity honor 100%(88 tags) / brm 100%(32 tags) / k618 100%(45 tags)；
check-honor-parity 162 串 / 159 在参考 / 3 白名单 / 0 missing。
单测本轮先红后绿：MapleManagerTest.ksudLikeAcceptsKernelSuVersionLine 里还留着
assertTrue("KNOWN 里没有 MapleSU", sh.contains("dev.maplesu.manager")) —— 9.204 删掉 KNOWN 借用表
之后这条断言必然失败，改为守 9.204 的新策略：脚本里 com.sukisu.ultra 只允许出现 1 次（MGR 默认值），
且不得再有 KNOWN=" 借用表。改后 150 tests / 0 fail / 0 err / 4 skipped / 29 suites（测试源码不进 APK，
故 APK 未重建）。

**产物.** ExtractKit-9.206-dedup.apk 6,828,754 B
sha256 94E702A659D8F3DB9EAE98086283EB309207532035AE7A4A2255CA0A019362D9，
versionCode 396 / versionName "9.206"，已装机（PPG-AN00 / 6.6.118，adb 192.168.5.7:34467）。

**六支 fam（9.206）.**

| 分支 | 大小 | sha256(前 8) | 说明 |
|---|---|---|---|
| 5.10 | 478,128 | 04e8a782 | 重编，与 9.204 逐字节相同 |
| 5.15 | 478,128 | 7b9c9195 | 重编，与 9.204 逐字节相同 |
| 6.1 | 450,576 | d05d8d51 | 重编，与 9.204 逐字节相同 |
| 6.6 | 476,048 | 94156b6d | 仍钉 9.188 + 脚本转发 shim |
| 6.12 | 501,584 | a4c5cef8 | 重编，-64 B（布局差异，串集合不变） |
| 6.18 | 464,240 | 78f12d82 | 重编，与 9.204 逐字节相同 |

**没动的东西.** 6.6 的假 cred 页回收问题（[child] woke uid=378603552，即 task 指针低
32 位被当成 uid 读回）本轮没修 —— 6.6 仍钉 9.188 基线，源码改动不进二进制。要修必须
先解钉 6.6，再按「锁页法」或「验后修」改写入时机。


## 9.207 — 6.6 解钉：uid 修复从 real_cred 开关里解耦

用户 m15491「修 注意备份」。备份 D:\deepseek work\backup-9.206-src.zip（47 文件）。

**病根（payload/src/fam/66.c:11 `#define EXTRACTKIT_NO_REAL_CRED 1`）**
- 6.6 只装 task->cred、不装 real_cred，而 9.104 那支把「erase 之后把 A+0x08 清零」这一步
  写在了 real_cred 的开关里：`for (pass = 1; pass <= (NO_REAL_CRED ? 1 : 4); pass++) { if (NO_REAL_CRED) break; ... }`
  ⇒ 6.6 上一步都不执行。
- rb_erase 走 case1-left 时 `__rb_change_child` 把 `A->rb_right`（= `task+0x820`）写进 `A+0x08`，
  那正好是 cred 的 uid/gid；走 case2/3 不脏 A+8。于是真机上 uid 有时是 0（成功），
  有时是 task_struct 的低 32 位（现场 `uid=378603552 = 0x16910000` = `task=0xffffff8916910000` 低 32 位），
  成功与否纯看当次 erase 拓扑 + 假 cred 页有没有被内核回收复用。

**改法**
- fake_stage 分支改成固定的「装 + 修」两步循环，最多 3 趟：每趟 `stage_write(fc.A + 0x08, MODE_ZERO, "fake_uid", NULL)`，
  零写没落地就 `continue`（下一趟 `fake_cred_install(&nf)` 重新 UAF + 新 A），绝不对同一对象二次 erase。
- 修完 6.6 直接 break（/proc/PID/status 的 Uid 段由 real_cred 生成、恒为 2000，不能当判据），
  判据交给子进程自报 uid；子进程回报处新增 `[!] 假 cred uid=%d（修复没生效），这一趟不算成功`。
- tools/build_fam.py：`PINNED_9188 = {}`（6.6 解钉，回到 payload/src/fam/66.c 编译）。

**产物**
- 6.6：501,328 B sha256=fd7fe3e86b874eae963cb6511cdcda337420a70ec694f7a930d6ebfaf61bed88（原钉住支 476,048 B / 94156b6d…）。
- 其余五支与 9.206 逐字节相同：5.10 478,128 04e8a782 / 5.15 478,128 7b9c9195 / 6.1 450,576 d05d8d51 /
  6.12 501,584 a4c5cef8 / 6.18 464,240 78f12d82。
- APK D:\deepseek work\ExtractKit-9.207-fakeuid.apk 6,845,058 B sha256=C1558A9F5452CD3C867FA0C2B3A64253E57EB4375721FD9DB5A50571A2BCBC6F；
  versionCode 397 / "9.207"；单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites；已 adb install -r Success。
- check-fam [ok]；check-parity honor 100%(88 tags) / brm 100%(32 tags) / k618 100%(45 tags)；
  check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing。

## 9.208 — 6.6 回滚：撤掉 MODE_ZERO 修补，重新钉回 9.188 稳定支

用户 m15662「稳定 panic 不能走 real cred」。

**为什么 9.207 必崩**
- 9.207 每趟都在 `fc.A + 0x08` 再打一次 `MODE_ZERO` erase（"fake_uid"）。erase 的写法是
  「删掉该 timer base 的一个 rb_node，让红黑树修复把这 8 字节改写成 0」，代价是修复回写
  `__rb_change_child` 会把 `A->rb_right`（= `task+0x820`）写进同一片地址 —— 也就是每修一次，
  就在这个 timer base 的树里留一个指向 task_struct 的坏指针。9.104 那支一次运行只 erase 一次
  （单个 plant），所以扛得住；9.207 修 + 重喷叠加到 3 趟，真机稳定 panic。
- 这与 9.105 在 6.1.157 上死机是同一个机理（重复 erase 叠加）。real_cred 双写路线用户明确不走。

**改法**
- `payload/src/fam/66.c`：删掉 9.207 的「装 + 修」循环（原 4685–4742 行），回到 9.188 行为 ——
  `fake_cred_install()` 装完 `task->cred` 就结束，不做 `MODE_ZERO`、不重复 erase、不读
  `/proc/PID/status`（Uid 段由 real_cred 生成，恒 2000）。原地留注释说明为什么不能修。
- `tools/build_fam.py`：`PINNED_9188 = {"6.6": ROOT / "payload/baseline/9188/ek-core-uid0-6.6"}`
  —— 6.6 重新钉回 9.188/9.104 原字节，仍走 `patch-stage-shim.py` 换内嵌转发 shim。

**产物**
- 6.6：476,048 B sha256=94156b6d252005473838cca91efd2afea3c88718adc78639be5aab3c3cc7a062（calibrated）。
- 其余五支与 9.207 逐字节相同：5.10 478,128 04e8a782 / 5.15 478,128 7b9c9195 / 6.1 450,576 d05d8d51 /
  6.12 501,584 a4c5cef8 / 6.18 464,240 78f12d82。
- APK D:\deepseek work\ExtractKit-9.208-nopanic.apk 6,828,754 B sha256=95FE4386F477B41619711515FFCDC128B2160F2A8346793F31F4359A96158000；
  versionCode 398 / "9.208"；单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites；已 adb install -r Success。
- check-fam [ok]；check-parity honor 100%(88 tags) / brm 100%(32) / k618 100%(45)；`66.c` `-fsyntax-only` 干净（只剩 unused function 警告）。

**遗留**
- uid 是否读到 0 仍由当次 `rb_erase` 拓扑决定（case2/3 不脏 A+8 → 0；case1-left 脏 → task 低 32 位）。
  在不新增 erase、不走 real_cred 的前提下，可行的方向只有「让那一次 erase 自己按 case2/3 走」，
  需要在 plant 前用页级窗口证据（`[+] plant … hit=`）挑 victim，而不是事后修补。

## 9.210 - payload 日志去中文（82 条 logf 换英文）

用户 m15838：「我想要的是日志里只保留 链路代码 无中文 以及解释性代码」。

- 提取：六支 fam 源里含中文的 logf 语句每支 78 条、共 82 条唯一语句（脚本 D:\deepseek work\_cjk.py / _cjk2 / _cjk3 / _cjk4，清单 D:\deepseek work\_cjk_full.json）。
- 替换：D:\deepseek work\_cjk_new.json 存 82 条英文版（保留 tag 与全部 % 占位与实参顺序，删括注解释）。D:\deepseek work\_apply.py 按整条 logf 字面替换、失败再空白折叠正则替换，作用到 payload/src/fam/{510,515,61,66,612,618}.c、payload/src/ek-core-uid0.c、payload/fam-src/6.6.c；每支 hit=80/81，miss 的语句该支本来没有。
- 主源与孤儿文件另 13/15 条用 D:\deepseek work\_apply2.py 短语字典清掉。
- 校验：D:\deepseek work\_left.py（括号配平扫 logf 里的 CJK 字面量）→ 8 个文件 cjk_logf=0；D:\deepseek work\_strscan.py（扫非 logf 的中文字符串字面量）→ 六支 0（中文只剩注释）。
- 事故：_cjk_new.json 里 [ids] 那条漏了结尾分号 → build_fam 报 510.c:694:65 error: expected ";" after expression；D:\deepseek work\_fix1.py 全量补成 " (no kmem id)"); 后通过。
- 9.210 六支：5.10 478,704 aa8f91f9 / 5.15 478,704 53e584fd / 6.1 451,216 8c433b16 / 6.6 476,048 94156b6d（pinned + shim，仍是老二进制，中文串还在）/ 6.12 500,752 d4d48259 / 6.18 464,880 a164d411。
- 9.210 APK：6,828,526 B sha256=3E3180DFA92FC15F698E2A3B335DA5BFD0E07FC6CBB5D77DFFB0EF2F6A8D6209，versionCode 400，单测 150/0/0/4，29 suites。

## 9.211 - 6.6 钉住支（pinned 9.188）中文日志串等长英文化

- 起因：9.210 只清了源码，6.6 跑的是 9.188 基线二进制，其 .rodata 里仍有 42 条中文格式串（[base] 期望 low21=…、[trim] 保留: socket 喷…、[!] selinux 清零未命中… 等），真机日志里照样是中文。
- 取证：按 NUL 分隔取整条 C 字符串扫（D:\deepseek work\_66zh2.py → _66zh2.json，42 条含 off/len/text）；按可打印 ASCII 连续段扫会把中文在全角括号处切断，不可用。
- 改法：新建 tools/patch-zh-log.py，内置 42 条 {中文: 英文}，逐条 find 中文 UTF-8 串、用英文覆盖并把字节数补齐到与原串完全相同（换行结尾的把空格补在换行前），偏移与长度不变；已替换的按英文串 find 判为幂等跳过；末尾自检 NUL 短串（<400 B）里不得再有 CJK，否则 exit 1。
- tools/build_fam.py 新增 zh_log(out)，在 PINNED_9105 / PINNED_9188 / PINNED_9104 三个分支的 shim_stage(out) 之后各调一次。
- 结果：6.6 = 476,048 B sha256=29273996225875b603f2ac8e38f6e895eae8062b58e4657ff1396157e9f21444（[zhpatch] replaced=42 already=0 left=0）；其余五支不变。check-fam [ok]；六支复扫 short_cjk=0、big_cjk(script)=1（唯一长串是内嵌 ksu_stage.sh 正文）。
- 9.211 APK：D:\deepseek work\ExtractKit-9.211-asciilog66.apk 6,827,958 B sha256=A5477A92C30C5A1B6E15AD7C78DCC001BC28C7B82B936845288C26D2D7B8E847，versionCode 401 / 9.211，单测 150 pass/0 fail/0 err/4 skipped/29 suites，dex 9.211×3 / 9.210×0，已 adb install -r Success。

## 仍剩的中文（9.211 之后）

- ksu_stage.sh（assets/stage/ksu_stage.sh 16,232 B）注释与 echo 仍是中文，输出落在 /data/local/tmp/ksu_stage.out。
- Kotlin 侧 153 条中文 log/appendLine（RunModel.kt / ExtractEngine.kt / EkCalib.kt），含 步骤 N/M 行与中文 step.label。


## 9.212 — App 侧日志去掉中文（承接 9.210/9.211 只做了 payload）

用户要求（m15838）：日志里只保留链路代码，不要中文、不要解释性文字。9.210 只清了 payload
（82 条 logf → 英文），9.211 清了 6.6 钉住支二进制里的 42 条中文格式串，App 侧 Kotlin 还有
153 条含中文的 log/appendLine。本节把 Kotlin 侧也清完。

改法：三批替换对表（_kt_en1.json 54 条 / _kt_en2.json 81 条 / _kt_en3.json 25 条 /
_kt_en4.json 38 条），格式 [file, old, new, expected_count]，由 _kt_apply.py 逐条校验
count == expected 才替换，count 不符记 miss 不动，最后统一 write(..., newline='\n')。
结果 applied=158 miss=2 → 补修后 applied=38 miss=0。

两处不只是翻译的语义改动：
- ExtractEngine.kt 的步骤行改用 ASCII 的 step.id（leak_uid0 / selftest_uid0 / extract_uid0 /
  extract_EK-CORE / chain_uid0），不再嵌 PayloadCatalog 里中文的 step.label：
  onStageUpdate("[${index + 1}/$total] ${step.id}")、log("======== step ... ${step.id} ========")
- RunModel.kt:176 的判据从 why.contains("未授权") 改成 why.contains("unauthorized")，与
  Shell.kt:111 的新文案 "Shizuku unauthorized (grant ExtractKit access in Shizuku)" 对齐。

保留中文的地方（都不写进运行日志）：RunModel.kt:35-47 Banner（执行中/需要授权/未成功/
已提权/环境受限/就绪）、FirmwareActivity.kt:89-181 固件页对话框、ConfigGen.kt:3044-3102
写 device_config.h 的中文注释、CalibrationModel.kt 的 UI 状态字段。

单测连带（4 个文件断言中文字面量，必须同步改英文）：DebugSwitchTest.kt:51 "过期"→"stale"；
ReleaseMatrixTest.kt:77 "冻结"→"frozen"、:84 "命中"→"-> family"、:86 "不在分支矩阵内"→
"outside family matrix"、:88 "解析不出"→"cannot parse major.minor"；VerdictTest.kt:66/67
"su 需在管理器里授权"/"su 可用" → "authorize su in the manager"/"su available"；
FamilyDefaultsTest.kt:141-142 "已标定"/"未标定" → "(calibrated)"/"uncalibrated"。

产物：ExtractKit-9.212-ktascii.apk 6,827,978 B，
sha256=E96779242E3375D9A162C7B53239737BD7FD79B8366C06E1ABCD27ADD747BE70，versionCode 402。
单测 150 pass / 0 fail / 0 err / 4 skipped。六支 fam 与 9.211 逐字节一致（本次未动 payload）：
5.10 478,704 aa8f91f9 / 5.15 478,704 53e584fd / 6.1 451,216 8c433b16 / 6.6 476,048 b0a2862a /
6.12 500,752 d4d48259 / 6.18 464,880 a164d411。dex 里 9.212×3、9.211×0。

构建坑：gradle 第二次跑时 daemon 持着
intermediates/dex/release/minifyReleaseWithR8/classes.dex 报 FileSystemException，
加 --no-daemon 即过。

仍未转英文：payload/src/ksu_stage.sh 的中文注释与 echo（输出到 /data/local/tmp/ksu_stage.out，
不进 App 日志）。


## 9.213 — ksu_stage.sh 的 echo 全部转英文（日志侧最后一处中文）

9.210/9.211 清 payload 二进制里的日志串，9.212 清 Kotlin 侧 log()，剩下的中文日志只有
payload/src/ksu_stage.sh 的 echo（落到 /data/local/tmp/ksu_stage.out）。本节把它清完。

改动（20 + 3 条，逐条 assert count==1 后替换，脚本 _stage_en.py / _stage_en2.py）：
- [resolve] 静态特征命中 … → [resolve] static pick $(basename "$_p") (best score, skip exec probe)
- [ksu] 来源版本: → [ksu] source version:
- [ksu] 包内没有可用 ksud（只扫 …） → no usable ksud in $MGR (scanned … only; 9.204 policy: no cross-package borrow, no /data/adb, fail fast)
- 四级/三级/两级降级全部失败 → all 4/3/2 fallback levels failed
- safe_mode 已恢复/已临时禁用 → safe_mode: restored N module(s) / temporarily disabled N module(s) (restored on success)
- 其余：dryrun=1 未写任何文件、副本自检不过、复制到 BIN_DIR 失败、kernelsu 已在运行…需重启、
  try=N 生效、该 ksud 只认 --package-uid、sig_enforce 还原、late-load 失败 rc、insmod 成功…，全部英文。

保留中文的只剩注释（ksu_stage.sh 407 行里 67 行注释是中文），不进运行日志、不进 ksu_stage.out。

校验（脚本 _cjk9213.py，按 NUL 切 C 字符串再 utf-8 解码，不按可打印 ASCII 段切）：
六支 payload 短串（<400 B，即所有 logf 格式串）含 CJK 的 = 0；只有 1 条 >400 B 的大串命中，
就是内嵌的 ksu_stage.sh 正文（里面只有注释是中文）。ksu_stage.sh 自身 echo/代码行含 CJK = 0。
设备上 sh -n 校验 SYNTAX_OK。

产物：ExtractKit-9.213-stageascii.apk 6,828,070 B，
sha256=E7215418E9FCE5FFC52FFCDDCAED5EF876DEE7EAA3C484942454F2219969C81A，versionCode 403。
单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites。六支：5.10 478,640 df8a52e6 /
5.15 478,640 b2554752 / 6.1 451,152 83aac30b / 6.6 476,048 b0a2862a（pinned 9.188 + shim，脚本换长度不影响它）
/ 6.12 500,688 2f8cdd5b / 6.18 464,880 af5138b0。check-fam [ok]；check-honor-parity 162 串 /
159 参考 / 3 白名单 / 0 missing；check-parity honor 100%(88 tags) / brm 100%(33) / k618 100%(46)。

## 9.214 — 6.6 假 cred uid 脏读：子进程握手 + 父进程补写（并把 DCE 坑修掉）

### 病根
9.213 之前 6.6 一直是「装假 cred → 清 selinux → 清 panic_on_warn → 最后一次零写 fake_cred+0x08」。
零写用的是 MODE_ZERO 的 rb_erase：它把 0 写到 fake_cred+0x08，但**同一次 erase** 里
`__rb_change_child` 又把 A->rb_right（= child_task+0x820）写回同一格，所以 uid 有时是 0、
有时是 task 指针低 32 位。用 /data/local/tmp/ek-core.log 的 47 趟统计：
ok=32 / bad=3（603252192、378603552、1604478432 都是 task 低 32 位）/ noreport=13。
脏的那趟 ksud 必然失败（/data/adb access=denied → worker exit=0x100），所以不能假定成功。

### 改法（不走 real_cred、不新增 erase 语义）
- 子进程（`wait fake` → wait_child_main(4)）：唤醒后先 `write(4,&rep)` 上报 getuid()；
  不是 0 就 `read(3,&ch,1)` 等父进程再唤醒，最多 3 轮，仍脏则 `_exit(9)`。
  只有读到 0 才往下 `setfsuid/setfsgid` 并 fork ksud。
- 父进程（fake_stage 分支）：`poll(st_fd,10000)` 读子进程上报；非 0 就补一次
  `stage_write(g_fake_A + CRED_UID_OFF, MODE_ZERO, "fake_uid", NULL)` 再 `write(go_fd,"A",1)`
  重新唤醒，最多 3 轮；读到 0 才算 uid_ok。补写抽成 `static __attribute__((noinline)) int fake_uid_repair(int round)`，
  日志 `[fake] repair round %d target=%#llx rc=%d`。

### 踩到的坑（重要）
初版把父进程的条件写成 `if (shell_mode != 4 || repairs >= 3) break;`。
但 **6.6 TU 的父进程里 shell_mode 永远不会是 4**：fake 模式是 `fake_stage`/`g_fake_stage` 标志，
4 只出现在子进程的 `wait fake` 参数（66.c:4434-4435、:4440）。于是编译期直接判定该分支不可达，
整段补写 + 三条日志被 DCE，**产物与改前逐字节相同**（6.6 500,560 B sha256=5f99b95b…），
扫串时表现为 `repair %d` / `re-wake` / `fake cred uid=` 全为 0，而 `never reached 0` 还在。
改成 `if (!fake_stage || repairs >= 3)` 后 6.6 变为 500,944 B sha256=fd205425…，
六条关键串全部出现（repair round 2 / zero miss; retry 1 / re-wake 1 / never reached 0 1 /
child report uid= 1 / waiting for repair round 1 / still dirty after 3 1）。

### 构建与校验
- tools/build_fam.py:91 `PINNED_9188 = {}`（6.6 回到 fam/66.c 编译）。
- 六支：5.10 478,640 df8a52e6 / 5.15 478,640 b2554752 / 6.1 451,152 83aac30b /
  6.6 500,944 fd205425 / 6.12 500,688 2f8cdd5b / 6.18 464,880 af5138b0；check-fam [ok]。
- app/build.gradle.kts:21-22 → versionCode 400 / "9.214"。

## 9.215 / 9.216 — 6.6 回钉 9.188 + App 层脏 uid 自动重试

### 9.214 解钉版在真机上的失败现场（证据）
设备 PPG-AN00 / 6.6.118-android15-8-g554929766a0d-abogki544555896-4k，日志
`/data/local/tmp/ek-core.log`（累计 219 趟，最后一趟是 9.214）：

```
[cred] attempt=0 child=11092 R=0xffffff802be48840 site_low=0x38458 recs=39112 task=0xffffff8910ec8000
[+] stage fake_cred target=0xffffff8910ec8820 mode=fake attempt=1/3
[+] fake cred A=0xffffff8a1c44ebd0 selinux_state=0xffffffd87fbba418
[+] stage fake_uid target=0xffffff8a1c44ebd8 mode=zero attempt=1/1
[verify] Uid:	2000	2000	2000	2000
[fake] uid 2000 dirty; waiting for repair round 1/2/3
[fake] repair round 1/2/3 target=0xffffff8a1c44ebd8 rc=0
[fake] uid 2000 still dirty after 3 repairs; giving up
[!] fake cred uid never reached 0; run failed
```

关键判读：子进程报的是 **uid=2000 euid=2000**（不是指针脏值），说明 task->cred 那次写没有
让子进程看到假 cred —— 写进了回收后装别的对象的页。每一趟写入都是
`[+] plant1 burst hit=0 foreign=0 free_seen=0` + `[uaf] stream miss; trying pipe reclaim fallback`，
即主源那套 plant/burst 在这颗内核上一次 UAF 窗口都没等到。所以三次补写 A+8 全是白费，
9.214 的修复逻辑本身生效了（rc=0、轮次握手正常），但装不上 cred 就无从谈修。

对照 9.213（6.6 钉 9.188 基线、同一台机器）：`[child] woke uid=0 euid=0` → `su -c id` 实测
`uid=0(root) context=u:r:ksu:s0`。结论：主源 6.6（9.148–9.198 的 device.cfg/[census]/[syms]/
plant 改造）在这颗内核上不可用，因此 9.215 把 6.6 重新钉回 9.188 基线。

### 9.215
- `tools/build_fam.py`：`PINNED_9188 = {"6.6": ROOT / "payload/baseline/9188/ek-core-uid0-6.6"}`
  （上方注释块记录上述真机证据），版本号 405 / "9.215"。
- 六支：5.10 df8a52e6 / 5.15 b2554752 / 6.1 83aac30b / 6.6 **b0a2862a**（pinned + shim + zh patch，
  与 9.213 逐字节一致）/ 6.12 2f8cdd5b / 6.18 af5138b0；check-fam [ok]。
- APK `ExtractKit-9.215-repin.apk` 6,828,066 B；已装机。

### 9.216
- 钉住的 9.188 支仍有概率性 uid 脏读（历史统计约 3/47 趟：rb_erase 的 __rb_change_child
  把 task+0x820 写进 A+0x08 后，那次零写可能自毁），这一层不重编源码改不了。
- 因此在 App 层加重跑：`app/src/main/kotlin/com/extractkit/app/RunModel.kt:198-218`，
  一次 `engine.run(chain_uid0)` 失败后自动再跑一次（全新子进程 + 全新假 cred 页），
  日志打 `[retry] attempt 2/2 (previous: <stage>)`；遇到
  `panic_on_warn` / `held` / `zombie` 这类「必须重启才算干净」的阶段不重跑，打
  `[retry] skip: stage '<x>' needs a reboot, not another run`。
- 版本号 406 / "9.216"；单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites。
- APK `ExtractKit-9.216-retry.apk` 6,828,066 B sha256=
  `BE359FE93DC05DBA0B99050562BA091905CC0BD811E5CBD8F665DEAEB470226A`；已 `install -r` Success，
  dumpsys versionName=9.216。

## 9.217 — 崩过一次就不再自动重试（App 层，payload 零改动）

### 起因
用户反馈「怎么感觉新版 panic 概率大大提高了，刚刚两次都 panic」。作业面只在 9.216 新增的
App 层自动重试：一次点击最多跑两趟主链。

### 统计（dev213 真机日志 186 趟）
- 结局：done=34 / 无结尾 148 / panic_on_warn_set=2 / cred_verify=1。
- 有 burst 证据（hit=1）的 20 趟：17 趟 done。
- 只靠 pipe 兜底（burst hit=0）的 32 趟：17 趟 done、15 趟失败 —— 这部分是盲写，约 47% 落在错误页上。

### 机理
payload/src/fam/66.c:3191-3211 把「pipe_plant 写满 4096 字节」当成 hit=1，而 :3216 的闸门
if (mode != MODE_FAKE && !hit && !foreign && !free_seen) 对 MODE_FAKE 直接放行，于是没有页级证据也照写。
写错页时 rb_erase 读到的是别人的对象字段，__rb_change_child 按 pc=A 去写 A+8/A+16，
panic_on_oops=1 的内核直接重启 —— 现场正好停在 [pipe] wrote=… 之后、[+] fake cred A= 之前。

### 改法
app/src/main/kotlin/com/extractkit/app/RunModel.kt：跑前取 boot_id 与 elapsedRealtime，
重试前再取一次；boot_id 变了或 uptime 回退，即认定这一趟把内核搞崩了，打
[retry] skip: device rebooted during the run (boot xxxxxxxx -> yyyyyyyy, uptime Ns) - the kernel crashed
并放弃重试。原有的 panic_on_warn / held / zombie 跳过名单保留。

### 校验
- versionCode 407 / versionName "9.217"；单测 150 pass / 0 fail / 0 err / 4 skipped / 29 suites。
- 六支 fam 与 9.216 完全一致（payload 未重编）：5.10 df8a52e6 / 5.15 b2554752 / 6.1 83aac30b /
  6.6 b0a2862a（钉 9.188+shim+zh patch）/ 6.12 2f8cdd5b / 6.18 af5138b0。
- dex：9.217×3、9.216×0、[retry] skip: device rebooted×1、needs a reboot, not another run×1、honor.map×7、perf.tbl×0。

## 9.218 — 6.6 拿掉「无证据盲写」：不再 panic，改成干净放弃

真机（PPG-AN00 / 6.6.118-android15-8-g554929766a0d-abogki544555896-4k）连续两趟 panic
之后，用户 m16780 的原话是「刚刚试了一次 又panic了」。9.217 只是在 App 层不再自动
重试，第一趟照样崩，所以要看的是 payload。

### 病根

钉住的 9.188 二进制（payload/baseline/9188/ek-core-uid0-6.6，476,048 B）里那句

    [~] plant1 no UAF window seen; write directly

在 payload/src/fam/66.c 里 grep 不到 —— 说明钉住那支**没有闸门**：burst 阶段
hit=0 / free_seen=0 / foreign=0 时它不做任何检查就把伪造的 rb_node 拿去 rb_erase，
落在别人的红黑树上就是 Oops，这颗内核 panic_on_oops=1，于是当场重启。
现源里其实有闸门，但条件是

    if (mode != MODE_FAKE && !hit && !foreign && !free_seen)   /* 旧 :3216 */

只挡 MODE_ZERO；而伪造 cred 恰恰走 MODE_FAKE，且 :3191-3217 的 pipe/AIO 回收链
一旦「写进去了」就置 hit=1，于是这道门对 fake 从来不开。

### 改法（payload/src/fam/66.c）

1. `static int g_blind_ok;`（:2724）：默认关。
2. burst 循环结束后、进 pipe/AIO 回收之前记一份原始证据：`ev = hit;`（:3196）。
   之后的 pipe/AIO 成功会把 hit 假置成 1，无法再当证据。
3. 闸门改成对所有模式一致：`if (!g_blind_ok && !ev && !foreign && !free_seen)`
   → 打 `[~] plant%d no page window (hit=0); skip write`、`free(payload)`、
   `g_held++`、`res->retry = 1` 后返回，绝不写。
4. 逃生口：`EXTRACTKIT_BLIND=1` 恢复旧行为，并在开头打
   `[uaf] blind write allowed=%d (0 = require trace evidence)`。

### App 侧（App 与 payload 配套）

app/src/main/kotlin/com/extractkit/app/RunModel.kt:210-216 的「不重试」名单补上
`no page window` 与 `fake cred write failed`：闸门放弃时上一趟的牺牲线程留在驻留
状态，同一开机内再跑一次只会再攒一个。

### 构建与校验

- tools/build_fam.py:97 `PINNED_9188 = {}`（6.6 第三次解钉，理由写在注释里）。
- 6.6 由 payload/src/fam/66.c 重编：501,008 B sha256=0bc738a50a3b29e7f49c9a7bd53679449b15aa80c67147c6d87f083eb9314657；
  其余五支与 9.217 逐字节相同（5.10 df8a52e6 / 5.15 b2554752 / 6.1 83aac30b / 6.12 2f8cdd5b / 6.18 af5138b0）。
- check-fam [ok]；check-parity honor 100%(88) / brm 100%(33) / k618 100%(46)；
  check-honor-parity 162 串 / 159 参考 / 3 白名单 / 0 missing；单测 150 pass / 0 fail / 4 skip / 29 suites。
- 新 6.6 串扫描：blind write allowed=×1、no page window×1、EXTRACTKIT_BLIND×1，短串中文 0 条。
- APK ExtractKit-9.218-noblind.apk 6,844,506 B
  sha256=95C46F3E0CF9A63D53C5B69FA9EFA9AAAF98B3A0AAD4E9D6B9CDD561A76F1699；versionCode 408 / "9.218"。

### 代价（必须记住）

钉住那支在这颗内核上本来 47% 的盲写是「写进去就算成功」的运气来源。闸门一关，
凡是当次开机拿不到 trace 证据（页事件没挂上、kmem 事件被 SELinux 拒）的跑法就会
干净放弃并提示重启，成功率随证据可得率走 —— 换来的是不再 panic、不再重启。
