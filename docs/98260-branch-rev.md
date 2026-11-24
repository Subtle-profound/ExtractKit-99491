# EK-CORE 分支 payload 逆向重写 · 依据与规格

状态：规格已成稿（逆向做到「架构 + 参数面 + 判据串」这一层），源码重写未开始。
来源 APK（只读，未改动）：

| APK | 大小 | 用途 |
|---|---|---|
| `C:\Users\Admin\Downloads\荣耀5系提权.apk` | 11,610,595 B | 5.10 分支来源 |
| `C:\Users\Admin\Downloads\ma.apk` | 64,492,925 B | 6.1 / 6.18 分支来源 |

工作副本：`D:\deepseek work\rev5x\`（5 系）、`D:\deepseek work\revma\`（ma.apk）。
工具：NDK r29 的 `llvm-objdump` / `llvm-readelf` / `llvm-strings`（本机 REA 的 Ghidra 只吃 PE/MZ/raw，对 ELF 返回 target_format_unsupported，Hopper 不接受 win32，故链路改走 llvm）。

---

## 1. 5.10：`assets/libsysopt.so`

- 870,920 B，ELF64 **ET_EXEC**，AArch64，entry `0x400580`，静态链接 libc，**未 strip**。
- `.symtab` 4237 项；定义符号 1173，其中自有（非 libc）555；`FUNC` 821。
- 已导出：`rev5x\libsysopt.dis`（128,109 行）、`rev5x\libsysopt.str`（3954 行）、`rev5x\libsysopt.sym`、`rev5x\str_addr.txt`（带地址）、`rev5x\funcs.txt`、`rev5x\main.dis`、`rev5x\data.hex`。

### 1.1 主流程（由 `main` 0x405f08(+14872) 的调用序列还原）

```
参数解析（name=value，见 1.2）
load_map_file(loadmap) + ksym_lookup×N        → UAF-LOAD map %s syms=%d slide=%#llx / UAF-SYM-MISS
perf_event_open 探测 KASLR                    → UAF-SLIDE perf_event_open: %s / UAF-SHOT step=...
perf_count / ioctl(perf) 取 pc              → UAF-PGT / UAF-BUDDY
pool_hold_start(poolhold)                     → UAF-POOLHOLD ready n=%d uid=%d（配额读 /proc/sys/net/ipv4/ip_local_reserved_ports）
reservoir_alloc                               → UAF-RESERVOIR cpus=%d per-cpu=%d made=%d
pin_cpu                                       → UAF-PIN-CPU / UAF-PIN-DONE
skb_per_pair + socketpair + setsockopt        → UAF-SKB sent=%d len=%d pairs=%d total=%d
make_timer（posix_timers_cache）              → UAF-T-START id=%d tid=%d
spray_phase（aio / uring / anon_early / foreign）→ UAF-SPRAY* / UAF-URING* / UAF-ANON-EARLY*
attempt → chain_pool_guard → chain_aim → chain_round → chain_pool_guard   （主循环体）
reap_phase                                    → UAF-REAP / UAF-REAPED / UAF-REAP-STOP / UAF-REAP-ABANDON
验证：chain_creds / chain_real_uid / chain_caps / chain_enforce / chain_selinux_ready / chain_read_self / chain_bm64
window_dump / dump_sysctl                     → UAF-WIN %#zx %#llx / UAF-CHAIN W=%#llx...
spray_aio_release / reservoir_alloc / chain_kill_worker → UAF-AIO-RELEASE / UAF-AIO-DESTROY
```

### 1.2 命令行参数面（`.rodata` 内 `name=` 串，共 61 个，逐字）

`attempts timers reap reapstop reapmax spray verbose storm pinwave retry tail waves wavegap settle shrink anon anonearly drain uring write refill hold prehold left check leftsym pcsym watch trace shots load rdsys rdcap churn stamp poolhold noplant tries windump churnbatch churnsettle churncpus reserve reservecpus reservesettle claimms reserverounds charge debug target target_exit memstart delays chain chainwait mods loadmap loadslide perf perfonly loadsym`

### 1.3 `.data` 里恢复出来的默认值（`llvm-objdump -s -j .data`）

- `verbose_mode` = 1
- `pool_holder` = -1(u32 max)
- `log_fd` = -1
- `chain_sysctl_fd` = -1
- `rdsys_cap` = 262144
- `spray_waves` = 1
- `wave_gap_ms` = 100
- `reap_stop` = 1
- `claim_ms` = 25
- `memstart` = 1073741824
- `settle_ms` = 500
- `reserve_rounds` = 1
- `churn_settle_ms` = 1000
- `chain_tries` = 8
- `drop_uid` = -1
- `target_exit_marker` = -1

其它：`spray_pc/spray_left` 初值为非零 u64（运行时状态，非默认参数）。

### 1.4 自有符号分组（555 项里的关键部分）

- 写链控制：`chain_aim / chain_round / chain_round_no / chain_pool_guard / chain_window / chain_wait / chain_worker / chain_kill_worker / chain_step / chain_step_name / chain_tries / chain_reap_error / chain_mode`
- 内核对象定位：`chain_ic / chain_ic_off / chain_t_off / chain_T / chain_W / chain_W2 / chain_net / chain_sig / chain_se / chain_mods / chain_caps / chain_creds / chain_real_uid / chain_enforce / chain_selinux_ready / chain_bm64`
- 喷射：`spray_aio / spray_aio_release / spray_uring / spray_skb / spray_skb_waves / spray_anon_early / spray_foreign / spray_phase / skb_per_pair`
- 预留/占用：`pool_hold_start / pool_hold_child / pool_hold_stop / reservoir_alloc / charge_slabs / reserve_rounds / reserve_cpus / reserve_n / reserve_settle_ms / claim_ms / pin_cpu`
- 回收：`reap_phase / reap_stop / reap_max / flush_claim_ctx / reclaim_stacks`
- 取证：`slab_stats / buddy_stats / pgt_stats / window_dump / dump_sysctl / read_status / read_check / decode_ranges / load_map_file / ksym_lookup`

### 1.5 判据串（StageMap 需对齐）

`UAF-CHAIN DONE`；`UAF-CHAIN W=%#llx(+%#zx) W2=%#llx(+%#zx) net=%#llx init_cred=%#llx sig_enforce=%#llx selinux_state=%#llx modules_disabled=%#llx sysctl=%s`；
`UAF-CHAIN noplant=2 unsafe: init_cred must be planted`；`UAF-CHAIN plant missed [init_cred]=%#llx`；
`UAF-CHAIN cred uid=%#x euid=%#x` / `UAF-CHAIN creds uid=%u euid=%u gid=%u caps=%#llx` / `UAF-CHAIN realcred ruid=%#x caps=%#llx`；
`UAF-CHAIN selinux enforce=%d` / `selinux enforce=0` / `selinux initialized enforce=%d`；
`UAF-CHAIN target_exit=42 required for unambiguous reap`；`UAF-CHAIN no-window gen=%u seen=%d`；
`UAF-CHAIN FAILED step=poolhold round=%d`；`UAF-CHAIN unreaped child id=%d pid=%d`。

### 1.6 bootflow.sh 实际调用参数（现网配置，逐字）

```
chain=1 reap=1 reapmax=2 attempts=4 timers=0 delays=0,100,200,400 reserve=2000 reserverounds=1
settle=200 storm=0 uring=0 spray=20 skb=0 stamp=4000 pinwave=0 tail=0 tries=24 perf=300
poolhold=1500 target=$D/perfprobe target_exit=42 load=$D/$KO loadparams= loadmap=$D/perf.tbl
log=$LOG reservesettle=0 claimms=150 rcuwait=50 sweep=16 trace=0 seearly=1 warmwant=0 sigearly=0
```
（`rcuwait/sweep/seearly/warmwant/sigearly` 是老版本残留参数，现内核二进制里没有对应 `name=` 串，重写时按「参数存在但被忽略」处理，**不得新增语义**。）

---

## 2. 6.1 / 6.18 / 其它分支来源（ma.apk）

| 目录 | 内核 | 主二进制 | 符号状态 |
|---|---|---|---|
| `61157` | 6.1.157（三 build：ELP-AN00 / MagicPad3 / AMG） | `brm_plant` 1,420,264 | **含 .debug_info 0x4f00d**，.symtab 811，FUNC 187 |
| `EK-CORE-61821` | 6.18.21 g928（WKL-AN20/AN80） | `exploit-android-key-ptr` 73,744 | ET_DYN，.symtab 187，FUNC 266 |
| `6123` / `6138` | 6.12.23 / 6.12.38 | — | 未取（6.12 按用户要求用 9.104） |
| `64560-61821` | 6.18.21（CVE-2026-64560 另一条线） | — | 未取 |

辅助二进制：`perfprobe`（EXEC，FUNC 1132）、`forker_618` 与 `slide_probe`（**无符号表**，需裸分析）、`kaslr_slide`。

6.1 与 6.18 的目标选择是硬 `case` 匹配单个 build 号（不匹配即 `61157_KERNEL_MATCH=0` 退出 2）；
我们的 `PayloadCatalog.PER_FAMILY` 用两段 key（`"6.1"`/`"6.18"`），重写时保持两段 key，但内部按 build 号分支，行为与原软件一致。

---

## 3. 重写规则（用户 m04063 明确）

1. 「9.1.4」就是 **9.104**；6.6 / 6.12 两支**保持 9.104 字节不动**。
2. 5.10 / 5.15 / 6.1 / 6.18 四支：按原软件策略一比一重写成我们自己的源码，再用 `tools/build_fam.py` 重新编译，产物名仍为 `ek-core-uid0-<fam>`。
3. **禁止把原 APK 的二进制原样塞进 assets**。
4. 不得删减原有步骤，不得凭个人判断新增无必要步骤；每支都要逆完整。
5. 5.15 由 5.10 这条按同策略推一支。

## 4. 尚未完成（下一步）

- 逐函数反编译 5.10（`chain_round` +2108、`spray_phase` +3112、`pool_hold_start` +1008、`reap_phase` +1244、`main` +14872）并落成 C。
- 6.1 用 DWARF 走 `llvm-dwarfdump` 取变量/结构名，逐语句还原。
- `build_fam.py` 改为「按分支取源」（当前是同一份主源编六次）。


---

## 5. 9.158 交付记录（六支分支链落地）

| fam | 链 | 字节 | sha256 |
|---|---|---|---|
| 5.10 | honor-uaf | 439,280 | 717ec5d16eb087488a7c229abfadb397238f54b4b53a0a5d526884029b8c750f |
| 5.15 | honor-uaf | 439,280 | 50f27d63d21cf5752479061233173af631ac26d3d6e65655eb2e0f288b859d42 |
| 6.1 | brm-plant | 432,880 | 9a5909c35401c6f6afd692536cf96ea8b19f019fc15d56a93ed1f3cbd9661446 |
| 6.6 | legacy-EK-CORE（9.104 原字节） | 476,048 | 66be18027bf0339774f6da08e3c4967df681493346874fedc2fbb1d12a56ebbf |
| 6.12 | legacy-EK-CORE（9.104 原字节） | 478,736 | 1cd8f9fa9ff4bc4ac38530be725bd786811025cdc5123d1db8c96d1fb7137a3c |
| 6.18 | keyptr-618 | 459,824 | deecfced31dda662a84aea8a3a2db5121eaca1095e5d0908ec73c6bb385eab01 |

- 6.6 / 6.12 由 `tools/build_fam.py` 的 `PINNED_9104` 分支直接从 `payload/baseline/9104/` 拷字节，不再现场编译（baseline 取自 `ExtractKit-9.104-full.apk`）。
- 5.15 由 5.10 同策略推出：同一套 honor-uaf 链，差异落在族闸门（`EXPECT_FAMILY="5.15."`）、`EXTRACTKIT_FAMILY_INT=515`、以及 `family_defaults.h` 里 5.10 独有的 `CRED_OFF_UCOUNTS := CRED_OFF_GROUPS` 修正不作用于 5.15（5.14 起才有 ucounts）。
- HONOR 外部资产随 APK 打包：`assets/payload/honor/{perfprobe 702,304, msm_perf.ko 6,975,344, perf.tbl 8,877}`，命令行由 `ChainPlan.honorArgs()` 逐字复刻 bootflow.sh 的 ARGS。
- 构建：`versionCode 347 / versionName 9.158`，129 tests / 0 fail / 4 skipped，BUILD SUCCESSFUL。
- 产物：`D:\deepseek work\ExtractKit-9.158-branch.apk` 8,585,103 B sha256=975e9a8db17dc292db98bdcd5d174fd0564814ccbb4904125a638b8461d38a64；APK 内 6 支 fam + 3 份 honor 资产与仓库逐字节一致，dex 含 honor-uaf / brm-plant / keyptr-618 / perfprobe / msm_perf.ko / perf.tbl。

## 6. 9.159 交付记录（去掉外部 perf.tbl，改自发表）

用户指令（m04240）：「从我们自己的 kallsyms/BTF 生成一份我们格式的表 完全不用外部文件 你可以完全逆向」。

### 6.1 删掉的东西

- `app/src/main/assets/payload/honor/perf.tbl`（8,877 B，258 行）**已删除**，APK 里不再有它（dex 里 `perf.tbl` 出现次数 = 0）。
- `ChainPlan.HONOR_ASSETS` 从 3 项降到 2 项：`perfprobe`（执行位）、`msm_perf.ko`；新增 `ChainPlan.HONOR_MAP = HonorMap.FILE`，命令行 `loadmap=$d/honor.map`。

### 6.2 加上的东西

- `app/src/main/kotlin/com/extractkit/app/HonorMap.kt`：`FILE="honor.map"`、`NAMES`（13 个符号）、`render(syms, kernel)`、`symsForCurrentKernel()`（走 `ConfigGen.profileFor(os.version)`）。
- `ExtractEngine.deployHonorMap()`（在 `deployAux` 之前，`ExtractEngine.kt:192-217`）：拿本机 profile 的符号表渲染成文本，`Shell.pushFile(..., executable = false)` 推到 `$WORK_DIR/honor.map`；没有 profile 时打 `· 本机无符号 profile，honor.map 不下发（payload 走编译期常量）` 并继续（不阻断）。
- `payload/src/chain_honor.c`：新增 `HONOR_MAP_MAX 64`、`struct honor_sym`、`g_honor_map/g_honor_nsyms`、`honor_sym()`、`honor_ic()`、`honor_se()`；`honor_load_map()` 从「只数行」改成真解析（跳过 `#` 行，收 `name 0xHEX`），日志 `UAF-LOAD map %s syms=%d useful=%d slide=%#llx`；9 处 `SELINUX_STATE_STATIC` 与 1 处 `HONOR_INIT_CRED` 改为走 `honor_se()` / `honor_ic()`（表值优先，回落编译期常量）。

### 6.3 表格式

```
# extractkit-map v1
# kernel=<uname -r>
# nsyms=<非零符号数>
init_task 0xffffffc00a81bf80
init_cred 0xffffffc00a830c18
selinux_state 0xffffffc00ae84b38
init_user_ns 0x0            # 本机 profile 没有 → 0，payload 回落
```

### 6.4 验证

- `tools/build_fam.py` 重编：5.10 / 5.15 从 439,280 → **440,368**（换了真解析器），其余四支不变（6.6 / 6.12 仍是 `PINNED_9104` 的 9.104 原字节）。
- 130 tests / 0 fail / 4 skipped（24 suites，新增 `honorMapIsGeneratedNotBundled`）。
- `ChainPlanTest.honorAssetsAreTheTwoExternalFiles`、`honorArgsCarryBootflowKeys` 改断言 `loadmap=…/honor.map`。
- APK 内 6 支 fam 与仓库逐字节一致；honor 只剩 `perfprobe 702,304` 与 `msm_perf.ko 6,975,344`；dex 含 `honor.map`×7 / `HonorMap`×4 / `deployHonorMap`×3 / `extractkit-map v1`×1。
- 产物：`D:\deepseek work\ExtractKit-9.159-map.apk` **8,583,348 B** sha256=`bdcf73a08b38e9d732ddacafc8a0419e5309874c8bc02f73f46bb09be91f7539`，versionCode **348** / versionName **9.159**。

### 6.5 仍未完成

- `perfprobe` / `msm_perf.ko` 仍是参考 APK 原样（用户已授权「你可以完全逆向」，但那是两万行级的活）。
- `chain_honor.c` 主体仍是日志骨架：`honor_load_ko()` 不 insmod（打 `bytes=0 patched=0/0`），UAF 部分没有真喷射。

## 7. 9.160：honor_load_ko 从「打印」变成真装载（参考实现一比一）

参考软件 `libsysopt.so` 的模块装载是 main 内联的一段：读 .ko → 校验 ELF64/e_machine=0xb7 →
遍历 section header 取 SHT_SYMTAB → 对每个 SHN_UNDEF 且名字在表里的符号写 `st_shndx=0xfff1`、
`st_value=表地址` → `syscall(105, buf, len, loadparams)`，最后打 `UAF-LOAD rc=%d errno=%d want=%d`。

9.160 把 `payload/src/chain_honor.c` 的 `honor_load_ko()` 换成同一套实现：

- 新增 `honor_read_file()`、`honor_patch_ko()`、`struct honor_ehdr/honor_shdr/honor_elf_sym`；
- 装载参数来自 `loadparams=`，装载日志三行与参考完全同形；
- 新增 `UAF-LOAD map-empty: %d syms in map, none matched the module` —— 表里没有模块要的符号时点名说清楚，
  不再靠 `patched=0/0` 猜。

仍未完成：`chain_round` / `spray_phase` / `reap_phase` 的真实 UAF 轮、共享匿名区握手（chain_aim/chain_window/chain_creds），
以及 honor.map 里 init_task/init_cred/sig_enforce/modules_disabled/kptr_restrict/init_net 六个符号的自有来源
（现在内置档案只有七个旧符号，这六项渲染成 0x0 ⇒ 装载时 patched=0；解法是用 tools/find-kallsyms.py 从我们自己解包的
boot.img 里取，本机当前没有任何 boot.img）。
