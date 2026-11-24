# TimerRoot(timeer.apk) 提权线路逆向 与 ExtractKit EK-CORE 对照

- 分析对象：C:\Users\Admin\Downloads\timeer.apk
- 体积/sha256：13,205,533 B / 2fa259467afd426baecaff42daca9e61e09fe5ddcd7c596a259fb9517c8cd371
- 包名/版本：com.tencent.timeroot，7.3 (versionCode 1977)，产品名 TimerRoot 7.x
- 结构：531 个条目 / 438 个节点；dex = classes.dex（+ baseline.prof/profilem）；so = lib/arm64-v8a/{libconscrypt_jni, libspake2, libtimer49, libfast_gx61, libfast_gx62, libfast_gx62_test, libfast_gx71, libfast_gx76}.so
- 本文所有行号指 jadx 反编译产物 C:\Users\Admin\AppData\Local\Temp\timeer_jadx\sources\com\oplus\timeroot\MainActivity.java（1,690,645 B 单一混淆类）等文件；所有 payload 结论来自 assets/timeroot/* 的静态串（工作副本 C:\Users\Admin\AppData\Local\Temp\timeer_ex\assets\timeroot\）。
- 复现命令：REA open_binary(path=...) -> inspect_artifact(detail="summary") 取 parent_evidence_id -> inspect_analysis_view{source:{kind:"retained-evidence",evidence_id:...}, view:{kind:"inventory",collection:"occurrences"}} -> extract_artifact{output_root, occurrence_ids}；dex 侧用 jadx 1.5.6（jadx -d <out> --no-imports --deobf timeer.apk）。

---

## 1. 摘要

TimerRoot 与 ExtractKit 打的是同一个洞（EK-CORE，k_itimer 内嵌 timer 节点 UAF），但工程化路线完全不同：

1. 驱动面：TimerRoot 走 Shizuku 或无线调试配对（App 自带 adb 客户端）；ExtractKit 走 adb 直连。
2. 偏移来源：TimerRoot 的 payload 在目标机上读 /sys/kernel/btf/vmlinux 现场推结构偏移，档案（profile）只补绝对符号地址与 page_offset；ExtractKit 的偏移来自 device.cfg / 编译期常量，BTF 只存在于 Kotlin 标定侧（Btf.kt），payload 运行时不读 BTF。
3. KASLR：TimerRoot 用 sched_blocked_reason 事件里泄漏的内核地址对整张符号表投票（votes>=8、observed>=800、跨轮一致、按内核缓存）；ExtractKit 在 payload 内用 7 个调度器锚点做小规模投票（votes>=3/anchors>=2），默认锚点只对 BSN-AN00 准。
4. 回收：TimerRoot 分 cred（换 node+off）与 tile（整页目标）两模式，页/缓存事件只作旁证；ExtractKit 走 mm_page_free/mm_page_alloc 页级窗口 + cred 覆写，hit=0 直接放弃。
5. 落地：TimerRoot 提权后起 unix-socket rootd 常驻（/data/local/tmp/tEK-CORE-root.sock），并由载荷自己执行 ksud late-load（EXIT_AFTER_KSU=1）；ExtractKit 是子进程 setresuid + 外部 ksud。
6. 覆盖面：TimerRoot 有 7 个模型 x 21 份符号表 x 54 行机型映射表；ExtractKit 是 1 个主源 + 6 支 family（5.10/5.15/6.1/6.6/6.12/6.18），缺"同一 family 多个 build"这一维度。

结论：ExtractKit 在"零外部依赖 + adb 直连"上更强，在"跨内核自适应"（运行时 BTF、全表 slide 投票、release 矩阵）与"提权后常驻/加载管理器"上明显落后。本文第 7 节给出 5 项移植清单。

---

## 2. TimerRoot 线路全图

六阶段，正常总时长约 3.9 s（manual.html 六步文案）：

    连接设备 -> 部署载荷 -> 抓 slide(KASLR) -> 触发 UAF/提权 -> rootd 常驻 -> ksud late-load -> 验证

### 2.1 连接设备
- manual.html：连接方式二选一——无线调试（6 位配对码，App 自带 adb 客户端）或 Shizuku。
- Shizuku 封装 p066p0.C1328c：m2011h() 连接判定、m2016f(path,byte[]) 写文件、m819E1(cmd,timeoutMs) 执行；MainActivity.java:18217 未连接时提示"Shizuku 未连接，点「连接 Shizuku」"（原文含直角引号）。
- 无线调试相关类：PairSearchService.java、PairingReceiver、PairCodeReceiver。

### 2.2 部署载荷
- MainActivity.java:18241：mkdir -p <A1>/timeroot；pkill -9 -f tEK-CORE_plant；pkill -9 -f tEK-CORE_su；sync。
- MainActivity.java:18243：str = "syms-" + m770P0() + ".txt"，按目标机内核串选符号表；18254 只挑 syms- 前缀条目。
- MainActivity.java:18287：远端 stat 大小 == 本地则跳过（增量推送）。
- MainActivity.java:18291：二进制先写 <name>.new 再 cp -f 原子替换；tEK-CORE_plant / tEK-CORE_su 例外直接写。
- 载荷清单（assets/timeroot/）：runEK-CORE.sh 1524 B、take_slide.sh 1017 B、prep_solve 372,968 B、tEK-CORE_plant 409,824 B、tEK-CORE_su 367,720 B、forker 367,304 B、be_trigger 375,552 B、21 份 syms-<kernel>-<git>-4k.txt。

### 2.3 抓 slide（KASLR）
MainActivity.java:18860-19058，最多 3 轮：
- 18893：cd <A1>/timeroot && sh take_slide.sh（超时 260000 ms）
- 18899：./prep_solve . syms.txt（超时 150000 ms）
- 正则取值：votes=(\d+)、anchors=(\d+)、observed=(\d+)、slide=(0x[0-9a-fA-F]+)；要求 slide 非空且跨轮一致，19029 判 votes>=8 才接受。
- 成功后 19137 写 SharedPreferences 的 slide_cache / slide_boot（按内核缓存，下次直接复用）。

take_slide.sh（25 行）采样参数：
    echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable
    echo 16384 > /sys/kernel/tracing/buffer_size_kb
    tracing_on = 1
    for c in 0..7: cat per_cpu/cpu$c/trace_pipe_raw > bl_$c.bin &
    sleep 1
    for i in 1..400: ./forker 4 30        # 4 线程 x 30，批量制造 sched 事件
    打 SLIDE_CAP_FORKED=400x4
    grep sched_blocked_reason trace > bl_text.txt
    pkill -f trace_pipe_raw; tracing_on = 0
    打 CAP <size> <file> 与 SLIDE_CAP_DONE lines=...

runEK-CORE.sh（53 行）四步 + 硬闸：
    [1/4] timeout 240 sh take_slide.sh
    [2/4] timeout 120 ./prep_solve . syms.txt
          无 slide.txt -> SOLVE_FAIL exit 11
          slide 为 0x0/0/空 -> ABORT exit 12
          OBS < 800 -> "ABORT 样本太少，slide 不可靠" exit 13
    [3/4] ./tEK-CORE_plant --slide X > plant.log &；轮询 150 次 grep ROOTD_LISTEN；没起 -> exit 14
    [4/4] ./tEK-CORE_su "/data/adb/ksud late-load --allow-shell"
          grep -i kernelsu /proc/modules；getenforce；su -c id

### 2.4 触发 UAF / 提权
MainActivity.java:19171-19257：
- 自定义方案：档案写到 <A1>/.trprofile.txt 并 chmod 644，19178 追加 --profile <A1>/.trprofile.txt；未选档案 -> 提示"没有选中档案"并跳过后续 5 个阶段。
- 19193：pkill tEK-CORE_plant；删 <A1>/tEK-CORE-root.sock 与 plant.log。
- 19199：读 <A1>/timeroot/page_offset.txt，形如 ^0x[0-9a-fA-F]+$ 时追加 --page-offset。
- 19206：选了 root 管理器时追加 --ksu <A1>/timeroot/ksud。
- 19223 主命令：
    cd <A1>/timeroot && setsid ./tEK-CORE_plant --slide <hex> [--page-offset <hex>] \
      [--profile <A1>/.trprofile.txt] [--ksu <path>] > plant.log 2>&1 < /dev/null &
- 19235：轮询 150 次 grep -q -e ROOTD_LISTEN -e 'KSU_OK=1' plant.log；19239 pgrep -f tEK-CORE_plant 判存活。

### 2.5 落地（rootd + ksud）
- rootd：unix socket /data/local/tmp/tEK-CORE-root.sock；日志 ROOTD_LISTEN path=%s pid=%d、ROOTD_READY path=%s child=%d。tEK-CORE_su 只是 socket 客户端（strings 里只有 "connect rootd" 与 socket 路径，不装 su 二进制）。
- ksud：载荷内部执行（KSU_RUN=%s、KSU_TRY=%d rc=%d live=%d、KSU_OK=1 / 0 / (already)、KSU_SKIP=no-ksud、EXIT_AFTER_KSU=1；候选路径 /data/adb/ksud 与 /data/local/tmp/timeroot/ksud；活体判定读 /proc/modules 里 kernelsu）。
- App 侧：MainActivity.java:19278 解析 KSU_VERIFIED=(\d+)（19292 KSU_RC=(-?\d+)），KSU_VERIFIED==1 -> 提示"KernelSU 由载荷直接加载完成"。

### 2.6 验证
manual.html 六步末项"验证"：su -c id（runEK-CORE.sh 第 [4/4] 步）、getenforce、/proc/modules 查 kernelsu。驻留进程信息（pid=...）属正常，重启后消失。

---

## 3. payload 能力清单（tEK-CORE_plant，409,824 B，静态 ELF，含 jemalloc/pthread 桩）

用法串：usage: %s --probe | --calib-page | --slide <hex> [--profile <path>] [--page-offset <hex>] [--budget <sec>]，另有 --calib-slide。

### 3.1 自检
PROBE_OK、PROBE_TRACE=%s bytes=%zu、PROBE_RSS=yes/no、PROBE_TRIGGER=yes/no、PROBE_SELINUX、PROBE_KERNEL、PROBE_UID=%u、PROFILE=%s keys=%d release=%s。

### 3.2 对象与偏移
- UAF 对象：k_itimer 内嵌的 timer 节点（k_itimer、kitimer_node、timer_link、LEAK_TIMERS n=%d、RETRY=leak-timers n=%d、RETRY=timers、CALIB_TIMERS=%d）。
- 偏移来自运行时 BTF：/sys/kernel/btf/vmlinux -> BTF_TASK_CRED=%d、BTF_KITIMER_NODE=%d、BTF_TASK_SIZE=%d；档案键 task_cred / kitimer_node / timer_link / selinux_link / page_offset / user_ns。没有硬编码结构偏移。

### 3.3 tracefs 面
- 用到的节点：/sys/kernel/tracing/events/kmem/rss_stat/{trigger,enable}、enable_event:kmem:kmem_cache_alloc、events/kmem/kmem_cache_alloc/id、trace、per_cpu/cpu%d/{trace_pipe_raw,trace_pipe}、tracing_on、buffer_size_kb；回退路径 /sys/kernel/debug/tracing/...。
- 消费事件：kmem:mm_page_alloc、kmem:mm_page_free、kmem:kmem_cache_alloc（与 ExtractKit 同族事件）。
- 写 rss_stat/trigger 是为了在无自然事件时造出可观测事件（我方的 AIO 写页 / census 也是同类思路）。

### 3.4 slide 侧输出
SLIDE=%#lx site=%#lx hits=%d、SLIDE_HITS=%d、SLIDE_EVENT_ID=%d RAW=%zu TIMERS=%d、SLIDE=%#lx PAGE_OFFSET=%#lx BUDGET=%llds、SLIDE_ERR={calloc,malloc,range,align,raw-read}、SLIDE=none、CALIB_ERR=trace-read；页面标定 CALIB_PTRS=%d CALIB_PFNS=%d、CALIB_PAGE=%#lx votes=%lu/%d、CALIB_PAGE=none；锚点侧 votes/anchors/observed 由 prep_solve 打。

### 3.5 回收侧输出
两种模式：RECLAIM_MODE=cred node=%lx off=%#x、RECLAIM_MODE=tile off=%#x target=%lx；证据 RECLAIM_WRITES=%d HIT=%d base=%lx、RECLAIM_FREED=%d cpu=%d base=%lx。

### 3.6 提权与 SELinux
CRED_INSTALLED=%#lx attempt=%d、CRED_REPORT=%s、FAIL=cred-pattern、WARN=fork cred child failed、ROOT uid=%u caps=%llx、SELINUX=%s / SELINUX=already / SELINUX_MISS=%d / SELINUX_TRY=%d / SELINUX_TRY_BEGIN state=%d（写 /sys/fs/selinux/enforce）。

### 3.7 辅助件
- forker（367,304 B，glibc 静态）：take_slide.sh 里 forker 4 30，批量造 sched_blocked_reason 事件。
- be_trigger（375,552 B）：另一种事件发生器；C0323b1.java:62 setsid ./be_trigger 50000 > be.log 2>&1 &，pgrep -x be_trigger 判活。
- prep_solve（372,968 B）：吃 take_slide.sh 抓到的 raw + syms.txt，投票解出 slide。
- tEK-CORE_su（367,720 B）：rootd 客户端。

---

## 4. 档案与符号表

### 4.1 档案键集合
- C0342h1.java:485 键序：{timer_link, task_link, selinux_link, <4 个未知键>, task_cred, kitimer_node, task_alloc, page_offset}
- C0342h1.java:1102 另一组遍历：{task_cred, cred_ucounts, kitimer_node, task_alloc, page_offset}
- 即"结构内偏移 + 关键全局符号 + page_offset"两类混合，payload 侧用 BTF 兜底。

### 4.2 三条取符号路
1. C0342h1.java:1174/1637/2104：C0325c.m989b(readBytes(new File("/proc/kallsyms")))
2. C0342h1.java:625：符号地址全 0（kptr_restrict）时提示"符号地址全是 0，这份 kallsyms 被 kptr_restrict 抹了，改用 vmlinux 的符号表"
3. C0342h1.java:822：落 derive_boot.img 走 boot.img 内内核；358/361/364 "从 OTA 包里提取 boot.img"；942/1424/1891 "这个镜像里读不到内核版本，请选 boot.img（不是 init_boot）"

### 4.3 kallsyms 还原器 C0325c.java（489 行）
- 第 8 行固定 13 个必需符号：do_timer_create、prepare_creds、selinux_state、init_user_ns、root_user、init_groups、init_ucounts、init_task、init_cred、empty_zero_page、kmalloc_caches、anon_pipe_buf_ops、sysctl_bootid。
- m989b(byte[])（66-421）步骤：
  1. m988a(hay,needle,from) 先定位 "func_" / "init_" / "_text"；
  2. 按 256 项 token 表（NUL 分隔）切出 kallsyms_token_table；
  3. 向前扫 offsets 表，候选长度 3000/2000/1500/1000/800/600/500/400/300/256，要求单调递增且首元素 > 0；
  4. num_syms 取 offsets-4 处 u32，范围 1000..900000，且要求 (num_syms + 255) / 256 == offsets.length；
  5. relative_base 取 num_syms 前 8 字节对齐处 u64；
  6. 每项 8 或 4 字节（由 8*num_syms <= 剩余空间 决定），bit7 走 varint 双字节长度；
  7. 名字由 token 索引拼装；地址 = 相对偏移 + relative_base；只保留 13 个必需符号。
- 返回值 (release, Map<name,Long>)；release 由 m990c(byte[])（425-481）扫 "Linux version " 取 <=96 字节可打印串，校验首字符数字、含 '.'、不含 '%'。

### 4.4 随包产物
- 21 份 assets/timeroot/syms-<kernel>-<git>-4k.txt，格式 "<hex> <type> <name>"，样例 ffffffc08211e280 T init_task（含 init_task、init_cred、selinux_state、misc_list、uhid_misc、uhid_fops、ashmem_ioctl、kmalloc_caches、anon_pipe_buf_ops、sysctl_bootid 等）。
- assets/支持机型.txt 54 行：build id -> 机型，含"按内核版本匹配"兜底。

### 4.5 内置档案加密 profiles.enc
MainActivity.java:11020-11143：
- 取 signingInfo.getApkContentsSigners()[0].toByteArray()（API < 28 用 signatures[0]）；
- SHA-256(sig) 必须等于 C492BF44E6B3A4D7F0FAAF3864C014EC92D79994215C5D1A1CF75D6754C04443，否则"签名不匹配，内置档案不可用"；
- key = SHA256(SHA256(sig)) 前半 16 字节，iv = 其后 16 字节，AES/CBC/PKCS5Padding 解密；
- 明文结构：循环 [u16 nameLen][name][u32 bodyLen][body]（UTF-8），越界即停 -> C0261a(name, body)。
- 结论：重打包即失效，属对方资产，本次不做解密（范围外）。

---

## 5. 多模型矩阵

MainActivity.java:2553 七个 key（注意末项拼写 falsh）：
| key | 显示名 |
|---|---|
| fast | 7.6-fast |
| fast71old | 7.1-fast |
| fast62 | 6.2-fast |
| fast61 | 6.1-fast |
| fast2 | 6.2-test |
| fast49 | 4.9-fast |
| falsh | flash |

- Root 管理器（2543/2547）：ksu -> KernelSU/me.weishu.kernelsu；next -> KernelSU Next/com.rifsxd.ksunext；suki -> SukiSU/com.sukisu.ultra；baka -> BakaSU/com.resukisu.resukisu；fina -> FinaSU/me.yuki.fina。
- 资产选择（7796-7811）：fast49 -> fast/timer4.9；fast61 -> fast/fast_61；fast62 -> fast/fast_gx62；fast2 -> fast/fast_gx62_test；default -> fast/fast_gx71；推到 /data/local/tmp/<A1>/timerfast_v<versionCode>（变量名 fastroot_62_v / fastroot_gxt_v / fastroot_gx_v），MD5 去重，chmod 755。
- 7948-7963：libfast_gx71.so 在 nativeLibraryDir 且 canExecute -> "已在本地执行7.1-fast模型"，否则写 /data/local/tmp 再 chmod 执行。
- 4867-4873 / 6547-6555：直接执行 <nativeLibraryDir>/libfast_gx76.so（或 libfast_gx61.so）当程序用（<abs> rootd 'id' 判 uid=0）——payload 以 .so 形态打包，绕开 assets 落盘 + chmod。
- flash 告警：13451 "内置符号表只对应 6.6.118-android15-8-g9bc34d5b0c79，当前内核是 <X>，flash 大概率解不出 slide"；18661/20786/21933/22851 "注意：flash 的 plant 只在 6.6.118 上验证过，这次是试跑"。
- 进程清理：6944/6992 ps 过滤 timerfast|fastroot|exploit64560|ghostlock|timerEK-CORE|ic-|libfast_gx。

### 5.1 粒度对照：TimerRoot 是「build 级」，我们是「族级 + 运行期」

两边都自称「按内核分档」，但分的轴不是同一个：

| 维度 | TimerRoot（timeer.apk） | ExtractKit 9.145 |
|---|---|---|
| 分档单位 | **build**：`syms-<kernel>-<git>` 21 份（如 `syms-6.6.118-android15-8-g9bc34d5b0c79-4k.txt`） | **族**：5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18 六支 fam 二进制 |
| 模型/资产数 | 7 个模型 key（fast/fast71old/fast62/fast61/fast2/fast49/falsh）× 21 份符号表 × 54 行机型表 | 1 主源 + 6 族分支（`family_defaults.h` 编译期选默认） |
| 偏移从哪来 | 运行期读 `/sys/kernel/btf/vmlinux`（BTF_TASK_CRED / BTF_KITIMER_NODE / BTF_TASK_SIZE） | `device.cfg` > BTF（`--btf`）> 族默认层 > 编译期 6.6 真值 |
| 符号地址从哪来 | 内置 `profiles.enc` 档案（按 git hash 命中）+ 随包 21 份 `syms-*.txt` + kallsyms 还原器 | 只有 6.6 有真地址；未标定族把 8 个地址置 0 → 自动退 offsets-only |
| 缺档时的动作 | flash 告警「内置符号表只对应 6.6.118-…，大概率解不出 slide」，仍试着跑 | `EXPECT_FAMILY` 不符直接返回 3；未标定族拒绝 fake cred（0+slide 会 panic） |
| 覆盖面 | 每个 build 都有自己的地址，但只有 21 个 build | 每个族都能进，但只有 6.6 一族有可信地址 |

结论：TimerRoot 用**海量 build 档案**换「换机即准」，代价是维护 N 份符号表；
我们用**族级闸门 + 标定档案 + 运行期 BTF**换「换族不崩」，代价是未标定族只能走
offsets-only、拿不到 fake cred。两者不冲突：把 `device.cfg` 当成“一份 build 档案”，
我们也就具备 TimerRoot 那样的 build 级精度，只是不预置 N 份。

9.145 之前我们连「族级」都是名义上的：6 支只差 `-DEXPECT_FAMILY` 闸门串，偏移全
来自 6.6 的 `device_config.h`，`FAMILY_IS_61` 还是恒假的死分支（详见
`docs/EK-CORE-flow.md` §10）。现在族身份、族默认、标定状态三者由
`tools/check-fam.py` 与 `FamilyDefaultsTest` 钉住。

---

## 6. 逐段对照表

| # | 环节 | TimerRoot 做法 | ExtractKit 9.143 做法 | 差在哪 | 是否移植 |
|---|---|---|---|---|---|
| 1 | 驱动面 | Shizuku / 无线调试配对（App 自带 adb） | adb 直连 | 我方依赖更少 | 否 |
| 2 | 偏移 | payload 运行时读 /sys/kernel/btf/vmlinux（BTF_TASK_CRED / BTF_KITIMER_NODE / BTF_TASK_SIZE） | device.cfg / 编译期常量；BTF 只在 Kotlin（Btf.kt）标定阶段用 | 换内核要重标定，弱机易错 | 是（P1） |
| 3 | KASLR slide | 全符号表 + 400x forker 灌事件 + 8 核 raw 并行 + 投票 votes>=8 / observed>=800 / 跨轮一致 / 按内核缓存 | payload 内 7 锚点投票（EXTRACTKIT_SCHED_SLIDE，ek-core-uid0.c:1587-1636），votes>=3 / anchors>=2，默认 3 锚点只对 BSN-AN00 | 覆盖面与判定严格度都低 | 是（P2） |
| 4 | 回收 | cred 与 tile 两模式，页/缓存事件只作旁证 | mm_page_free/alloc 页级窗口 + cred 覆写，hit=0 中止 | 只押一条路 | 是（P3） |
| 5 | 落地 | rootd 常驻 socket + 载荷内 ksud late-load | 子进程 setresuid + 外部 ksud | 常驻通道缺失 | 是（P4） |
| 6 | 内核矩阵 | 7 模型 x 21 符号表 x 54 行机型表 | 1 主源 + 6 支 family（9.145 起带族默认层与标定闸门） | 缺"同 family 多 build"维度（build 精度靠 device.cfg） | 是（P3 的 ReleaseMatrix） |
| 7 | 交付形态 | payload 以 .so 放 nativeLibraryDir 直接跑 | assets 落盘 + chmod | 落盘可能被 tmp noexec / 杀软拦 | 否（仅文档 P5） |

---

## 7. 移植清单（P1-P5）

### P1 payload 运行时 BTF（已实现，默认开）
- 新增 btf_probe()：直接 open/read /sys/kernel/btf/vmlinux（ELF 头 -> .BTF section -> 类型表），只解析 struct 成员名，得 task_struct.cred 偏移、k_itimer 内嵌节点偏移、task_struct 大小。
- 优先级：cfg 显式值 > BTF > 编译期默认；--btf / --no-btf 开关（默认开）。
- 日志：[btf] task_cred=... kitimer_node=... task_size=...；失败 [btf] unavailable（可 grep，等价 TimerRoot 的 BTF_ 串）。
- 风险：BTF 无 CONFIG_DEBUG_INFO_BTF 时不存在 -> 静默回落，不改变旧行为。

### P2 slide 全表投票（已实现，需显式 --syms 才启用）
- 新增 --syms <path>：解析 "<hex> <type> <name>" 表，取若干稳定符号（init_task/init_cred/selinux_state/kmalloc_caches/...）的链接地址；
- 采样：8 个 per_cpu trace_pipe_raw 并行读 + 批量 fork 灌 sched 事件（对齐 take_slide.sh 参数）；
- 投票：候选 = 采样到的内核指针 - 表内地址，2 MiB 对齐计票；门限 votes>=8、observed>=800、两次采样 slide 一致；
- 输出 [syms] votes=... observed=... slide=...（不一致打 [syms] inconsistent）；不可用/票数不足 -> 回落锚点法（默认路径与 9.143 完全一致）。

### P3 回收双模式 + release 矩阵（已实现，tile 默认关闭）
- tile 模式：仅在 cred 模式失败后、且已有页级窗口证据（page-claimed-by-alloc）时启用；hit=0 时函数级直接返回，绝不在无窗口证据下写入。
- Kotlin：PayloadCatalog / StageMap 增 [tile]、[syms]、[btf] 三条 pattern 与 hint 文案。
- 新增 ReleaseMatrix.kt：release（如 6.6.118-android15-8-g...）-> fam 选择的显式映射，缺失回落现有逻辑。

### P4 rootd 常驻 + 内置 ksud late-load（已实现，需显式开）
- --rootd：提权后在 /data/local/tmp/<kit>-root.sock 起 AF_UNIX 服务（fork 子进程持有 cred 并执行命令），父进程继续驻留；打 ROOTD_LISTEN path=... pid=...。
- --exec "cmd"：客户端模式，连 socket 执行命令并回显，不依赖外部 su；App 可用 payload --exec id 验证 uid=0。
- --ksu <path>：载荷内直接 late-load，打 KSU_RUN=...、KSU_TRY ... rc=... live=...、KSU_OK=1|0；Kotlin 解析 KSU_VERIFIED。
- StageMap 增 ROOTD_LISTEN、KSU_VERIFIED 两条 pattern，RunModel 增对应阶段进度。

### P5 payload-as-.so（仅文档）
- TimerRoot 用 libfast_gx76.so / libfast_gx61.so 直接当可执行文件跑（nativeLibraryDir 天然可执行，免落盘免 chmod）。
- 我方可行性：需 extractNativeLibs=true 或 Android 10+ 的 useEmbeddedDex/解压策略配合；会让 APK 变大且 ABI 受限，本轮不实现，留作备选通道。

---

## 8. 附录：工具坑与复现要点

- REA：inspect_artifact 不接受路径参数，必须先用 open_binary{"path": 绝对路径}；空参 inspect_artifact 返回当前目标的 summary 与 parent_evidence_id；列条目走 inspect_analysis_view 的 inventory occurrences（字段 occurrence_id / logical_path / declared_size）；抽文件用 extract_artifact{output_root, occurrence_ids}。
- inspect_android_package 需要 REA_JADX_MCP_JAR，未配置时报 capability_unavailable -> 改用本地 jadx 1.5.6（19 个类反编译报错，不影响 MainActivity）。
- pwsh 内联正则剥 HTML 会返回空串：改成 read 读整文件后在脚本里剥标签。
- jadx 输出体量：MainActivity.java 1,690,645 B 单类；C0342h1.java 328 KB（档案生成）；C0371h.java 57 KB、C0364a.java 45 KB、C0325c.java 20 KB（kallsyms 还原）。
- 我方仓库注意：payload 只有 payload/src/ek-core-uid0.c 会被编译，payload/fam-src/6.6.c 与 payload/src/clean66/* 是孤儿文件；build_payload.py 编主源、build_fam.py 用同一份源编 6 支 -DEXPECT_FAMILY。
