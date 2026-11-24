# chain_honor.c 缺陷审计（9.163 代码基线 → 9.164）

> 结论：**当前这条 honor 链在真机上不可能提权成功**。不是「差一点」，是几处结构性的：
> 受害者没人杀、喷射的页立刻被 munmap、写页写的是我们自己的匿名页、窗口判据用错数据源。
> 下面每条都给代码行 + 参考实现对照，能逐条复核。

## P0 级（任何一条都足以让链失败）

### B1 目标进程被 SIGKILL 掉，参考要的是它自己 exit(42)
- 我们：`chain_honor.c:1458` `kill(pid, SIGKILL); waitpid(...)`，随后 `:1464` 打 status。
- 参考：`UAF-CHAIN target_exit=42 required for unambiguous reap`（@0x7d900）、`UAF-TARGET-CHECK only target_exit=42 is supported`，attempt(@0x402988) 里是 fork→waitpid 并校验 WEXITSTATUS==42。
- 为什么致命：posix_timers_cache 的对象是在**任务正常 exit 的 munmap/exit 路径**里释放的。SIGKILL 走的是 do_group_exit 的异常分支，timer 对象不一定进同一批 slab 释放；参考靠 status==42 来确认「那一次 exit 真的走完了」。
- 另外 `:1425` 的 `UAF-ATTEMPT ... exited=%d code=%d status=%d` 传的是常量 -1/0/0，日志从头到尾在骗人。

### B2 喷射函数把页立刻 munmap，等于没喷射
- `honor_spray_aio:495-516`：mmap 一页 → 打两条日志 → 比对 pfn → **munmap**。
- `honor_spray_uring:520-546`：连 mmap 都不用真的提交，只打 `UAF-URING-*` 日志。
- `honor_poolhold:550-583`：打 7 条日志 + mmap 一页再 munmap。
- 参考：spray_phase(@0x404aa4, 3112 B) 是真的 `io_submit`/`io_setup` 批量占用；spray_aio(@0x400xxx) 释放；pool_hold_start(@0x401620) 才是「扣住页」。我们这三支是**日志替身**，没有任何一页被留住。

### B3 写页写错了地址，而且随后被丢弃
- `honor_write_page:601-637`：mmap 一页新匿名页 → `pagemap_pfn(page) != pfn` 基本必然不成立 → 打 `UAF-WRITE no pfn` 返回 0；即使相等，`honor_tile_cred` 也只是往**我们自己的用户页**里写 0 和 ~0，然后 `munmap`。
- `:626` `ka = pfnbase + pfn * HONOR_PAGE`：pfnbase 传的是 `g_base`（内核镜像基址，0xffffffc0…），不是 direct-map 基址，算出来的内核虚拟地址是错的。
- 参考：写的是**被回收的 timer 对象所在页的内核地址**（chain_window 拿到的 W），不是新 mmap 的页。

### B4 窗口判据用错数据源
- `chain_honor.c:1468-1477`：用 `honor_slab_read("objects") > 0` 当「有窗口」，`UAF-WINDOW gen=%u n=%ld first=%#llx` 的 `first` 直接填 `honor_se()`（selinux_state 地址），`UAF-WIND-DONE prev=%#llx T=%#llx` 两个参数都填 `honor_se()`。
- 参考：窗口判据是共享区 `sh[0x70]`(ROUND_ACK)==gen（我方 `chain_window()` 已 1:1 实现，却没被调用），W 是 chain_window 返回的地址。

### B5 timer 受害者不是参考那套（pthread 替身）
- 我们 `honor_timer_thread:348-370`：pthread + `CLOCK_MONOTONIC` + `SIGEV_THREAD_ID` + `timer_settime(it_value.tv_nsec=1ms)`，线程退出（pthread_join）不释放 timer 对象。
- 参考 child_main(@0x4027c0)：`timer_create(CLOCK_THREAD_CPUTIME_ID, SIGEV_SIGNAL/signo=0)`、`it_value.tv_sec=3600`，然后 `pthread_create(thread_fn@0x402ee0)`、`clone(SIGCHLD|CLONE_VM, sibling_fn@0x402728)`，由 sibling_fn 自旋到 barrier 后 `tkill(getpid(), SIGSEGV)` **自杀**——靠任务死亡把 timer 对象还回 slab。
- 时钟源、sigevent、时长、退出方式四处都不同，回收的 slab 对象自然对不上。

## P1 级（会让日志结论错、或让链路自相矛盾）

### B6 `chain_aim` 的实参是时间戳
- `:1495` `chain_aim((uint64_t)honor_now_ns(), 0ULL)` → 写进 spray_pc/spray_left 的是纳秒时间戳。
- 参考两处调用都是从状态里取：`ldr x1,[x19,#0xb50]; ldr x0,[x19,#0xa40]; bl 0x401934`（W 与 left）。

### B7 已 root 判定打了假值
- `:1484-1486` `if (getuid()==0) logf("UAF-CHAIN cred uid=%#x euid=%#x", 0, 0)` —— 传常量 0，永远显示 uid=0x0。

### B8 喷射结果的判断极性反了
- `:1497` `if (!honor_spray_uring(...)) logf("UAF-STORM-STEP r=0 after-uring")` —— 成功返回 1 时**不**打，失败返回 0 时打 "r=0"；而且失败也照样往下写页。

### B9 `UAF-CHAIN W=` 一行 8 个参数全是填充
- `:1514-1520`：`SELINUX_STATE_STATIC + 0x100`、0、`honor_se()`、`honor_ic()`、0 反复填；参考这条是把 W、W2、init_net、init_cred、sig_enforce、selinux_state、modules_disabled、sysctl 逐个打出来。

## 顺带确认：不是 bug 的几处
- `honor_drop_uid()` 先 setresuid(2000) 是**对的**：参考 main 也是先 setgroups/setgid/setuid 再进链（要的就是无特权上下文）。
- 字符串层已 0 生造（`tools/check-honor-parity.py` 131/126/5/0），格式串不再是问题。
- 8 个 1:1 函数（chain_bm64/enforce/selinux_ready/caps/creds/window/aim/real_uid）本身没查出逻辑错。

## 修复路线（按依赖顺序，不是按大小）
1. **child_main + thread_fn + sibling_fn**（0x4027c0/0x402ee0/0x402728，共 1152 B）：把受害者换成「clone(CLONE_VM) 子任务 + 自旋 barrier + tkill 自杀」。没有这一步，slab 里永远不会有可回收对象。
2. **attempt**（0x402988，1368 B）：fork 目标 → 等 exit code 42 → 记录 dt/status；删掉我们的 SIGKILL+waitpid 版。
3. **spray_phase / reap_phase**（0x404aa4/0x403508，4356 B）：真实的 io_uring/AIO 批量占用与回收，替换 honor_spray_* 三个替身。
4. **chain_round**（0x4056cc，2108 B）：把上面三步按参考顺序串起来（slab_stats → pgt_stats → spray → release → reservoir → reap）。
5. 最后才轮到 chain_read_self / 写页（B3）：W 从 chain_window 拿，写到 direct-map 地址。

## 与 9.164 的关系
本轮只修了 B7 与 B8（纯日志/极性，不动机制），因为修 B1–B5 必须先把上面 5 个函数搬过来；
在那之前动 write_page 之类的只会制造「看起来修了」的假象。
## 9.165 修复：B5（受害者换成参考 clone+自杀模型）

删掉旧的 `struct honor_timer_ctx` / `honor_timer_arm` / `honor_timer_thread` /
`honor_spawn_target` 整块（原 chain_honor.c 索引 9383→11095），按
`D:\deepseek work\rev5x/libsysopt.dis` 逐条重写三个参考函数：

| 函数 | 参考地址/大小 | 我方实现 |
| --- | --- | --- |
| sibling_fn | 0x402728 / 152 | `sibling_thunk`：自旋 sh[0xc]==attempt+gen+1 → dmb → 自旋 now_us()-sh[0x10] < sh[0x18] → syscall(129 tkill, getpid, SIGSEGV) → sched_yield 死循环 |
| thread_fn | 0x402ee0 / 544 | `thread_fn`：prctl("uaf%02d") → timer_create(CLOCK_THREAD_CPUTIME_ID, SIGEV_SIGNAL) → sh[0x209c]=sched_getcpu() → timer_settime(3600s) → sh[4]=gettid → sh[0]=1 → 等 barrier → execve(target,{target,NULL},{"UAF_TARGET_EXIT=42",NULL}) |
| child_main | 0x4027c0 / 456 | `child_main`：prctl("lead") → signal(SIGSEGV,SIG_IGN) → 建 ntimers 个定时器（it_value=3600s）→ pthread_create(thread_fn) → 等 sh[0]!=0 → mmap(0x100000, MAP_PRIVATE\|ANON\|LOCKED\|STACK) → clone(sibling_thunk, top, 0x111) → sh[8]=pid → syscall(93 exit, 0) |

新增共享区偏移：`SH_OFF_ARMED 0x00` / `SH_OFF_TID 0x04` / `SH_OFF_PID 0x08` / `SH_OFF_CPU 0x209c`。
新增一轮封装 `honor_attempt_run(attempt)`：fork → 等 armed（最多 2s）→ 写
sh[0x10]=now_us、sh[0x18]=stamp、sh[0xc]=attempt+1 放行 barrier → waitpid → 判
`WIFEXITED && WEXITSTATUS==42`。判据不再是 kill(SIGKILL)（B1 也随之消失）。

**已知偏离**：参考里 barrier（sh[0xc]）、窗口起点（sh[0x10]）与时长（sh[0x18]）由
`chain_round`（0x4056cc / 2108 B，尚未移植）写；现在暂由 `honor_attempt_run` 写，
等 chain_round 搬完后要改回它写。

`debug=` 选项：参考 main @0x406b18 用 strncmp 匹配长度 6 的 key，写入
`debug_mode@0x4c2620`；我方 `g_hc.debug` → `g_debug_mode`，控制
`UAF-S-START` / `UAF-T-START` / `UAF-T-EXEC` 三条 debug 打印。

审计：`python tools/check-honor-parity.py` → 128 串 / 123 在参考 / 5 白名单 / 0 missing。

## 仍未修
- B2（spray_aio/spray_uring/poolhold 是 mmap+munmap 替身）、B3（write_page 写自己 mmap 的页）、
  B4（窗口判据仍未用 sh[0x70]）、P1（chain_aim 实参传 now_ns）。
  这些要等 attempt(0x402988)/spray_phase(0x404aa4)/reap_phase(0x403508)/chain_round(0x4056cc) 搬完。

## 9.166 修复：attempt 移植（去掉 9.165 的已知偏离）

- 参考 attempt() @0x402988（1368 B）本身就在 0x402a54 段写 sh[0x10]=now_us / sh[0x0c]=gen_base+attempt+1，**barrier 由 attempt 写**，9.165 的「barrier 由 chain_round 写」注记作废。
- 9.166 换上 1:1 版 honor_attempt(a, stamp_us, ntimers)：3s 等 armed（超时 printf `UAF-ATTEMPT %d no-thread` + kill -9）、写 barrier、waitid(P_PID, WNOHANG|WNOWAIT|WEXITED) 轮询 10s、`UAF-ATTEMPT %d delay=%d timers=%d exited=%d comm=%s dt=%ld code=%d status=%d`（comm 取 si_code/si_status → target-marker/no-marker）、debug 下 waitpid 打 `UAF-ATTEMPT-STATUS %d st=%#x sig=%d code=%d`、kids/kids_mark 记录（a<64）、最后 5s 内 waitpid(WNOHANG) 收孙进程。
- child_main 的 timer 数量改回读全局 g_ntimers（参考 0x4c2624），不再用自造默认 24；bootflow timers=0 时与参考一致地不建 timer。
- 仍待移植：reap_phase 0x403508(1244)、spray_phase 0x404aa4(3112)、chain_round 0x4056cc(2108)、chain_read_self 0x402458(112)、pool_hold_start 0x401620。

## 9.169：B2 部分修复

- `honor_spray_aio` 不再是 mmap→日志→munmap 的替身，已按 0x403b7c 重写成真实现（io_setup 建 ring、按 ring 头算页数、fill_page 逐页写槽、trapped 分支、register_region 记账）。
- 仍是替身、待移植：`honor_spray_uring`（参考 0x403de0 / 1236 B）、`honor_spray_skb`（0x403248 / 400 B）、`honor_poolhold`（参考 pool_hold_start 0x4013fc / 1008 B）。
- B3（honor_write_page 写自己 mmap 的页）与 B4（窗口判据）未动。

## 9.170：B2 再进一步

- spray_skb / spray_skb_waves / skb_per_pair 已按反汇编 1:1 落地，不再是 mmap+日志的替身。
- 仍缺 main 内联的 socketpair 建表循环（0x4c2978），所以 skb 路径目前发不出去包。
- spray_uring / spray_anon_early / spray_foreign / poolhold 仍是替身；B3（honor_write_page）与 B4（窗口判据）未动。

## 9.171：B2 的 socket 面补齐

- 建表循环按 0x407f40 落地，skb 路径现在真的有 fd 可发；仍缺 spray_uring / spray_anon_early / spray_foreign / poolhold，B3/B4 未动。

## 9.172：B2 收口 + pool_hold 全量

- 喷射侧替身全部清零：spray_aio / spray_uring / spray_anon_early / spray_foreign 都是参考反汇编直译，不再有「mmap 一页 + 打日志 + munmap」的风扇。
- pool_hold_start/child/stop 全量落地：PDEATHSIG + 20ms 间隔建 timer + 'R' 就绪握手 + SigQ 配额闸 + poll(n*20+100000) 超时杀子。
- reservoir_alloc 1:1（每 cpu 建 n 个 CLOCK_MONOTONIC timer 并 pin 到该 cpu）。
- 仍存：B3（honor_write_page 写自己 mmap 的页）与 B4（窗口判据未用 sh[0x70]==gen）。

## 9.173：统计门禁 + ERASE-SCAN + pin_create

- B2 残留：spray_uring / spray_anon_early / spray_foreign / pin / reservoir / pool_hold 已在 9.172 落地；本轮补齐 pin_create（真正按 cpu 补 timer）与 spray_phase 的 pinwave 段，不再有「mmap 一页打日志就 munmap」的替身。
- slab_stats / buddy_stats / pgt_stats 之前无条件打印，现在按参考加 verbose 与 marker 双门禁；pgt 只打 DMA32 行。
- UAF-ERASE-SCAN 首次实现：以前 chain_round 完全没有这一块。
- 仍未修：B3（honor_write_page 写自己 mmap 的页）、B4（窗口判据未用 sh[0x70]==gen）、honor_reservoir_flush 只有部分逻辑。

## 9.176：模块装载缺陷修复 + perfprobe 重写
- 真实缺陷（严重）：honor.map 之前只有 14 条链符号，而 msm_perf.ko 有 225 个 SHN_UNDEF；`honor_patch_ko` 只补命中项，其余 211 个仍是 UNDEF → `init_module` 必然 -ENOENT/EINVAL。现在表扩到 216 条（另 4 条安全 rename），装载前能补上的都补上。
- 未能解析的 9 条会在装载前逐条打 `UAF-SYM-MISS <name>`，现场日志可直接看出缺哪个。
- perfprobe 不再是外部 glibc 大件：改为我们自己的 30 行源码编译，行为（TGT-RAN/TGT-CHECK + exit42）逐指令等价。

## 9.177：修掉「模块装载必然失败」（按用户决定改走 ksud late-load）

- 缺陷：旧 `honor_patch_ko()` 只能补 honor.map 里有的符号，而 msm_perf.ko 有 225 个 SHN_UNDEF；FW135 上最多补到 220 个，`init_module` 必然 ENOEXEC/ENOENT 而失败，同时 `UAF-CHAIN DONE load=%s` 又会因为 `g_hc.load` 非空而误报成功。
- 处理：整块进程内装载删除，改 `honor_handoff_ksud()`；成败判据从「路径非空」改成「/proc/modules 里有没有 kernelsu」，日志也从 `load=<路径>` 改成 `load=ksud late-load`。
- 顺带清掉：`load=`/`loadparams=` 仍由 ChainPlan 传（保持与参考 bootflow 的键集合一致）但链里不再使用；`slide` 在本段不再需要。
- 仍未动：B2 的 uring/skb/poolhold 里 `slide` 相关计算保留原样，等真机验证再判断。
