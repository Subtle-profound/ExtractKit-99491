# chain_honor.c 保真审查（9.163）

> 目的：回答「是不是原文里的，而不是自己生搬硬造的」。
> 结论先说：**字符串层面已经可以机器化证明「全部来自参考二进制」；函数层面只完成 8 个 1:1 移植，其余仍是我们的外壳或尚未移植**。两者必须分开看，不能混为一谈。

## 1. 参考物

- 参考实现：`D:\deepseek work\rev5x\bin\libsysopt.so`（870,920 B，ELF64 EXEC，AArch64，来自 荣耀5系提权.apk 的 assets）。
- 反汇编/符号：`rev5x\funcs.txt`（821 个 FUNC）、`rev5x\libsysopt.dis`、`rev5x\fn\*.dis`、`rev5x\str_addr.txt`。
- 我们的实现：`payload/src/chain_honor.c`（42,698 B），只编进 5.10 / 5.15 两支 fam。

## 2. 字符串层面：0 条生造（可复跑证明）

工具 `tools/check-honor-parity.py`：抽出我们所有 printf/logf/puts/flog 的格式串，逐条在 `libsysopt.so` 的字节里整串查找。

    131 个格式串 -> 126 个在参考里逐字节存在，5 个在白名单，0 missing

5 条白名单（`tools/honor-parity-allow.txt`，每条写了理由）：

| 格式串 | 为什么必须留着 |
| --- | --- |
| `UAF-CFG %s=%llu` / `UAF-CFG %s=%s` | 我们自己的参数回显；参考实现由 bootflow.sh 传 argv，没有等价输出 |
| `UAF-CHAIN listening at %s pid=%d` | 我们自己的 root socket 监听回显 |
| `UAF-LOAD %s: %s` | 读 map/ko 失败的 errno 分支；参考在这些分支直接 return，不打日志 |
| `UAF-LOAD map-empty: %d syms ...` | 同上，map 里一个符号都没命中时的提示 |

本轮按参考原文改掉的（原本是生造的）：

- `UAF-LOAD map %s syms=%d useful=%d slide=%#llx` → `UAF-LOAD map %s syms=%d slide=%#llx`（@0x7c3d0）
- `UAF-LOAD not aarch64 ELF` → `UAF-LOAD %s: not an aarch64 ELF`（@0x7e040，并给 honor_patch_ko 补 path 参数）
- `UAF-LOAD sym %s = %#llx` → `UAF-SYM %s=%#llx`（@0x7e068）
- `UAF-SYM init_cred=%#llx` / `UAF-SYM selinux_state=%#llx` → `UAF-SYM %s=%#llx` + 名字参数
- `UAF-SYM note: no map loaded...` → `UAF-SYM-MISS %s`（@0x7c418）
- `UAF-PTHREAD-FAIL timer` → `UAF-PTHREAD-FAIL %s`（@0x7c8b8）
- `UAF-T-EXEC id=%d exit` → `UAF-T-EXEC id=%d %s`（@0x7ca60）
- `UAF-RD-BEGIN path=%s cap=%zu n=%d` → `... n=%zd`（@0x7ca90）
- `UAF-CHECK %s read=%d` → `UAF-CHECK %s read=%zd `（@0x7e530，尾部空格也照抄）
- `UAF-RECLAIM-IO skip-proc-sysfs=%d skip-aio-max=%d` → 字面 `...=1 ...=1`（@0x7d488）
- `UAF-ANON-EARLY mmap: ok pfn=%#llx` → `UAF-ANON-EARLY mmap: %s`（@0x7cc40）
- `UAF-CHAIN FAILED step=load round=%d` → `UAF-CHAIN FAILED step=%s round=%d uid=%u euid=%u caps=%#llx`（@0x7e3f8）
- 删掉自造的 `UAF-SH mmap: ok`（参考 main @0x4078b0 mmap 后直接存指针，不打日志）
- 删掉自造的 `UAF-SELINUX ready=...`，换成参考真两条：`UAF-CHAIN selinux enforce=%d`（@0x7e308）+ `probe errno=%d enforce=%d`（@0x7e2c0）

## 3. 函数层面：8 个已 1:1，其余尚未

工具 `tools/check-honor-funcs.py`：把 chain_honor.c 里 53 个 static 函数名逐个丢进 `funcs.txt` 找。

    53 个 static 函数 -> 8 个是参考里的原名（即已 1:1 移植），45 个是我们自己的

已 1:1（名字、语义、常量、日志都能指回地址）：

| 我们的函数 | 参考地址 | 大小 | 说明 |
| --- | --- | --- | --- |
| chain_bm64 | 0x400838 | 52 | sh+0x8c+x 的 8 字节大端 |
| chain_real_uid | 0x40086c | 48 | |
| chain_selinux_ready | 0x400928 | 88 | open(path, 0)，读 127 字节 |
| chain_enforce | 0x400980 | 120 | open(path, 0)，读 7 字节 + strtoq |
| chain_caps | 0x400bb4 | 80 | capget |
| chain_window | 0x40258c | 180 | 先比对→usleep(10000)→--tries |
| chain_creds | 0x402640 | 232 | |
| chain_aim | 0x401934 | 176 | 两参数，写 spray_pc/left + have_*，打 UAF-SHOT |

步骤名表 @0x4bc770（.data.rel.ro）已按 ELF 段表读出 12 项：redirect, plant, redirect2, cred, realcred, restore, selinux, seinit, sig, probe, mods, load。
（教训：vaddr→文件偏移必须走 PT_LOAD；该文件不是 addr-0x400000。）

## 4. 还没移植的参考函数（下一步清单，按参考地址）

| 参考函数 | 地址 | 大小 | 我们现在的替代物 |
| --- | --- | --- | --- |
| sibling_fn | 0x402728 | 152 | 无（我们还没写自旋/tkill 自毁那段） |
| child_main | 0x4027c0 | 456 | 部分在 honor_timer_thread / honor_spawn_target |
| thread_fn | 0x402ee0 | 544 | 部分在 honor_timer_thread |
| attempt | 0x402988 | 1368 | honor_attempt_tags 只是一行日志 |
| reap_phase | 0x403508 | 1244 | 无 |
| spray_phase | 0x404aa4 | 3112 | honor_spray_aio / honor_spray_skb / honor_spray_uring（自造，非 1:1） |
| chain_round | 0x4056cc | 2108 | honor_chain_body 的循环（自造） |
| chain_read_self | 0x402458 | 112 | 无 |
| pool_hold_start | 0x401620 起 | — | honor_poolhold（自造） |

也就是说：**「一比一」目前只兑现了 8 个函数 + 全部字符串；主体编排（attempt/spray_phase/reap_phase/chain_round/child_main）仍然是我们的骨架**，这是下一步要补的，不是已经做到的。

## 5. 9.163 产物

- `D:\deepseek work\ExtractKit-9.163-parity.apk` 8,585,492 B
- sha256 `ed843594d203993099c90b45de79ebaabe76b97cc8467038a38ee756ac56820c`
- versionCode 352 / versionName 9.163
- fam：5.10 442,096 B（07cc3362…）、5.15 442,096 B（041cd3b8…）、6.1 432,880（9a5909c3…）、6.18 459,824（deecfced…）、6.6 476,048（66be1802… pinned 9.104）、6.12 478,736（1cd8f9fa… pinned 9.104）
- 复跑校验：`python tools/check-honor-parity.py`（0 missing）、`python tools/check-honor-funcs.py`

## 9.165 追加：受害者三函数已 1:1

未移植清单里划掉三项，剩六项：

- [x] sibling_fn 0x402728 (152) → `sibling_thunk`
- [x] thread_fn 0x402ee0 (544) → `thread_fn`
- [x] child_main 0x4027c0 (456) → `child_main`
- [ ] attempt 0x402988 (1368)
- [ ] reap_phase 0x403508 (1244)
- [ ] spray_phase 0x404aa4 (3112)
- [ ] chain_round 0x4056cc (2108)
- [ ] chain_read_self 0x402458 (112)
- [ ] pool_hold_start 0x401620

已 11 个函数与参考同名同构（原 8 个 + 本轮 3 个）。

## 9.167 追加：reap_phase + chain_read_self

- [x] attempt 0x402988 (1368) → `honor_attempt`（9.166）
- [x] reap_phase 0x403508 (1244) → `honor_reap_phase`（9.167，含 fill_page @0x40349c、read_check @0x4009f8）
- [x] chain_read_self 0x402458 (112) → `honor_chain_read_self`（9.167）
- [ ] spray_phase 0x404aa4 (3112)
- [ ] chain_round 0x4056cc (2108)
- [ ] pool_hold_start 0x401620

已 14 个函数与参考同名同构。

9.167 事实补充：`reap_max`(0x4c2ba8) 与 `chain_mode`(0x4c25a0) 在参考二进制里没有任何写入点（只读），因此 reap 的模式判定块是死代码；`hold_ms`/`refill_mode`/`check_path` 的写入键 bootflow.sh 都不传，默认 0/NULL。我们按原样保留该块，参数从 `hold/refill/reapstop/noplant/rdcap` 键取（bootflow 不传即为 0）。

9.167 产物：`D:\deepseek work\ExtractKit-9.167-reap.apk` 8,587,464 B sha256=`a06bede0c4f1060f8ff5a3c72ede3248423f02e677fdbad0eb6193db781f8d68`；133 tests / 0 fail / 4 skipped；parity 137 串 / 132 在参考 / 5 白名单 / 0 missing。

`
## 9.168 追加：chain_round @0x4056cc（子集移植，未全量）

已按反汇编逐段落进 `payload/src/chain_honor.c` 的 `honor_chain_round()`：

| 参考地址 | 行为 | 状态 |
|---|---|---|
| 0x4059f4 | `gen_base = round_no << 6`（写 [0x4c261c]） | OK |
| 0x405a18 | `attempt(i, delays[i % ndelays], ntimers)`；marks[i] 命中且闸开则 `n = i + 1` 截断 | OK |
| 0x405a4c | marks[i] && kids[i] > 0 → [0x4c2170] | OK |
| 0x405a88 | [0x4c2170] 时输出 `UAF-RECLAIM-IO skip-proc-sysfs=1 skip-aio-max=1` | OK |
| 0x405c30 | PREHOLD：`UAF-PREHOLD ms=%d round=%d` + usleep(ms*1000)（键 `prehold=`） | OK |
| 0x405ce0 | reap 闸开 → `reap_phase(n, NULL, -1)` + `UAF-KIDCPU cpu=%d round=%d` | OK |
| 0x405e88 | 未回收子进程：`UAF-CHAIN unreaped child id=%d pid=%d` | OK |
| 0x405b2c | round_no += 1 | OK |
| 0x4057xx | per-cpu socket 状态回收 / timer_delete 两段 / spray_aio_release / reservoir_flush+alloc | 待补 |
| 0x405b00 | slab_stats/pgt_stats("after-reap") + spray_phase 门（11 个全局任一 > 0） | 待补 |
| 0x405d1c | UAF-ERASE-SCAN（0x118 槽位、+0x1e 处的 0xc0de 标记） | 待补 |
| pinwave | calloc + make_timer x16 + pin_cpu | 待补 |

调用点：`honor_chain_body` 在 spray 之后（参考 main 408278）调用
`honor_chain_round(g_hc.attempts, g_hc.timers, delays[], ndelays)`，`delays` 由 bootflow 的
`delays=0,100,200,400` 解析（`honor_parse_delays`）。原先 body 里独立的
`honor_reap_phase(attempt, NULL, 0)` 已删除——reap 归 chain_round（参考 0x405ce0，elen = -1）。

参数语义已复核（libsysopt.dis 0x4029a4-0x4029e8）：
`attempt(w0=a, w1=b, w2=c)` → `[0x4c2618]=a`、`sh[0x18]=b`（窗口 us）、`[0x4c2624]=c`（ntimers）；
因此 chain_round 的 w1（ntimers）传给 attempt 的 c，delays[i%n] 传给 b——9.166 注释里
"attempt(a, stamp, ntimers)" 的 b 其实就是 delays 数组元素。

验收：5.10/5.15 = 444,624 B（sha 0d2ba586… / 9d22c864…），6.1/6.6/6.12/6.18 未变；
check-honor-parity.py 136 串 / 131 在参考 / 5 白名单 / 0 missing；133 tests / 0 fail / 4 skipped；
APK `D:\deepseek work\ExtractKit-9.168-round.apk` 8,588,852 B
sha256=e4ce403dd2dd6b624083dec1f12690fd310e63c0bea9630ca69ca3d0cb8269b4，versionCode 357 / 9.168。

## 9.169 追加：spray_aio @0x403b7c / fill_page @0x40349c / page_pfn @0x40251c / register_region @0x4006d4 / fill_segv @0x403100（全部 1:1）

| 参考地址 | 符号 | 9.169 状态 |
| --- | --- | --- |
| 0x403b7c / 612 B | spray_aio | ✅ 1:1（io_setup→按 ring 头算页数→逐页填→trapped 分支→注册/记账→i<=3 打 UAF-SPRAY-MAP） |
| 0x40349c / 108 B | fill_page | ✅ 1:1（A 段 page+0x78 起 15 槽、B 段 page+0xe0 起 14 槽，q[3]=tag|x） |
| 0x403100 / 92 B | fill_segv | ✅ 1:1（未在填页→SIG_DFL+raise；否则清 in_fill、置 trapped、siglongjmp） |
| 0x40251c / 112 B | page_pfn | ✅ 1:1（/proc/self/pagemap + pread8((addr>>12)*8)，v&0x7fffffffffffff） |
| 0x4006d4 | register_region | ✅ 1:1（表满 65535 丢弃，entry={base,len,mode}） |

关键细节（全部来自反汇编，不是猜测）：
- aarch64 的 io_setup 系统调用号是 **0**：`syscall(0, 1024, &ctx)`，返回 0 且 ctx!=0 才算成功。
- 失败分支与参考一致：**无论 verbose 与否都直接打 summary 并返回**；只有 `[0x4c0050]`（键 `verbose=`，main 0x4061a0 写入）非 0 时才多打一条 `UAF-SPRAY ctx=%d fail errno=%d`。
- 页数算法照抄：`sz = (u32)ctx[0x1c] + 0xfff + ((u32)ctx[4] << 5); npages = sz <= 0x2fff ? 32 : sz >> 12`。
- 填页 tag：`0xC0DE000000000000 | (i << 16) | (j << 24)`。
- 汇合点：先清 in_fill，再判 trapped —— trapped==0 → register_region(ctx, npages<<12)；trapped!=0 → aio_nctx++ 并记 ctx（<=0x7f）。
- 诊断行仅 i<=3：chain_mode(0x4c25a0)!=0 打短版，否则打带 pfn0/pfn1 的长版。

踩到的坑：`g_honor_quiet` 一开始是 static 且无写入点，-O2 直接把整段失败打印 DCE 掉（payload 里搜不到该格式串）。按参考把键名改成 `verbose=`、接到选项解析后，字符串才回来 —— 这也是「用二进制里有没有这个串」能当判据的原因。

仍未移植：spray_uring 0x403de0、spray_skb 0x403248、spray_skb_waves 0x4033d8、spray_anon_early 0x4039e4、spray_foreign 0x404754、pin_setup/pin_create/make_timer/pin_cpu、pool_hold_start/pool_hold_child、reservoir_alloc/reservoir_flush、buddy_stats/slab_stats/pgt_stats。

## 9.170 追加：spray_skb @0x403248 / spray_skb_waves @0x4033d8 / skb_per_pair @0x402008（全部 1:1）

| 参考地址 | 符号 | 状态 |
| --- | --- | --- |
| 0x403248 / 400 B | spray_skb | ✅ 1:1（malloc 0x1e78、28 槽 buf+0x78 步长 0x118/0x100、tag 底 0xC0DE0000FD0000、send(...,7800,0x40)、send 满则同 fd 再发、pairs 用尽 idx++、verbose 打 UAF-SKB sent=、g_skb_total += sent） |
| 0x4033d8 / 196 B | spray_skb_waves | ✅ 1:1（waves<=1 直通 spine_skb；per=(waves+n-1)/waves；每波 spray 后 n-=chunk、n<=0 收；wavegap>0 则 usleep(wavegap*1000)；i++ 后 waves<=i 收） |
| 0x402008 / 236 B | skb_per_pair | ✅ 1:1（读 /proc/sys/net/core/wmem_max 与 rmem_max，fscanf %lu 失败回 0x34000；取小除 0x34000，结果 <=0 取 1） |

关键细节：
- 槽位布局与 fill_page 不同：spray_skb 是 28 槽、起点 buf+0x78，q[3] = x | 0xC0DE0000FD0000（fill_page 是 29 槽两段、tag 由调用方给）。
- `send` 的 flags 是 0x40（MSG_DONTWAIT）。
- verbose 那行参考只传 3 个实参（sent / 7800 / total）却印 4 个转换符 —— 这是参考本身的缺陷，我们照抄，不补第 4 个参数。
- 唯一新增的可配置项是 `waves=` 与 `wavegap=`（参考 0x47d620 / 0x47d628 确有这两个键）。**没有**自造 skbpairs 键：pairs 一律由 skb_per_pair() 现算。

仍未移植：spray_uring 0x403de0、spray_anon_early 0x4039e4、spray_foreign 0x404754，以及 main 里内联的 socketpair 建立循环（0x4c2978 的 fd 表填充）。在它落地前 `g_skb_fds` 全 0，send 会失败返回 -1 而 sent 停在 0 —— 行为与参考在「pairs 未建立」时一致，但真机要有效果必须补上那段。

## 9.171 追加：main 内联 socketpair 建表 @0x407f40（1:1）

| 参考 | 实现 | 状态 |
| --- | --- | --- |
| 0x407f40-0x407ffc（main 内联，无独立符号） | `honor_skb_pairs_setup(int want)` | ✅ 1:1 |

要点：
- `per = skb_per_pair()`；`n = (per + want - 1) / per + 2`（sdiv 截断）；`n = min(n, 0x40)`；**只有 n 比已建的多时才继续建**（`n <= g_skb_pairs` 直接返回）。
- 每对：`socketpair(AF_UNIX=1, SOCK_DGRAM=2, 0, fds)`，失败即 break；`setsockopt(fds[0], SOL_SOCKET=1, SO_SNDBUF=7, &0x800000, 4)`、`setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF=8, &0x800000, 4)`。
- 表布局 0x4c2978：**每对占 8 字节**（fds[0] 在 +0，fds[1] 在 +4），所以 C 侧是 `g_skb_fds[2*i]` / `g_skb_fds[2*i+1]`，spray_skb 发的是 `g_skb_fds[2*idx]`。
- 收尾 `g_skb_pairs = n`（0x4c2970）。9.170 里 `g_skb_pairs = honor_skb_per_pair()` 是对该全局的误解，已改为调用建表函数；want 取 `skb=` 键（参考 0x4c2a04）。

产物：5.10 / 5.15 = 447,760 B（+192 B），6.1 / 6.6 / 6.12 / 6.18 字节不变。

## 9.172 追加：spray_uring / spray_anon_early / spray_foreign / reservoir / pin / pool_hold（一次性搬完批次）

| 参考函数 | 地址 | 大小 | 状态 |
| --- | --- | --- | --- |
| unregister_region | 0x400728 | 76 | 1:1（swap-with-last） |
| spray_uring | 0x403de0 | 1236 | 1:1 |
| spray_anon_early | 0x4039e4 | 408 | 1:1 |
| spray_foreign | 0x404754 | 848 | 1:1 主干 |
| pin_cpu | 0x401c50 | 156 | 1:1 |
| make_timer | 0x401bd8 | 120 | 1:1 |
| pin_setup | 0x401af0 | 232 | 1:1 |
| reservoir_alloc | 0x401cec | 1008 | 1:1 |
| pool_hold_child | 0x4012b0 | 332 | 1:1 |
| pool_hold_start | 0x4013fc | 1008 | 1:1 |
| pool_hold_stop | 0x401238 | 120 | 1:1 |
| reservoir_flush | 0x4042b4 | 1184 | 部分：只有格式串 0x47cf48 印证逐 cpu 释放，timer_delete 语义按 make_timer 反向推导 |

关键细节：
- spray_uring 的 len1 = max(cq_off.cqes + cq_entries*16, params+0x40 + sq_entries*4)、len2 = sq_entries*64；两块 mmap 的 offset 分别是 0 和 0x10000000；tag 分别是 0xC0DE000000FE0000（ring）与 0xC0DE0000FD0000（sqes）。
- spray_anon_early 的填充步长是 0x1000000 但 pc 每轮 +0x1000；mmap 带 MAP_POPULATE(0x8000)。
- spray_foreign 先写 /proc/sys/fs/aio-max-nr 为 4194304；g_wpage 单页取 pfn 后 g_spray_left/g_spray_pc 由 pfn<<12 反算（x = pfn<<12 - g_base - 0x8000000000）。
- pool_hold_start 的合法性判据：count > 3500 或 chain_mode == 0 即 invalid（bootflow 的 chain=1 因此必须传）。
- pool_hold_start 的 need 公式：max(c + reservesettle + cpus*d*max(claimms/20,1), cpus*reserve) + clamp(b,0,1024)*clamp(a,0,64) + (n + 0x100)。
- 配额闸：rlim_cur == RLIM_INFINITY 直接放行；否则要求 rlim_cur > used 且 need <= rlim_cur - used。

仍未移植：pin_create 0x401eb4(340)、chain_round 的 UAF-ERASE-SCAN 等 5 块、slab_stats/buddy_stats/pgt_stats 的逐指令版本（当前按 /proc 逐行等价实现）。

## 9.173 追加：pin_create / 统计门禁 / UAF-ERASE-SCAN

| 参考地址 | 函数 | 落地情况 |
| --- | --- | --- |
| 0x401eb4 (340 B) | `pin_create(int per)` | 1:1：per<=0 或表空/ ncpu<=0 直接返回；逐 cpu 若数组非空则 per>99 时打 `UAF-PIN-CPU c=%d used=%d`，`pin_cpu(cpu)` → 内循环 `used>=pin_per` 或 `make_timer()==-1` 停 → `pin_cpu(-1)` → `UAF-PIN-DONE c=%d used=%d` |
| 0x405088-0x4050c4 (spray_phase) | pinwave 段 | 1:1：`pin_setup(pinwave)` → `per=max(pinwave/ncpu,1)` → `pin_create(per)` → `printf("UAF-PIN n=%d per-cpu=%d total=%d")`（0x47d370） |
| 0x400af8 (188 B) | `slab_stats(name)` | 补门禁：`verbose(0x4c0050)==0` 或 `marker(0x4c2170)!=0` 即返回（0x400afc / 0x400b1c） |
| 0x401120 (204 B) | `buddy_stats(name)` | 同上门禁 + `/proc/buddyinfo` 逐行剥换行后打 `UAF-BUDDY %s %s` |
| 0x4020f4 (232 B) | `pgt_stats(name)` | 同上门禁 + 只打含 `"zone    DMA32"`（0x47c808）的行，缓冲 512 |
| 0x4006d4 | `register_region` | 补第三字段：`cpu = [0x4c214c]`（参考 0x400714-0x400718 写 entry+0x10） |
| 0x405d1c | `UAF-ERASE-SCAN` | 1:1：只扫 `region.cpu == g_cur_cpu` 的区域；每 0x1000 页重扫 slot 0..28（p=0x78, +0x118）；slot<=0xe 时上界 `p+0x20 > rem` 跳过，slot>0xe 时用 `p-0x1000` 且 `rem < p-0xfe0` 跳过；槽内 `q[0]==g_spray_pc && q[1]==0 && q[2]==g_spray_left` 视为完好跳过，否则 `*(u16*)(q+0x1e)==0xC0DE` 记 hit；结尾 `UAF-ERASE-SCAN %s regions=%d round=%d hits=%d first=%d+%#llx`（0x47d518，label="after-reap" 0x47d508）+ fflush |

- 新增全局：`g_pin_total`(0x4c2608)、`g_cur_cpu`(0x4c214c)；struct honor_region 加 `int cpu`。
- 已知偏离：ERASE-SCAN 的 round 实参用 `g_chain_round_no`（参考读 `[0x4c214c]`，该地址同时被当作 cpu 存进 region 表，语义含混，按现值取 round）。
- 验收：`build_fam.py` 5.10/5.15 = 454,352 B（ddea8768… / 4d54759c…）；6.1 432,880、6.18 459,824 未变；6.6/6.12 仍 pinned。`check-honor-parity.py` 151 串 / 146 在参考 / 5 白名单 / 0 missing。gradle 133 tests / 0 fail / 4 skipped。APK `ExtractKit-9.173-pin.apk` 8,599,040 B sha256=e655b79b7891c552b069256fe752d41fe4b60ee9e249b52e3ee58402f682e3ba（versionCode 362）。


## 9.174 追加：B3 write 路径 / B4 窗口闸 / reservoir_flush（全部按参考地址）

| 项 | 参考 | 落点 |
| --- | --- | --- |
| UAF-WRITE 段 | spray_foreign @0x404754 内联（参考无独立 write_page） | honor_spray_foreign：门 `write=`(0x4c2be0) 且 `!(have_pc && have_left)`；x1=(pfn<<12)-kbase(0x4c00b8)、ka=x1-0x8000000000；printf 实参 target=spray_left、value=spray_pc |
| kbase | 0x4c00b8 只由 `kbase=`(0x406bf0) 写 | 删掉「g_slide 推 kbase」的旧写法，默认 0 |
| pc=/left=/pcsym=/leftsym= | 0x406574 / 0x40659c / 0x40664c / 0x40666c | honor_parse_args + honor_ksym()（ksym_lookup @0x400f50 的 `name+add` 语法），在喷雾前应用 |
| B4 窗口闸 | main 0x408884-0x408ad4 | body 的 tries 循环：chain_aim(0x4c21a0,同) → chain_round → unreaped 停 → chain_window()>0 且 chain_bm64(0)==0x4c2190 记命中（UAF-WIND-DONE） |
| reservoir_flush | 0x4042b4（296 条） | 逐 cpu 轮转（idx=sh[0x209c]）、aio 表 0x4c29d0 释放、三组 timer_delete（剩余槽 / 步长 0x1d）、UAF-RESERVOIR flush / UAF-POOL-BURST / UAF-POOL-CLAIM、收尾 settle usleep + free |
| 删 | — | 自造的 honor_write_page 整函数、chain_aim(honor_now_ns(),0) 假实参 |

坑：`g_res_tab`/`g_res_aio` 若从不被赋值，-O2 会把整个 flush 函数连同三个格式串一起 DCE 掉（payload 里 0 次命中）；必须在 reservoir_alloc 里真写这两个指针。

仍未移植：chain_pool_guard @0x4019e4（B4 循环里跳过）；perfprobe / msm_perf.ko 仍是参考包原样字节。


## 9.175：chain_pool_guard @0x4019e4（1:1）

```c
if (g_pool_n == 0) return 1;                 // 0x4c259c（poolhold=）
if (g_pool_pid > 0) {                        // 0x4c0054
  for (;;) {
    r = waitpid(g_pool_pid, &st, WNOHANG);   // 0x434e70
    if (r < 0) { if (errno == EINTR) continue;
                 printf("UAF-POOLHOLD lost pid=%d rc=%d status=%d errno=%d\n", pid, r, st, errno);  // 0x47c690
                 g_pool_pid = -1; break; }
    if (r == 0) return 1;                    // 0x401adc
    printf(same, pid, r, st, 0); g_pool_pid = -1; break;   // 0x401ac4
  }
}
printf("UAF-CHAIN FAILED step=poolhold round=%d\n", g_cur_cpu /* 0x4c214c */);  // 0x47c6c8
logf("failed poolhold round=%d", g_cur_cpu);                                     // 0x47c6f8
return 0;
```
接在 B4 tries 循环头 `if (!honor_chain_pool_guard()) break;`（参考 0x408820）。

## msm_perf.ko 定性（9.175 新发现，重要）

- `assets/payload/honor/msm_perf.ko` **不是 perf 模块，是 KernelSU 的内核侧 LSM/sepolicy 模块**（作者改名）。证据：已定义函数含 `ksu_lsm_hook`(2828) / `apply_kernelsu_rules`(2748) / `is_manager_apk`(2172) / `handle_sepolicy`(1752) / `track_throne`(1748) / `__cfi_check`(2192)；.text 93,488 B / 475 个函数；modinfo 只有 `parmtype=allow_shell:bool`。
- **它需要 225 个未定义内核符号**（SHN_UNDEF），包括 `kallsyms_lookup_name`、`policydb_*`、`avtab_*`、`sidtab_*`、`selinux_state`、`commit_creds`、`prepare_creds`、`override_creds`、`register_kprobe`、`fsnotify_*`、`__cfi_slowpath_diag` 等。
- 我们现在的 honor.map 只有 14 个名字 → `honor_patch_ko` 只能补 14 个，其余 211 个仍是 SHN_UNDEF → **init_module 必然失败**。这是链上真实缺陷。
- 用 `.kall135.txt`（FW135 的 kallsyms dump，110,155 条）实测可解析 225 中的 **212** 个，缺 13 个（printk / __ubsan_handle_cfi_check_fail / arm64_const_caps_ready / cpu_hwcap_keys / __cfi_slowpath_diag / cpu_hwcaps / kmem_cache_alloc_trace / __flush_icache_range / __flush_dcache_area / __list_del_entry_valid / __list_add_valid / find_next_bit / __alloc_pages_nodemask）。
- 结论：不能靠「重写 msm_perf.ko」解决（那是 93KB 内核模块），正确做法是**把我方 honor.map 扩到覆盖该 .ko 的全部未定义符号**（数据来自我们自己的 boot.img kallsyms，用家规 tools/gen-honor-syms.py 生成），缺的 13 个再逐个从 kallsyms 的别名/后缀里找。

## 9.176 追加：模块导入符号表 + perfprobe 重写

### 1. honor.map 扩到覆盖 msm_perf.ko 的全部导入
- 新工具 `tools/gen-module-syms.py`（`python tools/gen-module-syms.py KALLSYMS.txt MODULE.ko --release <rel> [--kotlin F] [--map F] [--all]`）：
  解析 .ko 的 SHT_SYMTAB → 取 SHN_UNDEF 名 → 配我们自己的 kallsyms dump。
  只保留**别名安全**的 4 条 rename（printk→_printk、__list_del_entry_valid→_or_report、__list_add_valid→_or_report、find_next_bit→_find_next_bit）；
  语义不同的（kmem_cache_alloc_trace→__kmalloc、__flush_icache_range→dcache_clean_pou、__flush_dcache_area→dcache_clean_poc、__alloc_pages_nodemask→__alloc_pages）**故意不猜**，宁可报 miss 也不写错地址。
- 实测（`.kall135.txt` 110,155 条 / FW135 6.6.89-android15-8-g082e5a98dac1）：undef=225 resolved=216 fallback=4 missing=9。
  missing 9 条 = __ubsan_handle_cfi_check_fail、arm64_const_caps_ready、cpu_hwcap_keys、__cfi_slowpath_diag、cpu_hwcaps、kmem_cache_alloc_trace、__flush_icache_range、__flush_dcache_area、__alloc_pages_nodemask
  （前 5 条是该 kernel 未编 CFI / static-key，后 4 条是语义不等价）。
- 新 `app/src/main/kotlin/com/extractkit/app/ModuleSyms.kt`：`MODULE="msm_perf.ko"`、`UNRESOLVED`(9)、`tableFor(release)`（只认 6.6.89-android15-8-g082e5a98dac1 前缀）、内部 225 行 blob。
- `HonorMap.render()` 追加 `# module=msm_perf.ko` 段 + 225 行，`# nsyms=` 计入模块非零项。
- `chain_honor.c` 的 `honor_patch_ko()`：`addr==0` 时若 `g_honor_nsyms>0` 打 `UAF-SYM-MISS %s`（0x47c418 参考串），再 continue。
- 坑：`Long.toLongOrNull(16)` 解析 0xffffffc0_xxxxxxxx 会返回 null（超有符号范围），必须用 `java.lang.Long.parseUnsignedLong`。

### 2. perfprobe 从 glibc 大件重写为源码
- 参考 `assets/perfprobe` 702,304 B 静态 aarch64，353 KB .text 几乎全是 glibc；真逻辑只有 main 152 字节（0x4006d4-0x40076c）：
  getenv("UAF_TARGET_EXIT") → getenv("UAF_TARGET_CHECK") → strcmp(val,"1")==0 ? write(1,"TGT-CHECK\n",10) : write(1,"TGT-RAN\n",8) → return (UAF_TARGET_EXIT=="42") ? 42 : 0。
- 新 `payload/src/perfprobe.c` 逐指令等价重写；新 `tools/build-perfprobe.py` 用 NDK r29 编 `-O2 -static -s` → `app/src/main/assets/payload/honor/perfprobe`（417,752 B，比原来小 284,552 B）。
- 语义保留：42 退出码 = attempt() 的 `si_status==42` target-marker 判据；TGT-RAN/TGT-CHECK 用于父进程确认目标真的跑起来。

### 3. 仍未做的
- `msm_perf.ko`（6,975,344 B）保持参考包原样字节：它是 KernelSU 内核侧 LSM/sepolicy 模块本体（475 函数 / 93,488 B .text），重写等于重写 KernelSU；我们能做的已经做了——把它 225 个导入全部解析成地址表。
- 只有当本机 profile 有对应 build 的符号表时 honor.map 才含模块段；没有就只发链自己的 14 条。

## 9.177：收尾统一走 ksud late-load（5.x）

用户决定：**5.x 也统一走 ksud late-load**，不再在进程内自己 init_module(msm_perf.ko)。

### 删除
- `chain_honor.c` 原 733-889 行整块：`struct honor_elf_sym`、`honor_read_file()`、`honor_patch_ko()`、`honor_load_ko()`。
- `ChainPlan.HONOR_KO`、`HONOR_ASSETS` 里的 `msm_perf.ko`（现只剩 `perfprobe to true`）。
- `app/src/main/assets/payload/honor/msm_perf.ko`（6,975,344 B）、`ModuleSyms.kt`、`HonorMapModuleTest.kt`。
- `HonorMap.render()` 的 `# module=msm_perf.ko` + 225 行段；表回到 14 个 NAMES 项。

### 新增
- `honor_ksu_loaded()`：`/proc/modules` 里查 `kernelsu`。
- `honor_handoff_ksud()`：`write_ksu_script()` 落盘 → `setfsuid(0)/setfsgid(0)` → fork → 子进程把 1/2 重定向到 `/data/local/tmp/ksu_stage.out` → `execve("/system/bin/sh", {stage}, envp+g_mgr_env)` → 父 waitpid。
- 日志（参考包无此路径，已进白名单）：
  - `UAF-KSU handoff stage=%s mgr=%s fsuid=%ld fsgid=%ld`
  - `UAF-KSU worker exit=%#x loaded=%d`
- 调用点：原 `honor_load_ko(slide)` → `honor_handoff_ksud()`；成败判据 `honor_ksu_loaded()`；`UAF-CHAIN DONE load=%s` 传 `"ksud late-load"`。

### 为什么可以不要 msm_perf.ko 的符号表
tools/gen-module-syms.py 实测该 .ko 有 225 个 SHN_UNDEF，FW135 kallsyms 只解出 216 + 4 别名 + 9 缺失 → 旧的 14 项表必然让 init_module 失败。改由 ksud 提供模块后这条问题整体消失，gen-module-syms.py 留档不再使用。

### 验收
- check-honor-parity.py：`format strings: 151 in-reference: 146 allowlisted: 5 missing: 0`（白名单换成 2 条 UAF-KSU；原 UAF-LOAD 两条已随代码删除）。
- build_fam：5.10/5.15 = 467,056 B（sha `9847c6525a482290…` / `0eb6bbed4825e086…`，含 ksu_stage.sh 内嵌脚本，late-load×10 / --allow-shell×9 / /proc/modules×8）；6.1 432,880、6.6 476,048、6.12 478,736、6.18 459,824 全部逐字节不变。
- gradle BUILD SUCCESSFUL 48s；**133 tests / 0 fail / 0 err / 4 skipped / 25 suites**（比 9.176 少 3 例，即删掉的 HonorMapModuleTest）。
- APK `D:\deepseek work\ExtractKit-9.177-ksud.apk` 6,738,782 B sha256=`32263eb7a81b1fd37fd5502d751488e63156acfb4d4dbb055a89159b17c460dd`，versionCode 366 / 9.177；APK 内 honor 资产只剩 `assets/payload/honor/perfprobe`；dex `perf.tbl`×0、`ModuleSyms`×0、`module=msm_perf`×0；5.10 payload 里 `msm_perf`×0、`ksud late-load`×1。

## 9.178：仍未实现的参考步骤（不是编串，是缺实现）

5.10/5.15（ref_510_libsysopt）：UAF-AIO-DESTROY、UAF-AIO-RELEASE、UAF-CHURN、
UAF-DRAIN、UAF-MEM、UAF-NO-TARGET、UAF-RD-END、UAF-REAP-STOP、UAF-RETRY、
UAF-RING-RELEASE、UAF-SHRINK、UAF-SLAB-FD、UAF-STAMP、UAF-STAMP-CPU、UAF-SYM、
UAF-SYM-MISS、UAF-SYSCTL-FD、UAF-TRACE-BEGIN、UAF-TRACE-END、UAF-WRITE-HIT
（另 key: patched）。这些串在参考二进制里逐字存在，但我们没有对应的读取/写入
步骤，故 9.178 起不再打印。

6.18（ref_618_keyptr）：[selftest]（cred call_site 投票）未实现；原先自造的
{"uname":...} JSON 横幅已删除。另有 [aio]/[task]/[plante]/[trigger]/[multi]
等步骤仍是我方结构，尚未按参考重写。

## 9.181：覆盖率达到 100% 的手段

- 语义：不是「加日志凑数」，而是把参考里让这些分支可达的前置条件补齐——SIGSEGV 处理器（0x404af0）、
  g_chain_mode 的 volatile（参考 .bss 指针访问折不掉）、带真实期望页缓冲的 reap_phase 调用（main 0x4092e8）、
  以及 writehit / drain / mem / shrink / churn / stamp 的运行期门控。
- 判据仍是产物字节：每个 tag 都先在 tools/build_fam.py 产物里数到 >0 才算落地。
