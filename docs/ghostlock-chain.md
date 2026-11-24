# 一键root v1.6（com.buaishuijiao.X70）shell → uid=0 全链路解析

样本：`C:\\Users\\Admin\\Downloads\\qq file\\base.apk`
- 包名 com.buaishuijiao.X70，versionName v1.6；权限只有 WAKE_LOCK；queries me.weishu.kernelsu；Shizuku provider。
- 载荷 `assets/glpreload` 6,470,288 B，sha256 `c033080b4dae58d561742d0ad880d63176514f984a44ed1298a9bb2bcad650e5`，ELF64 DYN AArch64，BIND_NOW + PIE，.dynsym 仅 91 项（函数名只在 .symtab，只能 base+offset 调用）。
- dex 里只硬编码了两个"收录内核"串（classes.dex 0x5273 起，UTF-8 串表）：
  - `6.1.128-android14-11-g8a4968670f1c`
  - `6.1.157-android14-11-g19a495a97bff`
  → 没有服务器下发、没有 conf/GLK1 解析器（全文件搜 GLK1/GLK/init_cred/root_task_group/selinux_blob_sizes 全 0 命中），**按 build 写死**。

## 一、总调用链（main 0x627074 起）

```
main
 ├─ setuid/getuid 记录、open /data/local/tmp/glpreload 场景判断
 ├─ ghostlock_main(0x6267ac)            # 管道竞态：cpubind_init → cpubind_bind(2)
 │    ├─ pthread_create(waiter_thread 0x626414)   # FUTEX_WAIT 等待触发
 │    ├─ pthread_create(owner_thread 0x62669c)    # 持有 pipe_buffer，写 dirty
 │    ├─ pthread_create(consumer_thread 0x626218) # 消费，制造 UAF 窗口
 │    ├─ usleep(1000) → futex_op(...,12,1,1)
 │    └─ sleep(60) 兜底
 ├─ exploit_main(0x626b78)              # 拿 KASLR + 伪造 pipe_buf_operations + 两次 run_one
 ├─ install_pipe_physrw(0x62919c)       # 竞态胜出后固化成"物理地址任意读写"
 ├─ install_android_root(0x62a404)      # fork 带 flag 的子进程 → 找 task → patch cred → 收 uid 0
 ├─ install_embedded_su(0x62ab94)       # 落一个内嵌 su + /data/local/tmp/temp_su.sock
 └─ install_embedded_wallpaper(0x62aeec)# 覆盖 /data/system/users/0/wallpaper（改壁纸判定 root 生效）
```

## 二、KASLR：perf_event callchain 指纹表（get_kaslr_offset 0x6297c8）

1. `syscall(241, &attr, 0, -1, -1, 0)` = perf_event_open；attr.sample_type = **0x21**（PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN）。
2. `mmap(fd, 8192, PROT_READ|WRITE, MAP_SHARED, fd, 0)` 拿环形缓冲；`ioctl 0x2403`(RESET)、`0x2400`(DISABLE)。
3. 循环 `syscall(172= getpid)` **约 2,000,000 次**（0x1e8480）制造采样；再 `ioctl 0x2401`(ENABLE) 读环。
4. 解析记录：`[rec+0x6] u16 = size`、`[rec+0] u32 type == 9`（PERF_RECORD_SAMPLE），取 `[rec+8]` 的 IP、`[rec+0x18]` 数量、`[rec+0x20]` 起地址数组，只收 `>= 0xffff800000000000` 的**内核地址**。
5. 用 **11 条 (ip & 0x1fffff) → 基址候选** 的指纹表化简：命中后 `base = ip + K`（K 由 movz/movk 立即数内联，形如 `2^38 − off`，收尾用 `lsr x, 40; cbz` 过滤垃圾），同一候选被投票最多的胜出。
6. `munmap` + `close`，返回 base（存 `g+0xf38`，二次调用直接复用）。

> 11 条指纹 = 2 个 build × 若干采样点，各自 vmlinux 专属。这就是"收录两个内核"的实质：**换 build 必须重抠这张表**。

## 三、伪造 pipe_buf_operations（exploit_main 0x626b78）

在全局 `fops`（0x637038）里拼一张 0x100 字节的回调表，指针全部 = `base + 静态偏移`：
`0xffffffc008478d70`(+0x230)、`0xffffffc008478d70+0x2b8`、`0xffffffc0087bb14c`、`0xffffffc00a6f7e18`、`0xffffffc00a55a110`、`0xffffffc00a45dc60`（末者在收尾里按 +0x210 做 kernel_write/kernel_read 校验）。
随后 `run_one(&cfg,1)` → `is_kernel_ptr()` 校验 → 改 cfg → `run_one(&cfg,2)` → 用 `kernel_write_data(fd, 0xa45dc60+0x210, 8)` 写入并读回校验 → 收尾 reset_pipe_attempt / sysctl_destroy / close / kill。

`run_one(0x626ef4)`：把 cfg 三 qword 写进 `0x636fa8`，置 `0x637010=1` 放行 worker，usleep(1000) 轮询 ≤500 次，超时用 `pthread_kill(tid,12)` 踢进程；成功后清 0xfc0–0xff8 十几处计数，`log_context()` 落日志。

## 四、把竞态固化成物理读写（install_pipe_physrw 0x62919c）

1. `pipe()` + `fcntl()` + `write()` 建好管道；多次 `sysctl_read()`（`/proc/sys/kernel/...` 句柄）取内核指针，逐个 `is_kernel_ptr()` 校验。
2. `kernel_read64()` 读 `page_offset_base` 一类符号，`sysconf(_SC_PAGESIZE)` 得页大小，`kernelsnitch_param()` 取 snitch 参数。
3. 建立 `phys <-> 虚拟` 换算后，用 `kernel_write_data` 写回、再 `pipe_phys_read()` / `pipe_phys_write()` **反复自校验**；失败把错误码写进全局 0x1e8/0x1ec/0x1f0/0x1f4（对应三类校验），并把魔数字符串（"sev"+"c0"、"2 7 3 1"、"6 8 9 7 3 1"）写进去做哨兵。
4. 成功后导出三个原语：`pipe_phys_read_data(h, addr, buf, len)`、`pipe_phys_write_data(h, addr, buf, len)`、`pipe_read64/pipe_write64`。

## 五、找 task、改 cred（install_android_root 0x62a404）

1. `spawn_root_child()`（0x629c38）：mmap 共享标志页 + 建 `root_ready_pipe` + fork；子进程 `prctl(PR_SET_NAME)` 后 `setgid(0)/setuid(0)`（必然失败，只为留痕），父进程等 1 字节后开始 patch。
2. `find_task_by_tgid(h, tgid)`（0x62a030）：从硬编码 `0xffffffc00a0bfc10`（该 build 的 init_task 一类锚点）经 `data_addr` 转物理，沿 `tasks` 链表走最多 0x1001 次，比对 `task+0xe0`(pid)/`task+0xe4`(tgid)，命中后从 `task+0x2f8` 读 16 字节（日志用；注意这一处与 6.1 的 comm=0x848 不一致，疑似残留的 5.10/5.15 布局分支或纯日志字段，待核）。
3. 读 `task+0x830`(real_cred) / `task+0x838`(cred) → `patch_cred_object` ×2。
4. `patch_cred_identity(h, cred)`（0x62a1a0，逐字段实测）：
   ```
   if (!is_direct_ptr(cred)) fail;
   pipe_phys_write_data(h, cred+0x04, zeros, 0x20);   // uid,gid,suid,sgid,euid,egid,fsuid,fsgid 八连 0
   pipe_phys_write_data(h, cred+0x24, zeros, 0x04);   // securebits
   pipe_phys_write_data(h, cred+0x28, fullcaps, 0x28); // 5×u64 = 0x1ffffffffff = (1<<41)-1
   pipe_phys_read_data(h, cred+0x28, buf, 0x28);      // 读回校验 5 项是否全等
   ```
5. `patch_cred_sid`：读 `cred+0x78`(security) → 写 8 字节（u32 osid, u32 sid）到 `security+[0x637200]`，把 SELinux 侧身份一起换掉。
6. `collect_root_child()` 收尾：把子进程唤醒/回收，父进程此时已是 uid=0 + 全 caps + 目标 sid。

## 六、与我们 6.1 payload 的对应关系（关键结论）

- 他的 task/cred 偏移与我们 `ServerProfiles.kt` 里 **android14-11 / 6.1 的 profile 逐项相同**：
  `taskCred=0x838`、`taskComm=0x848`、`credUid=0x4`、`credSecurity=0x78`、`credUser=0x80`、`credUserNs=0x88`、`credUcounts=0x90`、`credGroups=0x98`、`credSize=0xb0`。
  → 结构体偏移**不用重抠**，6.1 GKI 同源。
- 需要按 build 重生成的只有三类：
  1. KASLR 指纹表（perf 采样点 low21 → 基址常数），即 11 条；
  2. 伪造 fops 里那 6 个内核文字地址（base+静态偏移）；
  3. task 链表锚点（init_task）与 `selinux_state`/`root_user` 一类全局地址。
  这三类我们**已有工具链**：`tools/find-kallsyms.py`、`tools/btf-dump.py`、`tools/gen-config.py`、`tools/ghostlock-conf.py`（后者本来就是按 release 生成 offset{} 的生成器），profile 表里已收录 `6.1.157-android14-11-g19a495a97bff` 等几十个 build。
- 我方 6.1 主线现在失败在 `calibration failed`（kmem tracepoint 标定 + rootd bind errno=13），而 ghostlock 这条路**不需要 tracepoint 标定**，只需要"任意物理读写"——正好绕开我们的死点。

## 七、移植到我们 6.1 payload 的落点（不改架构，只换 uid0 阶段）

1. 新增 `payload/src/ghostlock_map.h`：per-build 常量（11 条指纹 + 6 个 fops 地址 + init_task + selinux sid 对），由 `tools/gen-ghostlock-map.py` 从 kallsyms/BTF 生成；`device_config.h` 不动。
2. 新增 `payload/src/chain_ghost.c`：`ghost_lock_race()`（三线程，照 0x626218/0x62669c/0x626414 的结构）、`ghost_physrw()`（照 0x62919c 的自校验流程）、`ghost_patch_cred()`（照 0x62a1a0 的字段顺序，但 cred 地址走我们自己的 `find_task`）。
3. 6.1 的 `chain_brm` 保留为 fallback；`PayloadCatalog` 里 6.1 支加一个 mode 位选择 ghostlock。
4. uid=0 之后仍然走我们自己的 `write_ksu_script()` + `ksu_stage.sh`（ksud 由我方 pull，阶梯 try_load）——他那边装的 LKM/内嵌 su 一概不要。

## 八、我方实现（按本文第七节落地，2026-11-18）

### 8.1 代码位置（全新写，不碰旧链）
`payload/ghost6.1/` 六个源文件 + 一个档案头：

| 文件 | 对应参考 | 内容 |
|---|---|---|
| `ghost.h` | — | `ghost_map`（per-build 常量 + 6.1 结构偏移）、`ghost_ctx`、LOG/DBG、全部原型 |
| `util.c` | `log_startup_context`/`cpubind_*` | 文件读写、`sched_setattr_tid`（第二参数当 nice，直接用 SCHED_OTHER+nice）、`disable_rseq_for_thread`、`futex_op`、`open_ashmem_device`（/dev/ashmem 失败回落 memfd）、`is_kptr` |
| `kaslr.c` | `get_kaslr_offset` 0x6297c8 | perf_event_open(attr.sample_type=IP\|CALLCHAIN, mmap 2 页, ioctl 0x2403/0x2400/0x2401, 循环 getpid 造样本) → 按 `ip&0x1fffff` 指纹投票 → 2M 对齐校验 |
| `race.c` | `ghostlock_main` 0x6267ac + 三线程 | owner(nice+19, futex6/7) / consumer(nice-20, usleep 50000, 计数成对) / waiter(futex 事件推进)，原子全局对应参考的 0x636fc0..0x637000 一组 |
| `rw.c` | `install_pipe_physrw` 0x62919c、`pipe_phys_read/write` | 三层：`kernel_*_data(va)` → `pipe_phys_*(phys)` → 自校验；`pipe_point_at()` 改写 pipe_buffer->page/offset/len/flags（PB_PAGE 0x00 / PB_OFFSET 0x08 / PB_LEN 0x0c / PB_OPS 0x10 / PB_FLAGS 0x18 / PB_PRIVATE 0x1c） |
| `cred.c` | `find_task_by_tgid` 0x62a030、`patch_cred_*` 0x62a1a0/0x62a2e0/0x62a368 | tasks 链表遍历（≤4097）、八 id 0×0x20 → securebits 0×4 → caps 5×0x1ffffffffff 并读回校验、security sid、fork 同步 + 父子协作 |
| `map.c` + `map_6.1.h` | — | `tools/gen-ghost-map.py` 从 `ServerProfiles.kt` 抽 14 条 6.1 档案（selinux_state/root_user/init_user_ns），init_task 与 tasks 偏移留空 |
| `main.c` | `exploit_main` 0x626b78 | ashmem → kaslr → physrw → 自举 init_task/tasks → find_task → patch_cred → `handoff_ksu()` 执行 `ksu_stage.sh` |

### 8.2 与参考实现的差异（都是刻意为之）
1. **不内嵌 kernelsu.ko / 不自带 su**：uid=0 之后立刻 exec 我们的 `ksu_stage.sh`，ksud 由我方按 9.204 政策在 `$APP_ROOT/*/$MGR*/lib/arm64` 里静态挑，走阶梯 `late-load`。
2. **init_task 不写死**：参考写死 `0xffffffc00a0bfc10`；我们扫内核镜像里 `swapper/0` 串 + `pid/tgid==0` + `cred` 落在直接映射区三重校验定位（`ghost_find_init_task`），再用链表自洽性反推 `task_struct.tasks` 偏移（`ghost_resolve_tasks_off`，候选 0x180..0x600 步长 8）。
3. **KASLR 指纹表留空**：`map_6.1.h` 里 `fp[]` 目前是 `{0,0}` 占位，必须由 `gen-kallsyms`/`btf-dump` 对目标 build 生成真值，否则 `get_kaslr_offset` 直接失败退出。
4. **physrw 交付点**：`ghost_race_take_pipe()` 目前只认环境变量 `GHOST_PIPE_BUF`/`GHOST_FAKE_PAGE`（十六进制，实验室标定用），竞态胜出后由内核侧字段直接给出这两个地址的那一段还没有接上——这是整条链唯一未闭环的地方。

### 8.3 产物
- 构建：`python tools\build_ghost6.py`（NDK r29 `aarch64-linux-android34-clang`，-O2 -static -fno-pie，然后 llvm-strip -s）。
- 产物：`app/src/main/assets/payload/ghost/ek-core-uid0-6.1-ghost`，436,688 B，sha256 `cfab78066fcb1326f0548cd0fe815c658b16ea7311a837d1d8b6d4790e2c88e8`（2026-11-18 首版）。
- 六支 fam（5.10/5.15/6.1/6.6/6.12/6.18）一个字节没动；这个 ghost 二进制是**并列新增**，等实测通过再决定是否替换 6.1 支。


## 九、glpreload 的常量是否"缺参数"——用 6.1.128 Image 实证（2026-11-18）

### 9.1 结论
- glpreload 运行时**不接受任何外部参数**：.data 仅 412 B，全程序只有 2 处 getenv（CPUBIND_DEBUG / PPG_ROOT_CMD），无 argv 配置、无网络、无 BTF/kallsyms 依赖。所谓"收录内核"只是 dex 里两行 release 字符串做门禁，二进制内只有**一套**常量。
- 因此"参数完整"= 这套常量恰好落在该 build 的正确偏移上。两支 6.1 能跑，是因为同一 ACK 分支相邻 build 的这批偏移相同（运气/同源），不是各存一份表。
- 我们手上的 6.1.128 Image 是**第三支** build（版本串 6.1.128-android14-11-g52c266270871，+pgo +bolt +lto；dex 白名单是 g8a4968670f1c 与 6.1.157 g19a495a97bff，镜像内搜不到 g8a4968670f1c），常量全部错位 → 必须按 build 重生成。

### 9.2 已解出的完整常量清单（从 _glpreload 反汇编实测，KIMAGE_VADDR=0xffffffc008000000）
| 用途 | 值 | 来源 |
|---|---|---|
| KASLR 采样点 1..5 | 0x113E0 / 0x700DC / 0x14C578 / 0x4A1A58 / 0x106B3F4 | get_kaslr_offset 五个 delta+imm |
| 伪造表指针 | 0x478B40(+0x230 → 0x478D70, +0x2B8 → 0x478DF8) / 0x7BB14C(+0x1C0 → 0x7BB30C) / 0x477F84 / 0x7BB2B4 | exploit_main 0x626c0c–0x626ca4 |
| 写回目标 | K1 0x253C2C0 / K2 0x26F7E18 / 0x245DC60 | consumer stage2 / exploit_main 0x626d0c、0x626d8c |
| init_task 锚 | 0xA0BFC10 | find_task_by_tgid 起点 |

### 9.3 这些常量在本 Image（g52c266270871）上的落点
已用自写解析器读出全部 kallsyms（N=115,958；offsets@0x134fb68、names@0x13c0f50、markers@0x15482b8(453)、token_table@0x159d8b8、token_index@0x159dc58、rel_base=0xffffffc008000000@0x13c0f40；6.1 ACK 回移了 kallsyms_seqs_of_names）：
- 0x113E0 = el0t_64_sync（精确对齐；入口代码天然稳定）
- 0x700DC = path_get+0x34
- 0x14C578 = security_compute_validatetrans+0xd8
- 0x4A1A58 = ext4_writepage+0x28c
- 0x106B3F4 = snd_usb_endpoint_start+0x2b0
- 0x478B40 = tracing_set_tracer+0xb0（不是 pipe 回调）
- 0x7BB14C = z_erofs_decompress_queue+0x918
- 0xA0BFC10 = __eh_frame_start+0x22fdc8（**不是** init_task）

### 9.4 本 Image 的真实关键符号（可直接喂给 map_6.1.h）
init_task=0x21E1780、init_cred=0x21F3F48、root_user=0x21F2C20、init_user_ns=0x21F2990、selinux_state=0x2827FA8、anon_pipe_buf_ops=0x1163C58、default_pipe_buf_ops=0x1165480、anon_pipe_buf_release=0x5590A8、anon_pipe_buf_try_steal=0x559174、_text/_stext=0x0、_end=0x28C0000（image_size=0x028C0000）。

### 9.5 解析器（可复用）
脚本要点：rel_base(u64)+num_syms+names(u8 长度 + token 索引)+markers+seqs_of_names(3B/项)+token_table+token_index；token 表基址必须用"256 串 + 256 个严格递增 u16"定位后再回退到 'T_text' 这类首符号能正确解出的位置（本镜像 token_table 基址 = token_index-0x3A0）。符号名首字节是类型字符（T/t/d/b/B/R/r）。
解析结果落盘：D:\deepseek work\_ks61.json（rel/n/addrs/names/types）。

## 9. 逆向收口（全链读完）
### 9.1 链路总览（相对 KIMAGE_VADDR = 0xffffffc008000000）
1. cpubind + 三线程竞态（owner nice+19 / consumer nice-20 / waiter）→ PI-futex 抢 pipe_buffer；
2. get_kaslr_offset：perf_event_open + sample_type 0x21 + 200 万次 getpid，取 CALLCHAIN ip，用 5 个「采样指令地址」投票算 slide（slide = ip + delta + imm，且 < 2^40）；
3. exploit_main 伪造 struct file_operations（0x637038，0x100 B，槽位填 slide+内核地址），首次 run_one stage=1；
4. sig_stack_copy 构造假 rt_sigframe（fpsimd magic 0x46508001）→ rt_sigreturn 换寄存器 → pc 落 0x62615c；waiter 再以 ppoll 带 0x100 寄存器块发 syscall；
5. 第二次 run_one stage=2 → consumer 在核内做：open_ashmem → kernel_write_data(fd, K1, &(slide+K2), 8)；
6. install_pipe_physrw：劫持 sysctl 表项拿内核读原语 + 用自己的 pipe_buffer 做任意物理读写，23 B / 0x100 / "nebusec1" 四连自校验；
7. find_task_by_tgid：从 init_task+0x550 走 tasks 链，比 pid/tgid，读 comm 16 B；
8. patch_cred_object：八 id 清零 + securebits 0 + caps 五连 0x1FFFFFFFFFF + sid=1(SECINITSID_KERNEL)；
9. disable_antiroot_mod：module_find_by_name("rscan") + module_section_range(mod,3) + start+0x860 写 24 B 全 1；
10. handoff：/data/local/tmp/ksud late-load --post-magica --package-name <mgr>。

### 9.2 冷启锚点的真实含义（本轮新解）
- kernelsnitch 全解：setup（64 GiB 预映射 + futex 桶计时表）→ find_collisions（4096 线程 × 128 次 futex(98, op=0x81) 计时，取最小 8 个均值，> 4×基线记候选）→ bruteforce（a3 线程各自扫 8 MiB 窗口，围绕 0xffffff8000000000）→ 结果 = **struct mm_struct ***（二进制自带断言串 `(ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND)`）。
- 由此 fp 链成立：`mm + 0x338 = mm->owner(task_struct*) → task + files → files + 0x20 = fdt → fdtable + 0x8 = fd_array`。
- 我们的 Image 实测：mm_struct size 0x3c0、owner 0x338（与参考同）；task->files 0x880（参考 0x878，因我们多 ptracer_cred 0x830 后移 8）。
- `file + 0xd8 = private_data` → `pipe_inode_info + 0xa8 = bufs` → pipe_buffer 首址（两 build 全同）。

### 9.3 sysctl 读原语（本轮新解）
- 路径串实证：`/proc/sys/net/ipv4/tcp_comp_sack_delay_ns`，proc_handler = proc_doulongvec_minmax，maxlen 8，mode 0644。
- 手法：把 ctl_table 的 data 指针改写为目标内核地址，再 pread 该文件 + strtoul 得 8 字节。
- 参考：data 槽 0xa55ef0，原值 0xa72cf80。我方 Image 实测：entry 0x267fd78、**data 槽 0x267fd80**、原值 **0x28a7b40**。

### 9.4 ★ .text 布局与参考一致（关键结论）
参考二进制里用 movz/movk 内联的 5 条 KASLR 采样锚点，在我们 6.1.128 Image 上落到同名同偏移：
| 锚点(off) | 我方位移 | 我们 Image 的符号 |
| --- | --- | --- |
| 0x113E0 | 0x113e0 | el0t_64_sync+0x0 |
| 0x700DC | 0x700dc | path_get+0x34 |
| 0x14C578 | 0x14c578 | security_compute_validatetrans+0xd8 |
| 0x4A1A58 | 0x4a1a58 | ext4_writepage+0x28c |
| 0x106B3F4 | 0x106b3f4 | snd_usb_endpoint_start+0x2b0 |
另 4 个 fops 槽（0x7bb14c / 0x7bb30c / 0x477f84 / 0x478b40 / 0x478d70 / 0x478df8）在我们 Image 上也解出同名同内偏移（z_erofs_decompress_queue+0x918/+0xad8、ufshcd_wl_resume+0xa0、tracing_stop_tr+0x10/+0x98 等）。
⇒ 他那一套**文本常量可原样烧进我们的表**；只有 .data/.bss 常量（init_task、selinux_*、ctl 槽、fake 区）需按我们 build 重算。这也是他「一套常量覆盖两支 6.1」的真正原因。

### 9.5 我方 build 常量表（相对 KIMAGE 0xffffffc008000000）
| 角色 | 参考值 | 我方值(6.1.128-g52c266270871) |
| --- | --- | --- |
| init_task | 0x20bf6c0 | **0x21e1780** |
| tasks 锚点(init_task+0x550) | 0x20bfc10 | **0x21e1cd0** |
| selinux_state | 0x26eca40 | **0x2827fa8** |
| selinux_blob_sizes | 0x15f0e68 | **0x16d5dc8** |
| ctl data 槽 / 原值 | 0x255ef0 / 0x272cf80 | **0x267fd80 / 0x28a7b40** |
| anon_pipe_buf_ops | 0x90fcef0 | **0x1163c58** |
| fake 4KB 区 | 0x26f7e18 | 取我们 __log_buf(0x26f6e80)+0x798 |
| 任务/cred 偏移 | tasks 0x550, pid 0xe0, tgid 0xe4, comm 0x848, real_cred 0x830, cred 0x838 | tasks 0x550, pid 0x630, tgid 0x634, comm 0x850, real_cred 0x838, cred 0x840 |
| cred 偏移 | uid 0x04 … securebits 0x24, caps 0x28, security 0x78, size 0xb0 | 与参考**完全一致** |
| pipe/file/page | buf 0xa8, private_data 0xd8, page 0x40/flags 0x00/refcount 0x34 | 与参考一致 |

### 9.6 剩余未定（仅 .data/.bss，共 4 个）
- K1=0x253c2c0（.bss 8 B，被写入指针 slide+K2）、K2=0x1274ad8（.data）、
- 0x245dc60（4 B 开关，读到 1 则写 0；疑 panic_on_warn，待证）、
- 0x255a110（stage1 cfg 第二项）。
四者都不参与语义判断（不是结构偏移，也不是函数指针解引用目标），可以按「等价 scratch / 等价开关」在我方 build 上替换，不影响链路结构。


## 9.284（474）—— 只在那两个内核上跑，其余一律拒跑

用户指令：m24089「原来的那些分支不要动 新增链路跑新payload」、m24099「不匹配内核就不跑」、
m24118「主要目的是为了跑那两个内核加我们的late load 能不能适配新内核只是额外附带的 不行就不行」。

### 1. 常量来源（calib.json）
`payload/ghost6.1/calib.json` 按 release 存标定值，只有完整（fp>=3、race 5 项、fops 6 项、
init_task、task_tasks 全非零）才被 `tools/gen-ghost-map.py` 写进 `map_6.1.h` 与
`GhostCalibrated.RELEASES`。当前标定两支：

- `6.1.128-android14-11-g8a4968670f1c`
- `6.1.157-android14-11-g19a495a97bff`

值全部取自参考实现（一键root v1.6 / glpreload）的烧死常量，均为 **link-time 绝对地址**，
运行期统一 `+slide`：

| 项 | 值 |
| --- | --- |
| fp 5 锚点 | `0x113e0 / 0x700dc / 0x14c578 / 0x4a1a58 / 0x106b3f4`（key = ip & 0x1fffff，delta = -ip） |
| fops[6] | `0xffffffc0087bb14c, 0xffffffc00885f454, 0xffffffc00885f984, 0xffffffc008477f84, 0xffffffc0087bb2b4, 0xffffffc008478b40` |
| race[5] | fake_lock `0xffffffc00a6f7e18`、stage1 left `0xffffffc00a55a110`、stage2 left `0xffffffc00a53c2c0`、sig_enforce `0xffffffc00a45dc60`、data_addr 探针 `0xffffffc0095fffa0` |
| init_task | `0xffffffc00a0bf6c0`（= tasks 锚点 − 0x550，与 6.1.157-gaaa 符号表一致） |
| task_struct | tasks 0x550、real_cred 0x838、cred 0x840、pid 0xe0、tgid 0xe4、comm 0x850 |
| cred | uid 0x04、securebits 0x24、caps 0x28、security 0x78、size 0xb0 |

race[4] 早期被我方误填成 `fake_lock+0x100`；参考的 `+0x100` 只是 `data_addr` 的传参，
真正的探针基址是 `0xffffffc0095fffa0`（读 [probe] 与 [probe+0xa8] 算 page_offset_base），已改正。

### 2. 运行期匹配（C 与 App 双闸门）
- `map.c`：`const ghost_map *g_map;`（无初值）。`main.c` 用 `uname()` 取 release，
  `ghost_map_pick` 只做「profile 是 release 前缀且下一个字符是 '-' 或结束」，
  **不命中返回 NULL** → 打 `[!] ghost: kernel %s has no calibrated profile; refusing to run` 并 exit 2。
  （原实现命中不了会 fallback `&g_maps[0]`，等于拿别的 build 的 .data 常量去写内核 → panic，已删。）
- `GhostSupport.profileFor()` + `GhostCalibrated.RELEASES`：App 侧在部署之前就判，
  不在名单里直接 `GHOST_UNMATCHED`，连 push 都不做。

### 3. 隔离
选 ghost 时只跑 ghost：部署失败 → `GHOST_DEPLOY`、预检不过 → `GHOST_UNSUPPORTED`，
**绝不回退**去跑 EK-CORE fam / EK-CALIB。不选 ghost 时代码路径与 9.282 逐行一致；
六支 fam 载荷与 9.283 逐字节相同（验收脚本已比对）。

### 4. 验收（scripts 记录）
`D:\deepseek work\chk9284.py`：APK 7,027,746 B sha256=`2b11ad3b4aef51d8dc68a3d7196fec9780a55e227a5e015d04b0a39034d9ab4c`、
单测 143/0/0（skip 4）、ghost 载荷 438,000 B sha256=`045017bd193efbef813ebb012399098c109172723a4cde2cf0202fcb873be0d6`、
六支 fam 与 9.283 逐字节相同、dex 含两支标定 release 与 `GHOST_UNMATCHED`。
