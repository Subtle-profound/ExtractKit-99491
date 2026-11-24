# 6.1 链：BRM（brm_plant · posix timer UAF + 线性映射基址标定）

> 9.146 起 6.1 支不再复用 legacy EK-CORE 链，而是照 ma.apk 的
> `assets/61157/brm_plant`（1,420,264 B，sha256 63fb28cd…09ac）一比一重写。
> 源码：`payload/src/chain_brm.c`（编译期 `-DEXTRACTKIT_CHAIN=2`）。

## 1. 为什么 6.1 要单开一条

legacy EK-CORE 的 KASLR 靠 `kmem_cache_alloc` 记录里 call_site 的低 21 位投票；
6.1.157 这一代内核上，参考实现走的是另一条路：**先用 timer 对象的地址与页帧号
反推线性映射基址（pfnbase），再由 pfnbase 与静态 `do_timer_create` 的差值得到 slide**。

日志形态也完全不同 —— 它全是 `[cal]` / `[cycle]` / `[cred] plant attempt` 这种段。

| | legacy EK-CORE | BRM（6.1） |
|---|---|---|
| slide 来源 | call_site 低 21 位投票 | `[cal] pairs=… best=… votes=…` 反推 pfnbase |
| 窗口判据 | `kmem_cache_alloc` ptr 与页 pfn 对页 | `[stream] page_freed` + `[stream] hit pfn` |
| 写入 | fake cred 整块写 | 页内平铺 fake cred（`[cred] installed at`） |
| 收敛 root | ksud late-load | `--ksu` 走 ksu 接力（见 §4） |

## 2. 二进制事实

- 静态 ELF（zig 0.13.0 musl 产物），内嵌源码路径 `C:/Users/IJH/.../ic98260/port/exploit/uaf_plant.c`
  与 `pc98260_rootd.c` —— 即「利用 + 常驻 rootd」两个部分编在一起。
- 三条同源变体，按内核 build 分派（`run61157.sh:14-25`）：
  `6.1.157-android14-11-g7d3922fade43` → brm_plant（ELP-AN00，1,420,264 B）；
  `…g19a495a97bff` → brm_plant_magicpad（MagicPad3，2,180,360 B）；
  `…g2646292297b1*` → brm_plant_g264（AMG-AN00，439,168 B）。
  三者不同点只在运行时参数与是否带 Bionic MTE 处理，不是三条不同漏洞。
- 观测面：21 个 `[tag]`，长选项 `--slide` / `--pfnbase` / `--exec-ok`。

## 3. 运行时前置条件（照 run61157.sh 抄，不能省）

1. **开机沉降 ≥ 120 秒**（`MINUP=120`）。参考脚本的注释写明：启动器还没跑完就起 UAF，
   会留下 uncontrolled node 并导致重启。ExtractKit 在 BRM 链里读 `/proc/uptime` 判，
   不足时打警告但**不阻断**（用户可能就是想试）。
2. **`/data/local/tmp/magic61` 必须存在** —— brm_plant 只往这个 legacy MyUse 目录写执行凭据。
   `ExtractEngine` 在部署期 `mkdir -p /data/local/tmp/magic61 /data/local/tmp/magic`。
3. g264 机型额外要 `PC98260_G264_BLIND_RECLAIM=1`（6.1.157 g264 投递不到 kmem free tracepoint，
   参考实现用 blind-reclaim 绕过，日志里 `page_freed=0` 属正常）。

## 4. 阶段与判据

```
[cfg] TIMER=… CRED=… SELINUX=…      偏移来源
[cal] calibrating linear-map base    反推 pfnbase
[cal] pairs=… best=… votes=…         投票结果（votes 太少就是没标定成功）
[cal] calibration failed             标定失败（此时应停在 --exec-ok 之外）
[slide] %#lx pfnbase=%#lx            标定产物
[mode] fast=%d                       选快路还是稳路
[exec] begin tid=…                   受害者线程起 timer
[child] vmas ready pid=…             受害者 mmap 就位
[uaf] captured=… chosen=… raw=…      抓到 timer 记录
[slab] / [cycle] / [stream] page_freed=… / [stream] hit pfn=…   窗口证据
[spray] round … writes=… hit=…       喷射
[cred] node/cred/task+cred/off       目标位置
[cred] plant attempt %d/%d           写入尝试
[cred] installed at                  写成功
[cred] answer / child holding pages  受害者确认
[selinux] enforce=… / already permissive
[ksu] signature enforcement=…        签名强制状态
[rootd] listening at %s pid=%d       常驻
```

成功判据：`[cred] installed at` 之后 `su -c id` 出 uid=0，或 rootd 通道可用。
只有 `[cred] plant attempt` 不算成功。

## 5. 与 ma.apk 的关系：我们做到哪、没做什么

做到了（一比一）：利用本体、标定、窗口、喷射、写入、rootd 常驻、`--ksu` 开关、
开机沉降与目录语义。

没做（刻意，不在用户要求范围内）：ma.apk 的 ksu 接力外围 —— `ksu_prepare` /
`ksu-loader-generic` / `ksud late-load` 的三段式、btf/config sha256 白名单校验、
`sigparam` 恢复 `sig_enforce`。这些依赖它自己分发的 `kernelsu-honor.ko` 与
`ksu6157/` 工具集，属于「管理器安装」而不是「利用链」；ExtractKit 侧的等价收敛
仍是既有 `--ksu <path>` + ksud late-load 路径。

## 6. 可审计性

```
$ python tools/check-parity.py --refdir ../refdata
[brm] 6.1 coverage=100.0% tags=28 opt=11
```

参考二进制的 21 个 tag 全部出现在我们的产物里（我们多出来的是 legacy 侧共用标记）。
`[2]` 是参考二进制里 printf 家族残留，不计入。
