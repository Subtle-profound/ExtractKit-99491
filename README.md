# ExtractKit · 基于 CVE-2026-99491 的 Android 内核提权工具箱

一个 Android App（Kotlin + Jetpack Compose）+ 一份原生载荷，把「从内核漏洞拿到 uid 0，
再让 KernelSU 接管」这件事做成可标定、可复用的流程。

当前版本 **9.444**（versionCode 633），只在你拥有或明确获得授权的设备上使用。

## 它解决什么

内核漏洞利用的常量（kallsyms 地址、结构体偏移、call site 位置、tracepoint id）随内核 build
变化，换一台机器就得从头再来。ExtractKit 把这一步做成产品：

- **标定**：选一台机器的官方 `boot.img` / `Image`，App 在手机上解析内核版本、BTF 偏移、
  kallsyms 符号、call site，生成一份 ~3 KB 的 profile（或 `device.cfg`）。
- **执行**：同一份载荷读 profile 里的常量跑，不需要 PC、不需要重编。
- **同 build 的其他人**：把 profile 分享出去，对方「导入」即可，主页直接显示「已适配」。

## 漏洞原理

### CVE-2026-99491 · uinput / uhid（主力链，全内核家族）

- **缺陷**：`uhid` 设备的释放路径（`uhid_char_release()`）会对 `outq` 指的那块 2 KB slab 槽做
  `kfree()`，而这块槽此前已经被释放并回收过 ⇒ 释放后再用（UAF）。
- **写原语**：`uinput` 的 `struct input_value` 固定 8 字节（`u16 type; u16 code; s32 value;`），
  所以一次事件写入 = 往一个 8 字节对齐的内核地址写 8 字节，其中 **48 位可控**（低 16 位在
  `type`，高 32 位在 `value`）。
- **两步成链**：
  1. 让那块 2 KB 槽变成我们的内存：spray `uhid` 设备 + 回收页，使 `uhid` 的 `input_buf`
     正好落在刚释放的这一页上；此时槽内容就是预置的伪造 `cred`（`uid/euid/gid = 0` + 满 capability）。
  2. 改指针：用上面那个 8 字节写把 `task_struct->cred` 改指向伪造 `cred`。因为只有 48 位可控，
     一个 64 位指针要分两段接起来写（链式写）。
- **地址从哪来**决定走哪条分支（见下节）。拿到 uid 0 之后**不改管理器任何文件**，而是调用
  用户自己安装的根管理器的 ksud CLI：`late-load --post-magica --allow-shell --package-name <包名>`，
  让管理器把 `kernelsu.ko` 装进内核。管理器包名与 CLI 的 `.so` 名都按特征打分挑选
  （`-V` 输出 `uapi`、含 `KernelSU` 字样、CLI 特征串），所以 SukiSU Nova / KernelSU / 改名包 /
  隐私空间分身都能用，不写死 `libksud.so`。
- **收尾**：exec CLI 之前必须把 `outq[0]/outq[1]` 置 NULL。这些 fd 都带 `O_CLOEXEC`，CLI 的
  `daemonize()` 关掉继承的 fd 会走 `uhid_char_release()`，对我们回收的那块 2 KB 槽再
  `kfree()` 一次，约一秒后 panic；置 NULL 之后释放路径只做 `kfree(NULL)`。

### CVE-2026-98260 · posix timer UAF（多家族：5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18）

- **缺陷**：`k_itimer`（`posix_timers_cache`）释放后仍被使用。
- **写原语更窄**：只能对目标做 8 字节**归零写**，写不进可控指针。所以这条链不靠"指向伪造 cred"，
  而是配合内核模块补丁（`ko_patch.c`）把清零落在凭据相关字段上再拿 uid 0。
- **每个家族一支载荷**：`payload/fam/ek-core-uid0-<家族>`，编译期带 `-DEXPECT_FAMILY="<前缀>"`
  族闸门和 `-DEXTRACTKIT_FAMILY_ID`，跑错家族会直接拒跑。其中 **6.6 是本机实测标定**，
  其余家族是 offsets-only 待标定（标定完即可跑，成败另说）。
- **6.12 支多一段**：拿到 uid-0 cred 后在本机进程内 patch 并 `finit_module` 该 release 的
  `kernelsu.ko`，再跑 root_stage 装 ksud —— 这段装载路线**只对 6.12 生效**；release 不是
  已知的两条 6.12 前缀时自动退回纯 uid-0 shell。其余家族到 uid 0 为止。

### 三条分支怎么选

| 分支 | 地址从哪来 | 说明 |
| --- | --- | --- |
| `real_cred` | 不需要外部地址 | 进程自己 `cred == real_cred` 时直接改自己，默认、最稳 |
| `tracefs` | 内核 tracepoint 记录泄漏 cred 地址 | 非主线设备常开 tracefs |
| `no-tracefs`（实验） | 无泄漏，靠 spray 猜地址 | tracefs 被关时的兜底，成功率低 |

## 目录

```
app/src/main/kotlin/com/extractkit/app/
  ExtractEngine.kt     执行编排：profile 生成、载荷推送、模式选择、日志归集
  WacomCalib.kt        CVE-2026-99491 链的标定（符号 / 偏移 / call site）
  BootImage.kt         boot.img 解析（header v0~v4、gzip / lz4 / lz4-legacy、vendor_boot）
  Btf.kt               /sys/kernel/btf/vmlinux 或内嵌 .BTF 的结构体偏移
  KallsymsFinder.kt    从内核镜像里找 kallsyms（含压缩 / 未压缩两路）
  PayloadCatalog.kt    载荷清单（家族 → 资产、sha、大小）
  WacomBuiltin.kt      机型注册表（标定产物的登记处）
  Glass*.kt            界面（Compose，日夜双主题、玻璃拟态）
app/src/main/assets/
  payload/wacom/ek-w1-uid0-6.6      99491 主载荷（AArch64 静态 ELF）
  payload/wacom/profiles/*.json     已导入的标定产物
  payload/wacom/ko-syms-*.txt       各 build 的内核符号表（模块补丁用）
  payload/ek-core-android           98260 载荷（6.12）
  stage/ksu_stage.sh                ghost 链的脚本化装载（Shizuku 侧）
payload/
  src/                 99491 之前的 98260 / ek-core 源
  wacom-src/           当前 99491 载荷的 C 源（exp.c / ksu_boot.c / ko_patch.c）
tools/                 标定与构建脚本（kallsyms 扫描、BTF dump、配置生成、发版）
glass/                 Compose 组件库
docs/                  设计与排障笔记
```

## 构建

需要 JDK 17、Android SDK 35、NDK r29（载荷已有预编译产物，只编 App 不需要 NDK）。

```
gradlew assembleRelease        # 产物 app/build/outputs/apk/release/
```

重编原生载荷见 `payload/wacom-src/BUILD.md`。

## 限制与风险

- **没有「安全失败」**：这类漏洞利用回收失败、竞态输了、写到别人的页上，都会让内核当场挂掉。
  首次在真机上跑请先备份，并准备 fastboot 救砖。
- 载荷本身只负责「拿到 uid 0 + 满能力集」；**内核模块是否真的装进 `/data/adb` 取决于管理器**。
  App 会用打分的方式（`-V` 输出 `uapi`、`KernelSU` 字样、CLI 特征串）在管理器的
  `lib/<abi>/*.so` 里挑出 ksud CLI，不同管理器（SukiSU Nova / KernelSU / 改名包 / 分身）
  的 so 名字不同，所以不能写死 `libksud.so`。
- `no-tracefs` 分支是实验性的：它依赖伪造 cred 的完整能力集，能写 `/data/adb` 但不保证稳定。
- 98260 链各家族载荷里只有 6.6 在本机实测标定过，其余家族是 offsets-only 待标定；6.12 的「进程内 patch + finit_module」那段没有真机数据。
- 标定只对 **同 build** 有效；同族不同 build 的符号地址和 call site 都会变。

## 许可与致谢

本仓库整体以 **GPL-2.0** 分发（见 [LICENSE](LICENSE)、[NOTICE](NOTICE)）。
原因：`payload/wacom-src/exp.c` 与随包的 `ek-w1-uid0-6.6` 二进制衍生自上游
[woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO)（GPL-2.0-only）。

| 部分 | 许可 | 依据 |
| --- | --- | --- |
| 全仓 | GPL-2.0 | 见上 |
| `payload/wacom-src/exp.c`、`assets/payload/wacom/ek-w1-uid0-6.6` | GPL-2.0-only | 衍生自 [woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO) |
| `payload/src/`（98260 链）、`assets/payload/ek-core-android` | 上游 MIT，仓内按 GPL-2.0 分发 | [woshigenm/CVE-2026-98260](https://github.com/woshigenm/CVE-2026-98260) |
| `payload/wacom-src/ksu_boot.c`、`payload/src/ek-core-uid0.c` | 原创 | 运行时调用管理器 CLI，不捆绑 KernelSU 代码 |

### 致谢

- [woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO)
  —— 99491 uhid/uinput 链的原始 PoC（三模式 + uid 0 shell + 可选临时 KernelSU），本仓库载荷的基底，GPL-2.0
- [woshigenm/CVE-2026-98260](https://github.com/woshigenm/CVE-2026-98260)
  —— 98260 posix timer UAF 的 PoC（6.12 家族），MIT
- [tiann/KernelSU](https://github.com/tiann/KernelSU)
  —— `late-load` 机制与内核模块格式（GPL-3.0，本仓库只调用、不捆绑）
- [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku)
  —— 无 root 侧的执行通道（Apache-2.0，只调用、不捆绑）
- [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  —— fake cred + ksud late-load 组合思路的参考实现
- [wushidia/dada-cve](https://github.com/wushidia/dada-cve)、
  [nisu123f/dada-cve-AN00](https://github.com/nisu123f/dada-cve-AN00)
  —— call site 基线与 Honor 机型的移植参考
- [V4bel](https://github.com/V4bel)（Hyunwoo Kim）
  —— EK-CORE 系列的原始研究思路（早期仓库已不可查，致作者主页）
- GhostKey 系列工具 —— 早期出处 `Again1996-bit/EK-CORE-GhostKey` 已 404，
  同族公开实现见 [Feiman55/CVE-2026-98260-GhostKey](https://github.com/Feiman55/CVE-2026-98260-GhostKey)

第三方本体（KernelSU 的 `ksud`/`kernelsu.ko`、Shizuku）由用户自行安装，仓库内不含其源码或二进制。
