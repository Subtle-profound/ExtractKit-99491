# 更新日志

## 许可变更（2026-11-24）

- 仓库许可从 MIT 改为 **GPL-2.0**：`payload/wacom-src/exp.c` 与随包载荷衍生自
  [woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO)（GPL-2.0-only）。
  新增 `NOTICE` 逐部分说明；README 补上带链接的致谢。

## 9.457 — credAlloc 按 64 B 对齐 + 前 13 版的行为修正

- **cred_jar 对齐**：`credAlloc` 原来按 16 B 取整，但内核 `cred_init()` 用
  `kmem_cache_create("cred_jar", sizeof(struct cred), 0, SLAB_HWCACHE_ALIGN|…)`，是按 cache line
  （64 B）对齐的。新增 `ConfigGen.credSlabObjectBytes()`，现场标定与测试同源调用。
  `credSize = 0xB8` 两边都得 `0xC0`，但对 `credSize ∈ (192, 208]` 之类会少算一档。
- **一次点击只跑一次**（9.445）：删掉自动重跑第二轮。第一轮只要 fire 过，`exp.bootid` 已写，
  第二轮必被 `fire_guard()` 挡；与其白跑一轮并让人误读成 PARKED，不如直接给结论。
  代价：6.6 假 cred 页被回收的失效概率从 ~0.4% 回到 ~6%。
- **环境自检 tracefs 判据修正**（9.456）：原来查 `events/kmem/*/enable`（Android 上 root-only，
  永远 no）导致所有设备都报 BLOCKED。载荷其实只写 world-writable 的
  `events/kmem/rss_stat/trigger` + `tracing_on` + 读 `trace_pipe_raw`，判据已改成这三条。
- **恢复 `ksu_install_userspace()`**（9.453，撤销 9.448 的 no-op）：内核模块 `finit_module` 成功
  但 `/data/adb/ksud` 没落地时，管理器会一直显示「未安装」。七步：拷 `.new` → chmod → mv →
  mkdir → `<ksud> install` → `su`/`ksud` 软链。**这一段永久保留。**
- **抢槽诊断**（9.454）：`exp.c` 新增 `self_cell_diag()`，失败时打 attempt / rc / errno /
  got / want，而不是只有一行 `self cell install failed`。
- **内置 profile 增**：vivo V2505A `6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k`（9.446）、
  Redmi 2510DRK44C `6.6.118-android15-8-g0908354dac1b-ab16143355-4k`（9.455）。
  合计 139 条。都用官方 `boot.img` 离线算好（BTF + kallsyms + BL 反汇编），不需要在手机上标定。
- **标定页**：日志区改成吃掉剩余高度、框内滚动（9.450，同时修掉「没 Shizuku 点环境自检 ANR」
  —— Shizuku 连接与文件 IO 移到 `Dispatchers.IO`）；顺序归位（9.449）；链路推荐大字先加后删（9.447→9.452）。
- **删除「查询固件包」整条功能**（9.451 及其前身）：`FirmwareActivity` / `FirmwareCatalog` /
  `FirmwareBootExtractor` / `IknowResolver` / `iknow.tsv` 全部移除，顺带清掉一批死代码
  （APK 11.07 MB → 10.60 MB）。
- 载荷 124,984 B sha256 `6530b75fdaa340a8f5b0baf51bc2c1ee9c65fb7a9751c9287f44c06f246c4b22`。
- APK 10,596,571 B sha256 `032050fcb64dbf4051f75a1bf47eb9f852037d744a734ed7f8868a1b11cb1b72`。
- 验证：`chk9457.py` 14/14、单测 234 tests / 0 fail / 4 skip；真机只验了 tracefs 判据（READY）与布局。

## 9.444 — tracefs 补回 outq disarm（治 panic）+ 内置 6.12.69 profile

- **修 panic**：`tracefs` 分支在 exec 管理器 CLI 前恢复 `outq[0]/outq[1]` 置 NULL。
  之前 CLI `daemonize()` 关 fd → `uhid_char_release()` `kfree()` 回收来的 2K 槽 → 一秒后 panic。
  `real_cred` / `no-tracefs` 本来就 disarmed，这次补齐第三支。
- **内置 profile**：新增 `6.12.69-android16-6-g5fd39602326e-ab16372235-4k`
  （symbols 127,049、relativeBase `0xffffffc080000000`、derived 59/ok、ko-syms 226/缺 0），
  连同 `ko-syms` 注册进 `WacomBuiltin.ENTRIES` 与 `ExtractEngine.SYMS_BY_RELEASE`。
- 载荷 126,256 B sha256 `5b7de021af47b74803bbdee263633d0deee79ccc005556c3572cda63acdd104e`。
- APK 11,069,651 B sha256 `e252e07307b277a5a6ae24d80ecbfacf1986236059af008929770ad952e4f593`。
- 验证：`chk9444.py` 35/35、单测 237 tests / 0 fail；真机未跑。

## 9.443 — 整份还原上游

- 把 `exp.c` 还原成上游 `CVE-2026-99491` 原文，只删掉 `ko_syms_check` 的 extern 与预检块
  （`+0/-16`）。用于排除此前几版自己引入的时序回归。
- 823 行以上的改动不再保留：日志静音宏 `VLOG`、in-process loader 等。

## 9.439 — 按内容打分选取管理器 CLI

- 管理器的 ksud 不再写死 `lib/arm64-v8a/libksud.so`：遍历 `lib/<abi>/*.so` 用
  `-V` 输出与特征串打分，取最高分（同分取大），把 profile 里的 `ksu_ksud_name` 改成它。
- `late-load` 的 argv 改为空格形式：`late-load --post-magica --allow-shell --package-name <pkg>`。

## 9.396 / 9.397 — CVE-2026-98260 · 6.12 载荷接入

- 6.12 家族改跑 98260 链（posix timer UAF），含单文件 PIE 与 `ko_patch` 的内核模块补丁。

## 早期

更早的 9.3xx / 1.x 版本记录见仓库 Releases 与 `docs/`。
