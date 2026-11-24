# 更新日志

## 许可变更（2026-11-24）

- 仓库许可从 MIT 改为 **GPL-2.0**：`payload/wacom-src/exp.c` 与随包载荷衍生自
  [woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO)（GPL-2.0-only）。
  新增 `NOTICE` 逐部分说明；README 补上带链接的致谢。

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
