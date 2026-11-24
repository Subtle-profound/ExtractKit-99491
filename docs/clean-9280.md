# 9.280 — 从零重写的干净实现

用户指令（m22288 / m22316）：清空以前的脚本、完全从零重写 payload，无冗余代码、运行时无卡顿、软件侧无 bug。

## 1. payload：上游原文 + 上游构建参数，零本地改动
- 源码树 `payload/clean/src/` 是 `refdata/ekit-gh/payload/src` 的逐字节拷贝
  （ek-core-uid0.c 98,570 B、device_config.h、ksu_stage.h、ksu_stage.sh、runtime_cfg.h、trace_layout.h、ek-calib.c）。
- 构建 `tools/build-clean.py` 只做三件事：clang 编译 + llvm-strip + 回写 PayloadCatalog 的 sha 与 assets/SHA256SUMS.txt。
- 参数与上游 `tools/build-payload.sh` 逐字一致：
  `-O2 -static -fno-pie -no-pie -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -pthread --target=aarch64-linux-android34`。
- 产物 `assets/payload/ek-core-uid0` = 471,824 B sha256 `1c06fd4d…`，
  与上游仓 assets/payload/fam 里 5.10/5.15/6.1 三份预编译**字节完全相同** ⇒ 证明「源码+参数=上游成品」，本地零改动。
- 注意：上游 assets 里那份「通用」452,144 B `3ca0cabc…` 比它自己的源码旧，不是源码编出来的结果。

## 2. 交接脚本：改用上游原文
- `assets/stage/ksu_stage.sh` = 上游 10,716 B（sha256 `0b43dba7…`）。
- 成功判据只有一条：`grep -q '^kernelsu ' /proc/modules` 之后才 `KSU_LOADED`，否则 `KSU_MISSING`。
- 旧脚本（16,170 B / 19,698 B 那几代）连同 fam 六支、honor/perfprobe/ko66/insmod 资产全部退役：
  `assets/payload/fam/` 删除，`PER_FAMILY = emptyMap()`，所有内核只用 UID0 一支。

## 3. 软件侧：唯一一处真卡顿
- `Shell.kt` connectOnce 里原本是
  `Handler(main).post { reapStaleUserServices(); Shizuku.bindUserService(...) }`，
  而 reap 在主线程 `waitFor(4s)` + `waitFor(6s)` ⇒ 点击开始后主线程最坏堵 10 秒。
- 9.280 起 reap 整段跑在 daemon 线程（`extractkit-reap`），不 join；探针超时 2 s；
  真正 kill 前先 `if (service != null) return`（避免杀掉自己刚绑上的 UserService）。
- 同时删掉死代码：`ChainPlan.KO66_ASSETS`、`ExtractEngine.deployAux`、`GlassMainActivity.suAvailable/runSu`。

## 4. 判据（用户自己跑一次看这里）
1. UI 日志里点「开始提权」后立刻进入 `connect shell`，不再长时间卡住；
2. payload 日志出现 `[fake] worker execing ksu_stage.sh`；
3. `/data/local/tmp/ksu_stage.out` 结尾必须是 `KSU_LOADED`；
4. 独立核对：`cat /proc/modules | grep '^kernelsu '` 真有一行，`su -c id` 得到 `uid=0`。
   （rc=0 与 KSU_LOADED 单独出现都不算成功——旧脚本曾经打假成功。）
