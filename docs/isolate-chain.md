# 提权窗口内的场外因素清单（9.270 isolate）

目标：从 payload 起来到它 parking 的这段时间里，**只有链路自己在动**。任何第三方进程、
App 自己的清理逻辑、我的 adb 探测，都可能把「借来的 cred 页」提前还给 cred_jar，
从而触发 slub 双归属 -> `BUG()` -> 整机重启（panic_on_oops=1 时 Oops 也是重启）。

内核侧事实（`_kernel.elf` 反汇编）：
- `commit_creds` @ `0xffffffc0802388e0`，cred(0x820) != real_cred(0x818) 时跳 `0xffffffc080238ab0` = `brk #0x800`。
- `__sys_setfsuid` @ `0xffffffc0807d5174`：先 `prepare_creds`，只有 fsuid 真的变化才 `commit_creds`。

## A. 已在本版中和（代码里改掉）

| # | 场外因素 | 机理 | 本版处理 |
|---|---|---|---|
| A1 | `Shell.reapStaleUserServices()`（`Shell.kt`）| `su -c "kill -9 $(pgrep -f 'com.extractkit.app:shell')"`，payload 正是 `:shell` 的子进程；打死驻留进程 -> put_cred -> 借来的页还给 cred_jar -> BUG | 先 `pgrep -f 'ek-core-uid0'`，只要还有 payload 进程就跳过 reap，并记 `reap skipped: payload pid=... alive (isolate)` |
| A2 | `session.close()`（`ExtractEngine.kt` stream 收尾）| 超时也会 close，Shizuku 会话一收，payload 进程被连带收掉 | parked / fatal / timedOut 三种情况一律不 close，进程留活到手动重启 |
| A3 | App 自动重试 | 一次点击跑两趟，一个 boot 里堆多个驻留进程/多张借来的页 | 默认 `allow_retry=false`；打开时也有 boot_id 判定，重启过就不重试 |
| A4 | 升级安装 | `Shizuku` 绑定带 `.version(BuildConfig.VERSION_CODE)`，装新版本会杀掉旧 `:shell` —— 连同里面的驻留 payload | 装机前必须确认设备上**没有驻留进程**（就是重启后再装） |

## B. 需要操作纪律（不改代码，靠做法）

| # | 场外因素 | 机理 | 做法 |
|---|---|---|---|
| B1 | adb 探测 | 每次 `adb shell`、`sha256sum`、`ls -l`、`grep` 都在 uid 2000 域里 fork 进程、分配 cred/task_struct slab，正好污染我们要 plant 的那些 slab | **提权期间我不碰设备**；只在跑完后拉一次日志 |
| B2 | 超级用户列表 / 管理器 UI | MilkSU/MapleSU 每开一次列表就 `su` 一轮，可能触发它自己的 late-load / watchdog | 跑链期间不开管理器窗口；`安全模式`开关关掉（它会在 late-load 前停模块） |
| B3 | perfetto / atrace / traced | tracefs 的 kmem 事件是全局的，别的写者会抢 enable、抽走/覆盖事件，导致我们 `[ids] alloc=0`、plant 落空 | 跑链期间不要抓 trace，不要接 perfetto |
| B4 | 重复点击 | 同一个 boot 里第二次点，会在已有驻留的情况下再 plant 一次 | 一次点击，失败就重启再试 |

## C. 环境本身（不能改，只能识别）

| # | 因素 | 证据 | 影响 |
|---|---|---|---|
| C1 | `panic_on_oops=1` | shell 读 denied；su 读为 1 | 任何 Oops 都直接整机复位，所以「看起来像 panic」的门槛很低 |
| C2 | tracefs 写权限 | 日志 `[trace] direct ... enable denied (errno=13)` -> `[ids] alloc=0 free=0 ...` | 页归属只能靠 reclaim 兜底，plant 命中率低；命中不了就写进别人的页 |
| C3 | `kptr_restrict=2` | 无 root 读不到 kallsyms 地址 | slide 只能走标定/sysctl 路径 |
| C4 | 内核 BUG_ON | 见文件头 | 假 cred 一旦 cred != real_cred，任何 exec / setfsuid 变化都会 `brk #0x800` |

## 跑链前的检查单（按顺序）

1. 设备**刚重启**，一个 boot 内没跑过链；`/data/local/tmp/extract-kit/PARKED` 是上一个 boot 的残留可以不理，本 boot 新建就是脏。
2. 关掉「安全模式」；不要 touch `use_fam` / `use_literal`。
3. 管理器窗口不要停在超级用户列表页。
4. 我这边不执行任何 adb 命令（B1）。
5. 点一次；等日志自己停；失败就重启再点，不要在同一个 boot 里连点。

## 9.273 / 9.274：交接脚本删除内嵌 + 真 cred 路径补交接

真机事实（9.271 那趟，日志 D:\deepseek work\_devEK-CORE.log）：payload 本体无 panic 拿到
uid=0（`[child] setresuid(0,0,0)=0 resuid=0/0/0`），但**整趟没有 ksu 交接**——
日志里没有 `[fake] forking ksud worker`，ksu_stage.out 的 mtime 还停在 01:03。
两个独立原因，都修了：

### 1. 内嵌脚本必须死（9.273）

- 以前 payload 里编进一份 `ksu_stage.h`，App 又往设备推一份 `assets/stage/ksu_stage.sh`。
  两份不同步时，设备上跑的是旧梯子，却因为 `late-load rc=0` 照样打 `KSU_LOADED`
  （9.271 就是这样假成功的：设备上是 16,970 B / mtime 01:37 的 9.222 脚本）。
- 现在：`payload/src/ek-core-uid0.c` 不再 `#include "ksu_stage.h"`；
  `write_ksu_script()` 只校验 `EXTRACTKIT_STAGE` 指向的脚本可读并 chmod；
  没设或读不到时 fork 前就 `logf("[ksu] handoff skipped: no stage script ...")` 然后退出，
  **不会再出现「没交接却成功」的日志**。`tools/gen-ksu-stage.py` 不再生成头文件，
  并主动删掉残留的 `payload/src/ksu_stage.h`。
- App 侧 `ManagerAudit.deploy()` 推完用 `wc -c` 读回字节数，与 asset 尺寸不等就判失败。

### 2. 真 cred 路径也要交接（9.274）

- 交接只写在 `shell_mode == 4`（`args = "fake"`）分支里，而 App 走的是默认模式
  （`Modes.extract_uid0` 的 `args = ""`），默认分支拿到 uid 0 后只 exec 一个
  `sh -c "id; ...; echo ROOT_SHELL_OK"`，打印完就没了 —— 这就是「uid 0 成功但管理器没加载」。
- 9.274 在默认分支的临时 shell 之前插入同一套交接：脚本可读就 `execve("/system/bin/sh",
  {sh, <stage>})`，环境只带 PATH + `EXTRACTKIT_MGR=...`，stdout/stderr 落
  `/data/local/tmp/ksu_stage.out`（和 fake 分支一致），并先打
  `[ksu] handing off to stage script <path>`。
- 安全性：这条路径上 `setresuid(0,0,0)` 已经返回 0（cred 已重建、cred == real_cred），
  所以 exec 不会撞 `commit_creds()` 的 `BUG_ON(task->cred != old)`；
  fake 分支仍然不 exec（那里 cred != real_cred）。
- 判据：payload 日志出现 `[ksu] handing off to stage script`，随后
  ksu_stage.out 里出现 `KSU_LOADED`，且 `/proc/modules` 里真有 `kernelsu`。
  只看 rc=0 / KSU_LOADED 这两个串不算数（9.271 的教训）。

