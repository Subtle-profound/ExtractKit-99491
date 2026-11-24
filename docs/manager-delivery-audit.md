# 根管理器「送达」全链路审计（7.12）

目标：App 里选哪个管理器，就必须由那个管理器的 ksud 注册那个包名。
判定标准：同一次运行里 4 处一致 + 管理器自己显示「工作中」。

| # | 环节 | 证据点 | 7.12 状态 |
|---|------|--------|-----------|
| 1 | App 选中哪个包 | `· 目标管理器：<label> (<pkg>)` + `· 选择原因：…` | 已验证（`ManagerChooser` + 42 单测） |
| 2 | 环境变量怎么带 | `RunEnv.command()` → `cd <dir> && EXTRACTKIT_MGR=<pkg> ./bin` | 已验证（7.9 修复：变量原先只作用于 `cd`） |
| 3 | payload 主进程收到没 | `[mgr] manager package=<pkg>` | 已验证 |
| 4 | **凭据子进程**收到没 | `[mgr] child package=<pkg>` | 已验证（7.12 修复：`execve` 用 `ep[]` 清空环境） |
| 5 | 脚本收到没 | `[ksu] mgr=<pkg>` | 已验证 |
| 6 | 用谁家的 ksud | `[resolve] … owner=<pkg> cross=0/1 why=self/cross` | 已验证（owner 感知，跨品牌会警告） |
| 7 | ksud 支持这个参数吗 | `[ksu] help:  --package-name <PACKAGE_NAME> …` + `[ksu] flag=package-name ok` | 已验证（MilkSU 0.2.3 支持；无 `--package-uid`） |
| 8 | 注册时传的包名 | `late-load --kmi … --allow-shell --package-name <pkg>` | 已验证 |
| 9 | 驱动真的加载了吗 | `[ksu] late-load rc=0` + `KSU_LOADED` + `kernelsu … - Live` | 已验证 |
| 10 | 管理器认不认 | MilkSU 首页「工作中 [越狱模式] LKM」 | 已验证 |
| 11 | root 可用 | `su -c id` → `uid=0 … context=u:r:ksu:s0` | 已验证 |

## 已排除的历史坑

- **env 位置**：`VAR=x cd dir && ./bin` 的变量只给 `cd`（7.8 事故）。
- **execve 清环境**：`main → fork → execve(/proc/self/exe, …, ep[])`，`ep[]` 只有 PATH（7.11 事故）。
- **wait 分支早退**：重执行走 `argv[1]=="wait"`，`mgr_sanitize()` 在它之后才跑 → 永远拿默认值（7.12 修）。
- **脚本 CRLF**：Windows 文本模式写出 `\r\n`，设备上 `sh` 直接语法错误 → 空 `[resolve]` → 假「缺 ksud」（7.11 修，`gen-ksu-stage.py` 全部 `newline='\n'`）。
- **shell 域读不了 /data/app**：`why=noperm` 明确告知，不是「缺 ksud」。
- **ksud 全零文件**：每次都用管理器里的真 ksud 原子覆盖 `/data/adb/ksud`。
- **同一次开机换管理器**：`--package-name` 只在加载那一刻写进驱动，已加载时打 `KSU_ALREADY` + `hint=reboot`，App 侧同步红/黄横幅提示重启。

## 护栏（回归用）

- `tools/check-env-plumbing.py`：`mgr_sanitize` 必须在 wait 分支前；`ep[]` 必须带 `g_mgr_env`；跑 `ksu_stage` 的那次 `execve` 的 `envp` 必须带 `g_mgr_env`；必须存在 `mgrprobe`。已接进 `tools/build-payload.sh`。
- `tools/test-resolve.sh`：宿主机造假树跑解析，13 条断言（self / cross / 无来源 / 不含 `ksu/bin/ksud` / DRYRUN）。
- `mgrprobe`：`EXTRACTKIT_MGR=<pkg> ./payload mgrprobe` 用**和凭据子进程完全相同的 ep[]** 走一遍 exec，打印父子两侧包名，不碰内核。

## 7.12 真机实测（PPG-AN00 / 6.6.118）

```
[mgr] worker execing ksu_stage.sh (step 3)
[ksu] start uid=0 selinux=Permissive
[resolve] app_root=/data/app readable=1
[resolve] mgr=io.milksu.manager src=…/io.milksu.manager-…/lib/arm64/libksud.so owner=io.milksu.manager cross=0 why=self
[ksu] 来源版本: ksud MilkSU 0.2.3 (uapi: 6)
[ksu] help:       --package-name <PACKAGE_NAME>  manager package name [default: io.milksu.manager]
[ksu] flag=package-name ok
[ksu] 已替换 /data/adb/ksud <- …/libksud.so
[ksu] kmi=android15-6.6 … mgr=io.milksu.manager
[ksu] late-load rc=0
KSU_LOADED
```

`grep '^kernelsu ' /proc/modules` → `kernelsu 442368 2 - Live`
`su -c id` → `uid=0(root) … context=u:r:ksu:s0`
MilkSU 首页 → 「工作中 [越狱模式] LKM，版本 32802-6」
