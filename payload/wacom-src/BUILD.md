# wacom payload source (9.457)

这几个文件就是 `app/src/main/assets/payload/wacom/ek-w1-uid0-6.6` 的源码，
用 NDK r29 静态编译成单文件 PIE（aarch64），构建命令见下。

## 构建
```
NDK=/path/to/android-ndk-r29/toolchains/llvm/prebuilt/<host>/bin
CC=$NDK/aarch64-linux-android24-clang
$CC -O2 -g -Wall -Wextra -Wno-unused-parameter -fPIE -I . -c exp.c
$CC -O2 -g -Wall -Wextra -Wno-unused-parameter -fPIE -I . -c ksu_boot.c
$CC -O2 -g -Wall -Wextra -Wno-unused-parameter -fPIE -I . -Dmain=ko_patch_cli -c ko_patch.c
$CC -pie -pthread -o ek-w1-uid0-6.6 exp.o ksu_boot.o ko_patch.o
$NDK/llvm-strip --strip-all ek-w1-uid0-6.6
```

产物当前 124,984 B，sha256 `6530b75fdaa340a8f5b0baf51bc2c1ee9c65fb7a9751c9287f44c06f246c4b22`。

## 9.457 相对 9.444 的载荷变化
- 9.453：`ksu_boot.c` 恢复 `ksu_install_userspace()`（9.448 曾按「ksud 归管理器管」整段换成 no-op，
  结果内核模块虽然 finit_module 成功、用户态 /data/adb/ksud 却没落地，管理器始终显示「未安装」）。
- 9.454：`exp.c` 加 `self_cell_diag()`，抢槽失败时打印 attempt/rc/errno/got/want，不再只有一行 failed。
