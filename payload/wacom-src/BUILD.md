# payload/wacom-src —— CVE-2026-99491 链的原生载荷

产物就是 App 里的 `app/src/main/assets/payload/wacom/ek-w1-uid0-6.6`（单个静态 ELF，
设备上由 App 推送到 `/data/local/tmp/eksu.bin` 执行）。

```
aarch64-linux-android24-clang -O2 -g -Wall -Wextra -Wno-unused-parameter \
  -fPIE -fstack-protector-strong -pie \
  -o build/exp.exe exp.c ko_patch.c ksu_boot.c
llvm-strip --strip-all build/exp.exe
```

- `exp.c`：主利用。uinput 的 4 字节链式写 + tracepoint/slab 回收定位 `uhid` 的
  `input_buf`，伪造 cred 后把 uid/euid/fsuid 与 cap 集写成 0/满，再交给 `ksu_boot.c`
  让管理器自己的 CLI 去 `late-load`。
- `ko_patch.c`：内核模块 elf 的符号重定位补丁（KernelSU 的 kernelsu.ko 按 KMI 取）。
- `ksu_boot.c`：KernelSU 引导层。argv 是
  `late-load --post-magica --allow-shell --package-name <管理器包名>`，
  装用户态走 `ksud.new -> mv -f /data/adb/ksud` + `/data/adb/ksud install`。

运行时读 `/data/local/tmp/eksu/wacom.profile`（App 生成，按内核 build 的常量）。
