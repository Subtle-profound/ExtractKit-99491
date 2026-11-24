package com.extractkit.app

/**
 * EK-W1（wacom HID UAF）链已标定的内核。
 *
 * 与 GhostCalibrated 同构：符号地址、三处 alloc call site、cred/input_dev 结构偏移
 * 全部按 build 编死在二进制里，名单外的内核在 App 侧就拒跑（拿别的 build 去写会
 * 写坏 cred 结构，panic_on_oops=1 直接重启）。
 *
 * 9.354 起改由 `WacomBuiltin` 内置整份 profile（每支一个 release 一份），这里只剩
 * 早期按前缀放行的两支；新内核进 `WacomBuiltin.ENTRIES`，不再往这里加。
 */
internal object WacomCalibrated {
    val RELEASES: Set<String> = setOf(
        // boots.img 实测：uhid_device_add_worker / 3 处 alloc site / BTF 结构偏移逐项核对
        "6.6.118-android15-8-ga812a1946391",
        // 6.6.118-android15-8-g554929766a0d-abogki544555896-4k（HONOR PPG-AN00 / VKJ-AN90）
        "6.6.118-android15-8-g554929766a0d",
    )
}