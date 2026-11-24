package com.extractkit.app

import android.content.Context
import java.security.MessageDigest

/**
 * 9.354: 99491 profiles derived offline from kernels we actually own.
 *
 * Each entry pins the exact `uname -r` string the payload compares against plus the JSON
 * that the 9.353 calibration pipeline produced from that build's boot.img (BTF structure
 * offsets + kallsyms addresses + the cred allocation call site). Shipping them in assets
 * means the chain runs on these builds without the user importing a boot.img first.
 *
 * Only put values here that came out of a real image for that exact release: a guessed
 * profile writes cred / input_dev with the wrong offsets and panics the phone.
 *
 * 9.406: the payload now compares builds by version + "-androidN" + "-g<hash>" only, so a
 * table derived from one local build also covers the same kernel image rebuilt with a
 * different -abogkiNNNNNNNNN-4k stamp. Entries below stay per exact uname string; a release
 * that is not listed is still reachable by calibrating that boot.img in-app (CalibrationModel
 * writes both the profile and the ko-syms table).
 */
internal object WacomBuiltin {
    internal data class Entry(
        val release: String,
        val asset: String,
        val size: Int,
        val sha256: String,
    )

    private const val DIR = "payload/wacom/profiles/"

    internal val ENTRIES: List<Entry> = listOf(
        // HONOR PPG-AN00 6.6.118 g5549: the hand-verified original profile.
        Entry(
            "6.6.118-android15-8-g554929766a0d-abogki544555896-4k",
            "payload/wacom/profile-6.6.json",
            3162,
            "5e6809b219280ce68d35d4a6c1fadb88a17db6da9d281de35059591c7beb70c2",
        ),
        // 6.6.118 ga812a19 (same family as g5549, different .data addresses).
        Entry(
            "6.6.118-android15-8-ga812a1946391-abogki576098434-4k",
            DIR + "6.6.118-android15-8-ga812a1946391-abogki576098434-4k.json",
            3188,
            "d0630ed052c4b3de7888e39b190848678007b4d5c71f719a248cccaae091b8f0",
        ),
        // 6.6.89 g082e5a98dac1.
        Entry(
            "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k",
            DIR + "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k.json",
            3186,
            "9ea5982cbd394aeb82299eebf16259ee5b7cc71475dfee943432150b1b5ea968",
        ),
        // 6.12.58 gdf8d34cadbf7 (HONOR PPG-AN00 6.12 user boot.img): derived offline from that
        // image. Input_handle.handle_events / callback_head are 6.12 names and are read from BTF.
        Entry(
            "6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k",
            DIR + "6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k.json",
            3189,
            "9d811c925c5323266930cf0006462b0b31c5eebb7b02f323c04c3c70c4f4cac9",
        ),
        // 6.12.58 g142ddad31e60: upstream FANXIAOCHAO profile, shipped verbatim with its ko-syms
        // table so a device on that exact build runs without importing a boot.img first.
        Entry(
            "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k",
            DIR + "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k.json",
            3213,
            "b184f8ee02fd77b2d367258533f5631b34ea841355a06bba78fa8b738c660eeb",
        ),
        // 6.12.69 g5fd39602326e: derived from the user-supplied boot_a.img (6.12.69, header v4,
        // lz4 legacy kernel) with the in-app pipeline run host-side: BTF 7,047,098 B, kallsyms
        // 127,049 symbols, base 0xffffffc080000000, 59 values derived, validate clean.
        Entry(
            "6.12.69-android16-6-g5fd39602326e-ab16372235-4k",
            DIR + "6.12.69-android16-6-g5fd39602326e-ab16372235-4k.json",
            3179,
            "3d0f2608934b3ba6e757bc25d89890fb80cafbcc54e25cd1690325309cbc62b2",
        ),
        // 6.1.128 g52c266270871: cred is 176 B and uid sits at +4 on this generation.
        Entry(
            "6.1.128-android14-11-g52c266270871",
            DIR + "6.1.128-android14-11-g52c266270871.json",
            3152,
            "87f6b63ae5448a2b244542e7c2c40fdec3854257e9748fb5bc47279118663944",
        ),
        // 6.1.157 g19a495a97bff.
        Entry(
            "6.1.157-android14-11-g19a495a97bff",
            DIR + "6.1.157-android14-11-g19a495a97bff.json",
            3153,
            "222d5b4022a95af34a0084fddd2c3b090103926e6bc02c33515a34f03448e8ce",
        ),
    )

    /** Exact match only: the payload strcmp()s uname().release, so a prefix would deploy the wrong bytes. */
    internal fun forKernel(kernel: String): Entry? =
        ENTRIES.firstOrNull { RelMatch.same(it.release, kernel) }

    internal fun releases(): List<String> = ENTRIES.map { it.release }

    /** Read + verify. Any mismatch means table and bytes disagree, so return null instead of guessing. */
    internal fun bytes(ctx: Context, e: Entry): ByteArray? {
        val b = runCatching { ctx.assets.open(e.asset).use { it.readBytes() } }.getOrNull() ?: return null
        if (b.size != e.size) return null
        if (!sha256(b).equals(e.sha256, ignoreCase = true)) return null
        return b
    }

    private fun sha256(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(b)
        val sb = StringBuilder(d.size * 2)
        for (x in d) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }
}