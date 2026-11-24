package com.extractkit.app

import android.content.Context
import android.content.SharedPreferences
import java.io.File
import java.security.MessageDigest

/**
 * 9.354：标定出来的 EK-W1 profile 从只存一份扩成一个小库。
 *
 * 为什么是库：用户手上往往有多台机器、或者同一台换过 boot.img。以前 save() 会覆盖上一份，
 * 换回去还得重新扫一遍镜像。现在按 release 分文件存，按 uname().release 全串取 ——
 * payload 的 profile_check_runtime() 就是全串比较，这里不能放宽成前缀，否则会把别颗内核的常量写进 cred。
 *
 * 文件名是 release 的 sha256 前 16 位（release 串里有 - 和 +，不能直接当文件名），
 * 取的时候仍然以文件内容里的 release 为准，防止目录里被塞进来同名不同内容的文件。
 */
internal object WacomCalibStore {

    private const val PREFS = "wacom_calib"
    private const val KEY_AT = "at"
    private const val DIR = "wacom"
    private const val LEGACY_FILE = "wacom-profile.json"
    private const val LEGACY_RELEASE = "release"

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun dir(ctx: Context): File = File(ctx.applicationContext.filesDir, DIR)

    private fun sha256(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(b)
        val sb = StringBuilder(d.size * 2)
        for (x in d) {
            val v = x.toInt() and 0xFF
            if (v < 16) sb.append(48.toChar())
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }

    private fun fileFor(ctx: Context, release: String): File =
        File(dir(ctx), "p-" + sha256(release.toByteArray(Charsets.UTF_8)).take(16) + ".json")

    /** 存一份；写盘成功才记时间戳。同 release 再存就是覆盖它自己。 */
    /**
     * 9.354: the pre-9.354 release kept a single profile file plus a "release" pref.
     * Move it into the content-addressed store once, then delete the old file.
     */
    private fun migrateLegacy(ctx: Context) {
        runCatching {
            val legacy = File(ctx.applicationContext.filesDir, LEGACY_FILE)
            if (!legacy.isFile) return
            val bytes = legacy.readBytes()
            val release = releaseIn(bytes) ?: prefs(ctx).getString(LEGACY_RELEASE, null)
            if (release.isNullOrBlank()) {
                legacy.delete()
                return
            }
            dir(ctx).mkdirs()
            fileFor(ctx, release).writeBytes(bytes)
            legacy.delete()
        }
    }

    fun save(ctx: Context, release: String, json: String): File? {
        if (release.isBlank()) return null
        val bytes = json.toByteArray(Charsets.UTF_8)
        return try {
            dir(ctx).mkdirs()
            val f = fileFor(ctx, release)
            f.writeBytes(bytes)
            prefs(ctx).edit().putLong(KEY_AT, System.currentTimeMillis()).apply()
            f
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 9.407: 同一颗内核就给字节 —— 先按全串取，取不到再按 RelMatch（版本 + g<hash>）找。
     * 文件里记的 release 与这台机的内核不算同一 build 时一律不给。
     */
    fun bytesFor(ctx: Context, kernel: String): ByteArray? {
        if (kernel.isBlank()) return null
        migrateLegacy(ctx)
        val exact = fileFor(ctx, kernel)
        if (exact.isFile) {
            val bytes = runCatching { exact.readBytes() }.getOrNull()
            val rel = bytes?.let { releaseIn(it) }
            if (bytes != null && rel != null && RelMatch.same(rel, kernel)) return bytes
        }
        val all = dir(ctx).listFiles { f -> f.isFile && f.name.startsWith("p-") && f.name.endsWith(".json") }
            ?: return null
        for (f in all) {
            val bytes = runCatching { f.readBytes() }.getOrNull() ?: continue
            val rel = releaseIn(bytes) ?: continue
            if (RelMatch.same(rel, kernel)) return bytes
        }
        return null
    }

    /** 从 profile 原文里取 release。 */
    fun releaseIn(bytes: ByteArray): String? {
        val text = String(bytes, Charsets.UTF_8)
        val m = Regex("\"release\"\\s*:\\s*\"([^\"]*)\"").find(text) ?: return null
        return m.groupValues[1]
    }

    /** 库里所有条目对应的 release（去重、按写入时间新到旧）。 */
    fun entries(ctx: Context): List<String> {
        migrateLegacy(ctx)
        val files = dir(ctx).listFiles { f -> f.isFile && f.name.startsWith("p-") && f.name.endsWith(".json") }
            ?: return emptyList()
        return files.sortedByDescending { it.lastModified() }
            .mapNotNull { f -> runCatching { releaseIn(f.readBytes()) }.getOrNull() }
            .distinct()
    }

    fun count(ctx: Context): Int = entries(ctx).size

    // ---------------------------------------------------------------- 9.404 ko-syms

    private const val SYMS_DIR = "wacom-syms"

    private fun symsDir(ctx: Context): File = File(ctx.applicationContext.filesDir, SYMS_DIR)

    private fun symsFile(ctx: Context, release: String): File =
        File(symsDir(ctx), "s-" + sha256(release.toByteArray(Charsets.UTF_8)).take(16) + ".txt")

    /**
     * 9.404: the ko_patch table calibration derives from the same image. Keyed by release
     * for the same reason the profile store is: the header inside has to match uname().release
     * exactly, so one table can never serve another build.
     */
    fun saveSyms(ctx: Context, release: String, text: String): File? {
        if (release.isBlank()) return null
        return try {
            symsDir(ctx).mkdirs()
            val f = symsFile(ctx, release)
            f.writeBytes(text.toByteArray(Charsets.UTF_8))
            f
        } catch (e: Exception) {
            null
        }
    }

    /** 9.407: 表头 release 与这台机同一 build 就给（全串优先，其次 RelMatch）。 */
    fun symsFor(ctx: Context, kernel: String): ByteArray? {
        if (kernel.isBlank()) return null
        val exact = symsFile(ctx, kernel)
        if (exact.isFile) {
            val bytes = runCatching { exact.readBytes() }.getOrNull()
            val rel = bytes?.let { symsReleaseIn(it) }
            if (bytes != null && rel != null && RelMatch.same(rel, kernel)) return bytes
        }
        val all = symsDir(ctx).listFiles { f -> f.isFile && f.name.startsWith("s-") && f.name.endsWith(".txt") }
            ?: return null
        for (f in all) {
            val bytes = runCatching { f.readBytes() }.getOrNull() ?: continue
            val rel = symsReleaseIn(bytes) ?: continue
            if (RelMatch.same(rel, kernel)) return bytes
        }
        return null
    }

    /** Reads "# kernel_release: <release>" out of a ko-syms table. */
    fun symsReleaseIn(bytes: ByteArray): String? {
        val text = String(bytes, Charsets.UTF_8)
        val m = Regex("^#\\s*kernel_release:\\s*(\\S+)\\s*$", RegexOption.MULTILINE).find(text) ?: return null
        return m.groupValues[1]
    }

}
