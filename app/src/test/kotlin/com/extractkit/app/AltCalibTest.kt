package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 现场标定：拿 E:\alt_an00 的镜像完整走一遍「无 BTF」链路，
 * 打印 7 个符号 / 结构偏移 / call site / device.cfg 字节数，并把 cfg 落盘。
 */
class AltCalibTest {

    private fun load(path: String): ByteArray? = runCatching {
        val f = File(path)
        if (!f.isFile) return null
        val head = f.inputStream().use { it.readNBytes(8192) }
        if (head.size >= 64 && String(head, 0, 8, Charsets.US_ASCII) == "ANDROID!") {
            val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
            RandomAccessFile(f, "r").use { raf ->
                raf.seek(4096)
                ByteArray(size).also { raf.readFully(it) }
            }
        } else f.readBytes()
    }.getOrNull()

    @Test
    fun calibrateAltAn00() {
        // 现场标定用的镜像不在仓库里：没有就跳过，别把「本机没素材」当成回归。
        assumeTrue("本机没有 E:/alt_an00/Image", File("E:/alt_an00/Image").isFile)
        val img = load("E:/alt_an00/Image")
        assertNotNull("镜像不存在", img)
        val r = KallsymsFinder.find(img!!) { }
        assertNotNull("kallsyms 失败", r)
        val syms = r!!.symbols
        val base = r.relativeBase

        val btf = runCatching { BootImage.extractBtf(img)?.let { Btf.parse(it) } }.getOrNull()
        println("[calib] base=0x${java.lang.Long.toHexString(base)} numSyms=${r.numSyms} map=${syms.size} btf=${btf != null}")

        val off = ConfigGen.offsetsFromCode(img, syms, base)
        assertNotNull("offsetsFromCode 返回 null", off)
        val o = off!!
        fun h(v: Int) = "0x" + Integer.toHexString(v).uppercase()
        println("[calib] itimerSize=${h(o.itimerSize)} node=${h(o.itimerNode)} head=${h(o.itimerHead)} elist=${h(o.itimerElist)}")
        println("[calib] taskCred=${h(o.taskCred)} taskComm=${h(o.taskComm)}")
        println("[calib] credSize=${h(o.credSize)} uid=${h(o.credUid)} sec=${h(o.credSecurity)} user=${h(o.credUser)} ns=${h(o.credUserNs)} ucounts=${h(o.credUcounts)} groups=${h(o.credGroups)}")

        val anchors = ConfigGen.ANCHOR_SYMBOLS.map { it to (syms[it] ?: 0L) }
        println("[calib] anchors=" + anchors.joinToString { "${it.first}=0x${java.lang.Long.toHexString(it.second)}" })
        listOf("do_timer_create", "selinux_state", "panic_on_warn", "root_user", "init_user_ns", "init_ucounts", "init_groups")
            .forEach { println("[sym] $it=0x" + java.lang.Long.toHexString(syms[it] ?: 0L)) }

        // 本地再扫一遍 kmem_cache_create 的 size 参数（taskStruct 尺寸不是 Offsets 的字段）
        fun word(p: Int): Long =
            ((img[p].toLong() and 0xFF) or ((img[p + 1].toLong() and 0xFF) shl 8) or
                ((img[p + 2].toLong() and 0xFF) shl 16) or ((img[p + 3].toLong() and 0xFF) shl 24))

        fun sizeOf(fn: String): Int? {
            val va = syms[fn] ?: return null
            var p = (va - base).toInt()
            val end = minOf(p + 0x600, img.size - 4)
            var w1 = -1
            while (p < end) {
                val w = word(p)
                val rd = (w and 0x1FL).toInt()
                val top = w and 0xFF800000L
                if ((top == 0x52800000L || top == 0xD2800000L) && (rd == 1 || rd == 2)) {
                    val v = (((w ushr 5) and 0xFFFF) shl (16 * ((w ushr 21) and 0x3L).toInt())).toInt()
                    if (rd == 1) w1 = v
                } else if ((w and 0xFC000000L) == 0x94000000L) {
                    if (w1 >= 0x600 && w1 <= 0x3000) return w1
                    w1 = -1
                }
                p += 4
            }
            return null
        }
        println("[calib] taskSize=0x" + Integer.toHexString(sizeOf("fork_init") ?: 0))
        println("[calib] credInitSize=0x" + Integer.toHexString(sizeOf("cred_init") ?: 0))
        val cs = CallSiteFinder.find(img, syms, base)
        println("[calib] callsites timer=+${h(cs?.timerOffset ?: 0)} cred=${h(cs?.credLow21 ?: 0)} task=${h(cs?.taskLow21 ?: 0)}")

        val m = ConfigGen.Measured(
            timerSiteOffset = cs?.timerOffset ?: 0,
            credSiteLow21 = cs?.credLow21 ?: 0,
            taskAllocLow21 = cs?.taskLow21 ?: 0,
            taskAllocBytes = o.taskCred + 0xA0,
            credReq = o.credSize,
            credAlloc = (o.credSize + 15) / 16 * 16,
        )
        val cfg = runCatching { ConfigGen.emitCfgBlob(syms, o, m) }.getOrNull()
        assertNotNull("emitCfgBlob 失败", cfg)
        println("[calib] cfg=${cfg!!.size} B magic=${String(cfg, 0, 8, Charsets.US_ASCII)}")

        File("E:/alt_an00/device.cfg").writeBytes(cfg)
        File("E:/alt_an00/calib.txt").writeText(
            buildString {
                appendLine("release=5.10.252-android12-9-g839eb53a56c3")
                appendLine("base=0x${java.lang.Long.toHexString(base)}")
                appendLine("symbols=${r.numSyms}")
                appendLine("itimerSize=${h(o.itimerSize)}")
                appendLine("taskCred=${h(o.taskCred)} taskComm=${h(o.taskComm)}")
                appendLine("credSize=${h(o.credSize)} uid=${h(o.credUid)} sec=${h(o.credSecurity)}")
                appendLine("credUser=${h(o.credUser)} userNs=${h(o.credUserNs)} ucounts=${h(o.credUcounts)} groups=${h(o.credGroups)}")
                appendLine("timer=+${h(cs?.timerOffset ?: 0)} cred=${h(cs?.credLow21 ?: 0)} task=${h(cs?.taskLow21 ?: 0)}")
                appendLine("cfg=${cfg.size}")
            },
        )
        assertTrue("cfg 大小异常", cfg.size in 300..400)
    }

    private fun assertTrue(msg: String, cond: Boolean) = org.junit.Assert.assertTrue(msg, cond)
}
