package com.extractkit.app

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 9.412 · 本机自检采集。
 *
 * 背景：99491 三条链在 6.12 上都是「kfree 看到了，但喷上去的 skb 一个都没落进那个槽」。
 * 要判断这是「参数不对（尺寸类 / CPU）」还是「内核硬隔离（CONFIG_RANDOM_KMALLOC_CACHES）」，
 * 需要三样证据：/sys/kernel/slab 里有没有 kmalloc-rnd-*、profile 里 input_dev_size 的真实值、
 * tracefs 是否可写。以前这些只能靠 adb 在电脑上取，这个类让 App 用 Shizuku(shell, uid 2000)
 * 直接在本机采完并拼成一段可直接粘贴的纯文本报告。
 *
 * 设计约束：
 *  - 全部命令都短、无网络、不写系统分区；失败了也要留下「为什么失败」那一行。
 *  - 不假设 sh 的方言：只用 ls / cat / test / head / grep。
 */
object EnvProbe {

    private const val SKB_SHARED_INFO = 320

    private val BUCKETS = intArrayOf(
        8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192, 16384,
    )

    fun cacheOf(size: Int): Int {
        for (b in BUCKETS) if (size <= b) return b
        return BUCKETS[BUCKETS.size - 1]
    }

    fun cacheName(size: Int): String {
        val b = cacheOf(size)
        return if (b < 1024) "kmalloc-" + b else "kmalloc-" + (b / 1024) + "k"
    }

    private fun align(n: Int, a: Int = 64): Int = (n + a - 1) / a * a

    /** __alloc_skb 的实参：SKB_DATA_ALIGN(len) + SKB_DATA_ALIGN(sizeof(skb_shared_info))。 */
    fun skbReq(len: Int): Int = align(len) + align(SKB_SHARED_INFO)

    private fun sh(cmd: String): String = try {
        val r = Shell.exec(cmd)
        val out = r.second
        if (out.isBlank() && r.first != 0) "(rc=" + r.first + ")" else out
    } catch (t: Throwable) {
        "(ex " + (t.javaClass.simpleName) + ")"
    }

    private fun shRoot(cmd: String): String = try {
        val r = Shell.execRoot(cmd)
        if (r.second.isBlank() && r.first != 0) "(rc=" + r.first + ")" else r.second
    } catch (t: Throwable) {
        "(ex " + (t.javaClass.simpleName) + ")"
    }

    private fun hex(s: String, max: Int = 160): String {
        val b = StringBuilder()
        for (ch in s) {
            if (b.length >= max) break
            b.append(String.format(Locale.US, "%02x", ch.code and 0xff))
        }
        return b.toString()
    }

    /** 采一次，返回可直接粘贴的纯文本。IO 线程调用。 */
    suspend fun collect(): String = withContext(Dispatchers.IO) {
        val sb = StringBuilder()
        fun line(s: String) { sb.append(s).append((10).toChar()) }

        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        line("# ExtractKit 环境自检 " + stamp)
        line("app=" + BuildConfig.VERSION_NAME)
        line("model=" + Build.MODEL + " brand=" + Build.BRAND)
        line("release=" + Build.VERSION.RELEASE + " sdk=" + Build.VERSION.SDK_INT)
        line("patch=" + runCatching { Build.VERSION.SECURITY_PATCH }.getOrDefault("?"))
        line("kernel=" + System.getProperty("os.version").orEmpty())
        line("pagesize=" + runCatching {
            android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE).toString()
        }.getOrDefault("?"))

        val conn = Shell.connected()
        line("shizuku_connected=" + conn)
        if (!conn) {
            line("! Shizuku 未连接：下面的 shell 段会缺；先在首页授权再点一次采集。")
        } else {
            line("shell_id=" + sh("id").trim())
            val su = sh("which su 2>/dev/null").trim()
            line("su=" + su.ifBlank { "absent" })
        }

        line("")
        line("## slab")
        val slab = sh("ls /sys/kernel/slab 2>&1")
        val km = slab.lines().filter { it.startsWith("kmalloc") }
        val rnd = km.filter { it.contains("-rnd-") }
        line("kmalloc_cache_count=" + km.size)
        line("random_kmalloc_caches=" + (if (rnd.isNotEmpty()) "YES" else "NO"))
        if (rnd.isNotEmpty()) line("rnd_names=" + rnd.take(24).joinToString(","))
        if (km.isEmpty()) line("slab_list_raw=" + slab.trim().take(200))
        for (n in intArrayOf(512, 1024, 2048, 4096)) {
            val name = if (n < 1024) "kmalloc-" + n else "kmalloc-" + (n / 1024) + "k"
            if (!km.contains(name)) {
                line("objsize_" + name + "=cache-absent")
                continue
            }
            val o = sh("cat /sys/kernel/slab/" + name + "/objsize 2>&1").trim()
            line("objsize_" + name + "=" + o)
        }

        val si = sh("head -2 /proc/slabinfo 2>&1")
        if (si.contains("Permission denied") || si.contains("Permission denied", true)) {
            line("slabinfo=denied(shell)")
            val rc = shRoot("grep -c kmalloc-rnd /proc/slabinfo 2>&1").trim()
            line("slabinfo_root_rnd=" + rc)
        } else {
            val cnt = sh("grep -c kmalloc-rnd /proc/slabinfo 2>&1").trim()
            line("slabinfo_rnd_count=" + cnt)
            val big = sh("grep -E 'kmalloc-(1k|2k|4k) ' /proc/slabinfo 2>&1 | head -6")
            line("slabinfo_kmalloc=" + big.lines().joinToString(" | ").take(300))
        }

        line("")
        line("## tracefs")
        val tfBase = if (sh("test -d /sys/kernel/tracing && echo yes || echo no").trim() == "yes")
            "/sys/kernel/tracing" else "/sys/kernel/debug/tracing"
        line("tracing_dir=" + tfBase)
        line("mount=" + sh("grep -m1 tracefs /proc/mounts 2>/dev/null").trim().take(160))
        fun w(p: String): String = sh("test -w " + tfBase + "/" + p + " && echo yes || echo no").trim()
        fun r(p: String): String = sh("test -r " + tfBase + "/" + p + " && echo yes || echo no").trim()
        var tfTrace = w("trace")
        var tfOn = w("tracing_on")
        var tfEvEnable = w("events/kmem/kmem_cache_alloc/enable")
        var tfRaw = "no"
        line("trace_writable=" + tfTrace)
        line("tracing_on_writable=" + tfOn)
        line("set_event_writable=" + w("set_event"))
        line("instances_writable=" + w("instances"))
        line("buffer_size_kb=" + sh("cat " + tfBase + "/buffer_size_kb 2>/dev/null").trim()
            + " writable=" + w("buffer_size_kb"))
        line("current_tracer=" + sh("cat " + tfBase + "/current_tracer 2>/dev/null").trim()
            + " available=" + sh("cat " + tfBase + "/available_tracers 2>/dev/null").trim().take(80))
        for (ev in arrayOf("kmem_cache_alloc", "kmalloc", "kfree")) {
            line("ev_" + ev + "_enable_w=" + w("events/kmem/" + ev + "/enable")
                + " filter_w=" + w("events/kmem/" + ev + "/filter"))
        }
        line("ev_cache_alloc_format=" + sh(
            "grep -m6 'field:' " + tfBase + "/events/kmem/kmem_cache_alloc/format 2>/dev/null",
        ).lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(" ; ").take(300))
        var rawOk = 0
        var rawN = 0
        for (c in 0 until 4) {
            if (sh("test -d " + tfBase + "/per_cpu/cpu" + c + " && echo yes || echo no").trim() != "yes") continue
            rawN++
            if (r("per_cpu/cpu" + c + "/trace_pipe_raw") == "yes") rawOk++
        }
        tfRaw = if (rawOk > 0) "yes" else "no"
        line("trace_pipe_raw_readable=cpu" + rawOk + "/" + rawN)
        line("selinux=" + sh("cat /sys/fs/selinux/enforce 2>/dev/null").trim()
            + "(" + sh("getenforce 2>/dev/null").trim() + ")")
        line("kmem_events=" + sh("ls " + tfBase + "/events/kmem 2>&1 | head -14")
            .lines().joinToString(",").take(260))

        line("")
        line("## profile")
        for (d in arrayOf("/data/local/tmp/eksu", "/data/local/tmp/extract-kit")) {
            val ls = sh("ls -l " + d + " 2>&1")
            line("ls_" + d + "=" + ls.lines().joinToString(" | ").take(400))
        }

        var inputSize = -1
        var sprayLen = -1
        var sprayReq = -1
        var sprayCount = -1
        // 9.419：profile 里所有能读到的数字键都留一份，用来和本机 BTF 算出的
        // uhid_device 几何逐项对照（4492/4496 到底是"对的"还是"6.6 模板抄错的"）。
        val profNums = LinkedHashMap<String, Long>()
        for (p in arrayOf(
            "/data/local/tmp/eksu/wacom.profile",
            "/data/local/tmp/extract-kit/device.cfg",
        )) {
            val txt = sh("cat " + p + " 2>/dev/null")
            if (txt.isBlank()) continue
            line("profile=" + p + " bytes=" + txt.length)
            // 9.415：profile 是二进制的 EXKCFG01（8 字节 magic + u32 字段数 + 38×u64 + 5×u32 + 锚点），
            // 以前当成 key=value 文本解析，全变 -1。先按格式解一遍。
            if (txt.length > 12 && txt.startsWith("EXKCFG01")) {
                val n = (txt[8].code and 0xff) or ((txt[9].code and 0xff) shl 8) or
                    ((txt[10].code and 0xff) shl 16) or ((txt[11].code and 0xff) shl 24)
                line("cfg_magic=EXKCFG01 fields=" + n)
                fun u64(i: Int): Long {
                    var v = 0L
                    for (b in 0 until 8) v = v or ((txt[12 + i * 8 + b].code and 0xff).toLong() shl (8 * b))
                    return v
                }
                if (n >= 38) {
                    val names = arrayOf(
                        "static_timer", "timer_low21", "selinux_state", "panic_on_warn", "root_user",
                        "init_user_ns", "init_ucounts", "init_groups", "task_cred", "task_comm",
                        "task_alloc_low21", "task_alloc_bytes", "task_alloc_bytes2", "cred_req",
                        "cred_alloc", "cred_site_low21", "itimer_size", "itimer_node", "itimer_head",
                        "itimer_elist", "itimer_firing", "itimer_handling", "itimer_size2", "cred_uid",
                        "cred_security", "cred_user", "cred_user_ns", "cred_ucounts", "cred_groups",
                        "const_1f00", "selinux_blob_off", "selinux_sid", "const_u64", "ntimers",
                        "victim_idx", "slab_slots", "lockers", "vma_count",
                    )
                    for (i in names.indices) {
                        val v = u64(i)
                        if (v == 0L) continue
                        line("cfg." + names[i] + "=" + (if (v < 0) "0x" + java.lang.Long.toHexString(v) else v.toString()))
                    }
                    var off = 12 + 38 * 8
                    if (off + 20 <= txt.length) {
                        var ev = ""
                        for (k in 0 until 5) {
                            var v = 0
                            for (b in 0 until 4) v = v or ((txt[off + k * 4 + b].code and 0xff) shl (8 * b))
                            if (k > 0) ev += ","
                            ev += v.toString()
                        }
                        line("cfg.events=" + ev)
                        off += 20
                    }
                    if (off + 4 <= txt.length) {
                        var an = 0
                        for (b in 0 until 4) an = an or ((txt[off + b].code and 0xff) shl (8 * b))
                        line("cfg.anchors=" + an)
                    }
                }
                line("profile_hex=" + hex(txt).take(160))
                continue
            }
            val printable = txt.count { it == (10).toChar() || it.code in 32..126 }
            if (printable * 10 < txt.length * 8) {
                line("profile_hex=" + hex(txt).take(240))
                continue
            }
            // 9.416：标定库里的 profile 是 JSON（"input_dev_size": 1592 这种冒号写法），
            // 9.414/9.415 只认 key=value，于是四个数字全是 -1。先按 JSON 读。
            val jm = Regex("\"([A-Za-z0-9_.]+)\"\\s*:\\s*(\"[^\"]*\"|-?[0-9]+)")
            var jsonHit = 0
            for (m in jm.findAll(txt)) {
                val k = m.groupValues[1]
                val raw = m.groupValues[2].trim('"')
                if (k == "release" || k == "kernel" || k == "name") {
                    line("json." + k + "=" + raw)
                    jsonHit++
                    continue
                }
                val n = raw.toIntOrNull() ?: continue
                profNums[k] = n.toLong()
                if (k == "input_dev_size" || k == "spray_len" || k == "spray_skb_req" ||
                    k == "spray_count" || k == "spray_pairs"
                ) {
                    line("json." + k + "=" + n)
                    if (k == "input_dev_size") inputSize = n
                    if (k == "spray_len") sprayLen = n
                    if (k == "spray_skb_req") sprayReq = n
                    if (k == "spray_count" || k == "spray_pairs") sprayCount = n
                    jsonHit++
                }
            }
            if (jsonHit > 0) {
                line("profile_format=json(keys=" + jsonHit + ")")
                continue
            }
            for (l in txt.lines()) {
                val t = l.trim()
                if (t.isEmpty() || t.length > 120) continue
                if (t.startsWith("#") || t.startsWith(";") || t.startsWith("//")) continue
                if (!t.contains("=")) continue
                line("p| " + t)
                val cut = t.indexOf("=")
                val k = t.substring(0, cut).trim()
                val v = t.substring(cut + 1).trim().takeWhile { c -> c.isDigit() || c == (45).toChar() }
                val n = v.toIntOrNull() ?: -1
                if (n >= 0) profNums[k] = n.toLong()
                if (k.contains("input_dev_size")) inputSize = n
                if (k == "spray_len") sprayLen = n
                if (k == "spray_skb_req") sprayReq = n
                if (k == "spray_count" || k == "spray_pairs") sprayCount = n
            }
        }

        // 9.415：profile 是二进制时，真实数字只会出现在 payload 自己的日志里（exp2.log 等），
        // 把 /data/local/tmp 下的小文本日志扫一遍，抓这四个键。
        for (d in arrayOf("/data/local/tmp/eksu", "/data/local/tmp/extract-kit")) {
            val names = sh("ls " + d + " 2>/dev/null").lines().map { it.trim() }
            for (nm in names) {
                if (!(nm.endsWith(".log") || nm.endsWith(".txt") || nm.endsWith(".profile"))) continue
                val txt = sh("cat " + d + "/" + nm + " 2>/dev/null")
                if (txt.isBlank() || txt.length > 200000) continue
                for (l in txt.lines()) {
                    val t = l.trim()
                    if (t.isEmpty() || !t.contains("=")) continue
                    val cut = t.indexOf("=")
                    val k = t.substring(0, cut).trim().substringAfterLast(" ").substringAfterLast(":")
                    if (k != "input_dev_size" && k != "spray_len" && k != "spray_skb_req" &&
                        k != "spray_count" && k != "spray_pairs"
                    ) continue
                    val n = t.substring(cut + 1).trim().takeWhile { c -> c.isDigit() }.toIntOrNull() ?: continue
                    if (k == "input_dev_size") inputSize = n
                    if (k == "spray_len") sprayLen = n
                    if (k == "spray_skb_req") sprayReq = n
                    if (k == "spray_count" || k == "spray_pairs") sprayCount = n
                    line("from " + nm + ": " + k + "=" + n)
                }
            }
        }

        line("")
        line("## config")
        val cfgReadable = sh("test -r /proc/config.gz && echo yes || echo no").trim() == "yes"
        line("proc_config_gz=" + (if (cfgReadable) "readable" else "denied"))
        if (cfgReadable) {
            val b64 = sh("base64 /proc/config.gz 2>/dev/null")
            val cfgText = try {
                val clean = b64.filter { it != (10).toChar() && it != (13).toChar() }
                val raw = android.util.Base64.decode(clean, android.util.Base64.DEFAULT)
                java.util.zip.GZIPInputStream(java.io.ByteArrayInputStream(raw)).use {
                    String(it.readBytes(), Charsets.UTF_8)
                }
            } catch (t: Throwable) {
                ""
            }
            if (cfgText.isBlank()) {
                line("config=decode-failed")
            } else {
                line("config_bytes=" + cfgText.length)
                for (k in arrayOf(
                    "CONFIG_RANDOM_KMALLOC_CACHES", "CONFIG_SLAB_FREELIST_RANDOM",
                    "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_SLAB_MERGE_DEFAULT",
                    "CONFIG_SLAB_BUCKETS", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
                    "CONFIG_INIT_ON_FREE_DEFAULT_ON", "CONFIG_KFENCE", "CONFIG_KASAN",
                    "CONFIG_KASAN_HW_TAGS", "CONFIG_KCSAN", "CONFIG_DEBUG_PAGEALLOC",
                    "CONFIG_HARDENED_USERCOPY", "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
                    "CONFIG_UHID", "CONFIG_INPUT_UINPUT", "CONFIG_TRACING", "CONFIG_FTRACE",
                    "CONFIG_KPROBES", "CONFIG_BPF_SYSCALL", "CONFIG_SECURITY_SELINUX",
                    "CONFIG_USER_NS", "CONFIG_SLUB", "CONFIG_ARM64_MTE", "CONFIG_RANDOMIZE_BASE",
                    "CONFIG_PREEMPT_NONE", "CONFIG_PREEMPT_VOLUNTARY", "CONFIG_PREEMPT",
                )) {
                    val m = Regex("(?m)^" + k + "=(.*)$").find(cfgText)
                    line(k + "=" + (m?.groupValues?.get(1)?.trim() ?: "absent"))
                }
            }
        }
        line("cmdline=" + sh("cat /proc/cmdline 2>/dev/null").trim().take(240))

        line("")
        line("## sysctl")
        for (k in arrayOf("kptr_restrict", "dmesg_restrict", "perf_event_paranoid",
            "unprivileged_bpf_disabled", "kallsyms_show_value")) {
            line(k + "=" + sh("cat /proc/sys/kernel/" + k + " 2>/dev/null").trim())
        }
        val ksHead = sh("head -c 200 /proc/kallsyms 2>/dev/null")
        line("kallsyms_lines=" + sh("wc -l < /proc/kallsyms 2>/dev/null").trim())
        line("kallsyms_zeroed=" + (if (ksHead.startsWith("0000000000000000")) "yes" else "no")
            + " head=" + ksHead.lines().firstOrNull().orEmpty().take(90))

        line("")
        line("## devices")
        line("ls_uhid=" + sh("ls -l /dev/uhid 2>&1").trim().take(120))
        line("ls_uinput=" + sh("ls -l /dev/uinput 2>&1").trim().take(120))
        line("uhid_writable=" + sh("test -w /dev/uhid && echo yes || echo no").trim())
        line("uinput_writable=" + sh("test -w /dev/uinput && echo yes || echo no").trim())
        line("input_nodes=" + sh("ls /dev/input 2>/dev/null | wc -l").trim()
            + " sys_class_input=" + sh("ls /sys/class/input 2>/dev/null | wc -l").trim())

        line("")
        line("## host")
        line("cpu_online=" + sh("cat /sys/devices/system/cpu/online 2>/dev/null").trim()
            + " cpu_count=" + sh("ls -d /sys/devices/system/cpu/cpu[0-9]* 2>/dev/null | wc -l").trim())
        line("uptime=" + sh("cut -d' ' -f1 /proc/uptime 2>/dev/null").trim())
        line("meminfo=" + sh("grep -E 'MemTotal|MemAvailable|^Slab:|SReclaimable' /proc/meminfo 2>/dev/null")
            .lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(" | ").take(220))

        line("")
        line("## state")
        val bootId = sh("cat /proc/sys/kernel/random/boot_id 2>/dev/null").trim()
        val expBoot = sh("cat /data/local/tmp/eksu/exp.bootid 2>/dev/null").trim()
        val parkedLs = sh("ls -l /data/local/tmp/eksu/PARKED 2>/dev/null").trim()
        line("boot_id=" + bootId)
        line("exp_bootid=" + expBoot.ifBlank { "absent" })
        line("PARKED=" + parkedLs.ifBlank { "absent" })
        val parkedSame = parkedLs.isNotBlank() && expBoot.isNotBlank() && bootId == expBoot
        line("parked_same_boot=" + parkedSame)
        line("ko_syms=" + sh("ls -l /data/local/tmp/eksu/ko-syms*.txt 2>/dev/null")
            .lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(" ; ").take(240))
        line("manager_adb=" + sh("ls /data/adb 2>/dev/null").lines().joinToString(",").take(160))
        line("modules=" + sh("ls /data/adb/modules 2>/dev/null | head -6").lines().joinToString(",").take(120))

        line("")
        line("## computed")
        val len = if (sprayLen > 0) sprayLen else 1664
        val req = skbReq(len)
        line("input_dev_size=" + inputSize)
        line("spray_len=" + len + " spray_skb_req=" + req + " spray_skb_req_prof=" + sprayReq
            + " spray_count=" + sprayCount)
        if (inputSize > 0) {
            val a = cacheOf(inputSize)
            val b = cacheOf(req)
            line("input_dev_cache=" + cacheName(inputSize) + "(" + a + ")")
            line("skb_cache=" + cacheName(req) + "(" + b + ")")
            line("same_cache=" + (a == b))
            if (a != b) {
                val cand = ArrayList<Int>()
                for (n in intArrayOf(512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 1664, 1728, 1792, 1920, 2048)) {
                    if (cacheOf(skbReq(n)) == a) cand.add(n)
                }
                line("spray_len_for_same_cache=" + cand.joinToString(","))
            }
        }

        line("")
        line("## uhid")
        var uhidState = "UNKNOWN"
        if (!conn) {
            line("skipped=no-shell")
        } else {
            for (k in arrayOf(
                "uhid_waitq_self", "uhid_waitq_head_off", "uhid_outq_off",
                "uhid_worker_off", "uhid_worker_func_off",
                "uhid_serial_read_base_off", "uhid_input_buf_data_off",
            )) {
                line("profile " + k + "=" + (profNums[k]?.toString() ?: "absent"))
            }
            val btfPath = "/sys/kernel/btf/vmlinux"
            val btfRead = sh("test -r " + btfPath + " && echo yes || echo no").trim() == "yes"
            line("btf_path=" + btfPath + " readable=" + btfRead)
            if (!btfRead) {
                line("note=设备没暴露 " + btfPath + "；标定页从 boot.img 里取 BTF 算的是同一组键")
                uhidState = "NO_BTF"
            } else {
                line("btf_ls=" + sh("ls -l " + btfPath + " 2>/dev/null").trim().take(140))
                val b64 = sh("gzip -c " + btfPath + " 2>/dev/null | base64 -w0")
                var raw: ByteArray? = null
                try {
                    val clean = b64.filter { it != (10).toChar() && it != (13).toChar() }
                    if (clean.length > 100) {
                        val bytes = android.util.Base64.decode(clean, android.util.Base64.DEFAULT)
                        raw = try {
                            java.util.zip.GZIPInputStream(java.io.ByteArrayInputStream(bytes))
                                .use { it.readBytes() }
                        } catch (t: Throwable) {
                            bytes
                        }
                    }
                } catch (t: Throwable) {
                    raw = null
                }
                if (raw == null || raw.size < 1024) {
                    line("btf_fetch=failed(空输出：gzip/base64 缺失或 shell 输出限额)")
                    uhidState = "NO_BTF"
                } else {
                    line("btf_bytes=" + raw.size)
                    val bt = try {
                        Btf.parse(raw)
                    } catch (t: Throwable) {
                        null
                    }
                    if (bt == null) {
                        line("btf_parse=failed")
                        uhidState = "NO_BTF"
                    } else {
                        line("btf_types=" + bt.types.size)
                        val ud = bt.struct("uhid_device")
                        if (ud == null) {
                            line("uhid_device=absent")
                        } else {
                            line("uhid_device_size=" + ud.size + " members=" + ud.members.size)
                            for (m in ud.members) {
                                line(
                                    "field " + (if (m.name.isEmpty()) "(anon)" else m.name) +
                                        " off=" + m.byteOffset + " type=" + bt.describe(m.typeId),
                                )
                            }
                            val waitq = ud.members.firstOrNull { m ->
                                val t = bt.strip(m.typeId)
                                t != null && t.kind == 4 && t.name == "wait_queue_head"
                            }
                            val headInner = bt.memberOffset("wait_queue_head", "head")
                            val outq = ud.members.firstOrNull { bt.pointedName(it.typeId) == "uhid_event" }
                            val work = ud.members.firstOrNull { m ->
                                val t = bt.strip(m.typeId)
                                t != null && t.kind == 4 && t.name == "work_struct"
                            }
                            val funcInner = bt.memberOffset("work_struct", "func")
                            var derived = 0
                            var stale = 0
                            fun cmp(k: String, v: Long) {
                                derived++
                                line("derived " + k + "=" + v)
                                val pv = profNums[k] ?: return
                                val same = pv == v
                                if (!same) stale++
                                line(
                                    "cmp " + k + " btf=" + v + " profile=" + pv +
                                        " " + (if (same) "match" else "STALE(6.6 模板)"),
                                )
                            }
                            if (waitq != null && headInner != null) {
                                cmp("uhid_waitq_self", (waitq.byteOffset + headInner).toLong())
                            }
                            if (outq != null) {
                                cmp("uhid_outq_off", outq.byteOffset.toLong())
                                cmp("uhid_waitq_head_off", (outq.byteOffset - 4).toLong())
                            }
                            if (work != null && funcInner != null) {
                                cmp("uhid_worker_off", work.byteOffset.toLong())
                                cmp("uhid_worker_func_off", (work.byteOffset + funcInner).toLong())
                            }
                            line("uhid_derived=" + derived + " stale=" + stale)
                            uhidState = when {
                                derived == 0 -> "UNRESOLVED"
                                stale == 0 -> "MATCH"
                                else -> "STALE"
                            }
                            line(
                                "verdict=" + when (uhidState) {
                                    "MATCH" -> "UHID_GEOMETRY_MATCH：profile 那组数与本机 BTF 一致，4492/4496 不是抄错"
                                    "STALE" -> "UHID_GEOMETRY_STALE：profile 是 6.6 模板值，本机布局不同 —— self cell install 失败就出在这里"
                                    else -> "UHID_UNRESOLVED：waitq / outq / work_struct 有一项没在 BTF 里找到"
                                },
                            )
                        }
                    }
                }
            }
        }

        // 结论行：把「下一步该走哪条路」直接写进去，省得回来再问一遍。
        val rndOn = km.isNotEmpty() && rnd.isNotEmpty()
        val tfReady = tfTrace == "yes" && tfOn == "yes" && tfEvEnable == "yes" && tfRaw == "yes"
        line("")
        line("## gates")
        line("gate_tracefs=trace_w=" + tfTrace + " tracing_on_w=" + tfOn
            + " ev_enable_w=" + tfEvEnable + " trace_pipe_raw_r=" + tfRaw + " => " + (if (tfReady) "READY" else "BLOCKED"))
        line("gate_uaf=uhid_w=" + sh("test -w /dev/uhid && echo yes || echo no").trim()
            + " uinput_w=" + sh("test -w /dev/uinput && echo yes || echo no").trim())
        line("gate_uhid=" + uhidState)
        line("gate_fire=parked_same_boot=" + parkedSame
            + (if (parkedSame) " (上游行为：同一开机只能 fire 一次，重启后再来)" else ""))
        line("")
        line("## verdict")
        if (!conn) {
            line("verdict=NO_SHELL")
        } else if (km.isEmpty()) {
            line("verdict=NO_SLAB_LIST(/sys/kernel/slab 读不到)")
        } else if (rndOn) {
            line("verdict=RANDOM_KMALLOC_CACHES: 跨调用点喷 skb 落不进 input_dev 的 slab")
            line("next=走同源再分配（uinput/uhid 再建一次设备），不要继续调 spray_len")
        } else {
            line("verdict=SHARED_KMALLOC: 可以靠 spray_len / CPU pin 抢槽")
            if (tfReady) {
                line("tracefs=READY: 四道门都开（trace/tracing_on/kmem_cache_alloc enable/trace_pipe_raw）")
                line("next=删 PARKED 并重启后先试 tracefs 分支；它的 bootstrap 与 no-tracefs 相同，仍要过抢槽这一关")
            } else {
                line("tracefs=BLOCKED: 有门没开，跑 tracefs 会先死在 trace prepare / cred leak")
                line("next=按 same_cache 选 spray_len 或走同源再分配；tracefs 先别试")
            }
            if (parkedSame) line("fire=PARKED_SAME_BOOT: 上一趟留了标记；上游一次开机只 fire 一次，重启后再来")
        }
        sb.toString()
    }

    /**
     * 9.418 · 把报告落成一个 .log 文件再分享（不再是纯文本 EXTRA_TEXT）。
     *
     * 放在 filesDir/envprobe/ 下，manifest 的 FileProvider 已经声明了 `<files-path path="." />`，
     * 所以 FileProvider.getUriForFile(ctx, "<pkg>.files", f) 可以直接授权给聊天软件。
     * 文件名带时间戳：环境自检-20261124-133500.log，多次采集不会互相覆盖。
     */
    fun writeReport(ctx: Context, body: String): File {
        val dir = File(ctx.filesDir, "envprobe").apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val f = File(dir, "环境自检-" + stamp + ".log")
        f.writeText(body, Charsets.UTF_8)
        return f
    }
}
