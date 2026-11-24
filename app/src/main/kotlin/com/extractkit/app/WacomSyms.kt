package com.extractkit.app

/**
 * 9.404: the ko-syms table is now produced by calibration as well.
 *
 * Why: under --ksu the payload's first step is ko_syms_check(), and the table's
 * ---------------------------------------------------------------
 *   # kernel_release: <uname -r>
 * ---------------------------------------------------------------
 * header must equal the running release exactly (ko_patch.c:397 validate_syms_header).
 * A table from another build fails with syms_release and exp.c:6000 returns 2
 * BEFORE the UAF, so the chain never even arms. We only ship tables for the builds
 * we pinned; every other kernel has to get one from its own boot.img.
 *
 * The name set is not the same across families (6.12 has _noprof / sized_strscpy /
 * __fortify_panic), so the template is picked by kernel family, and only the
 * addresses come from the calibrated kallsyms.
 */
internal object WacomSyms {

    /** 6.12 name set. */
    const val ASSET_612: String =
        "payload/wacom/ko-syms-6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k.txt"

    /** 6.6 (and older families): no _noprof symbols. */
    const val ASSET_66: String = "payload/wacom/ko-syms.txt"

    fun templateAsset(family: String?): String = if (family == "6.12") ASSET_612 else ASSET_66

    /** Name column of a ko-syms table (headers and blanks skipped). */
    fun names(text: String): List<String> = text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { it.substringBefore(' ').substringBefore('\t') }
        .filter { it.isNotEmpty() }
        .distinct()
        .toList()

    data class Built(val text: String, val symbols: Int, val missing: List<String>)

    /**
     * Same shape as the pinned tables: format/kernel_release/symbol_count header plus
     * "<name> <hex>" rows. symbol_count counts the emitted rows (the validator compares
     * it with the real entry count), and names absent from this kallsyms are dropped.
     */
    fun build(template: String, release: String, addrs: Map<String, Long>): Built {
        val rows = ArrayList<String>()
        val missing = ArrayList<String>()
        for (n in names(template)) {
            val a = addrs[n] ?: 0L
            if (a == 0L) {
                missing.add(n)
                continue
            }
            rows.add(n + " " + java.lang.Long.toHexString(a))
        }
        val text = buildString {
            append("# format: 1\n")
            append("# kernel_release: ").append(release).append('\n')
            append("# symbol_count: ").append(rows.size).append('\n')
            append("# note: link-time VAs; ko_patch adds the boot slide\n")
            for (r in rows) append(r).append('\n')
        }
        return Built(text, rows.size, missing)
    }
}
