package com.extractkit.app

/**
 * 9.291：解析 stage 脚本发现阶段的候选排名。
 *
 * 脚本对每个候选二进制打一行（走 stderr，所以不会被命令替换吞掉）：
 *   [resolve] cand libksud_ksu.so score=37 size=1843560 caps=pn1,pm1,uid1
 *
 * 这里只做纯文本解析 + 排序，方便单测：分数高的优先，同分取体积大的（更可能是完整 CLI
 * 而不是同名小壳），再按名字定序，保证同样的输入每次排序结果一致。
 */
object CandidateRank {

    data class Cand(val name: String, val score: Int, val size: Long)

    fun parse(lines: List<String>): List<Cand> {
        val out = ArrayList<Cand>()
        for (raw in lines) {
            val line = raw.trim()
            val i = line.indexOf("[resolve] cand ")
            if (i < 0) continue
            val rest = line.substring(i + "[resolve] cand ".length).trim()
            val name = rest.substringBefore(' ').trim()
            if (name.isEmpty()) continue
            val score = field(rest, "score=")?.toIntOrNull() ?: continue
            val size = field(rest, "size=")?.toLongOrNull() ?: 0L
            out.add(Cand(name, score, size))
        }
        return out.sortedWith(
            compareByDescending<Cand> { it.score }.thenByDescending { it.size }.thenBy { it.name }
        )
    }

    fun best(lines: List<String>): Cand? = parse(lines).firstOrNull()

    /** 注册阶段的重试顺序：最高分在前。解析不出任何候选时返回空表。 */
    fun order(lines: List<String>): List<String> = parse(lines).map { it.name }

    private fun field(s: String, key: String): String? {
        val i = s.indexOf(key)
        if (i < 0) return null
        val tail = s.substring(i + key.length)
        val digits = tail.takeWhile { it.isDigit() }
        return if (digits.isNotEmpty()) digits else tail.takeWhile { !it.isWhitespace() }
    }
}
