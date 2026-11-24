package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 阶段标题去重（`ExtractEngine` 的日志映射层）的纯逻辑测试。
 *
 * 背景：payload 每个阶段会输出很多行，早先每行都会调一次 `onStage`，
 * 日志里变成「标题 / payload 行 / 标题 / payload 行」的噪声，把真正的
 * 成功行埋掉。这条逻辑现在收在 [StageMap.nextLabel] 里，用单测钉住，
 * 避免再靠「装机跑一遍看日志」才发现。
 */
class StageMapTest {

    private val leak = StageMap.Stage.LEAK
    private val reclaim = StageMap.Stage.RECLAIM

    @Test
    fun firstStageIsEmitted() {
        val (prev, emit) = StageMap.nextLabel(null, leak)
        assertEquals(StageMap.label(leak), prev)
        assertEquals(StageMap.label(leak), emit)
    }

    @Test
    fun repeatedStageIsSilent() {
        val once = StageMap.nextLabel(null, leak)
        val twice = StageMap.nextLabel(once.first, leak)
        assertEquals(StageMap.label(leak), twice.first)
        assertNull(twice.second)
    }

    @Test
    fun stageChangeIsEmitted() {
        val a = StageMap.nextLabel(null, leak)
        val b = StageMap.nextLabel(a.first, reclaim)
        assertEquals(StageMap.label(reclaim), b.second)
    }

    @Test
    fun nullStageKeepsPreviousLabel() {
        val a = StageMap.nextLabel(null, leak)
        val b = StageMap.nextLabel(a.first, null)
        assertEquals(a.first, b.first)
        assertNull(b.second)
    }

    @Test
    fun censusLinesMapToTraceStage() {
        // 设备侧 census 输出：逐事件一行的形态（界面不提供入口，adb 才能跑）
        val line = "[census] ev=mm_page_alloc dir=1 id=269 id_errno=0 en0='0'(0) wr=0 wr_errno=0 en1='1'"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.TRACE, hit!!.stage)
    }

    @Test
    fun pageClaimedByAllocMapsToReclaim() {
        // 页事件拿不到时的平级证据：同页 alloc 命中
        val line = "[+] plant2 page-claimed-by-alloc ptr=0xffff8880a1b2c3d0 pfn=0x9a9fb0 pid=4121"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun armReadbackMapsToTraceStage() {
        // 9.147：重挂后回读 enable/tracing_on，事件真开没开在这一行才能看出来
        val line = "[arm] start page_enable='1' cache_enable='1' tracing_on='1' armed=2"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.TRACE, hit!!.stage)
    }

    @Test
    fun winCountersMapToReclaimStage() {
        // 9.147：每轮窗口的分类计数，same_page=0 就是没拿到受害者页的直接证据
        val line = "[win] plant2 recs=14 cpus=1 ca=9 cf=5 pa=0 pf=0 unk=0 same_page=0 same_mine=0 " +
            "dmin=1f armed=2"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun pipeFallbackMapsToReclaimStage() {
        // 9.147：pipe 兜底写成功 —— 注意它不算窗口证据，只是「没拿到 tracepoint 也动了手」
        val line = "[pipe] wrote=4096 off=0x1200 page=1 hit=0（未验证，交给 uid 校验）"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun claimLineMapsToReclaimStage() {
        // 9.148：认领拆三档，pass0/1/2 各打一行；nrec=0 就是「一条都没有」
        val line = "[claim] plant1 pass0 cnt=7386 nrec=0 V=0x0"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun diagProbeLineMapsToReclaimStage() {
        // 9.148：三档全空时的窗口诊断与自 probe，仍属回收段
        val line = "[diag] plant1 probe self_thread=6512 pn=41 pid_hit=8 size_hit=8"
        val hit = StageMap.classify(line)
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun hbHeartbeatMapsToReclaimStage() {
        // 9.149：plant 之后父进程的带超时心跳（等孩子 fork 到位），属于回收段
        val hit = StageMap.classify("[hb] plant1 stage=A at 12ms")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun hbStallLineMapsToReclaimStageAndShowsChildState() {
        // 9.149：卡住时把子进程的 stat 状态一起打出来，便于判断是 D 还是 Z
        val hit = StageMap.classify("[hb] plant1 stall stage=C pid=10674 state=D after 15000ms")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun btfLineMapsToBasemapStage() {
        // 9.144：BTF 偏移探测（只读）也归到「解基址」这一段，因为它解的是结构偏移
        val hit = StageMap.classify("[btf] task_cred=0x820 kitimer_node=0x78")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.BASEMAP, hit!!.stage)
    }

    @Test
    fun symsLineMapsToBasemapStage() {
        // 符号表投票得到的 slide 与 direct map 基址是同一步
        val hit = StageMap.classify("[syms] slide=0x1c000000 votes=12 anchors=4 observed=20480")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.BASEMAP, hit!!.stage)
    }

    @Test
    fun tileLineMapsToReclaimStage() {
        // 9.144：tile 回收（在已回收页里平铺假 cred）属于写原语落地
        val hit = StageMap.classify("[tile] blob=0x100 round=3")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.RECLAIM, hit!!.stage)
    }

    @Test
    fun rootdListenMapsToHandoffStage() {
        // 常驻 root 通道就绪 = 把 root 交出去
        val hit = StageMap.classify("[rootd] ROOTD_LISTEN path=/data/local/tmp/extract-kit-root.sock pid=8123")
        assertNotNull(hit)
        assertEquals(StageMap.Stage.HANDOFF, hit!!.stage)
    }

    @Test
    fun labelFormatMatchesUiExpectation() {
        // 形如 "[5/10] 写原语落地"：下标从 1 开始、总数为 10
        val label = StageMap.label(reclaim)
        assertEquals("[${reclaim.order + 1}/10] ${reclaim.title}", label)
    }
}
