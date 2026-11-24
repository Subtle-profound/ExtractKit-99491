package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * 9.408：99491 这条链不再按内核家族设门。
 *
 * 载荷是数据驱动的（exp.c 只比 release，偏移来自 profile、符号来自 ko-syms），
 * 所以只要标定过就能在主页直接跑 —— 矩阵内的 5.10/5.15/6.1/6.6/6.12/6.18 与
 * 矩阵外的版本都必须能拿到同一份二进制，不能因为「家族不在名单」被拦住。
 */
class WacomFamilyGateTest {

    @Test
    fun everyFamilyGetsThePayload() {
        for (fam in listOf("5.10", "5.15", "6.1", "6.6", "6.12", "6.18")) {
            val p = Payloads.wacomFor(fam)
            assertNotNull("family " + fam + " must resolve", p)
            assertEquals("family " + fam + " uses the shared binary", "ek-w1-uid0-6.6", p!!.name)
        }
    }

    @Test
    fun outsideTheMatrixStillGetsThePayload() {
        for (fam in listOf("5.4", "6.7", "7.1", "", null)) {
            val p = Payloads.wacomFor(fam)
            assertNotNull("family " + fam + " must resolve", p)
            assertEquals("ek-w1-uid0-6.6", p!!.name)
        }
    }
}
