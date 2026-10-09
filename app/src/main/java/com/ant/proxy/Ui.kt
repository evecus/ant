package com.ant.proxy

import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding

/**
 * targetSdk 35 在 Android 15 上强制 edge-to-edge，
 * 让页面内容自动避开系统状态栏与导航栏。
 */
fun applySystemBarInsets(view: View, basePadDp: Int = 20) {
    val pad = (basePadDp * view.resources.displayMetrics.density).toInt()
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
        v.updatePadding(
            left = bars.left + pad,
            top = bars.top + pad,
            right = bars.right + pad,
            bottom = bars.bottom + pad
        )
        WindowInsetsCompat.CONSUMED
    }
}
