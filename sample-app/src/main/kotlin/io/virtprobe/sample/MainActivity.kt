// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sample

import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import io.virtprobe.sample.ui.VirtProbeScreen
import io.virtprobe.sdk.VirtProbe

/** 演示页。屏幕采集回调在 Activity 生命周期里注册，扫描时才能读到「注册之后是否发生过采集」。 */
class MainActivity : ComponentActivity() {
    private var screenCaptureWatch: AutoCloseable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        setContent { VirtProbeScreen() }
    }

    override fun onStart() {
        super.onStart()
        screenCaptureWatch = VirtProbe.attachScreenCaptureWatch(this)
    }

    override fun onStop() {
        screenCaptureWatch?.close()
        screenCaptureWatch = null
        super.onStop()
    }
}
