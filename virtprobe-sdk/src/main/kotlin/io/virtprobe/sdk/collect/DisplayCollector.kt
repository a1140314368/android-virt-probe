// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.app.AppOpsManager
import android.content.Context
import android.hardware.display.DisplayManager
import android.media.MediaRouter
import android.os.Build
import android.provider.Settings
import android.util.DisplayMetrics
import android.view.Display
import io.virtprobe.core.model.DisplayFact
import io.virtprobe.core.model.VirtualDisplaySnapshot

internal object DisplayCollector {
    fun collect(context: Context, screenCaptureNotified: Boolean?): VirtualDisplaySnapshot {
        val routes = remoteRoutes(context)
        return VirtualDisplaySnapshot(
            displays = displays(context),
            screenCaptureNotified = screenCaptureNotified,
            projectMediaMode = appOp(context, media = true),
            projectAudioMode = appOp(context, media = false),
            remoteRouteNames = routes.first,
            selectedRemoteRoute = routes.second,
            wifiDisplayOn = wifiDisplay(context),
        )
    }

    private fun displays(context: Context): List<DisplayFact> {
        val manager = context.getSystemService(DisplayManager::class.java) ?: return emptyList()
        return manager.displays.map { display ->
            val metrics = DisplayMetrics()
            @Suppress("DEPRECATION")
            display.getRealMetrics(metrics)
            val mode = display.mode
            DisplayFact(
                displayId = display.displayId,
                name = display.name.orEmpty(),
                flags = display.flags,
                widthPx = mode.physicalWidth,
                heightPx = mode.physicalHeight,
                densityDpi = metrics.densityDpi,
                refreshHz = mode.refreshRate,
                isDefault = display.displayId == Display.DEFAULT_DISPLAY,
            )
        }
    }

    private fun appOp(context: Context, media: Boolean): String? {
        val field = when {
            media && Build.VERSION.SDK_INT >= 29 -> "OPSTR_PROJECT_MEDIA"
            !media && Build.VERSION.SDK_INT >= 31 -> "OPSTR_PROJECT_AUDIO"
            else -> return null
        }
        return try {
            val op = AppOpsManager::class.java.getField(field).get(null) as String
            val appOps = context.getSystemService(AppOpsManager::class.java) ?: return null
            val method = AppOpsManager::class.java.getMethod(
                "checkOpNoThrow",
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
            )
            val mode = method.invoke(appOps, op, android.os.Process.myUid(), context.packageName) as Int
            modeName(mode)
        } catch (t: Throwable) {
            "ERROR:${t.javaClass.simpleName}"
        }
    }

    private fun modeName(mode: Int): String = when (mode) {
        AppOpsManager.MODE_ALLOWED -> "MODE_ALLOWED"
        AppOpsManager.MODE_IGNORED -> "MODE_IGNORED"
        AppOpsManager.MODE_ERRORED -> "MODE_ERRORED"
        AppOpsManager.MODE_DEFAULT -> "MODE_DEFAULT"
        4 -> "MODE_FOREGROUND"
        else -> "MODE_$mode"
    }

    private fun remoteRoutes(context: Context): Pair<List<String>, String?> {
        return try {
            val router = context.getSystemService(Context.MEDIA_ROUTER_SERVICE) as? MediaRouter
                ?: return emptyList<String>() to null
            val selectedRoute = router.getSelectedRoute(MediaRouter.ROUTE_TYPE_LIVE_VIDEO)
            val names = mutableListOf<String>()
            var selected: String? = null
            for (index in 0 until router.routeCount) {
                val route = router.getRouteAt(index)
                if (route.playbackType != MediaRouter.RouteInfo.PLAYBACK_TYPE_REMOTE) continue
                val name = route.getName(context)?.toString().orEmpty()
                if (name.isBlank()) continue
                names += name
                if (route == selectedRoute) selected = name
            }
            names to selected
        } catch (_: Throwable) {
            emptyList<String>() to null
        }
    }

    private fun wifiDisplay(context: Context): Boolean? {
        return try {
            Settings.Global.getInt(context.contentResolver, "wifi_display_on", 0) == 1
        } catch (_: Throwable) {
            null
        }
    }
}
