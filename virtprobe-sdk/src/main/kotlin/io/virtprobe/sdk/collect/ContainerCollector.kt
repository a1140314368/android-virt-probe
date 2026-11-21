// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.content.Context
import android.os.Process
import io.virtprobe.core.model.ContainerSnapshot
import io.virtprobe.sdk.native.NativeEvidence
import java.io.File

internal object ContainerCollector {
    fun collect(context: Context, native: NativeEvidence): ContainerSnapshot {
        val info = context.applicationInfo
        val uidPackages = context.packageManager.getPackagesForUid(Process.myUid())?.toList().orEmpty()
        val javaCmd = AndroidSignals.readText("/proc/self/cmdline", 4096)
        val javaMaps = AndroidSignals.readText("/proc/self/maps", 48 * 1024)
        val javaMount = AndroidSignals.readText("/proc/self/mountinfo", 48 * 1024)
        val javaEnv = AndroidSignals.readText("/proc/self/environ", 16 * 1024)
        val errors = linkedMapOf<String, String>()
        native.cmdlineError.takeIf { it.isNotBlank() && native.cmdline.isBlank() }?.let { errors["cmdline"] = it }
        javaCmd.second?.let { errors.putIfAbsent("cmdline", it) }
        native.mountinfoError.takeIf { it.isNotBlank() && native.mountinfo.isBlank() }?.let { errors["mountinfo"] = it }
        native.environError.takeIf { it.isNotBlank() && native.environ.isBlank() }?.let { errors["environ"] = it }
        return ContainerSnapshot(
            packageName = context.packageName,
            dataDir = info.dataDir.orEmpty(),
            sourceDir = info.sourceDir.orEmpty(),
            nativeLibraryDir = info.nativeLibraryDir.orEmpty(),
            userId = Process.myUid() / 100000,
            packagesForUid = uidPackages,
            cmdline = AndroidSignals.prefer(native.cmdline, javaCmd.first),
            mapsText = AndroidSignals.prefer(native.maps, javaMaps.first),
            mountInfoText = AndroidSignals.prefer(native.mountinfo, javaMount.first),
            environText = AndroidSignals.prefer(native.environ, javaEnv.first),
            classLoaderDexPaths = dexPaths(context.classLoader),
            stackFrames = Throwable().stackTrace.map { it.className }.take(48),
            readErrors = errors,
        )
    }

    private fun dexPaths(loader: ClassLoader?): List<String> {
        if (loader == null) return emptyList()
        val out = mutableListOf<String>()
        try {
            var type: Class<*>? = loader.javaClass
            var pathList: Any? = null
            while (type != null && pathList == null) {
                val field = type.declaredFields.firstOrNull { it.name == "pathList" }
                if (field != null) {
                    field.isAccessible = true
                    pathList = field.get(loader)
                }
                type = type.superclass
            }
            if (pathList == null) return out
            val elementsField = pathList.javaClass.getDeclaredField("dexElements")
            elementsField.isAccessible = true
            val elements = elementsField.get(pathList) as? Array<*> ?: return out
            for (element in elements) {
                if (element == null) continue
                for (field in element.javaClass.declaredFields) {
                    field.isAccessible = true
                    when (val value = field.get(element)) {
                        is File -> out += value.absolutePath
                        null -> Unit
                        else -> {
                            if (value.javaClass.name.contains("DexFile")) {
                                val name = value.javaClass.methods.firstOrNull {
                                    it.name == "getName" && it.parameterTypes.isEmpty()
                                }?.invoke(value) as? String
                                if (!name.isNullOrBlank()) out += name
                            }
                        }
                    }
                }
            }
        } catch (t: Throwable) {
            out += "error:${t.javaClass.simpleName}:${t.message.orEmpty()}"
        }
        return out.distinct()
    }
}
