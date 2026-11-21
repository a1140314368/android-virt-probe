// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.container

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.BLOCK_SENSITIVE_RECOMMENDATION_ZH
import io.virtprobe.core.model.ContainerSnapshot
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import io.virtprobe.core.parse.ProcText

/**
 * 应用内虚拟化容器、多开分身与宿主框架规则。
 * 工作资料（Work profile）的非 0 用户单独出现时只给低敏提示，必须再叠加宿主路径才升为高危。
 */
object ContainerRules {
    private val category = SignalCategory.CONTAINER

    fun evaluate(snapshot: ContainerSnapshot): List<SignalFinding> = listOf(
        dataDir(snapshot),
        apkPath(snapshot),
        userId(snapshot),
        uidPackages(snapshot),
        cmdline(snapshot),
        maps(snapshot),
        mounts(snapshot),
        environ(snapshot),
        classLoader(snapshot),
        stack(snapshot),
    )

    private fun dataDir(snapshot: ContainerSnapshot): SignalFinding {
        val dir = snapshot.dataDir.trim()
        val expected = listOf(
            "/data/data/${snapshot.packageName}",
            "/data/user/${snapshot.userId}/${snapshot.packageName}",
            "/data/user_de/${snapshot.userId}/${snapshot.packageName}",
        )
        val standard = expected.any { dir == it || dir.startsWith("$it/") }
        val host = hostPackageIn(dir, snapshot.packageName)
        val hit = host != null || (dir.isNotEmpty() && !standard)
        val severity = if (host != null) Severity.CRITICAL else Severity.HIGH
        return finding(
            signalId = "ctn.path.data",
            category = category,
            severity = severity,
            confidence = if (host != null) 0.96 else 0.8,
            detected = hit,
            titleZh = "私有数据目录异常",
            summaryZh = if (hit) "数据目录不在标准用户目录下，或嵌套了宿主包名。" else "数据目录符合当前用户的标准路径。",
            observedDataZh = "实际 dataDir=$dir，userId=${snapshot.userId}，包名=${snapshot.packageName}。" +
                (if (host != null) "路径中出现宿主包名 $host。" else ""),
            expectedBaselineZh = "真实安装的应用数据目录应为 /data/user/<用户号>/<本包名> 或 /data/data/<本包名>，不应嵌套在平行空间、DualSpace、VirtualApp、VMOS、360 分身等宿主目录里。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "dataDir" to dir,
                "expected" to expected.joinToString("|"),
                "host" to host.orEmpty(),
            ),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun apkPath(snapshot: ContainerSnapshot): SignalFinding {
        val path = snapshot.sourceDir.trim()
        val host = hostPackageIn(path, snapshot.packageName)
        val system = path.startsWith("/system/") || path.startsWith("/system_ext/") ||
            path.startsWith("/product/") || path.startsWith("/vendor/") || path.startsWith("/apex/")
        val inDataApp = "/data/app/" in path && snapshot.packageName in path
        val hit = host != null || (path.isNotEmpty() && !system && !inDataApp)
        return finding(
            signalId = "ctn.path.apk",
            category = category,
            severity = if (host != null) Severity.CRITICAL else Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "APK 安装路径异常",
            summaryZh = if (hit) "安装包路径不在 /data/app 或系统分区，或落在宿主目录中。" else "安装包路径符合普通安装或系统应用。",
            observedDataZh = "实际 sourceDir=$path。nativeLibraryDir=${snapshot.nativeLibraryDir}。" +
                (if (host != null) "路径中出现宿主包名 $host。" else ""),
            expectedBaselineZh = "普通应用的 base.apk 位于 /data/app/~~随机串~~/<本包名>-随机串/base.apk，系统应用位于 /system、/product 或 /apex。容器通常把 apk 放进宿主的私有目录。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "sourceDir" to path,
                "nativeLibraryDir" to snapshot.nativeLibraryDir,
                "host" to host.orEmpty(),
            ),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun userId(snapshot: ContainerSnapshot): SignalFinding {
        val hit = snapshot.userId != 0
        return finding(
            signalId = "ctn.user.id",
            category = category,
            severity = Severity.LOW,
            confidence = 0.55,
            detected = hit,
            titleZh = "非主用户运行",
            summaryZh = if (hit) "当前用户号不是 0。工作资料也会这样，不能单独当成容器。" else "当前运行在主用户。",
            observedDataZh = "实际 userId=${snapshot.userId}（由 uid / 100000 得到）。",
            expectedBaselineZh = "个人主用户的 userId 为 0。工作资料、多用户和部分多开会使用非 0 用户。只有同时出现宿主路径或宿主包名时，才应上升为容器结论。",
            recommendationZh = "这是低敏提示。若业务允许工作资料，不要仅凭 userId 阻断；请核对数据目录和同 UID 包名。",
            rawEvidence = mapOf("userId" to snapshot.userId.toString()),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun uidPackages(snapshot: ContainerSnapshot): SignalFinding {
        val others = snapshot.packagesForUid.filter { it.isNotBlank() && it != snapshot.packageName }.distinct()
        val host = others.firstOrNull { pkg -> KnownSignals.CONTAINER_PACKAGES.any { pkg == it || pkg.startsWith("$it.") } }
        val hit = others.isNotEmpty()
        val severity = if (host != null) Severity.CRITICAL else Severity.MEDIUM
        return finding(
            signalId = "ctn.uid.packages",
            category = category,
            severity = severity,
            confidence = if (host != null) 0.93 else 0.7,
            detected = hit,
            titleZh = "同 UID 多包名",
            summaryZh = if (host != null) "同一 UID 下出现了已知容器宿主包。" else if (hit) "同一 UID 下还有其它包名。" else "同一 UID 下只有本包。",
            observedDataZh = "PackageManager.getPackagesForUid 实际返回：${snapshot.packagesForUid.joinToString("，").ifBlank { "（空）" }}。",
            expectedBaselineZh = "普通第三方应用的 UID 只对应自己的包名。sharedUserId 的系统套件也可能共享 UID，所以陌生包名只算中危；已知分身宿主包名才算高危。",
            recommendationZh = if (host != null) {
                BLOCK_SENSITIVE_RECOMMENDATION_ZH
            } else {
                "同 UID 存在其它包名。请核对这些包是不是系统套件；若与宿主框架路径同时出现，按容器处理。"
            },
            rawEvidence = mapOf("packages" to snapshot.packagesForUid.joinToString(","), "host" to host.orEmpty()),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun cmdline(snapshot: ContainerSnapshot): SignalFinding {
        val cmd = snapshot.cmdline.replace('\u0000', ' ').trim()
        val readable = cmd.isNotEmpty() && snapshot.readErrors["cmdline"].isNullOrBlank()
        val host = hostPackageIn(cmd, snapshot.packageName)
        val mismatch = readable && !cmd.startsWith(snapshot.packageName)
        val hit = host != null || mismatch
        return finding(
            signalId = "ctn.proc.cmdline",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.86,
            detected = hit,
            titleZh = "进程命令行与包名不一致",
            summaryZh = if (hit) "/proc/self/cmdline 不是本包名，或直接写成了宿主包。" else "进程命令行与本包名一致，或当前不可读。",
            observedDataZh = "实际 cmdline=${cmd.ifBlank { "（空或不可读）" }}。读取错误=${snapshot.readErrors["cmdline"] ?: "无"}。",
            expectedBaselineZh = "真实进程的 cmdline 以本应用包名开头，子进程则形如 <包名>:<进程名>。容器里它经常变成宿主包名。读不到时只记录错误，不算命中。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf("cmdline" to cmd, "error" to snapshot.readErrors["cmdline"].orEmpty()),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun maps(snapshot: ContainerSnapshot): SignalFinding {
        val entries = ProcText.parseMaps(snapshot.mapsText)
        val foreignApk = entries.map { it.path }.filter { path ->
            path.endsWith(".apk") && snapshot.packageName !in path && !isSystemPath(path)
        }.distinct()
        val libs = entries.map { it.path }.filter { path ->
            KnownSignals.CONTAINER_LIBRARIES.any { marker -> path.contains(marker) }
        }.distinct()
        val host = (foreignApk + libs).firstNotNullOfOrNull { hostPackageIn(it, snapshot.packageName) }
        val hit = foreignApk.isNotEmpty() || libs.isNotEmpty()
        return finding(
            signalId = "ctn.maps.foreign",
            category = category,
            severity = if (host != null || libs.isNotEmpty()) Severity.CRITICAL else Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "内存映射中的异源 APK 或容器库",
            summaryZh = if (hit) "/proc/self/maps 出现其它应用的 apk，或容器注入的 so。" else "内存映射里没有异源 apk 或已知容器 so。",
            observedDataZh = "异源 apk：${foreignApk.joinToString("，").ifBlank { "无" }}。容器相关 so：${libs.joinToString("，").ifBlank { "无" }}。",
            expectedBaselineZh = "本进程的 apk 映射应属于自己的包名，系统库来自 /system、/apex、/vendor。出现宿主 apk、libva++.so、libsandhook、libblackbox 说明代码被装进了别的进程或被注入。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "foreignApk" to foreignApk.joinToString("|"),
                "libs" to libs.joinToString("|"),
                "mapEntries" to entries.size.toString(),
            ),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun mounts(snapshot: ContainerSnapshot): SignalFinding {
        val mounts = ProcText.parseMountInfo(snapshot.mountInfoText)
        val hits = mounts.filter { entry ->
            val blob = "${entry.mountPoint} ${entry.source} ${entry.fstype}".lowercase()
            hostPackageIn(blob, snapshot.packageName) != null ||
                "virtualapp" in blob || "blackbox" in blob || "parallel" in blob
        }
        return finding(
            signalId = "ctn.mount.redirect",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.84,
            detected = hits.isNotEmpty(),
            titleZh = "挂载信息中的路径重定向",
            summaryZh = if (hits.isNotEmpty()) "/proc/self/mountinfo 出现宿主或容器挂载。" else "挂载信息未出现容器重定向特征。",
            observedDataZh = if (hits.isEmpty()) {
                "解析到挂载 ${mounts.size} 条，未命中宿主路径。读取错误=${snapshot.readErrors["mountinfo"] ?: "无"}。"
            } else {
                "命中挂载：${hits.joinToString("；") { "${it.mountPoint} <- ${it.source}" }}。"
            },
            expectedBaselineZh = "真实应用看到的是系统分区和自己的数据目录挂载，不应把宿主的 /data/user/0/<宿主包> 重新挂到本进程的数据视图里。",
            recommendationZh = "存在容器路径重定向，建议阻断敏感操作，并把挂载原文留档。",
            rawEvidence = mapOf(
                "hitCount" to hits.size.toString(),
                "error" to snapshot.readErrors["mountinfo"].orEmpty(),
            ),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun environ(snapshot: ContainerSnapshot): SignalFinding {
        val env = ProcText.parseEnviron(snapshot.environText)
        val keys = env.keys.filter { key ->
            key.startsWith("VA_") || key.contains("VIRTUAL", ignoreCase = true) ||
                key.contains("BLACKBOX", ignoreCase = true) || key.contains("XPOSED", ignoreCase = true)
        }
        val classpath = env["CLASSPATH"].orEmpty()
        val foreignClasspath = classpath.contains(".apk") && snapshot.packageName !in classpath && !isSystemPath(classpath)
        val hit = keys.isNotEmpty() || foreignClasspath
        return finding(
            signalId = "ctn.environ.marker",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.88,
            detected = hit,
            titleZh = "环境变量中的容器标记",
            summaryZh = if (hit) "进程环境变量带有 VirtualApp、BlackBox、Xposed 或异源 CLASSPATH。" else "环境变量未发现容器标记。",
            observedDataZh = if (env.isEmpty()) {
                "environ 为空或不可读。错误=${snapshot.readErrors["environ"] ?: "无"}。"
            } else {
                "可疑键：${keys.joinToString("，") { "$it=${env[it]}" }.ifBlank { "无" }}。CLASSPATH=${classpath.ifBlank { "（空）" }}。"
            },
            expectedBaselineZh = "真实应用的环境变量主要是 Android 运行时写入的 TMPDIR、PATH 等，不应出现 VA_、VIRTUAL_APP、BLACKBOX，也不应把别的 apk 放进 CLASSPATH。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "keys" to keys.joinToString(","),
                "CLASSPATH" to classpath,
            ),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun classLoader(snapshot: ContainerSnapshot): SignalFinding {
        val foreign = snapshot.classLoaderDexPaths.filter { path ->
            path.endsWith(".apk") && snapshot.packageName !in path && !isSystemPath(path) && !path.startsWith("error:")
        }
        val host = snapshot.classLoaderDexPaths.firstNotNullOfOrNull { hostPackageIn(it, snapshot.packageName) }
        val prefixes = snapshot.classLoaderDexPaths.filter { path ->
            KnownSignals.HOST_FRAMEWORK_PREFIXES.any { prefix -> path.contains(prefix.removeSuffix(".")) }
        }
        val errors = snapshot.classLoaderDexPaths.filter { it.startsWith("error:") }
        val hit = foreign.isNotEmpty() || host != null || prefixes.isNotEmpty()
        return finding(
            signalId = "ctn.classloader.dex",
            category = category,
            severity = if (host != null) Severity.CRITICAL else Severity.HIGH,
            confidence = 0.86,
            detected = hit,
            titleZh = "类加载器 dexElements 异源路径",
            summaryZh = if (hit) "BaseDexClassLoader 的 dexElements 里有宿主或外来 apk。" else "类加载路径只包含本包和系统路径。",
            observedDataZh = "dex 路径：${snapshot.classLoaderDexPaths.joinToString("，").ifBlank { "（空）" }}。" +
                (if (errors.isEmpty()) "" else "反射错误：${errors.joinToString("，")}。"),
            expectedBaselineZh = "本应用的 dexElements 应指向自己的 base.apk 和系统框架。VirtualApp 一类容器会把宿主 apk 或插件路径插进同一个类加载器。反射失败只作为证据，不算命中。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf("paths" to snapshot.classLoaderDexPaths.joinToString("|")),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun stack(snapshot: ContainerSnapshot): SignalFinding {
        val hits = snapshot.stackFrames.filter { frame ->
            KnownSignals.HOST_FRAMEWORK_PREFIXES.any { frame.startsWith(it) }
        }.distinct()
        return finding(
            signalId = "ctn.stack.framework",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.83,
            detected = hits.isNotEmpty(),
            titleZh = "调用栈中的宿主框架前缀",
            summaryZh = if (hits.isNotEmpty()) "调用栈出现 VirtualApp、Xposed、BlackBox 或分身框架包前缀。" else "调用栈未出现已知宿主框架前缀。",
            observedDataZh = if (hits.isEmpty()) {
                "采样栈帧 ${snapshot.stackFrames.size} 条，未命中宿主前缀。"
            } else {
                "命中栈帧：${hits.joinToString("，")}。"
            },
            expectedBaselineZh = "在真实进程里，检测调用栈应停留在本应用、Android 框架和本 SDK。com.lody.virtual、io.va.exposed、de.robv.android.xposed、top.niunaijun.blackbox 等前缀表示代码正跑在宿主框架里。",
            recommendationZh = "调用栈暴露宿主框架，建议阻断敏感操作，并保留完整栈供审计。",
            rawEvidence = mapOf("hits" to hits.joinToString("|")),
            sourceAttribution = Attribution.CONTAINER,
        )
    }

    private fun hostPackageIn(text: String, selfPackage: String): String? {
        val lower = text.lowercase()
        return KnownSignals.CONTAINER_PACKAGES.firstOrNull { known ->
            known != selfPackage && known.lowercase() in lower
        }
    }

    private fun isSystemPath(path: String): Boolean {
        return path.startsWith("/system/") || path.startsWith("/system_ext/") ||
            path.startsWith("/apex/") || path.startsWith("/vendor/") ||
            path.startsWith("/product/") || path.startsWith("/framework")
    }
}
