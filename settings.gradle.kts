pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version "8.7.3"
        id("com.android.library") version "8.7.3"
        id("org.jetbrains.kotlin.android") version "2.0.21"
        id("org.jetbrains.kotlin.jvm") version "2.0.21"
        id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "android-virt-probe"

include(":virtprobe-core")

fun sdkDir(): java.io.File? {
    val candidates = mutableListOf<java.io.File>()
    val local = file("local.properties")
    if (local.exists()) {
        val props = java.util.Properties()
        local.inputStream().use { props.load(it) }
        props.getProperty("sdk.dir")?.let { candidates += file(it) }
    }
    System.getenv("ANDROID_HOME")?.let { candidates += file(it) }
    System.getenv("ANDROID_SDK_ROOT")?.let { candidates += file(it) }
    candidates += file(System.getProperty("user.home") + "/Android/Sdk")
    candidates += file("/opt/android-sdk")
    candidates += file("/usr/lib/android-sdk")
    return candidates.firstOrNull { it.resolve("platforms").isDirectory }
}

val forceAndroid = providers.gradleProperty("virtprobe.includeAndroid").orNull
val sdk = sdkDir()
val includeAndroid = when (forceAndroid) {
    "true" -> true
    "false" -> false
    else -> sdk != null
}

if (includeAndroid) {
    include(":virtprobe-sdk")
    include(":sample-app")
    println("VirtProbe: 已纳入 Android 模块，sdk=${sdk?.absolutePath ?: "未解析"}")
} else {
    println("VirtProbe: 未发现 Android SDK，本次只配置 :virtprobe-core。装好 SDK 后重新同步即可构建 :virtprobe-sdk 与 :sample-app。")
}
