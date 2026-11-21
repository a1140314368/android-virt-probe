// 根工程只做模块编排。
// Android Gradle Plugin 只在 settings 里声明，不在这里 apply，
// 这样没有 Android SDK 的环境仍能直接跑 :virtprobe-core 的 JVM 单元测试。

tasks.register("virtprobeInfo") {
    group = "help"
    description = "打印本仓库的模块与验证范围说明"
    doLast {
        println("android-virt-probe")
        println("核心判定在 :virtprobe-core，可脱离 Android SDK 用 JUnit 验证。")
        println("采集与演示在 :virtprobe-sdk / :sample-app，需要 Android SDK 与 NDK。")
    }
}
