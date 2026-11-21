// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.native

/**
 * 原生证据入口。库加载失败时不抛给业务方，而是返回带错误说明的空证据。
 */
internal object NativeBridge {
    val loaded: Boolean = try {
        System.loadLibrary("virtprobe_native")
        true
    } catch (_: Throwable) {
        false
    }

    private external fun collect(): String

    fun safeCollect(): NativeEvidence {
        if (!loaded) return NativeEvidence.empty("未加载 libvirtprobe_native")
        return try {
            NativeEvidence.parse(collect())
        } catch (t: Throwable) {
            NativeEvidence.empty(t.message ?: t.javaClass.simpleName)
        }
    }
}
