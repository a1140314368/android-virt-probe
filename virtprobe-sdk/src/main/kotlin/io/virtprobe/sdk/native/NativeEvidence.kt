// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.native

import org.json.JSONObject

/**
 * `collectEvidenceJson()` 的 Kotlin 视图。字段缺失时留空，不把解析失败伪装成检测命中。
 */
internal data class NativeEvidence(
    val error: String?,
    val properties: Map<String, String>,
    val existingPaths: List<String>,
    val pathErrors: Map<String, String>,
    val cpuinfo: String,
    val cpuinfoError: String,
    val maps: String,
    val mapsError: String,
    val mountinfo: String,
    val mountinfoError: String,
    val cmdline: String,
    val cmdlineError: String,
    val environ: String,
    val environError: String,
    val inputDevices: String,
    val inputError: String,
    val cpuPresent: String,
    val cpuPresentError: String,
    val unameMachine: String,
    val uinput: String,
    val eventNodes: List<String>,
    val batteryTemp: String,
    val batteryVoltage: String,
    val batteryCapacity: String,
    val hints: Map<String, String>,
) {
    companion object {
        fun empty(error: String): NativeEvidence = NativeEvidence(
            error = error,
            properties = emptyMap(),
            existingPaths = emptyList(),
            pathErrors = emptyMap(),
            cpuinfo = "",
            cpuinfoError = error,
            maps = "",
            mapsError = error,
            mountinfo = "",
            mountinfoError = error,
            cmdline = "",
            cmdlineError = error,
            environ = "",
            environError = error,
            inputDevices = "",
            inputError = error,
            cpuPresent = "",
            cpuPresentError = error,
            unameMachine = "",
            uinput = "UNKNOWN",
            eventNodes = emptyList(),
            batteryTemp = "",
            batteryVoltage = "",
            batteryCapacity = "",
            hints = emptyMap(),
        )

        fun parse(text: String): NativeEvidence {
            val json = JSONObject(text)
            return NativeEvidence(
                error = null,
                properties = json.obj("properties"),
                existingPaths = json.array("existingPaths"),
                pathErrors = json.obj("pathErrors"),
                cpuinfo = json.optString("cpuinfo"),
                cpuinfoError = json.optString("cpuinfoError"),
                maps = json.optString("maps"),
                mapsError = json.optString("mapsError"),
                mountinfo = json.optString("mountinfo"),
                mountinfoError = json.optString("mountinfoError"),
                cmdline = json.optString("cmdline"),
                cmdlineError = json.optString("cmdlineError"),
                environ = json.optString("environ"),
                environError = json.optString("environError"),
                inputDevices = json.optString("inputDevices"),
                inputError = json.optString("inputError"),
                cpuPresent = json.optString("cpuPresent").trim(),
                cpuPresentError = json.optString("cpuPresentError"),
                unameMachine = json.optString("unameMachine"),
                uinput = json.optString("uinput", "UNKNOWN"),
                eventNodes = json.array("eventNodes"),
                batteryTemp = json.optString("batteryTemp").trim(),
                batteryVoltage = json.optString("batteryVoltage").trim(),
                batteryCapacity = json.optString("batteryCapacity").trim(),
                hints = json.obj("hints"),
            )
        }

        private fun JSONObject.obj(name: String): Map<String, String> {
            val child = optJSONObject(name) ?: return emptyMap()
            val out = linkedMapOf<String, String>()
            val keys = child.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                out[key] = child.optString(key)
            }
            return out
        }

        private fun JSONObject.array(name: String): List<String> {
            val child = optJSONArray(name) ?: return emptyList()
            return buildList {
                for (index in 0 until child.length()) add(child.optString(index))
            }
        }
    }
}
