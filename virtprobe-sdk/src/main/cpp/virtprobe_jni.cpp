// SPDX-License-Identifier: Apache-2.0
#include <jni.h>

#include "collectors/evidence_collector.h"

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace {

void logLine(const char* message) {
#if defined(__ANDROID__)
    __android_log_print(ANDROID_LOG_INFO, "virtprobe", "%s", message);
#else
    (void)message;
#endif
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_io_virtprobe_sdk_native_NativeBridge_collect(JNIEnv* env, jclass /* clazz */) {
    logLine("collect native evidence");
    const std::string json = virtprobe::collectEvidenceJson();
    return env->NewStringUTF(json.c_str());
}
