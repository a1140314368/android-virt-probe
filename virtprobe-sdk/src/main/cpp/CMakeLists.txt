cmake_minimum_required(VERSION 3.18)
project(virtprobe_native CXX)

add_library(virtprobe_native SHARED
    virtprobe_jni.cpp
    collectors/syscall_probe.cpp
    collectors/property_collector.cpp
    collectors/evidence_collector.cpp
    parsers/text_parsers.cpp
    parsers/json_writer.cpp
)

target_include_directories(virtprobe_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(virtprobe_native PRIVATE cxx_std_17)

find_library(log-lib log)
if (log-lib)
    target_link_libraries(virtprobe_native ${log-lib})
endif()
