// SPDX-License-Identifier: Apache-2.0
#include "collectors/syscall_probe.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace virtprobe {

FileRead readFileAt(const std::string& path, std::size_t maxBytes) {
    FileRead result;
    const int fd = openat(AT_FDCWD, path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            result.error = "EACCES";
        } else if (errno == ENOENT) {
            result.error = "ABSENT";
        } else {
            result.error = std::strerror(errno);
        }
        return result;
    }
    std::string text;
    char buffer[4096];
    while (text.size() < maxBytes) {
        const std::size_t want = std::min(sizeof(buffer), maxBytes - text.size());
        const ssize_t n = ::read(fd, buffer, want);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            result.error = std::strerror(errno);
            break;
        }
        text.append(buffer, buffer + n);
    }
    ::close(fd);
    result.text = text;
    result.ok = result.error.empty();
    return result;
}

std::string accessState(const std::string& path) {
    if (faccessat(AT_FDCWD, path.c_str(), F_OK, 0) == 0) return "PRESENT";
    if (errno == EACCES || errno == EPERM) return "PERMISSION_DENIED";
    if (errno == ENOENT) return "ABSENT";
    return std::string("ERROR:") + std::strerror(errno);
}

std::string unameField(char which) {
    utsname name{};
    if (uname(&name) != 0) return "";
    switch (which) {
        case 'm':
            return name.machine;
        case 's':
            return name.sysname;
        case 'r':
            return name.release;
        default:
            return "";
    }
}

}  // namespace virtprobe
