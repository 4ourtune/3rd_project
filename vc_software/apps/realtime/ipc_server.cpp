#include "shared.h"
#include "vc_common.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {
// Runtime IPC paths live under /run to avoid stale sockets after reboot and to keep
// permissions tight (0770 for directories, 0660 for the socket itself).
constexpr const char* kRuntimeDir = "/run/vc";
constexpr const char* kIpcDir = "/run/vc/ipc";
constexpr const char* kSocketPath = "/run/vc/ipc/realtime.sock";

void ensure_directory(const char* path, mode_t mode) {
    if (::mkdir(path, mode) != 0 && errno != EEXIST) {
        std::perror("[ipc] mkdir");
    } else {
        ::chmod(path, mode);
    }
}

bool parse_message(std::string_view msg, std::string& cmd, uint64_t& req, std::string& src) {
    // Trim trailing CR/LF
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r')) {
        msg.remove_suffix(1);
    }

    bool req_found = false;
    size_t pos = 0;
    while (pos <= msg.size()) {
        size_t next = msg.find(';', pos);
        std::string_view token = msg.substr(pos, next == std::string_view::npos ? msg.size() - pos : next - pos);
        if (token.rfind("CMD=", 0) == 0) {
            cmd.assign(token.substr(4));
            for (char& ch : cmd) {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
        } else if (token.rfind("REQ=", 0) == 0) {
            std::string buf(token.substr(4));
            char* end = nullptr;
            errno = 0;
            unsigned long long value = std::strtoull(buf.c_str(), &end, 10);
            if (errno == 0 && end && *end == '\0') {
                req = static_cast<uint64_t>(value);
                req_found = true;
            }
        } else if (token.rfind("SRC=", 0) == 0) {
            src.assign(token.substr(4));
        }

        if (next == std::string_view::npos) {
            break;
        }
        pos = next + 1;
    }
    return !cmd.empty() && req_found;
}
}  // namespace

void ipc_thread() {
    ensure_directory(kRuntimeDir, 0770);
    ensure_directory(kIpcDir, 0770);
    ::unlink(kSocketPath);

    int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("[ipc] socket");
        return;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, kSocketPath, sizeof(addr.sun_path) - 1);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::perror("[ipc] bind");
        ::close(fd);
        ::unlink(kSocketPath);
        return;
    }

    if (::chmod(kSocketPath, 0660) != 0) {
        std::perror("[ipc] chmod");
    }

    // Allow graceful shutdown polling every 200ms
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[256];
    while (true) {
        {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            if (!g_shared.running) {
                break;
            }
        }

        sockaddr_un peer{};
        socklen_t plen = sizeof(peer);
        ssize_t n = ::recvfrom(fd, buf, sizeof(buf) - 1, 0, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            std::perror("[ipc] recvfrom");
            continue;
        }
        if (n == 0) {
            continue;
        }
        buf[n] = '\0';

        std::string cmd;
        std::string src;
        uint64_t req = 0;
        bool parsed = parse_message(std::string_view(buf, static_cast<size_t>(n)), cmd, req, src);

        bool ok = parsed;
        std::string reason = parsed ? "" : "badmsg";
        std::string extra;

        if (ok) {
            std::lock_guard<std::mutex> lk(g_shared.mtx);
            if (!g_shared.running) {
                ok = false;
                reason = "stopped";
            } else if (cmd == "LOCK") {
                g_shared.door_locked = true;
            } else if (cmd == "UNLOCK") {
                g_shared.door_locked = false;
            } else if (cmd == "START") {
                g_shared.engine_on = true;
            } else if (cmd == "STOP") {
                g_shared.engine_on = false;
            } else if (cmd == "GET_ALL") {
                extra = ";LOCKED=" + std::to_string(g_shared.door_locked ? 1 : 0);
                extra += ";ENGINE=" + std::to_string(g_shared.engine_on ? 1 : 0);
            } else {
                ok = false;
                reason = "badcmd";
            }
        }

        std::string response;
        if (ok) {
            response = "OK;REQ=" + std::to_string(req) + extra + "\n";
        } else {
            response = "ERR;" + reason + ";REQ=" + std::to_string(req) + "\n";
        }

        if (::sendto(fd, response.c_str(), response.size(), 0,
                     reinterpret_cast<sockaddr*>(&peer), plen) < 0) {
            std::perror("[ipc] sendto");
        }
    }

    ::close(fd);
    ::unlink(kSocketPath);
}
