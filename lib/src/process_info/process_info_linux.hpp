#pragma once
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

#include <fmt/format.h>
#include <iostream>
#include <proc/readproc.h>

#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>
namespace fs = std::filesystem;

namespace process_info {
namespace details {

    std::vector<uint32_t> get_all_pid()
    {
        std::vector<uint32_t> pids;

        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory())
                continue;

            const auto& path    = entry.path();
            std::string pid_str = path.filename().string();

            if (!std::all_of(pid_str.begin(), pid_str.end(), ::isdigit))
                continue;
            uint32_t pid = std::stoul(pid_str);
            pids.push_back(pid);
        }
        return pids;
    }
}  // namespace details

inline std::optional<uint32_t> get_pid(uint16_t port)
{
    static std::vector<std::string> protos{"tcp", "udp", "tcp6", "udp6"};

    auto pids = details::get_all_pid();
    std::sort(pids.begin(), pids.end(), std::greater<uint32_t>());

    for (const auto& pid : pids) {
        for (const auto& proto : protos) {
            auto          net_file = fmt::format("/proc/{}/net/{}", pid, proto);
            std::ifstream net_fp(net_file);
            if (!net_fp.is_open())
                continue;

            std::string line;
            std::string sl;
            std::string local_address;
            while (std::getline(net_fp, line)) {
                std::istringstream iss(line);
                iss >> sl >> local_address;
                if (sl == "sl" || local_address == "local_address")
                    continue;
                size_t colon_pos = local_address.find_last_of(':');
                if (colon_pos == std::string::npos)
                    continue;

                std::string port_hex = local_address.substr(colon_pos + 1);
                uint16_t    num      = std::stoul(port_hex, nullptr, 16);
                if (num == port)
                    return pid;
            }
        }
    }
    return std::nullopt;
}
inline std::optional<std::string> get_execute_path(uint32_t pid)
{
    auto    proc_path = fmt::format("/proc/{}/exe", pid);
    char    exe_path[PATH_MAX];
    ssize_t path_len = readlink(proc_path.c_str(), exe_path, PATH_MAX - 1);
    if (path_len < 0) {
        perror("readlink");
        return std::nullopt;
    }
    return exe_path;
}
inline uint32_t get_current_pid()
{
    return getpid();
}
}  // namespace process_info