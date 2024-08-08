#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <tun2socks/platform.h>

namespace process_info {
struct process_info
{
    uint32_t              pid;
    std::string           name;
    std::filesystem::path execute_path;
};

inline std::optional<process_info> get_process_info(uint16_t port);
inline uint32_t                    get_current_pid();

}  // namespace process_info

#if defined(OS_WINDOWS)
#    include "process_info/process_info_win32.hpp"
#elif defined(OS_MACOS)
#    include "process_info/process_info_mac.hpp"
#endif