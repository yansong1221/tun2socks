#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <tun2socks/platform.h>

namespace process_info {

inline std::optional<uint32_t>    get_pid(uint16_t port);
inline std::optional<std::string> get_execute_path(uint32_t pid);

inline uint32_t get_current_pid();

}  // namespace process_info

#if defined(OS_WINDOWS)
#    include "process_info/process_info_win32.hpp"
#elif defined(OS_MACOS)
#    include "process_info/process_info_mac.hpp"
#endif