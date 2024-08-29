#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <tun2socks/connection.h>
#include <tun2socks/platform.h>
namespace tun2socks {
namespace process_info {

    inline std::optional<connection::proc_info>
                    get_proc_info(uint16_t port);
    inline uint32_t get_current_pid();

}  // namespace process_info
}  // namespace tun2socks

#if defined(OS_WINDOWS)
#    include "process_info/process_info_win32.hpp"
#elif defined(OS_MACOS)
#    include "process_info/process_info_mac.hpp"
#elif defined(OS_LINUX)
#    include "process_info/process_info_linux.hpp"
#endif