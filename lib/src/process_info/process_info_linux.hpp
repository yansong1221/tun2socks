#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace process_info {

inline std::optional<uint32_t> get_pid(uint16_t port)
{
    return std::nullopt;
}
inline std::optional<std::string> get_execute_path(uint32_t pid)
{
    return std::nullopt;
}
inline uint32_t get_current_pid()
{
    return getpid();
}
}  // namespace process_info