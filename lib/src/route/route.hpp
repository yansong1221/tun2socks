#pragma once
#include "platform.hpp"

#include <boost/asio.hpp>
#include <optional>
#include <vector>

namespace route {

struct route_ipv4
{
    boost::asio::ip::address_v4 network;
    boost::asio::ip::address_v4 netmask;
    boost::asio::ip::address_v4 if_addr;
    uint32_t metric;
};

struct route_ipv6
{
    boost::asio::ip::address_v6 dest;
    uint8_t prefix_length;
    boost::asio::ip::address_v6 if_addr;
    uint32_t metric;
};

inline std::optional<route_ipv4> get_default_ipv4_route();
inline std::optional<route_ipv6> get_default_ipv6_route();

inline bool add_route_ipapi(const route_ipv4 &r);
inline bool del_route_ipapi(const route_ipv4 &r);

inline bool add_route_ipapi(const route_ipv6 &r);
inline bool del_route_ipapi(const route_ipv6 &r);
} // namespace route
#if defined(OS_WINDOWS)
#include "route_win32.hpp"
#endif