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
    boost::asio::ip::address_v4 network;
    boost::asio::ip::address_v4 netmask;
    boost::asio::ip::address_v4 if_addr;
    uint32_t metric;
};

inline std::optional<route_ipv4> get_default_ipv4_route();

} // namespace route

#include "route_win32.hpp"