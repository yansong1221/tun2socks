#pragma once
#include <tun2socks/parameter.h>
#include <tun2socks/platform.h>

#include <boost/asio.hpp>
#include <optional>
#include <vector>

namespace route {

struct route_ipv4
{
    boost::asio::ip::address_v4 network;
    boost::asio::ip::address_v4 netmask;
    boost::asio::ip::address_v4 if_addr;
    uint32_t                    metric;
};

struct route_ipv6
{
    boost::asio::ip::address_v6 dest;
    uint8_t                     prefix_length;
    boost::asio::ip::address_v6 if_addr;
    uint32_t                    metric;
};

struct adapter_info
{
#if defined(OS_WINDOWS)
    uint32_t ipv4_if_index = 0;
    uint32_t ipv6_if_index = 0;
#else
    int if_index = 0;
#endif
    std::string if_name;

    std::vector<boost::asio::ip::address_v6> unicast_addr_v6;
    std::vector<boost::asio::ip::address_v4> unicast_addr_v4;

    inline boost::asio::ip::address_v4 v4_address()
    {
        if (unicast_addr_v4.empty())
            return boost::asio::ip::address_v4::any();
        return unicast_addr_v4.front();
    }
    inline boost::asio::ip::address_v6 v6_address()
    {
        if (unicast_addr_v6.empty())
            return boost::asio::ip::address_v6::any();
        return unicast_addr_v6.front();
    }
};
inline std::optional<adapter_info> get_default_adapter();
inline void                        init_route(const tun2socks::parameter::tun_device& tun_param);

inline bool add_route_ipapi(const route_ipv4& r);
inline bool del_route_ipapi(const route_ipv4& r);

inline bool add_route_ipapi(const route_ipv6& r);
inline bool del_route_ipapi(const route_ipv6& r);
}  // namespace route
#if defined(OS_WINDOWS)
#    include "route_win32.hpp"
#elif defined(OS_MACOS)
#    include "route_mac.hpp"
#elif defined(OS_LINUX)
#    include "route_linux.hpp"
#endif