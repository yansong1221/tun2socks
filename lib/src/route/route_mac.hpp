#pragma once

#include <arpa/inet.h>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <ifaddrs.h>
#include <iostream>
#include <net/if_dl.h>
#include <net/route.h>
#include <string>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <vector>

namespace route {
namespace details {

    struct macos_adapter_info
    {
        std::string                              name;
        std::vector<boost::asio::ip::address_v4> unicast_addr_v4;
        std::vector<boost::asio::ip::address_v6> unicast_addr_v6;
    };

    struct macos_route_v4
    {
        boost::asio::ip::address_v4 destination;
        boost::asio::ip::address_v4 netmask;
        boost::asio::ip::address_v4 gateway;
        uint32_t                    iface_index;
    };

    inline static std::vector<macos_adapter_info> get_macos_all_adapters()
    {
        std::vector<macos_adapter_info> adapter_vec;

        struct ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return adapter_vec;
        }

        for (struct ifaddrs* iface = ifaddr; iface != nullptr; iface = iface->ifa_next) {
            if (iface->ifa_addr == nullptr) {
                continue;
            }

            macos_adapter_info adapter_info;
            adapter_info.name = iface->ifa_name;

            // IPv4 addresses
            if (iface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sa_in = reinterpret_cast<struct sockaddr_in*>(iface->ifa_addr);
                adapter_info.unicast_addr_v4.push_back(
                    boost::asio::ip::address_v4(ntohl(sa_in->sin_addr.s_addr)));
            }
            // IPv6 addresses
            else if (iface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6*                    sa_in6 = reinterpret_cast<struct sockaddr_in6*>(iface->ifa_addr);
                boost::asio::ip::address_v6::bytes_type bytes_v6;
                memcpy(bytes_v6.data(), sa_in6->sin6_addr.s6_addr, 16);
                adapter_info.unicast_addr_v6.push_back(boost::asio::ip::address_v6(bytes_v6));
            }
        }

        freeifaddrs(ifaddr);

        return adapter_vec;
    }

    inline static std::vector<macos_route_v4> get_macos_all_ipv4_route()
    {
        std::vector<macos_route_v4> route_vec;

        // Define the sysctl name for routing table
        int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP};

        // Get the size of the routing table
        size_t length;
        if (sysctl(mib, 5, nullptr, &length, nullptr, 0) == -1) {
            perror("sysctl");
            return route_vec;
        }

        // Allocate buffer for the routing table
        std::vector<char> buffer(length);

        if (sysctl(mib, 5, buffer.data(), &length, nullptr, 0) == -1) {
            perror("sysctl");
            return route_vec;
        }

        // Parse the routing table
        char* ptr = buffer.data();
        char* end = ptr + length;

        while (ptr < end) {
            struct rt_msghdr* rtm = reinterpret_cast<struct rt_msghdr*>(ptr);
            ptr += rtm->rtm_msglen;

            if (rtm->rtm_version != RTM_VERSION || rtm->rtm_type != RTM_GET) {
                continue;  // Skip unsupported or incorrect messages
            }

            // Parse the routing message
            struct sockaddr_in* sin = nullptr;
            macos_route_v4      route;

            if (rtm->rtm_addrs & RTA_DST) {
                sin               = reinterpret_cast<struct sockaddr_in*>(reinterpret_cast<char*>(rtm) + sizeof(struct rt_msghdr));
                route.destination = boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr));
            }

            if (rtm->rtm_addrs & RTA_NETMASK) {
                sin           = reinterpret_cast<struct sockaddr_in*>(reinterpret_cast<char*>(rtm) + sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in));
                route.netmask = boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr));
            }

            if (rtm->rtm_addrs & RTA_GATEWAY) {
                sin           = reinterpret_cast<struct sockaddr_in*>(reinterpret_cast<char*>(rtm) + sizeof(struct rt_msghdr) + 2 * sizeof(struct sockaddr_in));
                route.gateway = boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr));
            }

            if (rtm->rtm_addrs & RTA_IFP) {
                struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(reinterpret_cast<char*>(rtm) + sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in));
                route.iface_index       = sdl->sdl_index;
            }

            route_vec.push_back(route);
        }

        return route_vec;
    }

}  // namespace details
inline std::optional<route_ipv4> get_default_ipv4_route()
{
    return std::nullopt;
}
inline std::optional<route_ipv6> get_default_ipv6_route()
{
    return std::nullopt;
}

inline bool add_route_ipapi(const route_ipv4& r)
{
    return false;
}
inline bool del_route_ipapi(const route_ipv4& r)
{
    return false;
}

inline bool add_route_ipapi(const route_ipv6& r)
{
    return false;
}
inline bool del_route_ipapi(const route_ipv6& r)
{
    return false;
}
}  // namespace route