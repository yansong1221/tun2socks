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
        std::string                 iface_name;
        uint32_t                    metric;
    };

    std::vector<macos_route_v4> get_macos_all_ipv4_route()
    {
        // int sock = socket(AF_INET, SOCK_DGRAM, 0);
        // if (sock < 0) {
        //     perror("socket");
        //     return {};
        // }

        // ifconf ifc;
        // char   buf[4096];
        // ifc.ifc_len = sizeof(buf);
        // ifc.ifc_buf = buf;

        // if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        //     perror("ioctl");
        //     close(sock);
        //     return {};
        // }

        // std::vector<ifreq> interfaces;
        // int                numInterfaces = ifc.ifc_len / sizeof(ifreq);
        // for (int i = 0; i < numInterfaces; i++) {
        //     interfaces.push_back(ifc.ifc_req[i]);
        // }

        // for (int i = 0; i < interfaces.size(); ++i) {

        // }
        // std::vector<macos_route_v4> result;
        // close(sock);
        // return result;
        std::vector<macos_route_v4> result;

        // Step 1: Get routing table using sysctl
        int    mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
        size_t len;

        if (sysctl(mib, 6, nullptr, &len, nullptr, 0) == -1) {
            perror("sysctl estimate size");
            return result;
        }

        std::vector<char> buf(len);
        if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) == -1) {
            perror("sysctl get data");
            return result;
        }

        // Step 2: Parse the routing table entries
        char* end = buf.data() + len;
        for (char* next = buf.data(); next < end;) {
            struct rt_msghdr* rtm = reinterpret_cast<struct rt_msghdr*>(next);
            next += rtm->rtm_msglen;

            struct sockaddr* dst     = (struct sockaddr*)(rtm + 1);
            struct sockaddr* gateway = (struct sockaddr*)((char*)dst + dst->sa_len);
            struct sockaddr* netmask = (struct sockaddr*)((char*)gateway + gateway->sa_len);

            if (dst->sa_family != AF_INET || gateway->sa_family != AF_INET || netmask->sa_family != AF_INET) {
                continue;  // Ignore non-IPv4 routes
            }

            struct sockaddr_in* dst_in     = (struct sockaddr_in*)dst;
            struct sockaddr_in* gateway_in = (struct sockaddr_in*)gateway;
            struct sockaddr_in* netmask_in = (struct sockaddr_in*)netmask;

            macos_route_v4 route;
            route.destination = boost::asio::ip::address_v4(ntohl(dst_in->sin_addr.s_addr));
            route.gateway     = boost::asio::ip::address_v4(ntohl(gateway_in->sin_addr.s_addr));
            route.netmask     = boost::asio::ip::address_v4(ntohl(netmask_in->sin_addr.s_addr));
            route.metric      = rtm->rtm_rmx.rmx_hopcount;

            // Attempt to retrieve the interface name
            int  index = rtm->rtm_index;
            char ifname[IFNAMSIZ];
            if_indextoname(index, ifname);
            route.iface_name = ifname;

            result.push_back(route);
        }

        return result;
    }

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

}  // namespace details
inline std::optional<route_ipv4> get_default_ipv4_route()
{
    details::get_macos_all_ipv4_route();
    return std::nullopt;
}
inline std::optional<route_ipv6> get_default_ipv6_route()
{
    return std::nullopt;
}
inline std::optional<adapter_info> get_default_adapter()
{
    return std::nullopt;
}
inline void init_route(const tun2socks::parameter::tun_device& tun_param)
{

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