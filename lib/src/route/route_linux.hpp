#pragma once

#include <arpa/inet.h>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <ifaddrs.h>
#include <iostream>
#include <net/route.h>
#include <string>
#include <sys/types.h>
#include <vector>

#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
namespace route {
namespace details {

    struct linux_route_v4
    {
        boost::asio::ip::address_v4 destination;
        uint8_t                     prefix_length;
        boost::asio::ip::address_v4 gateway;

        int      if_index = -1;
        uint32_t metric   = 0;
    };
    struct linux_route_v6
    {
        boost::asio::ip::address_v6 destination;
        uint8_t                     prefix_length;
        boost::asio::ip::address_v6 gateway;

        int      if_index = -1;
        uint32_t metric   = 0;
    };

    boost::asio::ip::address_v4 create_ipv4_mask_from_prefix_length(uint8_t prefix_length)
    {
        // 初始化为全0
        uint32_t mask = 0;

        // 将前 prefix_length 位设置为 1
        if (prefix_length > 0) {
            mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF;
        }

        // 将 mask 转换为 boost::asio::ip::address_v4
        return boost::asio::ip::address_v4(boost::asio::ip::address_v4::bytes_type{
            static_cast<uint8_t>((mask >> 24) & 0xFF),
            static_cast<uint8_t>((mask >> 16) & 0xFF),
            static_cast<uint8_t>((mask >> 8) & 0xFF),
            static_cast<uint8_t>(mask & 0xFF)});
    }
    int calculate_prefix_length(const boost::asio::ip::address_v4& address)
    {
        // 将 address 转换为网络字节顺序的 32 位整数
        uint32_t mask          = address.to_ulong();
        int      prefix_length = 0;

        // 计算连续的 1 的数量
        while (mask) {
            prefix_length++;
            mask <<= 1;
        }

        return prefix_length;
    }
    inline static std::vector<adapter_info> get_linux_all_adapters()
    {
        std::unordered_map<std::string, adapter_info> map_adapter;

        struct ifaddrs* ifaddr;
        // 获取接口地址信息
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return {};
        }
        for (auto ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr) && (ifa->ifa_netmask) && (ifa->ifa_flags & IFF_UP)) {
                auto& info    = map_adapter[ifa->ifa_name];
                info.if_name  = ifa->ifa_name;
                info.if_index = if_nametoindex(ifa->ifa_name);
                int family    = ifa->ifa_addr->sa_family;
                if (family == AF_INET6) {
                    auto addr_in = (struct sockaddr_in6*)ifa->ifa_addr;

                    boost::asio::ip::address_v6::bytes_type ip_bytes;
                    memcpy(ip_bytes.data(), addr_in->sin6_addr.__in6_u.__u6_addr8, 16);

                    auto v6_addr = boost::asio::ip::make_address_v6(ip_bytes);
                    info.unicast_addr_v6.push_back(v6_addr);
                }
                else {
                    auto addr_in = (struct sockaddr_in*)ifa->ifa_addr;
                    auto v4_addr = boost::asio::ip::make_address_v4(::ntohl(addr_in->sin_addr.s_addr));
                    info.unicast_addr_v4.push_back(v4_addr);
                }
            }
        }
        freeifaddrs(ifaddr);

        std::vector<adapter_info> vec_adapter;
        for (const auto& v : map_adapter)
            vec_adapter.push_back(v.second);

        return vec_adapter;
    }
    inline static std::vector<linux_route_v4> get_linux_all_ipv4_route()
    {
        std::vector<linux_route_v4> route_vec;
        struct nl_sock*             sock = nl_socket_alloc();
        if (!sock) {
            return route_vec;
        }

        if (nl_connect(sock, NETLINK_ROUTE) < 0) {
            nl_socket_free(sock);
            return route_vec;
        }

        struct nl_cache* route_cache;
        rtnl_route_alloc_cache(sock, AF_INET, 0, &route_cache);

        for (nl_object* obj = nl_cache_get_first(route_cache); obj; obj = nl_cache_get_next(obj)) {
            struct rtnl_route* route_iter = (struct rtnl_route*)obj;
            if (rtnl_route_get_family(route_iter) != AF_INET)
                continue;

            struct nl_addr* dst = rtnl_route_get_dst(route_iter);

            linux_route_v4 info;
            info.metric = rtnl_route_get_priority(route_iter);
            {
                struct sockaddr_in addr;
                socklen_t          addr_len = sizeof(sockaddr_in);
                nl_addr_fill_sockaddr(dst, (struct sockaddr*)&addr, &addr_len);
                info.destination   = boost::asio::ip::make_address_v4(::ntohl(addr.sin_addr.s_addr));
                info.prefix_length = nl_addr_get_prefixlen(dst);
            }

            auto nh_count = rtnl_route_get_nnexthops(route_iter);
            for (int i = 0; i < nh_count; ++i) {
                struct rtnl_nexthop* nh = rtnl_route_nexthop_n(route_iter, i);
                if (!nh)
                    continue;
                info.if_index = rtnl_route_nh_get_ifindex(nh);
                auto gateway  = rtnl_route_nh_get_gateway(nh);
                if (gateway) {
                    struct sockaddr_in addr;
                    socklen_t          addr_len = sizeof(sockaddr_in);
                    nl_addr_fill_sockaddr(gateway, (struct sockaddr*)&addr, &addr_len);
                    info.gateway = boost::asio::ip::make_address_v4(::ntohl(addr.sin_addr.s_addr));
                    break;
                }
            }
            route_vec.push_back(info);
        }

        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return route_vec;
    }
    inline static std::optional<linux_route_v4> get_linux_default_ipv4_route()
    {
        auto                          routes = get_linux_all_ipv4_route();
        std::optional<linux_route_v4> best;

        for (const auto& route : routes) {
            if (route.destination.is_unspecified() && route.prefix_length == 0) {
                if (!best) {
                    best = route;
                    continue;
                }
                if (route.metric < best->metric)
                    best = route;
            }
        }
        return best;
    }
    inline static std::vector<linux_route_v6> get_linux_all_ipv6_route()
    {
        std::vector<linux_route_v6> route_vec;
        struct nl_sock*             sock = nl_socket_alloc();
        if (!sock) {
            return route_vec;
        }

        if (nl_connect(sock, NETLINK_ROUTE) < 0) {
            nl_socket_free(sock);
            return route_vec;
        }

        struct nl_cache* route_cache;
        rtnl_route_alloc_cache(sock, AF_INET6, 0, &route_cache);

        for (nl_object* obj = nl_cache_get_first(route_cache); obj; obj = nl_cache_get_next(obj)) {
            struct rtnl_route* route_iter = (struct rtnl_route*)obj;
            if (rtnl_route_get_family(route_iter) != AF_INET6)
                continue;

            struct nl_addr* dst = rtnl_route_get_dst(route_iter);

            linux_route_v6 info;
            info.metric = rtnl_route_get_priority(route_iter);
            {
                struct sockaddr_in6 addr;
                socklen_t           addr_len = sizeof(sockaddr_in6);
                nl_addr_fill_sockaddr(dst, (struct sockaddr*)&addr, &addr_len);

                boost::asio::ip::address_v6::bytes_type ip_bytes;
                memcpy(ip_bytes.data(), addr.sin6_addr.__in6_u.__u6_addr8, 16);

                info.destination   = boost::asio::ip::make_address_v6(ip_bytes);
                info.prefix_length = nl_addr_get_prefixlen(dst);
            }

            auto nh_count = rtnl_route_get_nnexthops(route_iter);
            for (int i = 0; i < nh_count; ++i) {
                struct rtnl_nexthop* nh = rtnl_route_nexthop_n(route_iter, i);
                if (!nh)
                    continue;
                info.if_index = rtnl_route_nh_get_ifindex(nh);
                auto gateway  = rtnl_route_nh_get_gateway(nh);
                if (gateway) {
                    struct sockaddr_in6 addr;
                    socklen_t           addr_len = sizeof(sockaddr_in6);
                    nl_addr_fill_sockaddr(gateway, (struct sockaddr*)&addr, &addr_len);

                    boost::asio::ip::address_v6::bytes_type ip_bytes;
                    memcpy(ip_bytes.data(), addr.sin6_addr.__in6_u.__u6_addr8, 16);
                    info.gateway = boost::asio::ip::make_address_v6(ip_bytes);
                    break;
                }
            }
            route_vec.push_back(info);
        }

        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return route_vec;
    }
    inline static std::optional<linux_route_v6> get_linux_default_ipv6_route()
    {
        auto                          routes = get_linux_all_ipv6_route();
        std::optional<linux_route_v6> best;

        for (const auto& route : routes) {
            if (route.destination.is_unspecified() && route.prefix_length == 0) {
                if (!best) {
                    best = route;
                    continue;
                }
                if (route.metric < best->metric)
                    best = route;
            }
        }
        return best;
    }

}  // namespace details

inline std::optional<adapter_info> get_default_adapter()
{
    auto route = details::get_linux_default_ipv4_route();
    if (!route)
        return std::nullopt;

    for (const auto& adapter : details::get_linux_all_adapters()) {
        if (adapter.if_index == route->if_index)
            return adapter;
    }
    return std::nullopt;
}
inline bool add_route_ipapi(const route_ipv4& r)
{
    for (const auto& adapter : details::get_linux_all_adapters()) {
        auto iter = std::find(adapter.unicast_addr_v4.begin(),
                              adapter.unicast_addr_v4.end(),
                              r.if_addr);

        if (iter == adapter.unicast_addr_v4.end())
            continue;

        spdlog::info("!1111111111111111");

        struct nl_sock*      sock;
        struct rtnl_route*   route;
        struct rtnl_nexthop* nexthop;
        int                  err;

        // Initialize Netlink socket
        sock = nl_socket_alloc();
        if (!sock) {
            fprintf(stderr, "Failed to allocate Netlink socket\n");
            return false;
        }

        // Connect to the Netlink socket
        if (nl_connect(sock, NETLINK_ROUTE)) {
            fprintf(stderr, "Failed to connect Netlink socket\n");
            nl_socket_free(sock);
            return false;
        }

        // Create a new route
        route = rtnl_route_alloc();
        if (!route) {
            fprintf(stderr, "Failed to allocate route\n");
            nl_socket_free(sock);
            return false;
        }

        // Set the destination address (e.g., 192.168.1.0/24)
        // auto destination = nl_addr_build(AF_INET, r.network.to_string().c_str(), details::calculate_prefix_length(r.netmask));
        auto destination = nl_addr_build(AF_INET, "0.0.0.0", 0);
        rtnl_route_set_priority(route, r.metric);
        rtnl_route_set_dst(route, destination);

        // Set the gateway address (e.g., 192.168.1.1)
        nexthop = rtnl_route_nh_alloc();
        if (!nexthop) {
            fprintf(stderr, "Failed to allocate nexthop\n");
            nl_addr_put(destination);
            rtnl_route_put(route);
            nl_socket_free(sock);
            return false;
        }
        // auto gateway = nl_addr_build(AF_INET, r.if_addr.to_string().c_str(), 0);
        // rtnl_route_nh_set_gateway(nexthop, gateway);
        rtnl_route_nh_set_ifindex(nexthop, adapter.if_index);
        rtnl_route_add_nexthop(route, nexthop);

        // Send the route to the kernel
        err = rtnl_route_add(sock, route, NLM_F_REPLACE);
        if (err < 0) {
            fprintf(stderr, "Failed to add route: %s\n", nl_geterror(err));
        }
        else {
            printf("Route added successfully\n");
        }

        // Cleanup
        nl_addr_put(destination);
        rtnl_route_put(route);
        nl_socket_free(sock);
        return true;
    }
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