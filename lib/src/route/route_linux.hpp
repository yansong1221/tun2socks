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

    struct linux_adapter_info
    {
        int                                      if_index;
        std::string                              if_name;
        std::vector<boost::asio::ip::address_v4> unicast_addr_v4;
        std::vector<boost::asio::ip::address_v6> unicast_addr_v6;
    };

    struct linux_route_v4
    {
        boost::asio::ip::address_v4 destination;
        uint8_t                     prefix_length;
        boost::asio::ip::address_v4 gateway;

        int      iface_index;
        uint32_t metric;
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
    inline static std::vector<linux_adapter_info> get_linux_all_adapters()
    {
        struct result
        {
            struct nl_sock*                 sock = nullptr;
            std::vector<linux_adapter_info> vec_adapter;
        };
        result res;

        struct nl_sock* sock = nl_socket_alloc();
        if (!sock) {
            spdlog::error("Failed to allocate netlink socket");
            return res.vec_adapter;
        }
        if (nl_connect(sock, NETLINK_ROUTE) < 0) {
            spdlog::error("Failed to connect to netlink");
            nl_socket_free(sock);
            return res.vec_adapter;
        }
        res.sock = sock;

        struct nl_cache* link_cache;
        rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);

        nl_cache_foreach(link_cache, [](struct nl_object* obj, void* arg) {
            struct rtnl_link* link = (struct rtnl_link*)obj;
            auto              res  = (result*)arg;

            linux_adapter_info info;

            info.if_name  = rtnl_link_get_name(link);
            info.if_index = rtnl_link_get_ifindex(link);

            struct nl_cache* addr_cache;
            rtnl_addr_alloc_cache(res->sock, &addr_cache);

            nl_cache_foreach(addr_cache,[](struct nl_object *obj,void*arg)
            {
                char buffer[128];
                auto addr = (struct rtnl_addr *)obj;
                auto info = (linux_adapter_info*)arg;

                struct nl_addr *addr_ip = rtnl_addr_get_local(addr);
                nl_addr2str(addr_ip,buffer,sizeof(buffer));

                if(rtnl_addr_get_family(addr) == AF_INET6)
                    info->unicast_addr_v6.push_back(boost::asio::ip::make_address_v6(buffer));
                else
                    info->unicast_addr_v4.push_back(boost::asio::ip::make_address_v4(buffer));
            },&info);
            nl_cache_free(addr_cache); }, &res);

        nl_cache_free(link_cache);
        nl_socket_free(sock);
        return res.vec_adapter;
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

        struct rtnl_route* route = rtnl_route_alloc();
        struct nl_cache*   route_cache;
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
            auto nh_count = rtnl_route_get_nnexthops(route);
            spdlog::info("22222222 {}",nh_count);
            for (int i = 0; i < nh_count; ++i) {
                struct rtnl_nexthop* nh = rtnl_route_nexthop_n(route_iter, i);
                if (nh) {
                    struct nl_addr* gateway = rtnl_route_nh_get_gateway(nh);
                    if (gateway) {
                        char gateway_str[INET6_ADDRSTRLEN];
                        nl_addr2str(gateway, gateway_str, sizeof(gateway_str));
                        printf("Nexthop %d gateway: %s\n", i, gateway_str);
                    }
                }
            }

            spdlog::info("11111111111 {} {} {}", info.destination.to_string(), info.prefix_length, info.metric);
            {
                // struct rtnl_nexthop* nh = rtnl_route_nexthop_n(route_iter, 1);
                // struct nl_addr*      gw = rtnl_route_nh_get_gateway(nh);

                // struct sockaddr_in addr;
                // socklen_t addr_len = sizeof(sockaddr_in);
                // nl_addr_fill_sockaddr(gw,(struct sockaddr*)&addr,&addr_len);

                // info.gateway          = boost::asio::ip::make_address_v4(::ntohl(addr.sin_addr.s_addr));
                // info.iface_index = rtnl_route_nh_get_ifindex(nh);
            }
            // spdlog::info("22222222222 {} {}",info.gateway.to_string(),info.iface_index);
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

}  // namespace details
inline std::optional<route_ipv4> get_default_ipv4_route()
{
    auto route = details::get_linux_default_ipv4_route();
    if (!route)
        return std::nullopt;

    for (const auto& adapter : details::get_linux_all_adapters()) {
        if (adapter.if_index == route->iface_index) {
            route_ipv4 info;
            if (!adapter.unicast_addr_v4.empty())
                info.if_addr = adapter.unicast_addr_v4.front();
            info.metric  = route->metric;
            info.netmask = details::create_ipv4_mask_from_prefix_length(route->prefix_length);
            info.network = route->destination;
            return info;
        }
    }
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