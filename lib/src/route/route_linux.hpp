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
    struct linux_route
    {
        boost::asio::ip::address destination;
        uint8_t                  prefix_length;
        boost::asio::ip::address gateway;

        int      if_index = -1;
        uint32_t metric   = 0;
    };
    inline static boost::asio::ip::address address_from_nl_addr(const struct nl_addr* addr)
    {
        char ip_str[128];
        nl_addr2str(addr, ip_str, sizeof(ip_str));
        boost::system::error_code ec;
        auto                      new_addr = boost::asio::ip::make_address(ip_str, ec);
        if (ec)
            return boost::asio::ip::address();

        return new_addr;
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
    inline static std::vector<linux_route> get_linux_all_route(int famliy)
    {
        std::vector<linux_route> route_vec;
        struct nl_sock*          sock = nl_socket_alloc();
        if (!sock) {
            return route_vec;
        }

        if (nl_connect(sock, NETLINK_ROUTE) < 0) {
            nl_socket_free(sock);
            return route_vec;
        }

        struct nl_cache* route_cache;
        rtnl_route_alloc_cache(sock, famliy, 0, &route_cache);

        for (nl_object* obj = nl_cache_get_first(route_cache); obj; obj = nl_cache_get_next(obj)) {
            struct rtnl_route* route_iter = (struct rtnl_route*)obj;
            if (rtnl_route_get_family(route_iter) != famliy)
                continue;

            struct nl_addr* dst = rtnl_route_get_dst(route_iter);

            linux_route info;
            info.metric        = rtnl_route_get_priority(route_iter);
            info.destination   = address_from_nl_addr(dst);
            info.prefix_length = nl_addr_get_prefixlen(dst);

            auto nh_count = rtnl_route_get_nnexthops(route_iter);
            for (int i = 0; i < nh_count; ++i) {
                struct rtnl_nexthop* nh = rtnl_route_nexthop_n(route_iter, i);
                if (!nh)
                    continue;
                info.if_index = rtnl_route_nh_get_ifindex(nh);
                auto gateway  = rtnl_route_nh_get_gateway(nh);
                if (gateway) {
                    info.gateway = address_from_nl_addr(gateway);
                    break;
                }
            }
            route_vec.push_back(info);
        }

        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return route_vec;
    }
    inline static std::optional<linux_route> get_linux_default_ipv4_route()
    {
        auto                       routes = get_linux_all_route(AF_INET);
        std::optional<linux_route> best;

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
    inline static std::optional<linux_route> get_linux_default_ipv6_route()
    {
        auto                       routes = get_linux_all_route(AF_INET6);
        std::optional<linux_route> best;

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
    inline bool route_ipapi(const linux_route& r, int famliy, std::function<bool(struct nl_sock*, struct rtnl_route*)> op)
    {
        struct nl_sock*      sock        = NULL;
        struct rtnl_route*   route       = NULL;
        struct rtnl_nexthop* nexthop     = NULL;
        struct nl_addr*      gateway     = nullptr;
        struct nl_addr*      destination = nullptr;

        // Initialize Netlink socket
        sock = nl_socket_alloc();
        if (!sock) {
            spdlog::error("Failed to allocate Netlink socket");
            return false;
        }

        // Connect to the Netlink socket
        if (nl_connect(sock, NETLINK_ROUTE)) {
            spdlog::error("Failed to connect Netlink socket");
            nl_socket_free(sock);
            return false;
        }

        // Create a new route
        route = rtnl_route_alloc();
        if (!route) {
            spdlog::error("Failed to allocate route");
            nl_socket_free(sock);
            return false;
        }

        // Set the destination address (e.g., 192.168.1.0/24)

        destination = nl_addr_build(famliy, r.destination.to_string().c_str(), r.prefix_length);
        rtnl_route_set_priority(route, r.metric);
        rtnl_route_set_dst(route, destination);

        // Set the gateway address (e.g., 192.168.1.1)
        nexthop = rtnl_route_nh_alloc();
        if (!nexthop) {
            spdlog::error("Failed to allocate nexthop");
            nl_addr_put(destination);
            rtnl_route_put(route);
            nl_socket_free(sock);
            return false;
        }
        if (!r.gateway.is_unspecified()) {
            nl_addr_parse(r.gateway.to_string().c_str(), famliy, &gateway);
            rtnl_route_nh_set_gateway(nexthop, gateway);
        }
        rtnl_route_nh_set_ifindex(nexthop, r.if_index);
        rtnl_route_add_nexthop(route, nexthop);

        // Send the route to the kernel
        auto res = op(sock, route);

        // Cleanup
        nl_addr_put(gateway);
        nl_addr_put(destination);
        rtnl_route_put(route);
        nl_socket_free(sock);
        return res;
    }
    inline bool add_route_ipapi(const linux_route& r, int famliy)
    {
        return route_ipapi(r, famliy, [](struct nl_sock* sock, struct rtnl_route* route) {
            // Send the route to the kernel
            auto err = rtnl_route_add(sock, route, NLM_F_REPLACE);
            if (err < 0) {
                spdlog::error("Failed to add route: {}", nl_geterror(err));
                return false;
            }
            else {
                spdlog::info("Route added successfully");
                return true;
            }
        });
    }
    inline bool del_route_ipapi(const linux_route& r, int famliy)
    {
        return route_ipapi(r, famliy, [](struct nl_sock* sock, struct rtnl_route* route) {
            // Send the route to the kernel
            auto err = rtnl_route_delete(sock, route, 0);
            if (err < 0) {
                spdlog::error("Failed to delete route: {}", nl_geterror(err));
                return false;
            }
            else {
                spdlog::info("Route delete successfully");
                return true;
            }
        });
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
inline void init_route(const tun2socks::parameter::tun_device& tun_param)
{
    for (const auto& adapter : details::get_linux_all_adapters()) {
        if (adapter.if_name != tun_param.tun_name)
            continue;

        if (tun_param.ipv4) {
            auto default_r = details::get_linux_default_ipv4_route();
            if (default_r && default_r->metric < 100) {
                details::del_route_ipapi(*default_r, AF_INET);
                default_r->metric = 100;
                details::add_route_ipapi(*default_r, AF_INET);
            }
            details::linux_route info;
            info.if_index      = adapter.if_index;
            info.metric        = 5;
            info.destination   = boost::asio::ip::address_v4::any();
            info.prefix_length = 0;
            details::add_route_ipapi(info, AF_INET);
        }
        if (tun_param.ipv6) {
            auto default_r = details::get_linux_default_ipv6_route();
            if (default_r && default_r->metric < 100) {
                details::del_route_ipapi(*default_r, AF_INET6);
                default_r->metric = 100;
                details::add_route_ipapi(*default_r, AF_INET6);
            }
            details::linux_route info;
            info.if_index      = adapter.if_index;
            info.metric        = 5;
            info.destination   = boost::asio::ip::address_v6::any();
            info.prefix_length = 0;
            details::add_route_ipapi(info, AF_INET6);
        }
        return;
    }
}
}  // namespace route