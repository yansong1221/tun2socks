#pragma once
#include <Windows.h>

#include <Mprapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

#include "misc.hpp"
#include <optional>
#include <unordered_map>
#include <vector>

namespace route {
namespace details {
    struct windows_adapter_info
    {
        uint32_t ipv4_if_index = 0;
        uint32_t ipv6_if_index = 0;

        std::string name;

        std::vector<boost::asio::ip::address_v6> unicast_addr_v6;
        std::vector<boost::asio::ip::address_v4> unicast_addr_v4;
    };

    struct windows_route_v4
    {
        boost::asio::ip::address_v4 net;
        boost::asio::ip::address_v4 mask;
        boost::asio::ip::address_v4 next_hop;
        uint32_t                    if_index;
        uint32_t                    metric;
    };

    struct windows_route_v6
    {
        boost::asio::ip::address_v6 dest;
        uint8_t                     prefix_length;
        boost::asio::ip::address_v6 next_hop;

        uint32_t if_index;
        uint32_t metric;
    };

    inline static std::vector<windows_adapter_info> get_windows_all_adapters()
    {
        std::vector<windows_adapter_info> adapter_vec;

        DWORD dwSize   = 0;
        DWORD dwRetVal = 0;

        // Call GetAdaptersAddresses to get the size needed for the buffer
        GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &dwSize);

        std::vector<BYTE>     buffer(dwSize);
        IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

        // Call GetAdaptersAddresses to get the actual data
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &dwSize);
        if (dwRetVal == NO_ERROR) {
            for (; pAddresses; pAddresses = pAddresses->Next) {
                if (pAddresses->OperStatus != IfOperStatusUp)
                    continue;

                windows_adapter_info _adapter_info;
                _adapter_info.ipv4_if_index = pAddresses->IfIndex;
                _adapter_info.ipv6_if_index = pAddresses->Ipv6IfIndex;

                _adapter_info.name = misc::utf16_utf8(pAddresses->FriendlyName);
                // Print the Unicast addresses
                for (IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pAddresses->FirstUnicastAddress; pUnicast;
                     pUnicast                             = pUnicast->Next) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                        sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(
                            pUnicast->Address.lpSockaddr);
                        _adapter_info.unicast_addr_v4.push_back(
                            boost::asio::ip::address_v4(::ntohl(sa_in->sin_addr.s_addr)));
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(
                            pUnicast->Address.lpSockaddr);

                        boost::asio::ip::address_v6::bytes_type bytes_v6;
                        memcpy(bytes_v6.data(), sa_in6->sin6_addr.u.Byte, 16);
                        _adapter_info.unicast_addr_v6.push_back(boost::asio::ip::address_v6(bytes_v6));
                    }
                }
                adapter_vec.push_back(_adapter_info);
            }
        }
        return adapter_vec;
    }
    inline static std::vector<windows_route_v4> get_windows_all_ipv4_route()
    {
        ULONG                         dwSize = 0;
        DWORD                         status;
        std::vector<windows_route_v4> route_vec;

        status = GetIpForwardTable(NULL, &dwSize, TRUE);
        if (status != ERROR_INSUFFICIENT_BUFFER)
            return route_vec;

        std::vector<BYTE>   buffer(dwSize);
        PMIB_IPFORWARDTABLE pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

        status = GetIpForwardTable(pTable, &dwSize, TRUE);
        if (status != NO_ERROR)
            return route_vec;

        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            const MIB_IPFORWARDROW* row = &pTable->table[i];

            const uint32_t net     = ::ntohl(row->dwForwardDest);
            const uint32_t mask    = ::ntohl(row->dwForwardMask);
            const DWORD    index   = row->dwForwardIfIndex;
            const DWORD    metric  = row->dwForwardMetric1;
            const DWORD    NextHop = ::ntohl(row->dwForwardNextHop);

            windows_route_v4 info;
            info.if_index = index;
            info.net      = boost::asio::ip::address_v4(net);
            info.mask     = boost::asio::ip::address_v4(mask);
            info.next_hop = boost::asio::ip::address_v4(NextHop);
            info.metric   = metric;
            route_vec.push_back(info);
        }
        return route_vec;
    }
    inline static std::vector<windows_route_v6> get_windows_all_ipv6_route()
    {
        std::vector<windows_route_v6> route_vec;

        PMIB_IPFORWARD_TABLE2 pIpForwardTable = nullptr;
        DWORD                 dwRetVal        = GetIpForwardTable2(AF_INET6, &pIpForwardTable);
        if (dwRetVal != NO_ERROR)
            return route_vec;

        for (ULONG i = 0; i < pIpForwardTable->NumEntries; i++) {
            const MIB_IPFORWARD_ROW2& row = pIpForwardTable->Table[i];

            windows_route_v6 info;

            boost::asio::ip::address_v6::bytes_type dest_ip_bytes;
            memcpy(dest_ip_bytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
            info.dest = boost::asio::ip::address_v6(dest_ip_bytes);

            info.prefix_length = row.DestinationPrefix.PrefixLength;

            boost::asio::ip::address_v6::bytes_type nexthop_ip_bytes;
            memcpy(nexthop_ip_bytes.data(), row.NextHop.Ipv6.sin6_addr.u.Byte, 16);
            info.next_hop = boost::asio::ip::address_v6(dest_ip_bytes);
            info.if_index = row.InterfaceIndex;
            info.metric   = row.Metric;
            route_vec.push_back(info);
        }
        FreeMibTable(pIpForwardTable);
        return route_vec;
    }

    inline static std::optional<windows_route_v4> get_windows_default_ipv4_route()
    {
        auto routes = get_windows_all_ipv4_route();

        std::optional<windows_route_v4> best;

        for (const auto& route : routes) {
            if (route.net.is_unspecified() && route.mask.is_unspecified()) {
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

    inline static std::optional<windows_adapter_info> get_windows_default_adapter()
    {
        auto route = get_windows_default_ipv4_route();
        if (!route)
            return std::nullopt;

        for (const auto& adapter : get_windows_all_adapters()) {
            if (adapter.ipv4_if_index == route->if_index)
                return adapter;
        }
        return std::nullopt;
    }
}  // namespace details

inline std::vector<route_ipv4> get_all_ipv4_route()
{
    std::vector<route_ipv4> route_vec;

    auto routes   = details::get_windows_all_ipv4_route();
    auto adapters = details::get_windows_all_adapters();
    for (const auto& route : routes) {
        for (const auto& adapter : adapters) {
            route_ipv4 info;
            if (!adapter.unicast_addr_v4.empty())
                info.if_addr = adapter.unicast_addr_v4.front();
            info.metric  = route.metric;
            info.netmask = route.mask;
            info.network = route.net;
            route_vec.push_back(info);
        }
    }
    return route_vec;
}

inline std::optional<route_ipv4> get_default_ipv4_route()
{
    auto route = details::get_windows_default_ipv4_route();
    if (!route)
        return std::nullopt;

    for (const auto& adapter : details::get_windows_all_adapters()) {
        if (adapter.ipv4_if_index == route->if_index) {
            route_ipv4 info;
            if (!adapter.unicast_addr_v4.empty())
                info.if_addr = adapter.unicast_addr_v4.front();
            info.metric  = route->metric;
            info.netmask = route->mask;
            info.network = route->net;
            return info;
        }
    }
    return std::nullopt;
}

inline std::optional<route_ipv6> get_default_ipv6_route()
{
    auto adapter = details::get_windows_default_adapter();
    if (!adapter)
        return std::nullopt;

    for (const auto& route : details::get_windows_all_ipv6_route()) {
        if (route.if_index == adapter->ipv6_if_index) {
            route_ipv6 info;
            if (!adapter->unicast_addr_v6.empty())
                info.if_addr = adapter->unicast_addr_v6.front();
            info.dest          = route.dest;
            info.metric        = route.metric;
            info.prefix_length = route.prefix_length;
            return info;
        }
    }
    return std::nullopt;
}

inline bool add_route_ipapi(const route_ipv4& r)
{
    bool  ret = false;
    DWORD status;

    for (const auto& adapter : details::get_windows_all_adapters()) {
        auto iter = std::find(adapter.unicast_addr_v4.begin(),
                              adapter.unicast_addr_v4.end(),
                              r.if_addr);

        if (iter == adapter.unicast_addr_v4.end())
            continue;

        MIB_IPFORWARDROW fr = {0};

        fr.dwForwardDest      = ::htonl(r.network.to_ulong());
        fr.dwForwardMask      = ::htonl(r.netmask.to_ulong());
        fr.dwForwardPolicy    = 0;
        fr.dwForwardIfIndex   = adapter.ipv4_if_index;
        fr.dwForwardType      = MIB_IPROUTE_TYPE_INDIRECT; /* the next hop is not the final dest */
        fr.dwForwardProto     = PROTO_IP_NETMGMT;          /* PROTO_IP_NETMGMT */
        fr.dwForwardAge       = 0;
        fr.dwForwardNextHopAS = 0;
        fr.dwForwardMetric1   = r.metric;

        status = CreateIpForwardEntry(&fr);

        if (status == NO_ERROR) {
            ret = true;
        }
        else {
            /* failed, try increasing the metric to work around Vista issue */
            const unsigned int forward_metric_limit = 2048; /* iteratively retry higher metrics up to this limit */

            for (; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1) {
                /* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
                 * --redirect-gateway over RRAS seems to need this. */
                for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType) {
                    status = CreateIpForwardEntry(&fr);
                    if (status == NO_ERROR) {
                        ret = true;
                        goto doublebreak;
                    }
                    else if (status != ERROR_BAD_ARGUMENTS) {
                        goto doublebreak;
                    }
                }
            }

        doublebreak:
            if (status != NO_ERROR) {
            }
        }

        return ret;
    }
    return false;
}

inline bool del_route_ipapi(const route_ipv4& r)
{
    bool  ret = false;
    DWORD status;

    for (const auto& adapter : details::get_windows_all_adapters()) {
        auto iter = std::find(adapter.unicast_addr_v4.begin(),
                              adapter.unicast_addr_v4.end(),
                              r.if_addr);

        if (iter == adapter.unicast_addr_v4.end())
            continue;

        MIB_IPFORWARDROW fr = {0};

        fr.dwForwardDest    = ::htonl(r.network.to_ulong());
        fr.dwForwardMask    = ::htonl(r.netmask.to_ulong());
        fr.dwForwardPolicy  = 0;
        fr.dwForwardIfIndex = adapter.ipv4_if_index;

        status = DeleteIpForwardEntry(&fr);

        if (status == NO_ERROR) {
            ret = true;
        }
    }
    return ret;
}

inline bool add_route_ipapi(const route_ipv6& r)
{
    for (const auto& adapter : details::get_windows_all_adapters()) {
        auto iter = std::find(adapter.unicast_addr_v6.begin(),
                              adapter.unicast_addr_v6.end(),
                              r.if_addr);

        if (iter == adapter.unicast_addr_v6.end())
            continue;

        MIB_IPFORWARD_ROW2 route;
        InitializeIpForwardEntry(&route);

        route.InterfaceIndex                     = adapter.ipv6_if_index;
        route.DestinationPrefix.PrefixLength     = r.prefix_length;
        route.DestinationPrefix.Prefix.si_family = AF_INET6;
        memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, r.dest.to_bytes().data(), 16);

        route.Protocol = MIB_IPPROTO_NETMGMT;
        route.Metric   = r.metric;

        DWORD dwRetVal = CreateIpForwardEntry2(&route);
        if (dwRetVal == NO_ERROR) {
            spdlog::info("Default route added successfully.");
        }
        else {
            spdlog::error("CreateIpForwardEntry2 failed with error: {}", dwRetVal);
        }
        return dwRetVal == NO_ERROR;
    }
    return false;
}
inline bool del_route_ipapi(const route_ipv6& r)
{
    for (const auto& adapter : details::get_windows_all_adapters()) {
        auto iter = std::find(adapter.unicast_addr_v6.begin(),
                              adapter.unicast_addr_v6.end(),
                              r.if_addr);

        if (iter == adapter.unicast_addr_v6.end())
            continue;

        MIB_IPFORWARD_ROW2 route;
        InitializeIpForwardEntry(&route);

        route.InterfaceIndex                     = adapter.ipv6_if_index;
        route.DestinationPrefix.PrefixLength     = r.prefix_length;
        route.DestinationPrefix.Prefix.si_family = AF_INET6;
        memcpy(route.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, r.dest.to_bytes().data(), 16);

        route.Protocol = MIB_IPPROTO_NETMGMT;
        route.Metric   = r.metric;

        DWORD dwRetVal = DeleteIpForwardEntry2(&route);

        if (dwRetVal == NO_ERROR) {
            spdlog::info("Default route deleted successfully.");
        }
        else {
            spdlog::error("DeleteIpForwardEntry2 failed with error: {}", dwRetVal);
        }
        return dwRetVal == NO_ERROR;
    }
    return false;
}
}  // namespace route