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

struct adapter_info
{
    uint32_t ipv4_if_index = 0;
    uint32_t ipv6_if_index = 0;

    std::string name;

    boost::asio::ip::address_v6 unicast_addr_v6;
    boost::asio::ip::address_v4 unicast_addr_v4;
};

inline static const std::vector<adapter_info> &get_adapters()
{
    static std::vector<adapter_info> adapter_vec;
    if (!adapter_vec.empty())
        return adapter_vec;

    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    // Call GetAdaptersAddresses to get the size needed for the buffer
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &dwSize);

    std::vector<BYTE> buffer(dwSize);
    IP_ADAPTER_ADDRESSES *pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

    // Call GetAdaptersAddresses to get the actual data
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &dwSize);
    if (dwRetVal == NO_ERROR) {
        for (; pAddresses; pAddresses = pAddresses->Next) {
            if (pAddresses->OperStatus != IfOperStatusUp)
                continue;

            adapter_info _adapter_info;
            _adapter_info.ipv4_if_index = pAddresses->IfIndex;
            _adapter_info.ipv6_if_index = pAddresses->Ipv6IfIndex;

            _adapter_info.name = misc::utf16_utf8(pAddresses->FriendlyName);
            // Print the Unicast addresses
            for (IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pAddresses->FirstUnicastAddress; pUnicast;
                 pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in *sa_in = reinterpret_cast<sockaddr_in *>(
                        pUnicast->Address.lpSockaddr);
                    _adapter_info.unicast_addr_v4 = boost::asio::ip::address_v4(
                        ::ntohl(sa_in->sin_addr.s_addr));
                } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    sockaddr_in6 *sa_in6 = reinterpret_cast<sockaddr_in6 *>(
                        pUnicast->Address.lpSockaddr);

                    boost::asio::ip::address_v6::bytes_type bytes_v6;
                    memcpy(bytes_v6.data(), sa_in6->sin6_addr.u.Byte, 16);
                    _adapter_info.unicast_addr_v6 = boost::asio::ip::address_v6(bytes_v6);
                }
            }
            adapter_vec.push_back(_adapter_info);
        }
    }
    return adapter_vec;
}
static const MIB_IPFORWARDROW *get_default_gateway_row(const MIB_IPFORWARDTABLE *routes)
{
    DWORD lowest_metric = MAXDWORD;
    const MIB_IPFORWARDROW *ret = NULL;
    int best = -1;

    if (routes) {
        for (DWORD i = 0; i < routes->dwNumEntries; ++i) {
            const MIB_IPFORWARDROW *row = &routes->table[i];
            const uint32_t net = ::ntohl(row->dwForwardDest);
            const uint32_t mask = ::ntohl(row->dwForwardMask);
            const DWORD index = row->dwForwardIfIndex;
            const DWORD metric = row->dwForwardMetric1;

            if (!net && !mask && metric < lowest_metric) {
                ret = row;
                lowest_metric = metric;
                best = i;
            }
        }
    }
    return ret;
}

inline std::optional<route_ipv4> get_default_ipv4_route()
{
    ULONG dwSize = 0;
    DWORD status;

    status = GetIpForwardTable(NULL, &dwSize, TRUE);
    if (status != ERROR_INSUFFICIENT_BUFFER)
        return std::nullopt;

    std::vector<BYTE> buffer(dwSize);
    PMIB_IPFORWARDTABLE pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

    status = GetIpForwardTable(pTable, &dwSize, TRUE);
    if (status != NO_ERROR)
        return std::nullopt;

    const MIB_IPFORWARDROW *row = get_default_gateway_row(pTable);
    if (row == nullptr)
        return std::nullopt;

    for (const auto &adapter : get_adapters()) {
        if (adapter.ipv4_if_index == row->dwForwardIfIndex) {
            route_ipv4 info;
            info.network = boost::asio::ip::address_v4(::ntohl(row->dwForwardDest));
            info.netmask = boost::asio::ip::address_v4(::ntohl(row->dwForwardMask));
            info.if_addr = adapter.unicast_addr_v4;
            info.metric = row->dwForwardMetric1;
            return info;
        }
    }
    return std::nullopt;
}

static const MIB_IPFORWARD_ROW2 *get_default_gateway_row(const MIB_IPFORWARD_TABLE2 *pIpForwardTable)
{
    DWORD lowest_metric = MAXDWORD;
    const MIB_IPFORWARD_ROW2 *ret = NULL;
    int best = -1;

    if (pIpForwardTable) {
        for (DWORD i = 0; i < pIpForwardTable->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2 &row = pIpForwardTable->Table[i];

            boost::asio::ip::address_v6::bytes_type ip_bytes;
            memcpy(ip_bytes.data(), row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);

            auto net = boost::asio::ip::address_v6(ip_bytes);
            auto prefix_length = row.DestinationPrefix.PrefixLength;

            auto index = row.InterfaceIndex;
            auto metric = row.Metric;

            if (!net && !mask && metric < lowest_metric) {
                ret = &row;
                lowest_metric = metric;
                best = i;
            }
        }
    }
    return ret;
}

inline std::optional<route_ipv6> get_default_ipv6_route()
{
    ULONG dwSize = 0;
    DWORD status;

    PMIB_IPFORWARD_TABLE2 pIpForwardTable = nullptr;

    DWORD dwRetVal = GetIpForwardTable2(AF_INET6, &pIpForwardTable);
    if (dwRetVal != NO_ERROR)
        return std::nullopt;

    for (ULONG i = 0; i < pIpForwardTable->NumEntries; i++) {
        const MIB_IPFORWARD_ROW2 &row = pIpForwardTable->Table[i];

        std::cout << "Destination: ";
        PrintIPv6Address(row.DestinationPrefix.Prefix);

        std::cout << "/" << (int) row.DestinationPrefix.PrefixLength;
        std::cout << " Next Hop: ";
        PrintIPv6Address(row.NextHop);

        std::cout << " Interface Index: " << row.InterfaceIndex << std::endl;
    }

    std::vector<BYTE> buffer(dwSize);
    PMIB_IPFORWARDTABLE pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());

    status = GetIpForwardTable(pTable, &dwSize, TRUE);
    if (status != NO_ERROR)
        return std::nullopt;

    const MIB_IPFORWARDROW *row = get_default_gateway_row(pTable);
    if (row == nullptr)
        return std::nullopt;

    for (const auto &adapter : get_adapters()) {
        if (adapter.ipv4_if_index == row->dwForwardIfIndex) {
            route_ipv4 info;
            info.network = boost::asio::ip::address_v4(::ntohl(row->dwForwardDest));
            info.netmask = boost::asio::ip::address_v4(::ntohl(row->dwForwardMask));
            info.if_addr = adapter.unicast_addr_v4;
            info.metric = row->dwForwardMetric1;
            return info;
        }
    }
    return std::nullopt;
}

inline bool add_route_ipapi(const route_ipv4 &r)
{
    bool ret = false;
    DWORD status;

    for (const auto &adapter : get_adapters()) {
        if (adapter.unicast_addr_v4 != r.if_addr)
            continue;

        MIB_IPFORWARDROW fr = {0};

        fr.dwForwardDest = ::htonl(r.network.to_ulong());
        fr.dwForwardMask = ::htonl(r.netmask.to_ulong());
        fr.dwForwardPolicy = 0;
        fr.dwForwardIfIndex = adapter.ipv4_if_index;
        fr.dwForwardType = 4;  /* the next hop is not the final dest */
        fr.dwForwardProto = 3; /* PROTO_IP_NETMGMT */
        fr.dwForwardAge = 0;
        fr.dwForwardNextHopAS = 0;
        fr.dwForwardMetric1 = r.metric;

        status = CreateIpForwardEntry(&fr);

        if (status == NO_ERROR) {
            ret = true;
        } else {
            /* failed, try increasing the metric to work around Vista issue */
            const unsigned int forward_metric_limit
                = 2048; /* iteratively retry higher metrics up to this limit */

            for (; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1) {
                /* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
                 * --redirect-gateway over RRAS seems to need this. */
                for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType) {
                    status = CreateIpForwardEntry(&fr);
                    if (status == NO_ERROR) {
                        ret = true;
                        goto doublebreak;
                    } else if (status != ERROR_BAD_ARGUMENTS) {
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

inline bool del_route_ipapi(const route_ipv4 &r)
{
    bool ret = false;
    DWORD status;

    for (const auto &adapter : get_adapters()) {
        if (adapter.unicast_addr_v4 != r.if_addr)
            continue;
        MIB_IPFORWARDROW fr = {0};

        fr.dwForwardDest = ::htonl(r.network.to_ulong());
        fr.dwForwardMask = ::htonl(r.netmask.to_ulong());
        fr.dwForwardPolicy = 0;
        fr.dwForwardIfIndex = adapter.ipv4_if_index;

        status = DeleteIpForwardEntry(&fr);

        if (status == NO_ERROR) {
            ret = true;
        }
    }
    return ret;
}
} // namespace route