#pragma once
#include "misc.hpp"
#include "platform.hpp"
#include <boost/asio.hpp>

#if defined(OS_WINDOWS)
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

#include <format>
#include <vector>

namespace adapters {

namespace details {} // namespace details

class adapter_info
{
public:
    std::string name;
    boost::asio::ip::address_v6 unicast_addr_v6;
    boost::asio::ip::address_v4 unicast_addr_v4;

    std::string to_string() const
    {
        return std::format("Adapter Name: {0} address_v4: {1} address_v6: {2}",
                           name,
                           unicast_addr_v4.to_string(),
                           unicast_addr_v6.to_string());
    }

public:
    static std::vector<adapter_info> get_adapters() { return get_adapters_impl(); }

private:
    static std::vector<adapter_info> get_adapters_impl()
    {
        std::vector<adapter_info> adapter_vec;

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
                _adapter_info.name = misc::utf16_utf8(pAddresses->FriendlyName);
                // Print the Unicast addresses
                for (IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pAddresses->FirstUnicastAddress;
                     pUnicast;
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
};

} // namespace adapters