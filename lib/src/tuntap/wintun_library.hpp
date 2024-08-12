#pragma once
#include <winsock2.h>

#include <Windows.h>

#include <ws2ipdef.h>

#include <iphlpapi.h>

#include <mstcpip.h>

#include <ip2string.h>

#include <winternl.h>

#include <stdarg.h>

#include <stdio.h>

#include <stdlib.h>

#include "wintun.h"

#include <fmt/format.h>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "misc.hpp"
#include <filesystem>
#include <format>
#include <spdlog/spdlog.h>

#include <comdef.h>

#include <Wbemidl.h>

#include "tuntap/basic_tuntap.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
namespace tun2socks {
namespace wintun {

    namespace details {

        inline static void log_throw_system_error(std::string_view prefix, DWORD ErrorCode)
        {
            boost::system::error_code ec(ErrorCode, boost::system::system_category());
            spdlog::error("{0} [code:{1} message:{2}]", prefix, ec.value(), ec.message());
            throw boost::system::system_error(ec);
        }
        inline static void log_throw_last_system_error(std::string_view prefix)
        {
            auto ErrorCode = GetLastError();
            log_throw_system_error(prefix, ErrorCode);
        }

        static void CALLBACK ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level,
                                           _In_ DWORD64             Timestamp,
                                           _In_z_ const WCHAR*      LogLine)
        {
            auto msg = std::filesystem::path(LogLine).string();
            switch (Level) {
                case WINTUN_LOG_INFO:
                    spdlog::info("[wintun.dll]: {0}", msg);
                    break;
                case WINTUN_LOG_WARN:
                    spdlog::warn("[wintun.dll]: {0}", msg);
                    break;
                case WINTUN_LOG_ERR:
                    spdlog::error("[wintun.dll]: {0}", msg);
                    break;
                default:
                    return;
            }
        }
        inline static std::string InterfaceLuidToGuidString(const NET_LUID& interfaceLuid)
        {
            GUID    interfaceGuid;
            HRESULT hr = ConvertInterfaceLuidToGuid(&interfaceLuid, &interfaceGuid);

            if (hr == NO_ERROR) {
                // 将 GUID 转换为字符串
                wchar_t guidString[40];  // GUID 字符串的长度为 39 + 1
                StringFromGUID2(interfaceGuid, guidString, sizeof(guidString) / sizeof(guidString[0]));

                return misc::utf16_utf8(guidString);
            }
            else {
                spdlog::error("Failed to convert InterfaceLuid to GUID. Error code: {}", hr);
                return "";
            }
        }

        inline static bool SetDnsServer(const std::string& adapterGuid, const std::string& dnsServers)
        {
            HKEY        hKey;
            std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + adapterGuid;

            LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
            if (result != ERROR_SUCCESS) {
                spdlog::error("Failed to open registry key. Error code: {}", result);
                return false;
            }

            result = RegSetValueEx(hKey, "NameServer", 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(dnsServers.c_str()),
                                   (dnsServers.size() + 1) * sizeof(wchar_t));

            if (result != ERROR_SUCCESS) {
                spdlog::error("Failed to set DNS server. Error code: {}", result);
                RegCloseKey(hKey);
                return false;
            }

            RegCloseKey(hKey);
            spdlog::info("DNS server set to {}", dnsServers);
            return true;
        }
        inline static bool SetIpv6DnsServers(const std::string& adapterGuid, const std::string& dnsServers)
        {
            HKEY        hKey;
            std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" + adapterGuid;

            LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
            if (result != ERROR_SUCCESS) {
                spdlog::error("Failed to open registry key. Error code: {}", result);
                return false;
            }

            result = RegSetValueEx(hKey, "NameServer", 0, REG_SZ,
                                   reinterpret_cast<const BYTE*>(dnsServers.c_str()),
                                   (dnsServers.size() + 1) * sizeof(wchar_t));

            if (result != ERROR_SUCCESS) {
                spdlog::error("Failed to set IPv6 DNS servers. Error code: {}", result);
                RegCloseKey(hKey);
                return false;
            }

            RegCloseKey(hKey);
            spdlog::info("IPv6 DNS servers set to {}", dnsServers);
            return true;
        }
    }  // namespace details

    class session;
    class adapter;
    class library;

    class library : public std::enable_shared_from_this<library> {
    public:
        WINTUN_CREATE_ADAPTER_FUNC*             WintunCreateAdapter           = nullptr;
        WINTUN_CLOSE_ADAPTER_FUNC*              WintunCloseAdapter            = nullptr;
        WINTUN_OPEN_ADAPTER_FUNC*               WintunOpenAdapter             = nullptr;
        WINTUN_GET_ADAPTER_LUID_FUNC*           WintunGetAdapterLUID          = nullptr;
        WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion = nullptr;
        WINTUN_DELETE_DRIVER_FUNC*              WintunDeleteDriver            = nullptr;
        WINTUN_SET_LOGGER_FUNC*                 WintunSetLogger               = nullptr;
        WINTUN_START_SESSION_FUNC*              WintunStartSession            = nullptr;
        WINTUN_END_SESSION_FUNC*                WintunEndSession              = nullptr;
        WINTUN_GET_READ_WAIT_EVENT_FUNC*        WintunGetReadWaitEvent        = nullptr;
        WINTUN_RECEIVE_PACKET_FUNC*             WintunReceivePacket           = nullptr;
        WINTUN_RELEASE_RECEIVE_PACKET_FUNC*     WintunReleaseReceivePacket    = nullptr;
        WINTUN_ALLOCATE_SEND_PACKET_FUNC*       WintunAllocateSendPacket      = nullptr;
        WINTUN_SEND_PACKET_FUNC*                WintunSendPacket              = nullptr;

    public:
        ~library() {}
        static std::shared_ptr<library> instance(boost::system::error_code& ec)
        {
            try {
                static std::weak_ptr<library> _instance;
                auto                          obj = _instance.lock();
                if (obj)
                    return obj;

                obj = std::make_shared<library>();
                obj->initialize_wintun();
                _instance = obj;
                return obj;
            }
            catch (const boost::system::system_error& system_error) {
                ec = system_error.code();
                return nullptr;
            }
        }
        inline std::shared_ptr<adapter> create_adapter(const parameter::tun_device& param,
                                                       boost::system::error_code&   ec) noexcept
        {
            try {
                std::wstring utf16_name        = misc::utf8_utf16(param.tun_name);
                std::wstring utf16_tunnel_type = misc::utf8_utf16(param.tun_name);

                GUID ExampleGuid = {0xdeadbabf,
                                    0xcefe,
                                    0xbeef,
                                    {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
                auto _adapter    = WintunCreateAdapter(utf16_name.c_str(),
                                                       utf16_tunnel_type.c_str(),
                                                       &ExampleGuid);
                if (!_adapter)
                    details::log_throw_last_system_error("Failed to create adapter");

                return std::make_shared<adapter>(shared_from_this(), _adapter);
            }
            catch (const boost::system::system_error& system_error) {
                ec = system_error.code();
                return nullptr;
            }
        }

    private:
        inline void initialize_wintun(void)
        {
            if (Wintun)
                return;

            Wintun.reset(
                LoadLibraryExW(L"wintun.dll",
                               NULL,
                               LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32));
            if (!Wintun)
                details::log_throw_last_system_error("Failed to load Wintun library");

#define X(Name) ((*(FARPROC*)& Name = GetProcAddress(Wintun.get(), #Name)) == NULL)
            if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) || X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) || X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) || X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
            {
                details::log_throw_last_system_error("Failed to initialize Wintun");
            }
            WintunSetLogger(details::ConsoleLogger);

            SPDLOG_INFO("Wintun library loaded");

            DWORD Version = WintunGetRunningDriverVersion();
            SPDLOG_INFO("Wintun v{0:d}.{1:d} loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);
        }

    private:
        struct library_deleter
        {
            void operator()(HMODULE m) const
            {
                FreeLibrary(m);
            }
        };
        std::unique_ptr<std::remove_pointer_t<HMODULE>, library_deleter> Wintun;
    };

    class adapter : public std::enable_shared_from_this<adapter> {
    public:
        adapter(std::shared_ptr<library> _library, WINTUN_ADAPTER_HANDLE _adapter)
            : library_(_library), wintun_adapter_(_adapter)
        {
        }
        ~adapter()
        {
            if (wintun_adapter_)
                library_->WintunCloseAdapter(wintun_adapter_);
        }
        inline std::shared_ptr<session> create_session(const parameter::tun_device& param,
                                                       boost::system::error_code&   ec) noexcept
        {
            try {
                if (param.ipv4) {
                    auto addr = boost::asio::ip::make_address_v4(param.ipv4->addr, ec);
                    if (ec)
                        return nullptr;

                    MIB_UNICASTIPADDRESS_ROW AddressRow;
                    InitializeUnicastIpAddressEntry(&AddressRow);

                    library_->WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);
                    AddressRow.Address.Ipv4.sin_family           = AF_INET;
                    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = ::htonl(addr.to_ulong());
                    AddressRow.OnLinkPrefixLength                = param.ipv4->prefix_length; /* This is a /32 network */
                    AddressRow.DadState                          = IpDadStatePreferred;

                    auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
                    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
                        details::log_throw_system_error("Failed to set IPv4 address", LastError);

                    details::SetDnsServer(details::InterfaceLuidToGuidString(AddressRow.InterfaceLuid), param.ipv4->dns);
                }
                if (param.ipv6) {
                    auto addr = boost::asio::ip::make_address_v6(param.ipv6->addr, ec);
                    if (ec)
                        return nullptr;

                    MIB_UNICASTIPADDRESS_ROW AddressRow;
                    InitializeUnicastIpAddressEntry(&AddressRow);

                    library_->WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);

                    AddressRow.Address.Ipv6.sin6_family = AF_INET6;
                    memcpy(AddressRow.Address.Ipv6.sin6_addr.u.Byte, addr.to_bytes().data(), 16);
                    AddressRow.OnLinkPrefixLength = param.ipv6->prefix_length; /* This is a /128 network */
                    AddressRow.DadState           = IpDadStatePreferred;
                    auto LastError                = CreateUnicastIpAddressEntry(&AddressRow);
                    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
                        details::log_throw_system_error("Failed to set IPv6 address", LastError);

                    details::SetIpv6DnsServers(details::InterfaceLuidToGuidString(AddressRow.InterfaceLuid), param.ipv6->dns);
                }

                auto Session = library_->WintunStartSession(wintun_adapter_, 0x400000);
                if (!Session)
                    details::log_throw_last_system_error("Failed to create adapter");

                return std::make_shared<session>(shared_from_this(), Session);
            }
            catch (const boost::system::system_error& system_error) {
                ec = system_error.code();
                return nullptr;
            }
        }

    private:
        inline std::shared_ptr<library> get_library() const
        {
            return library_;
        }

    private:
        std::shared_ptr<library> library_;

        WINTUN_ADAPTER_HANDLE wintun_adapter_ = nullptr;

        friend class session;
    };

    class session : public std::enable_shared_from_this<session> {
    public:
        session(std::shared_ptr<adapter> _adapter, WINTUN_SESSION_HANDLE _session)
            : adapter_(_adapter), wintun_session_(_session)
        {
        }
        ~session()
        {
            adapter_->get_library()->WintunEndSession(wintun_session_);
        }
        inline HANDLE read_wait_event()
        {
            return adapter_->get_library()->WintunGetReadWaitEvent(wintun_session_);
        }

        template <typename MutableBufferSequence>
        std::size_t receive_packet(MutableBufferSequence& buffer, boost::system::error_code& ec)
        {
            try {
                DWORD PacketSize;
                BYTE* Packet = adapter_->get_library()->WintunReceivePacket(wintun_session_,
                                                                            &PacketSize);
                if (Packet) {
                    boost::asio::buffer_copy(boost::asio::buffer(buffer),
                                             boost::asio::const_buffer(Packet, PacketSize));
                    adapter_->get_library()->WintunReleaseReceivePacket(wintun_session_, Packet);
                    return PacketSize;
                }
                DWORD LastError = GetLastError();
                if (LastError != ERROR_NO_MORE_ITEMS)
                    details::log_throw_system_error("Packet read failed", LastError);
            }
            catch (const boost::system::system_error& system_error) {
                ec = system_error.code();
            }
            return 0;
        }

        template <typename ConstBufferSequence>
        std::size_t send_packets(const ConstBufferSequence& buffer, boost::system::error_code& ec)
        {
            DWORD send_size = (DWORD)boost::asio::buffer_size(buffer);
            if (send_size == 0)
                return 0;

            BYTE* Packet = adapter_->get_library()->WintunAllocateSendPacket(wintun_session_, send_size);
            if (Packet) {
                boost::asio::buffer_copy(boost::asio::mutable_buffer(Packet, send_size), buffer);
                adapter_->get_library()->WintunSendPacket(wintun_session_, Packet);
                return send_size;
            }
            try {
                details::log_throw_last_system_error("Packet write failed");
            }
            catch (const boost::system::system_error& system_error) {
                ec = system_error.code();
            }
            return 0;
        }

    private:
        std::shared_ptr<adapter> adapter_;
        WINTUN_SESSION_HANDLE    wintun_session_;
    };

}  // namespace wintun
}  // namespace tun2socks