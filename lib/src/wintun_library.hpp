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

#include <spdlog/spdlog.h>

#pragma comment(lib, "iphlpapi.lib")

namespace wintun {

namespace details {
    inline void utf8_utf16(const std::string& utf8, std::wstring& utf16)
    {
        auto len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
        if (len > 0) {
            wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
            MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, tmp, len);
            utf16.assign(tmp);
            free(tmp);
        }
    }

    inline void utf16_utf8(const std::wstring& utf16, std::string& utf8)
    {
        auto len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, 0, 0);
        if (len > 0) {
            char* tmp = (char*)malloc(sizeof(char) * len);
            WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, tmp, len, 0, 0);
            utf8.assign(tmp);
            free(tmp);
        }
    }

    inline static void log_throw_system_error(std::string_view prefix, DWORD ErrorCode)
    {
        boost::system::error_code ec(ErrorCode, boost::system::system_category());
        SPDLOG_ERROR("{0} [code:{1} message:{2}]", prefix, ec.value(), ec.message());
        throw boost::system::system_error(ec);
    }
    inline static void log_throw_last_system_error(std::string_view prefix)
    {
        auto ErrorCode = GetLastError();
        log_throw_system_error(prefix, ErrorCode);
    }

    static void CALLBACK ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level,
        _In_ DWORD64 Timestamp,
        _In_z_ const WCHAR* LogLine)
    {
        SYSTEMTIME SystemTime;
        FileTimeToSystemTime((FILETIME*)&Timestamp, &SystemTime);
        WCHAR LevelMarker;
        switch (Level) {
        case WINTUN_LOG_INFO:
            LevelMarker = L'+';
            break;
        case WINTUN_LOG_WARN:
            LevelMarker = L'-';
            break;
        case WINTUN_LOG_ERR:
            LevelMarker = L'!';
            break;
        default:
            return;
        }
        fwprintf(stderr, L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n",
            SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay,
            SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond,
            SystemTime.wMilliseconds, LevelMarker, LogLine);
    }
}

class session;
class adapter;
class library;

class library : public std::enable_shared_from_this<library> {
public:
    WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion = nullptr;
    WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver = nullptr;
    WINTUN_SET_LOGGER_FUNC* WintunSetLogger = nullptr;
    WINTUN_START_SESSION_FUNC* WintunStartSession = nullptr;
    WINTUN_END_SESSION_FUNC* WintunEndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC* WintunSendPacket = nullptr;

public:
    ~library()
    {
    }
    static std::shared_ptr<library> instance()
    {
        static std::weak_ptr<library> _instance;
        auto obj = _instance.lock();
        if (obj)
            return obj;

        obj = std::make_shared<library>();
        obj->initialize_wintun();
        _instance = obj;
        return obj;
    }
    static std::shared_ptr<library> instance(boost::system::error_code& ec) noexcept
    {
        try {
            ec.clear();
            return library::instance();

        } catch (const boost::system::system_error& system_error) {
            ec = system_error.code();
            return nullptr;
        }
    }
    inline std::shared_ptr<adapter> create_adapter(const std::string& _name, const std::string& _tunnel_type);
    inline std::shared_ptr<adapter> create_adapter(const std::string& _name, const std::string& _tunnel_type, boost::system::error_code& ec) noexcept;

private:
    inline void initialize_wintun(void)
    {
        if (Wintun)
            return;

        Wintun.reset(LoadLibraryExW(
            L"wintun.dll", NULL,
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
    struct library_deleter {
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
        : library_(_library)
        , wintun_adapter_(_adapter)
    {
    }
    ~adapter()
    {
        if (wintun_adapter_)
            library_->WintunCloseAdapter(wintun_adapter_);
    }
    inline std::shared_ptr<session> create_session()
    {
        MIB_UNICASTIPADDRESS_ROW AddressRow;
        InitializeUnicastIpAddressEntry(&AddressRow);

        library_->WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);

        AddressRow.Address.Ipv4.sin_family = AF_INET;
        AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
        AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
        AddressRow.DadState = IpDadStatePreferred;

        auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
        if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
            details::log_throw_system_error("Failed to set IP address", LastError);

        auto Session = library_->WintunStartSession(wintun_adapter_, 0x400000);
        if (!Session)
            details::log_throw_last_system_error("Failed to create adapter");

        return std::make_shared<session>(shared_from_this(), Session);
    }
    inline std::shared_ptr<session> create_session(boost::system::error_code& ec) noexcept;

private:
    inline std::shared_ptr<library> get_library() const
    {
        return library_;
    }

private:
    std::shared_ptr<library> library_;

    std::string name_;
    std::string tunnel_type_;

    WINTUN_ADAPTER_HANDLE wintun_adapter_ = nullptr;

    friend class session;
};

class session {
public:
    session(std::shared_ptr<adapter> _adapter, WINTUN_SESSION_HANDLE _session)
        : adapter_(_adapter)
        , wintun_session_(_session)
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
    template <typename ReadHandler>
    inline void receive_packet(ReadHandler handler) const
    {
        boost::asio::async_completion<ReadHandler, void(BYTE*, DWORD)> init(handler);

        DWORD PacketSize;
        BYTE* Packet = adapter_->get_library()->WintunReceivePacket(wintun_session_, &PacketSize);
        if (Packet) {
            init.completion_handler(Packet, PacketSize);
            adapter_->get_library()->WintunReleaseReceivePacket(wintun_session_, Packet);
            return;
        }
        DWORD LastError = GetLastError();
        if (LastError != ERROR_NO_MORE_ITEMS)
            details::log_throw_system_error("Packet read failed", LastError);
    }
    inline void send_packets(boost::asio::const_buffer buffer)
    {
        auto b = boost::asio::buffer(buffer);
        if (b.size() == 0)
            return;

        BYTE* Packet = adapter_->get_library()->WintunAllocateSendPacket(wintun_session_,
            (DWORD)buffer.size());
        if (Packet) {
            boost::asio::buffer_copy(boost::asio::mutable_buffer(Packet, buffer.size()), buffer);
            adapter_->get_library()->WintunSendPacket(wintun_session_, Packet);
            return;
        }
        details::log_throw_last_system_error("Packet write failed");
    }

private:
    std::shared_ptr<adapter> adapter_;
    WINTUN_SESSION_HANDLE wintun_session_;
};

std::shared_ptr<wintun::adapter> library::create_adapter(const std::string& _name, const std::string& _tunnel_type)
{

    std::wstring utf16_name;
    std::wstring utf16_tunnel_type;

    details::utf8_utf16(_name, utf16_name);
    details::utf8_utf16(_tunnel_type, utf16_tunnel_type);

    GUID ExampleGuid = { 0xdeadbabf,
        0xcafe,
        0xbeef,
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    auto _adapter = WintunCreateAdapter(utf16_name.c_str(), utf16_tunnel_type.c_str(), &ExampleGuid);
    if (!_adapter)
        details::log_throw_last_system_error("Failed to create adapter");

    return std::make_shared<adapter>(shared_from_this(), _adapter);
}

std::shared_ptr<wintun::adapter> library::create_adapter(const std::string& _name, const std::string& _tunnel_type, boost::system::error_code& ec) noexcept
{
    try {
        ec.clear();
        return create_adapter(_name, _tunnel_type);

    } catch (const boost::system::system_error& system_error) {
        ec = system_error.code();
        return nullptr;
    }
}

std::shared_ptr<wintun::session> adapter::create_session(boost::system::error_code& ec) noexcept
{
    try {
        ec.clear();
        return create_session();

    } catch (const boost::system::system_error& system_error) {
        ec = system_error.code();
        return nullptr;
    }
}

}