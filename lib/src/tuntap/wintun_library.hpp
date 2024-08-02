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
namespace wintun {

namespace details {

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
                                   _In_z_ const WCHAR *LogLine)
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

static bool SetDNS(const std::wstring &adapterName, const std::vector<std::wstring> &dnsServers)
{
    HRESULT hres;

    // 初始化COM库
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres
                  << std::endl;
        return false;
    }

    // 初始化安全性
    hres = CoInitializeSecurity(NULL,
                                -1,                          // COM默认授权服务
                                NULL,                        // COM默认授权服务
                                NULL,                        // 保留为 NULL
                                RPC_C_AUTHN_LEVEL_DEFAULT,   // 默认认证
                                RPC_C_IMP_LEVEL_IMPERSONATE, // 默认模拟级别
                                NULL,                        // 认证服务的代理身份
                                EOAC_NONE,                   // 不使用额外功能
                                NULL                         // 保留为 NULL
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres
                  << std::endl;
        CoUninitialize();
        return false;
    }

    // 创建WMI连接
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator,
                            0,
                            CLSCTX_INPROC_SERVER,
                            IID_IWbemLocator,
                            (LPVOID *) &pLoc);

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres
                  << std::endl;
        CoUninitialize();
        return false;
    }

    IWbemServices *pSvc = NULL;

    // 连接到 WMI
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), // WMI 命名空间
                               NULL,                    // 用户名（NULL = 当前用户）
                               NULL,                    // 用户密码（NULL = 当前密码）
                               0,                       // 本地化设置
                               NULL,                    // 安全标志
                               0,                       // 权限标志
                               0,                       // 权限代理
                               &pSvc                    // 接收 IWbemServices 指针
    );

    if (FAILED(hres)) {
        std::cerr << "Could not connect to WMI server. Error code = 0x" << std::hex << hres
                  << std::endl;
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 设置WMI安全设置
    hres = CoSetProxyBlanket(pSvc,                        // IWbemServices 代理
                             RPC_C_AUTHN_WINNT,           // 身份验证服务
                             RPC_C_AUTHZ_NONE,            // 授权服务
                             NULL,                        // 服务器的相对名称
                             RPC_C_AUTHN_LEVEL_CALL,      // 认证级别
                             RPC_C_IMP_LEVEL_IMPERSONATE, // 模拟级别
                             NULL,                        // 客户端身份
                             EOAC_NONE                    // 代理功能
    );

    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres
                  << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 查询所有启用了 IP 的网络适配器
    IEnumWbemClassObject *pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "WMI query failed. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 处理结果
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    bool found = false;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"ServiceName", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            std::wstring netConnID = vtProp.bstrVal;
            VariantClear(&vtProp);

            // 检查适配器名称是否匹配
            if (netConnID == L"wintun") {
                found = true;

                // 调用适配器上的 SetDNSServerSearchOrder 方法
                IWbemClassObject *pClass = NULL;
                pSvc->GetObject(bstr_t("Win32_NetworkAdapterConfiguration"), 0, NULL, &pClass, NULL);
                IWbemClassObject *pInParamsDefinition = NULL;
                pClass->GetMethod(bstr_t("SetDNSServerSearchOrder"), 0, &pInParamsDefinition, NULL);

                IWbemClassObject *pClassInstance = NULL;
                pInParamsDefinition->SpawnInstance(0, &pClassInstance);

                SAFEARRAY *sa = SafeArrayCreateVector(VT_BSTR, 0, dnsServers.size());
                LONG index = 0;
                for (const auto &dns : dnsServers) {
                    BSTR dnsServer = SysAllocString(dns.c_str());
                    SafeArrayPutElement(sa, &index, dnsServer);
                    SysFreeString(dnsServer);
                    ++index;
                }

                VARIANT var;
                var.vt = VT_ARRAY | VT_BSTR;
                var.parray = sa;

                hr = pClassInstance->Put(L"DNSServerSearchOrder", 0, &var, 0);
                VariantClear(&var);
                SafeArrayDestroy(sa);

                IWbemClassObject *pOutParams;
                hr = pSvc->ExecMethod(bstr_t("Win32_NetworkAdapterConfiguration"),
                                      bstr_t("SetDNSServerSearchOrder"),
                                      0,
                                      NULL,
                                      pClassInstance,
                                      &pOutParams,
                                      NULL);

                if (FAILED(hr)) {
                    std::cerr << "Failed to set DNS. Error code = 0x" << std::hex << hr
                              << std::endl;
                    pClassInstance->Release();
                    pInParamsDefinition->Release();
                    pClass->Release();
                    pclsObj->Release();
                    pSvc->Release();
                    pLoc->Release();
                    pEnumerator->Release();
                    CoUninitialize();
                    return false;
                }

                pClassInstance->Release();
                pInParamsDefinition->Release();
                pClass->Release();
                break; // 找到匹配的适配器后，退出循环
            }
        }

        pclsObj->Release();
    }

    if (!found) {
        std::wcerr << L"Adapter '" << adapterName << L"' not found." << std::endl;
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return found;
}
} // namespace details

class session;
class adapter;
class library;

class library : public std::enable_shared_from_this<library>
{
public:
    WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion = nullptr;
    WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver = nullptr;
    WINTUN_SET_LOGGER_FUNC *WintunSetLogger = nullptr;
    WINTUN_START_SESSION_FUNC *WintunStartSession = nullptr;
    WINTUN_END_SESSION_FUNC *WintunEndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC *WintunSendPacket = nullptr;

public:
    ~library() {}
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
    static std::shared_ptr<library> instance(boost::system::error_code &ec) noexcept
    {
        try {
            ec.clear();
            return library::instance();

        } catch (const boost::system::system_error &system_error) {
            ec = system_error.code();
            return nullptr;
        }
    }
    inline std::shared_ptr<adapter> create_adapter(const tuntap::tun_parameter &param)
    {
        WintunDeleteDriver();
        std::wstring utf16_name = misc::utf8_utf16(param.tun_name);
        std::wstring utf16_tunnel_type = misc::utf8_utf16(param.tun_name);

        /*details::utf8_utf16(_name, utf16_name);
        details::utf8_utf16(_tunnel_type, utf16_tunnel_type);*/

        GUID ExampleGuid = {0xdeadbabf,
                            0xcafe,
                            0xbeef,
                            {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
        auto _adapter = WintunCreateAdapter(utf16_name.c_str(),
                                            utf16_tunnel_type.c_str(),
                                            &ExampleGuid);
        if (!_adapter)
            details::log_throw_last_system_error("Failed to create adapter");

        return std::make_shared<adapter>(shared_from_this(), _adapter);
    }
    inline std::shared_ptr<adapter> create_adapter(const tuntap::tun_parameter &param,
                                                   boost::system::error_code &ec) noexcept
    {
        try {
            return create_adapter(param);

        } catch (const boost::system::system_error &system_error) {
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

#define X(Name) ((*(FARPROC *) &Name = GetProcAddress(Wintun.get(), #Name)) == NULL)
        if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter)
            || X(WintunGetAdapterLUID) || X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver)
            || X(WintunSetLogger) || X(WintunStartSession) || X(WintunEndSession)
            || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket)
            || X(WintunAllocateSendPacket) || X(WintunSendPacket))
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
        void operator()(HMODULE m) const { FreeLibrary(m); }
    };
    std::unique_ptr<std::remove_pointer_t<HMODULE>, library_deleter> Wintun;
};

class adapter : public std::enable_shared_from_this<adapter>
{
public:
    adapter(std::shared_ptr<library> _library, WINTUN_ADAPTER_HANDLE _adapter)
        : library_(_library)
        , wintun_adapter_(_adapter)
    {}
    ~adapter()
    {
        if (wintun_adapter_)
            library_->WintunCloseAdapter(wintun_adapter_);
    }
    inline std::shared_ptr<session> create_session(const tuntap::tun_parameter &param)
    {
        if (param.ipv4) {
            MIB_UNICASTIPADDRESS_ROW AddressRow;
            InitializeUnicastIpAddressEntry(&AddressRow);

            library_->WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);
            AddressRow.Address.Ipv4.sin_family = AF_INET;
            AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = ::htonl(
                param.ipv4->addr.to_v4().to_ulong());
            AddressRow.OnLinkPrefixLength = param.ipv4->prefix_length; /* This is a /32 network */
            AddressRow.DadState = IpDadStatePreferred;

            auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
            if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
                details::log_throw_system_error("Failed to set IPv4 address", LastError);
        }
        if (param.ipv6) {
            MIB_UNICASTIPADDRESS_ROW AddressRow;
            InitializeUnicastIpAddressEntry(&AddressRow);

            library_->WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);

            AddressRow.Address.Ipv6.sin6_family = AF_INET6;
            memcpy(AddressRow.Address.Ipv6.sin6_addr.u.Byte,
                   param.ipv6->addr.to_v6().to_bytes().data(),
                   16);
            AddressRow.OnLinkPrefixLength = param.ipv6->prefix_length; /* This is a /128 network */
            AddressRow.DadState = IpDadStatePreferred;
            auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
            if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
                details::log_throw_system_error("Failed to set IPv6 address", LastError);
        }

        auto Session = library_->WintunStartSession(wintun_adapter_, 0x400000);
        if (!Session)
            details::log_throw_last_system_error("Failed to create adapter");

        if (param.ipv4) {
            auto cmd
                = std::format("netsh interface ip set dns name=\"{}\" source=static address={}",
                              param.tun_name,
                              param.ipv4->dns.to_v4().to_string());
            //set dns
            system(cmd.c_str());
        }
        if (param.ipv6) {
            auto cmd = std::format("netsh interface ipv6 set dnsservers \"{}\" static {}",
                                   param.tun_name,
                                   param.ipv6->dns.to_v6().to_string());
            //set dns
            system(cmd.c_str());
        }

        return std::make_shared<session>(shared_from_this(), Session);
    }
    inline std::shared_ptr<session> create_session(const tuntap::tun_parameter &param,
                                                   boost::system::error_code &ec) noexcept
    {
        try {
            return create_session(param);

        } catch (const boost::system::system_error &system_error) {
            ec = system_error.code();
            return nullptr;
        }
    }

private:
    inline std::shared_ptr<library> get_library() const { return library_; }

private:
    std::shared_ptr<library> library_;

    WINTUN_ADAPTER_HANDLE wintun_adapter_ = nullptr;

    friend class session;
};

class session : public std::enable_shared_from_this<session>
{
public:
    class wintun_recv_buffer : public tuntap::recv_buffer
    {
    public:
        wintun_recv_buffer(std::shared_ptr<session> _session, BYTE *packet, DWORD size)
            : session_(_session)
            , packet_(packet)
            , size_(size)
        {}
        ~wintun_recv_buffer() { session_->release_receive_packet(packet_); }

    public:
        inline boost::asio::const_buffer data() const override
        {
            return boost::asio::const_buffer(packet_, size_);
        }

    private:
        std::shared_ptr<session> session_;
        BYTE *packet_;
        DWORD size_;
    };

public:
    inline void release_receive_packet(BYTE *packet)
    {
        adapter_->get_library()->WintunReleaseReceivePacket(wintun_session_, packet);
    }

    session(std::shared_ptr<adapter> _adapter, WINTUN_SESSION_HANDLE _session)
        : adapter_(_adapter)
        , wintun_session_(_session)
    {}
    ~session() { adapter_->get_library()->WintunEndSession(wintun_session_); }
    inline HANDLE read_wait_event()
    {
        return adapter_->get_library()->WintunGetReadWaitEvent(wintun_session_);
    }

    inline std::shared_ptr<wintun_recv_buffer> receive_packet()
    {
        DWORD PacketSize;
        BYTE *Packet = adapter_->get_library()->WintunReceivePacket(wintun_session_, &PacketSize);
        if (Packet) {
            return std::make_shared<wintun_recv_buffer>(shared_from_this(), Packet, PacketSize);
        }
        DWORD LastError = GetLastError();
        if (LastError != ERROR_NO_MORE_ITEMS)
            details::log_throw_system_error("Packet read failed", LastError);
        return nullptr;
    }
    inline std::shared_ptr<wintun_recv_buffer> receive_packet(boost::system::error_code &ec)
    {
        try {
            return receive_packet();

        } catch (const boost::system::system_error &system_error) {
            ec = system_error.code();
            return nullptr;
        }
    }
    template<typename ConstBufferSequence>
    inline void send_packets(const ConstBufferSequence &buffer)
    {
        DWORD send_size = (DWORD) boost::asio::buffer_size(buffer);
        if (send_size == 0)
            return;

        BYTE *Packet = adapter_->get_library()->WintunAllocateSendPacket(wintun_session_, send_size);
        if (Packet) {
            boost::asio::buffer_copy(boost::asio::mutable_buffer(Packet, send_size), buffer);
            adapter_->get_library()->WintunSendPacket(wintun_session_, Packet);
            return;
        }
        details::log_throw_last_system_error("Packet write failed");
    }
    template<typename ConstBufferSequence>
    inline void send_packets(const ConstBufferSequence &buffer, boost::system::error_code &ec)
    {
        try {
            return send_packets(buffer);

        } catch (const boost::system::system_error &system_error) {
            ec = system_error.code();
        }
    }

private:
    std::shared_ptr<adapter> adapter_;
    WINTUN_SESSION_HANDLE wintun_session_;
};

} // namespace wintun