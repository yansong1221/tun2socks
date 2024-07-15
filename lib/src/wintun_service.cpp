
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <ip2string.h>
#include <winternl.h>

#include "wintun_service.h"
#include <fmt/format.h>


#pragma comment(lib, "iphlpapi.lib")

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter = nullptr;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter = nullptr;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter = nullptr;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID = nullptr;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion = nullptr;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver = nullptr;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger = nullptr;
static WINTUN_START_SESSION_FUNC *WintunStartSession = nullptr;
static WINTUN_END_SESSION_FUNC *WintunEndSession = nullptr;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent = nullptr;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket = nullptr;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket = nullptr;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket = nullptr;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket = nullptr;
static HMODULE Wintun = nullptr;

static HMODULE
InitializeWintun(void)
{
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME *)&Timestamp, &SystemTime);
    WCHAR LevelMarker;
    switch (Level)
    {
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
    fwprintf(
        stderr,
        L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond,
        SystemTime.wMilliseconds,
        LevelMarker,
        LogLine);
}

wintun_service::wintun_service(boost::asio::io_context &ioc) : event_(ioc) {}

bool
wintun_service::initialize_wintun()
{
    if (Wintun)
        return true;

    Wintun = InitializeWintun();
    if (!Wintun)
        return false;

    WintunSetLogger(ConsoleLogger);
    return true;
}

void
wintun_service::open()
{
    GUID ExampleGuid = { 0xdeadbabf, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    wintun_adapter_ = WintunCreateAdapter(L"test1", L"test444", &ExampleGuid);
    if (!wintun_adapter_)
    {
        fmt::format("Failed to create adapter {}", GetLastError());
        return;
    }
    DWORD Version = WintunGetRunningDriverVersion();
    fmt::format("Wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);

    WintunGetAdapterLUID(wintun_adapter_, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
    AddressRow.DadState = IpDadStatePreferred;

    auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        fmt::format("Failed to set IP address {}", LastError);
        return;
    }

    wintun_session_ = WintunStartSession(wintun_adapter_, 0x400000);
    if (!wintun_session_)
    {
        fmt::format("Failed to create adapter");
        return;
    }
}
