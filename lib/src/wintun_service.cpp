
#include "wintun_service.h"
#include "wintun.h"
#include <boost/dll/import.hpp>

static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter = nullptr;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter = nullptr;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter = nullptr;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID = nullptr;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion = nullptr;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver = nullptr;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger = nullptr;
static WINTUN_START_SESSION_FUNC* WintunStartSession = nullptr;
static WINTUN_END_SESSION_FUNC* WintunEndSession = nullptr;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent = nullptr;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket = nullptr;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket = nullptr;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket = nullptr;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket = nullptr;

static boost::dll::shared_library g_wintun_library;

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR* LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME*)&Timestamp, &SystemTime);
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

wintun_service::wintun_service(boost::asio::io_context& ioc)
    :event_(ioc)
{

}

bool wintun_service::initialize_wintun()
{
    if (g_wintun_library.is_loaded())
        return true;

    boost::dll::fs::error_code ec;
    g_wintun_library.load("wintun", ec, boost::dll::load_mode::append_decorations
        | boost::dll::load_mode::search_system_folders);
    if (ec)
        return false;
#define X(Name) (Name = g_wintun_library.get<decltype(Name)>(#Name)) == nullptr; if(!Name) {g_wintun_library.unload();return false;} 
    X(WintunCreateAdapter)
        X(WintunCloseAdapter)
        X(WintunOpenAdapter)
        X(WintunGetAdapterLUID)
        X(WintunGetRunningDriverVersion)
        X(WintunDeleteDriver)
        X(WintunSetLogger)
        X(WintunStartSession)
        X(WintunEndSession)
        X(WintunGetReadWaitEvent)
        X(WintunReceivePacket)
        X(WintunReleaseReceivePacket)
        X(WintunAllocateSendPacket)
        X(WintunSendPacket)
#undef X

        WintunSetLogger(ConsoleLogger);
    return true;
}
