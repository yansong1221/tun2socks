#pragma once
#include <winsock2.h>

#include <windows.h>

#include <psapi.h>

#include <tchar.h>

#include <iphlpapi.h>

#include <ws2tcpip.h>

#include <tlhelp32.h>

#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")

#include <filesystem>
#include <spdlog/spdlog.h>
namespace process_info {

void trim_right(std::string& str)
{
    while (!str.empty() && (str.back() == '\n' || str.back() == '\r'))
        str.pop_back();
}

std::optional<std::string> GetExecutablePath(DWORD pid)
{
    char command[256];
    snprintf(command, sizeof(command), "powershell -command \"(Get-Process -Id %d).Path\"", pid);
    FILE* pipe = _popen(command, "r");
    if (!pipe)
        return std::nullopt;

    char        buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    trim_right(result);
    _pclose(pipe);

    std::error_code ec;
    if (!std::filesystem::exists(result, ec))
        return std::nullopt;

    return result;
}

inline std::optional<uint32_t> get_pid(uint16_t port)
{
    std::vector<uint8_t> buffer;
    ULONG                ulSize = 0;
    if (GetExtendedTcpTable(NULL, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(ulSize);
        auto pTcpTable = (PMIB_TCPTABLE_OWNER_PID)buffer.data();

        if (GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
                USHORT localPort = ::ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                if (localPort == port)
                    return pTcpTable->table[i].dwOwningPid;
            }
        }
    }

    if (GetExtendedTcpTable(NULL, &ulSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(ulSize);
        auto pTcpTable = (PMIB_TCP6TABLE_OWNER_PID)buffer.data();

        if (GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
                USHORT localPort = ::ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                if (localPort == port)
                    return pTcpTable->table[i].dwOwningPid;
            }
        }
    }

    if (GetExtendedUdpTable(NULL, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(ulSize);
        auto pUdpTable = (MIB_UDPTABLE_OWNER_PID*)buffer.data();

        if (GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++) {
                USHORT localPort = ::ntohs((u_short)pUdpTable->table[i].dwLocalPort);
                if (localPort == port)
                    return pUdpTable->table[i].dwOwningPid;
            }
        }
    }

    if (GetExtendedUdpTable(NULL, &ulSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(ulSize);
        auto pUdpTable = (MIB_UDP6TABLE_OWNER_PID*)buffer.data();

        if (GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++) {
                USHORT localPort = ::ntohs((u_short)pUdpTable->table[i].dwLocalPort);
                if (localPort == port)
                    return pUdpTable->table[i].dwOwningPid;
            }
        }
    }
    return std::nullopt;
}
inline std::optional<std::string> get_execute_path(uint32_t pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, TRUE, pid);
    if (hProcess == nullptr) {
        auto p = GetExecutablePath(pid);
        if (!p)
            spdlog::error("Failed to open process pid: {}.", pid);
        return p;
    }

    char path[MAX_PATH];
    if (!GetModuleFileNameExA(hProcess, nullptr, path, MAX_PATH)) {
        CloseHandle(hProcess);
        spdlog::error("Failed to get process image name.");
        return std::nullopt;
    }
    else {
        CloseHandle(hProcess);
        return path;
    }
}

inline uint32_t get_current_pid()
{
    return GetCurrentProcessId();
}
}  // namespace process_info