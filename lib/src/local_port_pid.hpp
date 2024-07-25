#pragma once
#include <winsock2.h>

#include <windows.h>

#include <psapi.h>

#include <tchar.h>

#include <iphlpapi.h>

#include <ws2tcpip.h>

#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")

namespace local_port_pid {
inline static void PrintProcessInfo(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    TCHAR szProcessPath[MAX_PATH] = TEXT("<unknown>");

    // 打开指定进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    // 获取进程名称和路径
    if (hProcess != NULL) {
        HMODULE hMod;
        DWORD cbNeeded;

        // 获取进程的第一个模块句柄
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            GetModuleFileNameEx(hProcess,
                                hMod,
                                szProcessPath,
                                sizeof(szProcessPath) / sizeof(TCHAR));
        }
    }

    // 打印进程信息
    _tprintf(TEXT("PID: %u\n"), processID);
    _tprintf(TEXT("Process name: %s\n"), szProcessName);
    _tprintf(TEXT("Process path: %s\n"), szProcessPath);

    // 关闭进程句柄
    if (hProcess) {
        CloseHandle(hProcess);
    }
}

inline static DWORD tcp_using_port(USHORT port)
{
    DWORD pid = 0;
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return pid;
    }

    // 获取 TCP 表
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    ULONG ulSize = 0;
    if (GetExtendedTcpTable(NULL, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        != ERROR_INSUFFICIENT_BUFFER) {
        return pid;
    }
    pTcpTable = (MIB_TCPTABLE_OWNER_PID *) malloc(ulSize);
    if (pTcpTable == NULL) {
        WSACleanup();
        return pid;
    }

    if (GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        == NO_ERROR) {
        for (int i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
            USHORT localPort = ::ntohs((u_short) pTcpTable->table[i].dwLocalPort);
            if (localPort == port) {
                pid = pTcpTable->table[i].dwOwningPid;
                break;
            }
        }
    }

    // 清理
    free(pTcpTable);
    WSACleanup();
    return pid;
}

inline static DWORD udp_using_port(USHORT port)
{
    DWORD pid = 0;
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return pid;
    }

    // 获取 UDP 表
    PMIB_UDPTABLE_OWNER_PID pUdpTable;
    ULONG ulSize = 0;
    if (GetExtendedUdpTable(NULL, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)
        != ERROR_INSUFFICIENT_BUFFER) {
        return pid;
    }
    pUdpTable = (MIB_UDPTABLE_OWNER_PID *) malloc(ulSize);
    if (pUdpTable == NULL) {
        WSACleanup();
        return pid;
    }
    if (GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (int i = 0; i < (int) pUdpTable->dwNumEntries; i++) {
            USHORT localPort = ::ntohs((u_short) pUdpTable->table[i].dwLocalPort);
            if (localPort == port) {
                pid = pUdpTable->table[i].dwOwningPid;
                break;
            }
        }
    }
    // 清理
    free(pUdpTable);
    WSACleanup();
    return pid;
}
} // namespace local_port_pid