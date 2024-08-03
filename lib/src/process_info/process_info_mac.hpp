#pragma once
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace process_info {

inline std::optional<process_info> get_process_info(uint16_t port)
{
    pid_t pids_buffer[1024];
    int numberOfProcesses = proc_listallpids(pids_buffer, sizeof(pids_buffer));

    for (int i = 0; i < numberOfProcesses; ++i) {
        pid_t pid = pids_buffer[i];

        struct proc_fdinfo fdinfo[1024];
        int numberOfFds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo, sizeof(fdinfo));

        for (int j = 0; j < numberOfFds / PROC_PIDLISTFD_SIZE; ++j) {
            if (fdinfo[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo s;
                proc_pidfdinfo(pid, fdinfo[j].proc_fd, PROC_PIDFDSOCKETINFO, &s, sizeof(s));

                if (s.psi.soi_family == AF_INET && s.psi.soi_kind == SOCKINFO_TCP
                    && ntohs(s.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport) == port) {
                    // 获取进程名称
                    char name[PROC_PIDPATHINFO_MAXSIZE];
                    char path[PROC_PIDPATHINFO_MAXSIZE];
                    proc_name(pid, name, sizeof(name));
                    proc_pidpath(pid, path, sizeof(path));

                    process_info info;
                    info.pid = pid;
                    info.name = name;
                    info.execute_path = path;
                    return info;
                }
            }
        }
    }
    return std::nullopt;
}
} // namespace process_info