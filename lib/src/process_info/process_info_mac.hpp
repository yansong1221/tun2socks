#pragma once
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace process_info {

inline std::optional<uint32_t> get_pid(uint16_t port)
{
    pid_t pids_buffer[1024];
    int   numberOfProcesses = proc_listallpids(pids_buffer, sizeof(pids_buffer));

    for (int i = 0; i < numberOfProcesses; ++i) {
        pid_t pid = pids_buffer[i];

        struct proc_fdinfo fdinfo[1024];
        int                numberOfFds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo, sizeof(fdinfo));

        for (int j = 0; j < numberOfFds / PROC_PIDLISTFD_SIZE; ++j) {
            if (fdinfo[j].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo s;
                proc_pidfdinfo(pid, fdinfo[j].proc_fd, PROC_PIDFDSOCKETINFO, &s, sizeof(s));

                if (ntohs(s.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport) == port)
                    return pid;
            }
        }
    }
    return std::nullopt;
}
std::optional<std::string> get_execute_path(uint32_t pid)
{
    // 获取进程名称
    char path[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(pid, path, sizeof(path));
    return path;
}
uint32_t get_current_pid()
{
    return getpid();
}
}  // namespace process_info