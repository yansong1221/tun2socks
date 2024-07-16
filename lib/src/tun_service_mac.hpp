#pragma once

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/types.h>
 
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
 
#include <sys/ioctl.h>          // ioctl
#include <sys/kern_control.h>   // struct socketaddr_ctl
#include <net/if_utun.h>        // UTUN_CONTROL_NAME
#include <sys/sys_domain.h>
 
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
 
#include <cstring>
#include <iostream>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

namespace details {
inline static boost::system::error_code log_last_system_error(std::string_view prefix)
{
    boost::system::error_code ec(errno, boost::system::system_category());
    SPDLOG_ERROR("{0} [code:{1} message:{2}]", prefix, ec.value(), ec.message());
    return ec;
}
inline static void log_throw_last_system_error(std::string_view prefix)
{
    auto ec = log_last_system_error(prefix);
    throw boost::system::system_error(ec);
}
inline static bool utun_set_cloexec(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) {
        return false;
    }

    flags |= FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, flags) < 0) {
        return false;
    }

    return true;
}

/* Helper functions that tries to open utun device
         * return -2 on early initialization failures (utun not supported
         * at all (old OS X) and -1 on initlization failure of utun
         * device (utun works but utunX is already used */
inline static int utun_open(int utunnum) noexcept
{
    if (utunnum < 0 || utunnum > UINT8_MAX) {
        return -1;
    }

    struct ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        return fd;
    }

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));

    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = utunnum + 1;

    if (connect(fd, (struct sockaddr *) &sc, sizeof(sc)) < 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    utun_set_cloexec(fd);
    return fd;
}

inline static bool utun_get_if_name(int tun, std::string &ifrName) noexcept
{
    ifrName.clear();
    if (tun == -1) {
        return false;
    }

    /* Retrieve the assigned interface name. */
    char utunname[1000];
    socklen_t utunname_len = sizeof(utunname);
    if (getsockopt(tun, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len) < 0) {
        return false;
    }

    ifrName = utunname;
    return true;
}

inline static bool utun_set_if_ip_gw_and_mask(int tun,
                                const std::string &ip,
                                const std::string &gw,
                                const std::string &mask) noexcept
{
    if (tun == -1 || ip.empty() || mask.empty()) {
        return false;
    }

    std::string name;
    if (!utun_get_if_name(tun, name)) {
        return false;
    }

    char cmd[1000];
    snprintf(cmd,
             sizeof(cmd),
             "ifconfig %s inet %s %s netmask %s up",
             name.data(),
             ip.data(),
             gw.data(),
             mask.data());

    int status = system(cmd);
    return status == 0;
}

inline static bool utun_set_mtu(int tun, int mtu) noexcept
{
    if (tun == -1) {
        return false;
    }

    // MTU: 68 ~ 65535 RANGE.
    if (mtu < 68) {
        mtu = 68;
    }

    std::string name;
    if (!utun_get_if_name(tun, name)) {
        return false;
    }

    char buf[1000];
    snprintf(buf, sizeof(buf), "ifconfig %s mtu %d > /dev/null 2>&1", name.data(), mtu);

    int status = system(buf);
    return status == 0;
}

inline static int utun_utunnum(const std::string &dev) noexcept
{
    int v = 0;
    if (dev.empty()) {
        return v;
    }

    std::string s;
    for (char ch : dev) {
        if (ch >= '0' && ch <= '9') {
            s.append(1, ch);
            continue;
        }
    }

    v = atoi(s.data());
    if (v < 0) {
        v = 0;
    }
    else if (v > UINT8_MAX)
    {
        v = UINT8_MAX;
    }

    return v;
}
} // namespace details

class tun_service_mac
{
public:
    tun_service_mac(boost::asio::io_context &ioc)
        : ioc_(ioc)
        , stream_descriptor_(ioc)
    {}
    void open()
    {
        struct ifreq ifr;
        struct ifaddrs *ifa;

        int fd = details::utun_open(120);

        if (fd < 0)
            details::log_throw_last_system_error("Can't find a tun entry");

        stream_descriptor_.assign(fd);
    }

private:
    boost::asio::io_context &ioc_;
    boost::asio::posix::stream_descriptor stream_descriptor_;
};