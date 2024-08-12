#pragma once

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/asio.hpp>
#include <tun2socks/parameter.h>
namespace tun2socks {
namespace tuntap {

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
        boost::asio::ip::address_v4 create_ipv4_mask_from_prefix_length(uint8_t prefix_length)
        {
            // 初始化为全0
            uint32_t mask = 0;

            // 将前 prefix_length 位设置为 1
            if (prefix_length > 0) {
                mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF;
            }

            // 将 mask 转换为 boost::asio::ip::address_v4
            return boost::asio::ip::address_v4(boost::asio::ip::address_v4::bytes_type{
                static_cast<uint8_t>((mask >> 24) & 0xFF),
                static_cast<uint8_t>((mask >> 16) & 0xFF),
                static_cast<uint8_t>((mask >> 8) & 0xFF),
                static_cast<uint8_t>(mask & 0xFF)});
        }
        inline static void set_ipv4_address(int                                ctl_skt,
                                            const std::string&                 ifr_name,
                                            const boost::asio::ip::address_v4& ip,
                                            const boost::asio::ip::address_v4& mask)
        {
            ifreq ifr{0};

            // 设置 IP 地址
            sockaddr_in ip_addr{0};
            ip_addr.sin_family      = AF_INET;
            ip_addr.sin_addr.s_addr = ::htonl(ip.to_ulong());
            memcpy(&ifr.ifr_addr, &ip_addr, sizeof(ip_addr));
            strcpy(ifr.ifr_name, ifr_name.c_str());

            if (ioctl(ctl_skt, SIOCSIFADDR, &ifr) == -1) {
                log_throw_last_system_error("ioctl SIOCSIFADDR");
                return;
            }

            // 设置子网掩码
            sockaddr_in mask_struct{0};
            mask_struct.sin_family      = AF_INET;
            mask_struct.sin_addr.s_addr = ::htonl(mask.to_ulong());
            memcpy(&ifr.ifr_netmask, &mask_struct, sizeof(mask_struct));

            if (ioctl(ctl_skt, SIOCSIFNETMASK, &ifr) == -1) {
                log_throw_last_system_error("ioctl SIOCSIFNETMASK");
            }
        }

        inline static void set_ipv6_address(int                                ctl_skt,
                                            const std::string&                 ifr_name,
                                            const boost::asio::ip::address_v6& ip,
                                            uint8_t                            prefix_length)
        {
            in6_ifreq ifr6{0};

            strncpy(ifr6.ifr6_ifname, ifr_name.c_str(), IFNAMSIZ);
            ifr6.ifr6_addr      = *reinterpret_cast<const struct in6_addr*>(ip.to_bytes().data());
            ifr6.ifr6_prefixlen = prefix_length;

            if (ioctl(ctl_skt, SIOCSIFADDR, &ifr6) == -1) {
                log_throw_last_system_error("ioctl SIOCSIFADDR");
                return;
            }
        }
    }  // namespace details

    class tun_service_linux : public boost::asio::detail::service_base<tun_service_linux> {
    public:
        tun_service_linux(boost::asio::io_context& ioc)
            : boost::asio::detail::service_base<tun_service_linux>(ioc), stream_(ioc)
        {
        }

        inline void open(const parameter::tun_device& param, boost::system::error_code& ec)
        {
            int fd      = -1;
            int ctl_skt = -1;
            try {
                if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
                    details::log_throw_last_system_error("open");
                    return;
                }

                ifreq ifr{0};
                ifr.ifr_flags = IFF_TUN;
                ifr.ifr_flags |= IFF_NO_PI;
                strcpy(ifr.ifr_name, param.tun_name.c_str());
                if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
                    details::log_throw_last_system_error("ioctl");
                    return;
                }
                ctl_skt = socket(AF_INET, SOCK_DGRAM, 0);
                if (ctl_skt == -1) {
                    details::log_throw_last_system_error("socket");
                    return;
                }

                if (param.ipv4) {
                    details::set_ipv4_address(ctl_skt,
                                              param.tun_name,
                                              boost::asio::ip::make_address_v4(param.ipv4->addr),
                                              details::create_ipv4_mask_from_prefix_length(param.ipv4->prefix_length));
                }
                if (param.ipv6) {
                    details::set_ipv6_address(ctl_skt,
                                              param.tun_name,
                                              boost::asio::ip::make_address_v6(param.ipv6->addr),
                                              param.ipv6->prefix_length);
                }
                stream_descriptor_.assign(fd);
            }
            catch (const boost::system::system_error& system_error) {
                if (fd != -1)
                    ::close(fd);
                ec = system_error.code();
            }

            if (ctl_skt != -1)
                ::close(ctl_skt);
        }

        inline void close()
        {
            boost::system::error_code ec;
            stream_descriptor_.close(ec);
        }

        template <typename MutableBufferSequence>
        boost::asio::awaitable<std::size_t> async_read_some(const MutableBufferSequence& buffers,
                                                            boost::system::error_code&   ec)
        {
            auto bytes = co_await stream_descriptor_.async_read_some(buffers, net_awaitable[ec]);
            co_return bytes;
        }
        template <typename ConstBufferSequence>
        boost::asio::awaitable<std::size_t> async_write_some(const ConstBufferSequence& buffers,
                                                             boost::system::error_code& ec)
        {
            auto bytes = co_await stream_descriptor_.async_write_some(buffers, net_awaitable[ec]);
            co_return bytes;
        }

    private:
        boost::asio::posix::stream_descriptor stream_descriptor_;
    };
}  // namespace tuntap
}  // namespace tun2socks