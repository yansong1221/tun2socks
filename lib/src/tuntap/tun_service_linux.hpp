#pragma once

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>

#include <boost/asio.hpp>
#include <string>
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

        inline static void set_ipv4_address(const std::string&                 if_name,
                                            const boost::asio::ip::address_v4& ip,
                                            uint8_t                            prefix_length)
        {
            struct nl_sock*   sock;
            struct nl_cache*  cache;
            struct rtnl_addr* addr;
            struct rtnl_link* link;
            struct nl_cache*  links;
            struct nl_cache*  addrs;
            struct nl_addr*   local;
            int               ifindex;
            int               err;

            // Initialize netlink socket
            sock = nl_socket_alloc();
            if (!sock) {
                spdlog::error("Failed to allocate netlink socket.");
                return;
            }

            // Connect to netlink
            if (nl_connect(sock, NETLINK_ROUTE) < 0) {
                spdlog::error("Failed to connect to netlink.");
                nl_socket_free(sock);
                return;
            }

            // Get the link cache
            if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &links) < 0) {
                spdlog::error("Failed to get link cache.");
                nl_socket_free(sock);
                return;
            }

            // Find the interface by name
            link = rtnl_link_get_by_name(links, if_name.c_str());
            if (!link) {
                spdlog::error("Interface not found: {}", if_name);
                nl_cache_free(links);
                nl_socket_free(sock);
                return;
            }

            ifindex = rtnl_link_get_ifindex(link);
            nl_cache_free(links);

            // Create a new address object
            addr = rtnl_addr_alloc();
            if (!addr) {
                spdlog::error("Failed to allocate address.");
                nl_socket_free(sock);
                return;
            }

            // Set the address
            rtnl_addr_set_family(addr, AF_INET);
            rtnl_addr_set_ifindex(addr, ifindex);

            nl_addr_parse(ip.to_string().c_str(), AF_INET, &local);
            rtnl_addr_set_local(addr, local);
            rtnl_addr_set_prefixlen(addr, prefix_length);

            // Add the address
            err = rtnl_addr_add(sock, addr, NLM_F_CREATE);
            if (err < 0) {
                spdlog::error("Failed to add address: {}", nl_geterror(err));
            }
            else {
                spdlog::info("Successfully added IPv4 address.");
            }

            // Clean up
            rtnl_addr_put(addr);
            nl_socket_free(sock);
        }

        inline static void set_ipv6_address(const std::string&                 if_name,
                                            const boost::asio::ip::address_v6& ip,
                                            uint8_t                            prefix_length)
        {
            struct nl_sock*   sock;
            struct nl_cache*  cache;
            struct rtnl_addr* addr;
            struct rtnl_link* link;
            struct nl_cache*  links;
            struct nl_cache*  addrs;
            struct nl_addr*   local;
            int               ifindex;
            int               err;

            // Initialize netlink socket
            sock = nl_socket_alloc();
            if (!sock) {
                spdlog::error("Failed to allocate netlink socket.");
                return;
            }

            // Connect to netlink
            if (nl_connect(sock, NETLINK_ROUTE) < 0) {
                spdlog::error("Failed to connect to netlink.");
                nl_socket_free(sock);
                return;
            }

            // Get the link cache
            if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &links) < 0) {
                spdlog::error("Failed to get link cache.");
                nl_socket_free(sock);
                return;
            }

            // Find the interface by name
            link = rtnl_link_get_by_name(links, if_name.c_str());
            if (!link) {
                spdlog::error("Interface not found: {}", if_name);
                nl_cache_free(links);
                nl_socket_free(sock);
                return;
            }

            ifindex = rtnl_link_get_ifindex(link);
            nl_cache_free(links);

            // Create a new address object
            addr = rtnl_addr_alloc();
            if (!addr) {
                spdlog::error("Failed to allocate address.");
                nl_socket_free(sock);
                return;
            }

            // Set the address
            rtnl_addr_set_family(addr, AF_INET6);
            rtnl_addr_set_ifindex(addr, ifindex);

            nl_addr_parse(ip.to_string().c_str(), AF_INET6, &local);
            rtnl_addr_set_local(addr, local);
            rtnl_addr_set_prefixlen(addr, prefix_length);

            // Add the address
            err = rtnl_addr_add(sock, addr, NLM_F_CREATE);
            if (err < 0) {
                spdlog::error("Failed to add address: {}", nl_geterror(err));
            }
            else {
                spdlog::info("Successfully added IPv6 address.");
            }

            // Clean up
            rtnl_addr_put(addr);
            nl_socket_free(sock);
        }
    }  // namespace details

    class tun_service_linux : public boost::asio::detail::service_base<tun_service_linux> {
    public:
        tun_service_linux(boost::asio::io_context& ioc)
            : boost::asio::detail::service_base<tun_service_linux>(ioc),
              stream_descriptor_(ioc)
        {
        }

        inline void open(const parameter::tun_device& param, boost::system::error_code& ec)
        {
            int fd      = -1;
            int ctl_skt = -1;
            try {
                if ((fd = ::open("/dev/net/tun", O_RDWR)) == -1) {
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

                if (param.ipv4) {
                    details::set_ipv4_address(param.tun_name,
                                              boost::asio::ip::make_address_v4(param.ipv4->addr),
                                              param.ipv4->prefix_length);
                }
                if (param.ipv6) {
                    details::set_ipv6_address(
                        param.tun_name,
                        boost::asio::ip::make_address_v6(param.ipv6->addr),
                        param.ipv6->prefix_length);
                }
                if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
                    details::log_throw_last_system_error("ioctl");
                    return;
                }
                if (ioctl(fd, TUNGETIFF, &ifr) < 0) {
                    details::log_throw_last_system_error("ioctl");
                    return;
                }
                ifr.ifr_flags |= IFF_UP;

                ctl_skt = socket(AF_INET, SOCK_DGRAM, 0);
                if (ctl_skt == -1) {
                    details::log_throw_last_system_error("socket");
                    return;
                }

                if (ioctl(ctl_skt, SIOCSIFFLAGS, &ifr) < 0) {
                    details::log_throw_last_system_error("ioctl");
                    return;
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