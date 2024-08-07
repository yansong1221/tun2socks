#pragma once
#include "interface.hpp"
#include "lwip.hpp"
#include "process_info/process_info.hpp"
#include "proxy_policy.hpp"
#include "route/route.hpp"
#include "tcp_proxy.hpp"
#include "tuntap/tuntap.hpp"
#include "udp_proxy.hpp"
#include <queue>

class tun2socks_impl : public abstract::tun2socks {
public:
    struct socks5_proxy_info
    {
        std::string username;
        std::string password;
        std::string host;
        uint16_t    port = 0;
    };

public:
    explicit tun2socks_impl()
        : tuntap_(ioc_)
    {
    }
    void start(const tuntap::tun_parameter& tun_param,
               const socks5_proxy_info&     proxy_info)
    {
        boost::system::error_code ec;
        tuntap_.open(tun_param, ec);
        boost::asio::detail::throw_error(ec);

        socks5_proxy_ = proxy_info;

        auto ipv4_route = route::get_default_ipv4_route();
        auto ipv6_route = route::get_default_ipv6_route();

        if (ipv4_route)
            default_if_addr_v4_ = ipv4_route->if_addr;
        if (ipv6_route)
            default_if_addr_v6_ = ipv6_route->if_addr;

        spdlog::info("Default network interface v4: {0}", default_if_addr_v4_.to_string());
        spdlog::info("Default network interface v6: {0}", default_if_addr_v6_.to_string());

        if (tun_param.ipv4) {
            route::route_ipv4 info;
            info.if_addr = tun_param.ipv4->addr.to_v4();
            info.metric  = 0;
            info.netmask = boost::asio::ip::address_v4::any();
            info.network = boost::asio::ip::address_v4::any();
            route::add_route_ipapi(info);
        }
        if (tun_param.ipv6) {
            route::route_ipv6 info;
            info.if_addr       = tun_param.ipv6->addr.to_v6();
            info.metric        = 1;
            info.dest          = boost::asio::ip::address_v6::any();
            info.prefix_length = 0;
            route::add_route_ipapi(info);
        }
        proxy_policy_.add_proxy_process(R"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe)");

        lwip::instance().init(ioc_);
        auto t_pcb = lwip::tcp_listen_any();
        auto u_pcb = lwip::udp_listen_any();

        lwip::lwip_tcp_accept(t_pcb,
                              std::bind(&tun2socks_impl::on_tcp_accept,
                                        this,
                                        std::placeholders::_1,
                                        std::placeholders::_2,
                                        std::placeholders::_3));
        lwip::lwip_udp_create(
            std::bind(&tun2socks_impl::on_udp_create, this, std::placeholders::_1));

        lwip::instance().lwip_ip_output(std::bind(&tun2socks_impl::on_ip_output,
                                                  this,
                                                  std::placeholders::_1,
                                                  std::placeholders::_2));

        boost::asio::co_spawn(ioc_, read_tun_ip_packet(), boost::asio::detached);
        ioc_.run();
    }

private:
    void on_udp_create(struct udp_pcb* newpcb)
    {
        // Ports are always in host byte order.
        auto src_port  = newpcb->remote_port;
        auto dest_port = newpcb->local_port;
        auto addr_pair = create_address_pair(newpcb->local_ip,
                                             newpcb->remote_ip);

        transport_layer::udp_endpoint_pair endpoint_pair(addr_pair,
                                                         src_port,
                                                         dest_port);

        auto proxy = std::make_shared<udp_proxy>(ioc_,
                                                 endpoint_pair,
                                                 newpcb,
                                                 *this);
        proxy->start();
    }
    err_t on_ip_output(struct netif* netif, struct pbuf* p)
    {
        auto buffer           = toys::wrapper::pbuf_buffer::smart_copy(p);
        bool write_in_process = !send_queue_.empty();
        send_queue_.push(buffer);
        if (write_in_process)
            return ERR_OK;

        boost::asio::co_spawn(
            ioc_,
            [this]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                boost::asio::steady_timer try_again_timer(
                    co_await boost::asio::this_coro::executor);
                while (!send_queue_.empty()) {
                    const auto& buffer = send_queue_.front();
                    auto        bytes  = co_await tuntap_.async_write_some(buffer.data(), ec);
                    if (ec) {
                        spdlog::warn("Write IP Packet to tuntap Device Failed: {0}", ec.message());
                        co_return;
                    }
                    if (bytes == 0) {
                        try_again_timer.expires_from_now(std::chrono::milliseconds(64));
                        co_await try_again_timer.async_wait(net_awaitable[ec]);
                        if (ec)
                            break;
                        continue;
                    }
                    send_queue_.pop();
                }
            },
            boost::asio::detached);

        return ERR_OK;
    }

    inline static network_layer::address_pair_type create_address_pair(const ip_addr_t& local_ip,
                                                                       const ip_addr_t& remote_ip)
    {
        if (local_ip.type == IPADDR_TYPE_V4) {
            // IP addresses are always in network order.
            boost::asio::ip::address_v4 dest_ip(
                boost::asio::detail::socket_ops::network_to_host_long(local_ip.u_addr.ip4.addr));
            boost::asio::ip::address_v4 src_ip(
                boost::asio::detail::socket_ops::network_to_host_long(remote_ip.u_addr.ip4.addr));

            return network_layer::address_pair_type(src_ip, dest_ip);
        }
        else {
            // IP addresses are always in network order.
            boost::asio::ip::address_v6::bytes_type dest_ip;
            boost::asio::ip::address_v6::bytes_type src_ip;

            memcpy(dest_ip.data(), local_ip.u_addr.ip6.addr, 16);
            memcpy(src_ip.data(), remote_ip.u_addr.ip6.addr, 16);

            return network_layer::address_pair_type(src_ip, dest_ip);
        }
    }
    err_t on_tcp_accept(void* arg, struct tcp_pcb* newpcb, err_t err)
    {
        if (err != ERR_OK || newpcb == NULL)
            return ERR_VAL;

        // Ports are always in host byte order.
        auto src_port  = newpcb->remote_port;
        auto dest_port = newpcb->local_port;

        transport_layer::tcp_endpoint_pair endpoint_pair(create_address_pair(newpcb->local_ip,
                                                                             newpcb->remote_ip),
                                                         src_port,
                                                         dest_port);

        auto proxy = std::make_shared<tcp_proxy>(ioc_,
                                                 newpcb,
                                                 endpoint_pair,
                                                 *this);
        proxy->start();
        return ERR_OK;
    }

    boost::asio::awaitable<void> read_tun_ip_packet()
    {
        for (;;) {
            boost::system::error_code  ec;
            toys::wrapper::pbuf_buffer buffer(65532);

            auto bytes = co_await tuntap_.async_read_some(buffer.data(), ec);
            if (ec)
                co_return;

            buffer.realloc(bytes);
            pbuf_ref(&buffer);
            lwip::instance().lwip_ip_input(&buffer);
        }
    };

    boost::asio::awaitable<tcp_socket_ptr> create_proxy_socket(
        const transport_layer::tcp_endpoint_pair& endpoint_pair) override
    {
        spdlog::info("TCP proxy: {}", endpoint_pair.to_string());

        auto port_info = process_info::get_process_info(endpoint_pair.src.port());

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
            co_await boost::asio::this_coro::executor);

        if (proxy_policy_.is_direct(endpoint_pair)) {
            boost::system::error_code ec;
            open_bind_socket(*socket, endpoint_pair.dest, ec);
            if (ec)
                co_return nullptr;

            co_await socket->async_connect(endpoint_pair.dest, net_awaitable[ec]);
            if (ec) {
                spdlog::warn("Failed to connect to remote TCP endpoint [{0}]:{1}",
                             endpoint_pair.dest.address().to_string(),
                             endpoint_pair.dest.port());
                co_return nullptr;
            }
        }
        else {
            boost::system::error_code ec;

            boost::asio::ip::tcp::endpoint remote_endp;
            co_await connect_socks5_server(*socket, endpoint_pair.dest, remote_endp, ec);
            if (ec)
                co_return nullptr;
        }
        co_return socket;
    }
    boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        const transport_layer::udp_endpoint_pair& endpoint_pair,
        boost::asio::ip::udp::endpoint&           proxy_endpoint) override
    {
        spdlog::info("UDP proxy: {}", endpoint_pair.to_string());

        auto port_info = process_info::get_process_info(endpoint_pair.src.port());

        if (endpoint_pair.dest.protocol() == boost::asio::ip::udp::v6())
            co_return nullptr;

        auto socket = std::make_shared<boost::asio::ip::udp::socket>(
            co_await boost::asio::this_coro::executor);

        if (proxy_policy_.is_direct(endpoint_pair)) {
            boost::system::error_code ec;
            open_bind_socket(*socket, endpoint_pair.dest, ec);
            if (ec)
                co_return nullptr;
            proxy_endpoint = endpoint_pair.dest;
        }
        else {
            boost::asio::ip::tcp::socket proxy_sock(co_await boost::asio::this_coro::executor);

            boost::system::error_code      ec;
            boost::asio::ip::udp::endpoint remote_endp;
            co_await connect_socks5_server(proxy_sock, endpoint_pair.dest, remote_endp, ec);
            if (ec)
                co_return nullptr;

            proxy_endpoint = remote_endp;
        }
        co_return socket;
    }

private:
    template <typename Stream, typename InternetProtocol>
    inline void open_bind_socket(Stream&                                                  sock,
                                 const boost::asio::ip::basic_endpoint<InternetProtocol>& dest,
                                 boost::system::error_code&                               ec)
    {
        sock.open(dest.protocol());
        if (dest.protocol() == InternetProtocol::v4())
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_if_addr_v4_, 0), ec);
        else
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_if_addr_v6_, 0), ec);
        if (ec)
            spdlog::error("bind {0}", ec.message());
    }
    template <typename Stream, typename InternetProtocol>
    inline boost::asio::awaitable<void> connect_socks5_server(
        Stream&                                                  sock,
        const boost::asio::ip::basic_endpoint<InternetProtocol>& target_endp,
        boost::asio::ip::basic_endpoint<InternetProtocol>&       remote_endp,
        boost::system::error_code&                               ec)
    {
        if (!socks5_proxy_) {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
            co_return;
        }

        auto endp = boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(socks5_proxy_->host,
                                                                                 ec),
                                                   socks5_proxy_->port);
        if (ec) {
            auto error = ec;
            ec.clear();

            auto                           executor = co_await boost::asio::this_coro::executor;
            boost::asio::ip::tcp::resolver resolver(executor);

            auto target_endpoints = co_await resolver.async_resolve(socks5_proxy_->host,
                                                                    std::to_string(
                                                                        socks5_proxy_->port),
                                                                    net_awaitable[ec]);
            if (ec)
                co_return;

            if (target_endpoints.empty()) {
                ec = error;
                co_return;
            }
            endp = *target_endpoints.begin();
        }

        open_bind_socket(sock, endp, ec);
        if (ec)
            co_return;

        co_await sock.async_connect(endp, net_awaitable[ec]);

        if (ec) {
            spdlog::warn("can't connect socks5 server [{0}]:{1} message:{2}",
                         socks5_proxy_->host,
                         socks5_proxy_->port,
                         ec.message());
            co_return;
        }

        proxy::socks_client_option op;
        op.target_host    = target_endp.address().to_string();
        op.target_port    = target_endp.port();
        op.username       = socks5_proxy_->username;
        op.password       = socks5_proxy_->password;
        op.proxy_hostname = false;

        co_await proxy::async_socks_handshake(sock, op, remote_endp, ec);
        if (ec) {
            spdlog::warn("Handshake with remote server failed [{0}]:{1} message:{2}",
                         socks5_proxy_->host,
                         socks5_proxy_->port,
                         ec.message());
            co_return;
        }
        spdlog::info("Successfully connected to remote socks server [{0}]:{1}", socks5_proxy_->host, socks5_proxy_->port);
    }

private:
    boost::asio::io_context ioc_;

    tuntap::tuntap tuntap_;

    boost::asio::ip::address_v4 default_if_addr_v4_;
    boost::asio::ip::address_v6 default_if_addr_v6_;

    std::optional<socks5_proxy_info> socks5_proxy_;

    std::queue<toys::wrapper::pbuf_buffer> send_queue_;

    proxy_policy proxy_policy_;
};