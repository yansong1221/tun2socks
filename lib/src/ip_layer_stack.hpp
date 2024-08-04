#pragma once
#include "interface.hpp"
#include "io_context_pool.hpp"
#include "ip_packet.hpp"
#include "lwipstack.h"
#include "process_info/process_info.hpp"
#include "route/route.hpp"
#include "tcp_packet.hpp"
#include "tcp_proxy_ex.hpp"
#include "tuntap/tuntap.hpp"
#include "udp_packet.hpp"
#include "udp_proxy.hpp"
#include <queue>

class ip_layer_stack : public abstract::tun2socks
{
public:
    explicit ip_layer_stack()
        : tuntap_(pool_.getIOContext())
        , ioc_(pool_.getIOContext())
    {}
    void start()
    {
        tuntap::tun_parameter param;
        param.tun_name = "mate";

        tuntap::tun_parameter::address tun_ipv4;
        tun_ipv4.addr = boost::asio::ip::address_v4::from_string("10.6.7.7");
        tun_ipv4.dns = boost::asio::ip::address_v4::from_string("114.114.114.114");
        tun_ipv4.prefix_length = 24;
        param.ipv4 = tun_ipv4;

        tuntap::tun_parameter::address tun_ipv6;
        tun_ipv6.addr = boost::asio::ip::address_v6::from_string("fe80::613b:4e3f:81e9:7e01");
        tun_ipv6.dns = boost::asio::ip::address_v6::from_string("2606:4700:4700::1111");
        tun_ipv6.prefix_length = 64;
        param.ipv6 = tun_ipv6;

        tuntap_.open(param);

        auto ipv4_route = route::get_default_ipv4_route();
        auto ipv6_route = route::get_default_ipv6_route();

        if (ipv4_route)
            default_if_addr_v4_ = ipv4_route->if_addr;
        if (ipv6_route)
            default_if_addr_v6_ = ipv6_route->if_addr;

        spdlog::info("默认网络出口v4: {0}", default_if_addr_v4_.to_string());
        spdlog::info("默认网络出口v6: {0}", default_if_addr_v6_.to_string());

        {
            route::route_ipv4 info;
            info.if_addr = tun_ipv4.addr.to_v4();
            info.metric = 0;
            info.netmask = boost::asio::ip::address_v4::any();
            info.network = boost::asio::ip::address_v4::any();
            route::add_route_ipapi(info);
        }
        {
            route::route_ipv6 info;
            info.if_addr = tun_ipv6.addr.to_v6();
            info.metric = 1;
            info.dest = boost::asio::ip::address_v6::any();
            info.prefix_length = 0;
            route::add_route_ipapi(info);
        }

        LWIPStack::getInstance().init(ioc_);
        auto t_pcb = LWIPStack::tcp_listen_any();
        auto u_pcb = LWIPStack::udp_listen_any();

        LWIPStack::lwip_tcp_arg(t_pcb, this);

        LWIPStack::lwip_tcp_accept(t_pcb, [](void *arg, struct tcp_pcb *newpcb, err_t err) -> err_t {
            if (err != ERR_OK || newpcb == NULL)
                return ERR_VAL;

            auto self = (ip_layer_stack *) arg;
            return self->on_tcp_accept(newpcb);
        });

        LWIPStack::getInstance().set_output_function(
            [this](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) -> err_t {
                buffer::ref_buffer buffer;
                auto buf = buffer.prepare(p->tot_len);
                pbuf_copy_partial(p, buf.data(), p->tot_len, 0);
                buffer.commit(p->tot_len);
                tuntap_.write_packet(buffer);
                return ERR_OK;
            });

        boost::asio::co_spawn(tuntap_.get_io_context(), receive_ip_packet(), boost::asio::detached);

        pool_.Start();
        pool_.Wait();
    }

    err_t on_tcp_accept(struct tcp_pcb *newpcb)
    {
        // Ports are always in host byte order.
        auto src_port = newpcb->remote_port;
        auto dest_port = newpcb->local_port;

        network_layer::address_pair_type addr_pair;

        if (newpcb->local_ip.type == IPADDR_TYPE_V4) {
            // IP addresses are always in network order.
            boost::asio::ip::address_v4 dest_ip(
                boost::asio::detail::socket_ops::network_to_host_long(
                    newpcb->local_ip.u_addr.ip4.addr));
            boost::asio::ip::address_v4 src_ip(boost::asio::detail::socket_ops::network_to_host_long(
                newpcb->remote_ip.u_addr.ip4.addr));

            addr_pair = network_layer::address_pair_type(src_ip, dest_ip);

        } else {
            // IP addresses are always in network order.
            boost::asio::ip::address_v6::bytes_type dest_ip;
            boost::asio::ip::address_v6::bytes_type src_ip;

            memcpy(dest_ip.data(), newpcb->local_ip.u_addr.ip6.addr, 16);
            memcpy(src_ip.data(), newpcb->remote_ip.u_addr.ip6.addr, 16);

            addr_pair = network_layer::address_pair_type(src_ip, dest_ip);
        }

        transport_layer::tcp_endpoint_pair endpoint_pair(addr_pair, src_port, dest_port);

        auto proxy = std::make_shared<transport_layer::tcp_proxy>(pool_.getIOContext(),
                                                                  newpcb,
                                                                  endpoint_pair,
                                                                  *this);
        tcp_proxy_map_[endpoint_pair] = proxy;

        proxy->start();
        return ERR_OK;
    }

    boost::asio::awaitable<void> receive_ip_packet()
    {
        for (;;) {
            boost::system::error_code ec;
            auto buffer = co_await tuntap_.read_packet(ec);
            if (ec)
                co_return;

            auto p = pbuf_alloc(pbuf_layer::PBUF_RAW, buffer.size(), pbuf_type::PBUF_REF);
            p->payload = (void *) buffer.data().data();

            LWIPStack::getInstance().strand_ip_input(p, [buffer](err_t err) {});
        }
    };

    void close_endpoint_pair(const transport_layer::tcp_endpoint_pair &endpoint_pair) override
    {
        boost::asio::co_spawn(
            ioc_,
            [this, endpoint_pair]() -> boost::asio::awaitable<void> {
                tcp_proxy_map_.erase(endpoint_pair);
                co_return;
            },
            boost::asio::detached);
    }
    void close_endpoint_pair(const transport_layer::udp_endpoint_pair &endpoint_pair) override
    {
        boost::asio::co_spawn(
            ioc_,
            [this, endpoint_pair]() -> boost::asio::awaitable<void> {
                udp_proxy_map_.erase(endpoint_pair);
                co_return;
            },
            boost::asio::detached);
    }
    void write_tun_packet(const buffer::ref_const_buffer &buffers) override
    {
        tuntap_.write_packet(buffers);
    }
    void write_tun_packet(const transport_layer::tcp_packet &pack) override
    {
        boost::asio::co_spawn(
            ioc_,
            [this, pack]() -> boost::asio::awaitable<void> {
                buffer::ref_buffer buffers;

                auto ip_header_len = network_layer::ip_packet::make_ip_header_packet_len(
                    pack.endpoint_pair().to_address_pair());
                auto tcp_header_len = transport_layer::tcp_packet::make_tcp_header_packet_len();
                auto tcp_payload_len = pack.payload().size();
                auto total_len = ip_header_len + tcp_header_len + tcp_payload_len;

                auto p = buffers.prepare(total_len);

                network_layer::ip_packet::make_ip_header_packet(p,
                                                                pack.endpoint_pair()
                                                                    .to_address_pair(),
                                                                transport_layer::tcp_packet::protocol,
                                                                tcp_header_len + tcp_payload_len);
                p += ip_header_len;

                transport_layer::tcp_packet::make_ip_header_packet(p,
                                                                   pack.endpoint_pair(),
                                                                   pack.header_data(),
                                                                   pack.payload());
                p += tcp_header_len;

                boost::asio::buffer_copy(p, pack.payload());

                buffers.commit(total_len);

                tuntap_.write_packet(buffers);
                co_return;
            },
            boost::asio::detached);
    }
    void write_tun_packet(const transport_layer::udp_packet &pack) override
    {
        boost::asio::co_spawn(
            ioc_,
            [this, pack]() -> boost::asio::awaitable<void> {
                buffer::ref_buffer payload;
                pack.make_packet(payload.prepare(pack.raw_packet_size()));
                payload.commit(pack.raw_packet_size());

                network_layer::ip_packet ip_pack(pack.endpoint_pair().to_address_pair(),
                                                 transport_layer::udp_packet::protocol,
                                                 payload);
                write_ip_packet(ip_pack);
                co_return;
            },
            boost::asio::detached);
    }
    boost::asio::awaitable<tcp_socket_ptr> create_proxy_socket(
        const transport_layer::tcp_endpoint_pair &endpoint_pair) override
    {
        spdlog::info("tcp proxy: {}", endpoint_pair.to_string());

        auto port_info = process_info::get_process_info(endpoint_pair.src.port());

        boost::system::error_code ec;

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
            co_await boost::asio::this_coro::executor);

        if (true) {
            open_bind_socket(*socket, endpoint_pair.dest, ec);
            if (ec)
                co_return nullptr;

            co_await socket->async_connect(endpoint_pair.dest, net_awaitable[ec]);
            if (ec) {
                spdlog::warn("can't connect remote endpoint [{0}]:{1}",
                             endpoint_pair.dest.address().to_string(),
                             endpoint_pair.dest.port());
                co_return nullptr;
            }

        } else {
            open_bind_socket(*socket, socks5_endpoint_, ec);
            if (ec)
                co_return nullptr;

            co_await socket->async_connect(socks5_endpoint_, net_awaitable[ec]);

            if (ec) {
                spdlog::warn("can't connect socks5 server [{0}]:{1}",
                             socks5_endpoint_.address().to_string(),
                             socks5_endpoint_.port());
                co_return nullptr;
            }
            proxy::socks_client_option op;
            op.target_host = endpoint_pair.dest.address().to_string();
            op.target_port = endpoint_pair.dest.port();
            op.proxy_hostname = false;

            boost::asio::ip::tcp::endpoint remote_endp;
            co_await proxy::async_socks_handshake(*socket, op, remote_endp, ec);
            if (ec) {
                spdlog::warn("can't connect socks5 server [{0}]:{1}",
                             socks5_endpoint_.address().to_string(),
                             socks5_endpoint_.port());
                co_return nullptr;
            }
        }
        co_return socket;
    }
    boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        const transport_layer::udp_endpoint_pair &endpoint_pair,
        boost::asio::ip::udp::endpoint &proxy_endpoint) override
    {
        spdlog::info("udp proxy: {}", endpoint_pair.to_string());

        auto port_info = process_info::get_process_info(endpoint_pair.src.port());

        if (endpoint_pair.dest.protocol() == boost::asio::ip::udp::v6())
            co_return nullptr;

        boost::system::error_code ec;

        auto socket = std::make_shared<boost::asio::ip::udp::socket>(
            co_await boost::asio::this_coro::executor);

        if (true) {
            open_bind_socket(*socket, endpoint_pair.dest, ec);
            if (ec)
                co_return nullptr;
            proxy_endpoint = endpoint_pair.dest;
        } else {
            boost::asio::ip::tcp::socket proxy_sock(co_await boost::asio::this_coro::executor);
            open_bind_socket(proxy_sock, socks5_endpoint_, ec);
            if (ec)
                co_return nullptr;

            co_await proxy_sock.async_connect(socks5_endpoint_, net_awaitable[ec]);

            if (ec) {
                spdlog::warn("can't connect socks5 server [{0}]:{1}",
                             socks5_endpoint_.address().to_string(),
                             socks5_endpoint_.port());
                co_return nullptr;
            }
            proxy::socks_client_option op;
            op.target_host = endpoint_pair.dest.address().to_string();
            op.target_port = endpoint_pair.dest.port();
            op.proxy_hostname = false;

            boost::asio::ip::udp::endpoint remote_endp;
            co_await proxy::async_socks_handshake(proxy_sock, op, remote_endp, ec);
            if (ec) {
                spdlog::warn("can't connect socks5 server [{0}]:{1}",
                             socks5_endpoint_.address().to_string(),
                             socks5_endpoint_.port());
                co_return nullptr;
            }
            open_bind_socket(*socket, proxy_endpoint, ec);
            if (ec)
                co_return nullptr;

            proxy_endpoint = remote_endp;
        }
        co_return socket;
    }
    void write_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        buffer::ref_buffer buffer;
        ip_pack.make_packet(buffer.prepare(ip_pack.raw_packet_size()));
        buffer.commit(ip_pack.raw_packet_size());

        tuntap_.write_packet(buffer);
    }

private:
    template<typename Stream, typename InternetProtocol>
    inline void open_bind_socket(Stream &sock,
                                 const boost::asio::ip::basic_endpoint<InternetProtocol> &dest,
                                 boost::system::error_code &ec)
    {
        sock.open(dest.protocol());
        if (dest.protocol() == InternetProtocol::v4())
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_if_addr_v4_, 0), ec);
        else
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_if_addr_v6_, 0), ec);
        if (ec)
            spdlog::error("bind {0}", ec.message());
    }
    void on_udp_packet(const network_layer::ip_packet &ip_pack)
    {
        auto udp_pack = transport_layer::udp_packet::from_ip_packet(ip_pack);
        if (!udp_pack)
            return;

        auto endpoint_pair = udp_pack->endpoint_pair();
        auto proxy = udp_proxy_map_[endpoint_pair];
        if (!proxy) {
            proxy = std::make_shared<udp_proxy>(pool_.getIOContext(), endpoint_pair, *this);
            proxy->start();
            udp_proxy_map_[endpoint_pair] = proxy;
        }
        proxy->on_udp_packet(*udp_pack);
    }
    //void on_tcp_packet(const network_layer::ip_packet &ip_pack)
    //{
    //    auto tcp_pack = transport_layer::tcp_packet::from_ip_packet(ip_pack);
    //    if (!tcp_pack)
    //        return;

    //    auto endpoint_pair = tcp_pack->endpoint_pair();

    //    auto proxy = tcp_proxy_map_[endpoint_pair];
    //    if (!proxy) {
    //        proxy = std::make_shared<transport_layer::tcp_proxy>(pool_.getIOContext(),
    //                                                             endpoint_pair,
    //                                                             *this);
    //        tcp_proxy_map_[endpoint_pair] = proxy;
    //    }
    //    proxy->on_tcp_packet(*tcp_pack);
    //}

private:
    toys::pool::IOContextPool<1, 1> pool_;
    boost::asio::io_context &ioc_;

    tuntap::tuntap tuntap_;

    boost::asio::ip::address_v4 default_if_addr_v4_;
    boost::asio::ip::address_v6 default_if_addr_v6_;

    boost::asio::ip::tcp::endpoint socks5_endpoint_;

    std::unordered_map<transport_layer::tcp_endpoint_pair, transport_layer::tcp_proxy::ptr>
        tcp_proxy_map_;
    std::unordered_map<transport_layer::udp_endpoint_pair, udp_proxy::ptr> udp_proxy_map_;
};