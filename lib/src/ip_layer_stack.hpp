#pragma once
#include "interface.hpp"
#include "ip_packet.hpp"
#include "route/route.hpp"
#include "tcp_packet.hpp"
#include "tcp_proxy.hpp"
#include "tuntap/tuntap.hpp"
#include "udp_packet.hpp"
#include "udp_proxy.hpp"
#include <queue>

class ip_layer_stack : public interface::tun2socks
{
public:
    explicit ip_layer_stack(boost::asio::io_context &ioc, tuntap::tuntap &_tuntap)
        : ioc_(ioc)
        , tuntap_(ioc)
    {}
    void start()
    {
        auto result = route::get_default_ipv4_route();

        SPDLOG_INFO("if_addr: {0}", result->if_addr.to_string());
        default_if_addr_ = result->if_addr;

        tuntap_.open();
        boost::asio::co_spawn(ioc_, receive_ip_packet(), boost::asio::detached);
    }

    boost::asio::awaitable<void> on_ip_packet(boost::asio::streambuf &&buffer)
    {
        auto ip_pack = network_layer::ip_packet::from_packet(buffer.data());
        if (!ip_pack)
            co_return;

        switch (ip_pack->next_protocol()) {
        case transport_layer::udp_packet::protocol:
            co_await on_udp_packet(*ip_pack);
            break;
        case transport_layer::tcp_packet::protocol:
            co_await on_tcp_packet(*ip_pack);
            break;
        default:
            break;
        }
    }
    boost::asio::awaitable<void> receive_ip_packet()
    {
        for (;;) {
            boost::system::error_code ec;
            boost::asio::streambuf buffer;
            auto bytes = co_await tuntap_.async_read_some(buffer.prepare(64 * 1024),
                                                          net_awaitable[ec]);
            if (ec)
                co_return;
            buffer.commit(bytes);
            //co_await start_ip_packet(std::move(buffer));
            boost::asio::co_spawn(ioc_, on_ip_packet(std::move(buffer)), boost::asio::detached);
        }
    };

    void close_endpoint_pair(const transport_layer::tcp_endpoint_pair &endpoint_pair) override
    {
        tcp_proxy_map_.erase(endpoint_pair);
    }
    void close_endpoint_pair(const transport_layer::udp_endpoint_pair &endpoint_pair) override
    {
        udp_proxy_map_.erase(endpoint_pair);
    }

    void write_tun_packet(const transport_layer::tcp_packet &pack) override
    {
        boost::asio::streambuf payload;
        pack.make_packet(payload);

        network_layer::ip_packet ip_pack(pack.endpoint_pair().to_address_pair(),
                                         transport_layer::tcp_packet::protocol,
                                         payload.data());
        write_ip_packet(ip_pack);
    }
    void write_tun_packet(const transport_layer::udp_packet &pack) override
    {
        boost::asio::streambuf payload;
        pack.make_packet(payload);

        network_layer::ip_packet ip_pack(pack.endpoint_pair().to_address_pair(),
                                         transport_layer::udp_packet::protocol,
                                         payload.data());
        write_ip_packet(ip_pack);
    }
    virtual boost::asio::awaitable<tcp_socket_ptr> create_proxy_socket(
        const transport_layer::tcp_endpoint_pair &endpoint_pair)
    {
        auto pid = local_port_pid::tcp_using_port(endpoint_pair.src.port());
        local_port_pid::PrintProcessInfo(pid);

        boost::system::error_code ec;

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
            co_await boost::asio::this_coro::executor);

        socket->open(boost::asio::ip::tcp::v4());
        socket->bind(boost::asio::ip::tcp::endpoint(default_if_addr_, 0), ec);
        if (ec) {
            SPDLOG_INFO("bind {0}", ec.message());
            co_return nullptr;
        }

        co_await socket->async_connect(endpoint_pair.dest, net_awaitable[ec]);

        if (ec) {
            SPDLOG_WARN("can't conect tcp endpoint [{0}]:{1}",
                        endpoint_pair.dest.address().to_string(),
                        endpoint_pair.dest.port());
            co_return nullptr;
        }
        /*proxy::socks_client_option op;
            op.target_host = local_endpoint_pair_.dest.address().to_string();
            op.target_port = local_endpoint_pair_.dest.port();
            op.proxy_hostname = false;

            boost::asio::ip::tcp::endpoint remote_endp;
            co_await proxy::async_socks_handshake(socket_, op, remote_endp, ec);
            if (ec) {
                tcp_packet::tcp_flags flags;
                flags.flag.rst = true;
                flags.flag.ack = true;
                write_packet(flags, server_seq_num_, seq_num + 1);

                do_close();
                co_return;
            }*/
        co_return socket;
    }
    boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        const transport_layer::udp_endpoint_pair &endpoint_pair,
        boost::asio::ip::udp::endpoint &proxy_endpoint) override
    {
        auto pid = local_port_pid::udp_using_port(endpoint_pair.src.port());
        local_port_pid::PrintProcessInfo(pid);

        boost::system::error_code ec;

        auto socket = std::make_shared<boost::asio::ip::udp::socket>(
            co_await boost::asio::this_coro::executor);

        socket->open(boost::asio::ip::udp::v4());
        socket->bind(boost::asio::ip::udp::endpoint(default_if_addr_, 0), ec);
        if (ec) {
            SPDLOG_INFO("bind {0}", ec.message());
            co_return nullptr;
        }
        proxy_endpoint = endpoint_pair.dest;
        co_return socket;
    }
    void write_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        auto buffer = std::make_unique<boost::asio::streambuf>();
        ip_pack.make_packet(*buffer);

        bool write_in_process = !write_tun_deque_.empty();
        write_tun_deque_.push_back(std::move(buffer));
        if (write_in_process)
            return;

        boost::asio::co_spawn(ioc_, write_tuntap_packet(), boost::asio::detached);
    }

private:
    boost::asio::awaitable<void> write_tuntap_packet()
    {
        while (!write_tun_deque_.empty()) {
            const auto &buffer = write_tun_deque_.front();
            boost::system::error_code ec;
            auto bytes = co_await tuntap_.async_write_some(buffer->data(), net_awaitable[ec]);
            if (ec) {
                SPDLOG_WARN("Write IP Packet to tuntap Device Failed: {0}", ec.message());
                break;
            }
            if (bytes == 0) {
                boost::asio::steady_timer try_again_timer(co_await boost::asio::this_coro::executor);
                try_again_timer.expires_from_now(std::chrono::milliseconds(64));
                co_await try_again_timer.async_wait(net_awaitable[ec]);
                if (ec)
                    break;
                continue;
            }
            write_tun_deque_.pop_front();
        }
        co_return;
    }
    boost::asio::awaitable<void> on_udp_packet(const network_layer::ip_packet &ip_pack)
    {
        auto udp_pack = transport_layer::udp_packet::from_ip_packet(ip_pack);
        if (!udp_pack)
            co_return;

        auto endpoint_pair = udp_pack->endpoint_pair();
        auto proxy = udp_proxy_map_[endpoint_pair];
        if (!proxy) {
            proxy = std::make_shared<udp_proxy>(ioc_, endpoint_pair, *this);
            udp_proxy_map_[endpoint_pair] = proxy;
        }
        co_await proxy->on_udp_packet(*udp_pack);
    }
    boost::asio::awaitable<void> on_tcp_packet(const network_layer::ip_packet &ip_pack)
    {
        auto tcp_pack = transport_layer::tcp_packet::from_ip_packet(ip_pack);
        if (!tcp_pack)
            co_return;

        auto endpoint_pair = tcp_pack->endpoint_pair();

        auto proxy = tcp_proxy_map_[endpoint_pair];
        if (!proxy) {
            proxy = std::make_shared<transport_layer::tcp_proxy>(ioc_, endpoint_pair, *this);
            tcp_proxy_map_[endpoint_pair] = proxy;
        }
        co_await proxy->on_tcp_packet(*tcp_pack);
    }

private:
    boost::asio::io_context &ioc_;
    tuntap::tuntap tuntap_;

    boost::asio::ip::address default_if_addr_;

    std::deque<std::unique_ptr<boost::asio::streambuf>> write_tun_deque_;

    std::unordered_map<transport_layer::tcp_endpoint_pair, transport_layer::tcp_proxy::ptr>
        tcp_proxy_map_;
    std::unordered_map<transport_layer::udp_endpoint_pair, udp_proxy::ptr> udp_proxy_map_;
};