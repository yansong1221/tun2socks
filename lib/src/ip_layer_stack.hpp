#pragma once
#include "ip_packet.hpp"
#include "tcp_packet.hpp"
#include "tcp_proxy.hpp"
#include "tuntap.hpp"
#include "udp_packet.hpp"
#include "udp_proxy.hpp"

class ip_layer_stack
{
public:
    explicit ip_layer_stack(boost::asio::io_context &ioc, tuntap::tuntap &_tuntap)
        : ioc_(ioc)
        , tuntap_(_tuntap)
    {}
    void start() { boost::asio::co_spawn(ioc_, receive_ip_packet(), boost::asio::detached); }

    boost::asio::awaitable<void> start_ip_packet(boost::asio::streambuf &&buffer)
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
            boost::asio::co_spawn(ioc_, start_ip_packet(std::move(buffer)), boost::asio::detached);
        }
    };

    void close_tcp_proxy(const transport_layer::tcp_endpoint_pair &endpoint_pair)
    {
        tcp_proxy_map_.erase(endpoint_pair);
    }
    void close_udp_proxy(const transport_layer::udp_endpoint_pair &endpoint_pair)
    {
        udp_proxy_map_.erase(endpoint_pair);
    }

private:
    boost::asio::awaitable<void> on_udp_packet(const network_layer::ip_packet &ip_pack)
    {
        auto udp_pack = transport_layer::udp_packet::from_ip_packet(ip_pack);
        if (!udp_pack)
            co_return;

        auto endpoint_pair = udp_pack->endpoint_pair();
        auto proxy = udp_proxy_map_[endpoint_pair];
        if (!proxy) {
            proxy = std::make_shared<udp_proxy>(ioc_,
                                                tuntap_,
                                                endpoint_pair,
                                                std::bind(&ip_layer_stack::close_udp_proxy,
                                                          this,
                                                          std::placeholders::_1));
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
            proxy = std::make_shared<transport_layer::tcp_proxy>(
                ioc_,
                tuntap_,
                endpoint_pair,
                std::bind(&ip_layer_stack::close_tcp_proxy, this, std::placeholders::_1));
            tcp_proxy_map_[endpoint_pair] = proxy;
        }
        co_await proxy->on_tcp_packet(*tcp_pack);
    }

private:
    boost::asio::io_context &ioc_;

    tuntap::tuntap &tuntap_;
    std::unordered_map<transport_layer::tcp_endpoint_pair, transport_layer::tcp_proxy::ptr>
        tcp_proxy_map_;
    std::unordered_map<transport_layer::udp_endpoint_pair, udp_proxy::ptr> udp_proxy_map_;
};