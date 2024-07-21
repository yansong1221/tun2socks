#pragma once
#include "ip_packet.hpp"
#include "tcp_packet.hpp"
#include "tcp_stream.hpp"
#include "tuntap.hpp"
#include "udp_packet.hpp"

class ip_layer_stack
{
public:
    explicit ip_layer_stack(tuntap::tuntap &_tuntap)
        : tuntap_(_tuntap)
    {}
    void start()
    {
        boost::asio::co_spawn(tuntap_.get_executor(), receive_ip_packet(), boost::asio::detached);
    }
    boost::asio::awaitable<void> start_ip_packet(boost::asio::streambuf &&buffer)
    {
        auto ip_pack = network_layer::ip_packet::from_packet(buffer.data());
        if (!ip_pack)
            co_return;

        switch (ip_pack->next_protocol()) {
        case transport_layer::udp_packet::protocol_type: {
            auto udp_pack = transport_layer::udp_packet::from_ip_packet(*ip_pack);
            if (!udp_pack)
                break;

        } break;
        case transport_layer::tcp_packet::protocol_type: {
            auto tcp_pack = transport_layer::tcp_packet::from_ip_packet(*ip_pack);
            if (!tcp_pack)
                break;

            auto endpoint_pair = tcp_pack->endpoint_pair();

            transport_layer::tcp_stream::ptr tcp_stream = tcp_stream_map_[endpoint_pair];
            if (!tcp_stream) {
                tcp_stream = std::make_shared<transport_layer::tcp_stream>(tuntap_,
                                                                           tcp_pack->endpoint_pair());
                tcp_stream_map_[endpoint_pair] = tcp_stream;
            }
            co_await tcp_stream->on_tcp_packet(*tcp_pack);
            if (tcp_stream->closed())
                tcp_stream_map_.erase(endpoint_pair);

        } break;
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
            boost::asio::co_spawn(tuntap_.get_executor(),
                                  start_ip_packet(std::move(buffer)),
                                  boost::asio::detached);
        }
    };

private:
    tuntap::tuntap &tuntap_;
    std::unordered_map<transport_layer::tcp_endpoint_pair, transport_layer::tcp_stream::ptr>
        tcp_stream_map_;
};