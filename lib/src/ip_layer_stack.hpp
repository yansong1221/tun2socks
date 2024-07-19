#pragma once
#include "ip_packet.hpp"
#include "tuntap.hpp"
#include "udp_packet.hpp"

class ip_layer_stack
{
public:
    explicit ip_layer_stack(tuntap &_tuntap)
        : tuntap_(_tuntap)
    {}
    void start()
    {
        boost::asio::co_spawn(tuntap_.get_executor(), receive_ip_packet(), boost::asio::detached);
    }
    boost::asio::awaitable<void> start_ip_packet(boost::asio::streambuf &&buffer)
    {
        auto result = network_layer::ip_packet::from_packet(buffer.data());
        if (!result)
            co_return;

        auto ip_pack = result.value();
        switch (ip_pack.next_protocol()) {
        case transport_layer::udp_packet::protocol_type: {
            auto result = transport_layer::udp_packet::from_ip_packet(ip_pack);
            if (!result)
                break;

            auto udp_pack = result.value();

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
            boost::asio::co_spawn(tuntap_.get_executor(),
                                  start_ip_packet(std::move(buffer)),
                                  boost::asio::detached);
        }
    };

private:
    tuntap &tuntap_;
};