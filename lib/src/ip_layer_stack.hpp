#pragma once
#include "tuntap.hpp"
#include "ip_packet.hpp"

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

            auto ip = ip_packet::ip::create_from_packet(buffer.data());
            if (!ip)
                continue;

            boost::asio::streambuf test_buffer; 
            ip.value().make_packet(test_buffer);

            /*bytes = co_await tuntap_.async_write_some(buffer.data(), net_awaitable[ec]);
            if (ec)
                co_return;*/
        }
    };

private:
    tuntap &tuntap_;
};