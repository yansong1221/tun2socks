#pragma once
#include "tuntap.hpp"
#include "udp_packet.hpp"
#include <boost/asio.hpp>

class udp_proxy : public std::enable_shared_from_this<udp_proxy>
{
public:
    using ptr = std::shared_ptr<udp_proxy>;

    explicit udp_proxy(boost::asio::io_context &ioc,
                       tuntap::tuntap &tuntap,
                       const transport_layer::udp_endpoint_pair &endpoint_pair)
        : ioc_(ioc)
        , tuntap_(tuntap)
        , socket_(ioc)
        , udp_timeout_timer_(ioc)
        , local_endpoint_pair_(endpoint_pair)
        , remote_endpoint_pair_(endpoint_pair.swap())
    {
        boost::asio::co_spawn(ioc_, co_read_data(), boost::asio::detached);
    }

public:
    boost::asio::awaitable<void> on_udp_packet(const transport_layer::udp_packet &pack)
    {
        reset_timeout_timer();
        boost::system::error_code ec;
        co_await socket_.async_send_to(pack.payload(), local_endpoint_pair_.dest, net_awaitable[ec]);
    }

private:
    boost::asio::awaitable<void> co_reset_timeout_timer()
    {
        boost::system::error_code ec;
        udp_timeout_timer_.expires_from_now(udp_timeout_seconds_);
        co_await udp_timeout_timer_.async_wait(net_awaitable[ec]);
        if (ec)
            co_return;

        socket_.close(ec);
    }
    void reset_timeout_timer()
    {
        boost::system::error_code ec;
        udp_timeout_timer_.cancel(ec);
        boost::asio::co_spawn(ioc_, co_reset_timeout_timer(), boost::asio::detached);
    }
    boost::asio::awaitable<void> co_read_data()
    {
        boost::asio::streambuf read_buffer;

        for (;;) {
            reset_timeout_timer();

            boost::system::error_code ec;
            auto bytes = co_await socket_.async_receive_from(read_buffer.prepare(0x0FFF),
                                                             local_endpoint_pair_.dest,
                                                             net_awaitable[ec]);
            if (ec)
                co_return;

            read_buffer.commit(bytes);
            co_await write_packet(read_buffer.data());
            read_buffer.consume(bytes);
        }
    }
    boost::asio::awaitable<void> write_packet(const boost::asio::const_buffer &buffer)
    {
        boost::asio::streambuf write_buffer;
        transport_layer::udp_packet pack(remote_endpoint_pair_, buffer);
        pack.make_ip_packet(write_buffer);

        boost::system::error_code ec;
        co_await tuntap_.async_write_some(write_buffer.data(), net_awaitable[ec]);
    }

private:
    boost::asio::io_context &ioc_;
    tuntap::tuntap &tuntap_;
    boost::asio::ip::udp::socket socket_;

    std::chrono::seconds udp_timeout_seconds_ = std::chrono::seconds(60);
    boost::asio::steady_timer udp_timeout_timer_;

    transport_layer::udp_endpoint_pair local_endpoint_pair_;
    transport_layer::udp_endpoint_pair remote_endpoint_pair_;
};