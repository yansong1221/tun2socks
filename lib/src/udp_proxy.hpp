#pragma once
#include "interface.hpp"
#include "udp_packet.hpp"
#include <boost/asio.hpp>

class udp_proxy : public std::enable_shared_from_this<udp_proxy>
{
public:
    using ptr = std::shared_ptr<udp_proxy>;
    using close_function = std::function<void(const transport_layer::udp_endpoint_pair &)>;

    explicit udp_proxy(boost::asio::io_context &ioc,
                       const transport_layer::udp_endpoint_pair &endpoint_pair,
                       abstract::tun2socks &_tun2socks)
        : ioc_(ioc)
        , tun2socks_(_tun2socks)
        , udp_timeout_timer_(ioc)
        , local_endpoint_pair_(endpoint_pair)
        , remote_endpoint_pair_(endpoint_pair.swap())
    {}
    ~udp_proxy() { spdlog::info("UDP断开连接: {0}", local_endpoint_pair_.to_string()); }

public:
    void start() { boost::asio::co_spawn(ioc_, co_read_data(), boost::asio::detached); }

    void on_udp_packet(const transport_layer::udp_packet &pack)
    {
        std::vector<uint8_t> buffer;
        buffer.resize(pack.payload().size());
        boost::asio::buffer_copy(boost::asio::buffer(buffer), pack.payload());
        bool write_in_process = !send_buffer_.empty();
        send_buffer_.push_back(std::move(buffer));

        reset_timeout_timer();

        if (!socket_)
            return;

        if (write_in_process)
            return;

        boost::asio::co_spawn(ioc_, write_to_proxy(), boost::asio::detached);
    }

private:
    boost::asio::awaitable<void> co_reset_timeout_timer()
    {
        auto self = shared_from_this();

        boost::system::error_code ec;
        udp_timeout_timer_.expires_from_now(udp_timeout_seconds_);
        co_await udp_timeout_timer_.async_wait(net_awaitable[ec]);
        if (ec)
            co_return;

        do_close();
    }
    void reset_timeout_timer()
    {
        boost::system::error_code ec;
        udp_timeout_timer_.cancel(ec);
        boost::asio::co_spawn(ioc_, co_reset_timeout_timer(), boost::asio::detached);
    }
    boost::asio::awaitable<void> co_read_data()
    {
        auto self = shared_from_this();

        socket_ = co_await tun2socks_.create_proxy_socket(local_endpoint_pair_, proxy_endpoint_);
        if (!socket_) {
            do_close();
            co_return;
        }
        boost::asio::streambuf read_buffer;
        for (;;) {
            reset_timeout_timer();

            boost::system::error_code ec;
            auto bytes = co_await socket_->async_receive_from(read_buffer.prepare(0x0FFF),
                                                              proxy_endpoint_,
                                                              net_awaitable[ec]);
            if (ec) {
                spdlog::warn("从远端接收UDP 数据失败: [{}]:{} {}",
                             proxy_endpoint_.address().to_string(),
                             proxy_endpoint_.port(),
                             ec.message());
                do_close();
                co_return;
            }

            read_buffer.commit(bytes);

            transport_layer::udp_packet pack(remote_endpoint_pair_, read_buffer.data());
            tun2socks_.write_tun_packet(pack);

            read_buffer.consume(bytes);
        }
    }
    void do_close()
    {
        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
        tun2socks_.close_endpoint_pair(local_endpoint_pair_);
    }

private:
    boost::asio::awaitable<void> write_to_proxy()
    {
        auto self = shared_from_this();

        while (!send_buffer_.empty()) {
            boost::system::error_code ec;
            const auto &buffer = send_buffer_.front();
            co_await socket_->async_send_to(boost::asio::buffer(buffer),
                                            proxy_endpoint_,
                                            net_awaitable[ec]);

            if (ec) {
                spdlog::warn("发送 UDP 数据失败: [{}]:{} {}",
                             proxy_endpoint_.address().to_string(),
                             proxy_endpoint_.port(),
                             ec.message());
                do_close();
                co_return;
            }
            send_buffer_.pop_front();
        }
    }

private:
    boost::asio::io_context &ioc_;
    abstract::tun2socks::udp_socket_ptr socket_;
    abstract::tun2socks &tun2socks_;

    std::chrono::seconds udp_timeout_seconds_ = std::chrono::seconds(60);
    boost::asio::steady_timer udp_timeout_timer_;

    std::deque<std::vector<uint8_t>> send_buffer_;

    transport_layer::udp_endpoint_pair local_endpoint_pair_;
    transport_layer::udp_endpoint_pair remote_endpoint_pair_;
    boost::asio::ip::udp::endpoint proxy_endpoint_;
};