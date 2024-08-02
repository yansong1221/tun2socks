#pragma once
#include "buffer.hpp"
#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <deque>

namespace tuntap {

struct tun_parameter
{
    struct address
    {
        boost::asio::ip::address addr;
        boost::asio::ip::address dns;
        uint8_t prefix_length = 0;
    };
    std::string tun_name;
    std::optional<address> ipv4;
    std::optional<address> ipv6;
};

template<typename Device>
class basic_tuntap
{
public:
    typedef typename Device device_type;

    explicit basic_tuntap(boost::asio::io_context &ioc)
        : device_(boost::asio::use_service<device_type>(ioc))
    {}
    inline void open(const tun_parameter &param) { device_.open(param); }
    inline void close() { device_.close(); }

    boost::asio::io_context &get_io_context() noexcept { return device_.get_io_context(); }

    template<typename MutableBufferSequence>
    boost::asio::awaitable<std::size_t> async_read_some(const MutableBufferSequence &buffers,
                                                        boost::system::error_code &ec)
    {
        return device_.async_read_some(buffers, ec);
    }

    template<typename ConstBufferSequence>
    boost::asio::awaitable<std::size_t> async_write_some(const ConstBufferSequence &buffers,
                                                         boost::system::error_code &ec)
    {
        return device_.async_write_some(buffers, ec);
    }

    boost::asio::awaitable<buffer::ref_buffer> read_packet(boost::system::error_code &ec)
    {
        constexpr auto max_size = 64 * 1024;
        buffer::ref_buffer buffer;
        auto bytes = co_await async_read_some(buffer.prepare(max_size), ec);
        if (!ec)
            buffer.commit(bytes);

        co_return buffer;
    }

    void write_packet(const buffer::ref_const_buffer &buffer)
    {
        boost::asio::post(get_io_context(), [=]() {
            bool write_in_process = !write_tun_deque_.empty();
            write_tun_deque_.push_back(buffer);
            if (write_in_process)
                return;
            boost::asio::co_spawn(get_io_context(), write_tuntap_packet(), boost::asio::detached);
        });
    }

private:
    boost::asio::awaitable<void> write_tuntap_packet()
    {
        co_await boost::asio::post(co_await boost::asio::this_coro::executor,
                                   boost::asio::use_awaitable);

        while (!write_tun_deque_.empty()) {
            const auto &buffer = write_tun_deque_.front();
            boost::system::error_code ec;
            auto bytes = co_await device_.async_write_some(buffer, ec);
            if (ec) {
                spdlog::warn("Write IP Packet to tuntap Device Failed: {0}", ec.message());
                co_return;
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

private:
    device_type &device_;
    std::mutex write_lock_;
    std::deque<buffer::ref_const_buffer> write_tun_deque_;
};
} // namespace tuntap