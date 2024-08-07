#pragma once
#include "use_awaitable.hpp"
#include <boost/asio.hpp>

class network_monitor : public std::enable_shared_from_this<network_monitor> {
public:
    network_monitor(boost::asio::io_context& ioc)
        : ioc_(ioc),
          update_timer_(ioc)
    {
    }
    ~network_monitor()
    {
    }

public:
    uint32_t get_speed_download_1s() const
    {
        return speed_download_1s_;
    }

    uint32_t get_speed_upload_1s() const
    {
        return speed_upload_1s_;
    }

    uint64_t get_total_download_bytes() const
    {
        return total_download_bytes_;
    }

    uint64_t get_total_upload_bytes() const
    {
        return total_upload_bytes_;
    }

private:
    void update_download_bytes(uint32_t bytes)
    {
        total_download_bytes_ += bytes;
        speed_download_ += bytes;
    }
    void update_upload_bytes(uint32_t bytes)
    {
        total_upload_bytes_ += bytes;
        speed_upload_ += bytes;
    }
    void start()
    {
        boost::asio::co_spawn(
            ioc_, [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                for (;;) {
                    update_timer_.expires_from_now(std::chrono::seconds(1));
                    co_await update_timer_.async_wait(net_awaitable[ec]);
                    if (ec)
                        co_return;

                    speed_download_1s_ = speed_download_;
                    speed_upload_1s_   = speed_upload_;
                    speed_download_ = speed_upload_ = 0;
                }
            },
            boost::asio::detached);
    }
    void stop()
    {
        boost::system::error_code ec;
        update_timer_.cancel(ec);
    }

private:
    boost::asio::io_context&  ioc_;
    boost::asio::steady_timer update_timer_;

    uint64_t total_download_bytes_ = 0;
    uint64_t total_upload_bytes_   = 0;

    uint32_t speed_download_1s_ = 0;
    uint32_t speed_upload_1s_   = 0;

    uint32_t speed_download_ = 0;
    uint32_t speed_upload_   = 0;

    friend class tcp_proxy;
    friend class udp_proxy;
};