#pragma once
#include "net/endpoint_pair.hpp"
#include "process_info/process_info.hpp"
#include <tun2socks/connection.h>
#include "use_awaitable.hpp"

namespace tun2socks {

template <typename InternetProtocol>
class basic_connection : public connection,
                         public boost::asio::detail::service_base<basic_connection<InternetProtocol>>,
                         public std::enable_shared_from_this<basic_connection<InternetProtocol>> {
public:
    basic_connection(boost::asio::io_context&                          ioc,
                     const net::basic_endpoint_pair<InternetProtocol>& endpoint_pair)
        : boost::asio::detail::service_base<basic_connection<InternetProtocol>>(ioc),
          endpoint_pair_(endpoint_pair),
          update_timer_(ioc)
    {
        pid_ = process_info::get_pid(endpoint_pair.src.port());
        if (pid_)
            execute_path_ = process_info::get_execute_path(*pid_);
    }
    ~basic_connection()
    {
    }

public:
    void start()
    {
        boost::asio::co_spawn(
            this->get_io_context(), [this, self = this->shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                for (;;) {
                    update_timer_.expires_from_now(std::chrono::seconds(1));
                    co_await update_timer_.async_wait(net_awaitable[ec]);
                    if (ec)
                        co_return;

                    speed_download_1s_ = speed_download_.load();
                    speed_upload_1s_   = speed_upload_.load();
                    speed_download_    = 0;
                    speed_upload_      = 0;
                }
            },
            boost::asio::detached);

        this->on_connection_start();
    }
    void stop()
    {
        boost::system::error_code ec;
        update_timer_.cancel(ec);
        this->on_connection_stop();
    }

public:
    virtual std::optional<uint32_t> get_pid() const override
    {
        return pid_;
    }
    virtual std::optional<std::string> get_execute_path() const override
    {
        return execute_path_;
    }
    conn_type type() const override
    {
        if constexpr (std::is_same_v<boost::asio::ip::tcp, InternetProtocol>)
            return connection::conn_type::tcp;
        else if constexpr (std::is_same_v<boost::asio::ip::udp, InternetProtocol>)
            return connection::conn_type::udp;
        else
            static_assert(std::is_same_v<InternetProtocol, InternetProtocol>, "error internet protocol");
    }
    std::string local_endpoint() const override
    {
        return fmt::format("[{}]:{}",
                           endpoint_pair_.src.address().to_string(),
                           endpoint_pair_.src.port());
    }
    std::string remote_endpoint() const override
    {
        return fmt::format("[{}]:{}",
                           endpoint_pair_.dest.address().to_string(),
                           endpoint_pair_.dest.port());
    }
    uint32_t get_speed_download_1s() const override
    {
        return speed_download_1s_;
    }

    uint32_t get_speed_upload_1s() const override
    {
        return speed_upload_1s_;
    }

    uint64_t get_total_download_bytes() const override
    {
        return total_download_bytes_;
    }

    uint64_t get_total_upload_bytes() const override
    {
        return total_upload_bytes_;
    }

    const net::basic_endpoint_pair<InternetProtocol>& endpoint_pair() const
    {
        return endpoint_pair_;
    };

protected:
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
    virtual void on_connection_start() = 0;
    virtual void on_connection_stop()  = 0;

private:
    net::basic_endpoint_pair<InternetProtocol> endpoint_pair_;

    std::optional<uint32_t>    pid_;
    std::optional<std::string> execute_path_;

    boost::asio::steady_timer update_timer_;
    bool                      is_running_ = false;

    std::atomic_uint64_t total_download_bytes_ = 0;
    std::atomic_uint64_t total_upload_bytes_   = 0;

    std::atomic_uint32_t speed_download_1s_ = 0;
    std::atomic_uint32_t speed_upload_1s_   = 0;

    std::atomic_uint32_t speed_download_ = 0;
    std::atomic_uint32_t speed_upload_   = 0;
};

using tcp_basic_connection = basic_connection<boost::asio::ip::tcp>;
using udp_basic_connection = basic_connection<boost::asio::ip::udp>;
}  // namespace tun2socks