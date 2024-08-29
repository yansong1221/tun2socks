#pragma once
#include "core_impl_api.h"
#include "endpoint_pair.hpp"
#include "process_info/process_info.hpp"
#include "use_awaitable.hpp"
#include <tun2socks/connection.h>

namespace tun2socks {

template <typename InternetProtocol>
class basic_connection : public connection,
                         public boost::asio::detail::service_base<basic_connection<InternetProtocol>>,
                         public std::enable_shared_from_this<basic_connection<InternetProtocol>> {
public:
    using endpoint_pair_type = basic_endpoint_pair<InternetProtocol>;
    using connection_type    = basic_connection<InternetProtocol>;

private:
    class net_info_impl : public connection::net_info {
    public:
        void update_download_bytes(uint32_t bytes)
        {
            total_download_bytes += bytes;
            speed_download_ += bytes;
        }
        void update_upload_bytes(uint32_t bytes)
        {
            total_upload_bytes += bytes;
            speed_upload_ += bytes;
        }

        void update_1s()
        {
            speed_download_1s = speed_download_;
            speed_upload_1s   = speed_upload_;
            speed_download_   = 0;
            speed_upload_     = 0;
        }

    private:
        uint32_t speed_download_ = 0;
        uint32_t speed_upload_   = 0;
    };

public:
    explicit basic_connection(boost::asio::io_context&  ioc,
                              core_impl_api&            core,
                              const endpoint_pair_type& endpoint_pair)
        : boost::asio::detail::service_base<connection_type>(ioc),
          core_(core),
          endpoint_pair_(endpoint_pair),
          update_timer_(ioc)
    {
        proc_info_ = process_info::get_proc_info(endpoint_pair.src.port());
    }
    virtual ~basic_connection()
    {
    }

public:
    void start()
    {
        boost::asio::co_spawn(
            this->get_io_context(),
            [this, self = this->shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                for (;;) {
                    update_timer_.expires_after(std::chrono::seconds(1));
                    co_await update_timer_.async_wait(net_awaitable[ec]);
                    if (ec)
                        co_return;
                    net_info_.update_1s();
                }
            },
            boost::asio::detached);

        this->on_connection_start();
    }
    void stop() override
    {
        core_.remove_conn(this->shared_from_this());
        boost::system::error_code ec;
        update_timer_.cancel(ec);
        this->on_connection_stop();
    }

public:
    std::optional<proc_info> get_process_info() const override
    {
        return proc_info_;
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
    endpoint local_endpoint() const override
    {
        return std::make_pair(endpoint_pair_.src.address().to_string(), endpoint_pair_.src.port());
    }
    endpoint remote_endpoint() const override
    {
        return std::make_pair(endpoint_pair_.dest.address().to_string(), endpoint_pair_.dest.port());
    }
    const connection::net_info& get_net_info() const override
    {
        return net_info_;
    }
    const endpoint_pair_type& endpoint_pair() const
    {
        return endpoint_pair_;
    }

protected:
    void update_download_bytes(uint32_t bytes)
    {
        net_info_.update_download_bytes(bytes);
    }
    void update_upload_bytes(uint32_t bytes)
    {
        net_info_.update_upload_bytes(bytes);
    }
    virtual void on_connection_start() = 0;
    virtual void on_connection_stop()  = 0;

    core_impl_api& core_api()
    {
        return core_;
    }

private:
    core_impl_api&            core_;
    endpoint_pair_type        endpoint_pair_;
    std::optional<proc_info>  proc_info_;
    boost::asio::steady_timer update_timer_;
    net_info_impl             net_info_;
};

using tcp_basic_connection = basic_connection<boost::asio::ip::tcp>;
using udp_basic_connection = basic_connection<boost::asio::ip::udp>;
}  // namespace tun2socks