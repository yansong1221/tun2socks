#pragma once
#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "pbuf.hpp"
#include <boost/asio.hpp>
#include <queue>
#include <spdlog/spdlog.h>
#include <tun2socks/connection.h>

namespace tun2socks {
using namespace std::chrono_literals;
class udp_proxy : public udp_basic_connection {
public:
    using ptr = std::shared_ptr<udp_proxy>;

    explicit udp_proxy(boost::asio::io_context& ioc,
                       lwip::udp_conn::ptr      conn,
                       core_impl_api&           core)
        : udp_basic_connection(ioc, conn->endp_pair()),
          core_(core),
          conn_(conn),
          timeout_timer_(ioc)
    {
    }
    ~udp_proxy()
    {
        spdlog::info("UDP disconnect: {0}", endpoint_pair().to_string());
    }

protected:
    virtual void on_connection_start() override
    {
        conn_->set_recv_function(
            [this, self = shared_from_this()](wrapper::pbuf_buffer buffer) {
                if (!socket_)
                    return;

                reset_timeout_timer();
                socket_->async_send_to(
                    buffer.data(),
                    proxy_endpoint_,
                    [this, buffer, self = shared_from_this()](const boost::system::error_code& ec, std::size_t bytes) {
                        if (ec) {
                            do_close();
                            return;
                        }
                        update_upload_bytes(bytes);
                    });
            });
        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(self,
                                                             proxy_endpoint_);
                if (!socket_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;
                for (;;) {
                    reset_timeout_timer();

                    wrapper::pbuf_buffer buffer(4096);

                    auto bytes = co_await socket_->async_receive_from(buffer.data(),
                                                                      proxy_endpoint_,
                                                                      net_awaitable[ec]);
                    if (ec || !conn_) {
                        do_close();
                        co_return;
                    }

                    update_download_bytes(bytes);
                    buffer.realloc(bytes);
                    conn_->send(buffer);
                }
            },
            boost::asio::detached);
    }
    virtual void on_connection_stop() override
    {
        if (!conn_)
            return;
        conn_.reset();

        if (socket_) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
    }

private:
    void reset_timeout_timer()
    {
        boost::system::error_code ec;
        timeout_timer_.cancel(ec);
        timeout_timer_.expires_after(10s);
        timeout_timer_.async_wait(
            [this, self = shared_from_this()](boost::system::error_code ec) {
                if (ec)
                    return;
                do_close();
            });
    }
    void do_close()
    {
        core_.close_endpoint_pair(shared_from_this());
    }

private:
    lwip::udp_conn::ptr conn_;

    core_impl_api::udp_socket_ptr socket_;
    core_impl_api&                core_;

    boost::asio::ip::udp::endpoint proxy_endpoint_;

    boost::asio::steady_timer timeout_timer_;
};
}  // namespace tun2socks