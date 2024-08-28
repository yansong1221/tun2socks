
#pragma once
#include <spdlog/spdlog.h>

#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "pbuf.hpp"
#include "socks_client/socks_client.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <queue>

namespace tun2socks {

class tcp_proxy : public tcp_basic_connection {
public:
    using ptr = std::shared_ptr<tcp_proxy>;

public:
    tcp_proxy(boost::asio::io_context& ioc,
              lwip::tcp_conn::ptr      conn,
              core_impl_api&           core)
        : tcp_basic_connection(ioc, conn->endp_pair()),
          conn_(conn),
          core_(core)
    {
    }
    ~tcp_proxy()
    {
        spdlog::info("TCP disconnect: {}", endpoint_pair().to_string());
    }

protected:
    virtual void on_connection_start() override
    {
        conn_->set_recv_function(
            [this, self = shared_from_this()](const wrapper::pbuf_buffer& buffer, err_t err) -> err_t {
                if (err != ERR_OK || !buffer) {
                    do_close();
                    return ERR_OK;
                }

                if (!socket_)
                    return ERR_MEM;

                if (write_in_process_)
                    return ERR_MEM;

                write_in_process_ = true;

                boost::asio::async_write(
                    *socket_,
                    buffer.const_data(),
                    [this, self, buffer](const boost::system::error_code& ec, std::size_t bytes) {
                        write_in_process_ = false;
                        if (ec || !conn_) {
                            do_close();
                            return;
                        }

                        conn_->recved(bytes);
                    });
                return ERR_OK;
            });

        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(shared_from_this());
                if (!socket_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;

                for (; conn_;) {
                    wrapper::pbuf_buffer buffer(conn_->buf_len());

                    auto bytes = co_await socket_->async_read_some(buffer.mutable_data(),
                                                                   net_awaitable[ec]);
                    if (ec || !conn_) {
                        do_close();
                        co_return;
                    }
                    buffer.realloc(bytes);

                    auto data = buffer.const_data();

                    err_t err = conn_->write(data.data(), data.size());
                    if (err != ERR_OK) {
                        do_close();
                        co_return;
                    }
                    update_download_bytes(bytes);
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
    inline void do_close()
    {
        core_.close_endpoint_pair(shared_from_this());
    }

private:
    lwip::tcp_conn::ptr conn_;

    core_impl_api&                core_;
    core_impl_api::tcp_socket_ptr socket_;
    bool                          write_in_process_ = false;
};
}  // namespace tun2socks