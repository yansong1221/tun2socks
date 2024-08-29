
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
    explicit tcp_proxy(boost::asio::io_context& ioc,
                       lwip::tcp_conn::ptr      conn,
                       core_impl_api&           core)
        : tcp_basic_connection(ioc, core, conn->endp_pair()),
          conn_(conn)
    {
        spdlog::info("TCP proxy: {}", conn->endp_pair().to_string());
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
                    stop();
                    return ERR_OK;
                }

                if (!socket_)
                    return ERR_MEM;

                auto write_in_process = !write_queue_.empty();
                write_queue_.push_back(buffer);
                if (!write_in_process)
                    start_write_to_proxy();

                return ERR_OK;
            });

        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_api().create_proxy_socket(shared_from_this());
                if (!socket_) {
                    stop();
                    co_return;
                }

                boost::system::error_code ec;

                for (; conn_;) {
                    wrapper::pbuf_buffer buffer(conn_->buf_len());

                    auto bytes = co_await socket_->async_read_some(buffer.mutable_data(),
                                                                   net_awaitable[ec]);
                    if (ec || !conn_) {
                        stop();
                        co_return;
                    }
                    buffer.realloc(bytes);

                    auto data = buffer.const_data();

                    err_t err = conn_->write(data.data(), data.size());
                    if (err != ERR_OK) {
                        stop();
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
        write_queue_.clear();
    }

private:
    void start_write_to_proxy()
    {
        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                while (!write_queue_.empty()) {
                    const auto& buf   = write_queue_.front();
                    auto        bytes = co_await boost::asio::async_write(*socket_, buf.const_data(), net_awaitable[ec]);
                    if (ec || !conn_) {
                        stop();
                        co_return;
                    }
                    BOOST_ASSERT(bytes == buf.len());
                    write_queue_.pop_front();
                    conn_->recved(bytes);
                }
            },
            boost::asio::detached);
    }

private:
    lwip::tcp_conn::ptr              conn_;
    core_impl_api::tcp_socket_ptr    socket_;
    std::deque<wrapper::pbuf_buffer> write_queue_;
};
}  // namespace tun2socks