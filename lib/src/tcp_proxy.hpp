
#pragma once
#include <spdlog/spdlog.h>

#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "pbuf.hpp"
#include "socks_client/socks_client.hpp"
#include <memory>
#include <queue>

namespace tun2socks {

class tcp_proxy : public tcp_basic_connection {
public:
    using ptr = std::shared_ptr<tcp_proxy>;

public:
    tcp_proxy(boost::asio::io_context& ioc,
              net::tcp::tcp_pcb::ptr   pcb,
              net::tcp_endpoint_pair   local_endpoint_pair,
              core_impl_api&           core)
        : tcp_basic_connection(ioc, local_endpoint_pair),
          pcb_(pcb),
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
        pcb_->set_recved_function([this, self = shared_from_this()](shared_buffer buf) -> bool {
            if (!socket_ || recved_queue_.size() >= 100)
                return false;

            bool write_in_process = !recved_queue_.empty();
            recved_queue_.push(buf);
            if (!write_in_process) {
                boost::asio::co_spawn(
                    get_io_context(),
                    [this, self]() -> boost::asio::awaitable<void> {
                        boost::system::error_code ec;
                        while (pcb_ && !recved_queue_.empty()) {
                            const auto& buffer = recved_queue_.front();
                            auto        bytes  = co_await boost::asio::async_write(*socket_,
                                                                                   buffer.data(),
                                                                                   net_awaitable[ec]);
                            if (ec) {
                                do_close();
                                co_return;
                            }
                            update_upload_bytes(bytes);
                            recved_queue_.pop();
                        }
                    },
                    boost::asio::detached);
            }
            return true;
        });
        pcb_->set_close_function([this, self = shared_from_this()]() {
            do_close();
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
                for (;;) {
                    shared_buffer buffer(4096);

                    auto bytes = co_await socket_->async_read_some(buffer.data(), net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    buffer.resize(bytes);
                    update_download_bytes(bytes);
                    pcb_->write(buffer);
                }
            },
            boost::asio::detached);
    }
    virtual void on_connection_stop() override
    {
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
    net::tcp::tcp_pcb::ptr pcb_;

    core_impl_api&                core_;
    core_impl_api::tcp_socket_ptr socket_;

    std::queue<shared_buffer> recved_queue_;
};
}  // namespace tun2socks