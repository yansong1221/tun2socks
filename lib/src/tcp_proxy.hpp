
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
              struct tcp_pcb*          pcb,
              const tcp_endpoint_pair& local_endpoint_pair,
              core_impl_api&           core)
        : tcp_basic_connection(ioc, local_endpoint_pair),
          pcb_(pcb),
          core_(core)
    {
        lwip::lwip_tcp_receive(pcb_, std::bind(&tcp_proxy::on_recved,
                                               this,
                                               std::placeholders::_1,
                                               std::placeholders::_2,
                                               std::placeholders::_3,
                                               std::placeholders::_4));
    }
    ~tcp_proxy()
    {
        spdlog::info("TCP disconnect: {}", endpoint_pair().to_string());
    }

protected:
    virtual void on_connection_start() override
    {
        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(shared_from_this());
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;

                uint8_t buffer[TCP_MSS];
                for (;;) {
                    lwip::instance().lwip_tcp_output(pcb_);

                    auto sz    = std::min<uint16_t>(TCP_MSS, tcp_sndbuf(pcb_));
                    auto bytes = co_await socket_->async_read_some(boost::asio::mutable_buffer(buffer, sz),
                                                                   net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    if (!pcb_)
                        co_return;

                    err_t code = lwip::lwip_tcp_write(pcb_, buffer, bytes, TCP_WRITE_FLAG_COPY);
                    if (code != ERR_OK) {
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
        if (!pcb_)
            return;

        lwip::lwip_tcp_sent(pcb_, nullptr);
        lwip::lwip_tcp_receive(pcb_, nullptr);
        lwip::lwip_tcp_close(pcb_);
        tcp_shutdown(pcb_, 1, 1);
        tcp_close(pcb_);
        pcb_ = nullptr;

        if (socket_) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
    }

private:
    err_t on_recved(void*           arg,
                    struct tcp_pcb* tpcb,
                    struct pbuf*    p,
                    err_t           err)
    {
        if (tpcb == NULL)
            return ERR_VAL;

        if (err != ERR_OK || !p || 0 == p->len) {
            do_close();
            return ERR_OK;
        }

        if (!socket_ || recved_queue_.size() >= 100)
            return ERR_MEM;

        lwip::instance().lwip_tcp_recved(tpcb, p->tot_len);

        auto buffer = toys::wrapper::pbuf_buffer::smart_copy(p);
        pbuf_free(p);

        bool write_in_process = !recved_queue_.empty();
        recved_queue_.push(buffer);
        if (write_in_process)
            return ERR_OK;

        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
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

        return ERR_OK;
    }

private:
    inline void do_close()
    {
        core_.close_endpoint_pair(shared_from_this());
    }

private:
    struct tcp_pcb* pcb_ = NULL;

    core_impl_api&                core_;
    core_impl_api::tcp_socket_ptr socket_;

    std::queue<toys::wrapper::pbuf_buffer> recved_queue_;
};
}  // namespace tun2socks