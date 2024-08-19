
#pragma once
#include <spdlog/spdlog.h>

#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "network_monitor.hpp"
#include "pbuf.hpp"
#include "socks_client/socks_client.hpp"
#include <memory>
#include <queue>

namespace tun2socks {

class tcp_proxy : public tcp_basic_connection, public std::enable_shared_from_this<tcp_proxy> {
public:
    using ptr = std::shared_ptr<tcp_proxy>;

public:
    tcp_proxy(boost::asio::io_context& ioc,
              struct tcp_pcb*          pcb,
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

    void start()
    {
        lwip::lwip_tcp_receive(pcb_, std::bind(&tcp_proxy::on_recved,
                                               this,
                                               std::placeholders::_1,
                                               std::placeholders::_2,
                                               std::placeholders::_3,
                                               std::placeholders::_4));

        lwip::lwip_tcp_sent(pcb_, std::bind(&tcp_proxy::on_sent,
                                            this,
                                            std::placeholders::_1,
                                            std::placeholders::_2,
                                            std::placeholders::_3));
        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(shared_from_this());
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;
                for (; pcb_;) {
                    toys::wrapper::pbuf_buffer buffer(pcb_->mss);

                    auto bytes = co_await socket_->async_read_some(buffer.data(), net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    buffer.realloc(bytes);
                    net_monitor().update_download_bytes(bytes);
                    this->send_queue_.push(buffer);
                    try_send();
                }
            },
            boost::asio::detached);
    }

private:
    err_t on_sent(void*           arg,
                  struct tcp_pcb* tpcb,
                  u16_t           len)
    {
        if (tpcb == NULL)
            return ERR_VAL;
        try_send();
        return ERR_OK;
    }

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

        if (!socket_ || recved_queue_.size() >= 10)
            return ERR_MEM;

        lwip::instance().lwip_tcp_recved(tpcb, p->tot_len);

        toys::wrapper::pbuf_buffer buffer(p, false);

        bool write_in_process = !recved_queue_.empty();
        recved_queue_.push(buffer);
        if (write_in_process)
            return ERR_OK;

        boost::asio::co_spawn(
            get_io_context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                while (!recved_queue_.empty()) {
                    const auto& buffer = recved_queue_.front();
                    auto        bytes  = co_await boost::asio::async_write(*socket_,
                                                                           buffer.data(),
                                                                           net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    net_monitor().update_upload_bytes(bytes);
                    recved_queue_.pop();
                }
            },
            boost::asio::detached);

        return ERR_OK;
    }

private:
    inline void do_close()
    {
        if (!pcb_)
            return;

        lwip::lwip_tcp_sent(pcb_, nullptr);
        lwip::lwip_tcp_receive(pcb_, nullptr);
        lwip::lwip_tcp_close(pcb_);
        pcb_ = nullptr;

        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
        core_.close_endpoint_pair(shared_from_this());
    }
    void try_send()
    {
        while (pcb_ && !send_queue_.empty()) {
            const auto& buf  = send_queue_.front().data();
            err_t       code = lwip::lwip_tcp_write(pcb_, buf.data(), buf.size(), TCP_WRITE_FLAG_COPY);

            if (code == ERR_MEM) {
                return;
            }
            if (code != ERR_OK) {
                do_close();
                return;
            }
            code = lwip::instance().lwip_tcp_output(pcb_);
            if (code != ERR_OK) {
                do_close();
                return;
            }
            send_queue_.pop();
        }
    }

private:
    struct tcp_pcb* pcb_;

    core_impl_api&                core_;
    core_impl_api::tcp_socket_ptr socket_;

    std::queue<toys::wrapper::pbuf_buffer> recved_queue_;
    std::queue<toys::wrapper::pbuf_buffer> send_queue_;
};
}  // namespace tun2socks