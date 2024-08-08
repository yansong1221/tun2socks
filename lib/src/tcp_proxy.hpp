
#pragma once
#include <spdlog/spdlog.h>

#include "core_impl_api.h"
#include "lwip.hpp"
#include "network_monitor.hpp"
#include "pbuf.hpp"
#include "socks_client/socks_client.hpp"
#include <memory>
#include <queue>
#include <tun2socks/connection.h>

namespace tun2socks {

class tcp_proxy : public connection, public std::enable_shared_from_this<tcp_proxy> {
public:
    using ptr = std::shared_ptr<tcp_proxy>;

public:
    tcp_proxy(boost::asio::io_context& ioc,
              struct tcp_pcb*          pcb,
              tcp_endpoint_pair        local_endpoint_pair,
              core_impl_api&           core)
        : ioc_(ioc),
          net_monitor_(std::make_shared<network_monitor>(ioc)),
          pcb_(pcb),
          local_endpoint_pair_(local_endpoint_pair),
          core_(core)
    {
    }
    ~tcp_proxy()
    {
        spdlog::info("TCP disconnect: {}", local_endpoint_pair_.to_string());
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
            ioc_,
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(local_endpoint_pair_);
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }
                boost::system::error_code ec;
                boost::asio::steady_timer try_again_timer(
                    co_await boost::asio::this_coro::executor);

                for (; pcb_;) {
                    toys::wrapper::pbuf_buffer buffer(pcb_->mss);
                    if (!buffer) {
                        try_again_timer.expires_from_now(std::chrono::milliseconds(64));
                        co_await try_again_timer.async_wait(net_awaitable[ec]);
                        if (ec)
                            break;
                        continue;
                    }
                    auto bytes = co_await socket_->async_read_some(buffer.data(), net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    buffer.realloc(bytes);
                    net_monitor_->update_download_bytes(bytes);
                    this->send_queue_.push(buffer);
                    try_send();
                }
            },
            boost::asio::detached);
        net_monitor_->start();
    }

public:
    conn_type type() const override
    {
        return connection::conn_type::tcp;
    }
    std::string local_endpoint() const override
    {
        return fmt::format("[{}]:{}", local_endpoint_pair_.src.address().to_string(),
                           local_endpoint_pair_.src.port());
    }
    std::string remote_endpoint() const override
    {
        return fmt::format("[{}]:{}", local_endpoint_pair_.dest.address().to_string(),
                           local_endpoint_pair_.dest.port());
    }
    uint32_t get_speed_download_1s() const override
    {
        return net_monitor_->get_speed_download_1s();
    }

    uint32_t get_speed_upload_1s() const override
    {
        return net_monitor_->get_speed_upload_1s();
    }

    uint64_t get_total_download_bytes() const override
    {
        return net_monitor_->get_total_download_bytes();
    }

    uint64_t get_total_upload_bytes() const override
    {
        return net_monitor_->get_total_upload_bytes();
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

        if (!socket_)
            return ERR_MEM;

        if (recved_queue_.size() >= 10)
            return ERR_MEM;

        lwip::instance().lwip_tcp_recved(tpcb, p->tot_len);

        toys::wrapper::pbuf_buffer buffer(p, false);

        bool write_in_process = !recved_queue_.empty();
        recved_queue_.push(buffer);
        if (write_in_process)
            return ERR_OK;

        boost::asio::co_spawn(
            ioc_,
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
                    net_monitor_->update_upload_bytes(bytes);
                    recved_queue_.pop();
                }
            },
            boost::asio::detached);

        return ERR_OK;
    }

private:
    inline void do_close()
    {
        if (pcb_) {
            lwip::lwip_tcp_sent(pcb_, nullptr);
            lwip::lwip_tcp_receive(pcb_, nullptr);
            lwip::lwip_tcp_close(pcb_);
            pcb_ = nullptr;

            if (socket_ && socket_->is_open()) {
                boost::system::error_code ec;
                socket_->close(ec);
            }
            net_monitor_->stop();
            core_.close_endpoint_pair(local_endpoint_pair_);
        }
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
    struct tcp_pcb*               pcb_;
    boost::asio::io_context&      ioc_;
    core_impl_api&                core_;
    core_impl_api::tcp_socket_ptr socket_;

    tcp_endpoint_pair local_endpoint_pair_;

    std::queue<toys::wrapper::pbuf_buffer> recved_queue_;
    std::queue<toys::wrapper::pbuf_buffer> send_queue_;

    std::shared_ptr<network_monitor> net_monitor_;
};
}  // namespace tun2socks