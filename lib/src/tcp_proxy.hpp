
#pragma once
#include <spdlog/spdlog.h>

#include "interface.hpp"
#include "lwipstack.h"
#include "pbuf.hpp"
#include "socks_client/socks_client.hpp"
#include <queue>

namespace transport_layer {

class tcp_proxy : public std::enable_shared_from_this<tcp_proxy>
{
public:
    using ptr = std::shared_ptr<tcp_proxy>;

public:
    tcp_proxy(boost::asio::io_context &ioc,
              struct tcp_pcb *pcb,
              transport_layer::tcp_endpoint_pair local_endpoint_pair,
              abstract::tun2socks &_tun2socks)
        : strand_(ioc)
        , pcb_(pcb)
        , local_endpoint_pair_(local_endpoint_pair)
        , tun2socks_(_tun2socks)
    {}
    ~tcp_proxy() { spdlog::info("TCP断开连接 {}", local_endpoint_pair_.to_string()); }

    void start()
    {
        LWIPStack::getInstance().lwip_tcp_receive(pcb_,
                                                  std::bind(&tcp_proxy::on_recved,
                                                            this,
                                                            std::placeholders::_1,
                                                            std::placeholders::_2,
                                                            std::placeholders::_3,
                                                            std::placeholders::_4));
        LWIPStack::getInstance().lwip_tcp_sent(pcb_,
                                               std::bind(&tcp_proxy::on_sent,
                                                         this,
                                                         std::placeholders::_1,
                                                         std::placeholders::_2,
                                                         std::placeholders::_3));
        boost::asio::co_spawn(
            strand_.context(),
            [this, self = shared_from_this()]() mutable -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                socket_ = co_await tun2socks_.create_proxy_socket(local_endpoint_pair_);
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                for (; pcb_;) {
                    toys::wrapper::pbuf_buffer buffer(pcb_->mss);
                    if (!buffer) {
                        boost::asio::steady_timer try_again_timer(
                            co_await boost::asio::this_coro::executor);
                        try_again_timer.expires_from_now(std::chrono::milliseconds(64));
                        co_await try_again_timer.async_wait(net_awaitable[ec]);
                        if (ec)
                            break;
                        continue;
                    }

                    boost::system::error_code ec;
                    auto bytes = co_await socket_->async_read_some(buffer.data(), net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    buffer.realloc(bytes);
                    this->send_queue_.push_back(buffer);
                    try_send();
                }
            },
            boost::asio::detached);
    }

private:
    err_t on_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
    {
        if (tpcb == NULL)
            return ERR_VAL;
        try_send();
        return ERR_OK;
    }

    err_t on_recved(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
    {
        if (tpcb == NULL)
            return ERR_VAL;

        if (err != ERR_OK || !p || 0 == p->len) {
            do_close();
            return ERR_OK;
        }

        if (!socket_)
            return ERR_MEM;

        if (read_queue_.size() >= 10)
            return ERR_MEM;

        LWIPStack::getInstance().lwip_tcp_recved(tpcb, p->tot_len);

        toys::wrapper::pbuf_buffer buffer(p, false);
        bool write_in_process = !read_queue_.empty();
        read_queue_.push_back(buffer);
        if (write_in_process)
            return ERR_OK;

        boost::asio::co_spawn(
            strand_.context(),
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                while (!read_queue_.empty()) {
                    boost::system::error_code ec;
                    const auto &buffer = read_queue_.front();
                    auto bytes = co_await boost::asio::async_write(*socket_,
                                                                   buffer.data(),
                                                                   net_awaitable[ec]);
                    if (ec) {
                        do_close();
                        co_return;
                    }
                    read_queue_.pop_front();
                }
            },
            boost::asio::detached);

        return ERR_OK;
    }

private:
    inline void do_close()
    {
        if (pcb_) {
            LWIPStack::getInstance().lwip_tcp_sent(pcb_, nullptr);
            LWIPStack::getInstance().lwip_tcp_receive(pcb_, nullptr);
            LWIPStack::getInstance().lwip_tcp_close(pcb_);
            pcb_ = nullptr;
        }

        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
    }
    void try_send()
    {
        while (pcb_ && !send_queue_.empty()) {
            const auto &buf = send_queue_.front().data();
            err_t code = LWIPStack::getInstance().lwip_tcp_write(pcb_,
                                                                 buf.data(),
                                                                 buf.size(),
                                                                 TCP_WRITE_FLAG_COPY);
            if (code == ERR_MEM) {
                return;
            }
            if (code != ERR_OK) {
                do_close();
                return;
            }
            code = LWIPStack::getInstance().lwip_tcp_output(pcb_);
            if (code != ERR_OK) {
                do_close();
                return;
            }
            send_queue_.pop_front();
        }
    }

private:
    struct tcp_pcb *pcb_;
    boost::asio::io_context::strand strand_;
    abstract::tun2socks &tun2socks_;
    abstract::tun2socks::tcp_socket_ptr socket_;

    transport_layer::tcp_endpoint_pair local_endpoint_pair_;

    std::list<toys::wrapper::pbuf_buffer> read_queue_;
    std::list<toys::wrapper::pbuf_buffer> send_queue_;
};
} // namespace transport_layer
