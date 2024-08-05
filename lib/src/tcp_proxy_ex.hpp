
#pragma once
#include "tcp_packet.hpp"
#include <spdlog/spdlog.h>

#include "interface.hpp"
#include "lwipstack.h"
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
        : ioc_(ioc)
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
            ioc_,
            [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                socket_ = co_await tun2socks_.create_proxy_socket(local_endpoint_pair_);
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                boost::asio::co_spawn(ioc_, read_remote_data(self), boost::asio::detached);
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
        //auto self = shared_from_this();
        if (tpcb == NULL)
            return ERR_VAL;

        if (err != ERR_OK || !p || 0 == p->len) {
            do_close();
            return ERR_OK;
        }

        if (!socket_)
            return ERR_MEM;

        if (proxy_swap_buffer->size() >= 65535)
            return ERR_MEM;

        LWIPStack::getInstance().lwip_tcp_recved(tpcb, p->tot_len);

        auto buf = proxy_swap_buffer->prepare(p->tot_len);
        pbuf_copy_partial(p, buf.data(), p->tot_len, 0);
        proxy_swap_buffer->commit(p->tot_len);

        if (proxy_send_buffer->size() == 0) {
            proxy_send_buffer.swap(proxy_swap_buffer);

            boost::asio::co_spawn(ioc_,
                                  write_client_data_to_proxy(shared_from_this()),
                                  boost::asio::detached);
        }
        return ERR_OK;
    }

private:
    inline void do_close()
    {
        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
        if (pcb_) {
            LWIPStack::getInstance().lwip_tcp_sent(pcb_, nullptr);
            LWIPStack::getInstance().lwip_tcp_receive(pcb_, nullptr);
            LWIPStack::getInstance().lwip_tcp_close(pcb_);
            pcb_ = nullptr;
        }
    }
    void try_send()
    {
        boost::asio::post(ioc_, [this, self = shared_from_this()]() {
            while (!send_buffer_.empty()) {
                const auto &buf = send_buffer_.front();
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

                send_buffer_.pop();

                code = LWIPStack::getInstance().lwip_tcp_output(pcb_);
                if (code != ERR_OK) {
                    do_close();
                    return;
                }
            }
        });
    }
    boost::asio::awaitable<void> read_remote_data(tcp_proxy::ptr self)
    {
        for (; pcb_;) {
            boost::system::error_code ec;
            buffer::ref_buffer buffer;
            //int sent = std::min<int>(TCP_MSS, LWIPStack::getInstance().lwip_tcp_sndbuf(pcb_));
            auto bytes = co_await socket_->async_read_some(buffer.prepare(TCP_MSS),
                                                           net_awaitable[ec]);
            if (ec) {
                do_close();
                co_return;
            }
            buffer.commit(bytes);
            send_buffer_.push(buffer);
            try_send();
        }
    }
    boost::asio::awaitable<void> write_client_data_to_proxy(tcp_proxy::ptr self)
    {
        while (proxy_send_buffer->size() > 0) {
            boost::system::error_code ec;
            auto bytes = co_await boost::asio::async_write(*socket_,
                                                           proxy_send_buffer->data(),
                                                           net_awaitable[ec]);
            if (ec) {
                do_close();
                co_return;
            }
            proxy_send_buffer->consume(bytes);

            if (proxy_send_buffer->size() == 0)
                proxy_send_buffer.swap(proxy_swap_buffer);
        }
    }

private:
    struct tcp_pcb *pcb_;
    boost::asio::io_context &ioc_;
    abstract::tun2socks &tun2socks_;
    abstract::tun2socks::tcp_socket_ptr socket_;

    transport_layer::tcp_endpoint_pair local_endpoint_pair_;

    std::unique_ptr<boost::asio::streambuf> proxy_send_buffer
        = std::make_unique<boost::asio::streambuf>();
    std::unique_ptr<boost::asio::streambuf> proxy_swap_buffer
        = std::make_unique<boost::asio::streambuf>();

    std::unique_ptr<boost::asio::streambuf> local_send_buffer
        = std::make_unique<boost::asio::streambuf>();
    std::unique_ptr<boost::asio::streambuf> local_swap_buffer
        = std::make_unique<boost::asio::streambuf>();

    std::deque<buffer::ref_const_buffer>
            write_buffer_;
    std::queue<buffer::ref_const_buffer> send_buffer_;
};
} // namespace transport_layer
