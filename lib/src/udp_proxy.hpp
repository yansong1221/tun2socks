#pragma once
#include "basic_connection.hpp"
#include "core_impl_api.h"
<<<<<<< HEAD
#include "lwip.hpp"
#include "pbuf.hpp"
=======
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4
#include <boost/asio.hpp>
#include <queue>
#include <spdlog/spdlog.h>
#include <tun2socks/connection.h>

namespace tun2socks {
using namespace std::chrono_literals;
class udp_proxy : public udp_basic_connection {
public:
    using ptr = std::shared_ptr<udp_proxy>;

<<<<<<< HEAD
    explicit udp_proxy(boost::asio::io_context& ioc,
                       const udp_endpoint_pair& endpoint_pair,
                       struct udp_pcb*          pcb,
                       core_impl_api&           core)
=======
    explicit udp_proxy(boost::asio::io_context&      ioc,
                       const net::udp_endpoint_pair& endpoint_pair,
                       net::udp::udp_pcb::ptr        pcb,
                       core_impl_api&                core)
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4
        : udp_basic_connection(ioc, endpoint_pair),
          core_(core),
          pcb_(pcb),
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
        pcb_->set_recved_function([this, self = shared_from_this()](shared_buffer buf) {
            if (!socket_)
                return;

            if (send_queue_.size() >= 10)
                return;

            bool write_in_process = !send_queue_.empty();
            send_queue_.push(buf);
            if (write_in_process)
                return;

            boost::asio::co_spawn(
                get_io_context(), [this, self]() -> boost::asio::awaitable<void> {
                    boost::system::error_code ec;
                    while (!send_queue_.empty()) {
                        reset_timeout_timer();

                        const auto& buffer = send_queue_.front();
                        auto        bytes  = co_await socket_->async_send_to(buffer.data(),
                                                                             proxy_endpoint_,
                                                                             net_awaitable[ec]);

                        if (ec) {
                            spdlog::warn("Sending UDP data failed: [{}]:{} {}",
                                         proxy_endpoint_.address().to_string(),
                                         proxy_endpoint_.port(),
                                         ec.message());
                            do_close();
                            co_return;
                        }

                        update_upload_bytes(bytes);
                        send_queue_.pop();
                    }
                },
                boost::asio::detached);
        });

        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(shared_from_this(),
                                                             proxy_endpoint_);
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;
                for (; pcb_;) {
                    reset_timeout_timer();

<<<<<<< HEAD
                    toys::wrapper::pbuf_buffer buffer(4096);
=======
                    shared_buffer buffer(4096);
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4

                    auto bytes = co_await socket_->async_receive_from(buffer.data(),
                                                                      proxy_endpoint_,
                                                                      net_awaitable[ec]);
                    if (ec) {
                        spdlog::warn("Failed to receive UDP data from the remote end : [{}]:{} {}",
                                     proxy_endpoint_.address().to_string(),
                                     proxy_endpoint_.port(),
                                     ec.message());
                        do_close();
                        co_return;
                    }
<<<<<<< HEAD
                    if (!pcb_)
                        co_return;
                    update_download_bytes(bytes);
                    buffer.realloc(bytes);
                    lwip::lwip_udp_send(pcb_, &buffer);
=======
                    update_download_bytes(bytes);
                    buffer.resize(bytes);

                    pcb_->send(buffer);
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4
                }
            },
            boost::asio::detached);
    }
    virtual void on_connection_stop() override
    {
<<<<<<< HEAD
        if (!pcb_)
            return;

        lwip::lwip_udp_recv(pcb_, nullptr);
        lwip::lwip_udp_disconnect(pcb_);
        lwip::lwip_udp_remove(pcb_);
        pcb_ = nullptr;

=======
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4
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

        timeout_timer_.async_wait([this, self = shared_from_this()](boost::system::error_code ec) {
            if (ec)
                return;
            do_close();
        });
    }
<<<<<<< HEAD
    void on_udp_recved(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port)
    {
        if (pcb == nullptr)
            return;

        if (!socket_)
            return;

        auto buffer = toys::wrapper::pbuf_buffer::smart_copy(p);
        pbuf_free(p);

        bool write_in_process = !send_queue_.empty();
        send_queue_.push(buffer);
        if (write_in_process)
            return;

        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                while (pcb_ && !send_queue_.empty()) {
                    reset_timeout_timer();

                    const auto& buffer = send_queue_.front();
                    auto        bytes  = co_await socket_->async_send_to(buffer.data(),
                                                                         proxy_endpoint_,
                                                                         net_awaitable[ec]);

                    if (ec) {
                        spdlog::warn("Sending UDP data failed: [{}]:{} {}",
                                     proxy_endpoint_.address().to_string(),
                                     proxy_endpoint_.port(),
                                     ec.message());
                        do_close();
                        co_return;
                    }

                    update_upload_bytes(bytes);
                    send_queue_.pop();
                }
            },
            boost::asio::detached);
    }
=======
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4
    void do_close()
    {
        core_.close_endpoint_pair(shared_from_this());
    }

private:
<<<<<<< HEAD
    struct udp_pcb* pcb_ = nullptr;
=======
    net::udp::udp_pcb::ptr pcb_;
>>>>>>> 4b4e245fe323a42d88c13f18fbec855217dc13b4

    core_impl_api::udp_socket_ptr socket_;
    core_impl_api&                core_;

    std::queue<shared_buffer>      send_queue_;
    boost::asio::ip::udp::endpoint proxy_endpoint_;

    boost::asio::steady_timer timeout_timer_;
};
}  // namespace tun2socks