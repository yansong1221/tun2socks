#pragma once
#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "network_monitor.hpp"
#include "pbuf.hpp"
#include <boost/asio.hpp>
#include <queue>
#include <spdlog/spdlog.h>
#include <tun2socks/connection.h>

namespace tun2socks {

class udp_proxy : public udp_basic_connection, public std::enable_shared_from_this<udp_proxy> {
public:
    using ptr = std::shared_ptr<udp_proxy>;

    explicit udp_proxy(boost::asio::io_context& ioc,
                       const udp_endpoint_pair& endpoint_pair,
                       struct udp_pcb*          pcb,
                       core_impl_api&           core)
        : udp_basic_connection(ioc, endpoint_pair),
          core_(core),
          pcb_(pcb)
    {
    }
    ~udp_proxy()
    {
        spdlog::info("UDP disconnect: {0}", endpoint_pair().to_string());
    }

public:
    void start()
    {
        lwip::lwip_udp_set_timeout(pcb_, 1000 * 60);
        lwip::lwip_udp_timeout(pcb_, [this](struct udp_pcb* pcb) {
            if (pcb == nullptr)
                return;
            do_close();
        });
        lwip::lwip_udp_recv(pcb_, std::bind(&udp_proxy::on_udp_recved,
                                            this,
                                            std::placeholders::_1,
                                            std::placeholders::_2,
                                            std::placeholders::_3,
                                            std::placeholders::_4,
                                            std::placeholders::_5));
        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(endpoint_pair(),
                                                             proxy_endpoint_);
                if (!socket_ || !pcb_) {
                    do_close();
                    co_return;
                }

                boost::system::error_code ec;
                for (;;) {
                    toys::wrapper::pbuf_buffer buffer(4096);

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
                    net_monitor().update_download_bytes(bytes);
                    buffer.realloc(bytes);
                    lwip::lwip_udp_send(pcb_, &buffer);
                }
            },
            boost::asio::detached);
    }

private:
    void on_udp_recved(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port)
    {
        if (pcb == nullptr)
            return;

        if (!socket_)
            return;

        if (send_queue_.size() >= 10)
            return;

        toys::wrapper::pbuf_buffer buffer(p, false);

        bool write_in_process = !send_queue_.empty();
        send_queue_.push(buffer);
        if (write_in_process)
            return;

        boost::asio::co_spawn(
            get_io_context(), [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                while (!send_queue_.empty()) {
                    const auto& buffer = send_queue_.front();

                    auto bytes = co_await socket_->async_send_to(buffer.data(),
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
                    net_monitor().update_upload_bytes(bytes);
                    send_queue_.pop();
                }
            },
            boost::asio::detached);
    }
    void do_close()
    {
        if (pcb_) {
            lwip::lwip_udp_timeout(pcb_, nullptr);
            lwip::lwip_udp_recv(pcb_, nullptr);
            lwip::lwip_udp_disconnect(pcb_);
            pcb_ = nullptr;

            if (socket_ && socket_->is_open()) {
                boost::system::error_code ec;
                socket_->close(ec);
            }
            core_.close_endpoint_pair(endpoint_pair());
        }
    }

private:
    struct udp_pcb*               pcb_ = nullptr;
    core_impl_api::udp_socket_ptr socket_;
    core_impl_api&                core_;

    std::queue<toys::wrapper::pbuf_buffer> send_queue_;
    boost::asio::ip::udp::endpoint         proxy_endpoint_;
};
}  // namespace tun2socks