#pragma once
#include "core_impl_api.h"
#include "lwip.hpp"
#include "network_monitor.hpp"
#include "pbuf.hpp"
#include <boost/asio.hpp>
#include <queue>
#include <spdlog/spdlog.h>
#include <tun2socks/connection.h>

namespace tun2socks {

class udp_proxy : public connection, public std::enable_shared_from_this<udp_proxy> {
public:
    using ptr = std::shared_ptr<udp_proxy>;

    explicit udp_proxy(boost::asio::io_context& ioc,
                       const udp_endpoint_pair& endpoint_pair,
                       struct udp_pcb*          pcb,
                       core_impl_api&           core)
        : ioc_(ioc),
          net_monitor_(std::make_shared<network_monitor>(ioc)),
          core_(core),
          pcb_(pcb),
          local_endpoint_pair_(endpoint_pair)
    {
    }
    ~udp_proxy()
    {
        spdlog::info("UDP disconnect: {0}", local_endpoint_pair_.to_string());
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
            ioc_, [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
                socket_ = co_await core_.create_proxy_socket(local_endpoint_pair_,
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
                    net_monitor_->update_download_bytes(bytes);
                    buffer.realloc(bytes);
                    lwip::lwip_udp_send(pcb_, &buffer);
                }
            },
            boost::asio::detached);
        net_monitor_->start();
    }

public:
    conn_type type() const override
    {
        return connection::conn_type::udp;
    }
    std::string local_endpoint() const override
    {
        auto result = std::make_shared<std::promise<std::string>>();
        ioc_.dispatch([this, result]() mutable {
            result->set_value(fmt::format("[{}]:{}",
                                          local_endpoint_pair_.src.address().to_string(),
                                          local_endpoint_pair_.src.port()));
        });
        return result->get_future().get();
    }
    std::string remote_endpoint() const override
    {
        auto result = std::make_shared<std::promise<std::string>>();
        ioc_.dispatch([this, result]() mutable {
            result->set_value(fmt::format("[{}]:{}",
                                          local_endpoint_pair_.dest.address().to_string(),
                                          local_endpoint_pair_.dest.port()));
        });
        return result->get_future().get();
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
            ioc_, [this, self = shared_from_this()]() -> boost::asio::awaitable<void> {
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
                    net_monitor_->update_upload_bytes(bytes);
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
            net_monitor_->stop();
            core_.close_endpoint_pair(local_endpoint_pair_);
        }
    }

private:
    boost::asio::io_context&      ioc_;
    struct udp_pcb*               pcb_ = nullptr;
    core_impl_api::udp_socket_ptr socket_;
    core_impl_api&                core_;

    std::queue<toys::wrapper::pbuf_buffer> send_queue_;

    udp_endpoint_pair local_endpoint_pair_;

    boost::asio::ip::udp::endpoint proxy_endpoint_;

    std::shared_ptr<network_monitor> net_monitor_;
};
}  // namespace tun2socks