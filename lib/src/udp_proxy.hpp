#pragma once
#include "basic_connection.hpp"
#include "core_impl_api.h"
#include "lwip.hpp"
#include "pbuf.hpp"
#include <boost/asio.hpp>
#include <queue>
#include <spdlog/spdlog.h>
#include <tun2socks/connection.h>

namespace tun2socks {
using namespace std::chrono_literals;
class udp_proxy : public udp_basic_connection {
public:
    using ptr = std::shared_ptr<udp_proxy>;

    explicit udp_proxy(boost::asio::io_context& ioc,
                       lwip::udp_conn::ptr      conn,
                       core_impl_api&           core)
        : udp_basic_connection(ioc, conn->endp_pair()),
          core_(core),
          conn_(conn),
          timeout_timer_(ioc)
    {
        lwip::lwip_udp_recv(pcb_, std::bind(&udp_proxy::on_udp_recved,
                                            this,
                                            std::placeholders::_1,
                                            std::placeholders::_2,
                                            std::placeholders::_3,
                                            std::placeholders::_4,
                                            std::placeholders::_5));
    }
    ~udp_proxy()
    {
        spdlog::info("UDP disconnect: {0}", endpoint_pair().to_string());
    }

protected:
    virtual void on_connection_start() override
    {
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

                    wrapper::pbuf_buffer buffer(4096);

                    auto bytes = co_await socket_->async_receive_from(buffer.data(),
                                                                      proxy_endpoint_,
                                                                      net_awaitable[ec]);
                    if (ec) {
                        // spdlog::warn("Failed to receive UDP data from the remote end : [{}]:{} {}",
                        //              proxy_endpoint_.address().to_string(),
                        //              proxy_endpoint_.port(),
                        //              ec.message());
                        do_close();
                        co_return;
                    }
                    if (!pcb_)
                        co_return;
                    update_download_bytes(bytes);
                    buffer.realloc(bytes);
                    lwip::lwip_udp_send(pcb_, &buffer);
                }
            },
            boost::asio::detached);
    }
    virtual void on_connection_stop() override
    {
        if (!pcb_)
            return;

        lwip::lwip_udp_recv(pcb_, nullptr);
        lwip::lwip_udp_disconnect(pcb_);
        lwip::lwip_udp_remove(pcb_);
        pcb_ = nullptr;

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
    void on_udp_recved(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port)
    {
        if (pcb_ == nullptr)
            return;

        if (!socket_)
            return;

        auto buffer = wrapper::pbuf_buffer::smart_copy(p);
        pbuf_free(p);

        reset_timeout_timer();
        socket_->async_send_to(
            buffer.data(), proxy_endpoint_,
            [this, buffer, self = shared_from_this()](const boost::system::error_code& ec, std::size_t bytes) {
                if (ec) {
                    // spdlog::warn("Sending UDP data failed: [{}]:{} {}",
                    //              proxy_endpoint_.address().to_string(),
                    //              proxy_endpoint_.port(),
                    //              ec.message());
                    do_close();
                    return;
                }
                update_upload_bytes(bytes);
            });
    }
    void do_close()
    {
        core_.close_endpoint_pair(shared_from_this());
    }

private:
    lwip::udp_conn::ptr conn_;

    core_impl_api::udp_socket_ptr socket_;
    core_impl_api&                core_;

    boost::asio::ip::udp::endpoint proxy_endpoint_;

    boost::asio::steady_timer timeout_timer_;
};
}  // namespace tun2socks