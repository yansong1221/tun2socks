#pragma once
#include "endpoint_pair.hpp"
#include "network_monitor.hpp"
#include <tun2socks/connection.h>

namespace tun2socks {

template <typename InternetProtocol>
class basic_connection : public connection, public boost::asio::detail::service_base<basic_connection<InternetProtocol>> {
public:
    basic_connection(boost::asio::io_context&                     ioc,
                     const basic_endpoint_pair<InternetProtocol>& endpoint_pair)
        : boost::asio::detail::service_base<basic_connection<InternetProtocol>>(ioc),
          endpoint_pair_(endpoint_pair)
    {
        net_monitor_ = std::make_shared<network_monitor>(ioc);
        net_monitor_->start();
    }
    ~basic_connection()
    {
        net_monitor_->stop();
    }

public:
    conn_type type() const override
    {
        if constexpr (std::is_same_v<boost::asio::ip::tcp, InternetProtocol>)
            return connection::conn_type::tcp;
        else if constexpr (std::is_same_v<boost::asio::ip::udp, InternetProtocol>)
            return connection::conn_type::udp;
        else
            static_assert(std::is_same_v<InternetProtocol,InternetProtocol>, "error internet protocol");
    }
    std::string local_endpoint() const override
    {
        auto result = std::make_shared<std::promise<std::string>>();
        const_cast<basic_connection*>(this)->get_io_context().dispatch([this, result]() mutable {
            result->set_value(fmt::format("[{}]:{}",
                                          endpoint_pair_.src.address().to_string(),
                                          endpoint_pair_.src.port()));
        });
        return result->get_future().get();
    }
    std::string remote_endpoint() const override
    {
        auto result = std::make_shared<std::promise<std::string>>();
        const_cast<basic_connection*>(this)->get_io_context().dispatch([this, result]() mutable {
            result->set_value(fmt::format("[{}]:{}",
                                          endpoint_pair_.dest.address().to_string(),
                                          endpoint_pair_.dest.port()));
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

    const basic_endpoint_pair<InternetProtocol>& endpoint_pair() const
    {
        return endpoint_pair_;
    };
    tun2socks::network_monitor& net_monitor()
    {
        return *net_monitor_;
    };

private:
    std::shared_ptr<network_monitor>      net_monitor_;
    basic_endpoint_pair<InternetProtocol> endpoint_pair_;
};

using tcp_basic_connection = basic_connection<boost::asio::ip::tcp>;
using udp_basic_connection = basic_connection<boost::asio::ip::udp>;
}  // namespace tun2socks