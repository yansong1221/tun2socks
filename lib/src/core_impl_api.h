#pragma once
#include "basic_connection.hpp"
#include "endpoint_pair.hpp"

namespace tun2socks {

class core_impl_api {
public:
    virtual ~core_impl_api() = default;

    using tcp_socket_ptr = std::shared_ptr<boost::asio::ip::tcp::socket>;
    using udp_socket_ptr = std::shared_ptr<boost::asio::ip::udp::socket>;

    virtual boost::asio::awaitable<tcp_socket_ptr>
    create_proxy_socket(connection::ptr conn) = 0;

    virtual boost::asio::awaitable<udp_socket_ptr>
    create_proxy_socket(std::shared_ptr<udp_basic_connection> conn,
                        boost::asio::ip::udp::endpoint&       proxy_endpoint) = 0;

    virtual void remove_conn(connection::ptr conn) = 0;
};
}  // namespace tun2socks