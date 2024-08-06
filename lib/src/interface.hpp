#pragma once
#include "endpoint_pair.hpp"

namespace abstract {
class tun2socks
{
public:
    virtual ~tun2socks() = default;

    using tcp_socket_ptr = std::shared_ptr<boost::asio::ip::tcp::socket>;
    using udp_socket_ptr = std::shared_ptr<boost::asio::ip::udp::socket>;

    virtual boost::asio::awaitable<tcp_socket_ptr>
    create_proxy_socket(const transport_layer::tcp_endpoint_pair &endpoint_pair) = 0;
    virtual boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        const transport_layer::udp_endpoint_pair &endpoint_pair,
        boost::asio::ip::udp::endpoint &proxy_endpoint)
        = 0;
};
}; // namespace abstract