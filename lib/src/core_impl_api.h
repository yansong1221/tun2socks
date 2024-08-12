#pragma once
#include "endpoint_pair.hpp"

namespace tun2socks {

class core_impl_api {
public:
    virtual ~core_impl_api() = default;

    using tcp_socket_ptr = std::shared_ptr<boost::asio::ip::tcp::socket>;
    using udp_socket_ptr = std::shared_ptr<boost::asio::ip::udp::socket>;

    virtual boost::asio::awaitable<tcp_socket_ptr>
    create_proxy_socket(
        const tcp_endpoint_pair& endpoint_pair) = 0;
    virtual boost::asio::awaitable<udp_socket_ptr>
    create_proxy_socket(
        const udp_endpoint_pair&        endpoint_pair,
        boost::asio::ip::udp::endpoint& proxy_endpoint) = 0;

    virtual void close_endpoint_pair(const udp_endpoint_pair& endp_pair) = 0;
    virtual void close_endpoint_pair(const tcp_endpoint_pair& endp_pair) = 0;
};
}  // namespace tun2socks