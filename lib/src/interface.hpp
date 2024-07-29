#pragma once
#include "tcp_packet.hpp"
#include "udp_packet.hpp"

namespace interface {
class tun2socks
{
public:
    virtual ~tun2socks() = default;
    virtual void write_tun_packet(const transport_layer::tcp_packet &pack) = 0;
    virtual void write_tun_packet(const transport_layer::udp_packet &pack) = 0;
    virtual void close_endpoint_pair(const transport_layer::tcp_endpoint_pair &endpoint_pair) = 0;
    virtual void close_endpoint_pair(const transport_layer::udp_endpoint_pair &endpoint_pair) = 0;

    using tcp_socket_ptr = std::shared_ptr<boost::asio::ip::tcp::socket>;
    using udp_socket_ptr = std::shared_ptr<boost::asio::ip::udp::socket>;

    virtual boost::asio::awaitable<tcp_socket_ptr>
    create_proxy_socket(const transport_layer::tcp_endpoint_pair &endpoint_pair) = 0;
    virtual boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        const transport_layer::udp_endpoint_pair &endpoint_pair,
        boost::asio::ip::udp::endpoint &proxy_endpoint)
        = 0;
};
}; // namespace interface