#pragma once
#include "tuntap.hpp"
#include <boost/asio.hpp>
#include "ip_layer_stack.hpp"

class tun_device
{
public:
    tun_device();

public:
    boost::asio::awaitable<void> co_receive_packet();

private:
    boost::asio::io_context ioc_;
    tuntap tuntap_;
    ip_layer_stack ip_layer_stack_;
};