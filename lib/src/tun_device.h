#pragma once
#include "ip_layer_stack.hpp"
#include "tuntap/tuntap.hpp"
#include <boost/asio.hpp>

class tun_device
{
public:
    tun_device();

private:
    boost::asio::io_context ioc_;
    ip_layer_stack ip_layer_stack_;
};