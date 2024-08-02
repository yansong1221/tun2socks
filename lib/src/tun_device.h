#pragma once
#include "io_context_pool.hpp"
#include "ip_layer_stack.hpp"
#include "tuntap/tuntap.hpp"
#include <boost/asio.hpp>
class tun_device
{
public:
    tun_device();

private:
    std::unique_ptr<ip_layer_stack> ip_layer_stack_;
};