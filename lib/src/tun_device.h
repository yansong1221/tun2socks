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
    boost::asio::io_context ioc_;
    std::unique_ptr<ip_layer_stack> ip_layer_stack_;
    toys::pool::IOContextPool<1, 1> pool_;
};