#pragma once
#include "tuntap.hpp"
#include <boost/asio.hpp>

class tun_device
{
public:
    tun_device();

private:
    boost::asio::io_context ioc_;
    tuntap tuntap_;
};