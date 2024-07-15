#pragma once
#include <boost/asio.hpp>
#include "wintun_service.h"

class tun_device
{
public:
    tun_device();

private:
    boost::asio::io_context ioc_;
    wintun_service wintun_service_;
};