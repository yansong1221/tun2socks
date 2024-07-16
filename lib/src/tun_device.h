#pragma once
#include "platform.hpp"
#ifdef OS_WINDOWS
#include "wintun_service.hpp"
#elif defined(OS_MACOS)
#include "tun_service_mac.hpp"
#endif
#include <boost/asio.hpp>

class tun_device
{
public:
    tun_device();

private:
    boost::asio::io_context ioc_;
#ifdef OS_WINDOWS
    wintun_service wintun_service_;
#elif defined(OS_MACOS)
    tun_service_mac wintun_service_;
#endif
};