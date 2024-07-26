#include "tun_device.h"
#include "route/route.hpp"

tun_device::tun_device()
    : tuntap_(ioc_)
    , ip_layer_stack_(ioc_, tuntap_)
{
    auto result = route::get_default_ipv4_route();

    SPDLOG_INFO("if_addr: {0}", result->if_addr.to_string());
    //sock.local_endpoint();

    tuntap_.open();
    ip_layer_stack_.start();

    ioc_.run();
}