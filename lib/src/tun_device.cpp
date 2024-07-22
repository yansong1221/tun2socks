#include "tun_device.h"

tun_device::tun_device()
    : tuntap_(ioc_)
    , ip_layer_stack_(ioc_, tuntap_)
{
    tuntap_.open();
    ip_layer_stack_.start();

    ioc_.run();
}