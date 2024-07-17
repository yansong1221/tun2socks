#include "tun_device.h"

tun_device::tun_device()
    : tuntap_(ioc_)
{
    tuntap_.open();
}
