#include "tun_device.h"

tun_device::tun_device() : wintun_service_(ioc_)
{
    wintun_service_.open();
}
