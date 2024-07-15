#include "tun_device.h"

tun_device::tun_device() : wintun_service_(ioc_)
{
    wintun_service::initialize_wintun();
    wintun_service_.open();

}
