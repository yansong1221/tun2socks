#include "tun_device.h"

tun_device::tun_device()
{
    ip_layer_stack_.start();   
}