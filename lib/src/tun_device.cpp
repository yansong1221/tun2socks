#include "tun_device.h"

tun_device::tun_device()
{
    ip_layer_stack_ = std::make_unique<ip_layer_stack>();
    ip_layer_stack_->start();
    
}