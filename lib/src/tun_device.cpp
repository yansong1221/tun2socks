#include "tun_device.h"

tun_device::tun_device()
{
    ip_layer_stack_ = std::make_unique<ip_layer_stack>(pool_.getIOContext());
    ip_layer_stack_->start();
    pool_.Start();
    pool_.Wait();
}