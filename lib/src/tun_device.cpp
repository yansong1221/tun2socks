#include "tun_device.h"
#include "temporary_buffer.hh"
tun_device::tun_device()
{
    seastar::temporary_buffer<char> data;
    data.aligned(10, 10);
    ip_layer_stack_ = std::make_unique<ip_layer_stack>(pool_.getIOContext());
    ip_layer_stack_->start();
    pool_.Start();
    pool_.Wait();
}