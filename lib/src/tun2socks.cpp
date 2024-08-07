#include "tun2socks_impl.hpp"
#include <tun2socks/tun2socks.h>

tun2socks::tun2socks()
{
    impl_ = new tun2socks_impl();
}
tun2socks ::~tun2socks()
{
    delete impl_;
}
void tun2socks::start()
{
    impl_->start();
}
