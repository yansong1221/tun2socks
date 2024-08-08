#include "core_impl.hpp"
#include <boost/url.hpp>
#include <spdlog/spdlog.h>
#include <tun2socks/core.h>

using namespace tun2socks;

core::core()
{
    impl_ = new core_impl();
}
core ::~core()
{
    delete impl_;
}

bool core::start(const parameter::tun_device&    tun_param,
                 const parameter::socks5_server& socks5_param)
{
    return impl_->start(tun_param, socks5_param);
}

tun2socks::proxy_policy& core::proxy_policy()
{
    return impl_->proxy_policy();
}

void core::wait()
{
    impl_->wait();
}

void core::stop()
{
    impl_->stop_thread();
}

void core::set_connection_open_function(connection::open_function handle)
{
    impl_->set_connection_open_function(handle);
}

void core::set_connection_close_function(connection::open_function handle)
{
    impl_->set_connection_close_function(handle);
}
std::vector<connection::weak_ptr> core::udp_connections() const
{
    auto result = impl_->udp_connections();
    return result.get();
}
std::vector<connection::weak_ptr> core::tcp_connections() const
{
    auto result = impl_->tcp_connections();
    return result.get();
}