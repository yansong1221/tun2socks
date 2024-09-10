#include "core_impl.hpp"
#include <spdlog/spdlog.h>
#include <tun2socks/core.h>

#include <boost/asio.hpp>
#include <boost/url.hpp>
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

std::vector<connection::weak_ptr> core::connections() const
{
    return impl_->connections();
}

void core::parse_socks5_url(const std::string&        url,
                            parameter::socks5_server& socks5_param)
{
    boost::urls::url url_parser(url);
    if (url_parser.scheme() != "socks5")
        throw std::runtime_error("URL only supports SOCKS5 protocol");

    socks5_param.host     = url_parser.host();
    socks5_param.port     = std::stoi(url_parser.port());
    socks5_param.username = url_parser.user();
    socks5_param.password = url_parser.password();
}

void core::parse_cidr_addr(const std::string& cidr,
                           std::string&       ip,
                           uint8_t&           prefix_length)
{
    boost::system::error_code ec;

    auto net_v4 = boost::asio::ip::make_network_v4(cidr, ec);
    if (!ec) {
        ip            = net_v4.address().to_string();
        prefix_length = net_v4.prefix_length();
        return;
    }
    auto net_v6   = boost::asio::ip::make_network_v6(cidr);
    ip            = net_v6.address().to_string();
    prefix_length = net_v6.prefix_length();
}
