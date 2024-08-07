#include "tun2socks_impl.hpp"
#include <boost/url.hpp>
#include <spdlog/spdlog.h>
#include <tun2socks/tun2socks.h>

tun2socks::tun2socks()
{
    impl_ = new tun2socks_impl();
}
tun2socks ::~tun2socks()
{
    delete impl_;
}

void tun2socks::start(const tun_parameter& tun_param,
                      const std::string&   socks5_url)
{
    boost::urls::url_view parsed_url(socks5_url);
    if (parsed_url.scheme() != "socks5")
        throw std::runtime_error(fmt::format("Only supports socks5 your scheme is  {}",
                                             std::string(parsed_url.scheme())));

    tun2socks_impl::socks5_proxy_info proxy_info;
    proxy_info.host     = parsed_url.host();
    proxy_info.port     = parsed_url.port_number();
    proxy_info.username = parsed_url.user();
    proxy_info.password = parsed_url.password();

    tuntap::tun_parameter param;
    param.tun_name = tun_param.tun_name;

    if (tun_param.ipv4) {
        tuntap::tun_parameter::address tun_ipv4;
        tun_ipv4.addr          = boost::asio::ip::make_address_v4(tun_param.ipv4->addr);
        tun_ipv4.dns           = boost::asio::ip::make_address_v4(tun_param.ipv4->dns);
        tun_ipv4.prefix_length = tun_param.ipv4->prefix_length;
        param.ipv4             = tun_ipv4;
    }

    if (tun_param.ipv6) {
        tuntap::tun_parameter::address tun_ipv6;
        tun_ipv6.addr          = boost::asio::ip::make_address_v6(tun_param.ipv6->addr);
        tun_ipv6.dns           = boost::asio::ip::make_address_v6(tun_param.ipv6->addr);
        tun_ipv6.prefix_length = tun_param.ipv6->prefix_length;
        param.ipv6             = tun_ipv6;
    }
    impl_->start(param, proxy_info);
}
