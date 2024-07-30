#pragma once
#include <boost/asio.hpp>
namespace tuntap {
template<typename Device>
class basic_tuntap
{
public:
    typedef typename Device device_type;

    explicit basic_tuntap(boost::asio::io_context &ioc)
        : ioc_(ioc)
        , device_(ioc)
    {}
    inline void open(const std::string &tun_name,
                     const boost::asio::ip::address_v4 &ipv4_addr,
                     const boost::asio::ip::address_v6 &ipv6_addr)
    {
        device_.open(tun_name, ipv4_addr, ipv6_addr);
    }
    inline void close() { device_.close(); }

    auto get_executor() noexcept { return ioc_.get_executor(); }

    template<typename MutableBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) ReadToken>
    auto async_read_some(const MutableBufferSequence &buffers, ReadToken &&handler)
    {
        return device_.async_read_some(buffers, handler);
    }
    template<typename ConstBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t))
                 WriteHandler>
    auto async_write_some(const ConstBufferSequence &buffers, WriteHandler &&handler)
    {
        return device_.async_write_some(buffers, handler);
    }
    template<typename ConstBufferSequence>
    void write(const ConstBufferSequence &buffers, boost::system::error_code &ec)
    {
        device_.write(buffers, ec);
    }

private:
    boost::asio::io_context &ioc_;
    device_type device_;
};
} // namespace tuntap