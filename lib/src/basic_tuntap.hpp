#pragma once
#include <boost/asio.hpp>

template<typename Device>
class basic_tuntap
{
public:
    typedef typename Device device_type;

    explicit basic_tuntap(boost::asio::io_context &ioc)
        : device_(boost::asio::use_service<Device>(ioc))
    {}
    void open() { device_.open(); }

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

private:
    device_type device_;
};