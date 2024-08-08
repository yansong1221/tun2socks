#pragma once
#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <deque>
#include <tun2socks/parameter.h>

namespace tun2socks {

namespace tuntap {

    template <typename Device>
    class basic_tuntap {
    public:
        using device_type = Device;

        explicit basic_tuntap(boost::asio::io_context& ioc)
            : device_(boost::asio::use_service<device_type>(ioc))
        {
        }
        inline void open(const parameter::tun_device& param, boost::system::error_code& ec)
        {
            device_.open(param, ec);
        }
        inline void close()
        {
            device_.close();
        }

        boost::asio::io_context& get_io_context() noexcept
        {
            return device_.get_io_context();
        }

        template <typename MutableBufferSequence>
        boost::asio::awaitable<std::size_t> async_read_some(const MutableBufferSequence& buffers,
                                                            boost::system::error_code&   ec)
        {
            return device_.async_read_some(buffers, ec);
        }

        template <typename ConstBufferSequence>
        boost::asio::awaitable<std::size_t> async_write_some(const ConstBufferSequence& buffers,
                                                             boost::system::error_code& ec)
        {
            return device_.async_write_some(buffers, ec);
        }

    private:
        device_type& device_;
    };
}  // namespace tuntap
}  // namespace tun2socks