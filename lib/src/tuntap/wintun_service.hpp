#pragma once
#include "wintun_library.hpp"

#include "tuntap/basic_tuntap.hpp"
#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>

namespace tuntap {
class wintun_service : public boost::asio::detail::service_base<wintun_service>
{
public:
    wintun_service(boost::asio::io_context &ioc)
        : boost::asio::detail::service_base<wintun_service>(ioc)
        , receive_event_(ioc)
    {}

    inline void open(const tun_parameter &param)
    {
        boost::system::error_code ec;

        auto wintun_library = wintun::library::instance();
        auto wintun_adapter = wintun_library->create_adapter(param);
        wintun_session_ = wintun_adapter->create_session(param);

        receive_event_.assign(wintun_session_->read_wait_event());
    }

    inline void close()
    {
        boost::system::error_code ec;
        receive_event_.close(ec);
    }

    boost::asio::awaitable<recv_buffer_ptr> async_read_some(boost::system::error_code &ec)
    {
        co_await boost::asio::post(this->get_io_context(), boost::asio::use_awaitable);

        for (;;) {
            auto buffer = wintun_session_->receive_packet(ec);
            if (ec || buffer)
                co_return buffer;
            co_await receive_event_.async_wait(net_awaitable[ec]);
            if (ec)
                co_return nullptr;
        }
    }
    template<typename ConstBufferSequence>
    boost::asio::awaitable<std::size_t> async_write_some(const ConstBufferSequence &buffers,
                                                         boost::system::error_code &ec)
    {
        co_await boost::asio::post(this->get_io_context(), boost::asio::use_awaitable);
        wintun_session_->send_packets(buffers, ec);
        if (ec) {
            co_return 0;
        }
        co_return boost::asio::buffer_size(buffers);
    }

private:
    boost::asio::windows::object_handle receive_event_;
    std::shared_ptr<wintun::session> wintun_session_;
};
} // namespace tuntap