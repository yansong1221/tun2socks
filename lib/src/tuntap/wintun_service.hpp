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

    template<BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, recv_buffer_ptr))
                 ReadToken>
    auto async_read_some(ReadToken &&handler)
    {
        return boost::asio::async_initiate<ReadToken,
                                           void(boost::system::error_code, recv_buffer_ptr)>(
            [this](auto &&handler) {
                boost::system::error_code read_error;
                auto buffer = wintun_session_->receive_packet(read_error);
                if (read_error || buffer) {
                    handler(read_error, buffer);
                    return;
                }

                receive_event_.async_wait([this, handler = std::move(handler)](
                                              const boost::system::error_code &ec) mutable {
                    if (ec) {
                        handler(ec, nullptr);
                        return;
                    }
                    this->async_read_some(handler);
                });
            },
            handler);
    }
    template<typename ConstBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t))
                 WriteHandler>
    auto async_write_some(const ConstBufferSequence &buffers, WriteHandler &&handler)
    {
        return boost::asio::async_initiate<WriteHandler,
                                           void(boost::system::error_code, std::size_t)>(
            [this](auto &&handler, auto &&buffers) mutable {
                boost::asio::post(this->get_io_context(),
                                  [this,
                                   handler = std::move(handler),
                                   buffers = std::move(buffers)]() mutable {
                                      boost::system::error_code ec;
                                      wintun_session_->send_packets(buffers, ec);
                                      if (ec) {
                                          handler(ec, 0);
                                          return;
                                      }
                                      handler(ec, boost::asio::buffer_size(buffers));
                                  });
            },
            handler,
            buffers);
    }

private:
    boost::asio::windows::object_handle receive_event_;
    std::shared_ptr<wintun::session> wintun_session_;
};
} // namespace tuntap