#pragma once
#include "wintun_library.hpp"

#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>

class wintun_service
{
public:
    wintun_service(boost::asio::io_context &ioc)
        : ioc_(ioc)
        , receive_event_(ioc)
    {}

    inline void open()
    {
        boost::system::error_code ec;

        auto wintun_library = wintun::library::instance();
        auto wintun_adapter = wintun_library->create_adapter("test", "test");
        auto wintun_adapter2 = wintun_adapter;
        wintun_session_ = wintun_adapter->create_session();

        receive_event_.assign(wintun_session_->read_wait_event());
    }

    inline void close()
    {
        boost::system::error_code ec;
        receive_event_.close(ec);
    }

    template<typename MutableBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) ReadToken>
    auto async_read_some(const MutableBufferSequence &buffers, ReadToken &&handler)
    {
        return boost::asio::async_initiate<ReadToken, void(boost::system::error_code, std::size_t)>(
            [this](auto &&handler, auto &&buffers) {
                receive_event_.async_wait(
                    [this, handler = std::move(handler), buffers = std::move(buffers)](
                        const boost::system::error_code &ec) mutable {
                        if (ec) {
                            handler(ec, 0);
                            return;
                        }
                        boost::system::error_code read_error;
                        auto bytes_transferred = wintun_session_->receive_packet(buffers,
                                                                                 read_error);
                        handler(read_error, bytes_transferred);
                    });
            },
            handler,
            buffers);
    }
    template<typename ConstBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t))
                 WriteHandler>
    auto async_write_some(const ConstBufferSequence &buffers, WriteHandler &&handler)
    {
        return boost::asio::async_initiate<WriteHandler,
                                           void(boost::system::error_code, std::size_t)>(
            [this](auto &&handler, auto &&buffers) mutable {
                boost::asio::dispatch(ioc_,
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
    boost::asio::io_context &ioc_;
    boost::asio::windows::object_handle receive_event_;
    std::shared_ptr<wintun::session> wintun_session_;
};