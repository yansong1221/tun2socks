#pragma once
#include "wintun_library.hpp"

#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>

// 定义IP包头的结构体
struct Ipv4Header
{
    uint8_t ihl : 4;         // 头部长度
    uint8_t version : 4;     // 版本
    uint8_t tos;             // 服务类型
    uint16_t totalLength;    // 总长度
    uint16_t identification; // 标识符
    uint16_t flagsAndOffset; // 标志和片偏移
    uint8_t ttl;             // 生存时间
    uint8_t protocol;        // 协议
    uint16_t checksum;       // 头部校验和
    uint32_t sourceIp;       // 源IP地址
    uint32_t destIp;         // 目的IP地址
};

class wintun_service
{
    class initiate_async_read_some;

public:
    wintun_service(boost::asio::io_context &ioc)
        : ioc_(ioc)
        , receive_event_(ioc)
    {}
    using executor_type = typename boost::asio::io_context::executor_type;
    void open()
    {
        boost::system::error_code ec;

        auto wintun_library = wintun::library::instance();
        auto wintun_adapter = wintun_library->create_adapter("test", "test");
        auto wintun_adapter2 = wintun_adapter;
        wintun_session_ = wintun_adapter->create_session();

        receive_event_.assign(wintun_session_->read_wait_event());

        boost::asio::co_spawn(ioc_, co_receive_packet(), boost::asio::detached);
        ioc_.run();
    }
    boost::asio::awaitable<void> co_receive_packet()
    {
        for (;;) {
            boost::system::error_code ec;
            boost::asio::streambuf buffer;
            auto bytes = co_await async_read_some(buffer.prepare(64 * 1024), net_awaitable[ec]);
            if (ec)
                co_return;
        }
    };

    template<typename MutableBufferSequence,
             BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) ReadToken>
    auto async_read_some(const MutableBufferSequence &buffers, ReadToken &&handler)
    {
        return boost::asio::async_initiate<ReadToken, void(boost::system::error_code, std::size_t)>(
            [this](auto &&handler, auto &&buffers) {
                receive_event_.async_wait(
                    [&, handler = std::move(handler), buffers = std::move(buffers)](
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
            [this](auto &&handler, auto &&buffers) { wintun_session_->send_packets(buffers); },
            handler,
            buffers);
    }

private:
private:
    boost::asio::io_context &ioc_;
    boost::asio::windows::object_handle receive_event_;
    std::shared_ptr<wintun::session> wintun_session_;
};