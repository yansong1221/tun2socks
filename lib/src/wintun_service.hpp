#pragma once
#include "wintun_library.hpp"

#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>

// 定义IP包头的结构体
struct Ipv4Header {
    uint8_t ihl : 4; // 头部长度
    uint8_t version : 4; // 版本
    uint8_t tos; // 服务类型
    uint16_t totalLength; // 总长度
    uint16_t identification; // 标识符
    uint16_t flagsAndOffset; // 标志和片偏移
    uint8_t ttl; // 生存时间
    uint8_t protocol; // 协议
    uint16_t checksum; // 头部校验和
    uint32_t sourceIp; // 源IP地址
    uint32_t destIp; // 目的IP地址
};

class wintun_service {
public:
    wintun_service(boost::asio::io_context& ioc)
        : ioc_(ioc)
        , receive_event_(ioc)
    {
    }

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
            co_await receive_event_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));

            if (ec)
                co_return;

            wintun_session_->receive_packet(std::bind(&wintun_service::on_packet, this, std::placeholders::_1, std::placeholders::_2));
        }
    };

private:
    void on_packet(BYTE* data, DWORD size)
    {
    }

private:
    boost::asio::io_context& ioc_;
    boost::asio::windows::object_handle receive_event_;
    std::shared_ptr<wintun::session> wintun_session_;
};