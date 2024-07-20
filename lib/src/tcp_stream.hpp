
/**
* 服务端
初始状态（CLOSED）：

服务器启动并调用 socket() 创建一个套接字，然后调用 bind() 绑定到一个特定的端口。
服务器调用 listen() 进入 LISTEN 状态，等待客户端连接请求。
侦听状态（LISTEN）：

服务器在 LISTEN 状态下等待接收来自客户端的 SYN（同步）请求。
当接收到 SYN 请求时，服务器发送 SYN-ACK（同步-确认）响应，并进入 SYN_RECEIVED 状态。
同步已接收状态（SYN_RECEIVED）：

服务器在 SYN_RECEIVED 状态下等待接收客户端的 ACK（确认）响应。
当接收到 ACK 时，服务器进入 ESTABLISHED 状态，表示连接已建立，可以开始数据传输。
已建立状态（ESTABLISHED）：

在 ESTABLISHED 状态下，服务器和客户端可以进行双向的数据传输。
服务器保持在此状态，直到收到关闭连接的请求。
关闭等待状态（CLOSE_WAIT）：

当服务器收到来自客户端的 FIN（终止）请求时，服务器发送 ACK 响应并进入 CLOSE_WAIT 状态。
服务器在 CLOSE_WAIT 状态下等待应用程序调用 close() 来关闭连接。
最后确认状态（LAST_ACK）：

服务器在 CLOSE_WAIT 状态下调用 close() 后，发送 FIN 请求并进入 LAST_ACK 状态。
服务器在 LAST_ACK 状态下等待接收客户端的 ACK 响应。
关闭状态（CLOSED）：

当服务器在 LAST_ACK 状态下收到 ACK 响应时，连接关闭，服务器进入 CLOSED 状态。
 */

/**
 *客户端

初始状态（CLOSED）：

客户端调用 socket() 创建一个套接字。
客户端调用 connect() 发送 SYN 请求并进入 SYN_SENT 状态。
同步已发送状态（SYN_SENT）：

客户端在 SYN_SENT 状态下等待接收来自服务器的 SYN-ACK 响应。
当接收到 SYN-ACK 响应时，客户端发送 ACK 响应并进入 ESTABLISHED 状态。
已建立状态（ESTABLISHED）：

在 ESTABLISHED 状态下，客户端和服务器可以进行双向的数据传输。
客户端保持在此状态，直到发送关闭连接的请求。
终止等待状态（FIN_WAIT_1）：

当客户端需要关闭连接时，发送 FIN 请求并进入 FIN_WAIT_1 状态。
客户端在 FIN_WAIT_1 状态下等待接收来自服务器的 ACK 响应。
终止等待状态（FIN_WAIT_2）：

当客户端在 FIN_WAIT_1 状态下收到 ACK 响应时，进入 FIN_WAIT_2 状态。
客户端在 FIN_WAIT_2 状态下等待接收来自服务器的 FIN 请求。
时间等待状态（TIME_WAIT）：

当客户端在 FIN_WAIT_2 状态下收到 FIN 请求时，发送 ACK 响应并进入 TIME_WAIT 状态。
客户端在 TIME_WAIT 状态下等待一段时间以确保服务器收到了 ACK 响应，然后进入 CLOSED 状态。
 */
#pragma once
#include "tcp_packet.hpp"
#include "tuntap.hpp"
#include <spdlog/spdlog.h>

namespace transport_layer {

class tcp_stream
{
public:
    using ptr = std::shared_ptr<tcp_stream>;

    enum class tcp_state {
        ts_invalid = -1,
        ts_closed = 0,
        ts_listen = 1,
        ts_syn_sent = 2,
        ts_syn_rcvd = 3,
        ts_established = 4,
        ts_fin_wait_1 = 5,
        ts_fin_wait_2 = 6,
        ts_close_wait = 7,
        ts_closing = 8,
        ts_last_ack = 9,
        ts_time_wait = 10
    };
    union tcp_flags {
        struct unamed_struct
        {
            bool fin : 1;
            bool syn : 1;
            bool rst : 1;
            bool psh : 1;
            bool ack : 1;
            bool urg : 1;
            bool ece : 1;
            bool cwr : 1;
        } flag;
        uint8_t data;
    };

public:
    tcp_stream(tuntap::tuntap &tuntap)
        : tuntap_(tuntap)
        , socket_(tuntap.get_executor())
        , state_(tcp_state::ts_listen)
    {}

    bool closed() const { return state_ == tcp_state::ts_closed; }

    boost::asio::awaitable<void> on_tcp_packet(const tcp_packet &packet)
    {
        switch (state_) {
        case tcp_state::ts_closed:
            break;
        case tcp_state::ts_listen: {
            tcp_flags flags;
            flags.data = packet.flags();

            if (!flags.flag.syn) {
                state_ = tcp_state::ts_closed;
                co_return;
            }
            //这里应该要试试连接远程
            boost::system::error_code ec;
            if (packet.ip_version() == network_layer::ip_packet::version_type::v4) {
                socket_.open(boost::asio::ip::tcp::v4());
                socket_.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::from_string(
                                                                "192.168.31.152"),
                                                            0),
                             ec);
            }

            else {
                socket_.open(boost::asio::ip::tcp::v6());
                socket_.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::from_string(
                                                                "fe80::bab1:8f1d:f035:de5b%11"),
                                                            0),
                             ec);
            }

            if (ec) {
                SPDLOG_INFO("bind {0}", ec.message());
                state_ = tcp_state::ts_closed;
                co_return;
            }

           /* auto dest_endpoint = packet.endpoint_pair().dest;
            co_await socket_.async_connect(dest_endpoint, net_awaitable[ec]);
            if (ec) {
                SPDLOG_INFO("conect tcp endpoint [{0}]:{1}",
                            dest_endpoint.address().to_string(),
                            dest_endpoint.port());
                state_ = tcp_state::ts_closed;
                co_return;
            }*/
            state_ = tcp_state::ts_syn_rcvd;

            tcp_flags write_flags = {0};
            write_flags.flag.syn = 1;
            write_flags.flag.ack = 1;
            tcp_packet write_pack(packet.ip_version(),
                                  packet.endpoint_pair().swap(),
                                  seq_num_,
                                  packet.seq_num() + 1,
                                  write_flags.data);
            co_await write_tcp_packet(write_pack);
            co_return;

        } break;
        case tcp_state::ts_syn_rcvd: {
            tcp_flags flags;
            flags.data = packet.flags();
            if (!flags.flag.ack) {
                co_return;
            }

            if (packet.ack_num() != seq_num_ + 1) {
                co_return;
            }
            state_ = tcp_state::ts_established;
            co_return;
        } break;
        case transport_layer::tcp_stream::tcp_state::ts_established:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_fin_wait_1:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_fin_wait_2:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_close_wait:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_closing:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_last_ack:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_time_wait:
            break;
        default:
            break;
        }
    }

private:
    boost::asio::awaitable<void> write_tcp_packet(const tcp_packet &packet) const
    {
        boost::asio::streambuf buffer;
        packet.make_ip_packet(buffer);
        boost::system::error_code ec;
        co_await tuntap_.async_write_some(buffer.data(), net_awaitable[ec]);
    }

private:
    tuntap::tuntap &tuntap_;
    boost::asio::ip::tcp::socket socket_;

    uint32_t c_seq_num_ = 0;

    uint32_t seq_num_ = 1;

    tcp_state state_;
};
} // namespace transport_layer
