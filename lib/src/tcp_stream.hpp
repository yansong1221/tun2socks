
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

public:
    tcp_stream(tuntap::tuntap &tuntap, const transport_layer::tcp_endpoint_pair &endpoint_pair)
        : tuntap_(tuntap)
        , socket_(tuntap.get_executor())
        , state_(tcp_state::ts_listen)
        , local_endpoint_pair_(endpoint_pair)
        , remote_endpoint_pair_(endpoint_pair.swap())
    {}

    bool closed() const { return state_ == tcp_state::ts_closed; }

    boost::asio::awaitable<void> on_tcp_packet(const tcp_packet &packet)
    {
        auto flags = packet.header_data().flags;
        auto seq_num = packet.header_data().seq_num;
        auto ack_num = packet.header_data().ack_num;
        auto window_size = packet.header_data().window_size;

        switch (state_) {
        case tcp_state::ts_closed:
            break;
        case tcp_state::ts_listen: {
            //这里说明已经在连接远程了
            if (socket_.is_open())
                co_return;

            if (!flags.flag.syn) {
                state_ = tcp_state::ts_closed;
                co_return;
            }

            //这里应该要试试连接远程
            boost::system::error_code ec;
            if (local_endpoint_pair_.to_address_pair().ip_version() == 4) {
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

            auto dest_endpoint = packet.endpoint_pair().dest;
            co_await socket_.async_connect(dest_endpoint, net_awaitable[ec]);
            if (ec) {
                SPDLOG_WARN("cant conect tcp endpoint [{0}]:{1}",
                            dest_endpoint.address().to_string(),
                            dest_endpoint.port());
                state_ = tcp_state::ts_closed;
                co_return;
            }
            state_ = tcp_state::ts_syn_rcvd;

            next_server_ack_num_ = seq_num + 1;
            next_client_ack_num_ = server_seq_num_ + 1;
            client_window_size_ = window_size;

            tcp_packet::tcp_flags flags;
            flags.flag.syn = 1;
            flags.flag.ack = 1;
            co_await write_packet(flags);

            co_return;

        } break;
        case tcp_state::ts_syn_rcvd: {
            if (!flags.flag.ack) {
                co_return;
            }

            if (ack_num != next_client_ack_num_ || seq_num != next_server_ack_num_) {
                co_return;
            }
            server_seq_num_ = next_client_ack_num_;
            client_window_size_ = window_size;

            state_ = tcp_state::ts_established;
            boost::asio::co_spawn(socket_.get_executor(), start_read(), boost::asio::detached);
            co_return;
        } break;
        case tcp_state::ts_established: {
            if (!flags.flag.ack) {
                co_return;
            }
            if (ack_num != next_client_ack_num_ || seq_num != next_server_ack_num_)
                co_return;

            if (flags.flag.rst) {
                state_ = tcp_state::ts_close_wait;
                co_return;
            }
            client_window_size_ = window_size;

            //结束包 进行4次挥手
            if (flags.flag.fin) {
                next_server_ack_num_++;

                tcp_packet::tcp_flags flags;
                flags.flag.ack = true;
                co_await write_packet(flags);

                flags.flag.fin = true;
                co_await write_packet(flags);

                state_ = tcp_state::ts_close_wait;
                co_return;
            }

            //接收数据
            if (flags.flag.psh) {
                next_server_ack_num_ += packet.payload().size();

                tcp_packet::tcp_flags flags;
                flags.flag.ack = true;
                co_await write_packet(flags);

                boost::system::error_code ec;
                co_await boost::asio::async_write(socket_, packet.payload(), net_awaitable[ec]);
                co_return;
            }
            if (server_seq_num_ != next_client_ack_num_) {
                server_seq_num_ = next_client_ack_num_;
                boost::asio::co_spawn(socket_.get_executor(), start_read(), boost::asio::detached);
            }

        } break;
        case transport_layer::tcp_stream::tcp_state::ts_fin_wait_1:
            break;
        case transport_layer::tcp_stream::tcp_state::ts_fin_wait_2:
            break;
        case tcp_state::ts_close_wait: {
            auto flags = packet.header_data().flags;
            if (!flags.flag.ack) {
                co_return;
            }
            auto ack_num = packet.header_data().ack_num;

            if (ack_num != next_client_ack_num_) {
                co_return;
            }
            state_ = tcp_state::ts_closed;
            co_return;

        } break;
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

    boost::asio::awaitable<void> write_packet(
        tcp_packet::tcp_flags flags,
        const boost::asio::const_buffer &payload = boost::asio::const_buffer())
    {
        return write_packet(flags, server_seq_num_, next_server_ack_num_, payload);
    }
    boost::asio::awaitable<void> write_packet(
        tcp_packet::tcp_flags flags,
        uint32_t seq_num,
        uint32_t ack_num,
        const boost::asio::const_buffer &payload = boost::asio::const_buffer())
    {
        tcp_packet::header header_data;
        header_data.seq_num = seq_num;
        header_data.ack_num = ack_num;
        header_data.flags = flags;

        tcp_packet tcp_pack(remote_endpoint_pair_, header_data, payload);
        co_await write_tuntap_tcp_packet(tcp_pack);
    }

    boost::asio::awaitable<void> start_read()
    {
        if (client_window_size_ == 0)
            co_return;

        boost::system::error_code ec;
        boost::asio::streambuf read_buffer;
        auto bytes = co_await socket_.async_read_some(read_buffer.prepare(
                                                          std::max<uint16_t>(0x0FFF,
                                                                             client_window_size_)),
                                                      net_awaitable[ec]);
        if (state_ != tcp_state::ts_established) {
            co_return;
        }
        //远程关闭连接
        if (ec) {
            co_return;
        }
        read_buffer.commit(bytes);

        next_server_ack_num_ += bytes;

        tcp_packet::tcp_flags flags;
        flags.flag.ack = true;
        flags.flag.psh = true;

        co_await write_packet(flags, read_buffer.data());
    }

private:
    boost::asio::awaitable<void> write_tuntap_tcp_packet(const tcp_packet &packet) const
    {
        boost::asio::streambuf buffer;
        packet.make_ip_packet(buffer);
        boost::system::error_code ec;
        co_await tuntap_.async_write_some(buffer.data(), net_awaitable[ec]);
    }

private:
    tuntap::tuntap &tuntap_;
    boost::asio::ip::tcp::socket socket_;

    transport_layer::tcp_endpoint_pair local_endpoint_pair_;
    transport_layer::tcp_endpoint_pair remote_endpoint_pair_;

    uint32_t next_server_ack_num_ = 0; //服务器下一次找客户端需要发送的序列号
    uint32_t next_client_ack_num_ = 0; //客户端下一次找服务器需要发送的序列号
    uint16_t client_window_size_ = 0xFFFF;

    uint32_t server_seq_num_ = 0;

    tcp_state state_;
};
} // namespace transport_layer
