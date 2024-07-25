#pragma once
#include <cstring> // for std::memcpy
#include <functional>
#include <iostream>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/streambuf.hpp>

#include "tcp_packet.hpp"
#include "tuntap.hpp"
#include <spdlog/spdlog.h>

namespace avpncore {

// 定义接收到tcp连接请求时的accept handler, 每个tcp连接收到
// syn将会触发这个handler的调用, 在这个handler中, 需要确认
// 是否接受或拒绝这个tcp连接, 如果拒绝将会发回一个rst/fin的
// 数据包, 在这个handler里使用accept函数来确认是否接受这个
// syn连接请求.

class tcp_stream : public std::enable_shared_from_this<tcp_stream>
{
    enum tcp_state {
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

    std::string tcp_state_string(tcp_state s) const
    {
        switch (s) {
        case ts_invalid:
            return "ts_invalid";
        case ts_closed:
            return "ts_closed";
        case ts_listen:
            return "ts_listen";
        case ts_syn_sent:
            return "ts_syn_sent";
        case ts_syn_rcvd:
            return "ts_syn_rcvd";
        case ts_established:
            return "ts_established";
        case ts_fin_wait_1:
            return "ts_fin_wait_1";
        case ts_fin_wait_2:
            return "ts_fin_wait_2";
        case ts_close_wait:
            return "ts_close_wait";
        case ts_closing:
            return "ts_closing";
        case ts_last_ack:
            return "ts_last_ack";
        case ts_time_wait:
            return "ts_time_wait";
        }
        return "error tcp state";
    }

    struct tsm // tcp state machine
    {
        tsm()
            : state_(ts_invalid)
            , seq_(0)
            , ack_(0)
            , win_(0)
            , lseq_(0)
            , lack_(0)
            , lwin_(0)
        {}

        tcp_state state_;
        uint32_t seq_;
        uint32_t ack_; // 对端发过来的ack,用来确认是否丢包, 这里不存在丢包所以不用处理.
        uint32_t win_;

        uint32_t lseq_; // 随本端数据 发送而增大.
        uint32_t lack_; // 最后回复的ack, 是seq+收到的数据的大小.
        uint32_t lwin_;
    };

public:
    // write_ip_packet_handler 用于写入一个ip包
    // 到底层.

    using ptr = std::shared_ptr<tcp_stream>;
    using close_function = std::function<void(transport_layer::tcp_endpoint_pair)>;

    close_function close_function_;

    tcp_stream(boost::asio::io_context &io_context,
               tuntap::tuntap &tuntap,
               const transport_layer::tcp_endpoint_pair &endpoint_pair,
               const close_function &func)
        : m_io_context(io_context)
        , m_accepted(false)
        , m_do_closed(false)
        , m_abort(false)
        , close_function_(func)
        , local_endpoint_pair_(endpoint_pair)
        , remote_endpoint_pair_(endpoint_pair.swap())
        , tuntap_(tuntap)
        , socket_(io_context)
    {}

    ~tcp_stream() {}

    // 当用户收到accept得到它的时候，
    // 并向外发起连接后，将状态给回
    // 本地连接时，设置使用.
    // 本地连接根据设置状态发回本地连接.
    enum accept_state {
        ac_allow,
        ac_deny,
        ac_reset,
    };

    boost::asio::awaitable<void> write_tuntap_tcp_packet(
        const transport_layer::tcp_packet &packet) const
    {
        boost::asio::streambuf buffer;
        packet.make_ip_packet(buffer);
        boost::system::error_code ec;
        co_await tuntap_.async_write_some(buffer.data(), net_awaitable[ec]);
    }
    boost::asio::awaitable<void> write_packet(
        transport_layer::tcp_packet::tcp_flags flags,
        uint32_t seq_num,
        uint32_t ack_num,
        const boost::asio::const_buffer &payload = boost::asio::const_buffer())
    {
        transport_layer::tcp_packet::header header_data;
        header_data.seq_num = seq_num;
        header_data.ack_num = ack_num;
        header_data.flags = flags;

        transport_layer::tcp_packet tcp_pack(remote_endpoint_pair_, header_data, payload);
        co_await write_tuntap_tcp_packet(tcp_pack);
    }

    boost::asio::awaitable<void> accept(accept_state state)
    {
        if (m_accepted) {
            do_close();
            co_return;
        }

        m_accepted = true;

        transport_layer::tcp_packet::tcp_flags flags;
        flags.data = 0;
        int tcp_header_len = 0;

        m_tsm.lack_ = m_tsm.seq_ + 1;

        // 回复syn ack.
        if (state == ac_allow) {
            flags.flag.syn = 1;
            flags.flag.ack = 1;
        } else if (state == ac_deny) {
            flags.flag.rst = 1;
            flags.flag.ack = 1;
            do_close();
        } else {
            flags.flag.ack = 1;
            flags.flag.rst = 1;
            do_close();
        }

        co_await write_packet(flags, m_tsm.lseq_, m_tsm.lack_);

        // 回复ack之后本地seq加1
        m_tsm.lseq_ += 1;

        // 更新为syn包已经发送的状态.
        if (state == ac_allow) {
            m_tsm.state_ = tcp_state::ts_syn_sent;
            boost::asio::co_spawn(m_io_context,
                                  proxy_read_data_from_remote(),
                                  boost::asio::detached);
        }
    }

    // 接收底层ip数据.
    boost::asio::awaitable<void> output(const transport_layer::tcp_packet &packet)
    {
        // 下面开始执行tcp状态机, 总体参考下面实现, 稍作修改的地方几个就是这里初始状态设置
        // 为ts_invalid, 而不是closed, 因为这里我需要判断一个tcp stream对象是已经closed
        // 的, 还是新开的等待连接的对象, 另外执行到time_wait时, 按标准需要等待2MSL个时间
        // 再关闭, 在这个时间一直占用, 因为avpn里当一个连接到time_wait状态的时候, 对外实际
        // 是一个连接, 这个连接关闭了并不影响下一次, client使用相同ip:port来向相同server:
        // port发起请求.
        //
        //
        //                              +---------+ ---------\      active OPEN
        //                              |  CLOSED |            \    -----------
        //                              +---------+<---------\   \   create TCB
        //                                |     ^              \   \  snd SYN
        //                   passive OPEN |     |   CLOSE        \   \
			//                   ------------ |     | ----------       \   \
			//                    create TCB  |     | delete TCB         \   \
			//                                V     |                      \   \
			//                              +---------+            CLOSE    |    \
			//                              |  LISTEN |          ---------- |     |
        //                              +---------+          delete TCB |     |
        //                   rcv SYN      |     |     SEND              |     |
        //                  -----------   |     |    -------            |     V
        // +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
        // |         |<-----------------           ------------------>|         |
        // |   SYN   |                    rcv SYN                     |   SYN   |
        // |   RCVD  |<-----------------------------------------------|   SENT  |
        // |         |                    snd ACK                     |         |
        // |         |------------------           -------------------|         |
        // +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
        //   |           --------------   |     |   -----------
        //   |                  x         |     |     snd ACK
        //   |                            V     V
        //   |  CLOSE                   +---------+
        //   | -------                  |  ESTAB  |
        //   | snd FIN                  +---------+
        //   |                   CLOSE    |     |    rcv FIN
        //   V                  -------   |     |    -------
        // +---------+          snd FIN  /       \   snd ACK          +---------+
        // |  FIN    |<-----------------           ------------------>|  CLOSE  |
        // | WAIT-1  |------------------                              |   WAIT  |
        // +---------+          rcv FIN  \                            +---------+
        //   | rcv ACK of FIN   -------   |                            CLOSE  |
        //   | --------------   snd ACK   |                           ------- |
        //   V        x                   V                           snd FIN V
        // +---------+                  +---------+                   +---------+
        // |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
        // +---------+                  +---------+                   +---------+
        //   |                rcv ACK of FIN |                 rcv ACK of FIN |
        //   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
        //   |  -------              x       V    ------------        x       V
        //    \ snd ACK                 +---------+delete TCB         +---------+
        //     ------------------------>|TIME WAIT|------------------>| CLOSED  |
        //                              +---------+                   +---------+
        auto last_state = m_tsm.state_;
        uint32_t seq = packet.header_data().seq_num;
        m_tsm.ack_ = packet.header_data().ack_num;

        auto flags = packet.header_data().flags;
        uint16_t ws = packet.header_data().window_size;
        auto payload_len = packet.payload().size();

        if (flags.flag.syn && m_tsm.state_ != ts_invalid) {
            SPDLOG_WARN("{0} unexpected syn, skip it!", local_endpoint_pair_.to_string());
            co_return;
        }

        m_tsm.win_ = ws;

        // 收到rst强制中断.
        if (flags.flag.rst) {
            m_tsm.state_ = tcp_state::ts_closed;
            SPDLOG_WARN("{0} {1} -> flags.flag.rst",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state));
            do_close();
            co_return;
        }

        bool keep_alive = false;
        // tcp keep alive, only ack.
        if (m_tsm.state_ == tcp_state::ts_established && seq == m_tsm.seq_ - 1) {
            SPDLOG_WARN("{0} {1} tcp keep alive, skip it",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state));
            keep_alive = true;
            co_return;
        }

        // 记录当前seq.
        m_tsm.seq_ = seq;

        switch (m_tsm.state_) {
        case tcp_state::ts_listen:
        case tcp_state::ts_time_wait:
        case tcp_state::ts_closed: {
            // 关闭了还发数据过来, rst响应之.
            SPDLOG_WARN("{0} {1} -> {2} case ts_listen/ts_time_wait/ts_closed",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state),
                        tcp_state_string(m_tsm.state_));
            co_await reset();
            co_return;
        } break;
        case tcp_state::ts_invalid: // 初始状态, 如果不是syn, 则是个错误的数据包, 这里跳过.
        {
            boost::system::error_code ec;
            if (!flags.flag.syn) {
                co_await reset();
                co_return;
            }

            m_tsm.state_ = tcp_state::ts_syn_rcvd; // 更新状态为syn接收到的状态.
            SPDLOG_WARN("{0} {1} -> tcp_state::ts_syn_rcvd",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state));
            // 通知用户层接收到连接.
            //这里应该要试试连接远程
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
                co_await accept(ac_reset);
                co_return;
            }

            co_await socket_.async_connect(local_endpoint_pair_.dest, net_awaitable[ec]);
            if (ec) {
                SPDLOG_WARN("cant conect tcp endpoint [{0}]:{1}",
                            local_endpoint_pair_.dest.address().to_string(),
                            local_endpoint_pair_.dest.port());
                co_await accept(ac_deny);
                co_return;
            }

            co_await accept(ac_allow);
            co_return; // 直接返回, 由用户层确认是否接受连接回复syn ack.
        } break;
        case tcp_state::ts_syn_rcvd: {
            if (!flags.flag.syn) {
                co_await reset();
                co_return;
            }

            m_tsm.state_ = tcp_state::ts_syn_rcvd; // 更新状态为syn接收到的状态.
            SPDLOG_WARN("{0} {1} -> retransmission tcp_state::ts_syn_rcvd",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state));
            co_return;
        } break;
        case tcp_state::ts_syn_sent: // 这个状态只表示被动回复syn, 而不是主动syn请求.
        {
            // 期望客户端回复ack完成握手, 因为前面已经发了syn ack,
            // 这里收到的不是ack的话, 肯定是出错了, 这里先暂时跳过.
            if (!flags.flag.ack) {
                co_await reset();
                co_return;
            } else {
                m_tsm.state_ = tcp_state::ts_established; // 连接建立.
                SPDLOG_WARN("{0} {1} -> tcp_state::ts_established",
                            local_endpoint_pair_.to_string(),
                            tcp_state_string(last_state));
            }
        }
        case tcp_state::ts_established: {
            // 收到客户端fin, 被动关闭, 发送ack置状态为close_wait, 等待last ack.
            if (flags.flag.fin) {
                m_tsm.state_ = tcp_state::ts_close_wait;
                SPDLOG_WARN("{0} {1} -> tcp_state::ts_close_wait",
                            local_endpoint_pair_.to_string(),
                            tcp_state_string(last_state));
            }

            // 连接状态中, 只是一个ack包而已, 不用对ack包再ack.
            if (payload_len == 0 && !flags.flag.fin) {
                co_return;
            }
        } break;
        case tcp_state::ts_fin_wait_1: // 表示主动关闭.
        {
            bool need_ack = false;

            // 同时发出fin, 转为状态ts_time_wait, 回复ack, 关闭这个连接.
            if (flags.flag.fin && flags.flag.ack) {
                SPDLOG_WARN("{0} {1} -> tcp_state::ts_closed",
                            local_endpoint_pair_.to_string(),
                            tcp_state_string(last_state));
                m_tsm.state_ = tcp_state::ts_closed;
                do_close();
                // m_tsm.state_ = tcp_state::ts_time_wait;
                need_ack = true;
            }

            // 主动与本地客户端断开, 表示已经向本地客户端发出了fin, 还未收到这个fin的ack.
            if (!flags.flag.ack) {
                if (flags.flag.fin) // 收到fin, 回复ack.
                {
                    SPDLOG_WARN("{0} {1} -> tcp_state::ts_closing",
                                local_endpoint_pair_.to_string(),
                                tcp_state_string(last_state));
                    m_tsm.state_ = tcp_state::ts_closing;
                    do_close();
                    need_ack = true;
                } else {
                    co_await reset();
                    co_return;
                }
            }

            if (!need_ack) {
                // 只是收到ack, 转为fin_wait_2, 等待本地客户端的fin.
                SPDLOG_WARN("{0} {1} -> tcp_state::ts_fin_wait_2",
                            local_endpoint_pair_.to_string(),
                            tcp_state_string(last_state));
                m_tsm.state_ = tcp_state::ts_fin_wait_2;
                co_return;
            }
        } break;
        case tcp_state::ts_fin_wait_2: {
            if (!flags.flag.fin) // 只期望收到fin, 除非有数据, 否则都跳过.
            {
                if (payload_len <= 0)
                    co_return;
            }

            // 收到fin, 发回ack, 并关闭这个连接, 进入2MSL状态.
            if (flags.flag.fin) {
                SPDLOG_WARN("{0} {1} -> tcp_state::ts_closed",
                            local_endpoint_pair_.to_string(),
                            tcp_state_string(last_state));
                m_tsm.state_ = tcp_state::ts_closed;
                do_close();
                // m_tsm.state_ = tcp_state::ts_time_wait;
            }
        } break;
        case tcp_state::ts_close_wait: {
            // 对方主动关闭.
            // 等待自己发出fin给本地, 这时收到的ack, 只是最后部分半开状态的向
            // 本地发出数据, 本地回复的ack而已, 所以在这里, 只需要简单的跳过.
            if (flags.flag.ack)
                co_return;

            // 统统跳过, 在自己发没出fin之前, 所有除对数据的ack之外, 全是错误的
            // 数据, 这里可以直接rst掉这个连接.
            co_await reset();
            co_return;
        } break;
        case tcp_state::ts_last_ack:
        case tcp_state::ts_closing: {
            if (!flags.flag.ack) {
                co_return;
            }

            // 如果是close_wait, 则表示收到是last ack, 关闭这个连接.
            // 如果是closing, 则表示收到的是fin的ack, 进入2MSL状态.
            SPDLOG_WARN("{0} {1} -> tcp_state::ts_closed",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(last_state));
            m_tsm.state_ = tcp_state::ts_closed;
            do_close();
            // m_tsm.state_ = tcp_state::ts_time_wait;
            co_return;
        } break;
        }

        // save tcp payload.
        if (payload_len > 0 && !keep_alive) {
            auto target = boost::asio::buffer_cast<void *>(m_tcp_recv_buffer.prepare(payload_len));
            std::memcpy(target, packet.payload().data(), payload_len);
            m_tcp_recv_buffer.commit(payload_len);
            boost::asio::co_spawn(m_io_context, write_client_data_to_proxy(), boost::asio::detached);
        }

        int ack = m_tsm.seq_ + payload_len;
        if (payload_len == 0)
            ack += 1;

        // 回写ack.
        flags.data = 0;
        flags.flag.ack = 1;

        m_tsm.lack_ = ack;

        co_await write_packet(flags, m_tsm.lseq_, m_tsm.lack_);
    }

    // 上层发送数据接口.
    boost::asio::awaitable<void> write(const uint8_t *payload, int payload_len)
    {
        if (m_tsm.state_ == tcp_state::ts_invalid || m_tsm.state_ == tcp_state::ts_closed)
            co_return;

        transport_layer::tcp_packet::tcp_flags flags;
        flags.data = 0;
        flags.flag.ack = 1;

        co_await write_packet(flags,
                              m_tsm.lseq_,
                              m_tsm.lack_,
                              boost::asio::const_buffer(payload, payload_len));

        // 增加本地seq.
        m_tsm.lseq_ += payload_len;
    }
    boost::asio::awaitable<void> close()
    {
        if (m_abort)
            co_return;
        m_abort = true;

        // 已经关闭了, 不再响应close.
        if (m_tsm.state_ == tcp_state::ts_closed || m_tsm.state_ == tcp_state::ts_invalid) {
            co_return;
        }

        bool rst = false;

        // 连接状态, 主动关闭连接, 发送fin给本地, 并进入fin_wait1状态.
        if (m_tsm.state_ == tcp_state::ts_established) {
            SPDLOG_WARN("{0} {1} -> tcp_state::ts_fin_wait_1",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(m_tsm.state_));
            m_tsm.state_ = tcp_state::ts_fin_wait_1;
        } else if (m_tsm.state_ == tcp_state::ts_close_wait) {
            // 已经收到fin, 发送fin给本地, 并进入ts_last_ack状态.
            SPDLOG_WARN("{0} {1} -> tcp_state::ts_last_ack",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(m_tsm.state_));
            m_tsm.state_ = tcp_state::ts_last_ack;
        } else {
            SPDLOG_WARN("{0} {1} -> rst & tcp_state::ts_closed",
                        local_endpoint_pair_.to_string(),
                        tcp_state_string(m_tsm.state_));
            m_tsm.state_ = tcp_state::ts_closed;
            do_close();
            rst = true;
        }
        transport_layer::tcp_packet::tcp_flags flags;
        flags.data = 0;

        if (rst)
            flags.flag.rst = 1;
        else
            flags.flag.fin = 1;
        flags.flag.ack = 1;

        co_await write_packet(flags, m_tsm.lseq_, m_tsm.lack_);

        // 回复ack之后本地seq加1
        m_tsm.lseq_ += 1;
    }

    boost::asio::awaitable<void> reset()
    {
        transport_layer::tcp_packet::tcp_flags flags;
        flags.data = 0;

        flags.flag.ack = 1;
        flags.flag.rst = 1;

        co_await write_packet(flags, m_tsm.lseq_, m_tsm.lack_);
        // 回复ack之后本地seq加1
        m_tsm.lseq_ += 1;

        // 状态置为关闭.
        SPDLOG_WARN("{0} {1} -> rst & tcp_state::ts_closed",
                    local_endpoint_pair_.to_string(),
                    tcp_state_string(m_tsm.state_));
        m_tsm.state_ = tcp_state::ts_closed;

        // 回调写回数据.

        do_close();
    }

    transport_layer::tcp_endpoint_pair tcp_endpoint_pair() const { return local_endpoint_pair_; }

    // 返回当前窗口大小.
    int window_size() { return m_tsm.win_; }

    void do_close()
    {
        if (m_do_closed)
            return;

        m_do_closed = true;
        boost::system::error_code ec;
        socket_.close(ec);
        close_function_(local_endpoint_pair_);
    }

    boost::asio::awaitable<void> write_client_data_to_proxy()
    {
        if (client_data_sending_)
            co_return;

        boost::system::error_code ec;
        client_data_sending_ = true;
        for (;;) {
            auto buffer = m_tcp_recv_buffer.data();
            if (buffer.size() == 0)
                break;

            auto bytes = co_await socket_.async_write_some(buffer, net_awaitable[ec]);
            if (ec)
                break;

            m_tcp_recv_buffer.consume(bytes);
        }
        client_data_sending_ = false;
        if (ec) {
            SPDLOG_INFO("发送错误 {0}", ec.message());
            do_close();
        }
    }
    boost::asio::awaitable<void> proxy_read_data_from_remote()
    {
        for (;;) {
            uint8_t buffer[1024];
            boost::system::error_code ec;
            auto bytes = co_await socket_.async_read_some(boost::asio::buffer(buffer,
                                                                              sizeof(buffer)),
                                                          net_awaitable[ec]);
            if (ec)
                co_return;
            //boost::asio::buffer_copy(proxy_read_buffer_.prepare(bytes), buffer, bytes);
            //proxy_read_buffer_.commit(bytes);

            co_await write(buffer, bytes);
        }
    }

public:
    boost::asio::io_context &m_io_context;
    tuntap::tuntap &tuntap_;
    boost::asio::ip::tcp::socket socket_;
    bool client_data_sending_ = false;

    transport_layer::tcp_endpoint_pair local_endpoint_pair_;
    transport_layer::tcp_endpoint_pair remote_endpoint_pair_;

    boost::asio::streambuf m_tcp_recv_buffer;
    bool m_accepted;
    bool m_do_closed;
    tsm m_tsm;
    bool m_abort;
};
} // namespace avpncore
