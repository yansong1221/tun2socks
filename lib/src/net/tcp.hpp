#pragma once
#include "buffer.hpp"
#include "checksum.hpp"
#include "endpoint_pair.hpp"
#include "net/address_pair.hpp"
#include <spdlog/spdlog.h>

namespace tun2socks {
namespace net {
    namespace details {
        struct alignas(4) tcp_header
        {
            uint16_t src_port;   // 源端口号
            uint16_t dest_port;  // 目的端口号
            uint32_t seq_num;    // 序列号
            uint32_t ack_num;    // 确认号
            uint8_t  reserved : 4;
            uint8_t  data_offset : 4;
            uint8_t  flags;           // 标志字段
            uint16_t window_size;     // 窗口大小
            uint16_t checksum;        // 校验和
            uint16_t urgent_pointer;  // 紧急指针
        };

        inline static uint16_t tcp_checksum(const address_pair_type& address_pair, const shared_buffer& packet)
        {
            checksum::checksumer checker;
            if (address_pair.ip_version() == 6) {
                // IPv6伪头结构体
                struct alignas(4) pseud_v6_tcp_header
                {
                    uint8_t  src_addr[16];
                    uint8_t  dest_addr[16];
                    uint32_t length;
                    uint8_t  zeros[3];
                    uint8_t  protocol;
                } psh = {0};
                memcpy(psh.src_addr, address_pair.src.to_v6().to_bytes().data(), sizeof(psh.src_addr));
                memcpy(psh.dest_addr,
                       address_pair.dest.to_v6().to_bytes().data(),
                       sizeof(psh.dest_addr));
                psh.protocol = 6;
                psh.length   = htons(packet.size());
                checker.update(&psh, sizeof(psh));
            }
            else {
                // 伪头结构体
                struct alignas(4) pseud_v4_tcp_header
                {
                    uint32_t src_addr;
                    uint32_t dest_addr;
                    uint8_t  reserved;
                    uint8_t  protocol;
                    uint16_t tcp_length;
                } psh{0};
                psh.src_addr = boost::asio::detail::socket_ops::host_to_network_long(
                    address_pair.src.to_v4().to_ulong());
                psh.dest_addr = boost::asio::detail::socket_ops::host_to_network_long(
                    address_pair.dest.to_v4().to_ulong());
                psh.protocol   = 6;
                psh.tcp_length = htons(packet.size());

                checker.update(&psh, sizeof(psh));
            }
            checker.update(packet.data());
            return checker.get();
        }
    }  // namespace details

    class tcp {
    public:
        class tcp_pcb;
        using accept_function = std::function<std::weak_ptr<tcp_pcb>>;

        union tcp_flags
        {
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
            uint8_t data = 0;
        };

        struct header
        {
            uint32_t  seq_num = 0;
            uint32_t  ack_num = 0;
            tcp_flags flags;
            uint16_t  window_size = 0xFFFF;
        };

        class tcp_pcb : public std::enable_shared_from_this<tcp_pcb> {
        public:
            enum class tcp_state {
                ts_closed      = 0,
                ts_listen      = 1,
                ts_syn_sent    = 2,
                ts_syn_rcvd    = 3,
                ts_established = 4,
                ts_fin_wait_1  = 5,
                ts_fin_wait_2  = 6,
                ts_close_wait  = 7,
                ts_closing     = 8,
                ts_last_ack    = 9,
                ts_time_wait   = 10
            };
            using close_function = std::function<void(std::weak_ptr<tcp_pcb>)>;

            tcp_pcb(tcp& _tcp)
                : tcp_(_tcp),
                  state_(tcp_state::ts_listen)
            {
            }

        private:
            void write_packet(tcp::tcp_flags       flags,
                              const shared_buffer& payload = shared_buffer())
            {
                return write_packet(flags, server_seq_num_, client_seq_num_, payload);
            }
            void write_packet(tcp::tcp_flags       flags,
                              uint32_t             seq_num,
                              uint32_t             ack_num,
                              const shared_buffer& payload = shared_buffer())
            {
            }
            void recved(const tcp::header& header_data, shared_buffer payload)
            {
                auto flags       = header_data.flags;
                auto seq_num     = header_data.seq_num;
                auto ack_num     = header_data.ack_num;
                auto window_size = header_data.window_size;

                switch (state_) {
                    case tcp_state::ts_closed:
                        break;
                    case tcp_state::ts_listen: {
                        if (!flags.flag.syn)
                            break;

                        state_              = tcp_state::ts_syn_rcvd;
                        client_window_size_ = window_size;
                        client_seq_num_     = seq_num;

                        tcp::tcp_flags flags;
                        flags.flag.syn = 1;
                        flags.flag.ack = 1;
                        write_packet(flags, server_seq_num_, seq_num + 1);

                    } break;
                    case tcp_state::ts_syn_rcvd: {
                        if (!flags.flag.ack)
                            break;

                        if (ack_num != server_seq_num_ + 1 || seq_num != client_seq_num_ + 1)
                            break;

                        server_seq_num_++;
                        client_seq_num_++;
                        client_window_size_ = window_size;

                        state_ = tcp_state::ts_established;
                        tcp_.on_established(shared_from_this());
                    } break;
                    case tcp_state::ts_established: {
                        if (!flags.flag.ack) {
                            return;
                        }
                        if (flags.flag.rst) {
                            do_close();
                            return;
                        }

                        if (seq_num == client_seq_num_ - 1 || seq_num < client_seq_num_) {
                            tcp_packet::tcp_flags flags;
                            flags.flag.ack = true;

                            write_packet(flags, server_seq_num_, client_seq_num_);
                            return;
                        }

                        if (seq_num != client_seq_num_) {
                            return;
                        }

                        client_window_size_ = window_size;

                        // 结束包 进行4次挥手
                        if (flags.flag.fin) {
                            // state_ = tcp_state::ts_close_wait;

                            // tcp_packet::tcp_flags flags;
                            // flags.flag.ack = true;
                            // write_packet(flags, server_seq_num_, seq_num + 1);

                            // boost::system::error_code ec;
                            // socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

                            // state_ = tcp_state::ts_last_ack;
                            // flags.flag.fin = true;
                            // write_packet(flags, server_seq_num_, seq_num + 1);
                            // co_return;

                            tcp_packet::tcp_flags flags;
                            flags.flag.rst = true;
                            flags.flag.ack = true;
                            write_packet(flags, server_seq_num_, seq_num + 1);

                            do_close();
                            return;
                        }
                        write_client_data_to_proxy(packet.payload());
                    } break;
                    case tcp_state::ts_fin_wait_1: {
                        if (ack_num != server_seq_num_) {
                            return;
                        }
                        if (flags.flag.rst) {
                            do_close();
                            return;
                        }

                        if (!flags.flag.ack)
                            return;

                        state_ = tcp_state::ts_fin_wait_2;

                    } break;
                    case tcp_state::ts_fin_wait_2: {
                        if (ack_num != server_seq_num_) {
                            return;
                        }
                        if (flags.flag.rst) {
                            do_close();
                            return;
                        }

                        if (!flags.flag.ack)
                            return;
                        if (!flags.flag.fin)
                            return;

                        tcp_packet::tcp_flags flags;
                        flags.flag.ack = true;
                        write_packet(flags, server_seq_num_, seq_num + 1);
                        do_close();
                    } break;
                    case tcp_state::ts_close_wait:
                        break;
                    case tcp_state::ts_closing:
                        break;
                    case tcp_state::ts_last_ack: {
                        if (!flags.flag.ack) {
                            return;
                        }
                        if (ack_num != server_seq_num_ + 1) {
                            return;
                        }
                        do_close();
                    } break;
                    case tcp_state::ts_time_wait:
                        break;
                    default:
                        break;
                }
            }

        private:
            std::atomic_uint32_t client_seq_num_     = 0;
            std::atomic_uint16_t client_window_size_ = 0xFFFF;

            std::atomic_uint32_t server_seq_num_     = 0;
            std::atomic_uint16_t server_window_size_ = 0xFFFF;
            tcp_state            state_;

            tcp& tcp_;
        };

    public:
        void input(const address_pair_type& addr_pair, shared_buffer buffer)
        {
            auto buffers = buffer.data();

            if (buffers.size() < sizeof(details::tcp_header)) {
                SPDLOG_WARN("Received packet without room for a tcp header");
                return;
            }

            auto header     = boost::asio::buffer_cast<const details::tcp_header*>(buffers);
            auto header_len = header->data_offset * 4;

            if (buffer.size() < header_len) {
                SPDLOG_WARN("Received tcp packet length error");
                return;
            }

            if (details::tcp_checksum(addr_pair, buffer) != 0) {
                SPDLOG_WARN("Received IPv{0} tcp packet Calculation checksum error",
                            addr_pair.ip_version());
                return;
            }

            tcp_endpoint_pair endpoint_pair(addr_pair,
                                            boost::asio::detail::socket_ops::network_to_host_short(
                                                header->src_port),
                                            boost::asio::detail::socket_ops::network_to_host_short(
                                                header->dest_port));

            SPDLOG_DEBUG("Received IPv{0} TCP Packet {1}", addr_pair.ip_version(), endpoint_pair.to_string());

            tcp::header header_data;
            header_data.seq_num     = ntohl(header->seq_num);
            header_data.ack_num     = ntohl(header->ack_num);
            header_data.window_size = ntohs(header->window_size);
            header_data.flags.data  = header->flags;

            buffer.consume_front(header_len);
        }

    private:
        void on_established(std::shared_ptr<tcp_pcb> pcb)
        {
        }
    };
}  // namespace net
}  // namespace tun2socks