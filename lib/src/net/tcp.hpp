#pragma once
#include "buffer.hpp"
#include "checksum.hpp"
#include "endpoint_pair.hpp"
#include "net/address_pair.hpp"
#include <map>
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

        inline static uint16_t tcp_checksum(const address_pair_type& address_pair,
                                            const shared_buffer&     packet)
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

    using namespace std::chrono_literals;

    class tcp : public boost::asio::detail::service_base<tcp> {
    public:
        class tcp_pcb;

        using accept_function = std::function<void(std::weak_ptr<tcp_pcb>)>;
        using output_function = std::function<void(uint8_t proto, const address_pair_type&, shared_buffer buffer)>;

        constexpr static uint8_t protocol = 6;

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
            using weak_ptr = std::weak_ptr<tcp_pcb>;
            using ptr      = std::shared_ptr<tcp_pcb>;

            using close_function  = std::function<void()>;
            using recved_function = std::function<bool(shared_buffer)>;

            tcp_pcb(tcp& _tcp, const tcp_endpoint_pair& endp_pair)
                : tcp_(_tcp),
                  endp_pair_(endp_pair),
                  remote_endp_pair_(endp_pair.swap()),
                  timeout_timer_(_tcp.get_io_context()),
                  state_(tcp_state::ts_listen)
            {
            }

        public:
            const tcp_endpoint_pair& endp_pair() const
            {
                return endp_pair_;
            }
            void write(shared_buffer buf)
            {
                tcp::tcp_flags flags;
                flags.flag.ack = true;
                flags.flag.psh = true;

                auto sz = buf.size();

                write_packet(flags, buf);
                server_seq_num_ += sz;
            }
            void set_recved_function(recved_function f)
            {
                recved_func_ = f;
            }
            void set_close_function(close_function f)
            {
                close_func_ = f;
            }

        private:
            void reset_timeout_timer()
            {
                boost::system::error_code ec;
                timeout_timer_.cancel(ec);
                timeout_timer_.expires_after(100s);
                timeout_timer_.async_wait([this](boost::system::error_code ec) {
                    if (ec)
                        return;
                    do_rest(server_seq_num_, client_seq_num_);
                });
            }
            void do_rest(uint32_t seq_num, uint32_t ack_num)
            {
                tcp::tcp_flags flags;
                flags.flag.rst = true;
                flags.flag.ack = true;
                write_packet(flags, seq_num, ack_num);
                do_close();
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
                reset_timeout_timer();

                tcp::header header_data;
                header_data.seq_num     = seq_num;
                header_data.ack_num     = ack_num;
                header_data.flags       = flags;
                header_data.window_size = server_window_size_;
                tcp_.output(remote_endp_pair_, header_data, payload);
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
                    case tcp_state::ts_listen:
                        on_tcp_state_listen(header_data, payload);
                        break;
                    case tcp_state::ts_syn_rcvd:
                        on_tcp_state_syn_rcvd(header_data, payload);
                        break;
                    case tcp_state::ts_established:
                        on_tcp_state_established(header_data, payload);
                        break;
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

                        tcp::tcp_flags flags;
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
            void do_close()
            {
                if (close_func_)
                    close_func_();

                boost::system::error_code ec;
                timeout_timer_.cancel(ec);
                tcp_.on_pcb_remove(shared_from_this());
            }
            void on_tcp_state_listen(const tcp::header& header_data, shared_buffer payload)
            {
                auto flags       = header_data.flags;
                auto seq_num     = header_data.seq_num;
                auto ack_num     = header_data.ack_num;
                auto window_size = header_data.window_size;

                if (!flags.flag.syn)
                    return;

                state_              = tcp_state::ts_syn_rcvd;
                client_window_size_ = window_size;
                client_seq_num_     = seq_num;
                {
                    tcp::tcp_flags flags;
                    flags.flag.syn = 1;
                    flags.flag.ack = 1;
                    write_packet(flags, server_seq_num_, seq_num + 1);
                }
            }
            void on_tcp_state_syn_rcvd(const tcp::header& header_data, shared_buffer payload)
            {
                auto flags       = header_data.flags;
                auto seq_num     = header_data.seq_num;
                auto ack_num     = header_data.ack_num;
                auto window_size = header_data.window_size;

                if (!flags.flag.ack)
                    return;

                if (ack_num != server_seq_num_ + 1 || seq_num != client_seq_num_ + 1)
                    return;

                server_seq_num_++;
                client_seq_num_++;
                client_window_size_ = window_size;

                if (tcp_.on_established(shared_from_this())) {
                    state_ = tcp_state::ts_established;
                    reset_timeout_timer();
                }
                else {
                    state_ = tcp_state::ts_closed;
                    do_rest(server_seq_num_, client_seq_num_);
                }
            }
            void on_tcp_state_established(const tcp::header& header_data, shared_buffer payload)
            {
                auto flags       = header_data.flags;
                auto seq_num     = header_data.seq_num;
                auto ack_num     = header_data.ack_num;
                auto window_size = header_data.window_size;

                if (!flags.flag.ack) {
                    return;
                }
                if (flags.flag.rst) {
                    do_close();
                    return;
                }

                // Keepalive
                if (seq_num == client_seq_num_ - 1) {
                    tcp::tcp_flags flags;
                    flags.flag.ack = true;

                    write_packet(flags, server_seq_num_, client_seq_num_);
                    return;
                }
                if (seq_num < client_seq_num_)
                    return;

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
                    do_rest(server_seq_num_, seq_num + 1);
                    do_close();
                    return;
                }
                if (payload.size() == 0) {
                    return;
                }
                if (!recved_func_)
                    return;

                if (seq_num != client_seq_num_) {
                    out_of_order_packet_[seq_num] = payload;
                    return;
                }

                if (seq_num == client_seq_num_) {
                    if (!recved_func_(payload))
                        return;

                    client_seq_num_ += payload.size();

                    while (true) {
                        auto iter = out_of_order_packet_.find(client_seq_num_);
                        if (iter == out_of_order_packet_.end())
                            break;

                        if (!recved_func_(iter->second))
                            break;
                        client_seq_num_ += iter->second.size();
                        out_of_order_packet_.erase(iter);
                    }
                    out_of_order_packet_.clear();

                    tcp::tcp_flags flags;
                    flags.flag.ack = true;
                    write_packet(flags);
                }
            }

        private:
            std::atomic_uint32_t client_seq_num_     = 0;
            std::atomic_uint16_t client_window_size_ = 0xFFFF;

            std::atomic_uint32_t server_seq_num_     = 0;
            std::atomic_uint16_t server_window_size_ = 0xFFFF;
            tcp_state            state_;

            tcp&                      tcp_;
            tcp_endpoint_pair         endp_pair_;
            tcp_endpoint_pair         remote_endp_pair_;
            boost::asio::steady_timer timeout_timer_;

            recved_function recved_func_;
            close_function  close_func_;

            std::map<uint32_t, shared_buffer> out_of_order_packet_;
            friend class tcp;
        };

    public:
        tcp(boost::asio::io_context& ioc)
            : boost::asio::detail::service_base<tcp>(ioc)
        {
        }

    public:
        void set_tcp_output_function(output_function f)
        {
            output_func_ = f;
        }
        void set_tcp_accept_function(accept_function f)
        {
            accept_func_ = f;
        }

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
            header_data.seq_num     = boost::asio::detail::socket_ops::network_to_host_long(header->seq_num);
            header_data.ack_num     = boost::asio::detail::socket_ops::network_to_host_long(header->ack_num);
            header_data.window_size = boost::asio::detail::socket_ops::network_to_host_short(header->window_size);
            header_data.flags.data  = header->flags;

            buffer.consume_front(header_len);

            auto pcb = pcbs_[endpoint_pair];
            if (!pcb) {
                pcb                  = std::make_shared<tcp_pcb>(*this, endpoint_pair);
                pcbs_[endpoint_pair] = pcb;
            }
            pcb->recved(header_data, buffer);
        }

    private:
        void output(const tcp_endpoint_pair& endp_pair, const tcp::header& header_data, shared_buffer buffer)
        {
            auto remote_addr_pair = endp_pair.to_address_pair();

            auto header_buf = buffer.prepare_front(sizeof(details::tcp_header));
            auto header     = boost::asio::buffer_cast<details::tcp_header*>(header_buf);
            memset(header, 0, sizeof(details::tcp_header));

            header->src_port = boost::asio::detail::socket_ops::host_to_network_short(
                endp_pair.src.port());
            header->dest_port = boost::asio::detail::socket_ops::host_to_network_short(
                endp_pair.dest.port());
            header->seq_num = boost::asio::detail::socket_ops::host_to_network_long(
                header_data.seq_num);
            header->ack_num = boost::asio::detail::socket_ops::host_to_network_long(
                header_data.ack_num);
            header->data_offset = sizeof(details::tcp_header) / 4;
            header->flags       = header_data.flags.data;
            header->window_size = htons(header_data.window_size);

            header->checksum = details::tcp_checksum(remote_addr_pair, buffer);

            int ret = details::tcp_checksum(remote_addr_pair, buffer);
            if (output_func_)
                output_func_(tcp::protocol, remote_addr_pair, buffer);
        }
        bool on_established(tcp::tcp_pcb::ptr pcb)
        {
            if (!accept_func_)
                return false;

            accept_func_(pcb);
            return true;
        }
        void on_pcb_remove(tcp::tcp_pcb::ptr pcb)
        {
            boost::asio::post(get_io_context(), [this, pcb]() {
                pcbs_.erase(pcb->endp_pair());
            });
        }

    private:
        using pcb_map = std::unordered_map<tcp_endpoint_pair, tcp::tcp_pcb::ptr>;

        pcb_map         pcbs_;
        accept_function accept_func_;
        output_function output_func_;
    };
}  // namespace net
}  // namespace tun2socks