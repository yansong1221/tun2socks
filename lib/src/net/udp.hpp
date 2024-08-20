#pragma once
#include "address_pair.hpp"
#include "buffer.hpp"
#include "checksum.hpp"
#include "endpoint_pair.hpp"
#include "use_awaitable.hpp"
#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

namespace tun2socks {
namespace net {

    namespace details {
        struct alignas(4) udp_header
        {
            uint16_t src_port;   // 源端口号
            uint16_t dest_port;  // 目的端口号
            uint16_t length;     // 长度
            uint16_t checksum;   // 校验和
        };
        inline static uint16_t udp_checksum(const shared_buffer&     packet,
                                            const address_pair_type& address_pair)
        {
            checksum::checksumer checker;
            switch (address_pair.ip_version()) {
                case 4: {
                    // 伪头结构体
                    struct alignas(4) pseud_v4_udp_header
                    {
                        uint32_t src_addr;    // 源IP地址
                        uint32_t dest_addr;   // 目的IP地址
                        uint8_t  reserved;    // 预留字段
                        uint8_t  protocol;    // 协议号 (UDP协议为17)
                        uint16_t udp_length;  // UDP长度
                    } psh{0};

                    psh.src_addr = boost::asio::detail::socket_ops::host_to_network_long(
                        address_pair.src.to_v4().to_ulong());
                    psh.dest_addr = boost::asio::detail::socket_ops::host_to_network_long(
                        address_pair.dest.to_v4().to_ulong());
                    psh.reserved   = 0;
                    psh.protocol   = 17;
                    psh.udp_length = htons(packet.size());
                    checker.update(&psh, sizeof(psh));
                } break;
                case 6: {
                    // IPv6伪头结构体
                    struct alignas(4) pseud_v6_udp_header
                    {
                        uint8_t  src_addr[16];   // 源IP地址
                        uint8_t  dest_addr[16];  // 目的IP地址
                        uint32_t length;         // UDP长度
                        uint8_t  zero;           // 预留字段
                        uint8_t  protocol;       // 协议号 (UDP协议为17)
                    } psh = {0};
                    memcpy(psh.src_addr, address_pair.src.to_v6().to_bytes().data(), sizeof(psh.src_addr));
                    memcpy(psh.dest_addr,
                           address_pair.dest.to_v6().to_bytes().data(),
                           sizeof(psh.dest_addr));
                    psh.zero     = 0;
                    psh.protocol = 17;
                    psh.length   = htons(packet.size());
                    checker.update(&psh, sizeof(psh));
                } break;
                default:
                    break;
            }
            checker.update(packet.data());
            return checker.get();
        }

    }  // namespace details

    using namespace std::chrono_literals;

    class udp : public boost::asio::detail::service_base<udp> {
    public:
        class udp_pcb;

        using output_function = std::function<void(uint8_t proto, const address_pair_type&, shared_buffer buffer)>;
        using open_function   = std::function<void(std::weak_ptr<udp_pcb>)>;

        constexpr static uint8_t protocol = 17;

        class udp_pcb : public std::enable_shared_from_this<udp_pcb> {
        public:
            using ptr      = std::shared_ptr<udp::udp_pcb>;
            using weak_ptr = std::weak_ptr<udp::udp_pcb>;

            using recved_function  = std::function<void(shared_buffer)>;
            using timeout_function = std::function<void(udp_pcb::weak_ptr)>;

        public:
            udp_pcb(udp& _udp, const udp_endpoint_pair& endp_pair)
                : udp_(_udp),
                  timeout_timer_(_udp.get_io_context()),
                  endp_pair_(endp_pair),
                  remote_endp_pair_(endp_pair.swap())
            {
            }

        public:
            const udp_endpoint_pair& endp_pair() const
            {
                return endp_pair_;
            }

            void send(shared_buffer buffer)
            {
                if (closed_)
                    return;

                reset_timeout_timer();

                auto remote_addr_pair = remote_endp_pair_.to_address_pair();

                auto header_buf = buffer.prepare_front(sizeof(details::udp_header));
                auto header     = boost::asio::buffer_cast<details::udp_header*>(header_buf);
                memset(&header, 0, sizeof(details::udp_header));

                header->src_port = boost::asio::detail::socket_ops::host_to_network_short(
                    remote_endp_pair_.src.port());
                header->dest_port = boost::asio::detail::socket_ops::host_to_network_short(
                    remote_endp_pair_.dest.port());
                header->length   = boost::asio::detail::socket_ops::host_to_network_short(buffer.size());
                header->checksum = details::udp_checksum(buffer, remote_addr_pair);

                udp_.on_pcb_output(remote_addr_pair, buffer);
            }
            void disconnect()
            {
                if (closed_)
                    return;

                closed_ = true;
                udp_.on_pcb_remove(shared_from_this());
            }
            void set_recved_function(recved_function func)
            {
                recved_func_ = func;
            }
            void set_timeout_function(timeout_function func)
            {
                timeout_func_ = func;
            }

        private:
            void reset_timeout_timer()
            {
                if (closed_)
                    return;

                boost::system::error_code ec;
                timeout_timer_.cancel(ec);

                timeout_timer_.expires_after(timeout_seconds_);
                timeout_timer_.async_wait([this](boost::system::error_code ec) {
                    if (ec)
                        return;

                    if (timeout_func_)
                        timeout_func_(shared_from_this());

                    disconnect();
                });
            }
            void recved(shared_buffer buffer)
            {
                if (closed_)
                    return;

                reset_timeout_timer();
                if (recved_func_)
                    recved_func_(buffer);
            }

        private:
            udp&              udp_;
            udp_endpoint_pair endp_pair_;
            udp_endpoint_pair remote_endp_pair_;

            recved_function  recved_func_;
            timeout_function timeout_func_;

            std::chrono::seconds timeout_seconds_ = 10s;

            boost::asio::steady_timer timeout_timer_;
            bool                      closed_ = false;

            friend class udp;
        };

    public:
        udp(boost::asio::io_context& ioc)
            : boost::asio::detail::service_base<udp>(ioc)
        {
        }

    public:
        void input(const address_pair_type& addr_pair, shared_buffer buffer)
        {
            if (buffer.size() < sizeof(details::udp_header)) {
                spdlog::error("Received packet without room for an upd header");
                return;
            }

            auto     header    = boost::asio::buffer_cast<const details::udp_header*>(buffer.data());
            uint16_t total_len = boost::asio::detail::socket_ops::network_to_host_short(header->length);
            if (total_len != buffer.size()) {
                spdlog::error("Received udp packet length error");
                return;
            }
            if (details::udp_checksum(buffer, addr_pair) != 0) {
                spdlog::warn("Received IPv{0} udp packet Calculation checksum error", addr_pair.ip_version());
                return;
            }

            udp_endpoint_pair point_pair(addr_pair,
                                         boost::asio::detail::socket_ops::network_to_host_short(
                                             header->src_port),
                                         boost::asio::detail::socket_ops::network_to_host_short(
                                             header->dest_port));
            buffer.consume_front(sizeof(details::udp_header));

            spdlog::debug("Received IPv{0} udp packet {1}", addr_pair.ip_version(), point_pair.to_string());

            auto pcb = pcbs_[point_pair];
            if (!pcb) {
                pcb = std::make_shared<udp_pcb>(point_pair);

                pcbs_[point_pair] = pcb;

                if (udp_opened_func_)
                    udp_opened_func_(pcb);
            }
            pcb->recved(buffer);
        }

        void set_output_function(output_function func)
        {
            output_func_ = func;
        }
        void set_udp_open_function(open_function func)
        {
            udp_opened_func_ = func;
        }

    private:
        void on_pcb_remove(udp::udp_pcb::ptr pcb)
        {
            boost::asio::post(this->get_io_context(), [this, pcb]() {
                pcbs_.erase(pcb->endp_pair());
            });
        }
        void on_pcb_output(const address_pair_type& addr_pair, shared_buffer buffer)
        {
            if (output_func_)
                output_func_(udp::protocol, addr_pair, buffer);
        }

    private:
        using pcb_map = std::unordered_map<udp_endpoint_pair, udp::udp_pcb::ptr>;

        pcb_map         pcbs_;
        output_function output_func_;
        open_function   udp_opened_func_;
    };
}  // namespace net
}  // namespace tun2socks