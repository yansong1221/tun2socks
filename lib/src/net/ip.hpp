#pragma once
#include "address_pair.hpp"
#include "buffer.hpp"
#include "net/checksum.hpp"
#include <spdlog/spdlog.h>

namespace tun2socks {
namespace net {
    namespace details {
        struct alignas(4) ipv4_header
        {
            uint8_t  ihl : 4;
            uint8_t  version : 4;
            uint8_t  tos;
            uint16_t tot_len;
            uint16_t id;
            uint16_t frag_off;
            uint8_t  ttl;
            uint8_t  protocol;
            uint16_t check;
            uint32_t saddr;
            uint32_t daddr;
        };
        struct alignas(4) ipv6_header
        {
            uint32_t version_traffic_flow;  // Version, Traffic Class, and Flow Label
            uint16_t payload_len;           // Payload Length
            uint8_t  next_header;           // Next Header
            uint8_t  hop_limit;             // Hop Limit
            uint8_t  src_addr[16];          // Source Address
            uint8_t  dest_addr[16];         // Destination Address
        };

        inline static uint32_t make_version_traffic_flow(uint8_t version, uint8_t traffic, uint32_t flow)
        {
            uint32_t value = 0;
            value |= uint32_t(version & 0xF0) << 28;
            value |= (uint32_t)traffic << 20;
            value |= flow & 0x000FFFFF;
            return value;
        }
    }  // namespace details
    class ip {
    public:
        using output_function        = std::function<void(shared_buffer)>;
        using next_protocol_function = std::function<void(const address_pair_type&, shared_buffer)>;

    public:
        void input(shared_buffer buffer)
        {
            auto buffers = buffer.data();
            if (buffers.size() == 0) {
                SPDLOG_INFO("Received packet is empty");
                return;
            }
            auto    data    = boost::asio::buffer_cast<uint8_t*>(buffers);
            uint8_t version = (data[0] & 0xf0) >> 4;
            if (version == 6)
                input6(buffer);
            else
                input4(buffer);
        }
        void output(uint8_t proto, const address_pair_type& addr_pair, shared_buffer buffer)
        {
            if (addr_pair.ip_version() == 6)
                output6(proto, addr_pair, buffer);
            else
                output4(proto, addr_pair, buffer);
        }

        void set_ip_packet_output(output_function func)
        {
            output_ = func;
        }
        void register_protocol(uint8_t proto, next_protocol_function func)
        {
            protocol_observe_[proto].push_back(func);
        }

    private:
        void input4(shared_buffer buffer)
        {
            auto buffers = buffer.data();

            auto buf = boost::asio::buffer_cast<const uint8_t*>(buffers);
            auto len = boost::asio::buffer_size(buffers);

            if (len < sizeof(details::ipv4_header)) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return;
            }

            auto header     = boost::asio::buffer_cast<const details::ipv4_header*>(buffers);
            auto header_len = header->ihl * 4;
            auto total_len  = boost::asio::detail::socket_ops::network_to_host_short(header->tot_len);
            auto proto      = header->protocol;

            if (header_len < sizeof(details::ipv4_header) || total_len != len || total_len < header_len) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return;
            }

            if (checksum::ip_checksum((const uint8_t*)header, header_len) != 0) {
                SPDLOG_WARN("Received IPv4 packet Calculation checksum error");
                return;
            }

            address_pair_type addr_pair(boost::asio::detail::socket_ops::host_to_network_long(
                                            header->saddr),
                                        boost::asio::detail::socket_ops::host_to_network_long(
                                            header->daddr));

            SPDLOG_DEBUG("Received IPv4 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         proto);

            buffer.consume_front(header_len);
            distribute(proto, addr_pair, buffer);
        }
        void input6(shared_buffer buffer)
        {
            auto buffers = buffer.data();

            auto buf = boost::asio::buffer_cast<const uint8_t*>(buffers);
            auto len = boost::asio::buffer_size(buffers);

            if (len < sizeof(details::ipv6_header)) {
                SPDLOG_INFO("Received packet without room for an IPv6 header");
                return;
            }
            auto header = boost::asio::buffer_cast<const details::ipv6_header*>(buffers);

            auto version_traffic_flow = boost::asio::detail::socket_ops::network_to_host_long(
                header->version_traffic_flow);
            auto    version = (version_traffic_flow >> 28) & 0xF;
            auto    traffic = (version_traffic_flow >> 20) & 0xFF;
            auto    flow    = version_traffic_flow & 0xFFFFF;
            uint8_t proto   = header->next_header;

            auto payload_len = boost::asio::detail::socket_ops::network_to_host_short(
                header->payload_len);

            boost::asio::ip::address_v6::bytes_type src_addr_bytes;
            boost::asio::ip::address_v6::bytes_type dst_addr_bytes;

            memcpy(src_addr_bytes.data(), header->src_addr, sizeof(header->src_addr));
            memcpy(dst_addr_bytes.data(), header->dest_addr, sizeof(header->dest_addr));

            address_pair_type addr_pair(src_addr_bytes, dst_addr_bytes);

            SPDLOG_DEBUG("Received IPv6 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         proto);

            buffer.consume_front(sizeof(details::ipv6_header));
            distribute(proto, addr_pair, buffer);
        }

        void output4(uint8_t proto, const address_pair_type& addr_pair, shared_buffer buffer)
        {
            constexpr auto header_len = sizeof(details::ipv4_header);
            uint16_t       tot_len    = header_len + buffer.size();

            auto buffers = buffer.prepare_front(header_len);

            constexpr uint8_t           ihl   = header_len / 4;
            static std::atomic_uint16_t index = 0;

            auto header = boost::asio::buffer_cast<details::ipv4_header*>(buffers);
            memset(header, 0, header_len);

            header->ihl      = ihl;
            header->version  = 4;
            header->tot_len  = boost::asio::detail::socket_ops::host_to_network_short(tot_len);
            header->id       = boost::asio::detail::socket_ops::host_to_network_short(index++);
            header->ttl      = 0x30;
            header->protocol = proto;
            header->saddr    = boost::asio::detail::socket_ops::host_to_network_long(
                addr_pair.src.to_v4().to_ulong());
            header->daddr = boost::asio::detail::socket_ops::host_to_network_long(
                addr_pair.dest.to_v4().to_ulong());
            header->check = checksum::ip_checksum((const uint8_t*)(header), header_len);

            if (output_)
                output_(buffer);
        }
        void output6(uint8_t proto, const address_pair_type& addr_pair, shared_buffer buffer)
        {
            constexpr auto header_len  = sizeof(details::ipv6_header);
            auto           payload_len = buffer.size();

            auto buffers = buffer.prepare_front(header_len);

            auto src_addr_bytes = addr_pair.src.to_v6().to_bytes();
            auto dst_addr_bytes = addr_pair.dest.to_v6().to_bytes();

            auto header = boost::asio::buffer_cast<details::ipv6_header*>(buffers);
            memset(header, 0, header_len);

            header->version_traffic_flow = boost::asio::detail::socket_ops::host_to_network_long(
                details::make_version_traffic_flow(6, 0, 0));
            header->payload_len = boost::asio::detail::socket_ops::host_to_network_short(
                payload_len);
            header->next_header = proto;
            header->hop_limit   = 0x30;

            memcpy(header->src_addr, src_addr_bytes.data(), sizeof(header->src_addr));
            memcpy(header->dest_addr, dst_addr_bytes.data(), sizeof(header->dest_addr));

            if (output_)
                output_(buffer);
        }

        void distribute(uint8_t proto, const address_pair_type& addr_pair, shared_buffer buffer)
        {
            auto iter = protocol_observe_.find(proto);
            if (iter == protocol_observe_.end())
                return;

            for (const auto& func : iter->second)
                func(addr_pair, buffer);
        }

    private:
        using protocol_map = std::unordered_map<uint8_t, std::list<next_protocol_function>>;

        output_function output_;
        protocol_map    protocol_observe_;
    };
}  // namespace net
}  // namespace tun2socks