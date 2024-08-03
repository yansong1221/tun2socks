#pragma once
#include "address_pair.hpp"
#include "checksum.hpp"
#include "tuntap/basic_tuntap.hpp"
#include <boost/asio.hpp>
#include <optional>
#include <spdlog/spdlog.h>

namespace network_layer {

enum class icmp_type : uint8_t {
    echo_reply = 0,              // 回显应答
    destination_unreachable = 3, // 目的不可达
    source_quench = 4,           // 源抑制
    redirect = 5,                // 重定向
    echo_request = 8,            // 回显请求
    time_exceeded = 11,          // 时间超时
    parameter_problem = 12,      // 参数问题
    timestamp_request = 13,      // 时间戳请求
    timestamp_reply = 14         // 时间戳应答
};

namespace details {

struct alignas(4) icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
};
struct alignas(4) ipv4_header
{
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
struct alignas(4) ipv6_header
{
    uint32_t version_traffic_flow; // Version, Traffic Class, and Flow Label
    uint16_t payload_len;          // Payload Length
    uint8_t next_header;           // Next Header
    uint8_t hop_limit;             // Hop Limit
    uint8_t src_addr[16];          // Source Address
    uint8_t dest_addr[16];         // Destination Address
};

} // namespace details

class ip_packet
{
public:
    ip_packet(const network_layer::address_pair_type &address_pair,
              uint8_t protocol,
              buffer::ref_const_buffer payload_buffer)
        : payload_buffer_(payload_buffer)
        , address_pair_(address_pair)
        , protocol_(protocol)
    {}

    const network_layer::address_pair_type &address_pair() const { return address_pair_; }

    uint8_t next_protocol() const { return protocol_; }

    std::size_t raw_packet_size() const
    {
        switch (address_pair_.ip_version()) {
        case 4:
            return sizeof(details::ipv4_header) + boost::asio::buffer_size(payload());
        case 6:
            return sizeof(details::ipv6_header) + boost::asio::buffer_size(payload());
        }
        return 0;
    }
    buffer::ref_const_buffer payload() const { return payload_buffer_; }

    std::size_t make_packet(boost::asio::mutable_buffer buffer) const
    {
        switch (address_pair_.ip_version()) {
        case 4: {
            constexpr auto header_len = sizeof(details::ipv4_header);

            constexpr uint8_t ihl = header_len / 4;
            static std::atomic_uint16_t index = 0;

            uint16_t tot_len = raw_packet_size();

            memset(buffer.data(), 0, tot_len);

            auto header = boost::asio::buffer_cast<details::ipv4_header *>(buffer);
            header->ihl = ihl;
            header->version = 4;
            header->tot_len = boost::asio::detail::socket_ops::host_to_network_short(tot_len);
            header->id = boost::asio::detail::socket_ops::host_to_network_short(index++);
            header->ttl = 0x30;
            header->protocol = protocol_;
            header->saddr = boost::asio::detail::socket_ops::host_to_network_long(
                address_pair_.src.to_v4().to_ulong());
            header->daddr = boost::asio::detail::socket_ops::host_to_network_long(
                address_pair_.dest.to_v4().to_ulong());
            header->check = checksum::checksum((const uint8_t *) (header), header_len);

            buffer += header_len;
            boost::asio::buffer_copy(buffer, payload_buffer_);
            return tot_len;

        } break;
        case 6: {
            constexpr auto header_len = sizeof(details::ipv6_header);

            auto payload_len = (uint16_t) payload_buffer_.size();
            uint16_t tot_len = raw_packet_size();

            auto src_addr_bytes = address_pair_.src.to_v6().to_bytes();
            auto dst_addr_bytes = address_pair_.dest.to_v6().to_bytes();

            memset(buffer.data(), 0, tot_len);

            auto header = boost::asio::buffer_cast<details::ipv6_header *>(buffer);
            header->version_traffic_flow = boost::asio::detail::socket_ops::host_to_network_long(
                make_version_traffic_flow(6, 0, 0));
            header->payload_len = boost::asio::detail::socket_ops::host_to_network_short(
                payload_len);
            header->next_header = protocol_;
            header->hop_limit = 0x30;

            memcpy(header->src_addr, src_addr_bytes.data(), sizeof(header->src_addr));
            memcpy(header->dest_addr, dst_addr_bytes.data(), sizeof(header->dest_addr));

            buffer += header_len;
            boost::asio::buffer_copy(buffer, payload_buffer_);
            return tot_len;
        } break;
        default:
            break;
        }
        return 0;
    }

    static std::size_t ip_header_len(const network_layer::address_pair_type &address_pair)
    {
        switch (address_pair.ip_version()) {
        case 4:
            return sizeof(details::ipv4_header);
        case 6:
            return sizeof(details::ipv6_header);
        }
        return 0;
    }

    template<typename MutableBufferSequence>
    static void make_ip_header_packet(MutableBufferSequence &buffer,
                                      const network_layer::address_pair_type &address_pair,
                                      uint8_t protocol,
                                      uint16_t payload_len)
    {
        switch (address_pair.ip_version()) {
        case 4: {
            constexpr auto header_len = sizeof(details::ipv4_header);

            uint16_t tot_len = header_len + payload_len;

            constexpr uint8_t ihl = header_len / 4;
            static std::atomic_uint16_t index = 0;

            auto header = boost::asio::buffer_cast<details::ipv4_header *>(buffer);
            memset(header, 0, header_len);

            header->ihl = ihl;
            header->version = 4;
            header->tot_len = boost::asio::detail::socket_ops::host_to_network_short(tot_len);
            header->id = boost::asio::detail::socket_ops::host_to_network_short(index++);
            header->ttl = 0x30;
            header->protocol = protocol;
            header->saddr = boost::asio::detail::socket_ops::host_to_network_long(
                address_pair.src.to_v4().to_ulong());
            header->daddr = boost::asio::detail::socket_ops::host_to_network_long(
                address_pair.dest.to_v4().to_ulong());
            header->check = checksum::checksum((const uint8_t *) (header), header_len);

        } break;
        case 6: {
            constexpr auto header_len = sizeof(details::ipv6_header);

            auto src_addr_bytes = address_pair.src.to_v6().to_bytes();
            auto dst_addr_bytes = address_pair.dest.to_v6().to_bytes();

            auto header = boost::asio::buffer_cast<details::ipv6_header *>(buffer);
            memset(header, 0, header_len);

            header->version_traffic_flow = boost::asio::detail::socket_ops::host_to_network_long(
                make_version_traffic_flow(6, 0, 0));
            header->payload_len = boost::asio::detail::socket_ops::host_to_network_short(
                payload_len);
            header->next_header = protocol;
            header->hop_limit = 0x30;

            memcpy(header->src_addr, src_addr_bytes.data(), sizeof(header->src_addr));
            memcpy(header->dest_addr, dst_addr_bytes.data(), sizeof(header->dest_addr));

        } break;
        default:
            break;
        }
    }
    static std::optional<ip_packet> from_buffer(buffer::ref_buffer buffer)
    {
        auto buffers = buffer.data();

        auto buf = boost::asio::buffer_cast<const uint8_t *>(buffers);
        auto len = boost::asio::buffer_size(buffers);

        if (len == 0) {
            SPDLOG_INFO("Received packet is empty");
            return std::nullopt;
        }
        uint8_t version = (buf[0] & 0xf0) >> 4;
        switch (version) {
        case 4: {
            if (len < sizeof(details::ipv4_header)) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return std::nullopt;
            }

            auto header = boost::asio::buffer_cast<const details::ipv4_header *>(buffers);
            auto header_len = header->ihl * 4;
            auto total_len = ntohs(header->tot_len);

            if (header_len < sizeof(details::ipv4_header) || total_len != len
                || total_len < header_len) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return std::nullopt;
            }

            if (checksum::checksum((const uint8_t *) header, header_len) != 0) {
                SPDLOG_WARN("Received IPv4 packet Calculation checksum error");
                return std::nullopt;
            }

            address_pair_type addr_pair(boost::asio::detail::socket_ops::host_to_network_long(
                                            header->saddr),
                                        boost::asio::detail::socket_ops::host_to_network_long(
                                            header->daddr));

            SPDLOG_DEBUG("Received IPv4 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         header->protocol);

            buffer.consume(header_len);
            return ip_packet(addr_pair, header->protocol, buffer);
        } break;
        case 6: {
            if (len < sizeof(details::ipv6_header)) {
                SPDLOG_INFO("Received packet without room for an IPv6 header");
                return std::nullopt;
            }
            auto header = boost::asio::buffer_cast<const details::ipv6_header *>(buffers);

            auto version_traffic_flow = boost::asio::detail::socket_ops::network_to_host_long(
                header->version_traffic_flow);
            auto version = (version_traffic_flow >> 28) & 0xF;
            auto traffic = (version_traffic_flow >> 20) & 0xFF;
            auto flow = version_traffic_flow & 0xFFFFF;

            auto payload_len = boost::asio::detail::socket_ops::network_to_host_short(
                header->payload_len);

            boost::asio::ip::address_v6::bytes_type src_addr_bytes;
            boost::asio::ip::address_v6::bytes_type dst_addr_bytes;

            memcpy(src_addr_bytes.data(), header->src_addr, sizeof(header->src_addr));
            memcpy(dst_addr_bytes.data(), header->dest_addr, sizeof(header->dest_addr));

            network_layer::address_pair_type addr_pair(src_addr_bytes, dst_addr_bytes);

            SPDLOG_DEBUG("Received IPv6 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         header->next_header);

            buffer.consume(sizeof(details::ipv6_header));
            return ip_packet(addr_pair, header->next_header, buffer);
        } break;
        default:
            break;
        }
        return std::nullopt;
    } // namespace details
private:
    inline static uint32_t make_version_traffic_flow(uint8_t version, uint8_t traffic, uint32_t flow)
    {
        uint32_t value = 0;
        value |= uint32_t(version & 0xF0) << 28;
        value |= (uint32_t) traffic << 20;
        value |= flow & 0x000FFFFF;
        return value;
    }

private:
    network_layer::address_pair_type address_pair_;
    uint8_t protocol_;
    buffer::ref_const_buffer payload_buffer_;
};

} // namespace network_layer