#pragma once
#include "address_pair.hpp"
#include "checksum.hpp"
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
              const boost::asio::const_buffer &payload_data)
        : address_pair_(address_pair)
        , protocol_(protocol)
        , payload_data_(payload_data)
    {}

    const network_layer::address_pair_type &address_pair() const { return address_pair_; }

    uint8_t next_protocol() const { return protocol_; }
    boost::asio::const_buffer payload_data() const { return payload_data_; }

    template<typename Allocator>
    void make_packet(boost::asio::basic_streambuf<Allocator> &buffer) const
    {
        switch (address_pair_.ip_version()) {
        case 4: {
            constexpr auto header_len = sizeof(details::ipv4_header);

            constexpr uint8_t ihl = header_len / 4;
            static std::atomic_uint16_t index = 0;

            uint16_t tot_len = header_len + payload_data_.size();

            auto buf = buffer.prepare(tot_len);
            memset(buf.data(), 0, tot_len);

            auto header = boost::asio::buffer_cast<details::ipv4_header *>(buf);

            header->ihl = ihl;
            header->version = 4;
            header->tot_len = ::htons(tot_len);
            header->id = ::htons(index++);
            header->ttl = 0x30;
            header->protocol = protocol_;
            header->saddr = ::htonl(address_pair_.src.to_v4().to_ulong());
            header->daddr = ::htonl(address_pair_.dest.to_v4().to_ulong());

            header->check = checksum::checksum((const uint8_t *) (header), header_len);
            memcpy(header + 1, payload_data_.data(), payload_data_.size());

            buffer.commit(tot_len);

        } break;
        case 6: {
            constexpr auto header_len = sizeof(details::ipv6_header);

            auto payload_len = boost::asio::buffer_size(payload_data_);
            auto src_addr_bytes = address_pair_.src.to_v6().to_bytes();
            auto dst_addr_bytes = address_pair_.dest.to_v6().to_bytes();

            auto header_buffer = buffer.prepare(header_len);

            auto header = boost::asio::buffer_cast<details::ipv6_header *>(header_buffer);
            memset(header, 0, sizeof(details::ipv6_header));

            header->version_traffic_flow = ::htonl(make_version_traffic_flow(6, 0, 0));
            header->payload_len = ::htons(payload_len);
            header->next_header = protocol_;
            header->hop_limit = 0x30;

            memcpy(header->src_addr, src_addr_bytes.data(), sizeof(header->src_addr));
            memcpy(header->dest_addr, dst_addr_bytes.data(), sizeof(header->dest_addr));

            buffer.commit(header_len);
            if (payload_len > 0) {
                auto payload_buffer = buffer.prepare(payload_len);
                boost::asio::buffer_copy(payload_buffer, payload_data_);
                buffer.commit(payload_len);
            }
        } break;
        default:
            break;
        }
    }
    template<typename ConstBufferSequence>
    static std::unique_ptr<ip_packet> from_packet(ConstBufferSequence &&buffers)
    {
        auto buf = boost::asio::buffer_cast<const uint8_t *>(buffers);
        auto len = boost::asio::buffer_size(buffers);

        if (len == 0) {
            SPDLOG_INFO("Received packet is empty");
            return nullptr;
        }
        uint8_t version = (buf[0] & 0xf0) >> 4;
        switch (version) {
        case 4: {
            if (len < sizeof(details::ipv4_header)) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return nullptr;
            }

            auto header = boost::asio::buffer_cast<const details::ipv4_header *>(buffers);
            auto header_len = header->ihl * 4;
            auto total_len = ntohs(header->tot_len);

            if (header_len < sizeof(details::ipv4_header) || total_len != len
                || total_len < header_len) {
                SPDLOG_INFO("Received packet without room for an IPv4 header");
                return nullptr;
            }

            if (checksum::checksum((const uint8_t *) header, header_len) != 0) {
                SPDLOG_WARN("Received IPv4 packet Calculation checksum error");
                return nullptr;
            }

            address_pair_type addr_pair(::htonl(header->saddr), ::htonl(header->daddr));

            SPDLOG_DEBUG("Received IPv4 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         header->protocol);

            buffers += header_len;

            return std::make_unique<ip_packet>(addr_pair, header->protocol, buffers);
        } break;
        case 6: {
            if (len < sizeof(details::ipv6_header)) {
                SPDLOG_INFO("Received packet without room for an IPv6 header");
                return nullptr;
            }
            auto header = boost::asio::buffer_cast<const details::ipv6_header *>(buffers);

            auto version_traffic_flow = ::ntohl(header->version_traffic_flow);
            auto version = (version_traffic_flow >> 28) & 0xF;
            auto traffic = (version_traffic_flow >> 20) & 0xFF;
            auto flow = version_traffic_flow & 0xFFFFF;

            auto payload_len = ::ntohs(header->payload_len);

            boost::asio::ip::address_v6::bytes_type src_addr_bytes;
            boost::asio::ip::address_v6::bytes_type dst_addr_bytes;

            memcpy(src_addr_bytes.data(), header->src_addr, sizeof(header->src_addr));
            memcpy(dst_addr_bytes.data(), header->dest_addr, sizeof(header->dest_addr));

            network_layer::address_pair_type addr_pair(src_addr_bytes, dst_addr_bytes);

            SPDLOG_DEBUG("Received IPv6 packet {0} protocol:[0x{1:x}]",
                         addr_pair.to_string(),
                         header->next_header);

            buffers += sizeof(details::ipv6_header);
            return std::make_unique<ip_packet>(addr_pair, header->next_header, buffers);
        } break;
        default:
            break;
        }
        return nullptr;
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
    boost::asio::const_buffer payload_data_;
};

//template<typename Allocator, typename ConstBufferSequence>
//void make_icmp_packet(boost::asio::basic_streambuf<Allocator> &buffer,
//                      uint8_t type,
//                      uint8_t code,
//                      uint16_t identifier,
//                      uint16_t sequenceNumber,
//                      const ConstBufferSequence &payload)
//{
//    constexpr auto header_len = sizeof(details::icmp_header);
//    auto payload_len = boost::asio::buffer_size(payload);
//
//    auto header_buffer = buffer.prepare(header_len);
//    memset(header_buffer.data(), 0, header_buffer.size());
//
//    auto header = boost::asio::buffer_cast<details::icmp_header *>(header_buffer);
//    header->type = type;
//    header->code = code;
//    header->identifier = ::htons(identifier);
//    header->sequenceNumber = ::htons(sequenceNumber);
//    header->checksum = details::ip_checksum((const uint8_t *) (header), header_len);
//
//    buffer.commit(header_len);
//
//    if (payload_len != 0) {
//        auto payload_buffer = buffer.prepare(payload_len);
//        boost::asio::buffer_copy(payload_buffer, payload);
//        buffer.commit(payload_len);
//    }
//}

} // namespace network_layer