#pragma once
#include "checksum.hpp"
#include "endpoint_pair.hpp"
#include "ip_packet.hpp"
#include <boost/asio.hpp>
namespace transport_layer {

namespace details {
// 定义UDP头结构体
struct alignas(4) udp_header
{
    uint16_t src_port;  // 源端口号
    uint16_t dest_port; // 目的端口号
    uint16_t length;    // 长度
    uint16_t checksum;  // 校验和
};

} // namespace details
class udp_packet
{
public:
    constexpr static uint8_t protocol = 0x11;

public:
    udp_packet(const udp_endpoint_pair &endpoint_pair, const boost::asio::const_buffer &payload)
        : endpoint_pair_(endpoint_pair)
        , payload_(payload)
    {}
    inline const udp_endpoint_pair &endpoint_pair() const { return endpoint_pair_; }
    inline boost::asio::const_buffer payload() const { return payload_; }

    std::size_t raw_packet_size() const
    {
        return sizeof(details::udp_header) + boost::asio::buffer_size(payload());
    }

    std::size_t make_packet(boost::asio::mutable_buffer buffers) const
    {
        uint16_t length = raw_packet_size();
        auto paload_data = payload();

        memset(buffers.data(), 0, length);

        auto header = boost::asio::buffer_cast<details::udp_header *>(buffers);
        header->src_port = ::htons(endpoint_pair_.src.port());
        header->dest_port = ::htons(endpoint_pair_.dest.port());
        header->length = ::htons(length);
        header->checksum = checksum(header, endpoint_pair_.to_address_pair(), paload_data);

        memcpy(header + 1, paload_data.data(), paload_data.size());
        return length;
    }

    template<typename Allocator>
    void make_ip_packet(boost::asio::basic_streambuf<Allocator> &buffers)
    {
        boost::asio::streambuf payload;
        make_packet(payload);

        network_layer::ip_packet ip_pack(endpoint_pair_.to_address_pair(),
                                         udp_packet::protocol,
                                         payload.data());
        ip_pack.make_packet(buffers);
    }

    inline static std::unique_ptr<udp_packet> from_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        if (ip_pack.next_protocol() != udp_packet::protocol)
            return nullptr;

        auto buffer = ip_pack.payload_data();
        if (buffer.size() < sizeof(details::udp_header)) {
            SPDLOG_WARN("Received packet without room for an upd header");
            return nullptr;
        }

        auto header = boost::asio::buffer_cast<const details::udp_header *>(buffer);
        uint16_t total_len = ::ntohs(header->length);
        if (total_len != buffer.size()) {
            SPDLOG_WARN("Received udp packet length error");
            return nullptr;
        }
        uint16_t payload_len = total_len - sizeof(details::udp_header);

        if (checksum(header,
                     ip_pack.address_pair(),
                     boost::asio::const_buffer((const uint8_t *) (header + 1), payload_len))
            != 0) {
            SPDLOG_WARN("Received IPv{0} udp packet Calculation checksum error",
                        ip_pack.address_pair().ip_version());
            return nullptr;
        }
        udp_endpoint_pair point_pair(ip_pack.address_pair(),
                                     ::ntohs(header->src_port),
                                     ::ntohs(header->dest_port));

        SPDLOG_DEBUG("Received IPv{0} udp packet {1}",
                     ip_pack.address_pair().ip_version(),
                     point_pair.to_string());

        return std::make_unique<udp_packet>(point_pair,
                                            boost::asio::const_buffer(header + 1, payload_len));
    }

private:
    inline static uint16_t checksum(const details::udp_header *udp,
                                    const network_layer::address_pair_type &address_pair,
                                    const boost::asio::const_buffer &payload)
    {
        switch (address_pair.ip_version()) {
        case 4: {
            // 伪头结构体
            struct alignas(4) pseud_v4_udp_header
            {
                uint32_t src_addr;   // 源IP地址
                uint32_t dest_addr;  // 目的IP地址
                uint8_t reserved;    // 预留字段
                uint8_t protocol;    // 协议号 (UDP协议为17)
                uint16_t udp_length; // UDP长度
            } psh{0};
            psh.src_addr = ::htonl(address_pair.src.to_v4().to_ulong());
            psh.dest_addr = ::htonl(address_pair.dest.to_v4().to_ulong());
            psh.reserved = 0;
            psh.protocol = udp_packet::protocol;
            psh.udp_length = htons(sizeof(details::udp_header) + (uint16_t) payload.size());

            return checksum::checksum(udp,
                                      &psh,
                                      (const uint8_t *) payload.data(),
                                      (uint16_t) payload.size());
        }

        case 6: {
            // IPv6伪头结构体
            struct alignas(4) pseud_v6_udp_header
            {
                uint8_t src_addr[16];  // 源IP地址
                uint8_t dest_addr[16]; // 目的IP地址
                uint32_t length;       // UDP长度
                uint8_t zero;          // 预留字段
                uint8_t protocol;      // 协议号 (UDP协议为17)
            } psh = {0};
            memcpy(psh.src_addr, address_pair.src.to_v6().to_bytes().data(), sizeof(psh.src_addr));
            memcpy(psh.dest_addr,
                   address_pair.dest.to_v6().to_bytes().data(),
                   sizeof(psh.dest_addr));
            psh.zero = 0;
            psh.protocol = udp_packet::protocol;
            psh.length = htons(sizeof(details::udp_header) + (uint16_t) payload.size());

            return checksum::checksum(udp,
                                      &psh,
                                      (const uint8_t *) payload.data(),
                                      (uint16_t) payload.size());
        }
        default:
            break;
        }
        return 0;
    }

private:
    udp_endpoint_pair endpoint_pair_;
    boost::asio::const_buffer payload_;
};

} // namespace transport_layer