#pragma once
#include "checksum.hpp"
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
    constexpr static uint8_t protocol_type = 0x11;

public:
    udp_packet(network_layer::ip_packet::version_type ip_version,
               const boost::asio::ip::udp::endpoint &src_endpoint,
               const boost::asio::ip::udp::endpoint &dest_endpoint,
               const boost::asio::const_buffer &payload)
        : ip_version_(ip_version)
        , src_endpoint_(src_endpoint)
        , dest_endpoint_(dest_endpoint)
        , payload_(payload)
    {}
    inline network_layer::ip_packet::version_type ip_version() const { return ip_version_; }
    inline boost::asio::const_buffer payload() const { return payload_; }
    inline boost::asio::ip::udp::endpoint src_endpoint() const { return src_endpoint_; }
    inline boost::asio::ip::udp::endpoint dest_endpoint() const { return dest_endpoint_; }

    template<typename Allocator>
    void make_packet(boost::asio::basic_streambuf<Allocator> &buffers)
    {
        uint16_t length = sizeof(details::udp_header) + payload_.size();

        auto buf = buffers.prepare(length);
        memset(buf.data(), 0, length);

        auto header = boost::asio::buffer_cast<details::udp_header *>(buf);
        header->src_port = ::htons(src_endpoint_.port());
        header->dest_port = ::htons(dest_endpoint_.port());
        header->length = ::htons(length);
        header->checksum = checksum(header,
                                    ip_version_,
                                    src_endpoint_.address(),
                                    dest_endpoint_.address(),
                                    payload_.data(),
                                    payload_.size());
        memcpy(header + 1, payload_.data(), payload_.size());
        buffers.commit(length);
    }

    inline static std::optional<udp_packet> from_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        if (ip_pack.next_protocol() != udp_packet::protocol_type)
            return std::nullopt;

        auto buffer = ip_pack.payload_data();
        if (buffer.size() < sizeof(details::udp_header)) {
            SPDLOG_INFO("Received packet without room for an upd header");
            return std::nullopt;
        }

        auto header = boost::asio::buffer_cast<const details::udp_header *>(buffer);
        uint16_t total_len = ::ntohs(header->length);
        if (total_len != buffer.size()) {
            SPDLOG_WARN("Received udp packet length error");
            return std::nullopt;
        }
        uint16_t payload_len = total_len - sizeof(details::udp_header);

        if (checksum(header,
                     ip_pack.version(),
                     ip_pack.src_address(),
                     ip_pack.dest_address(),
                     (const uint8_t *) (header + 1),
                     payload_len)
            != 0) {
            SPDLOG_WARN("Received IPv{0} udp packet Calculation checksum error",
                        (int) ip_pack.version());
            return std::nullopt;
        }
        boost::asio::ip::udp::endpoint src_endpoint(ip_pack.src_address(),
                                                    ::ntohs(header->src_port));
        boost::asio::ip::udp::endpoint dest_endpoint(ip_pack.dest_address(),
                                                     ::ntohs(header->dest_port));

        SPDLOG_INFO("Received IPv{0} udp packet [{1}]:{2} -> [{3}]:{4}",
                    (int) ip_pack.version(),
                    src_endpoint.address().to_string(),
                    src_endpoint.port(),
                    dest_endpoint.address().to_string(),
                    dest_endpoint.port());

        return udp_packet(ip_pack.version(),
                          src_endpoint,
                          dest_endpoint,
                          boost::asio::const_buffer(header + 1, payload_len));
    }

private:
    inline static uint16_t checksum(const details::udp_header *udp,
                                    network_layer::ip_packet::version_type ip_version,
                                    const boost::asio::ip::address &src_addr,
                                    const boost::asio::ip::address &dest_addr,
                                    const uint8_t *data,
                                    std::size_t data_len)
    {
        switch (ip_version) {
        case network_layer::ip_packet::version_type::v4: {
            // 伪头结构体
            struct alignas(4) pseud_v4_udp_header
            {
                uint32_t src_addr;   // 源IP地址
                uint32_t dest_addr;  // 目的IP地址
                uint8_t reserved;    // 预留字段
                uint8_t protocol;    // 协议号 (UDP协议为17)
                uint16_t udp_length; // UDP长度
            } psh{0};
            psh.src_addr = ::htonl(src_addr.to_v4().to_ulong());
            psh.dest_addr = ::htonl(dest_addr.to_v4().to_ulong());
            psh.reserved = 0;
            psh.protocol = udp_packet::protocol_type;
            psh.udp_length = htons(sizeof(details::udp_header) + data_len);

            return checksum::checksum(udp, &psh, data, data_len);
        }

        case network_layer::ip_packet::version_type::v6: {
            // IPv6伪头结构体
            struct alignas(4) pseud_v6_udp_header
            {
                uint8_t src_addr[16];  // 源IP地址
                uint8_t dest_addr[16]; // 目的IP地址
                uint32_t length;       // UDP长度
                uint8_t zero;          // 预留字段
                uint8_t protocol;      // 协议号 (UDP协议为17)
            } psh = {0};
            memcpy(psh.src_addr, src_addr.to_v6().to_bytes().data(), sizeof(psh.src_addr));
            memcpy(psh.dest_addr, dest_addr.to_v6().to_bytes().data(), sizeof(psh.dest_addr));
            psh.zero = 0;
            psh.protocol = udp_packet::protocol_type;
            psh.length = htons(sizeof(details::udp_header) + data_len);

            return checksum::checksum(udp, &psh, data, data_len);
        }
        default:
            break;
        }
        return 0;
    }

private:
    network_layer::ip_packet::version_type ip_version_;
    boost::asio::ip::udp::endpoint src_endpoint_;
    boost::asio::ip::udp::endpoint dest_endpoint_;
    boost::asio::const_buffer payload_;
};

} // namespace transport_layer