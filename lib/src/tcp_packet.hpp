#pragma once
#include "ip_packet.hpp"

namespace transport_layer {

namespace details {
struct alignas(4) tcp_header
{
    uint16_t src_port;  // 源端口号
    uint16_t dest_port; // 目的端口号
    uint32_t seq_num;   // 序列号
    uint32_t ack_num;   // 确认号
    uint8_t data_offset_reserved;
    uint8_t flags;           // 标志字段
    uint16_t window_size;    // 窗口大小
    uint16_t checksum;       // 校验和
    uint16_t urgent_pointer; // 紧急指针
};
} // namespace details

class tcp_packet
{
public:
    constexpr static uint8_t protocol_type = 0x06;

public:
    explicit tcp_packet(const boost::asio::ip::tcp::endpoint &src_endpoint,
                        const boost::asio::ip::tcp::endpoint &dest_endpoint,
                        uint32_t seq_num,
                        uint32_t ack_num,
                        uint8_t flags,
                        const boost::asio::const_buffer &payload)
        : src_endpoint_(src_endpoint)
        , dest_endpoint_(dest_endpoint)
        , seq_num_(seq_num)
        , ack_num_(ack_num)
        , flags_(flags)
        , payload_(payload)

    {}
    inline static std::optional<tcp_packet> from_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        auto buffer = ip_pack.payload_data();

        if (buffer.size() < sizeof(details::tcp_header)) {
            SPDLOG_INFO("Received packet without room for a tcp header");
            return std::nullopt;
        }

        auto header = boost::asio::buffer_cast<const details::tcp_header *>(buffer);

        uint8_t data_offset = (header->data_offset_reserved & 0xf0) >> 4;
        auto header_len = data_offset * 4;

        if (buffer.size() < header_len) {
            SPDLOG_WARN("Received tcp packet length error");
            return std::nullopt;
        }

        if (checksum(header,
                     ip_pack.version(),
                     ip_pack.src_address(),
                     ip_pack.dest_address(),
                     (const uint8_t *) (header + 1),
                     buffer.size() - sizeof(details::tcp_header))
            != 0) {
            SPDLOG_WARN("Received IPv{0} tcp packet Calculation checksum error",
                        (int) ip_pack.version());
            return std::nullopt;
        }

        boost::asio::ip::tcp::endpoint src_endpoint(ip_pack.src_address(),
                                                    ::ntohs(header->src_port));
        boost::asio::ip::tcp::endpoint dest_endpoint(ip_pack.dest_address(),
                                                     ::ntohs(header->dest_port));

        SPDLOG_INFO("Received IPv{0} tcp packet [{1}]:{2} -> [{3}]:{4}",
                    (int) ip_pack.version(),
                    src_endpoint.address().to_string(),
                    src_endpoint.port(),
                    dest_endpoint.address().to_string(),
                    dest_endpoint.port());

        buffer += header_len;

        return tcp_packet(src_endpoint,
                          dest_endpoint,
                          ntohl(header->seq_num),
                          ntohl(header->ack_num),
                          header->flags,
                          buffer);
    }

private:
    inline static uint16_t checksum(const details::tcp_header *tcp,
                                    network_layer::ip_packet::version_type ip_version,
                                    const boost::asio::ip::address &src_addr,
                                    const boost::asio::ip::address &dest_addr,
                                    const uint8_t *data,
                                    std::size_t data_len)
    {
        switch (ip_version) {
        case network_layer::ip_packet::version_type::v4: {
            // 伪头结构体
            struct alignas(4) pseud_v4_tcp_header
            {
                uint32_t src_addr;
                uint32_t dest_addr;
                uint8_t reserved;
                uint8_t protocol;
                uint16_t tcp_length;
            } psh{0};
            psh.src_addr = ::htonl(src_addr.to_v4().to_ulong());
            psh.dest_addr = ::htonl(dest_addr.to_v4().to_ulong());
            psh.protocol = tcp_packet::protocol_type;
            psh.tcp_length = htons(sizeof(details::tcp_header) + data_len);

            return checksum::checksum(tcp, &psh, data, data_len);
        }

        case network_layer::ip_packet::version_type::v6: {
            // IPv6伪头结构体
            struct alignas(4) pseud_v6_tcp_header
            {
                uint8_t src_addr[16];
                uint8_t dest_addr[16];
                uint32_t length;
                uint8_t zeros[3];
                uint8_t protocol;
            } psh = {0};
            memcpy(psh.src_addr, src_addr.to_v6().to_bytes().data(), sizeof(psh.src_addr));
            memcpy(psh.dest_addr, dest_addr.to_v6().to_bytes().data(), sizeof(psh.dest_addr));
            psh.protocol = tcp_packet::protocol_type;
            psh.length = htons(sizeof(details::tcp_header) + data_len);

            return checksum::checksum(tcp, &psh, data, data_len);
        }
        default:
            break;
        }
        return 0;
    }

private:
    uint32_t seq_num_;
    uint32_t ack_num_;
    uint8_t flags_;
    boost::asio::ip::tcp::endpoint src_endpoint_;
    boost::asio::ip::tcp::endpoint dest_endpoint_;

    boost::asio::const_buffer payload_;
};
} // namespace transport_layer