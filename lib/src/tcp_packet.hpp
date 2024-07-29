#pragma once
#include "endpoint_pair.hpp"
#include "ip_packet.hpp"
#include <format>

namespace transport_layer {

namespace details {
struct alignas(4) tcp_header
{
    uint16_t src_port;  // 源端口号
    uint16_t dest_port; // 目的端口号
    uint32_t seq_num;   // 序列号
    uint32_t ack_num;   // 确认号
    uint8_t reserved : 4;
    uint8_t data_offset : 4;
    uint8_t flags;           // 标志字段
    uint16_t window_size;    // 窗口大小
    uint16_t checksum;       // 校验和
    uint16_t urgent_pointer; // 紧急指针
};
} // namespace details

class tcp_packet
{
public:
    constexpr static uint8_t protocol = 0x06;

    union tcp_flags {
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
        uint32_t seq_num = 0;
        uint32_t ack_num = 0;
        tcp_flags flags;
        uint16_t window_size = 4096;
    };

public:
    explicit tcp_packet(const tcp_endpoint_pair &_endpoint_pair,
                        const tcp_packet::header &header_data,
                        const boost::asio::const_buffer &payload = boost::asio::const_buffer())
        : endpoint_pair_(_endpoint_pair)
        , header_data_(header_data)
        , payload_(payload)

    {}

    const tcp_endpoint_pair &endpoint_pair() const { return endpoint_pair_; }
    const boost::asio::const_buffer &payload() const { return payload_; }

    const tcp_packet::header &header_data() const { return header_data_; }

    template<typename Allocator>
    void make_packet(boost::asio::basic_streambuf<Allocator> &buffers) const
    {
        uint16_t length = sizeof(details::tcp_header) + (uint16_t) payload_.size();

        auto buf = buffers.prepare(length);
        memset(buf.data(), 0, length);

        auto header = boost::asio::buffer_cast<details::tcp_header *>(buf);
        header->src_port = ::htons(endpoint_pair_.src.port());
        header->dest_port = ::htons(endpoint_pair_.dest.port());
        header->seq_num = ::htonl(header_data_.seq_num);
        header->ack_num = ::htonl(header_data_.ack_num);
        header->data_offset = sizeof(details::tcp_header) / 4;
        header->flags = header_data_.flags.data;
        header->window_size = htons(header_data_.window_size);
        header->checksum = checksum(header,
                                    endpoint_pair_.to_address_pair(),
                                    boost::asio::const_buffer((const uint8_t *) payload_.data(),
                                                              payload_.size()));
        memcpy(header + 1, payload_.data(), payload_.size());
        buffers.commit(length);
    }
    template<typename Allocator>
    void make_ip_packet(boost::asio::basic_streambuf<Allocator> &buffers) const
    {
        boost::asio::streambuf payload;
        make_packet(payload);

        network_layer::ip_packet ip_pack(endpoint_pair_.to_address_pair(),
                                         tcp_packet::protocol,
                                         payload.data());
        ip_pack.make_packet(buffers);
    }

    inline static std::unique_ptr<tcp_packet> from_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        auto buffer = ip_pack.payload_data();

        if (buffer.size() < sizeof(details::tcp_header)) {
            SPDLOG_WARN("Received packet without room for a tcp header");
            return nullptr;
        }

        auto header = boost::asio::buffer_cast<const details::tcp_header *>(buffer);
        auto header_len = header->data_offset * 4;

        if (buffer.size() < header_len) {
            SPDLOG_WARN("Received tcp packet length error");
            return nullptr;
        }

        if (checksum(header,
                     ip_pack.address_pair(),
                     boost::asio::const_buffer((header + 1),
                                               buffer.size() - sizeof(details::tcp_header)))
            != 0) {
            SPDLOG_WARN("Received IPv{0} tcp packet Calculation checksum error",
                        ip_pack.address_pair().ip_version());
            return nullptr;
        }
        tcp_endpoint_pair endpoint_pair(ip_pack.address_pair(),
                                        ::ntohs(header->src_port),
                                        ::ntohs(header->dest_port));

        SPDLOG_DEBUG("Received IPv{0} TCP Packet {1}",
                     ip_pack.address_pair().ip_version(),
                     endpoint_pair.to_string());

        buffer += header_len;

        tcp_packet::header header_data;
        header_data.seq_num = ntohl(header->seq_num);
        header_data.ack_num = ntohl(header->ack_num);
        header_data.window_size = ntohs(header->window_size);
        header_data.flags.data = header->flags;

        return std::make_unique<tcp_packet>(endpoint_pair, header_data, buffer);
    }

private:
    inline static uint16_t checksum(const details::tcp_header *tcp,
                                    const network_layer::address_pair_type &address_pair,
                                    const boost::asio::const_buffer payload)
    {
        switch (address_pair.ip_version()) {
        case 4: {
            // 伪头结构体
            struct alignas(4) pseud_v4_tcp_header
            {
                uint32_t src_addr;
                uint32_t dest_addr;
                uint8_t reserved;
                uint8_t protocol;
                uint16_t tcp_length;
            } psh{0};
            psh.src_addr = ::htonl(address_pair.src.to_v4().to_ulong());
            psh.dest_addr = ::htonl(address_pair.dest.to_v4().to_ulong());
            psh.protocol = tcp_packet::protocol;
            psh.tcp_length = htons(sizeof(details::tcp_header) + (uint16_t) payload.size());

            return checksum::checksum(tcp,
                                      &psh,
                                      (const uint8_t *) payload.data(),
                                      (uint16_t) payload.size());
        }

        case 6: {
            // IPv6伪头结构体
            struct alignas(4) pseud_v6_tcp_header
            {
                uint8_t src_addr[16];
                uint8_t dest_addr[16];
                uint32_t length;
                uint8_t zeros[3];
                uint8_t protocol;
            } psh = {0};
            memcpy(psh.src_addr, address_pair.src.to_v6().to_bytes().data(), sizeof(psh.src_addr));
            memcpy(psh.dest_addr,
                   address_pair.dest.to_v6().to_bytes().data(),
                   sizeof(psh.dest_addr));
            psh.protocol = tcp_packet::protocol;
            psh.length = htons(sizeof(details::tcp_header) + (uint16_t) payload.size());

            return checksum::checksum(tcp,
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
    header header_data_;
    tcp_endpoint_pair endpoint_pair_;
    boost::asio::const_buffer payload_;
};
} // namespace transport_layer
