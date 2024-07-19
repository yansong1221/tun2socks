#pragma once
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

struct alignas(4) tcp_header
{
    uint16_t sourcePort;           // 源端口号
    uint16_t destPort;             // 目标端口号
    uint32_t sequenceNumber;       // 序列号
    uint32_t acknowledgmentNumber; // 确认号
    uint8_t dataOffset;            // 数据偏移 + 保留字段
    uint8_t flags;                 // 标志位
    uint16_t windowSize;           // 窗口大小
    uint16_t checksum;             // 校验和
    uint16_t urgentPointer;        // 紧急指针
    // 可选的选项字段可以在需要时添加
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
    enum class version_type : uint8_t { v4 = 4, v6 = 6 };

    explicit ip_packet(version_type version,
                       const boost::asio::ip::address &src_addr,
                       const boost::asio::ip::address &dst_addr,
                       uint8_t protocol,
                       const boost::asio::const_buffer &payload_data)
        : version_(version)
        , src_addr_(src_addr)
        , dst_addr_(dst_addr)
        , protocol_(protocol)
        , payload_data_(payload_data)
    {}

    version_type version() const { return version_; }
    boost::asio::ip::address src_address() const { return src_addr_; }
    boost::asio::ip::address dst_address() const { return dst_addr_; }
    uint8_t next_protocol() const { return protocol_; }
    boost::asio::const_buffer payload_data() const { return payload_data_; }

    template<typename Allocator>
    void make_packet(boost::asio::basic_streambuf<Allocator> &buffer) const
    {
        switch (version_) {
        case version_type::v4: {
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
            header->saddr = ::htonl(src_addr_.to_v4().to_ulong());
            header->daddr = ::htonl(dst_addr_.to_v4().to_ulong());

            header->check = ip_checksum((const uint8_t *) (header), header_len);
            memcpy(header + 1, payload_data_.data(), payload_data_.size());

            buffer.commit(tot_len);

        } break;
        case version_type::v6: {
            constexpr auto header_len = sizeof(details::ipv6_header);

            auto payload_len = boost::asio::buffer_size(payload_data_);
            auto src_addr_bytes = src_addr_.to_v6().to_bytes();
            auto dst_addr_bytes = dst_addr_.to_v6().to_bytes();

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
    static std::optional<ip_packet> from_packet(ConstBufferSequence &&buffers)
    {
        auto buf = boost::asio::buffer_cast<const uint8_t *>(buffers);
        auto len = boost::asio::buffer_size(buffers);

        if (len == 0) {
            SPDLOG_INFO("Received packet is empty");
            return std::nullopt;
        }
        uint8_t version = (buf[0] & 0xf0) >> 4;
        switch (version) {
        case (uint8_t) version_type::v4: {
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

            if (ip_checksum((const uint8_t *) header, header_len) != 0) {
                SPDLOG_WARN("Received IPv4 packet Calculation checksum error");
                return std::nullopt;
            }

            boost::asio::ip::address_v4 src_addr(::htonl(header->saddr));
            boost::asio::ip::address_v4 dst_addr(::htonl(header->daddr));

            SPDLOG_DEBUG("IPv4 Packet [{0}] -> [{1}] protocol:[0x{2:x}]",
                         src_addr.to_string(),
                         dst_addr.to_string(),
                         header->protocol);

            buffers += header_len;
            //if (auto options_len = header_len - sizeof(details::ipv4_header); options_len > 0) {
            //    /* auto data = boost::asio::buffer_cast<const uint8_t *>(buffers);
            //    auto options_data = boost::asio::const_buffer(data, options_len);

            //    SPDLOG_INFO("Received packet without room for an IPv4 header");*/
            //    // 跳过
            //    buffers += options_len;
            //}

            return ip_packet(ip_packet::version_type::v4,
                             boost::asio::ip::address(src_addr),
                             boost::asio::ip::address(dst_addr),
                             header->protocol,
                             buffers);
        } break;
        case (uint8_t) version_type::v6: {
            if (len < sizeof(details::ipv6_header)) {
                SPDLOG_INFO("Received packet without room for an IPv6 header");
                return std::nullopt;
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

            boost::asio::ip::address_v6 src_addr(src_addr_bytes);
            boost::asio::ip::address_v6 dst_addr(dst_addr_bytes);

            SPDLOG_DEBUG("IPv6 Packet [{0}] -> [{1}] protocol:[0x{2:x}]",
                         src_addr.to_string(),
                         dst_addr.to_string(),
                         header->next_header);

            buffers += sizeof(details::ipv6_header);

            return ip_packet(ip_packet::version_type::v6,
                             boost::asio::ip::address(src_addr),
                             boost::asio::ip::address(dst_addr),
                             header->next_header,
                             buffers);
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
    inline static uint16_t ip_checksum(const uint8_t *buffer, std::size_t len)
    {
        uint32_t sum = 0;
        for (; len > 1; len -= 2, buffer += 2)
            sum += *(uint16_t *) buffer;
        if (len)
            sum += *buffer;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (uint16_t) (~sum);
    }

private:
    version_type version_;
    boost::asio::ip::address src_addr_;
    boost::asio::ip::address dst_addr_;
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