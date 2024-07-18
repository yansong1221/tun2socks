#pragma once
#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

namespace ip_packet {

enum class transport_protocol_type : uint8_t {
    unknown = 0,
    icmp = 0x01,
    tcp = 0x06,
    udp = 0x11,
};

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

inline static uint32_t make_version_traffic_flow(uint8_t version, uint8_t traffic, uint32_t flow)
{
    uint32_t value = 0;
    value |= uint32_t(version & 0xF0) << 28;
    value |= (uint32_t) traffic << 20;
    value |= flow & 0x000FFFFF;
    return value;
}

} // namespace details

class ip
{
public:
    enum class version_type { v4, v6 };
    virtual ~ip() = default;
    virtual version_type version() const = 0;
    virtual uint8_t next_protocol() const = 0;
    virtual boost::asio::const_buffer payload() const = 0;
};

class ipv4 : public ip
{
public:
    ipv4(boost::asio::ip::address_v4 &&src_addr,
         boost::asio::ip::address_v4 &&dst_addr,
         uint8_t protocol,
         boost::asio::const_buffer &&options_data,
         boost::asio::const_buffer &&payload_data)
        : src_addr_(src_addr)
        , dst_addr_(dst_addr)
        , protocol_(protocol)
        , options_data_(options_data)
        , payload_data_(payload_data)
    {}

public:
    version_type version() const override { return ip::version_type::v4; }
    uint8_t next_protocol() const override { return protocol_; }
    boost::asio::const_buffer payload() const override { return payload_data_; }

    boost::asio::ip::address_v4 src_address() const { return src_addr_; }
    boost::asio::ip::address_v4 dst_address() const { return dst_addr_; }

private:
    boost::asio::ip::address_v4 src_addr_;
    boost::asio::ip::address_v4 dst_addr_;
    uint8_t protocol_;
    boost::asio::const_buffer options_data_;
    boost::asio::const_buffer payload_data_;
};

template<typename Allocator, typename ConstBufferSequence>
void make_ipv4_packet(boost::asio::basic_streambuf<Allocator> &buffer,
                      const transport_protocol_type &proto_type,
                      const boost::asio::ip::address_v4 &src_addr,
                      const boost::asio::ip::address_v4 &dst_addr,
                      const ConstBufferSequence &payload)
{
    constexpr auto header_len = sizeof(details::ipv4_header);
    constexpr uint8_t ihl = header_len / 4;
    static std::atomic_uint16_t index = 0;

    auto payload_len = boost::asio::buffer_size(payload);

    auto header_buffer = buffer.prepare(header_len);
    memset(header_buffer.data(), 0, header_buffer.size());

    auto header = boost::asio::buffer_cast<details::ipv4_header *>(header_buffer);

    header->ihl = ihl;
    header->version = 4;
    header->tot_len = ::htons(sizeof(details::ipv4_header) + payload_len);
    header->id = ::htons(index++);
    header->ttl = 0x30;
    header->protocol = proto_type;
    header->saddr = ::htonl(src_addr.to_ulong());
    header->daddr = ::htonl(dst_addr.to_ulong());
    header->check = details::ip_checksum((const uint8_t *) (header), header_len);
    buffer.commit(header_len);

    auto payload_buffer = buffer.prepare(payload_len);
    boost::asio::buffer_copy(payload_buffer, payload);
    buffer.commit(payload_len);
}

template<typename Allocator, typename ConstBufferSequence>
void make_ipv6_packet(boost::asio::basic_streambuf<Allocator> &buffer,
                      const transport_protocol_type &proto_type,
                      const boost::asio::ip::address_v6 &src_addr,
                      const boost::asio::ip::address_v6 &dst_addr,
                      const ConstBufferSequence &payload)
{
    constexpr auto header_len = sizeof(details::ipv6_header);

    auto payload_len = boost::asio::buffer_size(payload);
    auto src_addr_bytes = src_addr.to_bytes();
    auto dst_addr_bytes = dst_addr.to_bytes();

    auto header_buffer = buffer.prepare(header_len);
    memset(header_buffer.data(), 0, header_buffer.size());

    auto header = boost::asio::buffer_cast<details::ipv6_header *>(header_buffer);
    header->version_traffic_flow = ::htonl(make_version_traffic_flow(6, 0, 0));
    header->payload_len = ::htons(payload_len);
    header->next_header = proto_type;
    header->hop_limit = 0x30;
    std::copy(src_addr_bytes.begin(), src_addr_bytes.end(), std::begin(header->src_addr));
    std::copy(dst_addr_bytes.begin(), dst_addr_bytes.end(), std::begin(header->dest_addr));

    buffer.commit(header_len);

    auto payload_buffer = buffer.prepare(payload_len);
    boost::asio::buffer_copy(payload_buffer, payload);
    buffer.commit(payload_len);
}
template<typename Allocator, typename ConstBufferSequence>
void make_icmp_packet(boost::asio::basic_streambuf<Allocator> &buffer,
                      uint8_t type,
                      uint8_t code,
                      uint16_t identifier,
                      uint16_t sequenceNumber,
                      const ConstBufferSequence &payload)
{
    constexpr auto header_len = sizeof(details::icmp_header);
    auto payload_len = boost::asio::buffer_size(payload);

    auto header_buffer = buffer.prepare(header_len);
    memset(header_buffer.data(), 0, header_buffer.size());

    auto header = boost::asio::buffer_cast<details::icmp_header *>(header_buffer);
    header->type = type;
    header->code = code;
    header->identifier = ::htons(identifier);
    header->sequenceNumber = ::htons(sequenceNumber);
    header->checksum = details::ip_checksum((const uint8_t *) (header), header_len);

    buffer.commit(header_len);

    if (payload_len != 0) {
        auto payload_buffer = buffer.prepare(payload_len);
        boost::asio::buffer_copy(payload_buffer, payload);
        buffer.commit(payload_len);
    }
}

template<typename ConstBufferSequence>
std::shared_ptr<ip> lookup_endpoint_pair(const ConstBufferSequence &buffers)
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

        if (header_len < sizeof(ipv4_header) || total_len < header_len) {
            SPDLOG_INFO("Received packet without room for an IPv4 header");
            return nullptr;
        }
        boost::asio::ip::address_v4 src_addr(htonl(header->saddr));
        boost::asio::ip::address_v4 dst_addr(htonl(header->daddr));

        auto protocol = header->protocol;

        buffers += header_len;

        boost::asio::const_buffer options_data;

        if (auto options_len = header_len - sizeof(ipv4_header); options_len > 0) {
            auto data = boost::asio::buffer_cast<void *>(buffers);
            options_data = boost::asio::const_buffer(data, options_len);
            buffers += options_len;
        }

        return std::make_shared<ipv4>(src_addr,
                                      dst_addr,
                                      protocol,
                                      options_data,
                                      boost::asio::const_buffer(buffers));
    } break;
    case 6: {
        if (len < sizeof(ipv6_header)) {
            SPDLOG_INFO("Received packet without room for an IPv6 header");
            return;
        }
        auto _header = reinterpret_cast<ipv6_header *>(buf);

        buf += sizeof(ipv6_header);
        len -= sizeof(ipv6_header);

    } break;
    default:
        break;
    }
    return nullptr;
} // namespace details
} // namespace ip_packet