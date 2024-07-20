#pragma once
#include "ip_packet.hpp"
#include <format>
#include <boost/container_hash/hash.hpp>

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
    constexpr static uint8_t protocol_type = 0x06;

    struct endpoint_pair_type
    {
        boost::asio::ip::tcp::endpoint src;
        boost::asio::ip::tcp::endpoint dest;

        bool operator==(const endpoint_pair_type &other) const
        {
            return src == other.src && dest == other.dest;
        }

        endpoint_pair_type swap() const
        {
            endpoint_pair_type other;
            other.src = dest;
            other.dest = src;
            return other;
        }

        std::string to_string() const
        {
            return std::format("[{0}]:{1} -> [{2}]:{3}",
                               src.address().to_string(),
                               src.port(),
                               dest.address().to_string(),
                               dest.port());
        }
    };

public:
    explicit tcp_packet(network_layer::ip_packet::version_type ip_version,
                        const endpoint_pair_type &_endpoint_pair,
                        uint32_t seq_num,
                        uint32_t ack_num,
                        uint8_t flags,
                        const boost::asio::const_buffer &payload = boost::asio::const_buffer())
        : ip_version_(ip_version)
        , endpoint_pair_(_endpoint_pair)
        , seq_num_(seq_num)
        , ack_num_(ack_num)
        , flags_(flags)
        , payload_(payload)

    {}

    const tcp_packet::endpoint_pair_type &endpoint_pair() const { return endpoint_pair_; }
    const boost::asio::const_buffer &payload() const { return payload_; }
    uint8_t flags() const { return flags_; }
    uint32_t seq_num() const { return seq_num_; }
    uint32_t ack_num() const { return ack_num_; }
    network_layer::ip_packet::version_type ip_version() const { return ip_version_; }

    template<typename Allocator>
    void make_packet(boost::asio::basic_streambuf<Allocator> &buffers) const
    {
        uint16_t length = sizeof(details::tcp_header) + payload_.size();

        auto buf = buffers.prepare(length);
        memset(buf.data(), 0, length);

        auto header = boost::asio::buffer_cast<details::tcp_header *>(buf);
        header->src_port = ::htons(endpoint_pair_.src.port());
        header->dest_port = ::htons(endpoint_pair_.dest.port());
        header->seq_num = ::htonl(seq_num_);
        header->ack_num = ::htonl(ack_num_);
        header->data_offset = sizeof(details::tcp_header) / 4;
        header->flags = flags_;
        header->window_size = 0xFFFF;
        header->checksum = checksum(header,
                                    ip_version_,
                                    endpoint_pair_.src.address(),
                                    endpoint_pair_.dest.address(),
                                    (const uint8_t *) payload_.data(),
                                    payload_.size());
        memcpy(header + 1, payload_.data(), payload_.size());
        buffers.commit(length);
    }
    template<typename Allocator>
    void make_ip_packet(boost::asio::basic_streambuf<Allocator> &buffers) const
    {
        boost::asio::streambuf payload;
        make_packet(payload);

        network_layer::ip_packet ip_pack(ip_version_,
                                         endpoint_pair_.src.address(),
                                         endpoint_pair_.dest.address(),
                                         tcp_packet::protocol_type,
                                         payload.data());
        ip_pack.make_packet(buffers);
    }

    inline static std::optional<tcp_packet> from_ip_packet(const network_layer::ip_packet &ip_pack)
    {
        auto buffer = ip_pack.payload_data();

        if (buffer.size() < sizeof(details::tcp_header)) {
            SPDLOG_INFO("Received packet without room for a tcp header");
            return std::nullopt;
        }

        auto header = boost::asio::buffer_cast<const details::tcp_header *>(buffer);
        auto header_len = header->data_offset * 4;

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
        endpoint_pair_type _endpoint_pair;
        _endpoint_pair.src = boost::asio::ip::tcp::endpoint(ip_pack.src_address(),
                                                            ::ntohs(header->src_port));
        _endpoint_pair.dest = boost::asio::ip::tcp::endpoint(ip_pack.dest_address(),
                                                             ::ntohs(header->dest_port));

        SPDLOG_INFO("Received IPv{0} tcp packet {1}",
                    (int) ip_pack.version(),
                    _endpoint_pair.to_string());

        buffer += header_len;

        return tcp_packet(ip_pack.version(),
                          _endpoint_pair,
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
    network_layer::ip_packet::version_type ip_version_;
    uint32_t seq_num_;
    uint32_t ack_num_;
    uint8_t flags_;
    endpoint_pair_type endpoint_pair_;

    boost::asio::const_buffer payload_;
};
} // namespace transport_layer

namespace std {
template<>
struct hash<boost::asio::ip::tcp::endpoint>
{
    typedef boost::asio::ip::tcp::endpoint argument_type;
    typedef std::size_t result_type;
    inline result_type operator()(argument_type const &s) const
    {
        std::string temp = s.address().to_string();
        std::size_t seed = 0;
        boost::hash_combine(seed, temp);
        boost::hash_combine(seed, s.port());
        return seed;
    }
};

template<>
struct hash<transport_layer::tcp_packet::endpoint_pair_type>
{
    typedef transport_layer::tcp_packet::endpoint_pair_type argument_type;
    typedef std::size_t result_type;
    inline result_type operator()(argument_type const &s) const
    {
        result_type const h1(std::hash<boost::asio::ip::tcp::endpoint>{}(s.src));
        result_type const h2(std::hash<boost::asio::ip::tcp::endpoint>{}(s.dest));
        std::size_t seed = 0;
        boost::hash_combine(seed, h1);
        boost::hash_combine(seed, h2);
        return seed;
    }
};
} // namespace std