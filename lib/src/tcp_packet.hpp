#pragma once
#include "ip_packet.hpp"

namespace transport_layer {

namespace details {
struct alignas(4) tcp_header
{
    uint16_t src_port;       // 源端口号
    uint16_t dest_port;      // 目的端口号
    uint32_t seq_num;        // 序列号
    uint32_t ack_num;        // 确认号
    uint8_t data_offset : 4; // 数据偏移
    uint8_t reserved : 4;    // 保留字段
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

private:
    uint32_t seq_num_;
    uint32_t ack_num_;
    boost::asio::ip::tcp::endpoint src_endpoint_;
    boost::asio::ip::tcp::endpoint dest_endpoint_;
};
} // namespace transport_layer