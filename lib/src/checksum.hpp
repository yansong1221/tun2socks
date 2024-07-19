#pragma once
#include <vector>

namespace checksum {
inline static uint16_t checksum(const uint8_t *buffer, std::size_t len)
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
template<typename Class>
typename std::enable_if_t<std::is_class_v<Class>, uint16_t> checksum(const Class *data)
{
    return checksum((const uint8_t *) data, sizeof(Class));
}

template<typename Header, typename PseudHeader>
inline static uint16_t checksum(const Header *header,
                                const PseudHeader *pseud_header,
                                const uint8_t *data,
                                std::size_t data_len)
{
    std::size_t psize = sizeof(PseudHeader) + sizeof(Header) + data_len;
    std::vector<uint8_t> buffer(psize, 0);
    uint8_t *buf = buffer.data();

    // 构建校验和数据
    memcpy(buf, pseud_header, sizeof(PseudHeader));
    memcpy(buf + sizeof(PseudHeader), header, sizeof(Header));
    memcpy(buf + sizeof(PseudHeader) + sizeof(Header), data, data_len);

    memcpy(buf + sizeof(PseudHeader), header, sizeof(Header));

    // 计算校验和
    return checksum(buf, psize);
}

} // namespace checksum