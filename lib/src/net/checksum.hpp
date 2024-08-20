#pragma once
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
namespace tun2socks {
namespace checksum {
    namespace details {
        uint64_t ntohll(uint64_t value)
        {
            auto p = (uint8_t*)&value;

            uint64_t result = 0;
            for (int i = 0; i < sizeof(uint64_t); ++i)
                result = (result << 8) | (*(p + i));
            return result;
        }
    }  // namespace details

    class checksumer {
    private:
        using _int128_t = boost::multiprecision::int128_t;

    public:
        void update(const boost::asio::const_buffer& buffer)
        {
            update(buffer.data(), buffer.size());
        }
        void update(const void* buffer, std::size_t len)
        {
            auto orig_len = len;
            auto data     = reinterpret_cast<const uint8_t*>(buffer);
            if (odd_) {
                sum_ += *data++;
                len--;
            }
            auto p64 = reinterpret_cast<const uint64_t*>(data);
            /*while (len >= 8) {
                sum_ += details::ntohll(*p64++);
                len -= 8;
            }*/
            auto p16 = reinterpret_cast<const uint16_t*>(p64);
            while (len >= 2) {
                sum_ += boost::asio::detail::socket_ops::network_to_host_short(*p16++);
                len -= 2;
            }
            auto p8 = reinterpret_cast<const uint8_t*>(p16);
            if (len) {
                sum_ += ((uint16_t)*p8++ << 8);
                len--;
            }
            odd_ ^= orig_len & 1;
        }
        uint16_t get() const
        {
            _int128_t sum1 = (sum_ & _int128_t(-1)) + (sum_ >> 64);
            uint64_t  csum = static_cast<uint64_t>((sum1 & _int128_t(-1)) + (sum1 >> 64));
            csum           = (csum & 0xffff) + ((csum >> 16) & 0xffff) + ((csum >> 32) & 0xffff) + (csum >> 48);
            csum           = (csum & 0xffff) + (csum >> 16);
            csum           = (csum & 0xffff) + (csum >> 16);
            return boost::asio::detail::socket_ops::host_to_network_short(~csum);
        }
        void reset()
        {
            sum_ = 0;
            odd_ = false;
        }

    private:
        _int128_t sum_ = 0;
        bool      odd_ = false;
    };
    inline static uint16_t ip_checksum(const void* buffer, std::size_t len)
    {
        checksumer ch;
        ch.update(buffer, len);
        return ch.get();
    }

    template <typename Class>
    typename std::enable_if_t<std::is_class_v<Class>, uint16_t> checksum(const Class* data)
    {
        return checksum((const uint8_t*)data, sizeof(Class));
    }

    template <typename Header, typename PseudHeader>
    inline static uint16_t checksum(const Header*      header,
                                    const PseudHeader* pseud_header,
                                    const uint8_t*     data,
                                    std::size_t        data_len)
    {
        std::size_t          psize = sizeof(PseudHeader) + sizeof(Header) + data_len;
        std::vector<uint8_t> buffer(psize, 0);
        uint8_t*             buf = buffer.data();

        // 构建校验和数据
        memcpy(buf, pseud_header, sizeof(PseudHeader));
        memcpy(buf + sizeof(PseudHeader), header, sizeof(Header));
        memcpy(buf + sizeof(PseudHeader) + sizeof(Header), data, data_len);

        memcpy(buf + sizeof(PseudHeader), header, sizeof(Header));

        // 计算校验和
        return checksum(buf, psize);
    }
}  // namespace checksum
}  // namespace tun2socks
