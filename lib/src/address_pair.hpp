#pragma once
#include <boost/asio.hpp>
#include <fmt/format.h>
namespace tun2socks {

class address_pair_type {
public:
    boost::asio::ip::address src;
    boost::asio::ip::address dest;

    address_pair_type() = default;
    address_pair_type(const boost::asio::ip::address& src_addr,
                      const boost::asio::ip::address& dest_addr)
    {
        this->src  = src_addr;
        this->dest = dest_addr;
    }
    address_pair_type(const boost::asio::ip::address_v6::bytes_type& src_addr,
                      const boost::asio::ip::address_v6::bytes_type& dest_addr)
    {
        this->src  = boost::asio::ip::address_v6(src_addr);
        this->dest = boost::asio::ip::address_v6(dest_addr);
    }
    address_pair_type(uint32_t src_addr, uint32_t dest_addr)
    {
        this->src  = boost::asio::ip::address_v4(src_addr);
        this->dest = boost::asio::ip::address_v4(dest_addr);
    }
    inline bool operator==(const address_pair_type& other) const
    {
        return src == other.src && dest == other.dest;
    }
    inline uint8_t ip_version() const
    {
        return src.is_v6() ? 6 : 4;
    }

    inline std::string to_string() const
    {
        return fmt::format("[{0}]->[{1}]", src.to_string(), dest.to_string());
    }
};

}  // namespace tun2socks

namespace std {
template <>
struct hash<tun2socks::address_pair_type>
{
    typedef tun2socks::address_pair_type argument_type;
    typedef std::size_t                  result_type;
    inline result_type                   operator()(argument_type const& s) const
    {
        return std::hash<std::string>{}(s.to_string());
    }
};
}  // namespace std