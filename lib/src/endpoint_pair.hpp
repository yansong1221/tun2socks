#pragma once
#include "address_pair.hpp"
#include <boost/asio.hpp>
#include <boost/container_hash/hash.hpp>

namespace transport_layer {
template<typename InternetProtocol>
struct basic_endpoint_pair
{
    using endpoint_type = typename boost::asio::ip::basic_endpoint<InternetProtocol>;

    endpoint_type src;
    endpoint_type dest;

    basic_endpoint_pair(const endpoint_type &src, const endpoint_type &dest)
    {
        this->src = src;
        this->dest = dest;
    }
    basic_endpoint_pair(const network_layer::address_pair_type &address_pair,
                        uint16_t src_port,
                        uint16_t dest_port)
    {
        this->src = endpoint_type(address_pair.src, src_port);
        this->dest = endpoint_type(address_pair.dest, dest_port);
    }

    inline network_layer::address_pair_type to_address_pair() const
    {
        return network_layer::address_pair_type(src.address(), dest.address());
    }

    inline bool operator==(const basic_endpoint_pair<InternetProtocol> &other) const
    {
        return src == other.src && dest == other.dest;
    }

    inline basic_endpoint_pair<InternetProtocol> swap() const
    {
        return basic_endpoint_pair(dest, src);
    }

    inline std::string to_string() const
    {
        return fmt::format("[{0}]:{1}->[{2}]:{3}",
                           src.address().to_string(),
                           src.port(),
                           dest.address().to_string(),
                           dest.port());
    }
};

using tcp_endpoint_pair = basic_endpoint_pair<boost::asio::ip::tcp>;
using udp_endpoint_pair = basic_endpoint_pair<boost::asio::ip::udp>;

} // namespace transport_layer

namespace std {
template<>
struct hash<transport_layer::tcp_endpoint_pair>
{
    typedef transport_layer::tcp_endpoint_pair argument_type;
    typedef std::size_t result_type;
    inline result_type operator()(argument_type const &s) const
    {
        return std::hash<std::string>{}(s.to_string());
    }
};
template<>
struct hash<transport_layer::udp_endpoint_pair>
{
    typedef transport_layer::udp_endpoint_pair argument_type;
    typedef std::size_t result_type;
    inline result_type operator()(argument_type const &s) const
    {
        return std::hash<std::string>{}(s.to_string());
    }
};

} // namespace std