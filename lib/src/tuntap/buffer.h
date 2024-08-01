#pragma once
#include <boost/asio.hpp>

namespace tuntap {

class recv_buffer
{
public:
    virtual ~recv_buffer() = default;
    virtual boost::asio::const_buffer data() const = 0;
};

using recv_buffer_ptr = std::shared_ptr<recv_buffer>;

} // namespace tuntap