#ifndef TUN2SOCKS_PBUF_HPP
#define TUN2SOCKS_PBUF_HPP

#include "lwip/pbuf.h"
#include <boost/asio/buffer.hpp>
#include <cstdint>

namespace toys {
namespace wrapper {

class pbuf_buffer
{
public:
    pbuf_buffer() = default;
    pbuf_buffer(pbuf *p, bool add_ref = true)
    {
        data_ = p;
        if (add_ref)
            pbuf_ref(data_);
    }
    pbuf_buffer(uint16_t length, pbuf_type ty = pbuf_type::PBUF_POOL)
    {
        data_ = pbuf_alloc(pbuf_layer::PBUF_RAW, length, ty);
    }
    ~pbuf_buffer()
    {
        if (data_) {
            BOOST_ASSERT(data_->ref != 0);
            pbuf_free(data_);
        }
    }

    pbuf_buffer &operator=(const pbuf_buffer &other)
    {
        if (std::addressof(other) == this)
            return *this;

        data_ = other.data_;
        pbuf_ref(data_);
        return *this;
    }
    pbuf_buffer(const pbuf_buffer &other) { *this = other; }

public:
    pbuf *operator&() { return data_; }
    operator bool() { return data_ != nullptr; }

    static pbuf_buffer copy(pbuf *p)
    {
        pbuf_buffer buffer(p->tot_len);
        pbuf_copy(&buffer, p);
        return buffer;
    }

    void realloc(std::size_t n) { pbuf_realloc(data_, n); }

    boost::asio::mutable_buffer data()
    {
        return boost::asio::mutable_buffer(data_->payload, data_->tot_len);
    }
    boost::asio::const_buffer data() const
    {
        return boost::asio::const_buffer(data_->payload, data_->tot_len);
    }

private:
    pbuf *data_ = nullptr;
};

} // namespace wrapper
} // namespace toys

#endif // TUN2SOCKS_PBUF_HPP
