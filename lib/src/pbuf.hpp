#ifndef TUN2SOCKS_PBUF_HPP
#define TUN2SOCKS_PBUF_HPP

#include "lwip/pbuf.h"
#include <boost/asio/buffer.hpp>
#include <cstdint>
namespace tun2socks {
namespace wrapper {

    class pbuf_buffer {
    public:
        pbuf_buffer() = default;
        explicit pbuf_buffer(pbuf* p)
        {
            data_ = p;
            pbuf_ref(data_);
        }
        pbuf_buffer(uint16_t   length,
                    pbuf_layer layer = pbuf_layer::PBUF_RAW,
                    pbuf_type  ty    = pbuf_type::PBUF_RAM)
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

        pbuf_buffer& operator=(const pbuf_buffer& other)
        {
            if (std::addressof(other) == this)
                return *this;

            data_ = other.data_;
            pbuf_ref(data_);
            return *this;
        }
        pbuf_buffer(const pbuf_buffer& other)
        {
            *this = other;
        }

    public:
        pbuf* operator&() const
        {
            return data_;
        }
        operator bool() const
        {
            return data_ != nullptr;
        }
        std::size_t len() const
        {
            return data_->tot_len;
        }
        static pbuf_buffer smart_copy(pbuf* p)
        {
            if (!p)
                return pbuf_buffer();

            if (p->next) {
                pbuf_buffer buffer(p->tot_len);
                pbuf_copy(&buffer, p);
                return buffer;
            }
            return pbuf_buffer(p);
        }

        void realloc(std::size_t n)
        {
            pbuf_realloc(data_, n);
        }
        pbuf* release()
        {
            if (!data_)
                return nullptr;

            auto p = data_;
            data_  = nullptr;
            return p;
        }

        boost::asio::mutable_buffer mutable_data()
        {
            return boost::asio::mutable_buffer(data_->payload, data_->tot_len);
        }
        boost::asio::const_buffer const_data() const
        {
            return boost::asio::const_buffer(data_->payload, data_->tot_len);
        }

    private:
        pbuf* data_ = nullptr;
    };

}  // namespace wrapper
}  // namespace tun2socks

#endif  // TUN2SOCKS_PBUF_HPP
