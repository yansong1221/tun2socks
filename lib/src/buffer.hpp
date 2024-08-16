#pragma once
#include <boost/asio.hpp>
#include <boost/pool/pool_alloc.hpp>
#include <optional>

namespace tun2socks {

class shared_buffer {
private:
    class shared_buffer_data {
        using buffer_type = std::vector<uint8_t, boost::fast_pool_allocator<uint8_t>>;

    public:
        explicit shared_buffer_data(std::size_t len, std::size_t offset)
            : data_(len + offset, 0),
              offset_(offset)
        {
        }

        const uint8_t* data() const
        {
            return &data_[offset_];
        }
        uint8_t* data()
        {
            return &data_[offset_];
        }
        std::size_t size() const
        {
            return data_.size() - offset_;
        }
        boost::asio::mutable_buffer mutable_data()
        {
            return boost::asio::mutable_buffer(data(), size());
        }
        boost::asio::const_buffer const_data() const
        {
            return boost::asio::const_buffer(data(), size());
        }

        void resize(std::size_t new_sz)
        {
            data_.resize(new_sz + offset_, 0);
        }

        boost::asio::mutable_buffer prepare_front(std::size_t sz)
        {
            if (sz > offset_) {
                data_.insert(data_.begin(), sz, 0);
                offset_ += sz;
            }
            offset_ -= sz;
            return boost::asio::mutable_buffer(data(), sz);
        }
        void consume_front(std::size_t sz)
        {
            if (sz > size())
                return;
            offset_ += sz;
        }

    private:
        buffer_type data_;
        std::size_t offset_ = 0;
    };

public:
    shared_buffer()
        : inner_data_(std::make_shared<shared_buffer_data>(0, 0))
    {
    }
    shared_buffer(std::size_t len, std::size_t offset = 0)
        : inner_data_(std::make_shared<shared_buffer_data>(len, offset))
    {
    }
    ~shared_buffer()
    {
    }

public:
    boost::asio::mutable_buffer data()
    {
        return inner_data_->mutable_data();
    }
    boost::asio::const_buffer data() const
    {
        return inner_data_->const_data();
    }

    std::size_t size() const
    {
        return inner_data_->size();
    }

    void resize(std::size_t new_sz)
    {
        inner_data_->resize(new_sz);
    }

    boost::asio::mutable_buffer prepare_front(std::size_t sz)
    {
        return inner_data_->prepare_front(sz);
    }
    void consume_front(std::size_t sz)
    {
        inner_data_->consume_front(sz);
    }

private:
    std::shared_ptr<shared_buffer_data> inner_data_;
};
}  // namespace tun2socks