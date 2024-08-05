#pragma once

#include <boost/asio.hpp>
#include <deque>
#include <mutex>

namespace buffer {

class streambuf_pool
{
public:
    static streambuf_pool &instance()
    {
        static streambuf_pool s_instance;
        return s_instance;
    }

    std::shared_ptr<boost::asio::streambuf> create()
    {
        std::unique_lock<std::mutex> lck(mutx_);
        if (!ptrs_.empty()) {
            auto p = ptrs_.front();
            ptrs_.pop_front();
            return p;
        }
        return std::make_shared<boost::asio::streambuf>();
    }

    void put(std::shared_ptr<boost::asio::streambuf> p)
    {
        std::unique_lock<std::mutex> lck(mutx_);
        p->consume(p->size());
        ptrs_.push_back(p);
    }

public:
    std::mutex mutx_;
    std::deque<std::shared_ptr<boost::asio::streambuf>> ptrs_;
};

class ref_buffer
{
public:
    ref_buffer()
        : streambuf_(std::make_shared<boost::asio::streambuf>())
    {}
    ~ref_buffer()
    {
        // if (streambuf_.use_count() == 1)
        //     streambuf_pool::instance().put(streambuf_);
    }
    boost::asio::streambuf::mutable_buffers_type prepare(std::size_t n)
    {
        return streambuf_->prepare(n);
    }
    boost::asio::streambuf::const_buffers_type data() const noexcept { return streambuf_->data(); }
    void commit(std::size_t n) { streambuf_->commit(n); }
    void consume(std::size_t n) { streambuf_->consume(n); }
    std::size_t size() const { return streambuf_->size(); }
    bool empty() const { return streambuf_->size() == 0; }

private:
    std::shared_ptr<boost::asio::streambuf> streambuf_;
};

class ref_const_buffer : public boost::asio::const_buffer
{
public:
    ref_const_buffer() = default;
    ref_const_buffer(ref_buffer buf)
        : boost::asio::const_buffer(buf.data())
        , buffer_(buf)
    {}

private:
    const ref_buffer buffer_;
};

} // namespace buffer