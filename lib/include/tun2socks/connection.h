#pragma once
#include <functional>
#include <memory>
#include <string>

namespace tun2socks {
class connection {
public:
    using weak_ptr = std::weak_ptr<connection>;

    using open_function  = std::function<void(connection::weak_ptr)>;
    using close_function = std::function<void(connection::weak_ptr)>;

    enum class conn_type {
        tcp,
        udp
    };

public:
    virtual ~connection()                                = default;
    virtual conn_type   type() const                     = 0;
    virtual std::string local_endpoint() const           = 0;
    virtual std::string remote_endpoint() const          = 0;
    virtual uint32_t    get_speed_download_1s() const    = 0;
    virtual uint32_t    get_speed_upload_1s() const      = 0;
    virtual uint64_t    get_total_download_bytes() const = 0;
    virtual uint64_t    get_total_upload_bytes() const   = 0;
};

}  // namespace tun2socks