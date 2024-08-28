#pragma once
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace tun2socks {
class connection {
public:
    using ptr      = std::shared_ptr<connection>;
    using weak_ptr = std::weak_ptr<connection>;

    using open_function  = std::function<void(connection::weak_ptr)>;
    using close_function = std::function<void(connection::weak_ptr)>;

    enum class conn_type {
        tcp,
        udp
    };

    using endpoint = std::pair<std::string, uint16_t>;

public:
    virtual ~connection()                                               = default;
    virtual conn_type                  type() const                     = 0;
    virtual endpoint                   local_endpoint() const           = 0;
    virtual endpoint                   remote_endpoint() const          = 0;
    virtual uint32_t                   get_speed_download_1s() const    = 0;
    virtual uint32_t                   get_speed_upload_1s() const      = 0;
    virtual uint64_t                   get_total_download_bytes() const = 0;
    virtual uint64_t                   get_total_upload_bytes() const   = 0;
    virtual std::optional<uint32_t>    get_pid() const                  = 0;
    virtual std::optional<std::string> get_execute_path() const         = 0;
    virtual void                       stop()                           = 0;
};

}  // namespace tun2socks