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

    struct proc_info
    {
        uint32_t    pid = 0;
        std::string execute_path;
    };

    struct net_info
    {
        uint32_t speed_download_1s    = 0;
        uint32_t speed_upload_1s      = 0;
        uint64_t total_download_bytes = 0;
        uint64_t total_upload_bytes   = 0;
    };

public:
    virtual ~connection()                                     = default;
    virtual conn_type                type() const             = 0;
    virtual endpoint                 local_endpoint() const   = 0;
    virtual endpoint                 remote_endpoint() const  = 0;
    virtual const net_info&          get_net_info() const     = 0;
    virtual std::optional<proc_info> get_process_info() const = 0;
    virtual void                     stop()                   = 0;
};

}  // namespace tun2socks