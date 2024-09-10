#pragma once
#include "connection.h"
#include "parameter.h"
#include "platform.h"
#include "proxy_policy.h"

namespace tun2socks {

class core_impl;
class core {
public:
    core();
    virtual ~core();

public:
    void set_connection_open_function(connection::open_function handle);
    void set_connection_close_function(connection::open_function handle);

    std::vector<connection::weak_ptr> connections() const;

    tun2socks::proxy_policy& proxy_policy();

    bool start(const parameter::tun_device&    tun_param,
               const parameter::socks5_server& socks5_param);

    void wait();

    void stop();

    static void parse_cidr_addr(const std::string& cidr,
                                std::string&       ip,
                                uint8_t&           prefix_length);

    static void parse_socks5_url(const std::string&        url,
                                 parameter::socks5_server& socks5_param);

private:
    core_impl* impl_;
};

}  // namespace tun2socks