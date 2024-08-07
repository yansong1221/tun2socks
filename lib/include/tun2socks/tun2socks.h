#pragma once
#include <optional>
#include <string>
#include <tun2socks/platform.h>

class tun2socks_impl;
class tun2socks {
public:
    struct tun_parameter
    {
        struct address
        {
            std::string addr;
            std::string dns;
            uint8_t     prefix_length = 0;
        };
        std::string            tun_name;
        std::optional<address> ipv4;
        std::optional<address> ipv6;
    };

public:
    tun2socks();
    ~tun2socks();

public:
    void add_proxy_execute(const std::string exe_name);

    void start(const tun_parameter& tun_param,
               const std::string&   socks5_url);

private:
    tun2socks_impl* impl_;
};