#pragma once
#include <optional>
#include <string>
namespace tun2socks {
namespace parameter {

    struct tun_device
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

    struct socks5_server
    {
        std::string username;
        std::string password;
        std::string host;
        uint16_t    port = 1080;
    };

}  // namespace parameter
}  // namespace tun2socks