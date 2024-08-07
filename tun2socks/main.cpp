#include <fcntl.h>
#include <io.h>
#include <locale>
#include <tun2socks/tun2socks.h>
#include <windows.h>
int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    std::locale::global(std::locale("en_US.UTF-8"));
    tun2socks tun2socks_;

    tun2socks::tun_parameter param;
    param.tun_name = "mate";

    tun2socks::tun_parameter::address tun_ipv4;
    tun_ipv4.addr          = "10.6.7.7";
    tun_ipv4.dns           = "114.114.114.114";
    tun_ipv4.prefix_length = 24;
    param.ipv4             = tun_ipv4;

    tun2socks::tun_parameter::address tun_ipv6;
    tun_ipv6.addr          = "fe80::613b:4e3f:81e9:7e01";
    tun_ipv6.dns           = "2606:4700:4700::1111";
    tun_ipv6.prefix_length = 64;
    param.ipv6             = tun_ipv6;

    tun2socks_.start(param, "socks5://user:password@192.168.101.8:7897");
    return 0;
}