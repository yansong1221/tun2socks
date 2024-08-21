#include <fcntl.h>

#include <locale>
#include <tun2socks/core.h>

#ifdef OS_WINDOWS
#    include <io.h>
#    include <windows.h>
#endif
int main(int argc, char** argv)
{
#ifdef OS_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
    std::locale::global(std::locale("en_US.UTF-8"));
#endif
    tun2socks::core tun2socks_;

    tun2socks::parameter::tun_device param;
    param.tun_name = "mate";

    tun2socks::parameter::tun_device::address tun_ipv4;
    tun_ipv4.addr          = "10.6.7.7";
    tun_ipv4.dns           = "114.114.114.114";
    tun_ipv4.prefix_length = 24;
    param.ipv4             = tun_ipv4;

    tun2socks::parameter::tun_device::address tun_ipv6;
    tun_ipv6.addr          = "fe80::613b:4e3f:81e9:7e01";
    tun_ipv6.dns           = "2606:4700:4700::1111";
    tun_ipv6.prefix_length = 64;
    param.ipv6             = tun_ipv6;

    tun2socks::parameter::socks5_server socks5_param;
    socks5_param.host     = "127.0.0.1";
    socks5_param.port     = 7897;
    socks5_param.username = "jack";
    socks5_param.password = "1111";
    // tun2socks_.start(param, "socks5://192.168.101.8:7897");

   /* tun2socks_.proxy_policy()
        .set_process(R"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe)", false);*/
    // tun2socks_.proxy_policy().set_process(R"(C:\Program Files\Clash Verge\verge-mihomo.exe)", true);
    tun2socks_.proxy_policy().set_process(10108, true);
    tun2socks_.proxy_policy().set_default_direct(true);
    tun2socks_.tcp_connections();

    try {
        tun2socks_.start(param, socks5_param);
    }
    catch (const std::exception& e) {
        printf("%s\n", e.what());
    }

    tun2socks_.wait();
    return 0;
}