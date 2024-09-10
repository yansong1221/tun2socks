#include <fcntl.h>

#include <locale>
#include <tun2socks/core.h>

#ifdef OS_WINDOWS
#    include <io.h>
#    include <windows.h>
#endif

#include "argparse.hpp"

int main(int argc, char** argv)
{
#ifdef OS_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
    std::locale::global(std::locale("en_US.UTF-8"));
#endif
    argparse::ArgumentParser program("tun2socks");

    program.add_argument("-tname", "--tunName")
        .help("The Name of the TUN interface.")
        .default_value(std::string("tun2socks"));

    program.add_argument("-tip4", "--tunIP4")
        .help("The IPV4 address of the TUN interface. Default( 10.1.2.1/24 )")
        .default_value(std::string("10.1.2.1/24"));

    program.add_argument("-tip4dns", "--tunIP4DNS")
        .help("The IPV4 DNS address of the TUN interface. Example( 8.8.8.8 )");

    program.add_argument("-tip6", "--tunIP6")
        .help("The IPV6 address of the TUN interface. Example( 2001:db8:85a3::8a2e:370:7334/64 )");

    program.add_argument("-tip6dns", "--tunIP6DNS")
        .help("The IPV6 DNS address of the TUN interface. Example( 2606:4700:4700::1111 )");

    program.add_argument("-s5proxy", "--socks5Proxy")
        .help("The URL of your socks5 server. Default( socks5://127.0.0.1:1080 )")
        .default_value(std::string("socks5://127.0.0.1:1080"));

    program.add_argument("-l", "--level")
        .help(
            "Set logging level. 0(Off), 1(Error), 2(Critical), 3(Warning), "
            "4(Info), 5(Debug), 6(Trace).")
        .default_value(4)
        .action([](const std::string& port) { return std::stoi(port); });
    program.add_argument("-f", "--log-file")
        .help("The path to log file. Logs are printed by default.");

    tun2socks::parameter::tun_device    tun_param;
    tun2socks::parameter::socks5_server socks5_param;

    tun2socks::core core;
    try {
        program.parse_args(argc, argv);

        tun_param.tun_name = program.get<std::string>("-tname");

        auto tip4 = program.get<std::string>("-tip4");

        tun2socks::parameter::tun_device::address tun_ipv4;
        tun2socks::core::parse_cidr_addr(tip4, tun_ipv4.addr, tun_ipv4.prefix_length);
        if (auto tip4dns = program.present<std::string>("-tip4dns"); tip4dns)
            tun_ipv4.dns = *tip4dns;

        tun_param.ipv4 = tun_ipv4;

        if (auto tip6 = program.present<std::string>("-tip6"); tip6) {
            tun2socks::parameter::tun_device::address tun_ipv6;
            tun2socks::core::parse_cidr_addr(*tip6, tun_ipv6.addr, tun_ipv6.prefix_length);
            if (auto tip6dns = program.present<std::string>("-tip6dns"); tip6dns)
                tun_ipv6.dns = *tip6dns;

            tun_param.ipv6 = tun_ipv6;
        }
        tun2socks::core::parse_socks5_url(program.get<std::string>("-s5proxy"), socks5_param);
    }
    catch (const std::exception& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return -1;
    }
    core.proxy_policy().set_process(10108, true);
    core.proxy_policy().set_default_direct(true);
    core.connections();

    core.start(tun_param, socks5_param);
    core.wait();
    return 0;
}