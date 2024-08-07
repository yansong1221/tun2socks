#include <fcntl.h>
#include <io.h>
#include <locale>
#include <tun2socks/tun2socks.h>
#include <windows.h>
int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);

    std::locale::global(std::locale("en_US.UTF-8"));
    tun2socks tun2socks_;
    tun2socks_.start();
    return 0;
}