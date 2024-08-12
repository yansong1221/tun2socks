#pragma once

#include <tun2socks/platform.h>

#include "basic_tuntap.hpp"
#ifdef OS_WINDOWS
#    include "wintun_service.hpp"
#elif defined(OS_MACOS)
#    include "tun_service_mac.hpp"
#elif defined(OS_LINUX)
#    include "tun_service_linux.hpp"
#endif
namespace tun2socks {

namespace tuntap {

#ifdef OS_WINDOWS
    using tuntap = basic_tuntap<wintun_service>;
#elif defined(OS_MACOS)
    using tuntap = basic_tuntap<tun_service_mac>;
#elif defined(OS_LINUX)
    using tuntap = basic_tuntap<tun_service_linux>;
#endif

}  // namespace tuntap
}  // namespace tun2socks