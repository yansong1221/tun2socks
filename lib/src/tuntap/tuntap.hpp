#pragma once

#include "platform.hpp"

#include "basic_tuntap.hpp"
#ifdef OS_WINDOWS
#    include "wintun_service.hpp"
#elif defined(OS_MACOS)
#    include "tun_service_mac.hpp"
#endif

namespace tuntap {

#ifdef OS_WINDOWS
using tuntap = basic_tuntap<wintun_service>;
#elif defined(OS_MACOS)
using tuntap = basic_tuntap<tun_service_mac>;
#endif

}  // namespace tuntap