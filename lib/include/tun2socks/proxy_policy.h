#pragma once
#include <string>

namespace tun2socks {
class proxy_policy {
public:
    virtual ~proxy_policy()                                        = default;
    virtual void set_process(const std::string& path, bool direct) = 0;
    virtual void set_process(uint32_t pid, bool direct)            = 0;
    virtual void set_address(const std::string& addr, bool direct) = 0;
    virtual void remove_process(const std::string& path)           = 0;
    virtual void remove_process(uint32_t pid)                      = 0;
    virtual void remove_address(const std::string& addr)           = 0;
    virtual void set_default_direct(bool flag)                     = 0;
    virtual void clear()                                           = 0;
};
}  // namespace tun2socks