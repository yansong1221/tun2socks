#pragma once
#include "basic_connection.hpp"
#include <atomic>
#include <boost/asio.hpp>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <string>
#include <tun2socks/proxy_policy.h>
#include <unordered_set>

namespace tun2socks {

class proxy_policy_impl : public proxy_policy {
public:
    proxy_policy_impl(boost::asio::io_context& ioc)
        : ioc_(ioc)
    {
    }
    template <typename InternetProtocol>
    inline bool is_direct(const basic_connection<InternetProtocol>& conn)
    {
        const auto& endpoint_pair = conn.endpoint_pair();
        auto        dest_addr     = endpoint_pair.dest.address();

        if (auto iter = addresses_.find(dest_addr);
            iter != addresses_.end()) {
            spdlog::info("Match to Dest IP address: {} direct: {}",
                         dest_addr.to_string(),
                         iter->second);
            return iter->second;
        }

        auto pid = conn.get_pid();
        if (!pid) {
            spdlog::warn("Process information for port not found: {}", endpoint_pair.to_string());
            return default_direct_;
        }
        if (auto iter = process_pid_.find(*pid);
            iter != process_pid_.end()) {
            spdlog::info("Match to pid: {} direct: {}",
                         *pid,
                         iter->second);
            return iter->second;
        }

        auto exe_path = conn.get_execute_path();
        if (!exe_path) {
            spdlog::warn("Process process path for pid not found: {}, {}", *pid, endpoint_pair.to_string());
            return default_direct_;
        }

        auto p = std::filesystem::path(*exe_path).lexically_normal().string();
        if (auto iter = process_path_.find(p);
            iter != process_path_.end()) {
            spdlog::info("Match to process path: {} direct: {}",
                         p,
                         iter->second);
            return iter->second;
        }
        return default_direct_;
    }

public:
    void set_process(const std::string& path, bool direct) override
    {
        auto p = std::filesystem::path(path).lexically_normal().string();
        ioc_.dispatch([this, p, direct]() {
            process_path_[p] = direct;
        });
    }
    void set_process(uint32_t pid, bool direct) override
    {
        ioc_.dispatch([this, pid, direct]() {
            process_pid_[pid] = direct;
        });
    }
    void set_address(const std::string& addr, bool direct) override
    {
        auto _addr = boost::asio::ip::make_address(addr);
        ioc_.dispatch([this, _addr, direct]() {
            addresses_[_addr] = direct;
        });
    }
    void remove_process(const std::string& path) override
    {
        auto p = std::filesystem::path(path).lexically_normal().string();
        ioc_.dispatch([this, p]() {
            process_path_.erase(p);
        });
    }
    void remove_process(uint32_t pid) override
    {
        ioc_.dispatch([this, pid]() {
            process_pid_.erase(pid);
        });
    }

    void remove_address(const std::string& addr) override
    {
        auto _addr = boost::asio::ip::make_address(addr);
        ioc_.dispatch([this, _addr]() {
            addresses_.erase(_addr);
        });
    }

    void set_default_direct(bool flag) override
    {
        default_direct_ = flag;
    }

    void clear() override
    {
        ioc_.dispatch([this]() {
            process_path_.clear();
            addresses_.clear();
            process_pid_.clear();
        });
    }

private:
    boost::asio::io_context&                           ioc_;
    std::atomic_bool                                   default_direct_ = false;
    std::unordered_map<uint32_t, bool>                 process_pid_;
    std::unordered_map<std::string, bool>              process_path_;
    std::unordered_map<boost::asio::ip::address, bool> addresses_;
};
}  // namespace tun2socks