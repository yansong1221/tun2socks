#pragma once
#include "endpoint_pair.hpp"
#include "process_info/process_info.hpp"
#include <boost/asio.hpp>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <string>
#include <unordered_set>

class proxy_policy {
public:
    template <typename InternetProtocol>
    inline bool is_direct(const transport_layer::basic_endpoint_pair<InternetProtocol>& endpoint_pair)
    {
        if (direct_address_.contains(endpoint_pair.dest.address()))
            return true;
        if (proxy_address_.contains(endpoint_pair.dest.address()))
            return false;

        auto info = process_info::get_process_info(endpoint_pair.src.port());
        if (!info) {
            spdlog::warn("没有找到端口的进程信息直接走代理: {}", endpoint_pair.to_string());
            return default_direct_;
        }
        if (info->pid == process_info::get_current_pid())
            return true;

        auto p = std::filesystem::path(info->execute_path).lexically_normal();
        if (direct_process_.contains(p))
            return true;

        if (proxy_process_.contains(p)) {
            spdlog::info("pid: {} name: {} execute_path: {}", info->pid, info->name, info->execute_path);
            return false;
        }
        return default_direct_;
    }

public:
    void add_proxy_process(const std::string& path)
    {
        proxy_process_.insert(std::filesystem::path(path).lexically_normal());
    }
    void add_direct_process(const std::string& path)
    {
        direct_process_.insert(std::filesystem::path(path).lexically_normal());
    }

private:
    bool default_direct_ = false;

    std::unordered_set<std::filesystem::path> direct_process_;
    std::unordered_set<std::filesystem::path> proxy_process_;

    std::unordered_set<boost::asio::ip::address> direct_address_;
    std::unordered_set<boost::asio::ip::address> proxy_address_;
};