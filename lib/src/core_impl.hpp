#pragma once
#include "core_impl_api.h"
#include "lwip.hpp"
#include "process_info/process_info.hpp"
#include "proxy_policy_impl.hpp"
#include "route/route.hpp"
#include "tcp_proxy.hpp"
#include "thread.hpp"
#include "tuntap/tuntap.hpp"
#include "udp_proxy.hpp"
#include <future>
#include <queue>

namespace tun2socks {

class core_impl : public thread, public core_impl_api {
public:
    explicit core_impl()
        : tuntap_(ioc_),
          proxy_policy_(ioc_)
    {
    }
    bool start(const parameter::tun_device&    tun_param,
               const parameter::socks5_server& socks5_param)
    {
        tun_param_    = tun_param;
        socks5_proxy_ = socks5_param;

        return start_thread();
    }

    tun2socks::proxy_policy_impl& proxy_policy()
    {
        return proxy_policy_;
    }
    void set_connection_open_function(connection::open_function handle)
    {
        ioc_.dispatch([this, handle]() {
            conn_open_func_ = handle;
        });
    }
    void set_connection_close_function(connection::open_function handle)
    {
        ioc_.dispatch([this, handle]() {
            conn_close_func_ = handle;
        });
    }
    std::vector<connection::weak_ptr> connections()
    {
        if (!is_runing())
            return {};

        auto result = std::make_shared<std::promise<std::vector<connection::weak_ptr>>>();
        ioc_.dispatch([this, result]() mutable -> void {
            std::vector<connection::weak_ptr> items;
            for (const auto& v : conns_)
                items.push_back(v);

            result->set_value(items);
        });
        return result->get_future().get();
    }

private:
    virtual bool on_thread_start() override
    {
        ioc_.poll();

        default_adapter_ = route::get_default_adapter();
        if (default_adapter_) {
            spdlog::info("Default network interface name: {} v4: {} v6: {}",
                         default_adapter_->if_name,
                         default_adapter_->v4_address().to_string(),
                         default_adapter_->v6_address().to_string());
        }
        else {
            spdlog::warn("Failed to obtain default network adapter");
        }

        boost::system::error_code ec;
        tuntap_.open(tun_param_, ec);
        boost::asio::detail::throw_error(ec);

        route::init_route(tun_param_);

        lwip::instance().init(ioc_);

        auto tcp_accepter = lwip::tcp_accepter::instance();
        tcp_accepter->set_accept_function([this, tcp_accepter](lwip::tcp_conn::ptr newpcb) {
            auto proxy = std::make_shared<tcp_proxy>(ioc_,
                                                     newpcb,
                                                     *this);

            proxy->start();
            conns_.insert(proxy);
            if (conn_open_func_)
                conn_open_func_(proxy);
        });

        auto udp_creator = lwip::udp_creator::instance();
        udp_creator->set_udp_create_function([this, udp_creator](lwip::udp_conn::ptr newpcb) {
            auto proxy = std::make_shared<udp_proxy>(ioc_,
                                                     newpcb,
                                                     *this);
            proxy->start();
            conns_.insert(proxy);

            if (conn_open_func_)
                conn_open_func_(proxy);
        });

        lwip::instance().set_ip_output([this](const wrapper::pbuf_buffer& buffer) {
            bool write_in_process = !send_queue_.empty();
            send_queue_.push_back(buffer);
            if (write_in_process)
                return;

            boost::asio::co_spawn(
                ioc_,
                [this]() -> boost::asio::awaitable<void> {
                    boost::system::error_code ec;
                    while (!send_queue_.empty()) {
                        const auto& buffer = send_queue_.front();
                        auto        bytes  = co_await tuntap_.async_write_some(buffer.const_data(), ec);
                        send_queue_.pop_front();

                        if (ec)
                            spdlog::warn("Write IP Packet to tuntap Device Failed: {0}", ec.message());
                    }
                },
                boost::asio::detached);
        });

        boost::asio::co_spawn(
            ioc_, [this]() -> boost::asio::awaitable<void> {
                boost::system::error_code ec;
                for (;;) {
                    wrapper::pbuf_buffer buffer(1500);

                    auto bytes = co_await tuntap_.async_read_some(buffer.mutable_data(), ec);
                    if (ec)
                        co_return;

                    buffer.realloc(bytes);
                    lwip::instance().ip_input(buffer);
                }
            },
            boost::asio::detached);
        return true;
    }
    virtual bool on_thread_run() override
    {
        boost::system::error_code ec;
        ioc_.restart();
        ioc_.run(ec);
        return false;
    }

    boost::asio::awaitable<tcp_socket_ptr> create_proxy_socket(
        connection::ptr conn) override
    {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
            co_await boost::asio::this_coro::executor);

        boost::asio::ip::tcp::endpoint dest(boost::asio::ip::address::from_string(conn->remote_endpoint().first),
                                            conn->remote_endpoint().second);

        if (proxy_policy_.is_direct(conn)) {
            boost::system::error_code ec;
            open_bind_socket(*socket, dest, ec);
            if (ec)
                co_return nullptr;

            co_await socket->async_connect(dest, net_awaitable[ec]);
            if (ec) {
                spdlog::warn("Failed to connect to remote TCP endpoint [{0}]:{1}",
                             dest.address().to_string(),
                             dest.port());
                co_return nullptr;
            }
        }
        else {
            boost::system::error_code ec;

            boost::asio::ip::tcp::endpoint remote_endp;
            co_await connect_socks5_server(*socket, dest, remote_endp, ec);
            if (ec)
                co_return nullptr;
        }
        co_return socket;
    }
    boost::asio::awaitable<udp_socket_ptr> create_proxy_socket(
        connection::ptr                 conn,
        boost::asio::ip::udp::endpoint& proxy_endpoint) override
    {
        auto socket = std::make_shared<boost::asio::ip::udp::socket>(
            co_await boost::asio::this_coro::executor);

        boost::asio::ip::udp::endpoint dest(boost::asio::ip::address::from_string(conn->remote_endpoint().first),
                                            conn->remote_endpoint().second);

        if (proxy_policy_.is_direct(conn)) {
            boost::system::error_code ec;
            open_bind_socket(*socket, dest, ec);
            if (ec)
                co_return nullptr;
            proxy_endpoint = dest;
        }
        else {
            boost::asio::ip::tcp::socket proxy_sock(co_await boost::asio::this_coro::executor);

            boost::system::error_code      ec;
            boost::asio::ip::udp::endpoint remote_endp;
            co_await connect_socks5_server(proxy_sock, dest, remote_endp, ec);
            if (ec)
                co_return nullptr;

            proxy_endpoint = remote_endp;
        }
        co_return socket;
    }
    void remove_conn(connection::ptr conn) override
    {
        auto iter = conns_.find(conn);
        if (iter == conns_.end())
            return;

        if (conn_close_func_)
            conn_close_func_(conn);

        conns_.erase(iter);
    }

private:
    template <typename Stream, typename InternetProtocol>
    inline void open_bind_socket(Stream&                                                  sock,
                                 const boost::asio::ip::basic_endpoint<InternetProtocol>& dest,
                                 boost::system::error_code&                               ec)
    {
        sock.open(dest.protocol(), ec);
        if (dest.address().is_loopback())
            return;

        if (!default_adapter_)
            return;

        if (dest.protocol() == InternetProtocol::v4())
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_adapter_->v4_address(), 0), ec);
        else
            sock.bind(boost::asio::ip::basic_endpoint<InternetProtocol>(default_adapter_->v6_address(), 0), ec);
        if (ec)
            spdlog::error("bind {0}", ec.message());
#ifdef OS_LINUX
        if (setsockopt(sock.native_handle(),
                       SOL_SOCKET,
                       SO_BINDTODEVICE,
                       default_adapter_->if_name.c_str(),
                       default_adapter_->if_name.length()) < 0) {
            perror("setsockopt failed");
            return;
        }
#endif
    }
    template <typename Stream, typename InternetProtocol>
    inline boost::asio::awaitable<void> connect_socks5_server(
        Stream&                                                  sock,
        const boost::asio::ip::basic_endpoint<InternetProtocol>& target_endp,
        boost::asio::ip::basic_endpoint<InternetProtocol>&       remote_endp,
        boost::system::error_code&                               ec)
    {
        auto endp = boost::asio::ip::tcp::endpoint(
            boost::asio::ip::make_address(socks5_proxy_.host, ec),
            socks5_proxy_.port);

        if (ec) {
            auto error = ec;
            ec.clear();

            boost::asio::ip::tcp::resolver resolver(co_await boost::asio::this_coro::executor);

            auto target_endpoints = co_await resolver.async_resolve(socks5_proxy_.host,
                                                                    std::to_string(
                                                                        socks5_proxy_.port),
                                                                    net_awaitable[ec]);
            if (ec)
                co_return;

            if (target_endpoints.empty()) {
                ec = error;
                co_return;
            }
            endp = *target_endpoints.begin();
        }

        open_bind_socket(sock, endp, ec);
        if (ec)
            co_return;

        co_await sock.async_connect(endp, net_awaitable[ec]);

        if (ec) {
            spdlog::warn("Failed to connect to socks5 server [{0}]:{1} message:{2}",
                         socks5_proxy_.host,
                         socks5_proxy_.port,
                         ec.message());
            co_return;
        }

        proxy::socks_client_option op;
        op.target_host    = target_endp.address().to_string();
        op.target_port    = target_endp.port();
        op.username       = socks5_proxy_.username;
        op.password       = socks5_proxy_.password;
        op.proxy_hostname = false;

        co_await proxy::async_socks_handshake(sock, op, remote_endp, ec);
        if (ec) {
            spdlog::warn("Handshake with remote server failed [{0}]:{1} message:{2}",
                         socks5_proxy_.host,
                         socks5_proxy_.port,
                         ec.message());
            co_return;
        }
        spdlog::info("Successfully connected to remote socks server [{0}]:{1}", socks5_proxy_.host, socks5_proxy_.port);
    }

private:
    boost::asio::io_context          ioc_;
    tuntap::tuntap                   tuntap_;
    parameter::socks5_server         socks5_proxy_;
    parameter::tun_device            tun_param_;
    std::deque<wrapper::pbuf_buffer> send_queue_;
    proxy_policy_impl                proxy_policy_;

    std::unordered_set<connection::ptr> conns_;

    connection::open_function  conn_open_func_;
    connection::close_function conn_close_func_;

    std::optional<route::adapter_info> default_adapter_;
};
}  // namespace tun2socks