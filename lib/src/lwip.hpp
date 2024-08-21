#pragma once

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/sys.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/udp.h>

#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <time.h>

#include "address_pair.hpp"
#include "endpoint_pair.hpp"
#include "use_awaitable.hpp"
namespace tun2socks {

class lwip {
public:
    inline static lwip& instance()
    {
        static lwip _stack;
        return _stack;
    }
    inline static address_pair_type create_address_pair(const ip_addr_t& local_ip,
                                                        const ip_addr_t& remote_ip)
    {
        if (local_ip.type == IPADDR_TYPE_V4) {
            // IP addresses are always in network order.
            boost::asio::ip::address_v4 dest_ip(
                boost::asio::detail::socket_ops::network_to_host_long(local_ip.u_addr.ip4.addr));
            boost::asio::ip::address_v4 src_ip(
                boost::asio::detail::socket_ops::network_to_host_long(remote_ip.u_addr.ip4.addr));

            return address_pair_type(src_ip, dest_ip);
        }
        else {
            // IP addresses are always in network order.
            boost::asio::ip::address_v6::bytes_type dest_ip;
            boost::asio::ip::address_v6::bytes_type src_ip;

            memcpy(dest_ip.data(), local_ip.u_addr.ip6.addr, 16);
            memcpy(src_ip.data(), remote_ip.u_addr.ip6.addr, 16);

            return address_pair_type(src_ip, dest_ip);
        }
    }
    inline static udp_endpoint_pair create_endpoint(struct udp_pcb* newpcb)
    {  // Ports are always in host byte order.
        auto src_port  = newpcb->remote_port;
        auto dest_port = newpcb->local_port;
        auto addr_pair = create_address_pair(newpcb->local_ip,
                                             newpcb->remote_ip);

        return udp_endpoint_pair(addr_pair,
                                 src_port,
                                 dest_port);
    }
    inline static tcp_endpoint_pair create_endpoint(struct tcp_pcb* newpcb)
    {  // Ports are always in host byte order.
        auto src_port  = newpcb->remote_port;
        auto dest_port = newpcb->local_port;
        auto addr_pair = create_address_pair(newpcb->local_ip,
                                             newpcb->remote_ip);
        return tcp_endpoint_pair(addr_pair,
                                 src_port,
                                 dest_port);
    }

    inline static tcp_pcb* lwip_tcp_new()
    {
        return ::tcp_new();
    }

    inline static udp_pcb* lwip_udp_new()
    {
        return ::udp_new();
    }

    inline static err_t lwip_tcp_bind(
        struct tcp_pcb*  pcb,
        const ip_addr_t* ipaddr,
        u16_t            port)
    {
        return ::tcp_bind(pcb, ipaddr, port);
    }

    inline static err_t lwip_udp_bind(struct udp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port)
    {
        return ::udp_bind(pcb, ipaddr, port);
    }

    inline static tcp_pcb* lwip_tcp_listen(tcp_pcb* pcb)
    {
        return ::tcp_listen(pcb);
    }

    inline static err_t lwip_udp_connect(struct udp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port)
    {
        return udp_connect(pcb, ipaddr, port);
    }

    inline static void lwip_tcp_arg(tcp_pcb* pcb, void* arg)
    {
        return tcp_arg(pcb, arg);
    }

    inline static void lwip_tcp_receive(
        struct tcp_pcb*                                       pcb,
        std::function<std::remove_pointer<tcp_recv_fn>::type> receive)
    {
        if (receive == NULL) {
            tcp_err(pcb, NULL);
        }
        else {
            tcp_err(pcb, [pcb, receive](void* arg, err_t err) { receive(arg, pcb, NULL, err); });
        }
        return tcp_recv(pcb, receive);
    }

    inline static void lwip_tcp_accept(
        struct tcp_pcb*                                         pcb,
        std::function<std::remove_pointer<tcp_accept_fn>::type> accept)
    {
        return tcp_accept(pcb, accept);
    }

    inline static void lwip_tcp_recved(struct tcp_pcb* pcb, u16_t len)
    {
        return tcp_recved(pcb, len);
    }
    inline static void lwip_tcp_sent(struct tcp_pcb*                                       pcb,
                                     std::function<std::remove_pointer<tcp_sent_fn>::type> sent)
    {
        return ::tcp_sent(pcb, sent);
    }

    inline static void lwip_udp_create(std::function<std::remove_pointer_t<udp_crt_fn>> create_fn)
    {
        return udp_create(create_fn);
    }

    inline static void lwip_udp_recv(struct udp_pcb*                                       pcb,
                                     std::function<std::remove_pointer<udp_recv_fn>::type> recv)
    {
        return udp_recv(pcb, recv, NULL);
    }
    inline static void lwip_udp_disconnect(struct udp_pcb* pcb)
    {
        ::udp_disconnect(pcb);
    }

    inline static void lwip_udp_remove(struct udp_pcb* pcb)
    {
        return udp_remove(pcb);
    }

    inline static tcp_pcb* tcp_listen_any()
    {
        auto pcb = lwip_tcp_new();
        auto any = ip_addr_any;
        lwip_tcp_bind(pcb, &any, 0);
        return lwip_tcp_listen(pcb);
    }

    inline static err_t lwip_tcp_write(struct tcp_pcb* pcb,
                                       const void*     arg,
                                       u16_t           len,
                                       u8_t            apiflags)
    {
        return tcp_write(pcb, arg, len, apiflags);
    }

    inline static err_t lwip_udp_send(struct udp_pcb* pcb, struct pbuf* p)
    {
        return udp_send(pcb, p);
    }

    inline static u32_t lwip_tcp_sndbuf(tcp_pcb* pcb)
    {
        return tcp_sndbuf(pcb);
    }

    inline static err_t lwip_tcp_output(tcp_pcb* pcb)
    {
        return ::tcp_output(pcb);
    }

    inline static err_t lwip_tcp_close(tcp_pcb* pcb)
    {
        err_t err = tcp_shutdown(pcb, 1, 1) | tcp_close(pcb);
        return err;
    }

    inline void init(boost::asio::io_context& ctx)
    {
        lwip_init();
        netif_default = netif_list;
        loopback_     = netif_list;

        boost::asio::co_spawn(
            ctx,
            []() -> boost::asio::awaitable<void> {
                for (;;) {
                    boost::system::error_code ec;
                    boost::asio::steady_timer update_timer(
                        co_await boost::asio::this_coro::executor);
                    update_timer.expires_from_now(std::chrono::seconds(1));
                    co_await update_timer.async_wait(net_awaitable[ec]);
                    if (ec)
                        co_return;
                    ::sys_check_timeouts();
                }
            },
            boost::asio::detached);
    }

    inline void lwip_ip_output(std::function<err_t(struct netif* netif, struct pbuf* p)> f)
    {
        loopback_->output     = [f](struct netif*     netif,
                                struct pbuf*      p,
                                const ip4_addr_t* ipaddr) -> err_t { return f(netif, p); };
        loopback_->output_ip6 = [f](struct netif*     netif,
                                    struct pbuf*      p,
                                    const ip6_addr_t* ipaddr) -> err_t { return f(netif, p); };
    }
    inline err_t lwip_ip_input(pbuf* p)
    {
        return loopback_->input(p, loopback_);
    }

private:
    lwip()
        : loopback_(NULL)
    {
    }

private:
    netif* loopback_;
};
}  // namespace tun2socks