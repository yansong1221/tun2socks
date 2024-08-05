#pragma once

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/sys.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <time.h>
#include <timeapi.h>

#define CORE_LOCK std::lock_guard<std::recursive_mutex> gurad(this->core_mtx_)

class LWIPStack
{
public:
    inline static LWIPStack &getInstance()
    {
        static LWIPStack _stack;
        return _stack;
    }

    inline tcp_pcb *lwip_tcp_new()
    {
        CORE_LOCK;
        return ::tcp_new();
    }

    inline udp_pcb *lwip_udp_new()
    {
        CORE_LOCK;
        return ::udp_new();
    }

    inline err_t lwip_tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
    {
        CORE_LOCK;
        return ::tcp_bind(pcb, ipaddr, port);
    }

    inline err_t lwip_udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
    {
        CORE_LOCK;
        return ::udp_bind(pcb, ipaddr, port);
    }

    inline tcp_pcb *lwip_tcp_listen(tcp_pcb *pcb)
    {
        CORE_LOCK;
        return ::tcp_listen(pcb);
    }

    inline err_t lwip_udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
    {
        CORE_LOCK;
        return udp_connect(pcb, ipaddr, port);
    }

    inline void lwip_tcp_arg(tcp_pcb *pcb, void *arg)
    {
        CORE_LOCK;
        return tcp_arg(pcb, arg);
    }

    inline void lwip_tcp_receive(struct tcp_pcb *pcb,
                                 std::function<std::remove_pointer<tcp_recv_fn>::type> receive)
    {
        CORE_LOCK;
        if (receive == NULL) {
            tcp_err(pcb, NULL);
        } else {
            tcp_err(pcb, [pcb, receive](void *arg, err_t err) { receive(arg, pcb, NULL, err); });
        }
        return tcp_recv(pcb, receive);
    }

    inline void lwip_tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
    {
        CORE_LOCK;
        return tcp_accept(pcb, accept);
    }

    inline void lwip_tcp_recved(struct tcp_pcb *pcb, u16_t len)
    {
        CORE_LOCK;
        return tcp_recved(pcb, len);
    }
    inline void lwip_tcp_sent(struct tcp_pcb *pcb,
                              std::function<std::remove_pointer<tcp_sent_fn>::type> sent)
    {
        CORE_LOCK;
        return ::tcp_sent(pcb, sent);
    }

    inline void lwip_udp_timeout(struct udp_pcb *pcb,
                                 std::function<std::remove_pointer_t<udp_timeout_fn>> timeout_fn)
    {
        CORE_LOCK;
        return udp_timeout(pcb, timeout_fn);
    }

    inline void lwip_udp_create(std::function<std::remove_pointer_t<udp_crt_fn>> create_fn)
    {
        CORE_LOCK;
        return udp_create(create_fn);
    }

    inline void lwip_udp_set_timeout(udp_pcb *pcb, u32_t timeout)
    {
        CORE_LOCK;
        return udp_set_timeout(pcb, timeout);
    }

    inline void lwip_udp_recv(struct udp_pcb *pcb,
                              std::function<std::remove_pointer<udp_recv_fn>::type> recv)
    {
        CORE_LOCK;
        return udp_recv(pcb, recv, NULL);
    }

    inline void lwip_udp_remove(struct udp_pcb *pcb)
    {
        CORE_LOCK;
        return udp_remove(pcb);
    }

    inline tcp_pcb *tcp_listen_any()
    {
        auto pcb = lwip_tcp_new();
        auto any = ip_addr_any;
        lwip_tcp_bind(pcb, &any, 0);
        return lwip_tcp_listen(pcb);
    }

    inline udp_pcb *udp_listen_any()
    {
        auto pcb = lwip_udp_new();
        auto any = ip_addr_any;
        lwip_udp_bind(pcb, &any, 0);
        return pcb;
    }

    inline err_t lwip_tcp_write(struct tcp_pcb *pcb, const void *arg, u16_t len, u8_t apiflags)
    {
        CORE_LOCK;
        return tcp_write(pcb, arg, len, apiflags);
    }

    inline err_t lwip_udp_send(struct udp_pcb *pcb, struct pbuf *p)
    {
        CORE_LOCK;
        return udp_send(pcb, p);
    }

    inline u32_t lwip_tcp_sndbuf(tcp_pcb *pcb)
    {
        CORE_LOCK;
        return tcp_sndbuf(pcb);
    }

    inline err_t lwip_tcp_output(tcp_pcb *pcb)
    {
        CORE_LOCK;
        return tcp_output(pcb);
    }

    inline err_t lwip_tcp_close(tcp_pcb *pcb)
    {
        CORE_LOCK;
        err_t err = tcp_shutdown(pcb, 1, 1) | tcp_close(pcb);
        return err;
    }

    inline void init(boost::asio::io_context &ctx)
    {
        CORE_LOCK;
        lwip_init();
        netif_default = netif_list;
        _loopback = netif_list;
    }

    inline void set_output_function(std::function<std::remove_pointer<netif_output_fn>::type> f)
    {
        CORE_LOCK;
        _loopback->output = f;
    }
    inline err_t lwip_ip_input(pbuf *p)
    {
        CORE_LOCK;
        return _loopback->input(p, _loopback);
    }

private:
    LWIPStack()
        : _loopback(NULL)
    {}

private:
    netif *_loopback;
    std::recursive_mutex core_mtx_;
};
