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
#include "pbuf.hpp"
#include "use_awaitable.hpp"

namespace tun2socks {

class lwip {
public:
    using ip_packet_output_function = std::function<void(wrapper::pbuf_buffer)>;

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

    class tcp_conn : public std::enable_shared_from_this<tcp_conn> {
    public:
        using ptr = std::shared_ptr<tcp_conn>;

        using recv_function = std::function<err_t(const wrapper::pbuf_buffer&, err_t)>;

    public:
        tcp_conn(struct tcp_pcb* pcb)
            : pcb_(pcb)
        {
            tcp_arg(pcb_, this);
            tcp_recv(pcb_, [](void* arg, struct tcp_pcb* conn, struct pbuf* p, err_t err) -> err_t {
                LWIP_UNUSED_ARG(conn);
                auto self = (tcp_conn*)arg;
                return self->on_recv(p, err);
            });
            tcp_sent(pcb_, [](void* arg, struct tcp_pcb* conn, u16_t len) -> err_t {
                LWIP_UNUSED_ARG(conn);
                auto self = (tcp_conn*)arg;
                return self->on_sent(len);
            });
            tcp_err(pcb_, [](void* arg, err_t err) {
                auto self = (tcp_conn*)arg;
                self->on_recv(NULL, err);
            });
        }
        virtual ~tcp_conn()
        {
            tcp_arg(pcb_, NULL);
            tcp_recv(pcb_, NULL);
            tcp_sent(pcb_, NULL);
            tcp_err(pcb_, NULL);
            tcp_shutdown(pcb_, 1, 1);
            tcp_close(pcb_);
        }

    public:
        inline std::size_t buf_len() const
        {
            return std::min<uint16_t>(tcp_mss(pcb_), tcp_sndbuf(pcb_));
        }
        inline void recved(uint16_t len)
        {
            tcp_recved(pcb_, len);
        }
        inline err_t write(const void* dataptr, uint16_t len)
        {
            auto err = tcp_write(pcb_, dataptr, len, TCP_WRITE_FLAG_COPY);
            if (err != ERR_OK)
                return err;

            return output();
        }
        inline err_t output()
        {
            return tcp_output(pcb_);
        }
        inline tcp_endpoint_pair endp_pair() const
        {
            return lwip::create_endpoint(pcb_);
        }
        void set_recv_function(recv_function f)
        {
            recv_func_ = f;
        }

    private:
        err_t on_recv(struct pbuf* p, err_t err)
        {
            if (!recv_func_)
                return ERR_MEM;

            if (err != ERR_OK) {
                recv_func_(wrapper::pbuf_buffer(), err);
                return ERR_OK;
            }

            auto buffer = wrapper::pbuf_buffer::smart_copy(p);

            err = recv_func_(buffer, err);
            if (err == ERR_OK && p)
                pbuf_free(p);

            return err;
        }
        err_t on_sent(u16_t len)
        {
            return ERR_OK;
        }

    private:
        struct tcp_pcb* pcb_;
        recv_function   recv_func_;
    };

    class tcp_accepter : public std::enable_shared_from_this<tcp_accepter> {
    public:
        using accept_function = std::function<void(tcp_conn::ptr)>;

    public:
        tcp_accepter()
        {
            auto pcb = ::tcp_new();
            auto any = ip_addr_any;
            tcp_bind(pcb, &any, 0);
            pcb_ = ::tcp_listen(pcb);

            ::tcp_arg(pcb_, this);
            ::tcp_accept(pcb_, [](void* arg, struct tcp_pcb* new_conn, err_t err) -> err_t {
                if (err != ERR_OK)
                    return ERR_VAL;

                auto self = (tcp_accepter*)arg;
                return self->on_accept(new_conn);
            });
        }
        virtual ~tcp_accepter()
        {
            tcp_close(pcb_);
        }

        void set_accept_function(accept_function f)
        {
            accept_func_ = f;
        }

    public:
        static std::shared_ptr<tcp_accepter> instance()
        {
            static std::weak_ptr<tcp_accepter> _instance;

            auto obj = _instance.lock();
            if (obj)
                return obj;

            obj = std::make_shared<tcp_accepter>();

            _instance = obj;
            return obj;
        }

    private:
        err_t on_accept(struct tcp_pcb* new_conn)
        {
            if (!accept_func_)
                return ERR_RST;

            auto conn = std::make_shared<tcp_conn>(new_conn);
            accept_func_(conn);
            return ERR_OK;
        }

    private:
        struct tcp_pcb* pcb_;
        accept_function accept_func_;
    };

    class udp_conn : public std::enable_shared_from_this<udp_conn> {
    public:
        using recv_function = std::function<void(wrapper::pbuf_buffer)>;
        using ptr           = std::shared_ptr<udp_conn>;

    public:
        explicit udp_conn(struct udp_pcb* pcb)
            : pcb_(pcb)
        {
            ::udp_recv(
                pcb_,
                [](void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
                    LWIP_UNUSED_ARG(pcb);
                    auto self = (udp_conn*)arg;
                    self->on_recv(p, addr, port);
                },
                this);
        }
        ~udp_conn()
        {
            udp_recv(pcb_, NULL, NULL);
            udp_disconnect(pcb_);
            udp_remove(pcb_);
        }

    public:
        err_t send(wrapper::pbuf_buffer buf)
        {
            return udp_send(pcb_, &buf);
        }
        inline udp_endpoint_pair endp_pair() const
        {
            return lwip::create_endpoint(pcb_);
        }
        void set_recv_function(recv_function f)
        {
            recv_func_ = f;
        }

    private:
        void on_recv(struct pbuf* p, const ip_addr_t* addr, u16_t port)
        {
            LWIP_UNUSED_ARG(addr);
            LWIP_UNUSED_ARG(port);
            auto buffer = wrapper::pbuf_buffer::smart_copy(p);
            pbuf_free(p);
            if (!recv_func_)
                return;

            recv_func_(buffer);
        }

    private:
        struct udp_pcb*   pcb_;
        recv_function     recv_func_;
        udp_endpoint_pair endp_pair_;
    };

    class udp_creator : public std::enable_shared_from_this<udp_creator> {
    public:
        using udp_create_function = std::function<void(std::shared_ptr<udp_conn>)>;

    public:
        udp_creator()
        {
            udp_create(
                [](struct udp_pcb* newpcb, void* arg) {
                    auto self = (udp_creator*)arg;
                    self->on_udp(newpcb);
                },
                this);
        }
        ~udp_creator()
        {
            udp_create(NULL, NULL);
        }

    public:
        static std::shared_ptr<udp_creator> instance()
        {
            static std::weak_ptr<udp_creator> _instance;

            auto obj = _instance.lock();
            if (obj)
                return obj;

            obj = std::make_shared<udp_creator>();

            _instance = obj;
            return obj;
        }
        void set_udp_create_function(udp_create_function f)
        {
            create_func_ = f;
        }

    private:
        void on_udp(struct udp_pcb* newpcb)
        {
            auto conn = std::make_shared<udp_conn>(newpcb);
            if (!create_func_)
                return;

            create_func_(conn);
        }

    private:
        udp_create_function create_func_;
    };

    inline void init(boost::asio::io_context& ctx)
    {
        lwip_init();
        netif_default    = netif_list;
        loopback_        = netif_list;
        loopback_->state = this;

        loopback_->output = [](struct netif*     netif,
                               struct pbuf*      p,
                               const ip4_addr_t* ipaddr) -> err_t {
            LWIP_UNUSED_ARG(ipaddr);
            auto self = (lwip*)netif->state;
            self->_on_ip_output(p);
            return ERR_OK;
        };
        loopback_->output_ip6 = [](struct netif*     netif,
                                   struct pbuf*      p,
                                   const ip6_addr_t* ipaddr) -> err_t {
            LWIP_UNUSED_ARG(ipaddr);
            auto self = (lwip*)netif->state;
            self->_on_ip_output(p);
            return ERR_OK;
        };

        boost::asio::co_spawn(
            ctx,
            []() -> boost::asio::awaitable<void> {
                for (;;) {
                    boost::system::error_code ec;
                    boost::asio::steady_timer update_timer(
                        co_await boost::asio::this_coro::executor);
                    update_timer.expires_from_now(std::chrono::milliseconds(1));
                    co_await update_timer.async_wait(net_awaitable[ec]);
                    if (ec)
                        co_return;
                    ::sys_check_timeouts();
                }
            },
            boost::asio::detached);
    }
    inline err_t ip_input(wrapper::pbuf_buffer buffer)
    {
        return loopback_->input(buffer.release(), loopback_);
    }

    inline void set_ip_output(ip_packet_output_function f)
    {
        ip_output_func_ = f;
    }

private:
    void _on_ip_output(struct pbuf* p)
    {
        if (!ip_output_func_)
            return;

        auto buffer = wrapper::pbuf_buffer::smart_copy(p);
        ip_output_func_(buffer);
    }

private:
    lwip()
        : loopback_(NULL)
    {
    }

private:
    netif*                    loopback_;
    ip_packet_output_function ip_output_func_;
};
}  // namespace tun2socks