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

#include "pbuf.hpp"
#include "use_awaitable.hpp"
namespace tun2socks {
namespace wrapper {

    class tcp_conn : public std::enable_shared_from_this<tcp_conn> {
    public:
        using recved_function = std::function<err_t(pbuf_buffer, err_t)>;
        using sent_function   = std::function<err_t(u16_t)>;
        using ptr             = std::shared_ptr<tcp_conn>;

        explicit tcp_conn(struct tcp_pcb* newpcb)
            : pcb_(newpcb)
        {
            ::tcp_arg(newpcb, this);
            ::tcp_err(newpcb, [](void* arg, err_t err) {
                auto self = (tcp_conn*)arg;
                self->on_tcb_error(err);
            });
            ::tcp_recv(newpcb, [](void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) -> err_t {
                auto self = (tcp_conn*)arg;
                return self->on_tcb_recv(tpcb, p, err);
            });
            ::tcp_sent(pcb_, [](void* arg, struct tcp_pcb* tpcb, u16_t len) -> err_t {
                auto self = (tcp_conn*)arg;
                return self->on_tcb_sent(tpcb, len);
            });
        }
        ~tcp_conn()
        {
            close();
        }
        struct tcp_pcb* pcb()
        {
            return pcb_;
        }
    public:
        void close()
        {
            if (!pcb_)
                return;

            ::tcp_arg(pcb_, nullptr);
            ::tcp_sent(pcb_, nullptr);
            ::tcp_err(pcb_, nullptr);
            ::tcp_recv(pcb_, nullptr);
            ::tcp_shutdown(pcb_, 1, 1);
            ::tcp_close(pcb_);

            pcb_ = nullptr;
        }
        void set_recved_function(recved_function f)
        {
            recved_func_ = f;
        }
        void set_sent_function(sent_function f)
        {
            sent_func_ = f;
        }
        err_t write(pbuf_buffer buf)
        {
            auto _buf = buf.data();
            return ::tcp_write(pcb_, _buf.data(), _buf.size(), TCP_WRITE_FLAG_COPY);
        }
        err_t output()
        {
            return ::tcp_output(pcb_);
        }
        void recved(u16_t len)
        {
            tcp_recved(pcb_, len);
        }

    private:
        err_t on_tcb_sent(struct tcp_pcb* tpcb, u16_t len)
        {
            if (tpcb == NULL)
                return ERR_VAL;

            if (!sent_func_)
                return ERR_OK;

            return sent_func_(len);
        }
        err_t on_tcb_recv(struct tcp_pcb* tpcb, struct pbuf* p, err_t err)
        {
            if (tpcb == NULL)
                return ERR_VAL;

            if (!recved_func_)
                return ERR_OK;

            return recved_func_(pbuf_buffer(p, false), err);
        }
        void on_tcb_error(err_t err)
        {
            if (!recved_func_)
                return;

            recved_func_(pbuf_buffer(), err);
        }

    private:
        struct tcp_pcb* pcb_;
        recved_function recved_func_;
        sent_function   sent_func_;
    };

    class udp_conn : public std::enable_shared_from_this<udp_conn> {
    public:
        using ptr             = std::shared_ptr<udp_conn>;
        using recved_function = std::function<void(pbuf_buffer)>;

    public:
        udp_conn(struct udp_pcb* pcb)
            : pcb_(pcb)
        {
            ::udp_recv(
                pcb, [](void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
                    if (!pcb)
                        return;

                    auto self = (udp_conn*)arg;
                    self->on_recv(p, addr, port);
                },
                this);
        }
        ~udp_conn()
        {
            close();
        }
        struct udp_pcb* pcb()
        {
            return pcb_;
        }

        err_t write(pbuf_buffer buf)
        {
            return ::udp_send(pcb_, &buf);
        }
        void set_recved_function(recved_function f)
        {
            recved_func_ = f;
        }
        void close()
        {
            if (!pcb_)
                return;

            ::udp_recv(pcb_, nullptr, nullptr);
            ::udp_disconnect(pcb_);
            ::udp_remove(pcb_);
            pcb_ = nullptr;
        }

    private:
        void on_recv(struct pbuf* p, const ip_addr_t* addr, u16_t port)
        {
            pbuf_buffer buf(p, false);
            if (!recved_func_)
                return;

            recved_func_(buf);
        }

    private:
        struct udp_pcb* pcb_;
        recved_function recved_func_;
    };
    class lwip {
    public:
        using ip_output_function  = std::function<void(pbuf_buffer)>;
        using tcp_accept_function = std::function<void(tcp_conn::ptr)>;
        using udp_accept_function = std::function<void(udp_conn::ptr)>;

        static lwip& instance()
        {
            static lwip _instance;
            return _instance;
        }

        inline void init(boost::asio::io_context& ctx)
        {
            lwip_init();

            netif_default    = netif_list;
            loopback_        = netif_default;
            loopback_->state = this;

            loopback_->output = [](struct netif*     netif,
                                   struct pbuf*      p,
                                   const ip4_addr_t* ipaddr) -> err_t {
                auto self = (lwip*)netif->state;
                self->on_ip_output(p);
                return ERR_OK;
            };
            loopback_->output_ip6 = [](struct netif*     netif,
                                       struct pbuf*      p,
                                       const ip6_addr_t* ipaddr) -> err_t {
                auto self = (lwip*)netif->state;
                self->on_ip_output(p);
                return ERR_OK;
            };

            ::default_tcp_accept(this, [](void* arg, struct tcp_pcb* newpcb, err_t err) -> err_t {
                if (err != ERR_OK || newpcb == NULL)
                    return ERR_VAL;

                auto self = (lwip*)arg;
                return self->on_tcp_accept(newpcb);
            });

            ::default_udp_accept(this, [](struct udp_pcb* pcb, void* user_data) -> err_t {
                auto self = (lwip*)(user_data);
                return self->on_udp_accept(pcb);
            });

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
        inline void tcp_accept(tcp_accept_function f)
        {
            tcp_accept_func_ = f;
        }
        inline void udp_accept(udp_accept_function f)
        {
            udp_accept_func_ = f;
        }

        inline void ip_packet_output(ip_output_function f)
        {
            ip_output_ = f;
        }
        inline err_t ip_packet_input(pbuf_buffer buf)
        {
            pbuf_ref(&buf);
            return loopback_->input(&buf, loopback_);
        }

    private:
        err_t on_tcp_accept(struct tcp_pcb* newpcb)
        {
            if (!tcp_accept_func_)
                return ERR_RST;

            auto conn = std::make_shared<tcp_conn>(newpcb);
            tcp_accept_func_(conn);
            return ERR_OK;
        }
        err_t on_udp_accept(struct udp_pcb* newpcb)
        {
            if (!udp_accept_func_)
                return ERR_RST;

            auto conn = std::make_shared<udp_conn>(newpcb);
            udp_accept_func_(conn);
            return ERR_OK;
        }

        void on_ip_output(struct pbuf* p)
        {
            if (ip_output_) {
                auto buffer = pbuf_buffer::smart_copy(p);
                ip_output_(buffer);
            }
        }

    private:
        lwip()
        {
        }

    private:
        struct netif* loopback_ = nullptr;

        ip_output_function  ip_output_;
        tcp_accept_function tcp_accept_func_;
        udp_accept_function udp_accept_func_;
    };
}  // namespace wrapper
}  // namespace tun2socks