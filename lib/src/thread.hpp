#pragma once
#include <future>
#include <thread>

#ifdef _WIN32
#    include <windows.h>
#else
#    include <pthread.h>
#    include <signal.h>
#endif
namespace tun2socks {
class thread {
public:
    virtual ~thread()
    {
        stop_thread();
    }

    bool start_thread()
    {
        if (is_runing())
            return true;

        stop_thread();

        std::promise<bool> status;
        auto               ret = status.get_future();

        run_status_ = true;
        td_         = std::thread(std::bind(&thread::__thread_run, this, std::ref(status)));
        return ret.get();
    }
    bool stop_thread(uint32_t millisecond = uint32_t(-1))
    {
        if (!is_runing()) {
            if (td_.joinable())
                td_.join();
            return true;
        }

        run_status_ = false;

        std::unique_lock<std::timed_mutex> lck(thread_mutex_,
                                               std::chrono::milliseconds(millisecond));
        if (!lck.owns_lock()) {
            run_status_ = true;
            return false;
        }

        if (td_.joinable())
            td_.join();

        return true;
    }
    bool is_runing() const
    {
#ifdef _WIN32
        if (WaitForSingleObject(td_.native_handle(), 0) != WAIT_TIMEOUT)
            return false;
#else
        auto handle = td_.native_handle();
        if (handle == 0)
            return false;
        if (pthread_kill(handle, 0) == ESRCH)
            return false;
#endif
        std::unique_lock<std::timed_mutex> lck(thread_mutex_, std::try_to_lock);
        return !lck.owns_lock();
    }

    void wait()
    {
        if (is_runing()) {
            if (td_.joinable())
                td_.join();
        }
    }

private:
    void __thread_run(std::promise<bool>& status)
    {
        std::unique_lock<std::timed_mutex> lck(thread_mutex_);

        try {
            bool success = this->on_thread_start();
            status.set_value(success);
            if (!success)
                return;
        }
        catch (...) {
            status.set_exception(std::current_exception());
            return;
        }

        while (run_status_) {
            if (!this->on_thread_run())
                break;
        }

        try {
            this->on_thread_end();
        }
        catch (...) {
        }
    }

protected:
    virtual bool on_thread_run() = 0;
    virtual bool on_thread_start()
    {
        return true;
    }
    virtual void on_thread_end() {}

private:
    mutable std::thread      td_;
    volatile bool            run_status_ = false;
    mutable std::timed_mutex thread_mutex_;
};
}  // namespace tun2socks