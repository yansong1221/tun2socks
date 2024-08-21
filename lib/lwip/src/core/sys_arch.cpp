#include <mutex>
#include <time.h>
#include <unordered_set>

#include "lwip/sys.h"
#include <chrono>

static std::chrono::steady_clock::time_point startupTime;

void sys_init(void)
{
    startupTime = std::chrono::steady_clock::now();
}

static u32_t
sys_get_ms_longlong(void)
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - startupTime).count();
}

u32_t sys_jiffies(void)
{
    return (u32_t)sys_get_ms_longlong();
}

u32_t sys_now(void)
{
    return (u32_t)sys_get_ms_longlong();
}
