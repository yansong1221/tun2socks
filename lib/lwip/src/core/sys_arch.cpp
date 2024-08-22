#include <mutex>
#include <time.h>
#include <unordered_set>

#include "lwip/sys.h"
#include "arch/sys_arch.h"
#include <chrono>

static std::unordered_set<void*>             sys_arch_pcb_sets;
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

int sys_arch_pcb_watch(void* pcb)
{
    if (NULL == pcb) {
        return 0;
    }

    int rc = 0;
    rc     = sys_arch_pcb_sets.insert(pcb).second ? 1 : 0;
    return rc;
}

int sys_arch_pcb_is_watch(void* pcb)
{
    if (NULL == pcb) {
        return 0;
    }

    int rc = 0;
    rc     = sys_arch_pcb_sets.find(pcb) != sys_arch_pcb_sets.end() ? 1 : 0;
    return rc;
}

int sys_arch_pcb_unwatch(void* pcb)
{
    if (NULL == pcb) {
        return 0;
    }

    int rc = 0;

    auto tail = sys_arch_pcb_sets.find(pcb);
    if (tail != sys_arch_pcb_sets.end()) {
        rc = 1;
        sys_arch_pcb_sets.erase(tail);
    }
    return rc;
}
