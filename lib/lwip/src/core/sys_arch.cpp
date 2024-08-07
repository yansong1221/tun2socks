#include <time.h>
#include <unordered_set>
#include <mutex>

#include "lwip/sys.h"
#include <chrono>


static std::mutex sys_arch_pcb_sets_syncobj;
static std::unordered_set<void *> sys_arch_pcb_sets;

void sys_init(void) {
	
}

static u32_t
sys_get_ms_longlong(void)
{
	auto time_point = std::chrono::steady_clock::now();
	return std::chrono::duration_cast<std::chrono::milliseconds>(time_point.time_since_epoch()).count();
}

u32_t
sys_jiffies(void)
{
	return (u32_t)sys_get_ms_longlong();
}

u32_t
sys_now(void)
{
	return (u32_t)sys_get_ms_longlong();
}

int sys_arch_pcb_watch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		rc = sys_arch_pcb_sets.insert(pcb).second ? 1 : 0;
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}

int sys_arch_pcb_is_watch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		rc = sys_arch_pcb_sets.find(pcb) != sys_arch_pcb_sets.end() ? 1 : 0;
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}

int sys_arch_pcb_unwatch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		auto tail = sys_arch_pcb_sets.find(pcb);
		if (tail != sys_arch_pcb_sets.end()) {
			rc = 1;
			sys_arch_pcb_sets.erase(tail);
		}
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}
