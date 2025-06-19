#include "pmu.h"
#include "util.h"

int init_memory_monitor(PmuCounter *pmu) {
    struct perf_event_attr attr = {0};
    attr.type = 8;
    attr.size = sizeof(attr);
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.pinned = 1;
    attr.exclusive = 1;
    
    attr.config = 0x0006;
    pmu->ld_retired_fd = perf_event_open(&attr, 0, 1, -1, 0);
    if (pmu->ld_retired_fd == -1) {
        printf("LD_RETIRED failed: %s\n", strerror(errno));
        
        // Try without CPU binding
        pmu->ld_retired_fd = perf_event_open(&attr, 0, -1, -1, 0);
        printf("LD_RETIRED without CPU binding: %s (fd=%d)\n", 
               pmu->ld_retired_fd != -1 ? "OK" : "FAIL", pmu->ld_retired_fd);
    }

    attr.config = 0x0007;
    pmu->st_retired_fd = perf_event_open(&attr, 0, 1, -1, 0);
    if (pmu->st_retired_fd == -1) {
        printf("ST_RETIRED failed: %s\n", strerror(errno));
        
        // Try without CPU binding
        pmu->st_retired_fd = perf_event_open(&attr, 0, -1, -1, 0);
        printf("ST_RETIRED without CPU binding: %s (fd=%d)\n", 
               pmu->st_retired_fd != -1 ? "OK" : "FAIL", pmu->st_retired_fd);
    }
    
    return 0;
}


// Only test Load retirement instructions
uint64_t test_load_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.ld_retired_fd <= 0) {
        return 0;
    }

    // Prepare test instructions
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // Get function pointer
    void (*exec_page)() = (void(*)()) insn_page;

    // Reset and enable LD counter
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Execute test instructions
    exec_page();

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Disable LD counter
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // Read result
    read(g_pmu.ld_retired_fd, &result, sizeof(uint64_t));
    return result;
}


// Only test Store retirement instructions
uint64_t test_store_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.st_retired_fd <= 0) {
        return 0;
    }

    // Prepare test instructions
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // Get function pointer
    void (*exec_page)() = (void(*)()) insn_page;

    // Reset and enable ST counter
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 执行测试指令
    exec_page();

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Disable ST counter
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // Read result
    read(g_pmu.st_retired_fd, &result, sizeof(uint64_t));
    return result;
}

