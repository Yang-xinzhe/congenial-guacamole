#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/mman.h> 
#include <string.h>
#include <ucontext.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>

#define MY_SIGSTKSZ 8192

void* insn_page;
volatile sig_atomic_t last_insn_signum = 0;
volatile sig_atomic_t executing_insn = 0;
extern char insn_test_plate_begin, insn_test_plate_end, insn_location;
uint32_t insn_offset;
uint32_t insn_test_plate_length;
void test_instruction(void) __attribute__((optimize("O0")));

typedef struct {
    int ld_retired_fd;      // 加载指令相关事件
    int st_retired_fd;      // 存储指令相关事件
} PmuCounter;

typedef struct {
    uint64_t ld_count;
    uint64_t st_count;
} TestResult;

static PmuCounter g_pmu = {0};

static int perf_event_open(struct perf_event_attr *hw_event,
                           pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void set_affinity(){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);

    if(sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_setaffinity");
    }

    mlockall(MCL_CURRENT | MCL_FUTURE);
}

void test_instruction(void)
{
    asm volatile(
        ".global insn_test_plate_begin \n"
        "insn_test_plate_begin:\n"

        ".global insn_location \n"
        "insn_location: \n"
        "nop \n"

        "bx lr \n"

        ".global insn_test_plate_end \n"
        "insn_test_plate_end: \n"
        :::);
}


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
        printf("LD_RETIRED失败: %s\n", strerror(errno));
        
        // 尝试不绑定CPU
        pmu->ld_retired_fd = perf_event_open(&attr, 0, -1, -1, 0);
        printf("不绑定CPU的LD_RETIRED: %s (fd=%d)\n", 
               pmu->ld_retired_fd != -1 ? "OK" : "FAIL", pmu->ld_retired_fd);
    }

    attr.config = 0x0007;
    pmu->st_retired_fd = perf_event_open(&attr, 0, 1, -1, 0);
    if (pmu->st_retired_fd == -1) {
        printf("ST_RETIRED失败: %s\n", strerror(errno));
        
        // 尝试不绑定CPU
        pmu->st_retired_fd = perf_event_open(&attr, 0, -1, -1, 0);
        printf("不绑定CPU的ST_RETIRED: %s (fd=%d)\n", 
               pmu->st_retired_fd != -1 ? "OK" : "FAIL", pmu->st_retired_fd);
    }
    
    return 0;
}

int init_insn_page(void) {
    insn_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(insn_page == MAP_FAILED) {
        perror("insn_mmap failed");
        return 1;
    }

    insn_test_plate_length = (&insn_test_plate_end - &insn_test_plate_begin);
    // printf("Debug: template length = %d bytes\n", insn_test_plate_length);
    memcpy(insn_page, &insn_test_plate_begin, insn_test_plate_length);

    insn_offset = (&insn_location - &insn_test_plate_begin) / 4;
    
    // printf("Debug: insn_offset=%d\n", insn_offset);
    
    return 0;
}

// 只测试Load退休指令
uint64_t test_load_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.ld_retired_fd <= 0) {
        return 0;
    }

    // 预先准备测试指令
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // 获取函数指针
    void (*exec_page)() = (void(*)()) insn_page;

    // 重置和启用LD计数器
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 执行测试指令
    exec_page();

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 禁用LD计数器
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // 读取结果
    read(g_pmu.ld_retired_fd, &result, sizeof(uint64_t));
    return result;
}

// 只测试Store退休指令
uint64_t test_store_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.st_retired_fd <= 0) {
        return 0;
    }

    // 预先准备测试指令
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // 获取函数指针
    void (*exec_page)() = (void(*)()) insn_page;

    // 重置和启用ST计数器
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 执行测试指令
    exec_page();

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 禁用ST计数器
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // 读取结果
    read(g_pmu.st_retired_fd, &result, sizeof(uint64_t));
    return result;
}

uint64_t test_nop_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.st_retired_fd <= 0) {
        return 0;
    }

    // 预先准备测试指令
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // 获取函数指针
    void (*exec_page)() = (void(*)()) insn_page;

    // 重置和启用ST计数器
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 执行测试指令
    exec_page();

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 禁用ST计数器
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // 读取结果
    read(g_pmu.st_retired_fd, &result, sizeof(uint64_t));
    return result;
}

size_t fill_insn_buffer(uint8_t *buf, size_t buf_size, uint32_t insn)
{
    if (buf_size < 4)
        return 0;
 
    else {
        buf[0] = insn & 0xff;
        buf[1] = (insn >> 8) & 0xff;
        buf[2] = (insn >> 16) & 0xff;
        buf[3] = (insn >> 24) & 0xff;
    }
    return 4;
}

void print_test_result(uint32_t instruction, TestResult *result) {
    // printf("\n=== 指令内存访问分析结果 ===\n");
    // printf("测试指令: 0x%08X\n", instruction);
    // printf("精确计数结果:\n");
    // printf("  加载指令: %llu\n", result->ld_count);
    // printf("  存储指令: %llu\n", result->st_count);
    
    // if (result->ld_count == 0 && result->st_count == 0) {
    //     printf("  -> 该指令不涉及内存访问\n");
    // } else if (result->ld_count > 0 && result->st_count == 0) {
    //     printf("  -> 该指令只涉及内存加载\n");
    // } else if (result->ld_count == 0 && result->st_count > 0) {
    //     printf("  -> 该指令只涉及内存存储\n");
    // } else {
    //     printf("  -> 该指令涉及内存加载和存储\n");
    // }
    printf("测试指令: 0x%08X", instruction);
    
    // 基准值：nop指令的背景噪声
    uint64_t base_ld = 17;
    uint64_t base_st = 5;
    
    // 计算相对于基准的增量
    int64_t ld_delta = result->ld_count - base_ld;
    int64_t st_delta = result->st_count - base_st;
    
    printf(" | LD:%llu(%+lld) ST:%llu(%+lld)", 
           result->ld_count, ld_delta, result->st_count, st_delta);
    
    // 判断指令类型
    if (ld_delta == 0 && st_delta == 0) {
        printf(" -> 不涉及内存访问");
    } else if (ld_delta == 1 && st_delta == 0) {
        printf(" -> LDR指令(单次加载)");
    } else if (ld_delta == 0 && st_delta == 1) {
        printf(" -> STR指令(单次存储)");
    } else if (ld_delta == 1 && st_delta == 1) {
        printf(" -> 同时加载+存储指令");
    } else if (ld_delta == 2 && st_delta == 0) {
        printf(" -> 双次加载指令");
    } else if (ld_delta == 0 && st_delta == 2) {
        printf(" -> 双次存储指令");
    } else if (ld_delta > 0 && st_delta == 0) {
        printf(" -> 多次加载指令(%lld次)", ld_delta);
    } else if (ld_delta == 0 && st_delta > 0) {
        printf(" -> 多次存储指令(%lld次)", st_delta);
    } else if (ld_delta > 0 && st_delta > 0) {
        printf(" -> 复合访存指令(LD:%lld, ST:%lld)", ld_delta, st_delta);
    } else {
        printf(" -> 异常情况(LD:%lld, ST:%lld)", ld_delta, st_delta);
    }
    
    printf("\n");
}

int main(int argc, const char* argv[]) {
    set_affinity();
    // uint32_t hidden_instruction = 0xE58D0000;  // str r0, [sp] - 应该只涉及1个store
    
    uint32_t test_instructions[] = {
        // === 不涉及内存访问的指令 ===
        0xE1A00000,  // nop (mov r0, r0)
        0xE3A00001,  // mov r0, #1
        0xE0800001,  // add r0, r0, r1  
        0xE0400001,  // sub r0, r0, r1
        0xE0000001,  // and r0, r0, r1
        0xE1800001,  // orr r0, r0, r1
        0xE0200001,  // eor r0, r0, r1
        0xE1A01000,  // mov r1, r0
        0xE1A01080,  // mov r1, r0, lsl #1
        0xE3500000,  // cmp r0, #0
        
        // === 单次内存访问指令 ===
        0xE59D0000,  // ldr r0, [sp]        - 1次load
        0xE59D0004,  // ldr r0, [sp, #4]    - 1次load  
        0xE58D0000,  // str r0, [sp]        - 1次store
        0xE58D0004,  // str r0, [sp, #4]    - 1次store
        
        // === 更多安全的Load指令（使用sp基址）===
        0xE59D0008,  // ldr r0, [sp, #8]    - load sp+8
        0xE59D000C,  // ldr r0, [sp, #12]   - load sp+12
        0xE59D0010,  // ldr r0, [sp, #16]   - load sp+16
        0xE59D1000,  // ldr r1, [sp]        - load到r1
        0xE59D1004,  // ldr r1, [sp, #4]    - load到r1+偏移
        0xE59D2000,  // ldr r2, [sp]        - load到r2
        0xE51D0004,  // ldr r0, [sp, #-4]   - load sp-4（负偏移）
        0xE51D0008,  // ldr r0, [sp, #-8]   - load sp-8
        
        // === 更多安全的Store指令（使用sp基址）===
        0xE58D0008,  // str r0, [sp, #8]    - store sp+8
        0xE58D000C,  // str r0, [sp, #12]   - store sp+12
        0xE58D0010,  // str r0, [sp, #16]   - store sp+16
        0xE58D1000,  // str r1, [sp]        - store r1到栈
        0xE58D1004,  // str r1, [sp, #4]    - store r1+偏移
        0xE58D2000,  // str r2, [sp]        - store r2到栈
        0xE50D0004,  // str r0, [sp, #-4]   - store sp-4（负偏移）
        0xE50D0008,  // str r0, [sp, #-8]   - store sp-8
        
        // === 字节访存（使用sp基址，更安全）===
        0xE5DD0000,  // ldrb r0, [sp]       - 字节load
        0xE5DD0001,  // ldrb r0, [sp, #1]   - 字节load+1
        0xE5DD0002,  // ldrb r0, [sp, #2]   - 字节load+2
        0xE5CD0000,  // strb r0, [sp]       - 字节store
        0xE5CD0001,  // strb r0, [sp, #1]   - 字节store+1
        0xE5CD0002,  // strb r0, [sp, #2]   - 字节store+2

        // 添加一些调试指令来验证异常
        0xE58D0000,  // str r0, [sp]     - 对比：应该ST+1
        0xE58D1000,  // str r1, [sp]     - 异常：显示ST+2  
        0xE58D2000,  // str r2, [sp]     - 测试：是否也ST+2？

        // 测试寄存器初始化的影响
        0xE3A01000,  // mov r1, #0       - 先初始化r1
        0xE58D1000,  // str r1, [sp]     - 再测试存储
    };

    int total_tests = sizeof(test_instructions) / sizeof(test_instructions[0]);
    for(int i = 0 ; i < total_tests ; i++) {
        uint32_t hidden_instruction = test_instructions[i];
        uint8_t insn_bytes[4];

        // printf("=== ARM隐藏指令PMU精确分析 ===\n");
        // printf("测试指令: 0x%08X\n", hidden_instruction);

        if(init_insn_page() != 0) {
            printf("init_insn_page failed\n");
            return 1;
        }

        if(init_memory_monitor(&g_pmu) != 0) {
            printf("PMU initial failed!\n");
        }

        size_t buf_length = fill_insn_buffer(insn_bytes,sizeof(insn_bytes), hidden_instruction);
        
        TestResult result = {0};
        
        // printf("\n[第1步] 测试Load退休指令...\n");
        result.ld_count = test_load_only(insn_bytes, buf_length);
        // printf("Load计数: %llu\n", result.ld_count);
        
        // printf("\n[第2步] 测试Store退休指令...\n");
        result.st_count = test_store_only(insn_bytes, buf_length);
        // printf("Store计数: %llu\n", result.st_count);

        print_test_result(hidden_instruction, &result);

        // buf_length = fill_insn_buffer(insn_bytes,sizeof(insn_bytes), nop);
        // uint64_t nop_result = test_nop_only(insn_bytes, buf_length);
        // printf("nop result: %lld\n", nop_result);

        if (g_pmu.ld_retired_fd > 0) close(g_pmu.ld_retired_fd);
        if (g_pmu.st_retired_fd > 0) close(g_pmu.st_retired_fd);
    }
    return 0;
}