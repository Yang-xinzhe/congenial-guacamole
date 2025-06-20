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

typedef __attribute__((aligned(4))) struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;
    uint32_t cpsr;
} RegisterStates;

typedef struct {
    uint16_t changed_regs; // R0-R12 which reg changed

    uint8_t SP : 1; // R13 (Stack Pointer)
    uint8_t LR : 1; // R14 (Link Register)
    uint8_t PC : 1; // R15 (Program Counter)
} RegChangeInfo;

typedef struct {
    // [31:28]
    uint8_t N : 1;  // Negative
    uint8_t Z : 1;  // '0'
    uint8_t C : 1;  // Progression
    uint8_t V : 1;  // Overflow
    // [27]
    uint8_t Q : 1; // Cumulative Saturation
    // [26:25]  IT[1:0]
    // [24]
    uint8_t J : 1; // Jazelle
    // [23:20] Reserved
    // [19:16]
    uint8_t GE : 1; // SIMD Greater Than
    // [15:10]  IT[7:2]
    // [9]
    uint8_t E : 1; // Control Load/Store
    // [8]
    uint8_t A : 1; // disables asynchronous abort
    // [7]
    uint8_t I : 1; // IRQ mode
    // [6]
    uint8_t F : 1; // FIQ mode
    // [5]
    uint8_t T : 1; // Thumb state
    // [4:0]
    uint8_t M : 1; // FIQ IRQ SVC ABT UND MON HYP
    // Change details
    uint32_t before_value;
    uint32_t after_value;
    uint32_t changed_mask; // Which bit changed
    enum{
        SAFE = 0, // Only Condition Flags Changed
        SUSPICIOUS = 1, // Execute State Changed
        DANGEROUS = 2, // System Control Changed
        CRITICAL = 3 // CPU Mode Changed
    } security_level;
    
} CpsrChangeInfo;

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

// void test_instruction(void)
// {
//     asm volatile(
//         ".global insn_test_plate_begin \n"
//         "insn_test_plate_begin:\n"

//         ".global insn_location \n"
//         "insn_location: \n"
//         "nop \n"

//         "bx lr \n"

//         ".global insn_test_plate_end \n"
//         "insn_test_plate_end: \n"
//         :::);
// }

void test_instruction(void)
{
    asm volatile(
        ".global insn_test_plate_begin \n"
        "insn_test_plate_begin:\n"

        // "mov r0, #0x55 \n"
        // "orr r0, r0, r0, lsl #8 \n"   // r0 = 0x5555
        // "orr r0, r0, r0, lsl #16 \n"  // r0 = 0x55555555
        // "mov r1, r0 \n"
        // "mov r2, r0 \n"
        // "mov r3, r0 \n"
        // "mov r4, r0 \n"
        // "mov r5, r0 \n"
        // "mov r6, r0 \n"
        // "mov r7, r0 \n"
        // "mov r8, r0 \n"
        // "mov r9, r0 \n"
        // "mov r10, r0 \n"
        // "mov r12, r0 \n"
        "mov r0, #0 \n"
        "ldr r1, =0x11111111 \n"
        "ldr r2, =0x22222222 \n"
        "ldr r3, =0x33333333 \n"
        "ldr r4, =0x44444444 \n"
        "ldr r5, =0x55555555 \n"
        "ldr r6, =0x66666666 \n"
        "ldr r7, =0x77777777 \n"
        "ldr r8, =0x88888888 \n"
        "ldr r9, =0x99999999 \n"
        "ldr r10, =0xaaaaaaaa \n"
        "ldr r11, =0xbbbbbbbb \n"
        "ldr r12, =0xcccccccc \n"

        "push {r0-r12, lr} \n"
        "ldr r0, =0x60000000   \n"

        // 保存r0
        "ldr r1, [sp, #0]      \n"    
        "str r1, [r0, #0]      \n"    
        
        // 保存r1
        "ldr r1, [sp, #4]      \n"    
        "str r1, [r0, #4]      \n"    
        
        // 修复：正确保存r2-r12，分两部分处理
        "add r1, sp, #8        \n"    // 指向栈上r2
        "add r2, r0, #8        \n"    // 指向目标r2位置
        "ldmia r1!, {r3-r12}   \n"    // 加载r2-r11到r3-r12（10个值）
        "stmia r2!, {r3-r12}   \n"    // 存储到r2-r11位置（10个值）
        
        // 单独处理r12
        "ldr r1, [sp, #48]     \n"    // 加载栈上r12
        "str r1, [r0, #48]     \n"    // 存储到目标r12位置
        
        // 保存lr
        "ldr r1, [sp, #52]     \n"    
        "str r1, [r0, #56]     \n"    
        
        // 修复：移除CPSR清零，直接读取当前状态
        "mrs r1, cpsr          \n"
        "str r1, [r0, #64]     \n"    
        
        // 保存SP和PC
        "mov r1, sp            \n"
        "add r1, r1, #56       \n"    
        "str r1, [r0, #52]     \n"    
        
        "str pc, [r0, #60]     \n"    
        "pop {r0-r12, lr}      \n"

        "dsb \n"

        ".global insn_location \n"
        "insn_location: \n"
        "nop \n"

        "dsb \n"

        // 第二部分：执行后保存（同样修复）
        "push {r0-r12, lr} \n"
        "ldr r0, =0x60000000   \n"
        "add r0, r0, #68       \n"

        // 保存r0
        "ldr r1, [sp, #0]      \n"
        "str r1, [r0, #0]      \n"
        
        // 保存r1
        "ldr r1, [sp, #4]      \n"
        "str r1, [r0, #4]      \n"
        
        // 修复：正确保存r2-r11
        "add r1, sp, #8        \n"
        "add r2, r0, #8        \n"
        "ldmia r1!, {r3-r12}   \n"
        "stmia r2!, {r3-r12}   \n"
        
        // 单独处理r12
        "ldr r1, [sp, #48]     \n"
        "str r1, [r0, #48]     \n"
        
        // 保存其余寄存器
        "ldr r1, [sp, #52]     \n"
        "str r1, [r0, #56]     \n"
        
        "mrs r1, cpsr          \n"
        "str r1, [r0, #64]     \n"
        
        "mov r1, sp            \n"
        "add r1, r1, #56       \n"
        "str r1, [r0, #52]     \n"
        
        "str pc, [r0, #60]     \n"
        "pop {r0-r12, lr} \n"

        "bx lr \n"

        ".ltorg\n"

        ".global insn_test_plate_end \n"
        "insn_test_plate_end: \n"
        :
        :
        : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "lr", "memory", "cc");
}

RegChangeInfo detect_reg_changes(RegisterStates *before, RegisterStates *after) {
    RegChangeInfo info = {0};
    if(before->r0  != after->r0) info.changed_regs |= (1 << 0);
    if(before->r1  != after->r1) info.changed_regs |= (1 << 1);
    if(before->r2  != after->r2) info.changed_regs |= (1 << 2);
    if(before->r3  != after->r3) info.changed_regs |= (1 << 3);
    if(before->r4  != after->r4) info.changed_regs |= (1 << 4);
    if(before->r5  != after->r5) info.changed_regs |= (1 << 5);
    if(before->r6  != after->r6) info.changed_regs |= (1 << 6);
    if(before->r7  != after->r7) info.changed_regs |= (1 << 7);
    if(before->r8  != after->r8) info.changed_regs |= (1 << 8);
    if(before->r9  != after->r9) info.changed_regs |= (1 << 9);
    if(before->r10 != after->r10) info.changed_regs |= (1 << 10);
    if(before->r11 != after->r11) info.changed_regs |= (1 << 11);
    if(before->r12 != after->r12) info.changed_regs |= (1 << 12);

    info.SP = (before->sp != after->sp);
    info.LR = (before->lr != after->lr);
    return info;
}

CpsrChangeInfo detect_cpsr_changes(RegisterStates *before, RegisterStates *after){
    CpsrChangeInfo info = {0};

    uint32_t before_cpsr = before->cpsr;
    uint32_t after_cpsr = after->cpsr;
    uint32_t changed = before_cpsr ^ after_cpsr;

    info.before_value = before_cpsr;
    info.after_value = after_cpsr;
    info.changed_mask = changed;

    info.N = (changed >> 31) & 1;
    info.Z = (changed >> 30) & 1;
    info.C = (changed >> 29) & 1;
    info.V = (changed >> 28) & 1;

    info.Q = (changed >> 27) & 1;
    
    info.J = (changed >> 24) & 1;

    info.GE = ((changed >> 16) & 0xF) != 0;

    info.E = (changed >> 9) & 1;
    info.A = (changed >> 8) & 1;
    info.I = (changed >> 7) & 1;
    info.F = (changed >> 6) & 1;

    info.T = (changed >> 5) & 1;

    uint32_t before_mode = before_cpsr & 0x1F;
    uint32_t after_mode = after_cpsr & 0x1F;
    info.M = (before_mode != after_mode);

    if(info.M) {
        info.security_level = CRITICAL;
        printf("MODE: 0x%02X -> 0x%02X\n", before_mode, after_mode);
    } else if(info.E || info.A || info.I || info.F) {
        info.security_level = DANGEROUS;
        printf("DANGEROUS\n");
    } else if(info.J || info.T) {
        info.security_level = SUSPICIOUS;
        printf("SUSPICIOUS\n");
    } else {
        info.security_level = SAFE;
    }
    return info;
}

void print_report(RegChangeInfo *regs_info, CpsrChangeInfo *cpsr_info, RegisterStates *before, RegisterStates *after) {
    if (last_insn_signum != 0) {
        printf("signal: %d (%s)\n", last_insn_signum, strsignal(last_insn_signum));
        switch(last_insn_signum) {
            case SIGILL:
                printf("  -> 未定义指令或特权指令\n");
                break;
            case SIGSEGV:
                printf("  -> 内存访问违规\n");
                break;
            case SIGTRAP:
                printf("  -> 调试陷阱\n");
                break;
            case SIGBUS:
                printf("  -> 总线错误\n");
                break;
        }
    } else {
        printf("signal: none\n");
    }
    
    printf("Regs:\n");
    if(regs_info->changed_regs == 0) {
        printf("General Register No Changed\n");
    } else {
        printf("  Changed general registers:\n");
        uint32_t *before_regs = (uint32_t*)before;
        uint32_t *after_regs = (uint32_t*)after;
        for(int i = 0 ; i < 13 ; i++) {
            if(regs_info->changed_regs & (1 << i)) {
                printf("    R%-2d: 0x%08X -> 0x%08X\n", i, before_regs[i], after_regs[i]);
            }
        }
    }
    printf("\n");
    printf("Special Registers:\n");
    if(regs_info->SP) printf("SP\n");
    if(regs_info->LR) printf("LR\n");
    if (!regs_info->SP && !regs_info->LR) {
        printf("SP/LR normal");
    }
    printf("\n");
    printf("CPSR:\n");
    if(cpsr_info->changed_mask == 0) {
        printf("CPSR no Changed\n");
    } else {
        if (cpsr_info->N || cpsr_info->Z || cpsr_info->C || cpsr_info->V) {
            printf("flags(");
            if (cpsr_info->N) printf("N");
            if (cpsr_info->Z) printf("Z");
            if (cpsr_info->C) printf("C");
            if (cpsr_info->V) printf("V");
            printf(") ");
        }

        if (cpsr_info->Q) printf("Q saturation ");
        if (cpsr_info->J) printf("Jazelle ");
        if (cpsr_info->GE) printf("SIMD-GE ");
        if (cpsr_info->T) printf("Thumb state ");
        
        if (cpsr_info->E) printf("endian ");
        if (cpsr_info->A) printf("async abort ");
        if (cpsr_info->I) printf("IRQ ");
        if (cpsr_info->F) printf("FIQ ");
        if (cpsr_info->M) printf("mode switch ");
    }
    printf("\n");
    printf("Safe Level:\n");
    switch(cpsr_info->security_level) {
        case SAFE:
            printf(" safe");
            break;
        case SUSPICIOUS:
            printf(" suspicious");
            break;
        case DANGEROUS:
            printf(" dangerous");
            break;
        case CRITICAL:
            printf(" critical");
            break;
    }
    printf("\n");
    if (cpsr_info->security_level >= DANGEROUS) {
        printf("\nchange details:\n");
        printf("   CPSR: 0x%08X -> 0x%08X\n", 
               cpsr_info->before_value, cpsr_info->after_value);
        
        if (cpsr_info->M) {
            uint32_t before_mode = cpsr_info->before_value & 0x1F;
            uint32_t after_mode = cpsr_info->after_value & 0x1F;
            printf("   mode: 0x%02X -> 0x%02X ", before_mode, after_mode);
            
            // 打印模式名称
            printf("(");
            switch(before_mode) {
                case 0x10: printf("USR"); break;
                case 0x11: printf("FIQ"); break;
                case 0x12: printf("IRQ"); break;
                case 0x13: printf("SVC"); break;
                case 0x17: printf("ABT"); break;
                case 0x1B: printf("UND"); break;
                case 0x1F: printf("SYS"); break;
                default: printf("0x%02X", before_mode);
            }
            printf(" -> ");
            switch(after_mode) {
                case 0x10: printf("USR"); break;
                case 0x11: printf("FIQ"); break;
                case 0x12: printf("IRQ"); break;
                case 0x13: printf("SVC"); break;
                case 0x17: printf("ABT"); break;
                case 0x1B: printf("UND"); break;
                case 0x1F: printf("SYS"); break;
                default: printf("0x%02X", after_mode);
            }
            printf(")\n");
        }
    }
}

int init_memory_monitor(PmuCounter *pmu) {
    struct perf_event_attr attr = {0};
    attr.type = 8;
    attr.size = sizeof(attr);
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.pinned = 1;
    // attr.exclusive = 1;
    
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

void test_load_store(uint8_t *insn_bytes, size_t insn_length, TestResult *result)
{
    if (g_pmu.ld_retired_fd <= 0 || g_pmu.st_retired_fd <= 0) {
        result->ld_count = 0;
        result->st_count = 0;
        return;
    }

    // 预先准备测试指令
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    executing_insn = 1;

    // 获取函数指针
    void (*exec_page)() = (void(*)()) insn_page;

    // 重置和启用ST计数器
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 执行测试指令
    exec_page();

    // 内存屏障
    asm volatile("dsb" ::: "memory");

    // 禁用ST计数器
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_DISABLE, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // 读取结果
    read(g_pmu.ld_retired_fd, &result->ld_count, sizeof(uint64_t));
    read(g_pmu.st_retired_fd, &result->st_count, sizeof(uint64_t));
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
    printf("测试指令: 0x%08X", instruction);
    
    // 基准值：nop指令的背景噪声
    uint64_t base_ld = 73; // 17
    uint64_t base_st = 28; // 5
    
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
        0xE1A08003,  // MOV  r8, r3
        0xE1A09004,  // MOV  r9, r4
        0xE181A00B,  // ORR  r10,r1,r11           (r10 发生变化, 不影响 NZCV)
        0xE1A0B006,  // MOV  r11,r6
        0xE1A0C002,  // MOV  r12,r2

        0xE1B00000,  // MOVS r0,r0                (只改标志位, 无访存)
        0xE2926001,  // ADDS r6,r2,#1             (改 r6 和 NZCV)
        0xE2537001,  // SUBS r7,r3,#1             (改 r7 和 NZCV)
        0xE1B0A004,  // MOVS r10,r4               (改 r10, 也刷新 NZCV)
        0xE1520003,  // CMP  r2,r3                (仅改 NZCV, 不写通用寄存器)

        0xE0C34597,  // UMULL r4,r5,r7,r7         (r4,r5 同时改变, NZCV=unchanged)
        0xE0E24597,  // UMLALS r4,r5,r7,r7        (r4,r5 + NZCV)
        0xE0A14692,  // ADC   r4,r1,r2            (改 r4 + NZCV, 依赖进位)

        // 0xE8BD000F,  // LDMIA sp!,{r0-r3}         (r0-r3,sp 改变，4 次 load)
        // 0xE92D00F0,  // STMDB sp!,{r4-r7}         (r4-r7,sp 改变，4 次 store)
        // 0xE8BD10F0,  // LDMIA sp!,{r4-r7,lr}      (r4-r7,lr,sp；5 次 load)
        // 0xE92D400F,  // STMDB sp!,{r0-r3,lr}      (r0-r3,lr,sp；5 次 store)

        0xE10F1000,  // MRS  r1,cpsr              (读 CPSR → r1，改 r1)
        0xE121F001,  // MSR  cpsr_flg,r1          (写 NZCVQP 标志；**可能触 SIGILL**)

        // === 中断控制指令 ===
        0xF10C01C0,  // CPSID i                   (禁用IRQ中断)
        0xF10C0140,  // CPSID f                   (禁用FIQ中断) 
        0xF10C01C0,  // CPSID i,f                 (同时禁用IRQ和FIQ)
        0xF10801C0,  // CPSIE i                   (启用IRQ中断)
        0xF1080140,  // CPSIE f                   (启用FIQ中断)
        0xF10801C0,  // CPSIE i,f                 (同时启用IRQ和FIQ)
        
        // === 模式切换指令 ===
        0xF1020011,  // CPS #0x11                 (切换到FIQ模式)
        0xF1020012,  // CPS #0x12                 (切换到IRQ模式) 
        0xF1020013,  // CPS #0x13                 (切换到SVC模式)
        0xF1020017,  // CPS #0x17                 (切换到ABT模式)
        0xF102001B,  // CPS #0x1B                 (切换到UND模式)
        0xF102001F,  // CPS #0x1F                 (切换到SYS模式)
        0xF1020010,  // CPS #0x10                 (切换到USR模式)
        
        // === MSR指令用于修改CPSR的各个字段 ===
        0xE121F001,  // MSR cpsr_c, r1            (修改CPSR控制字段，包括模式位)
        0xE128F001,  // MSR cpsr_f, r1            (修改CPSR标志字段)
        0xE124F001,  // MSR cpsr_s, r1            (修改CPSR状态字段)
        0xE122F001,  // MSR cpsr_x, r1            (修改CPSR扩展字段)
        0xE12FF001,  // MSR cpsr_cxsf, r1         (修改CPSR所有字段)
        
        // === 具体的中断控制值 ===
        0xE321F0C0,  // MSR cpsr_c, #0xC0         (直接设置IRQ+FIQ禁用位)
        0xE321F080,  // MSR cpsr_c, #0x80         (直接设置IRQ禁用位)
        0xE321F040,  // MSR cpsr_c, #0x40         (直接设置FIQ禁用位)
        0xE321F000,  // MSR cpsr_c, #0x00         (清除IRQ+FIQ禁用位)
        
        // === 模式切换组合 ===
        0xE321F0D3,  // MSR cpsr_c, #0xD3         (SVC模式 + IRQ+FIQ禁用)
        0xE321F0D1,  // MSR cpsr_c, #0xD1         (FIQ模式 + IRQ+FIQ禁用)
        0xE321F0D2,  // MSR cpsr_c, #0xD2         (IRQ模式 + IRQ+FIQ禁用)
        0xE321F05F,  // MSR cpsr_c, #0x5F         (系统模式 + IRQ+FIQ启用)
        
        // === 软件中断指令 ===
        0xEF000001,  // SWI #1                     (软件中断调用)
        0xEF000010,  // SWI #16                    (软件中断调用)
        0xEF0000FF,  // SWI #255                   (软件中断调用)
    };

    int shmid = shmget(IPC_PRIVATE, sizeof(RegisterStates) * 2, IPC_CREAT | 0666);
        if(shmid == -1) {
            perror("shmget failed");
            return 1;
        }

    void *addr = (void *)0x60000000;
    void *res = shmat(shmid, addr, 0);

    if(res == (void *)-1) {
        perror("shmat failed");
        return 1;
    }

    if(res != addr) {
        perror("shared memory unmatched");
        return 1;
    }

    

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
        
        RegisterStates *regs_before = (RegisterStates *)res;
        RegisterStates *regs_after = (RegisterStates *)res + 1;

        TestResult result = {0};
        
        // printf("\n[第1步] 测试Load退休指令...\n");
        // result.ld_count = test_load_only(insn_bytes, buf_length);
        // printf("Load计数: %llu\n", result.ld_count);
        
        // printf("\n[第2步] 测试Store退休指令...\n");
        // result.st_count = test_store_only(insn_bytes, buf_length);
        // printf("Store计数: %llu\n", result.st_count);
        
        test_load_store(insn_bytes, buf_length, &result);

        RegChangeInfo regs_info = detect_reg_changes(regs_before, regs_after);
        CpsrChangeInfo cpsr_info = detect_cpsr_changes(regs_before, regs_after);

        printf("===================================\n");
        print_report(&regs_info, &cpsr_info, regs_before, regs_after);
        print_test_result(hidden_instruction, &result);
        printf("===================================\n");
        printf("\n");


        if (g_pmu.ld_retired_fd > 0) close(g_pmu.ld_retired_fd);
        if (g_pmu.st_retired_fd > 0) close(g_pmu.st_retired_fd);
    }
    return 0;
}