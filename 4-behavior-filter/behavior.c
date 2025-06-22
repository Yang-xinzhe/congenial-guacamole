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
#include <unistd.h>
#include <fcntl.h>

#define MY_SIGSTKSZ 8192

#pragma pack(push, 1)
typedef struct {
    uint32_t opcode;
    // behavior 字段 bit 分配
    // [7:0]   - 基础行为分类 (8 bit)
    // [20:8]  - 寄存器变化详情 (13 bit) 
    // [22:21] - SP/LR 变化 (2 bit)
    // [24:23] - CPSR 安全级别 (2 bit)
    // [28:25] - 异常信号类型 (4 bit)
    // [31:29] - 预留扩展 (3 bit)
    uint32_t behavior;
} InstrBehavior;        // 8 bytes
#pragma pack(pop)

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
    int ld_retired_fd;      // Load retired
    int st_retired_fd;      // Store retired
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

        // Save r0
        "ldr r1, [sp, #0]      \n"    
        "str r1, [r0, #0]      \n"    
        
        // Save r1
        "ldr r1, [sp, #4]      \n"    
        "str r1, [r0, #4]      \n"    
        
        // Fix: Save r2-r12, split into two parts
        "add r1, sp, #8        \n"    // Point to r2 on stack
        "add r2, r0, #8        \n"    // Point to r2 in target
        "ldmia r1!, {r3-r12}   \n"    // Load r2-r11 to r3-r12 (10 values)
        "stmia r2!, {r3-r12}   \n"    // Store to r2-r11 (10 values)
        
        // Handle r12 separately
        "ldr r1, [sp, #48]     \n"    // Load r12 from stack
        "str r1, [r0, #48]     \n"    // Store to r12 in target
        
        // Save lr
        "ldr r1, [sp, #52]     \n"    
        "str r1, [r0, #56]     \n"    
        
        
        "mrs r1, cpsr          \n"
        "str r1, [r0, #64]     \n"    
        
        // Save SP and PC
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

        // Second part:
        "push {r0-r12, lr} \n"
        "ldr r0, =0x60000000   \n"
        "add r0, r0, #68       \n"

        // Save r0
        "ldr r1, [sp, #0]      \n"
        "str r1, [r0, #0]      \n"
        
        // Save r1
        "ldr r1, [sp, #4]      \n"
        "str r1, [r0, #4]      \n"
        
        // Fix: Save r2-r11
        "add r1, sp, #8        \n"
        "add r2, r0, #8        \n"
        "ldmia r1!, {r3-r12}   \n"
        "stmia r2!, {r3-r12}   \n"
        
        // Handle r12 separately
        "ldr r1, [sp, #48]     \n"
        "str r1, [r0, #48]     \n"
        
        // Save other registers
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
        // .ltorg is used to align the code to 4 bytes for load immediates to registers
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
            
            // Print mode name
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
    attr.type = 8;            // PERF_TYPE_HARDWARE
    attr.size = sizeof(attr); // Size of the event attribute structure
    attr.disabled = 1;        // Disable the event initially
    attr.exclude_kernel = 1;  // Exclude kernel events
    attr.exclude_hv = 1;      // Exclude hypervisor events
    attr.pinned = 1;          // Pin the event to a specific CPU
    // attr.exclusive = 1;     // Exclusive event
    
    attr.config = 0x0006;     // Event configuration
    pmu->ld_retired_fd = perf_event_open(&attr, 0, 1, -1, 0);
    if (pmu->ld_retired_fd == -1) {
        printf("LD_RETIRED失败: %s\n", strerror(errno));
        
        // Try to unbind CPU
        pmu->ld_retired_fd = perf_event_open(&attr, 0, -1, -1, 0);
        printf("不绑定CPU的LD_RETIRED: %s (fd=%d)\n", 
               pmu->ld_retired_fd != -1 ? "OK" : "FAIL", pmu->ld_retired_fd);
    }

    attr.config = 0x0007;
    pmu->st_retired_fd = perf_event_open(&attr, 0, 1, -1, 0);
    if (pmu->st_retired_fd == -1) {
        printf("ST_RETIRED失败: %s\n", strerror(errno));
        
        // Try to unbind CPU
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

// Test Load retired only
uint64_t test_load_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.ld_retired_fd <= 0) {
        return 0;
    }

    // Prepare test instruction
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

    // Execute test instruction
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

// Test Store retired only
uint64_t test_store_only(uint8_t *insn_bytes, size_t insn_length)
{
    if (g_pmu.st_retired_fd <= 0) {
        return 0;
    }

    // Prepare test instruction
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    uint64_t result = 0;
    executing_insn = 1;

    // Get function pointer
    void (*exec_page)() = (void(*)()) insn_page;

    // Reset and enable ST counter
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Execute test instruction
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

void test_load_store(uint8_t *insn_bytes, size_t insn_length, TestResult *result)
{
    if (g_pmu.ld_retired_fd <= 0 || g_pmu.st_retired_fd <= 0) {
        result->ld_count = 0;
        result->st_count = 0;
        return;
    }

    // Prepare test instruction
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page, insn_page + insn_test_plate_length);

    executing_insn = 1;

    // Get function pointer
    void (*exec_page)() = (void(*)()) insn_page;

    // Reset and enable ST counter
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_ENABLE, 0);

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Execute test instruction
    exec_page();

    // Memory barrier
    asm volatile("dsb" ::: "memory");

    // Disable ST counter
    ioctl(g_pmu.ld_retired_fd, PERF_EVENT_IOC_DISABLE, 0);
    ioctl(g_pmu.st_retired_fd, PERF_EVENT_IOC_DISABLE, 0);

    executing_insn = 0;
    
    // Read result
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
    
    // Base value: background noise of nop instruction
    uint64_t base_ld = 73; // 17 hardcoded
    uint64_t base_st = 28; // 5 hardcoded
    
    // Calculate the increment relative to the base
    int64_t ld_delta = result->ld_count - base_ld;
    int64_t st_delta = result->st_count - base_st;
    
    printf(" | LD:%llu(%+lld) ST:%llu(%+lld)", 
           result->ld_count, ld_delta, result->st_count, st_delta);
    
    // Determine the instruction type
    if (ld_delta == 0 && st_delta == 0) {
        printf(" -> No memory access");
    } else if (ld_delta == 1 && st_delta == 0) {
        printf(" -> LDR instruction (single load)");
    } else if (ld_delta == 0 && st_delta == 1) {
        printf(" -> STR instruction (single store)");
    } else if (ld_delta == 1 && st_delta == 1) {
        printf(" -> Load + Store instruction");
    } else if (ld_delta == 2 && st_delta == 0) {
        printf(" -> Double load instruction");
    } else if (ld_delta == 0 && st_delta == 2) {
        printf(" -> Double store instruction");
    } else if (ld_delta > 0 && st_delta == 0) {
        printf(" -> Multiple load instructions (%lld times)", ld_delta);
    } else if (ld_delta == 0 && st_delta > 0) {
        printf(" -> Multiple store instructions (%lld times)", st_delta);
    } else if (ld_delta > 0 && st_delta > 0) {
        printf(" -> Compound memory access instruction (LD:%lld, ST:%lld)", ld_delta, st_delta);
    } else {
        printf(" -> Exceptional case (LD:%lld, ST:%lld)", ld_delta, st_delta);
    }
    
    printf("\n");
}

static uint32_t pack_behavior(RegChangeInfo *regs, CpsrChangeInfo *cpsr, TestResult *test){
    uint32_t behavior = 0;

    uint64_t base_ld = 73;
    uint64_t base_st = 28;
    int64_t ld_delta = test->ld_count - base_ld;
    int64_t st_delta = test->st_count - base_st;

    if (ld_delta > 0)     behavior |= 1u << 0;
    if (st_delta > 0)     behavior |= 1u << 1;
    if (regs->changed_regs)     behavior |= 1u << 2;
    if (regs->SP || regs->LR)   behavior |= 1u << 3;

    if (cpsr->changed_mask != 0) {
        switch (cpsr->security_level) {
            case SAFE:          behavior |= 1u << 4; break;
            case SUSPICIOUS:    behavior |= 1u << 5; break;
            case DANGEROUS:     behavior |= 1u << 6; break;
            case CRITICAL:      behavior |= 1u << 7; break;
        }
    }

    // (bit 8-20, 13 bit)
    behavior |= (regs->changed_regs & 0x1FFF)       << 8;   // 13 bit
    // (bit 21-22)
    if (regs->SP) behavior |= 1u << 21;
    if (regs->LR) behavior |= 1u << 22;

    // (bit 23-24)
    behavior |= (cpsr->security_level & 0x3) << 23;

    // (bit 25-28)
    uint32_t signal_type = 0;
    switch (last_insn_signum) {
        case 0:       signal_type = 0; break;
        case SIGILL:  signal_type = 1; break;
        case SIGSEGV: signal_type = 2; break;
        case SIGBUS:  signal_type = 3; break;
        case SIGTRAP: signal_type = 4; break;
        default:      signal_type = 15; break;
    }
    behavior |= (signal_type & 0xF) << 25;

    // bit 29-31 reserved
    return behavior;
}

int main(int argc, const char* argv[]) {
    set_affinity();
    
    int result_fd = open("result.bin", O_CREAT | O_APPEND | O_WRONLY | O_SYNC, 0666);
    if(result_fd < 0) {
        perror("open result bin failed");
        return 1;
    }

    uint32_t test_instructions[] = {
        // === Instructions that do not involve memory access ===
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
        
        // === Single memory access instruction ===
        0xE59D0000,  // ldr r0, [sp]        - 1次load
        0xE59D0004,  // ldr r0, [sp, #4]    - 1次load  
        0xE58D0000,  // str r0, [sp]        - 1次store
        0xE58D0004,  // str r0, [sp, #4]    - 1次store
        
        // === More secure Load instructions (using sp base address) ===
        0xE59D0008,  // ldr r0, [sp, #8]    - load sp+8
        0xE59D000C,  // ldr r0, [sp, #12]   - load sp+12
        0xE59D0010,  // ldr r0, [sp, #16]   - load sp+16
        0xE59D1000,  // ldr r1, [sp]        - load to r1
        0xE59D1004,  // ldr r1, [sp, #4]    - load to r1+offset
        0xE59D2000,  // ldr r2, [sp]        - load to r2
        0xE51D0004,  // ldr r0, [sp, #-4]   - load sp-4 (negative offset)
        0xE51D0008,  // ldr r0, [sp, #-8]   - load sp-8
        
        // === More secure Store instructions (using sp base address) ===
        0xE58D0008,  // str r0, [sp, #8]    - store sp+8
        0xE58D000C,  // str r0, [sp, #12]   - store sp+12
        0xE58D0010,  // str r0, [sp, #16]   - store sp+16
        0xE58D1000,  // str r1, [sp]        - store r1 to stack
        0xE58D1004,  // str r1, [sp, #4]    - store r1+offset
        0xE58D2000,  // str r2, [sp]        - store r2 to stack
        0xE50D0004,  // str r0, [sp, #-4]   - store sp-4 (negative offset)
        0xE50D0008,  // str r0, [sp, #-8]   - store sp-8
        
        // === Byte memory access (using sp base address, more secure) ===
        0xE5DD0000,  // ldrb r0, [sp]       - byte load
        0xE5DD0001,  // ldrb r0, [sp, #1]   - byte load+1
        0xE5DD0002,  // ldrb r0, [sp, #2]   - byte load+2
        0xE5CD0000,  // strb r0, [sp]       - byte store
        0xE5CD0001,  // strb r0, [sp, #1]   - byte store+1
        0xE5CD0002,  // strb r0, [sp, #2]   - byte store+2

        // Add some debug instructions to verify exceptions
        0xE58D0000,  // str r0, [sp]     - Compare: should ST+1
        0xE58D1000,  // str r1, [sp]     - Exception: show ST+2  
        0xE58D2000,  // str r2, [sp]     - Test: is ST+2?

        // Test the effect of register initialization
        0xE3A01000,  // mov r1, #0       - Initialize r1 first
        0xE58D1000,  // str r1, [sp]     - Then test store
        0xE1A08003,  // MOV  r8, r3
        0xE1A09004,  // MOV  r9, r4
        0xE181A00B,  // ORR  r10,r1,r11           (r10 changes, but NZCV is unchanged)
        0xE1A0B006,  // MOV  r11,r6
        0xE1A0C002,  // MOV  r12,r2

        0xE1B00000,  // MOVS r0,r0                (Only change flags, no memory access)
        0xE2926001,  // ADDS r6,r2,#1             (Change r6 and NZCV)
        0xE2537001,  // SUBS r7,r3,#1             (Change r7 and NZCV)
        0xE1B0A004,  // MOVS r10,r4               (Change r10, also refresh NZCV)
        0xE1520003,  // CMP  r2,r3                (only change NZCV, no general register)

        0xE0C34597,  // UMULL r4,r5,r7,r7         (r4,r5 change, NZCV=unchanged)
        0xE0E24597,  // UMLALS r4,r5,r7,r7        (r4,r5 + NZCV)
        0xE0A14692,  // ADC   r4,r1,r2            (change r4 + NZCV, depend on carry)

        // 0xE8BD000F,  // LDMIA sp!,{r0-r3}         (r0-r3,sp change, 4 times load)
        // 0xE92D00F0,  // STMDB sp!,{r4-r7}         (r4-r7,sp change, 4 times store)
        // 0xE8BD10F0,  // LDMIA sp!,{r4-r7,lr}      (r4-r7,lr,sp; 5 times load)
        // 0xE92D400F,  // STMDB sp!,{r0-r3,lr}      (r0-r3,lr,sp; 5 times store)

        0xE10F1000,  // MRS  r1,cpsr              (read CPSR → r1, change r1)
        0xE121F001,  // MSR  cpsr_flg,r1          (write NZCVQP flag; **may trigger SIGILL**)

        // === Interrupt
        0xF10C01C0,  // CPSID i                   (disable IRQ interrupt)
        0xF10C0140,  // CPSID f                   (disable FIQ interrupt) 
        0xF10C01C0,  // CPSID i,f                 (disable IRQ and FIQ)
        0xF10801C0,  // CPSIE i                   (enable IRQ interrupt)
        0xF1080140,  // CPSIE f                   (enable FIQ interrupt)
        0xF10801C0,  // CPSIE i,f                 (enable IRQ and FIQ)
        
        // === Mode switch instruction ===
        0xF1020011,  // CPS #0x11                 (switch to FIQ mode)
        0xF1020012,  // CPS #0x12                 (switch to IRQ mode) 
        0xF1020013,  // CPS #0x13                 (switch to SVC mode)
        0xF1020017,  // CPS #0x17                 (switch to ABT mode)
        0xF102001B,  // CPS #0x1B                 (switch to UND mode)
        0xF102001F,  // CPS #0x1F                 (switch to SYS mode)
        0xF1020010,  // CPS #0x10                 (switch to USR mode)
        
        // === MSR instruction to modify CPSR fields ===
        0xE121F001,  // MSR cpsr_c, r1            (modify CPSR control field, including mode bit)
        0xE128F001,  // MSR cpsr_f, r1            (modify CPSR flag field)
        0xE124F001,  // MSR cpsr_s, r1            (modify CPSR status field)
        0xE122F001,  // MSR cpsr_x, r1            (modify CPSR extension field)
        0xE12FF001,  // MSR cpsr_cxsf, r1         (modify CPSR all fields)
        
        // === Specific interrupt control values ===
        0xE321F0C0,  // MSR cpsr_c, #0xC0         (set IRQ+FIQ disable bit directly)
        0xE321F080,  // MSR cpsr_c, #0x80         (set IRQ disable bit directly)
        0xE321F040,  // MSR cpsr_c, #0x40         (set FIQ disable bit directly)
        0xE321F000,  // MSR cpsr_c, #0x00         (clear IRQ+FIQ disable bit directly)
        
        // === Mode switch combination ===
        0xE321F0D3,  // MSR cpsr_c, #0xD3         (SVC mode + IRQ+FIQ disable)
        0xE321F0D1,  // MSR cpsr_c, #0xD1         (FIQ mode + IRQ+FIQ disable)
        0xE321F0D2,  // MSR cpsr_c, #0xD2         (IRQ mode + IRQ+FIQ disable)
        0xE321F05F,  // MSR cpsr_c, #0x5F         (SYS mode + IRQ+FIQ enable)
    

        0xf3f57010,  // VSHR.U32 D23, D0, #11  
        0xf2000110,  // VMOV.I32 D0, #0        (NEON immediate load)
        0xf3f57010,  // VSHR.U32 D23, D0, #11  
        0xf2200110,  // VADD.I32 D0, D0, D0    (NEON addition)
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

    if(init_insn_page() != 0) {
        printf("init_insn_page failed\n");
        return 1;
    }

    if(init_memory_monitor(&g_pmu) != 0) {
        printf("PMU initial failed!\n");
    }

    uint8_t nop_bytes[4] = {0x00, 0x00, 0xA0, 0xE1}; // nop 指令
    TestResult warmup_result;
    for(int i = 0; i < 5; i++) {
        test_load_store(nop_bytes, 4, &warmup_result);
    }

    int total_tests = sizeof(test_instructions) / sizeof(test_instructions[0]);
    for(int i = 0 ; i < total_tests ; i++) {
        uint32_t hidden_instruction = test_instructions[i];
        uint8_t insn_bytes[4];

        // printf("=== ARM隐藏指令PMU精确分析 ===\n");
        // printf("测试指令: 0x%08X\n", hidden_instruction);

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

        // printf("===================================\n");
        // print_report(&regs_info, &cpsr_info, regs_before, regs_after);
        // print_test_result(hidden_instruction, &result);
        // printf("===================================\n");
        // printf("\n");

        InstrBehavior ib = {
            .opcode = hidden_instruction,
            .behavior = pack_behavior(&regs_info, &cpsr_info, &result)
        };

        if(write(result_fd, &ib, sizeof(ib)) != sizeof(ib)) {
            perror("write result bin");
        }    
    }
    if (g_pmu.ld_retired_fd > 0) close(g_pmu.ld_retired_fd);
    if (g_pmu.st_retired_fd > 0) close(g_pmu.st_retired_fd);
    if (insn_page != MAP_FAILED) {
        munmap(insn_page, 4096);
    }
    close(result_fd);
    return 0;
}