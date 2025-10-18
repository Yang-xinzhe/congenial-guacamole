#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/mman.h> 
#include <string.h>
typedef __attribute__((aligned(4))) struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;
    uint32_t cpsr;
} RegisterStates;

void* insn_page;
extern char insn_test_plate_begin, insn_test_plate_end, insn_location;
uint32_t insn_offset;
extern char insn_test_plate_begin, insn_test_plate_end, insn_location;
uint32_t insn_test_plate_length;

void test_instruction(void) __attribute__((optimize("O0")));

void test_instruction(void)
{
    asm volatile(
        ".global insn_test_plate_begin \n"
        "insn_test_plate_begin:\n"

        "mov r0, #0x55 \n"
        "orr r0, r0, r0, lsl #8 \n"   // r0 = 0x5555
        "orr r0, r0, r0, lsl #16 \n"  // r0 = 0x55555555
        "mov r1, r0 \n"
        "mov r2, r0 \n"
        "mov r3, r0 \n"
        "mov r4, r0 \n"
        "mov r5, r0 \n"
        "mov r6, r0 \n"
        "mov r7, r0 \n"
        "mov r8, r0 \n"
        "mov r9, r0 \n"
        "mov r10, r0 \n"
        "mov r12, r0 \n"

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

        ".global insn_test_plate_end \n"
        "insn_test_plate_end: \n"
        :
        :
        : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "lr", "memory", "cc");
}

int init_insn_page(void) {
    insn_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(insn_page == MAP_FAILED) {
        perror("insn_mmap failed");
        return 1;
    }

    insn_test_plate_length = (&insn_test_plate_end - &insn_test_plate_begin);
    printf("Debug: template length = %d bytes\n", insn_test_plate_length);
    memcpy(insn_page, &insn_test_plate_begin, insn_test_plate_length);

    // printf("\nCopied instructions in insn_page:\n");
    // uint32_t *dest = (uint32_t*)insn_page;
    // for(int i = 0; i < insn_test_plate_length/4; i++) {
    //     printf("%03d: 0x%08x\n", i, dest[i]);
    // }

    insn_offset = (&insn_location - &insn_test_plate_begin) / 4;
    // printf("insn_offset = %d\n", insn_offset);
    return 0;
}

void execute_insn_page(uint8_t *insn_bytes, size_t insn_length)
{
    // Jumps to the instruction buffer
    void (*exec_page)() = (void(*)()) insn_page;
    // Update the first instruction in the instruction buffer
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);
    exec_page();
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

int main(int argc, const char* argv[]) {
    uint32_t hidden_instruction = 0xE3A03055;
    uint8_t insn_bytes[4];


    if(init_insn_page() != 0) {
        printf("init_insn_page failed\n");
        return 1;
    }

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

    size_t buf_length = fill_insn_buffer(insn_bytes,sizeof(insn_bytes), hidden_instruction);
    execute_insn_page(insn_bytes, buf_length);
    // test_instruction();

    // 从共享内存读取寄存器状态并打印
    RegisterStates *regs = (RegisterStates *)res;

    // 打印所有寄存器值
    printf("========== 寄存器状态 ==========\n");
    printf("通用寄存器:\n");
    printf("R0: 0x%08x    R1: 0x%08x    R2: 0x%08x    R3: 0x%08x\n", 
           regs->r0, regs->r1, regs->r2, regs->r3);
    printf("R4: 0x%08x    R5: 0x%08x    R6: 0x%08x    R7: 0x%08x\n", 
           regs->r4, regs->r5, regs->r6, regs->r7);
    printf("R8: 0x%08x    R9: 0x%08x    R10: 0x%08x   R11: 0x%08x\n", 
           regs->r8, regs->r9, regs->r10, regs->r11);
    printf("R12: 0x%08x\n", regs->r12);

    printf("\n特殊寄存器:\n");
    printf("SP: 0x%08x    LR: 0x%08x    PC: 0x%08x\n", 
           regs->sp, regs->lr, regs->pc);
    printf("CPSR: 0x%08x\n", regs->cpsr);

    // 分析CPSR的条件位
    uint32_t cpsr = regs->cpsr;
    printf("\nCPSR条件标志位:\n");
    printf("N=%d Z=%d C=%d V=%d (0x%01x)\n", 
           (cpsr >> 31) & 1,  // N位 - 负数标志
           (cpsr >> 30) & 1,  // Z位 - 零标志
           (cpsr >> 29) & 1,  // C位 - 进位标志
           (cpsr >> 28) & 1,  // V位 - 溢出标志
           (cpsr >> 28) & 0xF); // 所有条件位

    // 分析CPSR模式位
    printf("模式: ");
    uint32_t mode = cpsr & 0x1F;
    switch(mode) {
        case 0x10: printf("用户模式 (USR)"); break;
        case 0x11: printf("快速中断模式 (FIQ)"); break;
        case 0x12: printf("中断模式 (IRQ)"); break;
        case 0x13: printf("管理模式 (SVC)"); break;
        case 0x17: printf("中止模式 (ABT)"); break;
        case 0x1B: printf("未定义模式 (UND)"); break;
        case 0x1F: printf("系统模式 (SYS)"); break;
        default: printf("未知模式 (0x%02x)", mode);
    }
    printf("\n");

    // 中断状态
    printf("中断状态: I=%d F=%d (IRQ %s, FIQ %s)\n",
           (cpsr >> 7) & 1,   // I位 - IRQ禁用位
           (cpsr >> 6) & 1,   // F位 - FIQ禁用位
           ((cpsr >> 7) & 1) ? "禁用" : "启用",
           ((cpsr >> 6) & 1) ? "禁用" : "启用");

    RegisterStates *regs_after = (RegisterStates *)res + 1;

    printf("========== 寄存器状态 ==========\n");
    printf("通用寄存器:\n");
    printf("R0: 0x%08x    R1: 0x%08x    R2: 0x%08x    R3: 0x%08x\n", 
           regs_after->r0, regs_after->r1, regs_after->r2, regs_after->r3);
    printf("R4: 0x%08x    R5: 0x%08x    R6: 0x%08x    R7: 0x%08x\n", 
           regs_after->r4, regs_after->r5, regs_after->r6, regs_after->r7);
    printf("R8: 0x%08x    R9: 0x%08x    R10: 0x%08x   R11: 0x%08x\n", 
           regs_after->r8, regs_after->r9, regs_after->r10, regs_after->r11);
    printf("R12: 0x%08x\n", regs_after->r12);

    printf("\n特殊寄存器:\n");
    printf("SP: 0x%08x    LR: 0x%08x    PC: 0x%08x\n", 
           regs_after->sp, regs_after->lr, regs_after->pc);
    printf("CPSR: 0x%08x\n", regs_after->cpsr);

    // 分析CPSR的条件位
    cpsr = regs_after->cpsr;
    printf("\nCPSR条件标志位:\n");
    printf("N=%d Z=%d C=%d V=%d (0x%01x)\n", 
           (cpsr >> 31) & 1,  // N位 - 负数标志
           (cpsr >> 30) & 1,  // Z位 - 零标志
           (cpsr >> 29) & 1,  // C位 - 进位标志
           (cpsr >> 28) & 1,  // V位 - 溢出标志
           (cpsr >> 28) & 0xF); // 所有条件位

    // 分析CPSR模式位
    printf("模式: ");
    mode = cpsr & 0x1F;
    switch(mode) {
        case 0x10: printf("用户模式 (USR)"); break;
        case 0x11: printf("快速中断模式 (FIQ)"); break;
        case 0x12: printf("中断模式 (IRQ)"); break;
        case 0x13: printf("管理模式 (SVC)"); break;
        case 0x17: printf("中止模式 (ABT)"); break;
        case 0x1B: printf("未定义模式 (UND)"); break;
        case 0x1F: printf("系统模式 (SYS)"); break;
        default: printf("未知模式 (0x%02x)", mode);
    }
    printf("\n");

    // 中断状态
    printf("中断状态: I=%d F=%d (IRQ %s, FIQ %s)\n",
           (cpsr >> 7) & 1,   // I位 - IRQ禁用位
           (cpsr >> 6) & 1,   // F位 - FIQ禁用位
           ((cpsr >> 7) & 1) ? "禁用" : "启用",
           ((cpsr >> 6) & 1) ? "禁用" : "启用");



    return 0;
}