#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <assert.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <elf.h>
#include <stdint.h>
#include <stdint.h>
#include <stdbool.h>

#define PAGE_SIZE 4096
#define MY_SIGSTKSZ 8192

void *insn_page;
volatile sig_atomic_t last_insn_signum = 0;
volatile sig_atomic_t executing_insn = 0;
uint32_t insn_offset = 0;


static uint8_t sig_stack_array[MY_SIGSTKSZ];
stack_t sig_stack = {
    .ss_size = MY_SIGSTKSZ,
    .ss_sp = sig_stack_array,
};

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int);
void execution_boilerplate(void);
int init_insn_page(void);
void execute_insn_page(uint8_t*, size_t);
size_t fill_insn_buffer(uint8_t*, size_t, uint32_t);
uint32_t insn_test_plate_length;
uint32_t pc_value = 0;
uint32_t pc_after = 0;

extern char insn_test_plate_begin, insn_test_plate_end, insn_location;

void test_instruction(void) __attribute__((optimize("O0")));

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
        :::"memory", "cc");
}

void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    last_insn_signum = sig_num;


    if (executing_insn == 0) {
        // Something other than a hidden insn execution raised the signal,
        // so quit
        fprintf(stderr, "%s\n", strsignal(sig_num));
        exit(1);
    }

    // Jump to the next instruction (i.e. skip the illegal insn)
    // uintptr_t insn_skip = (uintptr_t)(insn_page) + (insn_offset+1)*4;

    // //aarch32
    // uc->uc_mcontext.arm_pc = insn_skip;
    printf("PC before = 0x%08x\n", pc_value);
    printf("Next PC = 0x%08lx\n", uc->uc_mcontext.arm_pc);
    _Exit(0);
}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int signum)
{
    sigaltstack(&sig_stack, NULL);

    struct sigaction s = {
        .sa_sigaction = handler,
        .sa_flags = SA_SIGINFO | SA_ONSTACK,
    };

    sigfillset(&s.sa_mask);

    sigaction(signum,  &s, NULL);
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
    executing_insn = 1;
    last_insn_signum = 0;

    

    // Jumps to the instruction buffer
    void (*exec_page)() = (void(*)()) insn_page;
    // Update the first instruction in the instruction buffer
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);

    // asm volatile(
    //     "str pc, %0"
    //     : "=m"(pc_value)
    //     :
    //     : "memory"
    // );

    asm volatile(
        "str pc, %0         \n"    // 保存执行前PC
        "blx %2             \n"    // 调用测试页面
        "str pc, %1         \n"    // 保存执行后PC
        : "=m"(pc_value), "=m"(pc_after)
        : "r"(insn_page)
        : "lr", "memory"
    );

    // exec_page();

    executing_insn = 0;
    printf("PC before = 0x%08x\n", pc_value);
    printf("PC after = 0x%08x\n", pc_after);
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

int main(int argc, const char *argv[]){
    // uint32_t hidden_instruction = 0xE1C000B0;
    uint32_t hidden_instruction = 0xE1A00000;
    uint8_t insn_bytes[4];

    if(init_insn_page() != 0) {
        printf("init_insn_page failed\n");
        return 1;
    }

    init_signal_handler(signal_handler, SIGILL);
    init_signal_handler(signal_handler, SIGSEGV);
    init_signal_handler(signal_handler, SIGTRAP);
    init_signal_handler(signal_handler, SIGBUS);

    size_t buf_length = fill_insn_buffer(insn_bytes,sizeof(insn_bytes), hidden_instruction);
    execute_insn_page(insn_bytes, buf_length);

    return 0;
}