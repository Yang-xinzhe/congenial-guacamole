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


#define SIGSEGV_THRESHOLD 10
#define BITMAP_MODE_FILE 1 // Store by file number
#define BITMAP_MODE_RANGE 2 // Store by interval
#define MAX_RANGES 500000 // 最大区间数量

#define PAGE_SIZE 4096
#define MY_SIGSTKSZ 8192
void *insn_page;
volatile sig_atomic_t last_insn_signum = 0;
volatile sig_atomic_t executing_insn = 0;
uint32_t insn_offset = 0;
uint32_t mask = 0x1111;

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
uint64_t get_nano_timestamp(void);

extern char boilerplate_start, boilerplate_end, insn_location;

uint8_t * result_bitmap = NULL;
uint32_t bitmap_size = 0;
uint32_t range_start = 0;
uint32_t range_end = 0;
int file_number = -1;

uint32_t hidden_insn;
uint32_t cnt = 0;
uint32_t sigsegv_cnt = 0;
uint32_t sigill_cnt = 0;
uint32_t sigtrap_cnt = 0;
uint32_t sigbus_cnt = 0;
uint32_t no_signal = 0;
uint32_t instructions_checked = 0; // total udf insns
struct Range {
    uint32_t start;
    uint32_t end;
};

int init_bitmap(uint32_t start, uint32_t end) {
    range_start= start;
    range_end = end;

    uint32_t bits_needed = end - start;
    bitmap_size = (bits_needed + 7) / 8; // round up to bytes

    // allocate
    result_bitmap = (uint8_t *)calloc(bitmap_size, 1);
    if(!result_bitmap) {
        perror("calloc result bitmap failed");
        return 1;
    }

    char *file_num_env = getenv("RESULT_FILE_NUMBER"); // passed by argv
    if(file_num_env != NULL) {
        file_number = atoi(file_num_env);
    }

    return 0;
}

void mark_executable(uint32_t insn) {
    //offset
    uint32_t offset = insn - range_start;

    if(offset >= (bitmap_size * 8)) {
        return ; // exceed bit map range
    }

    uint32_t byte_index = offset / 8;
    uint8_t bit_position = offset % 8;

    result_bitmap[byte_index] |= (1 << bit_position);
}

// 保存单个区间的bitmap到文件（追加模式）
void save_range_bitmap_to_file(FILE *output_file) {
    if(!result_bitmap || !output_file) return;

    // 写入区间信息和bitmap数据
    fwrite(&range_start, sizeof(uint32_t), 1, output_file);   // 区间起始
    fwrite(&range_end, sizeof(uint32_t), 1, output_file);     // 区间结束
    fwrite(&bitmap_size, sizeof(uint32_t), 1, output_file);   // bitmap大小
    fwrite(result_bitmap, 1, bitmap_size, output_file);       // bitmap数据

    if (result_bitmap) {
        free(result_bitmap);
        result_bitmap = NULL;
    }
}

// 保存整个文件的bitmap结果
void save_complete_file_results(int total_ranges) {
    mkdir("bitmap_results", 0755);

    char filename[256];
    snprintf(filename, sizeof(filename), "bitmap_results/res%d_complete.bin", file_number);

    FILE *f = fopen(filename, "rb+");
    if(f) {
        // 文件已存在，更新区间数量
        fseek(f, sizeof(int), SEEK_SET);
        fwrite(&total_ranges, sizeof(int), 1, f);
        fclose(f);
    }
    
    printf("完成文件 res%d.txt 处理，共保存 %d 个区间的bitmap结果到 %s\n", 
           file_number, total_ranges, filename);
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
    uintptr_t insn_skip = (uintptr_t)(insn_page) + (insn_offset+1)*4;

    //aarch32
    uc->uc_mcontext.arm_pc = insn_skip;

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


void execution_boilerplate(void)
{
        asm volatile(
            ".global boilerplate_start  \n"
            "boilerplate_start:         \n"

            // Store all gregs
            "push {r0-r12, lr}          \n"

            /*
             * It's better to use ptrace in cases where the sp might
             * be corrupted, but storing the sp in a vector reg
             * mitigates the issue somewhat.
             */
            "vmov s0, sp                \n"

            // Reset the regs to make insn execution deterministic
            // and avoid program corruption
            "mov r0, %[reg_init]        \n"
            "mov r1, %[reg_init]        \n"
            "mov r2, %[reg_init]        \n"
            "mov r3, %[reg_init]        \n"
            "mov r4, %[reg_init]        \n"
            "mov r5, %[reg_init]        \n"
            "mov r6, %[reg_init]        \n"
            "mov r7, %[reg_init]        \n"
            "mov r8, %[reg_init]        \n"
            "mov r9, %[reg_init]        \n"
            "mov r10, %[reg_init]       \n"
            "mov r11, %[reg_init]       \n"
            "mov r12, %[reg_init]       \n"
            "mov lr, %[reg_init]        \n"
            "mov sp, %[reg_init]        \n"

            // Note: this msr insn must be directly above the nop
            // because of the -c option (excluding the label ofc)
           "msr cpsr_f, #0             \n"

            ".global insn_location      \n"
            "insn_location:             \n"

            // This instruction will be replaced with the one to be tested
            "nop                        \n"

            "vmov sp, s0                \n"

            // Restore all gregs
            "pop {r0-r12, lr}           \n"

            "bx lr                      \n"
            ".global boilerplate_end    \n"
            "boilerplate_end:           \n"
            :
            : [reg_init] "n" (0)
            );

}

int init_insn_page(void)
{
    // Allocate an executable page / memory region
    insn_page = mmap(NULL,
                       PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (insn_page == MAP_FAILED)
        return 1;

    uint32_t boilerplate_length = (&boilerplate_end - &boilerplate_start) / 4;

    // Load the boilerplate assembly
    uint32_t i;
    for ( i = 0; i < boilerplate_length; ++i)
        ((uint32_t*)insn_page)[i] = ((uint32_t*)&boilerplate_start)[i];

    insn_offset = (&insn_location - &boilerplate_start) / 4;

    return 0;
}

void execute_insn_page(uint8_t *insn_bytes, size_t insn_length)
{
    // Jumps to the instruction buffer
    void (*exec_page)() = (void(*)()) insn_page;

    

    // Update the first instruction in the instruction buffer
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);

    last_insn_signum = 0;

    /*
     * Clear insn_page (at the insn to be tested + the msr insn before)
     * in the d- and icache
     * (some instructions might be skipped otherwise.)
     */
    __clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);

    executing_insn = 1;

    // Jump to the instruction to be tested (and execute it)
    exec_page();

    executing_insn = 0;

    
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

uint64_t get_nano_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

int main(int argc, char* argv[]){
    
    if(argc < 3) {
        fprintf(stderr, "用法: %s <file_number> <instruction>\n", argv[0]);
        return 1;
    }

    // 解析命令行参数
    int target_file_num = atoi(argv[1]);
    uint32_t test_insn = (uint32_t)strtoul(argv[2], NULL, 0);
    
    // 初始化信号处理器
    init_signal_handler(signal_handler, SIGILL);
    init_signal_handler(signal_handler, SIGSEGV);
    init_signal_handler(signal_handler, SIGTRAP);
    init_signal_handler(signal_handler, SIGBUS);

    if (init_insn_page() != 0) {
        perror("insn_page mmap failed");
        return 1;
    }

    // 测试单条指令
    hidden_insn = test_insn;
    uint8_t insn_bytes[4];
    size_t buf_length = fill_insn_buffer(insn_bytes, sizeof(insn_bytes), hidden_insn);
    
    execute_insn_page(insn_bytes, buf_length);
    
    munmap(insn_page, PAGE_SIZE);
    
    // 返回状态码：0=可执行，1=SIGILL，2=SIGSEGV，3=其他信号
    if (last_insn_signum == 0) {
        return 0;  // 可执行
    } else if (last_insn_signum == SIGILL) {
        return 1;  // SIGILL
    } else if (last_insn_signum == SIGSEGV) {
        return 2;  // SIGSEGV
    } else {
        return 3;  // 其他信号
    }
}

