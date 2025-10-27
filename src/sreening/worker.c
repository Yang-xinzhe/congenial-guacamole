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
#include <sys/time.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <pthread.h>


#define SIGSEGV_THRESHOLD 10
#define BITMAP_MODE_FILE 1 // Store by file number
#define BITMAP_MODE_RANGE 2 // Store by interval
#define MAX_RANGES 500000 // 最大区间数量

#define PAGE_SIZE 4096
#define MY_SIGSTKSZ 8192
static void *insn_region = NULL;  // 3页区域基址： [guard][code][guard]
void *insn_page;
volatile sig_atomic_t last_insn_signum = 0;
volatile sig_atomic_t executing_insn = 0;
volatile sig_atomic_t timeout_occurred = 0;
uint32_t insn_offset = 0;
uint32_t mask = 0x1111;

// 新增：逃生点和精准定时器
static sigjmp_buf escape_env;
static timer_t watchdog_timer;

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
uint8_t * timeout_bitmap = NULL;  // 超时bitmap
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
uint32_t sigalrm_cnt = 0;  // 超时计数
uint32_t no_signal = 0;
uint32_t instructions_checked = 0; // total udf insns

struct Range {
    uint32_t start;
    uint32_t end;
};

// 获取线程ID（用于 SIGEV_THREAD_ID）
static pid_t gettid_wrapper(void) {
    return syscall(SYS_gettid);
}

// 初始化精准定时器（timer_create + SIGEV_THREAD_ID）
int init_watchdog_timer(void) {
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGRTMIN;  // 使用实时信号
    sev._sigev_un._tid = gettid_wrapper();  // 指定线程ID（某些系统用这个字段名）
    
    if (timer_create(CLOCK_MONOTONIC, &sev, &watchdog_timer) != 0) {
        perror("timer_create failed");
        return -1;
    }
    return 0;
}

// 启动看门狗（微秒级超时）
static inline void arm_watchdog_us(int us) {
    struct itimerspec its = {
        .it_value.tv_sec = 0,
        .it_value.tv_nsec = us * 1000,
        .it_interval = {0, 0}  // 不重复
    };
    timer_settime(watchdog_timer, 0, &its, NULL);
}

// 停止看门狗
static inline void disarm_watchdog(void) {
    struct itimerspec its = {{0, 0}, {0, 0}};
    timer_settime(watchdog_timer, 0, &its, NULL);
}

int init_bitmap(uint32_t start, uint32_t end) {
    range_start= start;
    range_end = end;

    uint32_t bits_needed = end - start;
    bitmap_size = (bits_needed + 7) / 8; // round up to bytes

    // allocate result_bitmap
    result_bitmap = (uint8_t *)calloc(bitmap_size, 1);
    if(!result_bitmap) {
        perror("calloc result bitmap failed");
        return 1;
    }

    // allocate timeout_bitmap
    timeout_bitmap = (uint8_t *)calloc(bitmap_size, 1);
    if(!timeout_bitmap) {
        perror("calloc timeout bitmap failed");
        free(result_bitmap);
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

void mark_timeout(uint32_t insn) {
    //offset
    uint32_t offset = insn - range_start;

    if(offset >= (bitmap_size * 8)) {
        return ; // exceed bit map range
    }

    uint32_t byte_index = offset / 8;
    uint8_t bit_position = offset % 8;

    timeout_bitmap[byte_index] |= (1 << bit_position);
}

// 检查bitmap是否有任何非零位
int bitmap_has_data(uint8_t *bitmap, uint32_t size) {
    for(uint32_t i = 0; i < size; i++) {
        if(bitmap[i] != 0) {
            return 1;
        }
    }
    return 0;
}

// 保存单个区间的bitmap到文件（追加模式）
// 返回1表示写入了timeout数据，0表示没有写入
int save_range_bitmap_to_file(FILE *output_file, FILE *timeout_file) {
    if(!result_bitmap || !output_file) return 0;

    // 写入区间信息和bitmap数据到result文件
    fwrite(&range_start, sizeof(uint32_t), 1, output_file);   // 区间起始
    fwrite(&range_end, sizeof(uint32_t), 1, output_file);     // 区间结束
    fwrite(&bitmap_size, sizeof(uint32_t), 1, output_file);   // bitmap大小
    fwrite(result_bitmap, 1, bitmap_size, output_file);       // bitmap数据

    int timeout_written = 0;
    // 只在timeout_bitmap有数据时才写入
    if(timeout_bitmap && timeout_file && bitmap_has_data(timeout_bitmap, bitmap_size)) {
        fwrite(&range_start, sizeof(uint32_t), 1, timeout_file);
        fwrite(&range_end, sizeof(uint32_t), 1, timeout_file);
        fwrite(&bitmap_size, sizeof(uint32_t), 1, timeout_file);
        fwrite(timeout_bitmap, 1, bitmap_size, timeout_file);
        timeout_written = 1;
    }

    if (result_bitmap) {
        free(result_bitmap);
        result_bitmap = NULL;
    }
    if (timeout_bitmap) {
        free(timeout_bitmap);
        timeout_bitmap = NULL;
    }
    
    return timeout_written;
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


// 超时信号专用 handler（只做 longjmp，不改 PC）
void timeout_signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr) {
    (void)sig_num;
    (void)sig_info;
    (void)uc_ptr;
    
    timeout_occurred = 1;
    
    // 直接跳回安全点，不依赖 ucontext
    if (executing_insn) {
        siglongjmp(escape_env, 1);
    }
}

// 普通信号 handler（SIGILL/SIGSEGV/SIGBUS/SIGTRAP）
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

    // ARM32架构下才设置PC（避免编译错误）
#if defined(__arm__)
    uc->uc_mcontext.arm_pc = insn_skip;
#else
    (void)uc;  // 避免未使用警告
    // 非ARM平台用 siglongjmp 作为备用
    siglongjmp(escape_env, sig_num);
#endif
}

// 初始化超时信号 handler（专门配置，不同于普通信号）
void init_timeout_signal_handler(void (*handler)(int, siginfo_t*, void*), int signum) {
    sigaltstack(&sig_stack, NULL);
    
    struct sigaction s = {
        .sa_sigaction = handler,
        .sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER,  // 注意：去掉SA_RESTART，加上SA_NODEFER
    };
    
    sigemptyset(&s.sa_mask);  // 不屏蔽其他信号
    sigaction(signum, &s, NULL);
}

// 初始化普通信号 handler（保留原有逻辑）
void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int signum)
{
    sigaltstack(&sig_stack, NULL);

    struct sigaction s = {
        .sa_sigaction = handler,
        .sa_flags = SA_SIGINFO | SA_ONSTACK,  // 去掉 SA_RESTART
    };

    sigemptyset(&s.sa_mask);  // 改为不填满，避免屏蔽超时信号

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
    // 申请3页：左右为guard page (PROT_NONE)，中间为指令页
    insn_region = mmap(NULL,
                       PAGE_SIZE * 3,
                       PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (insn_region == MAP_FAILED)
        return 1;

    // 中间页作为真正的指令页
    insn_page = (uint8_t*)insn_region + PAGE_SIZE;

    // 临时设为 RWX 以便写入样板代码
    if (mprotect(insn_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        munmap(insn_region, PAGE_SIZE * 3);
        return 1;
    }

    uint32_t boilerplate_length = (&boilerplate_end - &boilerplate_start) / 4;

    // Load the boilerplate assembly
    uint32_t i;
    for ( i = 0; i < boilerplate_length; ++i)
        ((uint32_t*)insn_page)[i] = ((uint32_t*)&boilerplate_start)[i];

    insn_offset = (&insn_location - &boilerplate_start) / 4;

    // 写入完成后立刻切回 RX（只读可执行）
    if (mprotect(insn_page, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        munmap(insn_region, PAGE_SIZE * 3);
        return 1;
    }

    return 0;
}

// 执行指令页（核心改进：使用 sigsetjmp/siglongjmp + RX权限保护）
void execute_insn_page(uint8_t *insn_bytes, size_t insn_length)
{
    void (*exec_page)() = (void(*)()) insn_page;
    
    // 为写入指令临时开放写权限（RWX）
    if (mprotect(insn_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect RWX failed");
        return;
    }
    
    // 更新指令缓冲区
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    
    last_insn_signum = 0;
    timeout_occurred = 0;
    
    // 清除 i-cache 和 d-cache
    __clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);
    
    // 执行前立刻切回 RX（只读可执行），禁止自写或向 PC 附近写
    if (mprotect(insn_page, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect RX failed");
        return;
    }
    
    executing_insn = 1;
    
    // ========== 关键改进：设置逃生点 ==========
    if (sigsetjmp(escape_env, 1) == 0) {
        // 第一次执行：启动看门狗并执行指令
        arm_watchdog_us(200);  // 200微秒超时
        
        exec_page();  // 执行指令（若跑出页或写PC附近会SIGSEGV）
        
        // 正常返回
        disarm_watchdog();
    } else {
        // 从 siglongjmp 跳回（超时或其他信号）
        disarm_watchdog();
        
        // 如果是超时导致的
        if (timeout_occurred) {
            last_insn_signum = SIGALRM;  // 统一标记为超时
        }
        // 否则 last_insn_signum 已被普通 signal_handler 设置
    }
    
    executing_insn = 0;
    
    // 恢复为 RWX，方便下一条指令写入（可选优化：也可保持RX，下次写入时再开）
    if (mprotect(insn_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect restore RWX failed");
    }
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
    
    if(argc < 2) {
        fprintf(stderr, "用法: %s <file_number>\n", argv[0]);
        fprintf(stderr, "例如: %s 1  # 处理 results_A32/res1.txt\n", argv[0]);
        return 1;
    }

    // 直接读取文件模式
    int target_file_num = atoi(argv[1]);
    file_number = target_file_num;
    
    char file_num_env[32];
    snprintf(file_num_env, sizeof(file_num_env), "%d", file_number);
    setenv("RESULT_FILE_NUMBER", file_num_env, 1);
    
    time_t start_time = time(NULL);
    
    printf("[res%d] 处理文件: res%d.txt\n", file_number, target_file_num);
    
    // ========== 确保信号未被屏蔽 ==========
    sigset_t empty_set;
    sigemptyset(&empty_set);
    pthread_sigmask(SIG_SETMASK, &empty_set, NULL);
    
    // ========== 初始化信号处理器 ==========
    // 1. 普通异常信号（SIGILL/SIGSEGV/SIGBUS/SIGTRAP）
    init_signal_handler(signal_handler, SIGILL);
    init_signal_handler(signal_handler, SIGSEGV);
    init_signal_handler(signal_handler, SIGTRAP);
    init_signal_handler(signal_handler, SIGBUS);
    
    // 2. 超时信号（专用handler，使用实时信号）
    init_timeout_signal_handler(timeout_signal_handler, SIGRTMIN);
    
    // 3. 备用：SIGVTALRM（针对用户态忙等）
    init_timeout_signal_handler(timeout_signal_handler, SIGVTALRM);
    
    // ========== 初始化精准定时器 ==========
    if (init_watchdog_timer() != 0) {
        fprintf(stderr, "Failed to initialize watchdog timer\n");
        return 1;
    }

    if (init_insn_page() != 0) {
        perror("insn_page mmap failed");
        timer_delete(watchdog_timer);
        return 1;
    }

    // 读取res文件
    char input_filename[256];
    snprintf(input_filename, sizeof(input_filename), "results_A32/res%d.txt", target_file_num);
    
    FILE *res_file = fopen(input_filename, "r");
    if(!res_file) {
        fprintf(stderr, "无法打开文件 %s: %s\n", input_filename, strerror(errno));
        munmap(insn_region, PAGE_SIZE * 3);
        return 1;
    }
    
    // 读取所有区间
    struct Range ranges[MAX_RANGES];
    int range_count = 0;
    char line[256];
    
    while(fgets(line, sizeof(line), res_file) != NULL && range_count < MAX_RANGES) {
        uint32_t range_start, range_end;
        if(sscanf(line, "[%u, %u]", &range_start, &range_end) == 2) {
            ranges[range_count].start = range_start;
            ranges[range_count].end = range_end;
            range_count++;
        }
    }
    fclose(res_file);
    
    printf("[res%d] 从 %s 读取到 %d 个区间\n", file_number, input_filename, range_count);
    
    if(range_count == 0) {
        printf("[res%d] 文件中没有找到有效区间\n", file_number);
        munmap(insn_region, PAGE_SIZE * 3);
        return 0;
    }
    
    // 创建输出文件并写入文件头
    mkdir("bitmap_results", 0755);
    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "bitmap_results/res%d_complete.bin", file_number);
    
    FILE *output_file = fopen(output_filename, "wb");
    if(!output_file) {
        fprintf(stderr, "无法创建输出文件 %s\n", output_filename);
        munmap(insn_region, PAGE_SIZE * 3);
        return 1;
    }
    
    // 创建timeout_bitmap输出文件
    char timeout_filename[256];
    snprintf(timeout_filename, sizeof(timeout_filename), "bitmap_results/res%d_timeout.bin", file_number);
    
    FILE *timeout_file = fopen(timeout_filename, "wb");
    if(!timeout_file) {
        fprintf(stderr, "无法创建超时输出文件 %s\n", timeout_filename);
        fclose(output_file);
        munmap(insn_region, PAGE_SIZE * 3);
        return 1;
    }
    
    // 写入文件头：文件编号和区间数量（timeout_count稍后更新）
    fwrite(&file_number, sizeof(int), 1, output_file);
    fwrite(&range_count, sizeof(int), 1, output_file);
    fwrite(&file_number, sizeof(int), 1, timeout_file);
    int timeout_range_count = 0; // 实际写入的timeout区间数
    fwrite(&timeout_range_count, sizeof(int), 1, timeout_file); // 先写0，稍后更新
    
    // 计算总指令数用于总进度计算
    uint64_t total_insns = 0;
    for(int r = 0; r < range_count; r++) {
        total_insns += (ranges[r].end - ranges[r].start);
    }
    
    // 处理每个区间
    for(int r = 0; r < range_count; r++) {
        uint32_t range_start = ranges[r].start;
        uint32_t range_end = ranges[r].end;
        
        // 为每个区间初始化bitmap
        if (init_bitmap(range_start, range_end) != 0) {
            fprintf(stderr, "\n[res%d] init bitmap failed for range [%u, %u]\n", 
                    file_number, range_start, range_end);
            continue;
        }
        
        // 处理区间中的每条指令
        for (uint32_t i = range_start; i < range_end; i++) {
            hidden_insn = i;
            cnt++;

            uint8_t insn_bytes[4];
            size_t buf_length = fill_insn_buffer(insn_bytes, sizeof(insn_bytes), hidden_insn);
            
            execute_insn_page(insn_bytes, buf_length);

            if (last_insn_signum == SIGILL) {
                sigill_cnt++;
            } else if (last_insn_signum == SIGSEGV) {
                sigsegv_cnt++;
            } else if (last_insn_signum == SIGBUS) {
                sigbus_cnt++;
            } else if (last_insn_signum == SIGTRAP) {
                sigtrap_cnt++;
            } else if (last_insn_signum == SIGALRM || last_insn_signum == SIGPROF) {
                sigalrm_cnt++;
                mark_timeout(hidden_insn);  // 标记到timeout_bitmap
            } else{
                no_signal++;
                mark_executable(hidden_insn); 
            }
            instructions_checked++;
            
            // 每处理1000条指令更新一次进度（避免刷新过于频繁）
            if (instructions_checked % 1000 == 0 || i == range_end - 1) {
                float overall_progress = (float)instructions_checked / total_insns * 100.0;
                float range_progress = (float)(i - range_start + 1) / (range_end - range_start) * 100.0;
                int elapsed = time(NULL) - start_time;
                
                printf("\r[res%d] 总进度:%.1f%% 区间:%d/%d(%.0f%%) 已检查:%u 超时:%u 可执行:%u 用时:%ds   ",
                       file_number, overall_progress, r+1, range_count, range_progress,
                       instructions_checked, sigalrm_cnt, no_signal, elapsed);
                fflush(stdout);
            }
        }
        
        // 将这个区间的bitmap追加到文件
        if(save_range_bitmap_to_file(output_file, timeout_file)) {
            timeout_range_count++;
        }
    }
    
    // 更新timeout文件头中的实际区间数量
    fseek(timeout_file, sizeof(int), SEEK_SET);
    fwrite(&timeout_range_count, sizeof(int), 1, timeout_file);
    
    fclose(output_file);
    fclose(timeout_file);
    save_complete_file_results(range_count);
    
    // 完成后换行，避免覆盖进度条
    printf("\n");
    printf("[res%d] ===== 处理完成 =====\n", file_number);
    printf("[res%d] Total insn numbers (checked): %d \n", file_number, instructions_checked);
    printf("[res%d] SIGILL: %d\n", file_number, sigill_cnt);
    printf("[res%d] SIGSEGV: %d\n", file_number, sigsegv_cnt);
    printf("[res%d] SIGBUS: %d\n", file_number, sigbus_cnt);
    printf("[res%d] SIGTRAP: %d\n", file_number, sigtrap_cnt);
    printf("[res%d] SIGALRM (timeout): %d\n", file_number, sigalrm_cnt);
    printf("[res%d] No signal (executable): %d\n", file_number, no_signal);
    printf("[res%d] 实际写入 %d 个包含超时指令的区间\n", file_number, timeout_range_count);
    printf("[res%d] 总用时: %ld 秒\n", file_number, time(NULL) - start_time);
    
    // 清理定时器
    timer_delete(watchdog_timer);
    
    munmap(insn_region, PAGE_SIZE * 3);
    return 0;
        
}

