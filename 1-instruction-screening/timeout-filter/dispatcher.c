#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sched.h>
#include <sys/time.h> 

#define TIMEOUT_SECONDS 1  // 每条指令的超时时间
#define TIMEOUT_MS 500
#define MAX_RANGES 500000
#define MAX_TIMEOUT_INSTRUCTIONS 100000  // 最大超时指令数
#define MAX_CPUS 4  // 最大CPU核心数

struct Range {
    uint32_t start;
    uint32_t end;
};

// 超时指令记录
uint32_t timeout_instructions[MAX_TIMEOUT_INSTRUCTIONS];
uint32_t timeout_count = 0;

// 超时指令bitmap（按区间保存）
struct TimeoutRange {
    uint32_t start;
    uint32_t end;
    uint8_t *bitmap;
    uint32_t bitmap_size;
};
struct TimeoutRange timeout_ranges[MAX_RANGES];
int timeout_range_count = 0;

volatile int timeout_occurred = 0;
volatile pid_t current_child_pid = 0;

void timeout_handler(int sig) {
    timeout_occurred = 1;
    if (current_child_pid > 0) {
        printf("指令超时，终止进程 %d\n", current_child_pid);
        kill(current_child_pid, SIGKILL);
    }
}

void setup_timeout_handler() {
    struct sigaction sa;
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);
}

int set_cpu_affinity(int file_number, int cpu_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
        perror("设置CPU亲和性失败");
        return -1;
    }
    
    printf("文件 res%d.txt 绑定到CPU核心 %d\n", file_number, cpu_id);
    return cpu_id;
}

void record_timeout_instruction(uint32_t instruction) {
    if (timeout_count < MAX_TIMEOUT_INSTRUCTIONS) {
        timeout_instructions[timeout_count] = instruction;
        timeout_count++;
    } else {
        fprintf(stderr, "警告：超时指令记录已满，无法记录指令 0x%x\n", instruction);
    }
}

void save_timeout_instructions(int file_number) {
    if (timeout_range_count == 0) {
        printf("文件 res%d.txt: 没有超时指令需要保存\n", file_number);
        return;
    }
    
    mkdir("timeout_results", 0755);
    char timeout_filename[256];
    snprintf(timeout_filename, sizeof(timeout_filename), "timeout_results/timeout_res%d.bin", file_number);
    
    FILE *timeout_file = fopen(timeout_filename, "wb");
    if (!timeout_file) {
        fprintf(stderr, "无法创建超时指令文件 %s\n", timeout_filename);
        return;
    }
    
    // 写入文件头：文件编号和区间数量
    fwrite(&file_number, sizeof(int), 1, timeout_file);
    fwrite(&timeout_range_count, sizeof(int), 1, timeout_file);
    
    // 写入每个区间的超时bitmap
    uint32_t total_timeout_count = 0;
    for (int i = 0; i < timeout_range_count; i++) {
        struct TimeoutRange *tr = &timeout_ranges[i];
        
        // 写入区间信息
        fwrite(&tr->start, sizeof(uint32_t), 1, timeout_file);
        fwrite(&tr->end, sizeof(uint32_t), 1, timeout_file);
        fwrite(&tr->bitmap_size, sizeof(uint32_t), 1, timeout_file);
        
        // 写入bitmap数据
        fwrite(tr->bitmap, 1, tr->bitmap_size, timeout_file);
        
        // 统计这个区间的超时指令数量
        for (uint32_t j = 0; j < tr->bitmap_size; j++) {
            uint8_t byte = tr->bitmap[j];
            while (byte) {
                if (byte & 1) total_timeout_count++;
                byte >>= 1;
            }
        }
        
        // 释放bitmap内存
        free(tr->bitmap);
        tr->bitmap = NULL;
    }
    
    fclose(timeout_file);
    
    printf("文件 res%d.txt: 保存了 %u 个超时指令（%d个区间）到 %s\n", 
           file_number, total_timeout_count, timeout_range_count, timeout_filename);
    
    // 重置计数器
    timeout_range_count = 0;
}

int execute_single_check(int file_number, uint32_t instruction) {
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return -1;
    }
    
    if (pid == 0) {
        // 子进程：执行single_check
        char file_num_str[32];
        char insn_str[32];
        snprintf(file_num_str, sizeof(file_num_str), "%d", file_number);
        snprintf(insn_str, sizeof(insn_str), "%u", instruction);
        
        execl("./single_check", "./single_check", file_num_str, insn_str, NULL);
        perror("execl failed");
        exit(127);
    } else {
        // 父进程：设置超时并等待子进程
        current_child_pid = pid;
        timeout_occurred = 0;
        
        struct itimerval timer;
        timer.it_value.tv_sec = TIMEOUT_MS / 1000;      // 0秒
        timer.it_value.tv_usec = (TIMEOUT_MS % 1000) * 1000;  // 500000微秒
        timer.it_interval.tv_sec = 0;   // 不重复
        timer.it_interval.tv_usec = 0;
        
        setitimer(ITIMER_REAL, &timer, NULL);

        // alarm(TIMEOUT_SECONDS);
        
        int status;
        pid_t result = waitpid(pid, &status, 0);
        
        // alarm(0);  // 取消alarm
        timer.it_value.tv_sec = 0;
        timer.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer, NULL);

        current_child_pid = 0;
        
        if (timeout_occurred) {
            printf("文件 %d 指令 0x%x 超时被终止\n", file_number, instruction);
            
            // 如果waitpid被信号中断，需要再次等待回收被杀死的子进程
            if (result == -1 && errno == EINTR) {
                // 等待被SIGKILL杀死的子进程，避免僵尸进程
                waitpid(pid, &status, 0);
            }
            return -2;  // 超时
        }
        
        if (result == -1) {
            perror("waitpid failed");
            return -1;
        }
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            printf("指令 0x%x single_check进程被信号 %d 终止\n", instruction, WTERMSIG(status));
            return -3;  // 被信号终止
        }
        
        return -1;
    }
}

// 处理单个文件的函数
int process_single_file(int file_number, int cpu_id) {
    // 设置CPU亲和性
    if (cpu_id >= 0) {
        if (set_cpu_affinity(file_number, cpu_id) < 0) {
            fprintf(stderr, "警告：文件 %d 无法设置CPU亲和性，继续运行...\n", file_number);
        }
    }
    
    // 初始化超时计数
    timeout_count = 0;
    
    // 设置超时处理器
    setup_timeout_handler();
    
    // 读取res文件
    char input_filename[256];
    snprintf(input_filename, sizeof(input_filename), "result/res%d.txt", file_number);
    
    FILE *res_file = fopen(input_filename, "r");
    if (!res_file) {
        fprintf(stderr, "无法打开文件 %s: %s\n", input_filename, strerror(errno));
        return 1;
    }
    
    // 读取所有区间
    struct Range ranges[MAX_RANGES];
    int range_count = 0;
    char line[256];
    
    while (fgets(line, sizeof(line), res_file) != NULL && range_count < MAX_RANGES) {
        uint32_t range_start, range_end;
        if (sscanf(line, "[%u, %u]", &range_start, &range_end) == 2) {
            ranges[range_count].start = range_start;
            ranges[range_count].end = range_end;
            range_count++;
        }
    }
    fclose(res_file);
    
    printf("从 %s 读取到 %d 个区间\n", input_filename, range_count);
    
    if (range_count == 0) {
        printf("文件中没有找到有效区间\n");
        return 0;
    }
    
    // 创建输出目录
    mkdir("bitmap_results", 0755);
    
    // 删除旧的结果文件（如果存在）
    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "bitmap_results/res%d_complete.bin", file_number);
    unlink(output_filename);
    
    // 写入文件头
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fprintf(stderr, "无法创建输出文件 %s\n", output_filename);
        return 1;
    }
    
    // 写入文件编号和区间数量
    fwrite(&file_number, sizeof(int), 1, output_file);
    fwrite(&range_count, sizeof(int), 1, output_file);
    fclose(output_file);
    
    // 统计变量
    uint32_t total_instructions = 0;
    uint32_t executable_count = 0;
    uint32_t sigill_count = 0;
    uint32_t sigsegv_count = 0;
    uint32_t timeout_inst_count = 0;  // 重命名以避免与全局变量冲突
    uint32_t other_count = 0;
    
    time_t start_time = time(NULL);
    
    // 处理每个区间
    for (int r = 0; r < range_count; r++) {
        uint32_t range_start = ranges[r].start;
        uint32_t range_end = ranges[r].end;
        uint32_t range_size = range_end - range_start;
        
        // printf("处理区间 %d/%d: [%u, %u] (%u 条指令)\n", 
        //        r + 1, range_count, range_start, range_end, range_size);
        
        // 为当前区间创建bitmap
        uint32_t bitmap_size = (range_size + 7) / 8;  // 向上取整到字节
        uint8_t *region_bitmap = calloc(bitmap_size, 1);
        if (!region_bitmap) {
            fprintf(stderr, "为区间 [%u, %u] 分配bitmap内存失败\n", range_start, range_end);
            continue;
        }
        
        // 为当前区间创建timeout bitmap
        uint8_t *timeout_bitmap = calloc(bitmap_size, 1);
        if (!timeout_bitmap) {
            fprintf(stderr, "为区间 [%u, %u] 分配timeout bitmap内存失败\n", range_start, range_end);
            free(region_bitmap);
            continue;
        }
        
        // 测试区间内的每条指令
        int has_timeout = 0;
        for (uint32_t insn = range_start; insn < range_end; insn++) {
            int result = execute_single_check(file_number, insn);
            
            total_instructions++;
            uint32_t offset = insn - range_start;
            uint32_t byte_index = offset / 8;
            uint8_t bit_position = offset % 8;
            
            // 如果指令可执行，在bitmap中标记
            if (result == 0) {
                executable_count++;
                region_bitmap[byte_index] |= (1 << bit_position);
            } else {
                switch (result) {
                    case 1:
                        sigill_count++;
                        break;
                    case 2:
                        sigsegv_count++;
                        break;
                    case -2:
                        timeout_inst_count++;
                        // 在timeout bitmap中标记
                        timeout_bitmap[byte_index] |= (1 << bit_position);
                        has_timeout = 1;
                        break;
                    default:
                        other_count++;
                        break;
                }
            }
            
            // 每1000条指令显示一次进度
            if (total_instructions % 100000 == 0) {
                time_t current_time = time(NULL);
                double elapsed = difftime(current_time, start_time);
                double rate = total_instructions / elapsed;
                
                printf("文件 %d 已测试 %u 条指令，速度: %.1f 指令/秒 "
                       "(可执行:%u, SIGILL:%u, SIGSEGV:%u, 超时:%u, 其他:%u)\n",
                       file_number, total_instructions, rate, executable_count, sigill_count, 
                       sigsegv_count, timeout_inst_count, other_count);
            }
        }
        
        // 将当前区间的bitmap追加到文件
        FILE *append_file = fopen(output_filename, "ab");
        if (append_file) {
            // 写入区间信息和bitmap数据
            fwrite(&range_start, sizeof(uint32_t), 1, append_file);   // 区间起始
            fwrite(&range_end, sizeof(uint32_t), 1, append_file);     // 区间结束
            fwrite(&bitmap_size, sizeof(uint32_t), 1, append_file);   // bitmap大小
            fwrite(region_bitmap, 1, bitmap_size, append_file);       // bitmap数据
            fclose(append_file);
        } else {
            fprintf(stderr, "无法打开输出文件进行追加写入\n");
        }
        
        // 如果有超时指令，保存timeout bitmap
        if (has_timeout) {
            if (timeout_range_count < MAX_RANGES) {
                timeout_ranges[timeout_range_count].start = range_start;
                timeout_ranges[timeout_range_count].end = range_end;
                timeout_ranges[timeout_range_count].bitmap = timeout_bitmap;
                timeout_ranges[timeout_range_count].bitmap_size = bitmap_size;
                timeout_range_count++;
                // 不要释放timeout_bitmap，将在save_timeout_instructions中释放
            } else {
                fprintf(stderr, "超时区间记录已满，无法保存区间 [%u, %u] 的超时bitmap\n", range_start, range_end);
                free(timeout_bitmap);
            }
        } else {
            free(timeout_bitmap);
        }
        
        free(region_bitmap);
    }
    
    time_t end_time = time(NULL);
    double total_elapsed = difftime(end_time, start_time);
    
    printf("\n测试完成！\n");
    printf("总耗时: %.1f 秒\n", total_elapsed);
    printf("平均速度: %.1f 指令/秒\n", total_instructions / total_elapsed);
    printf("\n结果统计:\n");
    printf("总指令数: %u\n", total_instructions);
    printf("可执行指令: %u (%.2f%%)\n", executable_count, 
           100.0 * executable_count / total_instructions);
    printf("SIGILL: %u (%.2f%%)\n", sigill_count, 
           100.0 * sigill_count / total_instructions);
    printf("SIGSEGV: %u (%.2f%%)\n", sigsegv_count, 
           100.0 * sigsegv_count / total_instructions);
    printf("超时: %u (%.2f%%)\n", timeout_inst_count, 
           100.0 * timeout_inst_count / total_instructions);
    printf("其他: %u (%.2f%%)\n", other_count, 
           100.0 * other_count / total_instructions);
    
    printf("\n结果已保存到: %s\n", output_filename);
    
    // 保存超时指令
    save_timeout_instructions(file_number);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <file_numbers...>\n", argv[0]);
        fprintf(stderr, "例如: %s 16 17 20 21  # 并行处理多个文件\n", argv[0]);
        fprintf(stderr, "      %s 17         # 处理单个文件\n", argv[0]);
        return 1;
    }
    
    int file_count = argc - 1;
    printf("开始并行处理 %d 个文件，使用最多 %d 个CPU核心\n", file_count, MAX_CPUS);
    
    // 如果只有一个文件，直接处理
    if (file_count == 1) {
        int file_number = atoi(argv[1]);
        return process_single_file(file_number, 0);  // 使用CPU核心0
    }
    
    // 多文件并行处理
    // 活跃进程管理
    struct {
        pid_t pid;
        int file_number;
        time_t start_time;
    } active_processes[MAX_CPUS];
    
    // 初始化活跃进程数组
    for (int i = 0; i < MAX_CPUS; i++) {
        active_processes[i].pid = -1;
        active_processes[i].file_number = -1;
        active_processes[i].start_time = 0;
    }
    
    int file_numbers[file_count];
    for (int i = 0; i < file_count; i++) {
        file_numbers[i] = atoi(argv[i + 1]);
    }
    
    // 记录开始时间
    time_t start_time = time(NULL);
    
    int next_file_index = 0;  // 下一个要处理的文件索引
    int completed = 0;
    int failed = 0;
    int last_reported_progress = 0;  // 上次报告的进度
    
    while (completed + failed < file_count) {
        // 启动新的进程（如果有空闲CPU核心且还有文件要处理）
        for (int cpu = 0; cpu < MAX_CPUS && next_file_index < file_count; cpu++) {
            if (active_processes[cpu].pid == -1) {
                int file_number = file_numbers[next_file_index];
                
                pid_t pid = fork();
                if (pid == -1) {
                    perror("fork failed");
                    failed++;
                    next_file_index++;
                    continue;
                } else if (pid == 0) {
                    // 子进程：处理单个文件
                    exit(process_single_file(file_number, cpu));
                } else {
                    // 父进程：记录子进程信息
                    active_processes[cpu].pid = pid;
                    active_processes[cpu].file_number = file_number;
                    active_processes[cpu].start_time = time(NULL);
                    
                    printf("启动处理文件 res%d.txt (PID: %d, CPU核心: %d)\n", 
                           file_number, pid, cpu);
                    next_file_index++;
                }
            }
        }
        
        // 检查是否有进程完成
        for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
            if (active_processes[cpu].pid != -1) {
                int status;
                pid_t result = waitpid(active_processes[cpu].pid, &status, WNOHANG);
                
                if (result == active_processes[cpu].pid) {
                    // 进程已完成
                    int file_number = active_processes[cpu].file_number;
                    time_t elapsed = time(NULL) - active_processes[cpu].start_time;
                    
                    if (WIFEXITED(status)) {
                        int exit_code = WEXITSTATUS(status);
                        if (exit_code == 0) {
                            printf("✓ 文件 res%d.txt 处理完成 (CPU核心: %d, 耗时: %lds)\n", 
                                   file_number, cpu, elapsed);
                            completed++;
                        } else {
                            printf("✗ 文件 res%d.txt 处理失败，退出码: %d (CPU核心: %d, 耗时: %lds)\n", 
                                   file_number, exit_code, cpu, elapsed);
                            failed++;
                        }
                    } else if (WIFSIGNALED(status)) {
                        printf("✗ 文件 res%d.txt 被信号 %d 终止 (CPU核心: %d, 耗时: %lds)\n", 
                               file_number, WTERMSIG(status), cpu, elapsed);
                        failed++;
                    } else {
                        printf("✗ 文件 res%d.txt 异常结束 (CPU核心: %d, 耗时: %lds)\n", 
                               file_number, cpu, elapsed);
                        failed++;
                    }
                    
                    // 清理活跃进程槽位
                    active_processes[cpu].pid = -1;
                    active_processes[cpu].file_number = -1;
                    active_processes[cpu].start_time = 0;
                    
                    // 显示进度（只在进度发生变化时显示）
                    int current_progress = completed + failed;
                    if (current_progress % 5 == 0 && current_progress > last_reported_progress) {
                        printf("进度: 完成 %d, 失败 %d, 总计 %d/%d\n", 
                               completed, failed, current_progress, file_count);
                        last_reported_progress = current_progress;
                    }
                    
                } else if (result == -1 && errno != ECHILD) {
                    // waitpid出错
                    perror("waitpid failed");
                    printf("✗ 文件 res%d.txt waitpid失败 (CPU核心: %d)\n", 
                           active_processes[cpu].file_number, cpu);
                    
                    // 强制杀死进程并清理
                    kill(active_processes[cpu].pid, SIGKILL);
                    waitpid(active_processes[cpu].pid, NULL, 0);
                    
                    active_processes[cpu].pid = -1;
                    active_processes[cpu].file_number = -1;
                    active_processes[cpu].start_time = 0;
                    failed++;
                }
            }
        }
        
                          // 短暂休眠避免CPU占用过高
         usleep(100000);  // 100ms
    }
    
    // 计算总处理时间
    time_t end_time = time(NULL);
    double total_elapsed = difftime(end_time, start_time);
    int hours = total_elapsed / 3600;
    int minutes = ((int)total_elapsed % 3600) / 60;
    int seconds = (int)total_elapsed % 60;
    
    printf("\n=============== 所有任务完成 ===============\n");
    printf("总耗时: %02d:%02d:%02d\n", hours, minutes, seconds);
    printf("处理统计:\n");
    printf("  成功: %d 个文件\n", completed);
    printf("  失败: %d 个文件\n", failed);
    printf("  总计: %d 个文件\n", file_count);
    printf("\n结果保存在以下目录:\n");
    printf("  - bitmap_results/ (可执行指令bitmap)\n");
    printf("  - timeout_results/ (超时指令bitmap)\n");
    
    return (failed > 0) ? 1 : 0;
}