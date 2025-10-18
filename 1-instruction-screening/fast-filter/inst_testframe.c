#define _GNU_SOURCE   
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>   

#define NUM_CORES 6
#define MAX_FILES 256

FILE *problem_ranges_file = NULL;

struct Worker {
    pid_t pid; // child pid
    int core_id;
    int busy; //flag
    int file_number; // 处理的文件编号
    time_t start_time; 
};

int set_cpu_affinity(pid_t pid, int core_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (sched_setaffinity(pid, sizeof(mask), &mask) < 0) {
        perror("Setting CPU affinity failed");
        return -1;
    }
    return 0;
}

int main() {
    if(access("./ins_check", X_OK) != 0) {
        fprintf(stderr, "Cannot execute ins_check\n");
        return 1;
    }

    problem_ranges_file = fopen("problem_ranges.txt", "a");
    if (!problem_ranges_file) {
        fprintf(stderr, "无法创建问题区间日志文件\n");
        return 1;
    }

    // 初始化worker数组
    struct Worker workers[NUM_CORES];
    for(int i = 0; i < NUM_CORES; i++) {
        workers[i].pid = -1;
        workers[i].core_id = i;
        workers[i].busy = 0;
        workers[i].file_number = -1;
    }

    int files_processed = 0;
    int current_file = 0;

    printf("开始分发文件处理任务，共有 %d 个CPU核心\n", NUM_CORES);

    while(files_processed < MAX_FILES || current_file < MAX_FILES) {
        // 分配新的文件给空闲的worker
        for(int w = 0; w < NUM_CORES; w++) {
            if(!workers[w].busy && current_file < MAX_FILES) {
                // 检查文件是否存在
                char input_filename[100];
                snprintf(input_filename, sizeof(input_filename), "results_A32/res%d.txt", current_file);
                
                if(access(input_filename, R_OK) != 0) {
                    printf("文件 %s 不存在，跳过\n", input_filename);
                    current_file++;
                    continue;
                }

                pid_t pid = fork();
                if(pid < 0) {
                    perror("fork failed");
                    current_file++;
                } else if(pid == 0) {
                    // 子进程：设置CPU亲和性并直接执行ins_check处理整个文件
                    if(set_cpu_affinity(getpid(), workers[w].core_id) < 0) {
                        fprintf(stderr, "Cannot set child process %d to core %d\n", 
                                getpid(), workers[w].core_id);
                    }
                    
                    // 直接exec ins_check，传入文件编号，让ins_check读取并处理整个文件
                    char file_num_str[20];
                    snprintf(file_num_str, sizeof(file_num_str), "%d", current_file);
                    
                    execl("./ins_check", "ins_check", file_num_str, NULL);
                    perror("./ins_check failed!");
                    _exit(1);
                } else {
                    // 父进程：记录worker状态
                    workers[w].pid = pid;
                    workers[w].busy = 1;
                    workers[w].file_number = current_file;
                    workers[w].start_time = time(NULL);
                    
                    printf("分配文件 res%d.txt 给 Core %d (PID: %d)\n", current_file, workers[w].core_id, pid);
                    current_file++;
                }
            }
        }

        // 检查已完成的worker
        for(int w = 0; w < NUM_CORES; w++) {
            if(workers[w].busy) {
                time_t current_time = time(NULL);
                
                // 检查超时（2小时）
                if(current_time - workers[w].start_time > 7200) {
                    printf("Core %d 处理文件 res%d.txt 超时，终止进程 PID:%d\n", 
                           workers[w].core_id, workers[w].file_number, workers[w].pid);
                    
                    fprintf(problem_ranges_file, "file: %d timeout (>2 hours)\n", workers[w].file_number);
                    fflush(problem_ranges_file);
                    
                    kill(workers[w].pid, SIGKILL);
                    waitpid(workers[w].pid, NULL, 0);
                    
                    workers[w].pid = -1;
                    workers[w].busy = 0;
                    workers[w].file_number = -1;
                    files_processed++;
                    continue;
                }

                int status;
                pid_t result = waitpid(workers[w].pid, &status, WNOHANG);
                
                if(result > 0) {
                    // 子进程完成
                    if(WIFEXITED(status)) {
                        int exit_code = WEXITSTATUS(status);
                        if(exit_code == 0) {
                            printf("Core %d 成功完成文件 res%d.txt\n", 
                                   workers[w].core_id, workers[w].file_number);
                        } else if(exit_code == 10) {
                            printf("Core %d 处理文件 res%d.txt 遇到连续SIGSEGV\n", 
                                   workers[w].core_id, workers[w].file_number);
                            fprintf(problem_ranges_file, "file: %d consecutive SIGSEGV\n", workers[w].file_number);
                            fflush(problem_ranges_file);
                        } else {
                            printf("Core %d 处理文件 res%d.txt 失败 (退出码: %d)\n", 
                                   workers[w].core_id, workers[w].file_number, exit_code);
                            fprintf(problem_ranges_file, "file: %d failed (exit code %d)\n", 
                                    workers[w].file_number, exit_code);
                            fflush(problem_ranges_file);
                        }
                    } else {
                        printf("Core %d 处理文件 res%d.txt 被信号终止\n", 
                               workers[w].core_id, workers[w].file_number);
                        fprintf(problem_ranges_file, "file: %d terminated by signal\n", workers[w].file_number);
                        fflush(problem_ranges_file);
                    }
                    
                    workers[w].pid = -1;
                    workers[w].busy = 0;
                    workers[w].file_number = -1;
                    files_processed++;
                }
            }
        }

        // 短暂睡眠避免CPU占用过高
        usleep(500000); // 500ms
    }

    printf("所有文件处理完成！\n");
    
    if(problem_ranges_file) {
        fclose(problem_ranges_file);
    }
    
    return 0;
}