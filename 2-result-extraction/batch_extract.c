#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

// 区间结构
typedef struct {
    uint32_t start;
    uint32_t end;
    uint32_t bitmap_size;
    uint8_t *bitmap;
} Range;

// 文件解析结果结构
typedef struct {
    int file_number;
    int range_count;
    Range *ranges;
    uint32_t total_executable_count;
} FileResult;

// 解析单个bitmap文件
int parse_bitmap_file(const char *filename, FileResult *result) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "无法打开文件 %s: %s\n", filename, strerror(errno));
        return -1;
    }
    
    // 读取文件头
    if (fread(&result->file_number, sizeof(int), 1, file) != 1 ||
        fread(&result->range_count, sizeof(int), 1, file) != 1) {
        fprintf(stderr, "读取文件头失败: %s\n", filename);
        fclose(file);
        return -1;
    }
    
    // 分配区间数组
    result->ranges = malloc(result->range_count * sizeof(Range));
    if (!result->ranges) {
        fprintf(stderr, "分配内存失败\n");
        fclose(file);
        return -1;
    }
    
    result->total_executable_count = 0;
    
    // 读取每个区间的数据
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        
        // 读取区间信息
        if (fread(&range->start, sizeof(uint32_t), 1, file) != 1 ||
            fread(&range->end, sizeof(uint32_t), 1, file) != 1 ||
            fread(&range->bitmap_size, sizeof(uint32_t), 1, file) != 1) {
            fprintf(stderr, "读取区间 %d 信息失败\n", i);
            fclose(file);
            return -1;
        }
        
        // 分配并读取bitmap数据
        range->bitmap = malloc(range->bitmap_size);
        if (!range->bitmap) {
            fprintf(stderr, "为区间 %d 分配bitmap内存失败\n", i);
            fclose(file);
            return -1;
        }
        
        if (fread(range->bitmap, 1, range->bitmap_size, file) != range->bitmap_size) {
            fprintf(stderr, "读取区间 %d bitmap数据失败\n", i);
            free(range->bitmap);
            fclose(file);
            return -1;
        }
        
        // 统计该区间的可执行指令数量
        uint32_t executable_count = 0;
        for (uint32_t j = 0; j < range->bitmap_size; j++) {
            uint8_t byte = range->bitmap[j];
            while (byte) {
                if (byte & 1) executable_count++;
                byte >>= 1;
            }
        }
        
        result->total_executable_count += executable_count;
    }
    
    fclose(file);
    return 0;
}

// 释放文件结果内存
void free_file_result(FileResult *result) {
    if (result->ranges) {
        for (int i = 0; i < result->range_count; i++) {
            if (result->ranges[i].bitmap) {
                free(result->ranges[i].bitmap);
            }
        }
        free(result->ranges);
    }
}

// 导出可执行指令到文本文件（纯区间格式）
void export_executable_instructions_by_range(FileResult *result, const char *output_filename) {
    FILE *output = fopen(output_filename, "w");
    if (!output) {
        fprintf(stderr, "无法创建输出文件 %s: %s\n", output_filename, strerror(errno));
        return;
    }
    
    uint32_t total_exported_ranges = 0;
    uint32_t total_exported_instructions = 0;
    
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        
        // 先扫描一遍，找出所有可执行指令的位置
        uint32_t *executable_instructions = malloc((range->end - range->start) * sizeof(uint32_t));
        uint32_t executable_count = 0;
        
        for (uint32_t insn = range->start; insn < range->end; insn++) {
            uint32_t offset = insn - range->start;
            uint32_t byte_index = offset / 8;
            uint8_t bit_position = offset % 8;
            
            if (byte_index < range->bitmap_size && 
                (range->bitmap[byte_index] & (1 << bit_position))) {
                executable_instructions[executable_count++] = insn;
            }
        }
        
        if (executable_count > 0) {
            // 合并连续的可执行指令为区间
            uint32_t range_start = executable_instructions[0];
            uint32_t range_end = executable_instructions[0];
            
            for (uint32_t j = 1; j < executable_count; j++) {
                uint32_t current_insn = executable_instructions[j];
                
                // 如果当前指令与前一个指令连续
                if (current_insn == range_end + 1) {
                    range_end = current_insn;
                } else {
                    // 输出当前区间（右开区间格式）
                    fprintf(output, "[%u, %u]\n", range_start, range_end + 1);
                    total_exported_ranges++;
                    total_exported_instructions += (range_end - range_start + 1);
                    
                    // 开始新区间
                    range_start = current_insn;
                    range_end = current_insn;
                }
            }
            
            // 输出最后一个区间（右开区间格式）
            fprintf(output, "[%u, %u]\n", range_start, range_end + 1);
            total_exported_ranges++;
            total_exported_instructions += (range_end - range_start + 1);
        }
        
        free(executable_instructions);
    }
    
    fclose(output);
    printf("文件 %d: 成功导出 %u 个连续可执行区间（共 %u 条指令）到 %s\n", 
           result->file_number, total_exported_ranges, total_exported_instructions, output_filename);
}

// 处理单个bitmap文件
int process_single_bitmap_file(const char *input_filename) {
    // 从输入文件名提取文件编号
    char *basename_copy = strdup(input_filename);
    char *basename_ptr = strrchr(basename_copy, '/');
    if (basename_ptr) {
        basename_ptr++;
    } else {
        basename_ptr = basename_copy;
    }
    
    int file_number;
    if (sscanf(basename_ptr, "res%d_complete.bin", &file_number) != 1) {
        fprintf(stderr, "无法从文件名 %s 解析文件编号\n", input_filename);
        free(basename_copy);
        return -1;
    }
    free(basename_copy);
    
    // 解析bitmap文件
    FileResult result = {0};
    if (parse_bitmap_file(input_filename, &result) != 0) {
        return -1;
    }
    
    // 创建输出目录
    mkdir("extracted_instructions", 0755);
    
    // 生成输出文件名
    char output_filename[512];
    snprintf(output_filename, sizeof(output_filename), 
             "extracted_instructions/res%d_executable.txt", file_number);
    
    // 导出可执行指令
    export_executable_instructions_by_range(&result, output_filename);
    
    // 清理内存
    free_file_result(&result);
    
    return 0;
}

// 批量处理所有bitmap文件
int batch_process_all_files() {
    DIR *dir = opendir("bitmap_results");
    if (!dir) {
        fprintf(stderr, "无法打开 bitmap_results 目录: %s\n", strerror(errno));
        return -1;
    }
    
    printf("开始批量处理bitmap文件...\n\n");
    
    struct dirent *entry;
    int processed = 0;
    int failed = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "_complete.bin")) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "bitmap_results/%s", entry->d_name);
            
            printf("处理文件: %s", entry->d_name);
            
            if (process_single_bitmap_file(filepath) == 0) {
                processed++;
                printf(" ✓\n");
            } else {
                failed++;
                printf(" ✗\n");
            }
        }
    }
    
    closedir(dir);
    
    printf("\n========== 批量处理完成 ==========\n");
    printf("成功处理: %d 个文件\n", processed);
    printf("处理失败: %d 个文件\n", failed);
    printf("总计: %d 个文件\n", processed + failed);
    printf("\n结果保存在 extracted_instructions/ 目录中\n");
    
    // 显示输出目录内容
    DIR *output_dir = opendir("extracted_instructions");
    if (output_dir) {
        printf("\n生成的文件:\n");
        int file_count = 0;
        while ((entry = readdir(output_dir)) != NULL) {
            if (strstr(entry->d_name, "_executable.txt")) {
                char output_filepath[512];
                snprintf(output_filepath, sizeof(output_filepath), 
                        "extracted_instructions/%s", entry->d_name);
                
                struct stat st;
                if (stat(output_filepath, &st) == 0) {
                    printf("  %s (%.1f KB)\n", entry->d_name, st.st_size / 1024.0);
                    file_count++;
                }
            }
        }
        closedir(output_dir);
        printf("共生成 %d 个txt文件\n", file_count);
    }
    
    return (failed > 0) ? 1 : 0;
}

void show_help(const char *program_name) {
    printf("用法: %s [选项] [bitmap_file]\n\n", program_name);
    printf("选项:\n");
    printf("  -h, --help          显示此帮助信息\n");
    printf("  -a, --all           批量处理所有bitmap文件\n");
    printf("  -f, --file <file>   处理指定的bitmap文件\n\n");
    printf("示例:\n");
    printf("  %s -a                                    # 批量处理所有文件\n", program_name);
    printf("  %s -f bitmap_results/res0_complete.bin   # 处理单个文件\n", program_name);
    printf("  %s bitmap_results/res0_complete.bin      # 处理单个文件（简化形式）\n", program_name);
    printf("\n输出:\n");
    printf("  结果将保存在 extracted_instructions/ 目录中\n");
    printf("  文件格式: res<编号>_executable.txt\n");
    printf("  内容格式: 每行一个十六进制指令值，按区间组织\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }
    
    // 解析命令行参数
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        show_help(argv[0]);
        return 0;
    } else if (strcmp(argv[1], "-a") == 0 || strcmp(argv[1], "--all") == 0) {
        return batch_process_all_files();
    } else if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "错误: -f 选项需要指定文件名\n");
            return 1;
        }
        return process_single_bitmap_file(argv[2]);
    } else if (argv[1][0] != '-') {
        // 直接指定文件名
        return process_single_bitmap_file(argv[1]);
    } else {
        fprintf(stderr, "未知选项: %s\n", argv[1]);
        show_help(argv[0]);
        return 1;
    }
} 