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
    
    printf("文件 %s: 文件编号=%d, 区间数量=%d\n", 
           filename, result->file_number, result->range_count);
    
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
        
        printf("  区间 %d: [0x%08x, 0x%08x] bitmap大小=%u字节, 可执行指令=%u条\n",
               i+1, range->start, range->end, range->bitmap_size, executable_count);
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

// 检查指令是否可执行
int is_instruction_executable(FileResult *result, uint32_t instruction) {
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        
        if (instruction >= range->start && instruction < range->end) {
            uint32_t offset = instruction - range->start;
            uint32_t byte_index = offset / 8;
            uint8_t bit_position = offset % 8;
            
            if (byte_index < range->bitmap_size) {
                return (range->bitmap[byte_index] & (1 << bit_position)) ? 1 : 0;
            }
        }
    }
    return 0; // 不在任何区间内，认为不可执行
}

// 提取区间内的所有可执行指令
void extract_executable_instructions(FileResult *result, uint32_t range_index) {
    if (range_index >= result->range_count) {
        printf("区间索引 %u 超出范围 (最大: %d)\n", range_index, result->range_count - 1);
        return;
    }
    
    Range *range = &result->ranges[range_index];
    printf("\n区间 %u [0x%08x, 0x%08x] 的可执行指令:\n", 
           range_index + 1, range->start, range->end);
    
    uint32_t count = 0;
    for (uint32_t insn = range->start; insn < range->end; insn++) {
        uint32_t offset = insn - range->start;
        uint32_t byte_index = offset / 8;
        uint8_t bit_position = offset % 8;
        
        if (byte_index < range->bitmap_size && 
            (range->bitmap[byte_index] & (1 << bit_position))) {
            printf("0x%08x ", insn);
            count++;
            
            // 每行显示8个指令
            if (count % 8 == 0) {
                printf("\n");
            }
        }
    }
    
    if (count % 8 != 0) {
        printf("\n");
    }
    
    printf("区间 %u 总共有 %u 条可执行指令\n", range_index + 1, count);
}

// 导出可执行指令到文本文件
void export_executable_instructions(FileResult *result, const char *output_filename) {
    FILE *output = fopen(output_filename, "w");
    if (!output) {
        fprintf(stderr, "无法创建输出文件 %s: %s\n", output_filename, strerror(errno));
        return;
    }
    
    fprintf(output, "# 文件编号: %d\n", result->file_number);
    fprintf(output, "# 区间数量: %d\n", result->range_count);
    fprintf(output, "# 总可执行指令数: %u\n\n", result->total_executable_count);
    
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        fprintf(output, "# 区间 %d: [0x%08x, 0x%08x]\n", i+1, range->start, range->end);
        
        for (uint32_t insn = range->start; insn < range->end; insn++) {
            uint32_t offset = insn - range->start;
            uint32_t byte_index = offset / 8;
            uint8_t bit_position = offset % 8;
            
            if (byte_index < range->bitmap_size && 
                (range->bitmap[byte_index] & (1 << bit_position))) {
                fprintf(output, "0x%08x\n", insn);
            }
        }
        
        fprintf(output, "\n");
    }
    
    fclose(output);
    printf("可执行指令已导出到文件: %s\n", output_filename);
}

// 显示统计信息
void show_statistics(FileResult *result) {
    printf("\n========== 统计信息 ==========\n");
    printf("文件编号: %d\n", result->file_number);
    printf("区间数量: %d\n", result->range_count);
    printf("总可执行指令数: %u\n", result->total_executable_count);
    
    // 计算总指令空间大小
    uint64_t total_instruction_space = 0;
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        total_instruction_space += (range->end - range->start);
    }
    
    printf("总指令空间大小: %lu\n", total_instruction_space);
    
    if (total_instruction_space > 0) {
        double executable_ratio = (double)result->total_executable_count / total_instruction_space * 100.0;
        printf("可执行指令比例: %.4f%%\n", executable_ratio);
    }
    
    printf("\n各区间详细信息:\n");
    for (int i = 0; i < result->range_count; i++) {
        Range *range = &result->ranges[i];
        uint32_t range_size = range->end - range->start;
        
        // 统计该区间的可执行指令数量
        uint32_t executable_count = 0;
        for (uint32_t j = 0; j < range->bitmap_size; j++) {
            uint8_t byte = range->bitmap[j];
            while (byte) {
                if (byte & 1) executable_count++;
                byte >>= 1;
            }
        }
        
        double range_ratio = (double)executable_count / range_size * 100.0;
        printf("  区间 %d: [0x%08x, 0x%08x] 大小=%u, 可执行=%u (%.4f%%)\n",
               i+1, range->start, range->end, range_size, executable_count, range_ratio);
    }
}

// 交互式查询模式
void interactive_mode(FileResult *result) {
    char input[256];
    printf("\n========== 交互式查询模式 ==========\n");
    printf("可用命令:\n");
    printf("  check <instruction_hex>  - 检查指令是否可执行\n");
    printf("  extract <range_index>    - 提取指定区间的可执行指令 (从1开始)\n");
    printf("  export <filename>        - 导出所有可执行指令到文件\n");
    printf("  stats                    - 显示统计信息\n");
    printf("  quit                     - 退出\n\n");
    
    while (1) {
        printf("filter> ");
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // 移除换行符
        input[strcspn(input, "\n")] = 0;
        
        char command[64], param[192];
        int parsed = sscanf(input, "%63s %191s", command, param);
        
        if (parsed == 0) continue;
        
        if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0) {
            break;
        } else if (strcmp(command, "stats") == 0) {
            show_statistics(result);
        } else if (strcmp(command, "check") == 0 && parsed == 2) {
            uint32_t instruction = (uint32_t)strtoul(param, NULL, 0);
            int executable = is_instruction_executable(result, instruction);
            printf("指令 0x%08x %s\n", instruction, executable ? "可执行" : "不可执行");
        } else if (strcmp(command, "extract") == 0 && parsed == 2) {
            uint32_t range_index = (uint32_t)strtoul(param, NULL, 10);
            if (range_index > 0) {
                extract_executable_instructions(result, range_index - 1);
            } else {
                printf("区间索引必须大于0\n");
            }
        } else if (strcmp(command, "export") == 0 && parsed == 2) {
            export_executable_instructions(result, param);
        } else {
            printf("未知命令或参数错误。输入 'quit' 退出。\n");
        }
    }
}

// 显示帮助信息
void show_help(const char *program_name) {
    printf("用法: %s [选项] <bitmap_file>\n\n", program_name);
    printf("选项:\n");
    printf("  -h, --help              显示此帮助信息\n");
    printf("  -s, --stats             仅显示统计信息\n");
    printf("  -c, --check <hex>       检查指定指令是否可执行\n");
    printf("  -e, --extract <index>   提取指定区间的可执行指令 (从1开始)\n");
    printf("  -o, --output <file>     导出所有可执行指令到文件\n");
    printf("  -i, --interactive       进入交互式模式\n");
    printf("  -l, --list              列出bitmap_results目录中的所有文件\n\n");
    printf("示例:\n");
    printf("  %s bitmap_results/res0_complete.bin\n", program_name);
    printf("  %s -s bitmap_results/res0_complete.bin\n", program_name);
    printf("  %s -c 0xe1a00001 bitmap_results/res0_complete.bin\n", program_name);
    printf("  %s -e 1 bitmap_results/res0_complete.bin\n", program_name);
    printf("  %s -o output.txt bitmap_results/res0_complete.bin\n", program_name);
    printf("  %s -i bitmap_results/res0_complete.bin\n", program_name);
}

// 列出bitmap结果文件
void list_bitmap_files() {
    DIR *dir = opendir("bitmap_results");
    if (!dir) {
        fprintf(stderr, "无法打开 bitmap_results 目录: %s\n", strerror(errno));
        return;
    }
    
    printf("bitmap_results 目录中的文件:\n");
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "_complete.bin")) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "bitmap_results/%s", entry->d_name);
            
            struct stat st;
            if (stat(filepath, &st) == 0) {
                printf("  %s (%.1f MB)\n", entry->d_name, st.st_size / 1024.0 / 1024.0);
                count++;
            }
        }
    }
    
    closedir(dir);
    printf("共找到 %d 个bitmap文件\n", count);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }
    
    // 解析命令行参数
    char *bitmap_file = NULL;
    int show_stats_only = 0;
    int interactive = 0;
    uint32_t check_instruction = 0;
    int check_mode = 0;
    uint32_t extract_range = 0;
    char *output_file = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list_bitmap_files();
            return 0;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stats") == 0) {
            show_stats_only = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            interactive = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
            if (i + 1 < argc) {
                check_instruction = (uint32_t)strtoul(argv[++i], NULL, 0);
                check_mode = 1;
            } else {
                fprintf(stderr, "错误: -c 选项需要指定指令值\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--extract") == 0) {
            if (i + 1 < argc) {
                extract_range = (uint32_t)strtoul(argv[++i], NULL, 10);
            } else {
                fprintf(stderr, "错误: -e 选项需要指定区间索引\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                fprintf(stderr, "错误: -o 选项需要指定输出文件名\n");
                return 1;
            }
        } else if (argv[i][0] != '-') {
            bitmap_file = argv[i];
        } else {
            fprintf(stderr, "未知选项: %s\n", argv[i]);
            return 1;
        }
    }
    
    if (!bitmap_file) {
        fprintf(stderr, "错误: 必须指定bitmap文件\n");
        show_help(argv[0]);
        return 1;
    }
    
    // 解析bitmap文件
    FileResult result = {0};
    if (parse_bitmap_file(bitmap_file, &result) != 0) {
        return 1;
    }
    
    printf("\n解析完成! 总共找到 %u 条可执行指令\n", result.total_executable_count);
    
    // 根据命令行选项执行相应操作
    if (show_stats_only) {
        show_statistics(&result);
    } else if (check_mode) {
        int executable = is_instruction_executable(&result, check_instruction);
        printf("指令 0x%08x %s\n", check_instruction, executable ? "可执行" : "不可执行");
    } else if (extract_range > 0) {
        extract_executable_instructions(&result, extract_range - 1);
    } else if (output_file) {
        export_executable_instructions(&result, output_file);
    } else if (interactive) {
        interactive_mode(&result);
    } else {
        // 默认显示统计信息并进入交互模式
        show_statistics(&result);
        interactive_mode(&result);
    }
    
    // 清理内存
    free_file_result(&result);
    
    return 0;
}