# 指令筛选阶段

这个目录包含用于大规模ARM32指令筛选的工具，通过信号处理机制识别可执行的隐藏指令。

## 目录结构

```
1-instruction-screening/
├── fast-filter/          # 快速过滤器
│   ├── ins_check.c       # 主要的指令检查程序
│   └── inst_testframe.c  # 指令测试框架
├── timeout-filter/       # 超时过滤器
│   ├── dispatcher.c      # 任务分发器
│   └── single_check.c    # 单指令检查
└── results_A32/         # ARM32筛选结果存储
```

## 工作原理

### 快速过滤器 (fast-filter)

**核心功能：**
- 使用信号处理机制捕获非法指令异常
- 通过mmap创建可执行内存页面
- 实时执行和测试ARM32指令
- 将结果保存为高效的bitmap格式

**主要特性：**
- **信号恢复**：捕获SIGSEGV、SIGILL、SIGTRAP、SIGBUS等异常信号
- **内存保护**：使用独立的信号处理栈
- **高效存储**：bitmap压缩存储筛选结果
- **区间处理**：支持指令区间分割和并行处理

### 超时过滤器 (timeout-filter)

**核心功能：**
- 处理可能导致程序挂起的指令
- 使用进程隔离和超时机制
- 分发任务到多个工作进程

## 编译和使用

### 编译快速过滤器
```bash
cd fast-filter
gcc -o ins_check ins_check.c -static
```

### 编译测试框架
```bash
gcc -o inst_testframe inst_testframe.c
```

### 编译超时过滤器
```bash
cd timeout-filter
gcc -o dispatcher dispatcher.c
gcc -o single_check single_check.c
```

## 使用方法

### 基本指令筛选
```bash
# 筛选指定区间的指令
./ins_check -s 0x00000000 -e 0x0000FFFF

# 使用环境变量指定结果文件编号
export RESULT_FILE_NUMBER=1
./ins_check -f input_ranges.txt
```

### 参数说明
- `-s <start>`: 指定起始指令编码
- `-e <end>`: 指定结束指令编码  
- `-f <file>`: 从文件读取指令区间
- 环境变量 `RESULT_FILE_NUMBER`: 设置输出文件编号

## 输出格式

筛选结果保存为二进制bitmap文件：
```
bitmap_results/resN_complete.bin
```

文件格式：
1. 文件头：文件编号、区间数量
2. 每个区间：起始地址、结束地址、bitmap大小、bitmap数据

## 性能优化

- **并行处理**：支持将指令空间分割到多个进程
- **内存映射**：使用mmap优化内存访问
- **信号优化**：专用信号处理栈减少开销
- **缓存优化**：指令缓存清理确保执行正确性

## 安全注意事项

⚠️ **重要警告**：
- 本工具会执行未知的机器码，存在系统风险
- 建议在虚拟机或容器中运行
- 确保有足够的系统权限和资源
- 运行前备份重要数据

## 故障排除

### 常见问题
1. **段错误过多**：调整 `SIGSEGV_THRESHOLD` 阈值
2. **内存不足**：减少处理区间大小
3. **权限问题**：确保有执行权限和内存映射权限

### 调试选项
代码中包含调试输出，可以通过取消注释相关代码来启用详细日志。 