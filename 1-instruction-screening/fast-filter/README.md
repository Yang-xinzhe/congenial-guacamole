# 快速过滤器

快速过滤器是指令筛选阶段的核心组件，通过信号处理机制高效识别可执行的ARM32指令。

## 文件说明

- **`ins_check.c`** - 主要的指令检查程序，核心筛选逻辑
- **`inst_testframe.c`** - 指令测试框架，提供测试环境

## ins_check.c 功能详解

### 核心机制
基于信号处理的指令验证：
```c
// 信号处理流程
执行指令 → 触发异常 → 信号处理器 → 跳过指令 → 记录结果
```

### 主要特性

#### 1. 内存管理
- 使用 `mmap()` 创建可执行内存页面
- 动态复制指令模板到执行区域
- 自动内存清理和缓存管理

#### 2. 信号处理
支持多种异常信号：
- `SIGSEGV` - 段错误（访问无效内存）
- `SIGILL` - 非法指令
- `SIGTRAP` - 调试陷阱
- `SIGBUS` - 总线错误

#### 3. Bitmap存储
高效的结果存储格式：
- 1位表示1个指令的可执行状态
- 支持大规模指令空间的压缩存储
- 按区间组织数据便于并行处理

### 编译选项
```bash
# 基本编译
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -o ins_check ins_check.c

# 静态链接（推荐）
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -o ins_check ins_check.c -static

# 调试版本
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -g -O0 -o ins_check ins_check.c -DDEBUG
```

### 使用方法

#### 命令行参数
```bash
# 指定指令区间
./ins_check -s 0x00000000 -e 0x0000FFFF

# 从文件读取区间
./ins_check -f ranges.txt

# 设置结果文件编号
export RESULT_FILE_NUMBER=1
./ins_check -f ranges.txt
```

#### 区间文件格式
```
0x00000000 0x0000FFFF
0x10000000 0x1000FFFF
0x20000000 0x2000FFFF
```

### 输出格式

#### Bitmap文件结构
```
文件头:
├── file_number (4字节) - 文件编号
└── range_count (4字节) - 区间数量

每个区间:
├── start (4字节) - 起始地址
├── end (4字节) - 结束地址  
├── bitmap_size (4字节) - bitmap大小
└── bitmap (变长) - 实际bitmap数据
```

#### 统计输出
程序运行时显示：
```
处理区间: [0x00000000, 0x0000FFFF]
SIGSEGV: 1234, SIGILL: 5678, SIGTRAP: 90, SIGBUS: 12
可执行指令: 3456, 总指令数: 65536
```

### 性能优化

#### 内存优化
- 使用专用信号栈避免栈溢出
- 动态分配bitmap减少内存浪费
- 及时释放临时资源

#### 执行优化
- 内联汇编减少函数调用开销
- 缓存清理确保指令执行正确性
- 信号处理器中最小化处理逻辑

### 安全机制

#### 异常恢复
```c
// 信号处理器中的PC调整
uc->uc_mcontext.arm_pc = insn_skip;
```

#### 阈值保护
```c
#define SIGSEGV_THRESHOLD 10
// 连续异常过多时自动退出
```

#### 执行隔离
- 独立的可执行内存页面
- 信号处理栈隔离
- 寄存器状态保护

### 调试和监控

#### 调试输出
取消注释调试代码可启用详细输出：
```c
// printf("执行指令: 0x%08x\n", insn);
// printf("信号: %s\n", strsignal(sig_num));
```

#### 运行时监控
- 实时显示处理进度
- 异常计数统计
- 性能指标监控

### 已知限制

1. **架构依赖**：专门为ARM32设计
2. **权限要求**：需要创建可执行内存的权限
3. **信号限制**：某些系统信号无法捕获
4. **内存限制**：大型指令空间可能内存不足

### 故障排除

#### 常见错误
```bash
# 权限错误
Error: mmap failed: Permission denied
解决: 检查系统权限设置

# 内存不足
Error: calloc result bitmap failed
解决: 减少处理区间大小

# 信号处理错误
Error: Signal handler setup failed
解决: 检查系统信号配置
```

#### 性能调优
- 调整 `SIGSEGV_THRESHOLD` 适应不同环境
- 根据系统内存调整处理区间大小
- 使用静态链接避免库依赖问题 