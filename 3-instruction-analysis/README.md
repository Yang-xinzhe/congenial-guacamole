# 指令分析阶段

这个目录包含对发现的ARM32隐藏指令进行深入分析的工具，从微架构和寄存器状态两个维度研究指令行为。

## 目录结构

```
3-instruction-analysis/
├── pmu-analysis/         # 性能监控单元分析
│   └── pmu_test.c       # PMU性能计数器测试
└── register-analysis/    # 寄存器状态分析
    ├── reg_compare.c    # 寄存器对比分析
    └── macro_analyzer.c # 宏指令分析器
```

## 分析维度

### 1. 性能监控单元分析 (PMU Analysis)
通过ARM处理器的性能监控单元(PMU)分析指令的微架构行为：
- **指令计数**：分析指令执行次数和类型
- **缓存行为**：监控L1/L2缓存命中率
- **分支预测**：统计分支指令的预测准确性
- **流水线效率**：测量指令流水线的停顿和效率

### 2. 寄存器状态分析 (Register Analysis)
分析指令执行前后的寄存器状态变化：
- **通用寄存器**：R0-R12的值变化
- **状态寄存器**：CPSR标志位的变化  
- **堆栈指针**：SP寄存器的变化
- **程序计数器**：PC寄存器的行为

## 工作原理

### 寄存器状态分析流程
1. **状态初始化**：将所有寄存器设置为已知模式值(0x55555555)
2. **执行前快照**：保存指令执行前的寄存器状态
3. **指令执行**：在隔离环境中执行目标指令
4. **执行后快照**：保存指令执行后的寄存器状态
5. **差异分析**：对比前后状态，识别变化模式

### 内存共享机制
使用System V共享内存在固定地址(0x60000000)存储寄存器状态：
```c
typedef struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;
    uint32_t cpsr;
} RegisterStates;
```

## 编译和使用

### 编译寄存器分析工具
```bash
cd register-analysis
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -o reg_compare reg_compare.c -static
```

### 编译PMU分析工具
```bash
cd pmu-analysis
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -o pmu_test pmu_test.c
```

### 编译宏分析器
```bash
cd register-analysis
arm-linux-gnueabihf-gcc -marm -march=armv8-a -mfpu=vfpv4 -fomit-frame-pointer -mfloat-abi=hard -o macro_analyzer macro_analyzer.c
```

## 使用方法

### 基本寄存器分析
```bash
# 分析单个指令
./reg_compare 0xE3A03055

# 批量分析指令文件
./reg_compare -f instruction_list.txt
```

### PMU性能分析
```bash
# 启动PMU监控
./pmu_test

# 需要特殊权限访问PMU
sudo ./pmu_test
```

## 分析输出

### 寄存器变化报告
程序输出指令执行前后的寄存器状态：
```
指令: 0xE3A03055
执行前状态:
  R0=0x55555555, R1=0x55555555, R2=0x55555555
  R3=0x55555555, R4=0x55555555, ...
  CPSR=0x60000010

执行后状态:
  R0=0x55555555, R1=0x55555555, R2=0x55555555
  R3=0x00000055, R4=0x55555555, ...
  CPSR=0x60000010

变化检测:
  R3: 0x55555555 → 0x00000055 (发生变化)
```

### PMU计数器数据
```
指令执行统计:
  总指令数: 1024
  分支指令: 128
  缓存命中率: 95.2%
  流水线停顿: 12个周期
```

## 技术特性

### 高精度测量
- **原子操作**：确保测量过程不被中断
- **缓存控制**：清理指令缓存确保执行正确性
- **内存屏障**：使用DSB指令确保内存操作顺序
- **状态隔离**：避免测量过程影响目标指令

### 错误处理
- **信号捕获**：处理可能的异常指令
- **状态恢复**：异常后恢复到安全状态
- **资源清理**：自动清理共享内存和其他资源

### 可扩展性
- **模块化设计**：分析组件可独立使用
- **批处理支持**：支持大规模指令分析
- **输出格式化**：多种输出格式适应不同需求

## 应用场景

### 指令功能推测
通过寄存器变化模式推测隐藏指令的功能：
- **数据传输指令**：观察寄存器间的数据复制
- **运算指令**：分析数值计算结果和状态标志
- **控制指令**：监控程序流程和分支行为

### 微架构研究
通过PMU数据研究处理器内部行为：
- **执行单元使用**：识别指令使用的功能单元
- **性能瓶颈**：发现性能限制因素
- **优化策略**：为代码优化提供指导

## 限制和注意事项

### 权限要求
- **PMU访问**：需要内核权限访问性能计数器
- **内存映射**：需要创建可执行内存页面的权限
- **信号处理**：需要注册系统信号处理程序

### 环境依赖
- **ARM32架构**：专门为ARM32处理器设计
- **Linux系统**：依赖Linux的内存管理和信号机制
- **硬件支持**：PMU功能需要硬件支持

### 安全考虑
⚠️ **警告**：分析过程会执行未知指令，建议在隔离环境中运行。

## 故障排除

### 常见问题
1. **共享内存失败**：检查系统共享内存限制
2. **PMU访问被拒绝**：确保有足够权限或使用sudo
3. **指令执行异常**：检查目标指令是否有效
4. **内存地址冲突**：确保0x60000000地址可用

### 调试技巧
- 启用调试输出查看详细执行过程
- 使用简单的已知指令验证分析框架
- 检查寄存器初始化是否正确 