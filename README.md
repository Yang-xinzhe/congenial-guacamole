# ARM32 指令分析工具集

这是一个用于分析ARM32架构隐藏指令的综合工具集，通过多阶段的筛选、提取和分析流程，识别和研究ARM32处理器中的隐藏指令特性。

## 项目结构

```
congenial-guacamole/
├── 1-instruction-screening/    # 指令筛选阶段
│   ├── fast-filter/           # 快速过滤器
│   ├── timeout-filter/        # 超时过滤器
│   └── results_A32/          # ARM32筛选结果
├── 2-result-extraction/       # 结果提取阶段
├── 3-instruction-analysis/    # 指令分析阶段
│   ├── pmu-analysis/         # 性能监控单元分析
│   └── register-analysis/    # 寄存器状态分析
└── README.md                 # 本文件
```

## 工作流程

### 第一阶段：指令筛选 (1-instruction-screening)
对ARM32指令集进行大规模筛选，识别能够成功执行的隐藏指令：
- **快速过滤器**：基于信号处理的快速指令验证
- **超时过滤器**：处理可能导致程序挂起的指令
- 生成bitmap格式的筛选结果

### 第二阶段：结果提取 (2-result-extraction)
从bitmap结果中提取可执行指令的连续区间：
- 解析筛选阶段生成的二进制bitmap文件
- 提取可执行指令并合并为连续区间
- 导出为文本格式的指令区间列表

### 第三阶段：指令分析 (3-instruction-analysis)
对发现的隐藏指令进行深入分析：
- **PMU分析**：性能计数器和微架构行为分析
- **寄存器分析**：指令执行前后的寄存器状态变化

## 快速开始

1. **编译筛选工具**：
   ```bash
   cd 1-instruction-screening/fast-filter
   gcc -o ins_check ins_check.c
   ```

2. **运行指令筛选**：
   ```bash
   ./ins_check [参数]
   ```

3. **提取结果**：
   ```bash
   cd 2-result-extraction
   gcc -o batch_extract batch_extract.c
   ./extract_all_simple.sh
   ```

4. **分析指令**：
   ```bash
   cd 3-instruction-analysis/register-analysis
   gcc -o reg_compare reg_compare.c
   ```

## 技术特点

- **并行处理**：支持大规模指令集的并行筛选
- **错误恢复**：基于信号处理的错误指令恢复机制
- **高效存储**：使用bitmap压缩存储筛选结果
- **深度分析**：多维度的指令行为分析

## 注意事项

- 本工具集专门针对ARM32架构设计
- 需要在支持ARM32的环境中运行
- 部分功能需要特殊权限（如PMU访问）
- 建议在隔离环境中运行筛选程序

## 贡献

欢迎提交Issues和Pull Requests来改进这个工具集。

## 许可证

本项目基于开源许可证发布，具体许可证信息请查看LICENSE文件。 