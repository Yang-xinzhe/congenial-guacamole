# 结果提取阶段

这个目录包含用于从指令筛选阶段生成的bitmap结果中提取可执行指令区间的工具。

## 目录结构

```
2-result-extraction/
├── batch_extract.c         # 批量提取程序
├── filter.c               # 过滤器程序
├── extract_all_simple.sh  # 批量提取脚本
└── process_samples.sh     # 样本处理脚本
```

## 工作原理

### 核心功能
- 解析第一阶段生成的二进制bitmap文件
- 提取其中标记为可执行的指令
- 将连续的可执行指令合并为区间
- 导出为易于分析的文本格式

### 数据流程
```
bitmap_results/*.bin → 解析 → 提取 → 合并 → extracted_instructions/*.txt
```

## 编译程序

### 编译批量提取工具
```bash
gcc -o batch_extract batch_extract.c
```

### 编译过滤器
```bash
gcc -o filter filter.c
```

## 使用方法

### 方法一：使用自动化脚本（推荐）
```bash
# 批量处理所有bitmap文件
./extract_all_simple.sh
```

脚本会自动：
1. 扫描 `bitmap_results/` 目录中的所有 `*_complete.bin` 文件
2. 对每个文件调用 `batch_extract` 程序
3. 在 `extracted_instructions/` 目录生成对应的文本文件
4. 显示处理统计信息

### 方法二：手动处理单个文件
```bash
# 处理单个bitmap文件
./batch_extract bitmap_results/res1_complete.bin

# 查看生成的结果
cat extracted_instructions/res1_ranges.txt
```

## 输入格式

### Bitmap文件格式
输入的二进制文件包含：
1. **文件头** (8字节)：
   - `file_number` (4字节)：文件编号
   - `range_count` (4字节)：区间数量

2. **每个区间的数据**：
   - `start` (4字节)：区间起始地址
   - `end` (4字节)：区间结束地址  
   - `bitmap_size` (4字节)：bitmap数据大小
   - `bitmap` (变长)：实际的bitmap数据

## 输出格式

### 指令区间文件
生成的文本文件格式为：
```
[起始地址, 结束地址]
[起始地址, 结束地址]
...
```

示例：
```
[0x12345678, 0x12345680]
[0x12345690, 0x123456A0]
[0x123456B0, 0x123456C0]
```

**注意**：输出使用右开区间格式 `[start, end)`，即包含起始地址但不包含结束地址。

## 功能特性

### 区间合并算法
- 自动识别连续的可执行指令
- 将相邻指令合并为连续区间
- 最大化区间利用率，减少碎片

### 统计信息
程序运行时会显示：
- 处理的文件数量
- 成功/失败统计
- 提取的区间数量
- 可执行指令总数

### 内存管理
- 动态内存分配适应不同大小的bitmap
- 自动清理临时数据
- 支持大型dataset的处理

## 使用示例

### 完整工作流程
```bash
# 1. 确保有bitmap输入文件
ls bitmap_results/

# 2. 编译提取工具
gcc -o batch_extract batch_extract.c

# 3. 运行批量提取
./extract_all_simple.sh

# 4. 查看结果
ls -lh extracted_instructions/
head extracted_instructions/res1_ranges.txt
```

### 处理特定文件
```bash
# 只处理特定编号的文件
./batch_extract bitmap_results/res5_complete.bin

# 查看提取统计
wc -l extracted_instructions/res5_ranges.txt
```

## 性能优化

- **流式处理**：逐区间处理，减少内存占用
- **位运算优化**：高效的bitmap解析算法
- **批量I/O**：减少文件访问开销
- **内存复用**：重复利用缓冲区

## 故障排除

### 常见问题

1. **文件格式错误**
   ```
   错误：读取文件头失败
   解决：检查输入文件是否为有效的bitmap格式
   ```

2. **内存不足**
   ```
   错误：分配内存失败
   解决：减少处理的文件大小或增加系统内存
   ```

3. **权限问题**
   ```
   错误：无法创建输出文件
   解决：检查输出目录权限，确保可写
   ```

### 验证结果
```bash
# 检查提取结果的完整性
for file in extracted_instructions/*.txt; do
    echo "文件: $file"
    echo "区间数量: $(wc -l < "$file")"
    echo "格式检查: $(head -1 "$file")"
    echo "---"
done
```

## 输出目录结构

```
extracted_instructions/
├── res1_ranges.txt    # 文件1的指令区间
├── res2_ranges.txt    # 文件2的指令区间
├── res3_ranges.txt    # 文件3的指令区间
└── ...               # 其他文件的区间
```

每个文件对应第一阶段中一个并行处理任务的结果。 