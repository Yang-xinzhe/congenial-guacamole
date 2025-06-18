# 寄存器分析

寄存器分析模块通过对比指令执行前后的寄存器状态变化，深入分析ARM32隐藏指令的功能和行为。

## 文件说明

- **`reg_compare.c`** - 寄存器状态对比分析程序
- **`macro_analyzer.c`** - 宏指令行为分析器

## reg_compare.c 详解

### 核心功能
通过精确的寄存器状态快照，分析指令的具体作用：
1. 在固定地址(0x60000000)创建共享内存区域
2. 将所有寄存器初始化为模式值(0x55555555)  
3. 保存指令执行前的寄存器状态
4. 执行目标指令
5. 保存指令执行后的寄存器状态
6. 对比前后状态，识别变化

### 寄存器状态结构
```c
typedef struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;    // 特殊寄存器
    uint32_t cpsr;          // 状态寄存器
} RegisterStates;
```

### 内存布局
```
地址 0x60000000:
├── RegisterStates before[68字节]  - 执行前状态
└── RegisterStates after[68字节]   - 执行后状态
```

### 测试框架设计

#### 指令执行模板
使用内联汇编构建指令执行环境：
```asm
// 1. 初始化所有寄存器为0x55555555
mov r0, #0x55
orr r0, r0, r0, lsl #8   // r0 = 0x5555
orr r0, r0, r0, lsl #16  // r0 = 0x55555555
mov r1, r0               // 复制到其他寄存器
...

// 2. 保存执行前状态
push {r0-r12, lr}
ldr r0, =0x60000000      // 共享内存地址
// 保存寄存器值到内存

// 3. 执行目标指令
.global insn_location
insn_location:
nop                      // 占位符，运行时替换为目标指令

// 4. 保存执行后状态  
push {r0-r12, lr}
ldr r0, =0x60000000
add r0, r0, #68          // 偏移到after区域
// 保存寄存器值到内存
```

### 编译和使用

#### 编译
```bash
# 基本编译
gcc -o reg_compare reg_compare.c

# 静态链接（推荐）
gcc -o reg_compare reg_compare.c -static

# 调试版本
gcc -g -O0 -o reg_compare reg_compare.c
```

#### 基本使用
```bash
# 分析单个指令
./reg_compare 0xE3A03055

# 指令含义: mov r3, #0x55
# 预期结果: r3寄存器从0x55555555变为0x00000055
```

### 分析输出示例

#### 正常指令分析
```
分析指令: 0xE3A03055 (mov r3, #0x55)

执行前寄存器状态:
R0=0x55555555  R1=0x55555555  R2=0x55555555  R3=0x55555555
R4=0x55555555  R5=0x55555555  R6=0x55555555  R7=0x55555555
R8=0x55555555  R9=0x55555555  R10=0x55555555 R11=0x55555555
R12=0x55555555 SP=0x7FFE1234  LR=0x55555555  PC=0x12345678
CPSR=0x60000010

执行后寄存器状态:
R0=0x55555555  R1=0x55555555  R2=0x55555555  R3=0x00000055  ✓
R4=0x55555555  R5=0x55555555  R6=0x55555555  R7=0x55555555
R8=0x55555555  R9=0x55555555  R10=0x55555555 R11=0x55555555
R12=0x55555555 SP=0x7FFE1234  LR=0x55555555  PC=0x1234567C
CPSR=0x60000010

检测到的变化:
✓ R3: 0x55555555 → 0x00000055 (立即数加载)
✓ PC: 0x12345678 → 0x1234567C (正常递增)

指令功能: 将立即数0x55加载到寄存器R3
```

#### 异常指令分析
```
分析指令: 0xFFFFFFFF (未知指令)

执行结果: 指令执行异常
异常类型: SIGILL (非法指令)
寄存器状态: 未发生变化（指令未执行）
```

### 技术实现细节

#### 内存管理
```c
// 创建共享内存
int shmid = shmget(IPC_PRIVATE, sizeof(RegisterStates) * 2, IPC_CREAT | 0666);
void *res = shmat(shmid, (void *)0x60000000, 0);
```

#### 指令替换
```c
// 动态替换指令模板中的目标指令
memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
__clear_cache(insn_page + (insn_offset-1) * 4, 
              insn_page + insn_offset * 4 + insn_length);
```

#### 状态保护
- 使用栈保护防止寄存器被覆盖
- DSB指令确保内存操作顺序
- 缓存清理确保指令更新生效

### 应用场景

#### 1. 指令功能识别
```bash
# 分析数据传输指令
./reg_compare 0xE1A03000  # mov r3, r0
# 预期: r3 = r0的值

# 分析算术指令  
./reg_compare 0xE0834000  # add r4, r3, r0
# 预期: r4 = r3 + r0

# 分析逻辑指令
./reg_compare 0xE0034000  # and r4, r3, r0  
# 预期: r4 = r3 & r0
```

#### 2. 隐藏指令研究
```bash
# 分析未文档化的指令编码
./reg_compare 0xE1234567  # 未知指令
# 观察是否有寄存器变化，推测功能
```

#### 3. 状态标志分析
```bash
# 分析影响CPSR的指令
./reg_compare 0xE3130001  # 测试指令
# 观察CPSR标志位变化(N,Z,C,V)
```

### 批量分析支持

#### 指令列表文件
创建包含多个指令的文件：
```
0xE3A03055
0xE1A04000  
0xE0835000
0xE1234567
```

#### 批量处理脚本
```bash
#!/bin/bash
while read instruction; do
    echo "分析指令: $instruction"
    ./reg_compare "$instruction"
    echo "---"
done < instruction_list.txt
```

### 高级功能

#### 条件执行分析
ARM32指令支持条件执行，可以分析条件码：
```bash
# 分析条件执行指令
./reg_compare 0x03A03055  # moveq r3, #0x55 (仅在Z=1时执行)
```

#### 状态变化模式识别
通过多次运行识别指令的一致性行为：
```bash
# 多次执行同一指令验证结果一致性
for i in {1..10}; do
    ./reg_compare 0xE3A03055
done
```

### 限制和注意事项

#### 系统限制
1. **地址冲突**：0x60000000地址必须可用
2. **权限要求**：需要共享内存创建权限
3. **架构依赖**：仅支持ARM32架构

#### 分析限制  
1. **内存访问指令**：无法准确分析访问外部内存的指令
2. **系统调用**：无法分析触发系统调用的指令
3. **异常指令**：异常指令无法获得正常的执行后状态

### 故障排除

#### 常见问题
```bash
# 共享内存失败
Error: shmget failed: No space left on device
解决: 清理系统共享内存或调整参数

# 地址映射失败  
Error: shmat failed: Cannot allocate memory
解决: 检查0x60000000地址是否被占用

# 指令执行异常
Error: Instruction caused exception
解决: 正常现象，表示指令不可执行
```

#### 调试建议
- 启用调试输出查看详细执行流程
- 使用已知指令验证分析框架正确性
- 检查内存布局确保数据正确性 