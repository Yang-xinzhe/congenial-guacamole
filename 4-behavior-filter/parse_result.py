#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARM指令行为分析结果解析器
解析result.bin文件并生成CSV格式的分析报告
"""

import struct
import csv
import argparse
import sys
from pathlib import Path

# 二进制文件格式定义
FMT = "<II"  # opcode:uint32, behavior:uint32 (小端序)
ENTRY_SIZE = struct.calcsize(FMT)

def decode_behavior(behavior):
    """解码behavior字段"""
    result = {}
    
    # 基础行为分类 (bit 0-7)
    result['has_load'] = bool(behavior & (1 << 0))
    result['has_store'] = bool(behavior & (1 << 1))
    result['reg_changed'] = bool(behavior & (1 << 2))
    result['sp_lr_changed'] = bool(behavior & (1 << 3))
    result['cpsr_safe'] = bool(behavior & (1 << 4))
    result['cpsr_suspicious'] = bool(behavior & (1 << 5))
    result['cpsr_dangerous'] = bool(behavior & (1 << 6))
    result['cpsr_critical'] = bool(behavior & (1 << 7))
    
    # 寄存器变化详情 (bit 8-20, 13 bit)
    changed_regs = (behavior >> 8) & 0x1FFF
    result['changed_regs_bitmap'] = changed_regs
    
    # SP/LR 变化详情 (bit 21-22)
    result['sp_changed'] = bool(behavior & (1 << 21))
    result['lr_changed'] = bool(behavior & (1 << 22))
    
    # CPSR 安全级别 (bit 23-24)
    security_level = (behavior >> 23) & 0x3
    security_names = ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'CRITICAL']
    result['security_level'] = security_names[security_level]
    
    # 异常信号类型 (bit 25-28)
    signal_type = (behavior >> 25) & 0xF
    signal_names = {
        0: 'NONE',
        1: 'SIGILL',
        2: 'SIGSEGV', 
        3: 'SIGBUS',
        4: 'SIGTRAP',
        15: 'OTHER'
    }
    result['signal'] = signal_names.get(signal_type, f'UNKNOWN({signal_type})')
    
    return result

def classify_instruction(opcode, behavior_info):
    """对指令进行分类"""
    categories = []
    
    # 访存类
    if behavior_info['has_load'] or behavior_info['has_store']:
        if behavior_info['has_load'] and behavior_info['has_store']:
            categories.append('访存(读写)')
        elif behavior_info['has_load']:
            categories.append('访存(读)')
        elif behavior_info['has_store']:
            categories.append('访存(写)')
    
    # 计算类
    if behavior_info['reg_changed']:
        categories.append('计算')
    
    # 标志更改类 - 修复：只有真正有CPSR变化时才算标志更改
    if any([behavior_info['cpsr_safe'], behavior_info['cpsr_suspicious'], 
            behavior_info['cpsr_dangerous'], behavior_info['cpsr_critical']]):
        categories.append('标志更改')
    
    # 控制类
    if behavior_info['sp_lr_changed']:
        categories.append('控制')
    
    # 异常类
    if behavior_info['signal'] != 'NONE':
        categories.append('异常')
    
    return categories if categories else ['无行为']

def get_changed_registers(bitmap):
    """获取变化的寄存器列表"""
    changed = []
    for i in range(13):  # R0-R12
        if bitmap & (1 << i):
            changed.append(f'R{i}')
    return ','.join(changed) if changed else '无'

def parse_result_file(bin_path, csv_path):
    """解析result.bin文件并生成CSV"""
    
    if not Path(bin_path).exists():
        print(f"错误: 文件 {bin_path} 不存在")
        return False
    
    results = []
    
    try:
        with open(bin_path, "rb") as f:
            entry_count = 0
            while chunk := f.read(ENTRY_SIZE):
                if len(chunk) != ENTRY_SIZE:
                    print(f"警告: 文件末尾数据不完整，跳过 {len(chunk)} 字节")
                    break
                
                opcode, behavior = struct.unpack(FMT, chunk)
                behavior_info = decode_behavior(behavior)
                categories = classify_instruction(opcode, behavior_info)
                
                # 构建CSV行数据
                row = {
                    '指令': f'0x{opcode:08X}',
                    '分类': ';'.join(categories),
                    '访存类型': '',
                    '计算类型': '',
                    '标志更改': '',
                    '安全性': behavior_info['security_level'],
                    '变化寄存器': get_changed_registers(behavior_info['changed_regs_bitmap']),
                    'SP变化': '是' if behavior_info['sp_changed'] else '否',
                    'LR变化': '是' if behavior_info['lr_changed'] else '否',
                    '异常信号': behavior_info['signal'],
                    '原始behavior': f'0x{behavior:08X}'
                }
                
                # 细化访存类型
                if behavior_info['has_load'] and behavior_info['has_store']:
                    row['访存类型'] = '读写'
                elif behavior_info['has_load']:
                    row['访存类型'] = '读'
                elif behavior_info['has_store']:
                    row['访存类型'] = '写'
                else:
                    row['访存类型'] = '无'
                
                # 计算类型（基于寄存器变化）
                if behavior_info['reg_changed']:
                    reg_count = bin(behavior_info['changed_regs_bitmap']).count('1')
                    if reg_count == 1:
                        row['计算类型'] = '单寄存器'
                    elif reg_count <= 3:
                        row['计算类型'] = '少量寄存器'
                    else:
                        row['计算类型'] = '多寄存器'
                else:
                    row['计算类型'] = '无'
                
                # 标志更改类型 - 修复：只有真正有CPSR变化时才显示
                if any([behavior_info['cpsr_safe'], behavior_info['cpsr_suspicious'], 
                        behavior_info['cpsr_dangerous'], behavior_info['cpsr_critical']]):
                    row['标志更改'] = behavior_info['security_level']
                else:
                    row['标志更改'] = '无'
                
                results.append(row)
                entry_count += 1
    
    except Exception as e:
        print(f"错误: 读取文件时发生异常: {e}")
        return False
    
    # 写入CSV文件
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['指令', '分类', '访存类型', '计算类型', '标志更改', '安全性', 
                         '变化寄存器', 'SP变化', 'LR变化', '异常信号', '原始behavior']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            writer.writerows(results)
            
        print(f"成功解析 {entry_count} 条指令记录")
        print(f"结果已保存到: {csv_path}")
        
        # 打印统计信息
        print_statistics(results)
        
    except Exception as e:
        print(f"错误: 写入CSV文件时发生异常: {e}")
        return False
    
    return True

def print_statistics(results):
    """打印统计信息"""
    total = len(results)
    if total == 0:
        return
    
    print(f"\n=== 统计信息 ===")
    print(f"总指令数: {total}")
    
    # 按分类统计
    category_stats = {}
    for result in results:
        categories = result['分类'].split(';')
        for cat in categories:
            category_stats[cat] = category_stats.get(cat, 0) + 1
    
    print("\n指令分类统计:")
    for cat, count in sorted(category_stats.items()):
        percentage = (count / total) * 100
        print(f"  {cat}: {count} ({percentage:.1f}%)")
    
    # 安全性统计
    security_stats = {}
    for result in results:
        sec = result['安全性']
        security_stats[sec] = security_stats.get(sec, 0) + 1
    
    print("\n安全性统计:")
    for sec, count in sorted(security_stats.items()):
        percentage = (count / total) * 100
        print(f"  {sec}: {count} ({percentage:.1f}%)")
    
    # 异常统计
    signal_stats = {}
    for result in results:
        sig = result['异常信号']
        if sig != 'NONE':
            signal_stats[sig] = signal_stats.get(sig, 0) + 1
    
    if signal_stats:
        print("\n异常信号统计:")
        for sig, count in sorted(signal_stats.items()):
            percentage = (count / total) * 100
            print(f"  {sig}: {count} ({percentage:.1f}%)")

def main():
    parser = argparse.ArgumentParser(description='ARM指令行为分析结果解析器')
    parser.add_argument('input', help='输入的result.bin文件路径')
    parser.add_argument('-o', '--output', help='输出的CSV文件路径 (默认: result.csv)')
    
    args = parser.parse_args()
    
    input_path = args.input
    output_path = args.output or 'result.csv'
    
    print(f"解析文件: {input_path}")
    print(f"输出文件: {output_path}")
    
    success = parse_result_file(input_path, output_path)
    
    if success:
        print(f"\n解析完成! 可以用Excel或其他工具打开 {output_path} 查看结果")
        return 0
    else:
        print("解析失败!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 