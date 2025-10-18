#!/bin/bash

echo "开始批量提取可执行指令区间..."
echo "=========================================="

# 计数器
total=0
success=0
failed=0

# 创建输出目录
mkdir -p extracted_instructions

# 处理所有非空的bitmap文件
for file in bitmap_results/*_complete.bin; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        filename=$(basename "$file")
        echo -n "处理 $filename ... "
        
        if ./batch_extract "$file" >/dev/null 2>&1; then
            echo "✓"
            ((success++))
        else
            echo "✗"
            ((failed++))
        fi
        ((total++))
    fi
done

echo "=========================================="
echo "处理完成！"
echo "总文件数: $total"
echo "成功: $success"
echo "失败: $failed"
echo ""
echo "生成的文件:"
ls -lh extracted_instructions/*.txt 2>/dev/null | head -10
echo ""
echo "所有提取的指令区间已保存在 extracted_instructions/ 目录中"
echo "文件格式: [起始地址, 结束地址]" 