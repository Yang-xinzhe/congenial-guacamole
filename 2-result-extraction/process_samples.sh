#!/bin/bash

echo "开始处理示例bitmap文件..."

# 选择几个有内容的文件进行演示
sample_files=(
    "res0_complete.bin"
    "res1_complete.bin" 
    "res6_complete.bin"
    "res14_complete.bin"
    "res22_complete.bin"
    "res30_complete.bin"
    "res102_complete.bin"
    "res103_complete.bin"
)

processed=0
failed=0

for file in "${sample_files[@]}"; do
    if [ -f "bitmap_results/$file" ] && [ -s "bitmap_results/$file" ]; then
        echo -n "处理 $file ... "
        if ./batch_extract "bitmap_results/$file"; then
            echo "✓"
            ((processed++))
        else
            echo "✗"
            ((failed++))
        fi
    else
        echo "跳过 $file (文件不存在或为空)"
        ((failed++))
    fi
done

echo ""
echo "========== 处理完成 =========="
echo "成功: $processed 个文件"
echo "失败: $failed 个文件"

echo ""
echo "生成的文件:"
ls -lh extracted_instructions/*.txt | while read -r line; do
    echo "  $line"
done 