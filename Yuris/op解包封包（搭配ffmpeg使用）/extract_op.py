"""
extract_op.py - 从 op.ypf 提取视频为可播放的 .mpg 文件

用法:
  python extract_op.py [输入.ypf] [输出.mpg]

说明:
  - Yu-Ris 引擎的 op.ypf 没有封包结构，就是裸 MPEG PS 视频数据
  - 提取就是直接复制并改扩展名为 .mpg
"""

import os
import sys
import shutil

WORK_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    default_input = os.path.join(WORK_DIR, "op.ypf")
    default_output = os.path.join(WORK_DIR, "op_extracted.mpg")

    input_path = sys.argv[1] if len(sys.argv) > 1 else default_input
    output_path = sys.argv[2] if len(sys.argv) > 2 else default_output

    if not os.path.exists(input_path):
        print(f"错误: 输入文件不存在: {input_path}")
        sys.exit(1)

    # 验证是 MPEG PS
    with open(input_path, "rb") as f:
        header = f.read(4)

    if header == b'\x00\x00\x01\xba':
        fmt = "MPEG Program Stream"
    else:
        fmt = f"未知格式 (header: {header.hex()})"
        print(f"警告: {fmt}，可能不是标准 MPEG PS")

    size = os.path.getsize(input_path)
    print(f"输入: {input_path}")
    print(f"格式: {fmt}")
    print(f"大小: {size / 1024 / 1024:.1f} MB")

    shutil.copy2(input_path, output_path)

    print(f"已提取: {output_path}")
    print("可以用任意播放器打开 .mpg 文件")

if __name__ == "__main__":
    main()
