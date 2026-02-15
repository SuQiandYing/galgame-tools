"""
repack_op.py - 将视频文件回封为 op.ypf (Yu-Ris 引擎 OP 视频)

用法:
  python repack_op.py [输入视频] [输出文件]

说明:
  - 原始 op.ypf 没有封包结构，就是裸视频数据用 .ypf 扩展名
  - 如果输入是 MP4/H265，会自动调用 FFmpeg 转码为 MPEG-1 PS 格式
  - 如果输入已经是 MPEG PS 格式，直接复制
  - 自动备份原始 op.ypf
"""

import os
import sys
import shutil
import subprocess
import struct

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
FFMPEG = os.path.join(WORK_DIR, "ffmpeg.exe")

def is_mpeg_ps(filepath):
    """检查文件是否为 MPEG Program Stream"""
    with open(filepath, "rb") as f:
        header = f.read(4)
        return header == b'\x00\x00\x01\xba'

def transcode_to_mpeg1(input_path, output_path):
    """将视频转码为 MPEG-1 PS 格式 (Yu-Ris 兼容)"""
    if not os.path.exists(FFMPEG):
        print(f"错误: 找不到 FFmpeg: {FFMPEG}")
        print("请将 ffmpeg.exe 放在脚本同目录下")
        sys.exit(1)

    cmd = [
        FFMPEG, "-y", "-i", input_path,
        "-c:v", "mpeg1video",
        "-b:v", "15000k",
        "-maxrate", "15000k",
        "-bufsize", "2000k",
        "-g", "15",
        "-bf", "2",
        "-s", "1280x720",
        "-r", "30",
        "-pix_fmt", "yuv420p",
        "-c:a", "mp2",
        "-b:a", "128k",
        "-ar", "48000",
        "-ac", "2",
        "-f", "vob",
        output_path
    ]

    print(f"正在转码: {os.path.basename(input_path)} -> {os.path.basename(output_path)}")
    print("编码: mpeg1video 15Mbps / mp2 128kbps / 1280x720 30fps")
    print("请等待...")

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        print(f"FFmpeg 错误:\n{result.stderr[-500:].decode('utf-8', errors='replace')}")
        sys.exit(1)

    size = os.path.getsize(output_path)
    print(f"转码完成: {size / 1024 / 1024:.1f} MB")

def main():
    # 默认路径
    default_input = os.path.join(WORK_DIR, "op_extracted.mpg")
    default_output = os.path.join(WORK_DIR, "op_new.ypf")

    input_path = sys.argv[1] if len(sys.argv) > 1 else default_input
    output_path = sys.argv[2] if len(sys.argv) > 2 else default_output

    if not os.path.exists(input_path):
        print(f"错误: 输入文件不存在: {input_path}")
        sys.exit(1)

    # 备份原始 op.ypf
    op_path = os.path.join(WORK_DIR, "op.ypf")
    backup_path = os.path.join(WORK_DIR, "op_original_backup.ypf")
    if os.path.exists(op_path) and not os.path.exists(backup_path):
        shutil.copy2(op_path, backup_path)
        print(f"已备份: op.ypf -> op_original_backup.ypf")

    # 判断输入格式
    if is_mpeg_ps(input_path):
        # 已经是 MPEG PS，直接复制
        print(f"输入已是 MPEG PS 格式，直接复制")
        shutil.copy2(input_path, output_path)
    else:
        # 需要转码
        print(f"输入不是 MPEG PS 格式，需要转码为 MPEG-1 PS")
        transcode_to_mpeg1(input_path, output_path)

    size = os.path.getsize(output_path)
    print(f"\n生成: {output_path} ({size / 1024 / 1024:.1f} MB)")
    print(f"使用方法: 将 {os.path.basename(output_path)} 重命名为 op.ypf 放回游戏目录")

if __name__ == "__main__":
    main()
