"""字节级比较与 hex diff，用于往返验证。"""
from __future__ import annotations

from .hashing import fingerprint_bytes
from .types import SourceArtifact, VerifyReport

CONTEXT = 16


def compare_bytes(original: bytes, rebuilt: bytes, *,
                  original_path: str = "", rebuilt_path: str = "",
                  max_diffs: int = 24) -> VerifyReport:
    """比较两个缓冲区并定位第一处差异。"""
    o_sha, o_md5, o_crc = fingerprint_bytes(original)
    r_sha, r_md5, r_crc = fingerprint_bytes(rebuilt)
    report = VerifyReport(
        identical=original == rebuilt,
        original=SourceArtifact(original_path, len(original), o_sha, o_md5, o_crc),
        rebuilt=SourceArtifact(rebuilt_path, len(rebuilt), r_sha, r_md5, r_crc),
    )
    if report.identical:
        report.notes.append(
            f"逐字节一致：{len(original)} 字节，sha256={o_sha}")
        return report

    if len(original) != len(rebuilt):
        report.notes.append(
            f"长度不同：原件={len(original)} 重建={len(rebuilt)} "
            f"({len(rebuilt) - len(original):+d})")
    limit = min(len(original), len(rebuilt))
    first = next((i for i in range(limit) if original[i] != rebuilt[i]), limit)
    report.first_diff_offset = first
    if first < limit:
        report.expected_byte = original[first]
        report.actual_byte = rebuilt[first]
    shown = 0
    for i in range(first, limit):
        if original[i] == rebuilt[i]:
            continue
        lo = max(0, i - CONTEXT)
        hi = min(limit, i + CONTEXT)
        report.hexdiff.append(
            f"@0x{i:08X} 期望 0x{original[i]:02X} 实际 0x{rebuilt[i]:02X}\n"
            f"  原件[{lo:#x}:{hi:#x}] {original[lo:hi].hex(' ')}\n"
            f"  重建[{lo:#x}:{hi:#x}] {rebuilt[lo:hi].hex(' ')}")
        shown += 1
        if shown >= max_diffs:
            report.notes.append(
                f"hex diff 在 {max_diffs} 处差异字节后截断")
            break
    return report


def hexdump(data: bytes, start: int, length: int = 128) -> str:
    """每行 16 字节的经典 hexdump，用于错误报告。"""
    lines = []
    end = min(len(data), start + length)
    for base in range(start, end, 16):
        chunk = data[base:base + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base:08X}  {hexpart}  |{text}|")
    return "\n".join(lines)
