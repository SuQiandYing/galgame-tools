# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import os
import zlib
from pathlib import Path
from typing import Optional


def checksums(data: bytes) -> dict:
    return {
        "size": len(data),
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08X}",
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def file_checksums(path: Path) -> dict:
    h_md5 = hashlib.md5()
    h_sha = hashlib.sha256()
    crc = 0
    total = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            crc = zlib.crc32(chunk, crc)
            h_md5.update(chunk)
            h_sha.update(chunk)
    return {"size": total, "crc32": f"{crc & 0xFFFFFFFF:08X}", "md5": h_md5.hexdigest(), "sha256": h_sha.hexdigest()}


def first_diff(a: bytes, b: bytes) -> Optional[int]:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return n
    return None


def hexdump_window(data: bytes, center: int, radius: int = 64) -> str:
    start = max(0, center - radius)
    end = min(len(data), center + radius)
    lines = []
    for off in range(start, end, 16):
        chunk = data[off:off+16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{off:08X}  {hx:<47}  {asc}")
    return "\n".join(lines)


def verify_files(original: Path, rebuilt: Path, report_path: Path, hexdiff_path: Path) -> bool:
    a = original.read_bytes()
    b = rebuilt.read_bytes()
    ca = checksums(a)
    cb = checksums(b)
    diff = first_diff(a, b)
    ok = diff is None
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"original={original}",
        f"rebuilt={rebuilt}",
        f"[{'OK' if ca['size']==cb['size'] else 'FAIL'}] byte_size original={ca['size']} rebuilt={cb['size']}",
        f"[{'OK' if ca['crc32']==cb['crc32'] else 'FAIL'}] crc32 original={ca['crc32']} rebuilt={cb['crc32']}",
        f"[{'OK' if ca['md5']==cb['md5'] else 'FAIL'}] md5 original={ca['md5']} rebuilt={cb['md5']}",
        f"[{'OK' if ca['sha256']==cb['sha256'] else 'FAIL'}] sha256 original={ca['sha256']} rebuilt={cb['sha256']}",
        f"[{'OK' if diff is None else 'FAIL'}] first_diff_offset={('NONE' if diff is None else f'0x{diff:08X}')}",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if diff is None:
        hexdiff_path.write_text("[OK] no byte differences\n", encoding="utf-8")
    else:
        hexdiff_path.write_text(
            f"first_diff_offset=0x{diff:08X}\n\nEXPECTED original context:\n{hexdump_window(a, diff)}\n\nACTUAL rebuilt context:\n{hexdump_window(b, diff)}\n",
            encoding="utf-8",
        )
    return ok


def safe_relpath(name: str, fallback: str) -> str:
    clean = name.replace("\\", "/").lstrip("/")
    p = Path(clean)
    if not clean or ".." in p.parts:
        return fallback
    return clean


def ensure_clean_dir(path: Path) -> None:
    import shutil
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_stream(src: Path, dst_f, chunk_size: int = 1024 * 1024) -> int:
    total = 0
    with src.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            dst_f.write(chunk)
            total += len(chunk)
    return total
