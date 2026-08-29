"""指纹计算与原子写入辅助。

原件保持只读；每次写入都先写临时文件，刷新、fsync、校验之后再原子改名。
"""
from __future__ import annotations

import hashlib
import json
import os
import zlib
from pathlib import Path

from .types import SourceArtifact

BLOCK = 1 << 20


def fingerprint_bytes(data: bytes) -> tuple[str, str, int]:
    return (
        hashlib.sha256(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
        zlib.crc32(data) & 0xFFFFFFFF,
    )


def fingerprint_file(path: str | os.PathLike[str]) -> SourceArtifact:
    """以 O(BLOCK) 内存流式读取文件并返回其 SourceArtifact。"""
    p = Path(path)
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    crc = 0
    size = 0
    with p.open("rb") as fh:
        while chunk := fh.read(BLOCK):
            sha.update(chunk)
            md5.update(chunk)
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
    return SourceArtifact(
        path=str(p),
        byte_size=size,
        sha256=sha.hexdigest(),
        md5=md5.hexdigest(),
        crc32=crc & 0xFFFFFFFF,
    )


def sha256_range(data: bytes, start: int, end: int) -> str:
    return hashlib.sha256(data[start:end]).hexdigest()


def canonical_hash(obj: object) -> str:
    """对规范化结构做稳定哈希，用作 semantic_identity。"""
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def atomic_write(path: str | os.PathLike[str], data: bytes) -> None:
    """经临时文件 + fsync + 原子替换写入数据。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if tmp.stat().st_size != len(data):
        tmp.unlink(missing_ok=True)
        raise OSError(f"写入不完整：{p}")
    os.replace(tmp, p)


def atomic_write_text(path: str | os.PathLike[str], text: str,
                      encoding: str = "utf-8") -> None:
    atomic_write(path, text.encode(encoding))
