from __future__ import annotations

import binascii
import hashlib
from pathlib import Path
from typing import BinaryIO


def hash_bytes(data: bytes) -> dict[str, str | int]:
    return {
        "size": len(data),
        "crc32": f"{binascii.crc32(data) & 0xFFFFFFFF:08X}",
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def hash_file(path: str | Path, chunk_size: int = 1024 * 1024) -> dict[str, str | int]:
    path = Path(path)
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    crc = 0
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha256.update(chunk)
    return {
        "path": str(path),
        "size": size,
        "crc32": f"{crc & 0xFFFFFFFF:08X}",
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
