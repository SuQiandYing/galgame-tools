from __future__ import annotations

import struct
from pathlib import Path


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: str | Path, data: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def u32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def i32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<i", data, off)[0]


def u16le(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def i16le(data: bytes, off: int) -> int:
    return struct.unpack_from("<h", data, off)[0]


def i8(data: bytes, off: int) -> int:
    return struct.unpack_from("<b", data, off)[0]
