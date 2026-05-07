from __future__ import annotations

import hashlib
import struct


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_with_codec(raw: bytes, codec: str) -> str:
    try:
        return raw.decode(codec)
    except UnicodeDecodeError:
        return raw.decode(codec, errors="surrogateescape")


def encode_with_codec(text: str, codec: str) -> bytes:
    try:
        return text.encode(codec)
    except UnicodeEncodeError:
        return text.encode(codec, errors="surrogateescape")


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("alignment must be positive")
    return ((value + alignment - 1) // alignment) * alignment
