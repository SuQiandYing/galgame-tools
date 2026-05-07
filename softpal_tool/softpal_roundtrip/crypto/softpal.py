from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SoftPalCipherConfig:
    header_magic: int = 0x24
    header_size: int = 0x10
    key1: int = 0x084DF873
    key2: int = 0xFF987DEE
    initial_rotation: int = 0x04


def _ror8(value: int, amount: int) -> int:
    amount %= 8
    return ((value >> amount) | (value << (8 - amount))) & 0xFF


def _rol8(value: int, amount: int) -> int:
    amount %= 8
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def softpal_encrypt_bytes(
    data: bytes,
    config: SoftPalCipherConfig | None = None,
) -> bytes:
    config = config or SoftPalCipherConfig()
    buf = bytearray(data)
    if not buf or buf[0] != config.header_magic:
        return bytes(buf)
    size = len(buf)
    count = max(0, (size - config.header_size) // 4)
    pos = config.header_size
    rot = config.initial_rotation
    for _ in range(count):
        if pos + 4 > size:
            break
        dword = int.from_bytes(buf[pos : pos + 4], "little")
        dword ^= config.key2
        dword ^= config.key1
        buf[pos : pos + 4] = dword.to_bytes(4, "little")
        buf[pos] = _ror8(buf[pos], rot)
        rot = (rot + 1) & 0xFF
        pos += 4
    return bytes(buf)


def softpal_decrypt_bytes(
    data: bytes,
    config: SoftPalCipherConfig | None = None,
) -> bytes:
    config = config or SoftPalCipherConfig()
    buf = bytearray(data)
    if not buf:
        return bytes(buf)
    if len(buf) < config.header_size:
        return bytes(buf)
    if buf[0] != config.header_magic:
        return bytes(buf)
    size = len(buf)
    count = max(0, (size - config.header_size) // 4)
    pos = config.header_size
    rot = config.initial_rotation
    for _ in range(count):
        if pos + 4 > size:
            break
        block = bytearray(buf[pos : pos + 4])
        block[0] = _rol8(block[0], rot)
        dword = int.from_bytes(block, "little")
        dword ^= config.key1
        dword ^= config.key2
        buf[pos : pos + 4] = dword.to_bytes(4, "little")
        rot = (rot + 1) & 0xFF
        pos += 4
    return bytes(buf)
