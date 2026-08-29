"""PSB v3 文件头的解析与重建。

校验字段为 `adler32(header[0x08:0x28])`，已对 264 个语料文件全部验证（对九个
偏移字段做 adler32；CRC32 与其他区间组合均不匹配）。
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from ..core.errors import ParseError, ProbeRejected
from . import psb_spec as S

_FIELDS = ("header_length", "offset_names", "offset_strings",
           "offset_strings_data", "offset_chunk_offsets",
           "offset_chunk_lengths", "offset_chunk_data", "offset_entries")


@dataclass(slots=True)
class PsbHeader:
    version: int
    header_encrypt: int
    header_length: int
    offset_names: int
    offset_strings: int
    offset_strings_data: int
    offset_chunk_offsets: int
    offset_chunk_lengths: int
    offset_chunk_data: int
    offset_entries: int
    checksum: int

    @property
    def size(self) -> int:
        return S.HEADER_LENGTH_V3

    def offsets(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _FIELDS}

    def to_bytes(self) -> bytes:
        body = struct.pack(
            "<8I", self.header_length, self.offset_names, self.offset_strings,
            self.offset_strings_data, self.offset_chunk_offsets,
            self.offset_chunk_lengths, self.offset_chunk_data,
            self.offset_entries)
        return (struct.pack("<4sHH", S.SIGNATURE, self.version,
                            self.header_encrypt)
                + body + struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF))

    def computed_checksum(self) -> int:
        return zlib.adler32(self.to_bytes()[slice(*S.CHECKSUM_SPAN)]) & 0xFFFFFFFF


def read_header(data: bytes, *, strict: bool = True) -> PsbHeader:
    """解析并做边界检查的 PSB v3 文件头。"""
    if len(data) < S.HEADER_LENGTH_V3:
        raise ProbeRejected(f"文件长度小于 PSB 文件头（{len(data)} 字节）")
    sig, version, encrypt = struct.unpack_from("<4sHH", data, 0)
    if sig != S.SIGNATURE:
        raise ProbeRejected(f"签名错误 {sig!r}，期望 {S.SIGNATURE!r}")
    if version not in S.SUPPORTED_VERSIONS:
        raise ProbeRejected(f"不支持的 PSB 版本 {version}")
    if encrypt != 0:
        raise ProbeRejected(
            f"header_encrypt={encrypt}；加密文件头不做解码"
            "（字节原样保留，因为不存在密钥证据）")
    values = struct.unpack_from("<9I", data, 8)
    header = PsbHeader(version, encrypt, *values)
    if header.header_length != S.HEADER_LENGTH_V3:
        raise ParseError("header_length 取值异常", offset=8,
                         expected=S.HEADER_LENGTH_V3,
                         actual=header.header_length)
    for name, value in header.offsets().items():
        if not 0 <= value <= len(data):
            raise ParseError(f"{name} 越界", offset=8,
                             expected=f"[0,{len(data)}]", actual=value)
    if strict and header.checksum != header.computed_checksum():
        raise ParseError("文件头校验和不匹配", offset=0x28,
                         expected=f"0x{header.computed_checksum():08X}",
                         actual=f"0x{header.checksum:08X}")
    if header.offset_chunk_data != len(data):
        raise ParseError(
            "无 chunk 的剧本文件中 offset_chunk_data 必须等于文件长度",
            offset=0x20, expected=len(data),
            actual=header.offset_chunk_data)
    order = [
        ("names", header.offset_names),
        ("entries", header.offset_entries),
        ("strings", header.offset_strings),
        ("strings_data", header.offset_strings_data),
        ("chunk_offsets", header.offset_chunk_offsets),
        ("chunk_lengths", header.offset_chunk_lengths),
        ("chunk_data", header.offset_chunk_data),
    ]
    for (prev_name, prev), (name, cur) in zip(order, order[1:]):
        if cur < prev:
            raise ParseError(
                f"分区 {name} 的起点早于 {prev_name}",
                offset=8, expected=f">={prev}", actual=cur)
    if header.offset_names != S.HEADER_LENGTH_V3:
        raise ParseError("名称区必须紧跟文件头", offset=0x0C,
                         expected=S.HEADER_LENGTH_V3,
                         actual=header.offset_names)
    return header
