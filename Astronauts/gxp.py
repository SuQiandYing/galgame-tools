# -*- coding: utf-8 -*-
"""gxp.py — GXP 归档（Astronauts）解包与封包。

格式（小端，与 ZMOA 载荷的大端相反）：

    0x00  'GXP\0'
    0x04  u32  version              实测 100
    0x08  u32  magic2               实测 0x10203040
    0x0C  u32  flag0                实测 1
    0x10  u32  flag1                实测 0
    0x14  u32  flag2                实测 1
    0x18  i32  entry_count
    0x1C  u32  index_size           索引区总字节数
    0x20  u32  data_size            数据区总字节数
    0x24  u32  reserved             实测 0
    0x28  i64  base_offset          数据区起始（= 0x30 + index_size）
    0x30  索引区：entry_count 条，每条 entry_size 字节（加密）
    base  数据区：各条目内容（加密）

索引条目（解密后，小端）：

    0x00  u32  entry_size           本条目索引长度（含自身与名字）
    0x04  u32  size_lo              文件长度低 32 位
    0x08  u32  size_hi              文件长度高 32 位
    0x0C  u32  name_chars           名字 UTF-16 字符数
    0x10  u32  unk_time_lo          实测为时间戳类字段，原样保留
    0x14  u32  unk_time_hi
    0x18  i64  offset               相对 base_offset 的偏移
    0x20  ...  名字（UTF-16LE，name_chars*2 字节）
    ...        对齐填充至 entry_size（原样保留）

加密：逐字节 `b ^= (i & 0xFF) ^ KNOWN_KEY[i % 23]`，i 为该缓冲区内的下标
（索引条目从条目起始计数，数据从条目数据起始计数）。归档名兜底密钥同时
xor `arcname[i % len]`——本作 bincode.gxp 使用固定密钥即可解开，故仅在固定
密钥失败时才尝试名字密钥。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

MAGIC = b"GXP\0"
HEADER_SIZE = 0x30
INDEX_HEADER_SIZE = 0x20

KNOWN_KEY = bytes([
    0x40, 0x21, 0x28, 0x38, 0xA6, 0x6E, 0x43, 0xA5, 0x40, 0x21, 0x28, 0x38,
    0xA6, 0x43, 0xA5, 0x64, 0x3E, 0x65, 0x24, 0x20, 0x46, 0x6E, 0x74,
])

# 预生成一个周期的掩码：周期 = lcm(256, 23) = 5888
_MASK_PERIOD = 256 * len(KNOWN_KEY)
_MASK = bytes(((i & 0xFF) ^ KNOWN_KEY[i % len(KNOWN_KEY)]) for i in range(_MASK_PERIOD))


class GxpError(Exception):
    pass


def crypt(data: bytes | bytearray, name_key: bytes | None = None) -> bytes:
    """对称加解密（下标自缓冲区起始计数）。name_key 为 None 时使用固定密钥。

    每个索引条目与每个数据条目各自从下标 0 重新计数——这是 GXP 的既有行为，
    也是逐字节往返成立的前提（实测：按整块连续计数会在第二个条目起全错）。
    """
    n = len(data)
    src = bytes(data)
    if name_key is None:
        out = bytearray(n)
        pos = 0
        while pos < n:
            chunk = src[pos:pos + _MASK_PERIOD]          # pos 恒为周期整数倍
            out[pos:pos + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, _MASK))
            pos += len(chunk)
        return bytes(out)
    out = bytearray(n)
    klen = len(name_key)
    for i in range(n):
        out[i] = src[i] ^ _MASK[i % _MASK_PERIOD] ^ name_key[i % klen]
    return bytes(out)


def _entry_key(name_key: bytes | None) -> int:
    k = (KNOWN_KEY[0]
         | (1 ^ KNOWN_KEY[1]) << 8
         | (2 ^ KNOWN_KEY[2]) << 16
         | (3 ^ KNOWN_KEY[3]) << 24)
    if name_key is not None:
        ak = (name_key[0]
              | name_key[1 % len(name_key)] << 8
              | name_key[2 % len(name_key)] << 16
              | name_key[3 % len(name_key)] << 24)
        k ^= ak
    return k & 0xFFFFFFFF


@dataclass
class GxpEntry:
    name: str
    offset: int          # 相对 base_offset
    size: int
    entry_size: int      # 索引条目长度
    unk_time_lo: int = 0
    unk_time_hi: int = 0
    tail: bytes = b""    # 名字之后到 entry_size 的原始填充，保证逐字节往返
    data: bytes | None = field(default=None, repr=False)


@dataclass
class GxpArchive:
    header: bytes                    # 原始 0x30 头，重建时原样复用
    base_offset: int
    entries: list[GxpEntry]
    name_key: bytes | None
    source_size: int
    source_sha256: str

    def by_name(self, name: str) -> GxpEntry:
        for e in self.entries:
            if e.name == name or e.name.replace("\\", "/").endswith(name):
                return e
        raise KeyError(name)


def read_archive(path: str | Path) -> GxpArchive:
    path = Path(path)
    raw = path.read_bytes()
    if raw[:4] != MAGIC:
        raise GxpError(f"不是 GXP 归档：{path}")
    for name_key in (None, path.name.encode("ascii", "ignore")):
        try:
            return _parse(raw, name_key)
        except GxpError:
            continue
    raise GxpError(f"索引解析失败（固定密钥与归档名密钥均不适用）：{path}")


def _parse(raw: bytes, name_key: bytes | None) -> GxpArchive:
    count = struct.unpack_from("<i", raw, 0x18)[0]
    if not (0 < count < 0x100000):
        raise GxpError(f"条目数不合理：{count}")
    base_offset = struct.unpack_from("<q", raw, 0x28)[0]
    ekey = _entry_key(name_key)

    entries: list[GxpEntry] = []
    off = HEADER_SIZE
    for i in range(count):
        if off + 4 > len(raw):
            raise GxpError(f"索引越界 @{off:#x}")
        enc_len = struct.unpack_from("<I", raw, off)[0]
        entry_size = enc_len ^ ekey
        if entry_size < INDEX_HEADER_SIZE or entry_size > 0x1000:
            raise GxpError(f"条目 {i} 索引长度不合理：{entry_size:#x}")
        if off + entry_size > len(raw):
            raise GxpError(f"条目 {i} 索引越界")
        eb = crypt(raw[off:off + entry_size], name_key)
        if struct.unpack_from("<I", eb, 0)[0] != entry_size:
            raise GxpError(f"条目 {i} 长度自校验失败")
        size_lo, size_hi = struct.unpack_from("<II", eb, 4)
        name_chars = struct.unpack_from("<I", eb, 0x0C)[0]
        t_lo, t_hi = struct.unpack_from("<II", eb, 0x10)
        data_off = struct.unpack_from("<q", eb, 0x18)[0]
        nbytes = name_chars * 2
        if INDEX_HEADER_SIZE + nbytes > entry_size:
            raise GxpError(f"条目 {i} 名字越界")
        name = eb[INDEX_HEADER_SIZE:INDEX_HEADER_SIZE + nbytes].decode("utf-16-le")
        tail = eb[INDEX_HEADER_SIZE + nbytes:]
        size = size_lo | (size_hi << 32)
        if base_offset + data_off + size > len(raw):
            raise GxpError(f"条目 {i} 数据越界")
        entries.append(GxpEntry(name=name, offset=data_off, size=size,
                                entry_size=entry_size, unk_time_lo=t_lo,
                                unk_time_hi=t_hi, tail=tail))
        off += entry_size

    for e in entries:
        enc = raw[base_offset + e.offset: base_offset + e.offset + e.size]
        e.data = crypt(enc, name_key)

    return GxpArchive(header=raw[:HEADER_SIZE], base_offset=base_offset,
                      entries=entries, name_key=name_key, source_size=len(raw),
                      source_sha256=hashlib.sha256(raw).hexdigest())


def unpack(path: str | Path, dest_dir: str | Path) -> list[Path]:
    """解包到 dest_dir，返回写出的文件列表。目录结构保持归档内路径。"""
    arc = read_archive(path)
    dest = Path(dest_dir)
    written = []
    for e in arc.entries:
        rel = e.name.replace("\\", "/").lstrip("/")
        if ".." in rel.split("/"):
            raise GxpError(f"拒绝路径穿越：{e.name}")
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_bytes(e.data or b"")
        tmp.replace(out)
        written.append(out)
    return written


def build_archive(arc: GxpArchive, replacements: dict[str, bytes] | None = None) -> bytes:
    """按原索引顺序与字段重建归档；replacements 按条目名替换内容（可变长）。"""
    replacements = {k.replace("\\", "/"): v for k, v in (replacements or {}).items()}

    index = bytearray()
    data = bytearray()
    plain_entries = []
    for e in arc.entries:
        key = e.name.replace("\\", "/")
        payload = replacements.get(key, e.data or b"")
        nbytes = e.name.encode("utf-16-le")
        eb = bytearray(e.entry_size)
        struct.pack_into("<I", eb, 0x00, e.entry_size)
        struct.pack_into("<II", eb, 0x04, len(payload) & 0xFFFFFFFF, len(payload) >> 32)
        struct.pack_into("<I", eb, 0x0C, len(nbytes) // 2)
        struct.pack_into("<II", eb, 0x10, e.unk_time_lo, e.unk_time_hi)
        struct.pack_into("<q", eb, 0x18, len(data))
        eb[INDEX_HEADER_SIZE:INDEX_HEADER_SIZE + len(nbytes)] = nbytes
        eb[INDEX_HEADER_SIZE + len(nbytes):] = e.tail
        plain_entries.append((len(index), bytes(eb)))
        index += eb
        data += payload

    out = bytearray(arc.header)
    struct.pack_into("<i", out, 0x18, len(arc.entries))
    struct.pack_into("<I", out, 0x1C, len(index))
    struct.pack_into("<I", out, 0x20, len(data))
    struct.pack_into("<q", out, 0x28, HEADER_SIZE + len(index))
    for _rel_off, eb in plain_entries:
        out += crypt(eb, arc.name_key)          # 每条索引独立计数
    # 数据区：逐条目独立加密（与解包侧一致）
    cursor = 0
    for e in arc.entries:
        key = e.name.replace("\\", "/")
        payload = replacements.get(key, e.data or b"")
        out += crypt(payload, arc.name_key)
        cursor += len(payload)
    assert cursor == len(data)
    return bytes(out)


def repack(src_archive: str | Path, out_path: str | Path,
           replacements: dict[str, bytes] | None = None,
           from_dir: str | Path | None = None) -> Path:
    """封包。out_path 可自定义名称；from_dir 存在时按归档内路径读取替换文件。"""
    arc = read_archive(src_archive)
    reps: dict[str, bytes] = dict(replacements or {})
    if from_dir is not None:
        base = Path(from_dir)
        for e in arc.entries:
            rel = e.name.replace("\\", "/").lstrip("/")
            cand = base / rel
            if cand.is_file():
                reps.setdefault(e.name.replace("\\", "/"), cand.read_bytes())
    blob = build_archive(arc, reps)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        import os
        os.fsync(f.fileno())
    # 重新解析验证
    verify = _parse(blob, arc.name_key)
    if len(verify.entries) != len(arc.entries):
        tmp.unlink(missing_ok=True)
        raise GxpError("重建归档条目数不符")
    for a, b in zip(arc.entries, verify.entries):
        if a.name != b.name:
            tmp.unlink(missing_ok=True)
            raise GxpError(f"重建归档条目名不符：{a.name} != {b.name}")
        expect = reps.get(a.name.replace("\\", "/"), a.data or b"")
        if b.data != expect:
            tmp.unlink(missing_ok=True)
            raise GxpError(f"重建归档条目内容不符：{a.name}")
    tmp.replace(out_path)
    return out_path


def _cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="gxp", description="GXP 归档解包 / 封包")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("list", help="列出条目")
    p1.add_argument("archive")

    p2 = sub.add_parser("unpack", help="解包")
    p2.add_argument("archive")
    p2.add_argument("-o", "--out", default=None, help="输出目录（默认 <归档名>_unpacked）")

    p3 = sub.add_parser("pack", help="封包（输出名可自定义）")
    p3.add_argument("archive", help="原归档（提供索引字段模板）")
    p3.add_argument("-d", "--dir", required=True, help="替换内容所在目录")
    p3.add_argument("-o", "--out", required=True, help="输出归档路径（可自定义名称）")

    a = ap.parse_args(argv)
    if a.cmd == "list":
        arc = read_archive(a.archive)
        print(f"{arc.source_sha256[:16]}  {arc.source_size} 字节  "
              f"{len(arc.entries)} 条目  密钥={'归档名' if arc.name_key else '固定'}")
        for e in arc.entries:
            print(f"  {e.size:>12}  {e.offset:#012x}  {e.name}")
        return 0
    if a.cmd == "unpack":
        out = Path(a.out) if a.out else Path(a.archive).with_name(Path(a.archive).stem + "_unpacked")
        files = unpack(a.archive, out)
        print(f"已解包 {len(files)} 个文件 → {out}")
        for f in files:
            print("  ", f)
        return 0
    if a.cmd == "pack":
        out = repack(a.archive, a.out, from_dir=a.dir)
        print(f"已封包 → {out}（{out.stat().st_size} 字节，已通过重解析校验）")
        return 0
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
