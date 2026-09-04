"""EntisGLS "NOA" 封包：读取、解包、打包。

容器是从 0x40 开始的 ``DirEntry`` 记录树，每个叶条目指向一个 ``filedata`` 块，
载荷可能是原始存储、BSHF 加密，或 ERISA "Nemesis" 压缩。

解包支持原始与 BSHF 两种存储；Nemesis 压缩条目会明确报错，不返回截断数据。

打包交由引擎自带的 ``tools/noa32c.exe`` 完成：引擎会校验每个条目末尾 4 字节，
那是打包器内部编码器寄存器的刷出值，依赖整个明文的累积状态，本模块未能复现。
详见 vm_analysis.md 的 EV_BSHF 与 EV_NOA_INDEX。

本模块不含任何作品专属字面量。封包密码来自 ``profiles/*.json``，也可由调用方
直接传入。

单条目录记录布局（全部小端）：

    u64 size            解码后的载荷长度
    u32 attr            0x01000000 = 普通文件，0x10 = 子目录，0x20/0x40 = 终止符
    u32 encryption      见 EncType
    s64 offset          相对于所属 DirEntry 起始
    u64 reserved        引擎时间戳
    u32 extra_length    随后该长度的字节（attr 无 0x70 位时）
    u32 name_length     随后该长度的字节，含结尾 NUL
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import profile

try:
    import numpy as _np
except ImportError:            # 可选依赖：只影响速度，不影响正确性
    _np = None

U32 = struct.Struct("<I")
U64 = struct.Struct("<Q")
S64 = struct.Struct("<q")

MAGIC = b"Entis\x1a\x00\x00"
MAGIC_VIST = b"VIST\x1a"
FORMAT_ID = 0x02000400
ROOT_OFFSET = 0x40
DIR_TAG = b"DirEntry"
FILE_TAG = b"filedata"
DEFAULT_ENCODING = "cp932"

ATTR_DIRECTORY = 0x10
ATTR_TERMINATORS = (0x20, 0x40)


def known_password(path: Path) -> str | None:
    """查数据档里登记的封包密码；没有记录返回 None。"""
    return profile.archive_password(path)


class EncType:
    RAW = 0x00000000
    ERISA_CODE = 0x80000010
    BSHF_CRYPT = 0x40000000
    SIMPLE_CRYPT32 = 0x20000000
    ERISA_CRYPT = 0xC0000010
    ERISA_CRYPT32 = 0xA0000010


ENC_NAMES = {
    EncType.RAW: "raw",
    EncType.ERISA_CODE: "nemesis",
    EncType.BSHF_CRYPT: "bshf",
    EncType.SIMPLE_CRYPT32: "simple32",
    EncType.ERISA_CRYPT: "nemesis+bshf",
    EncType.ERISA_CRYPT32: "nemesis+simple32",
}


class NoaError(Exception):
    pass


class PasswordRequired(NoaError):
    pass


@dataclass(slots=True)
class NoaEntry:
    name: str
    size: int
    attr: int
    encryption: int
    data_offset: int          # absolute offset of the 'filedata' record
    extra: bytes = b""
    stored_size: int = 0      # bytes of stored payload, from the record header
    reserved: int = 0         # engine timestamp; preserved verbatim on rebuild

    @property
    def enc_name(self) -> str:
        return ENC_NAMES.get(self.encryption, f"0x{self.encryption:08X}")


@dataclass(slots=True)
class NoaArchive:
    path: Path
    data: bytes
    entries: list[NoaEntry] = field(default_factory=list)
    encoding: str = DEFAULT_ENCODING

    @property
    def needs_password(self) -> bool:
        return any(e.encryption not in (EncType.RAW, EncType.ERISA_CODE)
                   for e in self.entries)


# --------------------------------------------------------------------------
# index parsing
# --------------------------------------------------------------------------

def read_archive(path: Path, encoding: str | None = None) -> NoaArchive:
    data = Path(path).read_bytes()
    if not (data.startswith(MAGIC) or data.startswith(MAGIC_VIST)):
        raise NoaError("not an Entis archive")
    if U32.unpack_from(data, 8)[0] != FORMAT_ID:
        raise NoaError("unsupported Entis archive format id")
    if encoding is None:
        encoding = DEFAULT_ENCODING
    archive = NoaArchive(Path(path), data, encoding=encoding)
    _parse_dir(archive, ROOT_OFFSET, "")
    if not archive.entries:
        raise NoaError("archive index is empty")
    return archive


def _parse_dir(archive: NoaArchive, dir_offset: int, current: str) -> None:
    data = archive.data
    if data[dir_offset:dir_offset + 8] != DIR_TAG:
        raise NoaError(f"expected a DirEntry at 0x{dir_offset:X}")
    size = S64.unpack_from(data, dir_offset + 8)[0]
    if size <= 0:
        raise NoaError(f"DirEntry at 0x{dir_offset:X} has size {size}")
    base = dir_offset
    pos = dir_offset + 0x10
    count = struct.unpack_from("<i", data, pos)[0]
    pos += 4
    for _ in range(count):
        entry_size = U64.unpack_from(data, pos)[0]
        pos += 8
        attr = U32.unpack_from(data, pos)[0]
        pos += 4
        encryption = U32.unpack_from(data, pos)[0]
        pos += 4
        offset = base + S64.unpack_from(data, pos)[0]
        pos += 8
        reserved = U64.unpack_from(data, pos)[0]
        pos += 8
        extra_length = U32.unpack_from(data, pos)[0]
        pos += 4
        extra = b""
        if extra_length and not attr & 0x70:
            extra = data[pos:pos + extra_length]
        pos += extra_length
        name_length = U32.unpack_from(data, pos)[0]
        pos += 4
        raw_name = data[pos:pos + name_length]
        pos += name_length
        name = raw_name.split(b"\0", 1)[0].decode(archive.encoding, "replace")
        full = name if not current else f"{current}/{name}"

        if attr == ATTR_DIRECTORY:
            _parse_dir(archive, offset + 0x10, full)
            continue
        if attr in ATTR_TERMINATORS:
            break
        stored = 0
        if data[offset:offset + 8] == FILE_TAG:
            stored = U64.unpack_from(data, offset + 8)[0]
        archive.entries.append(NoaEntry(
            name=full, size=entry_size, attr=attr, encryption=encryption,
            data_offset=offset, extra=extra, stored_size=stored,
            reserved=reserved,
        ))


# --------------------------------------------------------------------------
# BSHF decryption
# --------------------------------------------------------------------------

def bshf_key(password: str) -> bytes:
    raw = password.encode("ascii", "replace")
    length = max(len(raw), 32)
    key = bytearray(length)
    key[:len(raw)] = raw
    count = len(raw)
    if count < 32:
        key[count] = 0x1B
        count += 1
        for i in range(count, 32):
            key[i] = (key[i % count] + key[i - 1]) & 0xFF
        return bytes(key[:32])
    return bytes(key)


def _bshf_permutation(key: bytes, key_offset: int) -> list[tuple[int, int]]:
    """Bit permutation for one 32-byte block: sequence index -> (byte, mask).

    Identical in both directions; encoding and decoding differ only in which
    side of the mapping is read.  Derived from noa32c.exe sub_414B50 and the
    matching decode path in ArcNOA.cs.
    """
    key_length = len(key)
    mask = bytearray(32)
    table: list[tuple[int, int]] = []
    key_pos = key_offset
    bit = 0
    for _ in range(256):
        bit = (bit + key[key_pos]) & 0xFF
        key_pos += 1
        if key_pos >= key_length:
            key_pos = 0
        index = bit >> 3
        bit_mask = 0x80 >> (bit & 7)
        while mask[index] == 0xFF:
            bit = (bit + 8) & 0xFF
            index = bit >> 3
        while mask[index] & bit_mask:
            bit += 1
            bit_mask >>= 1
            if bit_mask == 0:
                bit = (bit + 8) & 0xFF
                index = bit >> 3
                bit_mask = 0x80
        mask[index] |= bit_mask
        table.append((index, bit_mask))
    return table


def _bshf_bit_maps(password: str) -> list:
    """每个密钥相位一张位索引表。

    置换只由 ``key_offset`` 决定，它每块 +1 并按密钥长度回绕，所以无论载荷多大，
    32 字节密钥也只有 32 种置换：各建一次然后复用。返回可直接供 numpy 花式索引
    使用的扁平位索引数组；numpy 缺失时退回普通列表，只影响速度。
    """
    key = bshf_key(password)
    maps: list = []
    for offset in range(len(key)):
        table = _bshf_permutation(key, offset)
        # 源位 i 在 32 字节块内的目标位（块内按 MSB 优先编号）
        dest = [index * 8 + (8 - bit_mask.bit_length()) for index, bit_mask in table]
        maps.append(dest)
    if _np is not None:
        maps = [_np.asarray(m, dtype=_np.int64) for m in maps]
    return maps


def bshf_decode(source: bytes, password: str, want: int) -> bytes:
    """解密 BSHF：每 32 字节一块，按密钥派生的 256 位置换还原。

    一次向量化处理全部块；缺 numpy 时逐块回退。
    """
    usable = len(source) - len(source) % 32
    if usable <= 0:
        return b""
    data = source[:usable]
    maps = _bshf_bit_maps(password)
    phases = len(maps)

    if _np is None:
        out = bytearray(usable)
        for block_index in range(usable // 32):
            base = block_index * 32
            table = maps[block_index % phases]
            block = data[base:base + 32]
            result = bytearray(32)
            for src, target in enumerate(table):
                if block[src >> 3] & (0x80 >> (src & 7)):
                    result[target >> 3] |= 0x80 >> (target & 7)
            out[base:base + 32] = result
        return bytes(out[:want])

    blocks = _np.frombuffer(data, dtype=_np.uint8).reshape(-1, 32)
    bits = _np.unpackbits(blocks, axis=1)                  # (n, 256)，MSB 优先
    result = _np.empty_like(bits)
    count = bits.shape[0]
    for phase in range(phases):
        rows = _np.arange(phase, count, phases)
        if rows.size:
            result[rows[:, None], maps[phase][None, :]] = bits[rows]
    return _np.packbits(result, axis=1).tobytes()[:want]


# --------------------------------------------------------------------------

def entry_payload(archive: NoaArchive, entry: NoaEntry,
                  password: str | None = None) -> bytes:
    """Return one entry's decoded bytes, or raise if that is not yet possible."""
    data = archive.data
    start = entry.data_offset
    if data[start:start + 8] != FILE_TAG:
        raise NoaError(f"{entry.name}: no filedata record at 0x{start:X}")
    stored = U64.unpack_from(data, start + 8)[0]
    body = data[start + 0x10:start + 0x10 + stored]

    if entry.encryption == EncType.RAW:
        return body[:entry.size]
    if entry.encryption == EncType.BSHF_CRYPT:
        if not password:
            raise PasswordRequired(f"{entry.name} is BSHF-encrypted")
        # The engine decrypts stored-4 bytes.  For a csx that includes a
        # 26-byte trailer past the last section; returning only entry.size
        # truncates it and the game then reports the script as missing.
        want = max(entry.stored_size - 4, entry.size)
        out = bshf_decode(body, password, want)
        if len(out) < entry.size:
            raise NoaError(f"{entry.name}: BSHF decode came up short")
        return out
    raise NoaError(f"{entry.name}: encryption {entry.enc_name} is not supported")


def extract(path: Path, out_dir: Path, password: str | None = None,
            encoding: str | None = None) -> dict:
    """Extract every entry it can, and report the ones it cannot."""
    archive = read_archive(path, encoding)
    if not password:
        password = known_password(path)
    out_dir = Path(out_dir)
    written: list[str] = []
    failed: list[dict] = []
    for entry in archive.entries:
        try:
            payload = entry_payload(archive, entry, password)
        except NoaError as exc:
            failed.append({"name": entry.name, "encryption": entry.enc_name,
                           "reason": str(exc)})
            continue
        target = out_dir / Path(entry.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(payload)
        temporary.replace(target)
        written.append(entry.name)
    return {
        "archive": str(path), "output": str(out_dir),
        "entries": len(archive.entries), "extracted": len(written),
        "failed": failed,
        "encryption_kinds": sorted({e.enc_name for e in archive.entries}),
    }


PACKER_NAME = "noa32c.exe"


def find_packer() -> Path | None:
    """Locate the engine's own archiver, preferring the copy shipped alongside."""
    here = Path(__file__).resolve().parent
    for candidate in (here / "tools" / PACKER_NAME, here / PACKER_NAME):
        if candidate.is_file():
            return candidate
    return None


def pack_with_engine(source_dir: Path, output: Path, password: str | None = None,
                     encryption: str = "bshf", timeout: int = 3600) -> dict:
    """Pack a directory by driving the engine's own archiver.

    The engine validates a four-byte trailer that its packer appends after each
    entry's scrambled blocks; that value is a flush of the packer's internal
    encoder state and is not reproduced by this module.  Calling the original
    archiver therefore produces the only output the game reliably accepts.

    The tool insists on ``/``-prefixed options with ``\\`` path separators, and
    must run with its source directory as the working directory, so the call is
    issued through ``cmd /c`` with an absolute destination.
    """
    import os
    import subprocess

    packer = find_packer()
    if packer is None:
        raise NoaError(
            f"{PACKER_NAME} was not found next to this module or in tools/; "
            "it is required to write an archive the engine will load")
    source_dir = Path(source_dir).resolve()
    output = Path(output).resolve()
    if not source_dir.is_dir():
        raise NoaError(f"{source_dir} is not a directory")
    files = [p for p in source_dir.iterdir() if p.is_file()]
    if not files:
        raise NoaError(f"{source_dir} contains no files to pack")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    options = f"/p /{encryption}"
    if password:
        options += f" /pass {password}"

    # The tool fails on paths containing non-ASCII characters, and this game
    # ships under a Japanese directory name, so it is run inside a temporary
    # ASCII-only workspace with the inputs hard-linked (copied only if the link
    # cannot be made, e.g. across volumes).
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory(prefix="noapack_") as tmp:
        work = Path(tmp)
        staging = work / "src"
        staging.mkdir()
        for item in files:
            target = staging / item.name
            try:
                os.link(item, target)
            except OSError:
                shutil.copy2(item, target)
        tool = work / PACKER_NAME
        shutil.copy2(packer, tool)
        built = work / "out.noa"
        # Run with the staging directory as cwd so the '*.*' pattern resolves
        # there; the tool needs a relative pattern, not an absolute one.
        argv = [str(tool), "/p", f"/{encryption}"]
        if password:
            argv += ["/pass", password]
        argv += ["*.*", str(built)]
        done = subprocess.run(argv, cwd=str(staging), capture_output=True,
                              timeout=timeout)
        if not built.is_file():
            detail = (done.stdout or b"") + b" " + (done.stderr or b"")
            raise NoaError(f"{PACKER_NAME} produced no archive: "
                           f"{detail.decode('cp932', 'replace').strip()[:300]}")
        shutil.move(str(built), output)

    check = read_archive(output)
    return {
        "source": str(source_dir), "output": str(output),
        "entries": len(check.entries), "output_size": output.stat().st_size,
        "packer": str(packer), "encryption": encryption,
        "ok": True, "issues": [],
    }
