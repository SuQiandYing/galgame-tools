# -*- coding: utf-8 -*-
"""CatScene .cst 全量反汇编：二进制 → IR → asm.txt + 双行文本 + 覆盖证书。

用法：
    python disassembler.py <文件或目录> [...] [-o 输出目录] [--source-encoding cp932]
                           [--target-encoding cp932] [--no-asm] [--jobs N]
    拖放：把文件或文件夹拖到本文件图标上。

铁律：只读源；IR 唯一真值；不静默兜底；阶段隔离。
"""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opcodelist as D  # noqa: E402


def _utf8_console() -> None:
    """Windows 控制台缺省 GBK，中文报错会变问号。只改显示，不改产物。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass

# ---------------------------------------------------------------- 异常


class CstError(Exception):
    """本工具的全部解析失败都继承它，绝不静默降级。"""


class MagicError(CstError):
    pass


class LayerError(CstError):
    pass


class StructureError(CstError):
    pass


class AddressSpaceGapError(CstError):
    pass


class AddressSpaceCollisionError(CstError):
    pass


class UnknownRecordTypeError(CstError):
    pass


class SanityGateError(CstError):
    pass


# ---------------------------------------------------------------- IR 对象

_U32 = struct.Struct("<I")
_U32X4 = struct.Struct("<4I")
_U32X2 = struct.Struct("<2I")
_HDR = D.CONTAINER["header_size"]
_MAGIC = D.CONTAINER["magic"]
_PREFIX = D.PAYLOAD["record"]["prefix_byte"]
_TERM = D.PAYLOAD["record"]["terminator"]
_TYPE_CMD = D.TYPE_CMD
_TYPE_MSG = D.TYPE_MSG
_TYPE_NAME = D.TYPE_NAME
_TYPE_PAGE = D.TYPE_PAGE
_TERMINATORS = frozenset(D.BLOCK_TERMINATORS)
_MARKUP = re.compile(D.MARKUP_PATTERN)
_RULES = [(r, re.compile(r["pattern"])) for r in D.TEXT_RULES]
_PH_RE = re.compile(D.TEXT_FORMAT["placeholder_re"])
_ORIG_RE = re.compile(D.TEXT_FORMAT["orig_re"])
_TRAN_RE = re.compile(D.TEXT_FORMAT["tran_re"])


@dataclass(frozen=True, slots=True)
class Record:
    """记录流中的一条记录。offset 是数据区内相对偏移，即偏移表存的键值。"""
    rec_id: int
    offset: int
    type_byte: int
    payload: bytes
    block_id: int

    @property
    def total_size(self) -> int:
        return 2 + len(self.payload) + 1


@dataclass(frozen=True, slots=True)
class Block:
    block_id: int
    record_count: int
    first_record: int


@dataclass(frozen=True, slots=True)
class TextEntry:
    idx: int
    rec_id: int
    tag: str
    tag_subtype: str
    tag_source: str
    translate_policy: str
    source: str
    raw: bytes
    prefix: bytes
    suffix: bytes
    speaker_idx: int | None
    rule_id: str | None
    matched_rule_id: str | None
    undecodable: bool
    exported: bool = True


@dataclass(frozen=True, slots=True)
class JoinSite:
    join_id: str
    site_offset: int
    site_width: int
    key_kind: str
    key_value: int
    target_rec_id: int
    collision_class: str
    rewrite_policy: str
    confidence: str


@dataclass(slots=True)
class Doc:
    """一个 .cst 的完整 IR。asm、文本、证书、重建全部只从这里投影。"""
    path: Path
    raw_size: int
    raw_sha256: str
    com_size: int
    unc_size: int
    payload_sha256: str
    payload_size_field: int
    block_count: int
    table_offset: int
    data_offset: int
    blocks: list[Block]
    records: list[Record]
    offsets: list[int]
    payload_len: int
    zlib_stream: bytes
    text_entries: list[TextEntry] = field(default_factory=list)
    name_bindings: list[dict] = field(default_factory=list)
    join_sites: list[JoinSite] = field(default_factory=list)
    rule_hits: dict = field(default_factory=dict)
    window_hits: dict = field(default_factory=dict)
    unresolved: list[dict] = field(default_factory=list)
    form: str = "container"
    cipher: dict = field(default_factory=lambda: {"id": "none",
                                                  "algorithm": "identity"})
    langs: list[str] = field(default_factory=list)   # 仅 cstl
    cstl_count: int = 0                              # 仅 cstl


# ---------------------------------------------------------------- 解析


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_bytes(data: bytes, path: Path, key: bytes | None = None) -> Doc:
    """封装层 → 载荷 → 区域 → 记录流。任何不一致立即抛错。

    接受两种输入形态（D.CONTAINER_FORMS）：
      container    原始 .cst：CatScene 头 + zlib 流
      bare-payload 已被外部脚本解压过的裸载荷（没有 CatScene 头）
    """
    if data[:D.CSTL["magic_size"]] == D.CSTL["magic"]:
        return parse_cstl(data, path)
    if len(data) < _HDR:
        raise MagicError(f"{path.name}: 文件短于容器头 {_HDR} 字节")
    if data[:len(_MAGIC)] != _MAGIC:
        doc = _try_bare_payload(data, path)
        if doc is not None:
            _build_join_sites(doc)
            return doc
        raise MagicError(
            f"{path.name}: 魔数不是 {_MAGIC!r}，且不是自相一致的裸载荷。"
            f"若文件被加密，请用 --key 指定密钥文件")
    com = _U32.unpack_from(data, D.CONTAINER["field_com_size"]["offset"])[0]
    unc = _U32.unpack_from(data, D.CONTAINER["field_unc_size"]["offset"])[0]
    if _HDR + com != len(data):
        raise LayerError(
            f"{path.name}: 容器头声明压缩长度 {com}，加头 {_HDR} 后为 {_HDR + com}，"
            f"实际文件 {len(data)} 字节，尾部有 {len(data) - _HDR - com} 字节未归属")
    stream = data[_HDR:_HDR + com]
    payload, cipher = _decode_layer(stream, unc, path, key)
    if len(payload) != unc:
        raise LayerError(
            f"{path.name}: 容器头声明解压长度 {unc}，实际 {len(payload)}")
    doc = _parse_payload(payload, path, data, com, unc, stream)
    doc.cipher = cipher
    _build_join_sites(doc)
    return doc


def _decode_layer(stream: bytes, unc: int, path: Path,
                  key: bytes | None) -> tuple[bytes, dict]:
    """解封装层。明文直接 zlib；解不开时按 D.CIPHER_PROBES 逐个试。

    候选的接受条件是 D.CIPHER_ACCEPT 的三条硬约束——解出的必须是合法 zlib 流、
    长度与头部字段相符、且记录流能解析。这个条件强到不可能假阳性，
    所以「解出来像文本」这种弱判据永远不会被采纳（§2.2 不得伪造明文）。
    """
    try:
        return zlib.decompress(stream), {"id": "none", "algorithm": "identity"}
    except zlib.error:
        pass
    tried = []
    for probe in D.CIPHER_PROBES:
        if probe["algorithm"] == "identity":
            continue
        for cand, desc in _cipher_candidates(probe, stream, key):
            tried.append(desc)
            try:
                out = zlib.decompress(cand)
            except zlib.error:
                continue
            if len(out) != unc:
                continue
            try:
                _check_payload_header(out)
            except CstError:
                continue
            return out, {"id": probe["id"], "algorithm": probe["algorithm"],
                         "detail": desc, "confidence": "derived",
                         "evidence": "解出的字节是合法 zlib 流，长度与容器头相符，"
                                     "且载荷头四个字段自相一致"}
    raise LayerError(
        f"{path.name}: zlib 解压失败，且 {len(tried)} 个解密候选全部不满足"
        f"「合法 zlib + 长度相符 + 载荷头自洽」。按 §2.2 保留原字节，不猜测。"
        f"若知道密钥请用 --key 指定")


def _cipher_candidates(probe: dict, stream: bytes, key: bytes | None):
    if probe["algorithm"] == "xor-single-byte":
        lo, hi = probe["params"]["range"]
        for k in range(lo, hi):
            yield bytes(b ^ k for b in stream), f"xor 单字节 {k:#02x}"
    elif probe["algorithm"] == "xor-repeating-key" and key:
        n = len(key)
        yield bytes(b ^ key[i % n] for i, b in enumerate(stream)), \
            f"xor 循环密钥 {n} 字节"


def _check_payload_header(payload: bytes) -> None:
    """载荷头四字段自洽性——加密候选的接受判据之一，也是裸载荷的识别判据。"""
    hdr = D.PAYLOAD["header"]["size"]
    if len(payload) < hdr:
        raise StructureError("短于载荷头")
    psz, bcnt, toff, doff = _U32X4.unpack_from(payload, 0)
    if psz != len(payload) - hdr:
        raise StructureError("payload_size 不符")
    if toff != bcnt * D.PAYLOAD["block_table"]["entry_size"]:
        raise StructureError("table_offset 与 block_count 不符")
    if not (toff <= doff <= len(payload) - hdr):
        raise StructureError("data_offset 越界")
    if (doff - toff) % D.PAYLOAD["offset_table"]["entry_size"]:
        raise StructureError("偏移表跨度不整除")


def _cstl_varint(b: bytes, p: int) -> tuple[int, int]:
    """0xFF 累加式变长整数（§CSTL）。ff ff 17 = 255+255+23 = 533。

    不是 LEB128——按 LEB128 或 u8 读都会错位，这是本格式最容易踩的坑。
    """
    v = 0
    n = len(b)
    while p < n and b[p] == 0xFF:
        v += 0xFF
        p += 1
    if p >= n:
        raise StructureError("varint 在文件末尾未终止")
    return v + b[p], p + 1


def _cstl_emit(v: int) -> bytes:
    out = bytearray()
    while v >= 0xFF:
        out.append(0xFF)
        v -= 0xFF
    out.append(v)
    return bytes(out)


def parse_cstl(data: bytes, path: Path) -> Doc:
    """.cstl 多语言文本层。不压缩不加密；每条 = 逐语言的 (说话者, 正文)。"""
    C = D.CSTL
    if data[:C["magic_size"]] != C["magic"]:
        raise MagicError(f"{path.name}: 不是 {C['magic']!r}")
    res = C["reserved"]
    if C["reserved"]["must_be_zero"] and any(
            data[res["offset"]:res["offset"] + res["width"]]):
        raise StructureError(f"{path.name}: 保留字段非零")
    p = C["lang_count"]["offset"]
    nlang = data[p]
    p += C["lang_count"]["width"]
    langs: list[str] = []
    for _ in range(nlang):
        ln, p = _cstl_varint(data, p)
        langs.append(data[p:p + ln].decode("ascii"))
        p += ln
    count, p = _cstl_varint(data, p)
    per = C["slots_per_lang"] * nlang
    flat: list[bytes] = []
    spans: list[tuple[int, int]] = []
    while p < len(data):
        ln, p = _cstl_varint(data, p)
        if p + ln > len(data):
            raise AddressSpaceGapError(
                f"{path.name}: 偏移 {p} 处的串长 {ln} 越过文件末尾")
        spans.append((p, ln))
        flat.append(data[p:p + ln])
        p += ln
    if len(flat) % per:
        raise StructureError(
            f"{path.name}: {len(flat)} 个串不能被每条 {per} 个整除")
    got = len(flat) // per
    if got != count:
        raise StructureError(
            f"{path.name}: 头部声明 {count} 条，实际读出 {got} 条")
    # 复用同一套 IR 对象：一个槽位当一条记录，页当块。
    records: list[Record] = []
    for i, (blob, (off, _)) in enumerate(zip(flat, spans)):
        records.append(Record(i, off, D.TYPE_MSG if i % 2 else D.TYPE_NAME,
                              blob, i // per))
    blocks = [Block(k, per, k * per) for k in range(count)]
    doc = Doc(path=path, raw_size=len(data), raw_sha256=_sha256(data),
              com_size=0, unc_size=len(data), payload_sha256=_sha256(data),
              payload_size_field=len(data), block_count=count,
              table_offset=0, data_offset=0, blocks=blocks, records=records,
              offsets=[r.offset for r in records], payload_len=len(data),
              zlib_stream=b"")
    doc.form = "cstl"
    doc.langs = langs
    doc.cstl_count = count
    return doc


def _try_bare_payload(data: bytes, path: Path) -> Doc | None:
    """无 CatScene 头时，看它是否本身就是一份自洽的载荷。

    外部解压脚本（读 [8:12]/[12:16] 取长度、zlib.decompress 后直接落盘）的产物
    正是这种形态。识别判据是载荷头四字段自洽 + 记录流可完整切分，不靠文件名或扩展名。
    """
    try:
        _check_payload_header(data)
    except CstError:
        return None
    try:
        doc = _parse_payload(data, path, data, 0, len(data), b"")
    except CstError:
        return None
    doc.form = "bare-payload"
    return doc


def _parse_payload(payload: bytes, path: Path, data: bytes,
                   com: int, unc: int, stream: bytes) -> Doc:
    hdr = D.PAYLOAD["header"]
    if len(payload) < hdr["size"]:
        raise StructureError(f"{path.name}: 载荷短于载荷头")
    psz, bcnt, toff, doff = _U32X4.unpack_from(payload, 0)
    if psz != len(payload) - hdr["size"]:
        raise StructureError(
            f"{path.name}: 载荷头 payload_size={psz}，实际 {len(payload) - hdr['size']}")
    ent = D.PAYLOAD["block_table"]["entry_size"]
    if toff != bcnt * ent:
        raise StructureError(
            f"{path.name}: table_offset={toff} 与 block_count={bcnt}×{ent} 不符")
    tbase = hdr["size"] + toff
    dbase = hdr["size"] + doff
    if not (tbase <= dbase <= len(payload)):
        raise StructureError(f"{path.name}: 区域边界越界 tbase={tbase} dbase={dbase}")
    span = dbase - tbase
    esz = D.PAYLOAD["offset_table"]["entry_size"]
    if span % esz:
        raise StructureError(
            f"{path.name}: 偏移表跨度 {span} 不是 {esz} 的整数倍，拒绝截断或补齐")
    scnt = span // esz
    blocks = [Block(i, *_U32X2.unpack_from(payload, hdr["size"] + ent * i))
              for i in range(bcnt)]
    offsets = _unpack_u32_stream(payload[tbase:dbase])
    records = _cut_records(payload, dbase, offsets, path)
    _check_blocks(blocks, records, scnt, path)
    return Doc(
        path=path, raw_size=len(data), raw_sha256=_sha256(data),
        com_size=com, unc_size=unc, payload_sha256=_sha256(payload),
        payload_size_field=psz, block_count=bcnt, table_offset=toff,
        data_offset=doff, blocks=blocks, records=records,
        offsets=list(offsets), payload_len=len(payload), zlib_stream=stream)


def _unpack_u32_stream(buf: bytes) -> array.array:
    """批量解包，一次 C 层调用（§12.2）。字节序来自方言声明，不从宿主推断。"""
    if len(buf) % 4:
        raise StructureError(f"偏移表长度 {len(buf)} 不是 4 的整数倍")
    words = array.array("I")
    words.frombytes(buf)
    if (sys.byteorder == "little") != (D.PAYLOAD["endianness"] == "little"):
        words.byteswap()
    return words


def _cut_records(payload: bytes, dbase: int, offsets: Sequence[int],
                 path: Path) -> list[Record]:
    """按偏移表切分记录，逐条验证首尾相接与终止符，保证数据区每字节唯一归属。"""
    n = len(offsets)
    if n == 0:
        if dbase != len(payload):
            raise AddressSpaceGapError(f"{path.name}: 无记录但数据区非空")
        return []
    if offsets[0] != 0:
        raise StructureError(f"{path.name}: 偏移表首项 {offsets[0]} != 0")
    out: list[Record] = []
    unknown: list[int] = []
    for i in range(n):
        start = dbase + offsets[i]
        if i + 1 < n:
            nxt = dbase + offsets[i + 1]
            if nxt <= start:
                raise StructureError(f"{path.name}: 记录 {i} 偏移非单调递增")
            end = nxt - 1
        else:
            end = len(payload) - 1
        if end >= len(payload) or payload[end] != _TERM[0]:
            raise AddressSpaceGapError(
                f"{path.name}: 记录 {i} 末字节不是终止符 {_TERM!r}")
        if payload.find(_TERM, start, end) != -1:
            raise AddressSpaceCollisionError(
                f"{path.name}: 记录 {i} 内部出现终止符，切分不唯一")
        if end - start < 2:
            raise StructureError(f"{path.name}: 记录 {i} 短于前缀+类型字节")
        if payload[start] != _PREFIX:
            raise StructureError(
                f"{path.name}: 记录 {i} 前缀字节 {payload[start]:#02x} != {_PREFIX:#02x}")
        tb = payload[start + 1]
        if tb not in D.KNOWN_TYPE_BYTES:
            unknown.append(i)
        out.append(Record(i, offsets[i], tb, payload[start + 2:end], -1))
    if unknown:
        raise UnknownRecordTypeError(
            f"{path.name}: 记录 {unknown[:8]} 的类型字节未在方言中登记，"
            f"按 §0.2 不得走已知分支静默产出空结果")
    if dbase + offsets[-1] >= len(payload):
        raise AddressSpaceGapError(f"{path.name}: 末记录起点越界")
    return out


def _check_blocks(blocks: Sequence[Block], records: Sequence[Record],
                  scnt: int, path: Path) -> None:
    """块表必须恰好平铺记录流，且可由页结束记录独立推导（两条独立证据）。"""
    cursor = 0
    for b in blocks:
        if b.first_record != cursor:
            raise AddressSpaceGapError(
                f"{path.name}: 块 {b.block_id} 起点 {b.first_record} != 游标 {cursor}")
        cursor += b.record_count
    if cursor != scnt:
        raise AddressSpaceGapError(
            f"{path.name}: 块表覆盖 {cursor} 条记录，偏移表有 {scnt} 条")
    derived = _derive_blocks(records)
    got = [(b.record_count, b.first_record) for b in blocks]
    if derived != got:
        raise StructureError(
            f"{path.name}: 块表与按页结束记录推导的结果不一致，"
            f"首个分歧于 {_first_diff(derived, got)}")
    for b in blocks:
        for k in range(b.first_record, b.first_record + b.record_count):
            object.__setattr__(records[k], "block_id", b.block_id)


def _derive_blocks(records: Sequence[Record]) -> list[tuple[int, int]]:
    starts = [0]
    for i, r in enumerate(records):
        if r.type_byte in _TERMINATORS and i + 1 < len(records):
            starts.append(i + 1)
    out = []
    for j, st in enumerate(starts):
        en = starts[j + 1] if j + 1 < len(starts) else len(records)
        out.append((en - st, st))
    return out


def _first_diff(a: Sequence, b: Sequence):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return {"index": i, "derived": x, "stored": y}
    return {"index": min(len(a), len(b)), "len_derived": len(a), "len_stored": len(b)}


def load(path: Path) -> Doc:
    return parse_bytes(path.read_bytes(), path)


# ---------------------------------------------------------------- 文本发现


def _decode(b: bytes, enc: str) -> tuple[str, bool]:
    """禁止 surrogateescape / replace 兜底（§4.4）。失败即标 undecodable。"""
    try:
        t = b.decode(enc)
    except UnicodeDecodeError:
        return _to_placeholders(b), True
    if t.encode(enc) != b:
        return _to_placeholders(b), True
    return _escape_control(t, enc), False


def _to_placeholders(b: bytes) -> str:
    op = D.TEXT_FORMAT["placeholder_open"]
    cl = D.TEXT_FORMAT["placeholder_close"]
    sep = D.TEXT_FORMAT["placeholder_sep"]
    return op + sep.join("%02X" % c for c in b) + cl


def _escape_control(t: str, enc: str) -> str:
    """控制字符不可安全显示，逐字节转占位符；斜杠与全角空格保持原样。"""
    if not any(ord(c) < 0x20 for c in t):
        return t
    op = D.TEXT_FORMAT["placeholder_open"]
    cl = D.TEXT_FORMAT["placeholder_close"]
    sep = D.TEXT_FORMAT["placeholder_sep"]
    out = []
    for c in t:
        if ord(c) < 0x20:
            out.append(op + sep.join("%02X" % x for x in c.encode(enc)) + cl)
        else:
            out.append(c)
    return "".join(out)


def _from_placeholders(t: str, enc: str) -> bytes:
    """占位符直接解析为原始字节，忽略编码边界（§4.5）。"""
    out = bytearray()
    pos = 0
    for m in _PH_RE.finditer(t):
        if m.start() > pos:
            out += t[pos:m.start()].encode(enc)
        for h in m.group(1).split(D.TEXT_FORMAT["placeholder_sep"]):
            out.append(int(h, 16))
        pos = m.end()
    if pos < len(t):
        out += t[pos:].encode(enc)
    return bytes(out)


def _substantive(t: str) -> bool:
    return bool(_MARKUP.sub("", t).strip().strip(D.IDEOGRAPHIC_SPACE))


def _discover_cstl(doc: Doc) -> None:
    """.cstl 的文本投影：每条按语言 × (说话者, 正文) 展开。

    空说话者槽表示旁白，不导出——译者对着一个空条目做不出任何不同的操作（§4.6）。
    说话者与正文的绑定由槽位序号直接给出（slot-ordinal），无需前瞻或顺序偏好。
    """
    per = D.CSTL["slots_per_lang"] * len(doc.langs)
    entries: list[TextEntry] = []
    bindings: list[dict] = []
    idx = 0
    name_idx: dict[int, int] = {}
    for rec in doc.records:
        slot = rec.rec_id % per
        lang = doc.langs[slot // D.CSTL["slots_per_lang"]]
        role = D.CSTL["slot_roles"][slot % D.CSTL["slots_per_lang"]]
        meta = D.CSTL_SLOTS[role]
        src, bad = _decode(rec.payload, D.CSTL["encoding"])
        idx += 1
        entries.append(TextEntry(
            idx=idx, rec_id=rec.rec_id, tag=meta["tag"],
            tag_subtype=f'{meta["tag_subtype"]}:{lang}',
            tag_source=meta["tag_source"],
            translate_policy="frozen" if bad else meta["translate_policy"],
            source=src, raw=rec.payload, prefix=b"", suffix=b"",
            speaker_idx=None, rule_id=None, matched_rule_id=None,
            undecodable=bad, exported=bool(rec.payload)))
        if role == "name":
            name_idx[rec.rec_id] = idx
        elif rec.rec_id - 1 in name_idx:
            n = name_idx[rec.rec_id - 1]
            bindings.append({
                "binding_id": f"B{rec.rec_id:06d}", "name_entry_idx": n,
                "msg_entry_idx": idx, "name_kind": "actual",
                "method": "slot-ordinal", "confidence": "derived",
                "candidates": [idx], "agreed_by": ["cstl-slot"],
                "evidence_refs": ["EV_CSTL_LAYOUT"]})
    doc.text_entries = entries
    doc.name_bindings = bindings
    doc.rule_hits = dict.fromkeys((r["id"] for r, _ in _RULES), 0)
    doc.window_hits = {w["name"]: 0 for w in D.WINDOWS}
    spk = {b["msg_entry_idx"]: b["name_entry_idx"] for b in bindings}
    for i, e in enumerate(entries):
        if e.idx in spk:
            doc.text_entries[i] = _with_speaker(e, spk[e.idx])


def discover_text(doc: Doc, source_encoding: str) -> None:
    """从已解析的记录结构投影文本条目。不对原始字节做旁路扫描（铁律 2）。"""
    if doc.form == "cstl":
        _discover_cstl(doc)
        return
    rules = dict.fromkeys((r["id"] for r, _ in _RULES), 0)
    windows = {w["name"]: 0 for w in D.WINDOWS}
    entries: list[TextEntry] = []
    idx = 0
    open_cmd: str | None = None
    open_span = 0
    span_limit = next(w["value"] for w in D.WINDOWS if w["name"] == "choice_block_span")
    for rec in doc.records:
        meta = D.RECORD_TYPES[rec.type_byte]
        if meta["role"] == "text":
            open_cmd = None
            open_span = 0
            idx += 1
            src, bad = _decode(rec.payload, source_encoding)
            blank = D.EMPTY_TEXT_RECORD
            is_flush = (not rec.payload
                        and rec.type_byte in blank["applies_to_types"])
            if is_flush:
                entries.append(TextEntry(
                    idx=idx, rec_id=rec.rec_id, tag=blank["tag"],
                    tag_subtype=blank["tag_subtype"],
                    tag_source=blank["tag_source"],
                    translate_policy=blank["translate_policy"],
                    source=src, raw=rec.payload, prefix=b"", suffix=b"",
                    speaker_idx=None, rule_id=None,
                    matched_rule_id="empty-text-record", undecodable=bad,
                    exported=blank["export_to_text_file"]))
                continue
            entries.append(TextEntry(
                idx=idx, rec_id=rec.rec_id, tag=meta["tag"],
                tag_subtype=meta["tag_subtype"], tag_source=meta["tag_source"],
                translate_policy="frozen" if bad else meta["translate_policy"],
                source=src, raw=rec.payload, prefix=b"", suffix=b"",
                speaker_idx=None, rule_id=None, matched_rule_id=None,
                undecodable=bad))
            continue
        if rec.type_byte != _TYPE_CMD:
            open_cmd = None
            open_span = 0
            continue
        head, hit = _classify_command(rec, open_cmd, source_encoding)
        if head == D.CHOICE_OPEN_COMMAND:
            open_cmd = head
            open_span = 0
            continue
        if hit is None:
            open_cmd = None
            open_span = 0
            continue
        rule, m = hit
        if rule.get("requires_open_command"):
            open_span += 1
            if open_span > span_limit:
                windows["choice_block_span"] += 1
                raise StructureError(
                    f"{doc.path.name}: 记录 {rec.rec_id} 处 {rule['id']} 块跨度超过"
                    f"窗口上限 {span_limit}，按 on_exceed=blocked 停止")
        rules[rule["id"]] += 1
        idx += 1
        pre = m.group(1).encode(source_encoding)
        body = m.group(2)
        suf = m.group(3).encode(source_encoding)
        src, bad = _decode(body.encode(source_encoding), source_encoding)
        entries.append(TextEntry(
            idx=idx, rec_id=rec.rec_id, tag=rule["tag"],
            tag_subtype=rule["tag_subtype"], tag_source=rule["tag_source"],
            translate_policy="frozen" if bad else rule["translate_policy"],
            source=src, raw=body.encode(source_encoding), prefix=pre, suffix=suf,
            speaker_idx=None, rule_id=rule["id"], matched_rule_id=rule["id"],
            undecodable=bad))
    doc.text_entries = entries
    doc.rule_hits = rules
    doc.window_hits = windows
    _bind_names(doc)


def _classify_command(rec: Record, open_cmd: str | None, enc: str):
    """命令记录的操作数分类。规则按声明顺序求值，首个命中即返回，无兜底规则。"""
    try:
        t = rec.payload.decode(enc)
    except UnicodeDecodeError:
        return None, None
    head = t.split(D.COMMAND_HEAD_SEPARATOR)[0]
    if head == D.CHOICE_OPEN_COMMAND:
        return head, None
    for rule, pat in _RULES:
        need = rule.get("requires_open_command")
        if need is not None and open_cmd != need:
            continue
        m = pat.match(t)
        if m:
            return head, (rule, m)
    return head, None


def _bind_names(doc: Doc) -> None:
    """人名绑定：块内 NAME 记录与其后第一条实义 MSG 配对。
    method=slot-ordinal —— 依据是「块内至多一条 NAME」这一已证明的结构约束，
    不是「第一个匹配的是名字」这类顺序偏好。"""
    by_rec = {e.rec_id: e for e in doc.text_entries}
    bindings = []
    for blk in doc.blocks:
        lo, hi = blk.first_record, blk.first_record + blk.record_count
        names = [r for r in doc.records[lo:hi] if r.type_byte == _TYPE_NAME]
        if not names:
            continue
        if len(names) > 1:
            doc.unresolved.append({
                "kind": "multi_name_block", "block_id": blk.block_id,
                "rec_ids": [r.rec_id for r in names],
                "reason": "块内多于一条 NAME，绑定歧义，不任选"})
            continue
        nm = names[0]
        cands = [r for r in doc.records[nm.rec_id + 1:hi]
                 if r.type_byte == _TYPE_MSG
                 and _substantive(by_rec[r.rec_id].source)]
        ne = by_rec.get(nm.rec_id)
        if ne is None:
            continue
        if not cands:
            bindings.append({
                "binding_id": f"B{blk.block_id:06d}", "name_entry_idx": ne.idx,
                "msg_entry_idx": None, "name_kind": "actual",
                "method": "slot-ordinal", "confidence": "ambiguous",
                "candidates": [], "agreed_by": ["block-slot"],
                "evidence_refs": ["EV_NAME_PER_BLOCK"]})
            doc.unresolved.append({
                "kind": "name_without_message", "block_id": blk.block_id,
                "rec_id": nm.rec_id, "reason": "块内 NAME 之后无实义 MSG"})
            continue
        me = by_rec[cands[0].rec_id]
        conf = "derived" if len(cands) == 1 else "ambiguous"
        bindings.append({
            "binding_id": f"B{blk.block_id:06d}", "name_entry_idx": ne.idx,
            "msg_entry_idx": me.idx, "name_kind": "actual",
            "method": "slot-ordinal", "confidence": conf,
            "candidates": [by_rec[c.rec_id].idx for c in cands],
            "agreed_by": ["block-slot"],
            "evidence_refs": ["EV_NAME_PER_BLOCK", "EV_NAME_FOLLOWED_BY_MSG"]})
        if conf == "ambiguous":
            doc.unresolved.append({
                "kind": "multi_message_block", "block_id": blk.block_id,
                "candidates": [by_rec[c.rec_id].idx for c in cands],
                "reason": "同一 NAME 有多条实义 MSG 候选，按 §4.7 标 ambiguous"})
    doc.name_bindings = bindings
    spk: dict[int, int] = {}
    for b in bindings:
        if b["msg_entry_idx"] is not None and b["confidence"] == "derived":
            spk[b["msg_entry_idx"]] = b["name_entry_idx"]
    if spk:
        for i, e in enumerate(doc.text_entries):
            if e.idx in spk:
                doc.text_entries[i] = _with_speaker(e, spk[e.idx])


def _with_speaker(e: TextEntry, s: int) -> TextEntry:
    return TextEntry(e.idx, e.rec_id, e.tag, e.tag_subtype, e.tag_source,
                     e.translate_policy, e.source, e.raw, e.prefix, e.suffix,
                     s, e.rule_id, e.matched_rule_id, e.undecodable, e.exported)


def _build_join_sites(doc: Doc) -> None:
    """引用连接：偏移表每槽的值等于某记录在数据区内的起始偏移（key=entry_offset）。
    这个集合同时是文本发现的依据和变长回封必须回填的槽位集合（§3）。"""
    hdr = D.PAYLOAD["header"]["size"]
    tbase = hdr + doc.table_offset
    esz = D.PAYLOAD["offset_table"]["entry_size"]
    key_set = {r.offset for r in doc.records}
    if len(key_set) != len(doc.records):
        raise AddressSpaceCollisionError(f"{doc.path.name}: 记录起始偏移不唯一")
    sites = []
    for i, r in enumerate(doc.records):
        off = tbase + esz * i
        sites.append(JoinSite(
            join_id=f"J{i:06d}", site_offset=off, site_width=esz,
            key_kind=D.PAYLOAD["offset_table"]["key_kind"], key_value=r.offset,
            target_rec_id=r.rec_id, collision_class="unique",
            rewrite_policy="rewrite", confidence="derived"))
    doc.join_sites = sites


# ---------------------------------------------------------------- 重建


def _repack_cstl(doc: Doc, ov: dict[int, bytes]) -> tuple[bytes, dict]:
    """.cstl 重建。长度字段就是引用槽，逐条重新发出即完成回填。"""
    C = D.CSTL
    out = bytearray(C["magic"])
    out += bytes(C["reserved"]["width"])
    out.append(len(doc.langs))
    for lg in doc.langs:
        e = lg.encode("ascii")
        out += _cstl_emit(len(e))
        out += e
    out += _cstl_emit(doc.cstl_count)
    reloc = []
    for r in doc.records:
        blob = ov.get(r.rec_id, r.payload)
        if len(blob) != len(r.payload):
            reloc.append({"join_id": f"J{r.rec_id:06d}", "offset": len(out),
                          "length": len(_cstl_emit(len(blob))),
                          "old": len(r.payload), "new": len(blob)})
        out += _cstl_emit(len(blob))
        out += blob
    blob = bytes(out)
    return blob, {"relocations": reloc, "payload": blob,
                  "payload_sha256": _sha256(blob), "stream_len": len(blob),
                  "stream_reused": False, "form": "cstl"}


def repack(doc: Doc, overrides: dict[int, bytes] | None = None) -> tuple[bytes, dict]:
    """从 IR 重建。overrides: rec_id -> 新 payload。按站点回填，不按值匹配（§6.3）。"""
    ov = overrides or {}
    if doc.form == "cstl":
        return _repack_cstl(doc, ov)
    hdr = D.PAYLOAD["header"]["size"]
    ent = D.PAYLOAD["block_table"]["entry_size"]
    esz = D.PAYLOAD["offset_table"]["entry_size"]
    body = bytearray()
    new_off: list[int] = []
    for r in doc.records:
        new_off.append(len(body))
        body.append(_PREFIX)
        body.append(r.type_byte)
        body += ov.get(r.rec_id, r.payload)
        body += _TERM
    tbase = hdr + ent * len(doc.blocks)
    dbase = tbase + esz * len(doc.records)
    out = bytearray(dbase + len(body))
    _U32X4.pack_into(out, 0, len(out) - hdr, len(doc.blocks), tbase - hdr, dbase - hdr)
    for i, b in enumerate(doc.blocks):
        _U32X2.pack_into(out, hdr + ent * i, b.record_count, b.first_record)
    reloc = []
    for site, val in zip(doc.join_sites, new_off):
        _U32.pack_into(out, site.site_offset, val)
        if val != site.key_value:
            reloc.append({"join_id": site.join_id, "offset": site.site_offset,
                          "length": site.site_width, "old": site.key_value,
                          "new": val})
    out[dbase:] = body
    payload = bytes(out)
    # 未修改块复用原始压缩结果（§6.4）。这不只是省时间：不同 deflate 实现对同一
    # 输入会产出不同的合法字节流，重新压缩会让零编辑往返在那些文件上无法逐字节一致。
    # 载荷相同就把原始 zlib 流原样写回，往返即恒等。
    payload_sha = _sha256(payload)
    if doc.form == "bare-payload":
        # 读进来是裸载荷就按裸载荷写回。不擅自加上 CatScene 头——
        # 那会让「重建产物与输入形态一致」这条不成立，使用者也分不清拿到的是哪种文件。
        return payload, {"relocations": reloc, "payload": payload,
                         "payload_sha256": payload_sha,
                         "stream_len": len(payload), "stream_reused": True,
                         "form": "bare-payload"}
    reused = payload_sha == doc.payload_sha256
    if reused:
        stream = doc.zlib_stream
    else:
        stream = zlib.compress(payload, D.CONTAINER["compression"]["level"])
    container = bytearray(_HDR)
    container[:len(_MAGIC)] = _MAGIC
    _U32.pack_into(container, D.CONTAINER["field_com_size"]["offset"], len(stream))
    _U32.pack_into(container, D.CONTAINER["field_unc_size"]["offset"], len(payload))
    return bytes(container) + stream, {
        "relocations": reloc, "payload": payload,
        "payload_sha256": payload_sha, "stream_len": len(stream),
        "stream_reused": reused, "form": "container"}


# ---------------------------------------------------------------- 覆盖证书


def coverage_certificate(doc: Doc) -> dict:
    """容器层区间：魔数、两个长度字段、zlib 流。每字节唯一归属，无缺口无重叠。
    裸载荷形态没有容器层，区间就是载荷本身的四段。"""
    ms = D.CONTAINER["magic_size"]
    co = D.CONTAINER["field_com_size"]
    uo = D.CONTAINER["field_unc_size"]
    data = doc.path.read_bytes()
    if doc.form == "cstl":
        return _cstl_certificate(doc, data)
    if doc.form == "bare-payload":
        return _bare_certificate(doc, data)
    iv = [
        ("C_MAGIC", 0, ms, "decoded", "magic"),
        ("C_COMSZ", co["offset"], co["offset"] + co["width"], "decoded", "length-field"),
        ("C_UNCSZ", uo["offset"], uo["offset"] + uo["width"], "decoded", "length-field"),
        ("C_ZSTREAM", _HDR, _HDR + doc.com_size, "decoded", "compressed-payload"),
    ]
    intervals = []
    tiers = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    for iid, s, e, status, kind in iv:
        tier = "T2"
        tiers[tier] += e - s
        intervals.append({
            "id": iid, "layer_id": "L000", "start": s, "end": e, "status": status,
            "kind": kind, "raw_sha256": _sha256(data[s:e]), "owner": "container",
            "decode_tier": tier,
            "tier_evidence_refs": D.CONTAINER["evidence_refs"],
            "tier_blocked_at": None, "confidence": D.CONTAINER["confidence"],
            "evidence_refs": D.CONTAINER["evidence_refs"],
            "rewrite_policy": "regenerate" if kind == "length-field" else "rewrite",
        })
    counts = {}
    for i in intervals:
        counts[i["status"]] = counts.get(i["status"], 0) + i["end"] - i["start"]
    covered = sum(i["end"] - i["start"] for i in intervals)
    tag_src = {"structural": 0, "anchor": 0, "binding": 0,
               "heuristic": 0, "user": 0, "unresolved": 0}
    for e in doc.text_entries:
        tag_src[e.tag_source] = tag_src.get(e.tag_source, 0) + 1
    return {
        "schema_version": "1.1.0", "layer_id": "L000",
        "source": doc.path.name, "source_size": doc.raw_size,
        "intervals": intervals, "gaps": [], "overlaps": [],
        "status_counts": counts,
        "byte_coverage": covered / doc.raw_size if doc.raw_size else 1.0,
        "structural_coverage": 1.0, "tier_coverage": tiers,
        "min_tier": D.TIERS["min_tier"],
        "declared_capabilities": list(D.TIERS["declared_capabilities"]),
        "tier_blocked": [], "instruction_coverage": D.TIERS["instruction_coverage"],
        "tag_source_counts": tag_src,
        "analysis_mode": D.DECISION["analysis_mode"],
        "unpack_mode": D.DECISION["unpack_mode"],
        "text_source": D.DECISION["text_source"],
        "decision_evidence_refs": list(D.DECISION["decision_evidence_refs"]),
        "transform_edges": [payload_layer(doc)],
        "toolchain": {"tool": D.TOOL_VERSION, "ir": D.IR_VERSION,
                      "dialect": D.ENGINE_ID, "schema": D.SCHEMA_VERSION},
    }


def _cstl_certificate(doc: Doc, data: bytes) -> dict:
    """.cstl 覆盖证书：头 + 逐条 (长度字段 + UTF-8 字节)，恰好平铺整个文件。"""
    head_end = doc.records[0].offset - len(_cstl_emit(len(doc.records[0].payload))) \
        if doc.records else len(data)
    intervals = [{"id": "L_HEAD", "start": 0, "end": head_end,
                  "status": "decoded", "kind": "cstl-header",
                  "decode_tier": "T2"}]
    for r in doc.records:
        w = len(_cstl_emit(len(r.payload)))
        intervals.append({"id": f"L_STR{r.rec_id:06d}", "start": r.offset - w,
                          "end": r.offset + len(r.payload), "status": "decoded",
                          "kind": "cstl-string", "decode_tier": "T3"})
    intervals = [i for i in intervals if i["end"] > i["start"]]
    cursor = 0
    for i in intervals:
        if i["start"] != cursor:
            raise AddressSpaceGapError(
                f"{doc.path.name}: 区间 {i['id']} 起点 {i['start']} != 游标 {cursor}")
        cursor = i["end"]
    if cursor != len(data):
        raise AddressSpaceGapError(
            f"{doc.path.name}: 区间止于 {cursor}，文件长 {len(data)}")
    tiers = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    counts: dict[str, int] = {}
    for i in intervals:
        n = i["end"] - i["start"]
        tiers[i["decode_tier"]] += n
        counts[i["status"]] = counts.get(i["status"], 0) + n
        i.update({"layer_id": "L000",
                  "raw_sha256": _sha256(data[i["start"]:i["end"]]),
                  "owner": "cstl", "tier_evidence_refs": D.CSTL["evidence_refs"],
                  "tier_blocked_at": None, "confidence": D.CSTL["confidence"],
                  "evidence_refs": D.CSTL["evidence_refs"],
                  "rewrite_policy": "rewrite"})
    tag_src = {"structural": 0, "anchor": 0, "binding": 0,
               "heuristic": 0, "user": 0, "unresolved": 0}
    for e in doc.text_entries:
        tag_src[e.tag_source] = tag_src.get(e.tag_source, 0) + 1
    return {
        "schema_version": "1.1.0", "layer_id": "L000",
        "source": doc.path.name, "source_size": len(data),
        "intervals": intervals, "gaps": [], "overlaps": [],
        "status_counts": counts, "byte_coverage": 1.0,
        "structural_coverage": 1.0, "tier_coverage": tiers,
        "min_tier": "T2", "container_form": "cstl",
        "languages": list(doc.langs), "entries": doc.cstl_count,
        "declared_capabilities": list(D.TIERS["declared_capabilities"]),
        "tier_blocked": [], "instruction_coverage": "not_applicable",
        "tag_source_counts": tag_src,
        "analysis_mode": "data-text-only", "unpack_mode": "not-required",
        "text_source": "embedded",
        "decision_evidence_refs": list(D.CSTL["evidence_refs"]),
        "transform_edges": [], "roundtrip": {},
        "toolchain": {"tool": D.TOOL_VERSION, "ir": D.IR_VERSION,
                      "dialect": D.ENGINE_ID, "schema": D.SCHEMA_VERSION},
    }


def _bare_certificate(doc: Doc, data: bytes) -> dict:
    """裸载荷的覆盖证书：区间直接落在载荷结构上，没有 transform 层。"""
    pc = payload_certificate(doc)
    intervals = []
    tiers = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    for i in pc["intervals"]:
        tiers[i["decode_tier"]] += i["end"] - i["start"]
        intervals.append({
            "id": i["id"], "layer_id": "L000", "start": i["start"],
            "end": i["end"], "status": i["status"], "kind": i["kind"],
            "raw_sha256": _sha256(data[i["start"]:i["end"]]),
            "owner": "bare-payload", "decode_tier": i["decode_tier"],
            "tier_evidence_refs": ["EV_BARE_PAYLOAD", "EV_PAYLOAD_HDR"],
            "tier_blocked_at": None, "confidence": "derived",
            "evidence_refs": ["EV_BARE_PAYLOAD"], "rewrite_policy": "rewrite"})
    counts: dict[str, int] = {}
    for i in intervals:
        counts[i["status"]] = counts.get(i["status"], 0) + i["end"] - i["start"]
    tag_src = {"structural": 0, "anchor": 0, "binding": 0,
               "heuristic": 0, "user": 0, "unresolved": 0}
    for e in doc.text_entries:
        tag_src[e.tag_source] = tag_src.get(e.tag_source, 0) + 1
    return {
        "schema_version": "1.1.0", "layer_id": "L000",
        "source": doc.path.name, "source_size": len(data),
        "intervals": intervals, "gaps": [], "overlaps": [],
        "status_counts": counts, "byte_coverage": 1.0,
        "structural_coverage": 1.0, "tier_coverage": tiers,
        "min_tier": D.TIERS["min_tier"],
        "declared_capabilities": list(D.TIERS["declared_capabilities"]),
        "tier_blocked": [], "instruction_coverage": D.TIERS["instruction_coverage"],
        "tag_source_counts": tag_src, "container_form": "bare-payload",
        "analysis_mode": D.DECISION["analysis_mode"],
        "unpack_mode": "not-required",
        "text_source": D.DECISION["text_source"],
        "decision_evidence_refs": ["EV_BARE_PAYLOAD", "EV_PAYLOAD_HDR"],
        "transform_edges": [], "roundtrip": {},
        "toolchain": {"tool": D.TOOL_VERSION, "ir": D.IR_VERSION,
                      "dialect": D.ENGINE_ID, "schema": D.SCHEMA_VERSION},
    }


def payload_layer(doc: Doc) -> dict:
    return {
        "id": "L001", "parent": "L000",
        "source_span": [_HDR, _HDR + doc.com_size],
        "input_hash": _sha256(doc.zlib_stream), "output_hash": doc.payload_sha256,
        "algorithm": D.CONTAINER["compression"]["algorithm"],
        "key_ref": None,
        "params": {"level": D.CONTAINER["compression"]["level"],
                   "wbits": D.CONTAINER["compression"]["wbits"]},
        "order": 0, "reversible": True,
        "confidence": D.CONTAINER["compression"]["confidence"],
        "evidence_refs": D.CONTAINER["compression"]["evidence_refs"],
    }


def payload_certificate(doc: Doc) -> dict:
    """载荷层区间：载荷头、块表、偏移表、逐条记录。数据区每字节唯一归属。"""
    if doc.form == "cstl":
        c = _cstl_certificate(doc, doc.path.read_bytes())
        return {"schema_version": "1.1.0", "layer_id": "L000",
                "source_size": c["source_size"], "intervals": c["intervals"],
                "gaps": [], "overlaps": [], "byte_coverage": 1.0,
                "structural_coverage": 1.0,
                "tier_coverage": c["tier_coverage"], "min_tier": "T2",
                "record_count": len(doc.records),
                "block_count": len(doc.blocks)}
    hdr = D.PAYLOAD["header"]["size"]
    ent = D.PAYLOAD["block_table"]["entry_size"]
    esz = D.PAYLOAD["offset_table"]["entry_size"]
    tbase = hdr + doc.table_offset
    dbase = hdr + doc.data_offset
    if tbase != hdr + ent * len(doc.blocks):
        raise StructureError(
            f"{doc.path.name}: 块表跨度与 table_offset 不符")
    intervals = [
        {"id": "P_HDR", "start": 0, "end": hdr, "status": "decoded",
         "kind": "payload-header", "decode_tier": "T2"},
        {"id": "P_BLOCKS", "start": hdr, "end": tbase,
         "status": "decoded", "kind": "block-table", "decode_tier": "T2"},
        {"id": "P_OFFSETS", "start": tbase, "end": dbase,
         "status": "decoded", "kind": "offset-table", "decode_tier": "T2"},
    ]
    for r in doc.records:
        s = dbase + r.offset
        intervals.append({
            "id": f"P_REC{r.rec_id:06d}", "start": s, "end": s + r.total_size,
            "status": "decoded", "kind": "record", "decode_tier": "T3",
            "type_byte": r.type_byte,
            "mnemonic": D.RECORD_TYPES[r.type_byte]["mnemonic"]})
    intervals = [i for i in intervals if i["end"] > i["start"]]
    cursor = 0
    for i in intervals:
        if i["start"] != cursor:
            raise AddressSpaceGapError(
                f"{doc.path.name}: 载荷区间 {i['id']} 起点 {i['start']} != 游标 {cursor}")
        cursor = i["end"]
    if cursor != doc.payload_len:
        raise AddressSpaceGapError(
            f"{doc.path.name}: 载荷区间止于 {cursor}，载荷长 {doc.payload_len}")
    tiers = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    for i in intervals:
        tiers[i["decode_tier"]] += i["end"] - i["start"]
    return {"schema_version": "1.1.0", "layer_id": "L001",
            "source_size": doc.payload_len, "intervals": intervals,
            "gaps": [], "overlaps": [], "byte_coverage": 1.0,
            "structural_coverage": 1.0, "tier_coverage": tiers,
            "min_tier": "T2", "record_count": len(doc.records),
            "block_count": len(doc.blocks)}


# ---------------------------------------------------------------- 产出合理性门禁


def sanity_gate(stats: dict) -> list[str]:
    """§0.1：对产出本身的检查。命中即失败，不允许当作样本特性放过。"""
    fails = []
    tags = stats.get("tags", {})
    total = sum(tags.values())
    for need in D.SANITY["require_nonzero_tags"]:
        if tags.get(need, 0) == 0:
            fails.append(f"目标产出为 0：tag={need} 一条未命中。"
                         f"剧本类样本不可能没有 {need}，按 §0.1 判失败")
    if total:
        for k, v in tags.items():
            if v / total > D.SANITY["max_single_tag_share"] and len(tags) > 1:
                fails.append(f"产出高度倾斜：tag={k} 占 {v / total:.1%}，"
                             f"超过 {D.SANITY['max_single_tag_share']:.0%}")
    kib = stats.get("source_bytes", 0) / 1024.0
    if kib > 0:
        dens = tags.get("msg", 0) / kib
        if dens < D.SANITY["min_msg_per_kib"]:
            fails.append(f"正文密度过低：{dens:.4f} 条/KiB，"
                         f"低于下限 {D.SANITY['min_msg_per_kib']}")
    if stats.get("record_types_unknown"):
        fails.append(f"存在未登记的记录类型字节：{stats['record_types_unknown']}")
    return fails


# ---------------------------------------------------------------- 自检


def selfcheck(doc: Doc, data: bytes) -> dict:
    """零编辑往返自检（§9）。identical 为真时不跑第二轮——那是在证明恒等式（§12.8）。"""
    rebuilt, info = repack(doc)
    identical = rebuilt == data
    r = {"identical": identical,
         "payload_identical": info["payload_sha256"] == doc.payload_sha256,
         "src_sha256": doc.raw_sha256, "rebuilt_sha256": _sha256(rebuilt),
         "relocations": len(info["relocations"]),
         "stable": None, "first_diff": None}
    if identical:
        r["stable"] = True
        return r
    for i, (a, b) in enumerate(zip(data, rebuilt)):
        if a != b:
            r["first_diff"] = {"offset": i, "src": a, "rebuilt": b}
            break
    if r["first_diff"] is None:
        r["first_diff"] = {"offset": min(len(data), len(rebuilt)),
                           "src_len": len(data), "rebuilt_len": len(rebuilt)}
    doc2 = parse_bytes(rebuilt, doc.path)
    again, _ = repack(doc2)
    r["stable"] = (again == rebuilt)
    return r


# ---------------------------------------------------------------- asm 投影


def render_asm(doc: Doc, tier: str) -> str:
    a = D.ASM
    lines = [
        a["encoding_directive"].format(enc=D.ENCODING["source"]),
        a["dialect_directive"].format(engine=D.ENGINE_ID, ver=D.SCHEMA_VERSION),
        a["tier_directive"].format(tier=tier),
        f'{a["comment_prefix"]} source {doc.path.name} sha256 {doc.raw_sha256}',
        f'{a["comment_prefix"]} payload {doc.payload_len} bytes, '
        f'{len(doc.records)} records, {len(doc.blocks)} blocks',
    ]
    by_rec = {e.rec_id: e for e in doc.text_entries}
    for blk in doc.blocks:
        lines.append("")
        lines.append(a["label_format"].format(n=blk.block_id))
        lo, hi = blk.first_record, blk.first_record + blk.record_count
        for r in doc.records[lo:hi]:
            meta = D.RECORD_TYPES[r.type_byte]
            e = by_rec.get(r.rec_id)
            if e is not None and not e.prefix and not e.suffix:
                text = e.source
            else:
                text, _ = _decode(r.payload, D.ENCODING["source"])
            body = a["string_directive"].format(text=_asm_escape(text)).strip()
            lines.append(a["record_format"].format(
                mnemonic=meta["mnemonic"], idx=r.rec_id, payload=body))
            if e is not None:
                note = f'{a["comment_prefix"]}   idx={e.idx:08d} tag={e.tag}'
                if e.speaker_idx:
                    note += f" speaker=idx{e.speaker_idx:08d}"
                lines.append("    " + note)
    lines.append("")
    return "\n".join(lines)


def _asm_escape(t: str) -> str:
    return t.replace('"', '{{22}}')


# ---------------------------------------------------------------- 双行文本投影


def render_texts(doc: Doc, job_sha: str, source_encoding: str,
                 target_encoding: str, idx_base: int = 0) -> str:
    """双行文本投影。idx 是作业内全局唯一的定宽十进制。
    frozen 条目仍然导出（§4.3），译文行预填原文以满足「逐字符相同」的校验。"""
    f = D.TEXT_FORMAT
    w = f["idx_width"]
    hdr = D.PAYLOAD["header"]["size"]
    dbase = hdr + doc.data_offset
    m = f["orig_mark"]
    n = f["tran_mark"]
    # .cstl 本身就是 UTF-8，与 .cst 的 cp932 无关。写错编码会让 ③ 报一堆
    # 假的「不可表示」错误，所以按形态取真实编码。
    if doc.form == "cstl":
        source_encoding = target_encoding = D.CSTL["encoding"]
    out = [
        f["header_line1"].format(ir=D.IR_VERSION, tool=D.TOOL_VERSION,
                                 job_sha256=job_sha, file_sha256=doc.raw_sha256),
        f["header_line2"].format(source=source_encoding, target=target_encoding),
        f["header_line3"].format(src=doc.path.name),
        f["header_line4"],
        f["comment_prefix"],
    ]
    if doc.form == "cstl":
        out.append(f'{f["comment_prefix"]} languages '
                   + " ".join(doc.langs))
    spk = {}
    for b in doc.name_bindings:
        if b["msg_entry_idx"] is not None:
            spk[b["msg_entry_idx"]] = b["name_entry_idx"]
    names = {e.idx: e.source for e in doc.text_entries if e.tag == "name"}
    for e in doc.text_entries:
        if not e.exported:
            continue          # 零长度结构标记，无可翻译内容（§4.6）
        rec = doc.records[e.rec_id]
        gidx = idx_base + e.idx
        meta = {"idx": f"{gidx:0{w}d}", "off": f"0x{dbase + rec.offset:08X}",
                "rec": e.rec_id, "tag": e.tag, "policy": e.translate_policy}
        s = spk.get(e.idx)
        if s is not None and s in names:
            line = f["meta_line_speaker"].format(speaker=names[s], **meta)
        else:
            line = f["meta_line"].format(**meta)
        if doc.form == "cstl":
            # 多语言层必须标出这条属于哪个语言槽——否则译者不知道该改哪一行。
            line += " lang=" + e.tag_subtype.rsplit(":", 1)[-1]
        out.append(line)
        # 译文行预填原文：译者在原句上改，而不是对着空行从零打字。
        # 与「留空」语义等价（§4.6：译文等于原文即未修改），但可编辑性完全不同。
        # 用 f-string 拼，不用 % 格式化——正文里的 % 会被当成格式符（实测 cstl 命中）。
        num = f"{gidx:0{w}d}"
        out.append(f"{m}{num}{m}{e.tag}{m}{e.source}")
        out.append(f"{n}{num}{n}{e.tag}{n}{e.source}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- IR 序列化


def _dumps(o) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def ir_records(doc: Doc, src_id: int, idx_base: int) -> dict[str, list[str]]:
    """IR 投影。逐条只写会被机器校验或被人读的字段——重复的常量走 ir/meta.json，
    原始字节走源文件（manifest 记 sha256，读时校验），不在 JSONL 里再存一份。"""
    hdr = D.PAYLOAD["header"]["size"]
    dbase = hdr + doc.data_offset
    ent = D.PAYLOAD["block_table"]["entry_size"]
    tbase = hdr + doc.table_offset
    out: dict[str, list[str]] = {}
    out["regions.jsonl"] = [_dumps(dict(r, src_id=src_id)) for r in (
        {"id": "P_HDR", "type": "payload-header", "start": 0, "end": hdr,
         "parse_status": "decoded", "decode_tier": "T2"},
        {"id": "P_BLOCKS", "type": "block-table", "start": hdr, "end": tbase,
         "parse_status": "decoded", "decode_tier": "T2"},
        {"id": "P_OFFSETS", "type": "offset-table", "start": tbase, "end": dbase,
         "parse_status": "decoded", "decode_tier": "T2"},
        {"id": "P_RECSTREAM", "type": "record-stream", "start": dbase,
         "end": doc.payload_len, "parse_status": "decoded", "decode_tier": "T3",
         "record_count": len(doc.records),
         "note": "逐条区间见 instructions.jsonl，逐字节归属见覆盖证书"},
    )]
    out["blocks.jsonl"] = [_dumps({
        "src_id": src_id, "block_id": b.block_id, "record_count": b.record_count,
        "first_record": b.first_record}) for b in doc.blocks]
    out["instructions.jsonl"] = [_dumps({
        "src_id": src_id, "rec_id": r.rec_id, "offset": dbase + r.offset,
        "size": r.total_size, "opcode": r.type_byte,
        "mnemonic": D.RECORD_TYPES[r.type_byte]["mnemonic"],
        "block_id": r.block_id}) for r in doc.records]
    out["join_sites.jsonl"] = [_dumps({
        "src_id": src_id, "join_id": s.join_id, "site_offset": s.site_offset,
        "site_width": s.site_width, "site_endianness": D.PAYLOAD["endianness"],
        "key_kind": s.key_kind, "key_value": s.key_value,
        "target_object_id": f"P_REC{s.target_rec_id:06d}",
        "collision_class": s.collision_class,
        "rewrite_policy": s.rewrite_policy}) for s in doc.join_sites]
    out["text_entries.jsonl"] = [_dumps({
        "src_id": src_id, "idx": idx_base + e.idx, "local_idx": e.idx,
        "rec_id": e.rec_id, "tag": e.tag, "tag_subtype": e.tag_subtype,
        "tag_source": e.tag_source, "translate_policy": e.translate_policy,
        "source": e.source, "raw_len": len(e.raw),
        "prefix": e.prefix.decode("latin-1"), "suffix": e.suffix.decode("latin-1"),
        "speaker_idx": None if e.speaker_idx is None else idx_base + e.speaker_idx,
        "matched_rule_id": e.matched_rule_id,
        "parse_status": "undecodable" if e.undecodable else "decoded",
        "exported": e.exported, "slot_capacity": None})
        for e in doc.text_entries]
    out["name_bindings.jsonl"] = [_dumps({
        "src_id": src_id, "binding_id": b["binding_id"],
        "name_entry_idx": idx_base + b["name_entry_idx"],
        "msg_entry_idx": None if b["msg_entry_idx"] is None
        else idx_base + b["msg_entry_idx"],
        "name_kind": b["name_kind"], "method": b["method"],
        "confidence": b["confidence"],
        "candidates": [idx_base + c for c in b["candidates"]]})
        for b in doc.name_bindings]
    out["unresolved.jsonl"] = [_dumps(dict(u, src_id=src_id))
                               for u in doc.unresolved]
    return out


def ir_meta() -> dict:
    """逐条记录里被省掉的常量集中放这里，供审计复原全字段视图。"""
    return {
        "schema_version": D.SCHEMA_VERSION, "ir": D.IR_VERSION,
        "tool": D.TOOL_VERSION, "dialect_id": D.ENGINE_ID,
        "endianness": D.PAYLOAD["endianness"],
        "layers": {"L000": "container", "L001": "zlib-payload"},
        "join_sites": {"source_layer": "L001", "target_layer": "L001",
                       "site_tier": "T2", "anchor_ref": "offset-table-slot",
                       "confidence": "derived",
                       "evidence_refs": ["EV_OFFSET_TABLE"]},
        "record_types": {("%#04x" % k): v for k, v in D.RECORD_TYPES.items()},
        "name_bindings": {"agreed_by": ["block-slot"],
                          "evidence_refs": ["EV_NAME_PER_BLOCK",
                                            "EV_NAME_FOLLOWED_BY_MSG"]},
        "raw_bytes_policy": "记录原始字节不内联进 IR；重建时从 manifest 记录的源文件"
                            "按 sha256 校验后重新解析，等价于内容寻址且不重复占盘",
    }


# ---------------------------------------------------------------- 批量作业

_IR_FILES = ("regions.jsonl", "blocks.jsonl", "instructions.jsonl",
             "join_sites.jsonl", "text_entries.jsonl", "name_bindings.jsonl",
             "unresolved.jsonl")


INPUT_SUFFIXES = (".cst", ".cstl")


def collect_inputs(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out.extend(sorted(q for q in p.rglob("*") if q.is_file()
                              and q.suffix.lower() in INPUT_SUFFIXES))
        elif p.is_file():
            out.append(p)
        else:
            raise CstError(f"输入不存在：{p}")
    if not out:
        raise CstError("没有找到 .cst / .cstl 文件")
    seen, uniq = set(), []
    for p in out:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def common_parent(paths: Sequence[Path]) -> Path:
    rs = [p.resolve() for p in paths]
    if len(rs) == 1:
        return rs[0].parent
    return Path(os.path.commonpath([str(p.parent) for p in rs]))


def _rel(p: Path, base: Path) -> str:
    try:
        return p.resolve().relative_to(base).as_posix()
    except ValueError:
        return p.name


def _one(job: tuple) -> dict:
    """worker：解析单个源，返回可 pickle 的记录段（§12.6）。"""
    path_s, rel, src_enc, tgt_enc, want_asm, key = job
    path = Path(path_s)
    try:
        data = path.read_bytes()
        doc = parse_bytes(data, path, key)
        discover_text(doc, src_enc)
        cert = coverage_certificate(doc)
        pcert = payload_certificate(doc)
        chk = selfcheck(doc, data)
        tags: dict[str, int] = {}
        for e in doc.text_entries:
            tags[e.tag] = tags.get(e.tag, 0) + 1
        pol: dict[str, int] = {}
        for e in doc.text_entries:
            pol[e.translate_policy] = pol.get(e.translate_policy, 0) + 1
        return {
            "ok": True, "rel": rel, "path": path_s, "sha256": doc.raw_sha256,
            "size": doc.raw_size, "cert": cert, "pcert_summary": {
                "record_count": pcert["record_count"],
                "block_count": pcert["block_count"],
                "byte_coverage": pcert["byte_coverage"],
                "tier_coverage": pcert["tier_coverage"]},
            "selfcheck": chk, "tags": tags, "policies": pol,
            "rule_hits": doc.rule_hits, "window_hits": doc.window_hits,
            "unresolved": len(doc.unresolved), "bindings": len(doc.name_bindings),
            "ambiguous_bindings": sum(1 for b in doc.name_bindings
                                      if b["confidence"] == "ambiguous"),
            "entries": len(doc.text_entries),
            "doc_state": _freeze(doc), "want_asm": want_asm,
            "form": doc.form, "cipher": doc.cipher["id"],
            "asm": render_asm(doc, D.TIERS["min_tier"]) if want_asm else None,
        }
    except Exception as exc:
        return {"ok": False, "rel": rel, "path": path_s,
                "error": f"{type(exc).__name__}: {exc}"}


def _freeze(doc: Doc) -> dict:
    """把 Doc 压成可 pickle 的最小状态，主进程用它渲染文本与写 IR。"""
    return {
        "raw_size": doc.raw_size, "raw_sha256": doc.raw_sha256,
        "com_size": doc.com_size, "unc_size": doc.unc_size,
        "payload_sha256": doc.payload_sha256,
        "payload_size_field": doc.payload_size_field,
        "block_count": doc.block_count, "table_offset": doc.table_offset,
        "data_offset": doc.data_offset, "payload_len": doc.payload_len,
        "blocks": [(b.block_id, b.record_count, b.first_record) for b in doc.blocks],
        "records": [(r.rec_id, r.offset, r.type_byte, r.payload, r.block_id)
                    for r in doc.records],
        "offsets": doc.offsets, "zlib_stream": doc.zlib_stream,
        "text_entries": [(e.idx, e.rec_id, e.tag, e.tag_subtype, e.tag_source,
                          e.translate_policy, e.source, e.raw, e.prefix, e.suffix,
                          e.speaker_idx, e.rule_id, e.matched_rule_id,
                          e.undecodable, e.exported) for e in doc.text_entries],
        "name_bindings": doc.name_bindings, "unresolved": doc.unresolved,
        "join_sites": [(s.join_id, s.site_offset, s.site_width, s.key_kind,
                        s.key_value, s.target_rec_id, s.collision_class,
                        s.rewrite_policy, s.confidence) for s in doc.join_sites],
        "rule_hits": doc.rule_hits, "window_hits": doc.window_hits,
        "form": doc.form, "cipher": doc.cipher,
        "langs": doc.langs, "cstl_count": doc.cstl_count,
    }


def thaw(state: dict, path: Path) -> Doc:
    doc = Doc(
        path=path, raw_size=state["raw_size"], raw_sha256=state["raw_sha256"],
        com_size=state["com_size"], unc_size=state["unc_size"],
        payload_sha256=state["payload_sha256"],
        payload_size_field=state["payload_size_field"],
        block_count=state["block_count"], table_offset=state["table_offset"],
        data_offset=state["data_offset"],
        blocks=[Block(*b) for b in state["blocks"]],
        records=[Record(*r) for r in state["records"]],
        offsets=list(state["offsets"]), payload_len=state["payload_len"],
        zlib_stream=state["zlib_stream"])
    doc.text_entries = [TextEntry(*t) for t in state["text_entries"]]
    doc.name_bindings = state["name_bindings"]
    doc.unresolved = state["unresolved"]
    doc.join_sites = [JoinSite(*s) for s in state["join_sites"]]
    doc.rule_hits = state["rule_hits"]
    doc.window_hits = state["window_hits"]
    doc.form = state["form"]
    doc.cipher = state["cipher"]
    doc.langs = state["langs"]
    doc.cstl_count = state["cstl_count"]
    return doc


def run_disasm(inputs: Sequence[Path], outdir: Path, source_encoding: str,
               target_encoding: str, want_asm: bool = True, jobs: int | None = None,
               progress=None, key: bytes | None = None) -> dict:
    """全量反汇编。IR 合库，文本与 asm 镜像原结构（§2.3）。"""
    base = common_parent(inputs)
    ir = outdir / "ir"
    for d in (ir, outdir / "texts", outdir / "reports", outdir / "logs"):
        d.mkdir(parents=True, exist_ok=True)
    if want_asm:
        (outdir / "asm").mkdir(parents=True, exist_ok=True)
    jobspec = [(str(p), _rel(p, base), source_encoding, target_encoding,
                want_asm, key) for p in inputs]
    results: list[dict] = []
    use_pool = jobs != 1 and len(jobspec) >= 8
    if use_pool:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for i, r in enumerate(pool.map(_one, jobspec, chunksize=8)):
                results.append(r)
                if progress:
                    progress(i + 1, len(jobspec), r["rel"])
    else:
        for i, spec in enumerate(jobspec):
            results.append(_one(spec))
            if progress:
                progress(i + 1, len(jobspec), results[-1]["rel"])
    results.sort(key=lambda r: r["rel"])
    failures = [r for r in results if not r["ok"]]
    ok = [r for r in results if r["ok"]]
    job_sha = hashlib.sha256(
        "".join(f"{r['rel']}:{r['sha256']}" for r in ok).encode()).hexdigest()
    buf: dict[str, list[str]] = {k: [] for k in _IR_FILES}
    manifest: list[str] = []
    certs: list[dict] = []
    line_at = {k: 1 for k in _IR_FILES}
    idx_base = 0
    for src_id, r in enumerate(ok):
        doc = thaw(r["doc_state"], Path(r["path"]))
        recs = ir_records(doc, src_id, idx_base)
        ranges = {}
        for k in _IR_FILES:
            n = len(recs.get(k, []))
            ranges[k] = [line_at[k], line_at[k] + n]
            line_at[k] += n
            buf[k].extend(recs.get(k, []))
        manifest.append(_dumps({
            "src_id": src_id, "sha256": r["sha256"], "path": r["rel"],
            "size": r["size"], "records": len(doc.records),
            "blocks": len(doc.blocks), "entries": len(doc.text_entries),
            "idx_base": idx_base, "decode_tier": D.TIERS["min_tier"],
            "payload_sha256": doc.payload_sha256, "line_ranges": ranges}))
        certs.append(r["cert"])
        tp = outdir / "texts" / (r["rel"] + ".txt")
        _atomic_write_text(tp, render_texts(doc, job_sha, source_encoding,
                                           target_encoding, idx_base),
                           D.ENCODING["text_file"])
        if want_asm and r["asm"] is not None:
            _atomic_write_text(outdir / "asm" / (r["rel"] + ".asm.txt"),
                               r["asm"], D.ENCODING["asm"])
        idx_base += len(doc.text_entries)
    job_line = _dumps({"src_id": -1, "sha256": job_sha, "path": "(job)",
                       "kind": "job-anchor", "files": len(ok),
                       "entries": idx_base, "source_root": str(base),
                       "source_encoding": source_encoding,
                       "target_encoding": target_encoding,
                       "note": "本行是作业级锚，双行文本文件头的 src_sha256 与它比对"})
    _atomic_write_text(ir / "manifest.jsonl",
                       "\n".join([job_line] + manifest) + "\n", "utf-8")
    for k in _IR_FILES:
        _atomic_write_text(ir / k, "\n".join(buf[k]) + "\n" if buf[k] else "", "utf-8")
    _atomic_write_text(ir / "decision.json",
                       json.dumps(D.DECISION, ensure_ascii=False, indent=2,
                                  sort_keys=True), "utf-8")
    _atomic_write_text(ir / "meta.json",
                       json.dumps(ir_meta(), ensure_ascii=False, indent=2,
                                  sort_keys=True), "utf-8")
    report = _build_report(ok, failures, certs, job_sha, source_encoding,
                           target_encoding, base, outdir)
    _atomic_write_text(outdir / "reports" / "coverage_certificate.json",
                       json.dumps({"job_sha256": job_sha, "certificates": certs},
                                  ensure_ascii=False, indent=2, sort_keys=True),
                       "utf-8")
    _atomic_write_text(outdir / "reports" / "disasm.json",
                       json.dumps(report, ensure_ascii=False, indent=2,
                                  sort_keys=True), "utf-8")
    return report


def _build_report(ok, failures, certs, job_sha, senc, tenc, base, outdir) -> dict:
    tags: dict[str, int] = {}
    pol: dict[str, int] = {}
    rules: dict[str, int] = {}
    win: dict[str, int] = {}
    tsrc: dict[str, int] = {}
    src_bytes = 0
    for r in ok:
        src_bytes += r["size"]
        for k, v in r["tags"].items():
            tags[k] = tags.get(k, 0) + v
        for k, v in r["policies"].items():
            pol[k] = pol.get(k, 0) + v
        for k, v in r["rule_hits"].items():
            rules[k] = rules.get(k, 0) + v
        for k, v in r["window_hits"].items():
            win[k] = win.get(k, 0) + v
        for k, v in r["cert"]["tag_source_counts"].items():
            if v:
                tsrc[k] = tsrc.get(k, 0) + v
    rt_fail = [r["rel"] for r in ok if not r["selfcheck"]["identical"]]
    stats = {"tags": tags, "source_bytes": src_bytes, "record_types_unknown": []}
    sanity = sanity_gate(stats)
    forms = _tally_key(ok, "form")
    ciphers = _tally_key(ok, "cipher")
    return {
        "container_forms": forms, "cipher_layers": ciphers,
        "tool": D.TOOL_VERSION, "dialect": D.ENGINE_ID, "ir": D.IR_VERSION,
        "job_sha256": job_sha, "input_root": str(base), "output_dir": str(outdir),
        "files_total": len(ok) + len(failures), "files_ok": len(ok),
        "files_failed": len(failures), "failures": failures[:50],
        "source_bytes": src_bytes,
        "records": sum(r["pcert_summary"]["record_count"] for r in ok),
        "blocks": sum(r["pcert_summary"]["block_count"] for r in ok),
        "text_entries": sum(r["entries"] for r in ok),
        "min_byte_coverage": min((c["byte_coverage"] for c in certs), default=0.0),
        "min_tier": D.TIERS["min_tier"],
        "declared_capabilities": list(D.TIERS["declared_capabilities"]),
        "instruction_coverage": D.TIERS["instruction_coverage"],
        "roundtrip_identity": not rt_fail and bool(ok),
        "roundtrip_failures": rt_fail[:50],
        "tags": tags, "translate_policies": pol, "tag_source_counts": tsrc,
        "heuristic_entries": tsrc.get("heuristic", 0),
        "unresolved_entries": tsrc.get("unresolved", 0),
        "unresolved_notes": sum(r["unresolved"] for r in ok),
        "name_bindings": sum(r["bindings"] for r in ok),
        "ambiguous_bindings": sum(r["ambiguous_bindings"] for r in ok),
        "rule_hits": rules, "window_hits": win,
        "source_encoding": senc, "target_encoding": tenc,
        "sanity_gate": {"ok": not sanity, "failures": sanity},
        "ok": bool(ok) and not failures and not rt_fail and not sanity,
    }


def _tally_key(rows: Sequence[dict], key: str) -> dict:
    out: dict = {}
    for r in rows:
        v = r.get(key, "?")
        out[v] = out.get(v, 0) + 1
    return out


def _atomic_write_text(path: Path, text: str, encoding: str) -> None:
    """写临时文件 → flush+fsync → 原子改名（铁律 1、§6.5）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding=encoding, newline="\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------- CLI


def _cli(argv: Sequence[str] | None = None) -> int:
    _utf8_console()
    ap = argparse.ArgumentParser(
        description="CatScene .cst 全量反汇编（无损、可逐字节回封）")
    ap.add_argument("inputs", nargs="*", help=".cst 文件或包含它们的目录")
    ap.add_argument("-o", "--output", default=None, help="输出目录，缺省为输入共同父目录下 output/")
    ap.add_argument("--source-encoding", default=D.ENCODING["source"])
    ap.add_argument("--target-encoding", default=D.ENCODING["target"])
    ap.add_argument("--no-asm", action="store_true", help="跳过 asm 视图（核心门禁照旧执行）")
    ap.add_argument("--jobs", type=int, default=None, help="并行进程数，1 为单进程")
    ap.add_argument("--key", default=None,
                    help="密钥文件（如 key.dat），仅在文件被加密、zlib 解不开时使用")
    args = ap.parse_args(argv)
    if not args.inputs:
        ap.print_help()
        return 2
    key = None
    if args.key:
        kp = Path(args.key)
        if not kp.is_file():
            print(f"错误：密钥文件不存在 {kp}", file=sys.stderr)
            return 1
        key = kp.read_bytes()
        print(f"密钥      {kp.name}（{len(key)} 字节）")
    try:
        inputs = collect_inputs(Path(p) for p in args.inputs)
    except CstError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    base = common_parent(inputs)
    outdir = Path(args.output) if args.output else base / "output"
    print(f"输入 {len(inputs)} 个文件，共同父目录 {base}")
    print(f"输出 {outdir}")

    def prog(i, n, name):
        if i == n or i % 20 == 0:
            print(f"  [{i}/{n}] {name}")

    rep = run_disasm(inputs, outdir, args.source_encoding, args.target_encoding,
                     want_asm=not args.no_asm, jobs=args.jobs, progress=prog,
                     key=key)
    print()
    print(f"文件      {rep['files_ok']}/{rep['files_total']} 解析成功")
    print(f"输入形态  {rep['container_forms']}  解封装 {rep['cipher_layers']}")
    print(f"记录      {rep['records']}  块 {rep['blocks']}")
    print(f"字节覆盖  最低 {rep['min_byte_coverage']:.4%}")
    print(f"往返      {'逐字节一致' if rep['roundtrip_identity'] else '不一致'}")
    print(f"文本      {rep['text_entries']} 条 {rep['tags']}")
    print(f"理解深度  {rep['min_tier']}（{rep['instruction_coverage']} 指令覆盖）")
    print(f"产出门禁  {'通过' if rep['sanity_gate']['ok'] else '失败'}")
    for m in rep["sanity_gate"]["failures"]:
        print(f"    ! {m}")
    for m in rep["failures"]:
        print(f"    ! {m['rel']}: {m['error']}")
    for m in rep["roundtrip_failures"]:
        print(f"    ! 往返不一致: {m}")
    print(f"报告      {outdir / 'reports' / 'disasm.json'}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(_cli())
