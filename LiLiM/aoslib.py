# -*- coding: utf-8 -*-
"""结构逻辑：容器解析、Huffman 编解码、行形态派发、内存 IR。

本模块不含引擎特定字面量——全部数值、命令名、正则来自 opcodelist（§7 硬规则，
可用 check_no_literals.py 机械检查）。
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import opcodelist as D


class ParseError(Exception):
    pass


class UnknownLineShape(ParseError):
    """无形态命中。§7.1.3：必须失败，不得返回空结果。"""

    def __init__(self, src: str, lineno: int, signature: str):
        super().__init__(f"{src}:{lineno} 无形态命中，signature={signature!r}")
        self.src, self.lineno, self.signature = src, lineno, signature


class AddressSpaceGapError(ParseError):
    pass


class AddressSpaceCollisionError(ParseError):
    pass


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# Huffman（TRANSFORMS["huffman_lilim"]）
# --------------------------------------------------------------------------
_HUF = next(t for t in D.TRANSFORMS if t["id"] == "huffman_lilim")
_HP = _HUF["params"]
_TREE = _HP["tree"]


class _BitReader:
    __slots__ = ("b", "p", "acc", "n")

    def __init__(self, b: bytes):
        self.b, self.p, self.acc, self.n = b, 0, 0, 0

    def bit(self) -> int:
        if self.n == 0:
            if self.p >= len(self.b):
                raise ParseError("位流提前耗尽")
            self.acc = self.b[self.p]
            self.p += 1
            self.n = 8
        v = (self.acc >> 7) & 1
        self.acc = (self.acc << 1) & 0xFF
        self.n -= 1
        return v

    def bits(self, count: int) -> int:
        v = 0
        for _ in range(count):
            v = (v << 1) | self.bit()
        return v


class _BitWriter:
    __slots__ = ("out", "acc", "n")

    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def bit(self, v: int) -> None:
        self.acc = (self.acc << 1) | (v & 1)
        self.n += 1
        if self.n == 8:
            self.out.append(self.acc)
            self.acc, self.n = 0, 0

    def bits(self, value: int, count: int) -> None:
        for i in range(count - 1, -1, -1):
            self.bit((value >> i) & 1)

    def finish(self) -> bytes:
        if self.n:
            self.out.append((self.acc << (8 - self.n)) & 0xFF)
            self.acc, self.n = 0, 0
        return bytes(self.out)


def huffman_decode(payload: bytes, unpacked_size: int) -> bytes:
    """解压。位序与树编码见 opcodelist.TRANSFORMS。"""
    br = _BitReader(payload)
    limit = _TREE["max_symbols"]
    first = _TREE["first_internal_symbol"]
    lhs = [0] * limit
    rhs = [0] * limit
    next_sym = [first]
    internal = _TREE["internal_marker"]
    vbits = _TREE["leaf_value_bits"]

    def build() -> int:
        # 迭代式前序重建，避免深树触发递归上限。
        root_slot: list[int] = []
        stack: list[tuple[int, int]] = []  # (parent, which_child) which: 0=left 1=right
        while True:
            if br.bit() == internal:
                node = next_sym[0]
                next_sym[0] += 1
                if node >= limit:
                    raise ParseError("Huffman 节点数超出方言声明上限")
            else:
                node = br.bits(vbits)
            if stack:
                parent, which = stack.pop()
                if which == 0:
                    lhs[parent] = node
                    stack.append((parent, 1))
                else:
                    rhs[parent] = node
            else:
                root_slot.append(node)
            if node >= first:
                stack.append((node, 0))
            elif not stack:
                break
        return root_slot[0]

    root = build()
    out = bytearray()
    if root < first:
        # 单叶树：整个流为同一字节的重复，无判定位。
        return bytes([root]) * unpacked_size
    while len(out) < unpacked_size:
        sym = root
        while sym >= first:
            sym = rhs[sym] if br.bit() else lhs[sym]
        out.append(sym)
    return bytes(out)


def _canonical_tree(data: bytes) -> tuple[dict[int, str], list[tuple[int, Any]]]:
    """按频次构造 Huffman 树，返回码表与前序编码序列。

    构造规则固定（频次升序、同频按字节值升序、合并结果插回队尾保持稳定），因此
    同一输入必得同一棵树——渲染确定性的前提（§2.6）。
    """
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    if not freq:
        raise ParseError("空数据无法构造 Huffman 树")

    first = _TREE["first_internal_symbol"]
    nodes: dict[int, Any] = {}
    seq = sorted(freq.items(), key=lambda kv: (kv[1], kv[0]))
    heap: list[tuple[int, int, Any]] = [(f, b, b) for b, f in seq]
    counter = 0
    while len(heap) > 1:
        heap.sort(key=lambda t: (t[0], t[1]))
        (f1, o1, n1), (f2, o2, n2) = heap[0], heap[1]
        del heap[:2]
        counter += 1
        node = ("I", n1, n2)
        heap.append((f1 + f2, first + counter, node))
    root = heap[0][2]

    codes: dict[int, str] = {}
    preorder: list[tuple[int, Any]] = []

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, tuple):
            preorder.append((_TREE["internal_marker"], None))
            walk(node[1], prefix + "0")
            walk(node[2], prefix + "1")
        else:
            preorder.append((_TREE["leaf_marker"], node))
            codes[node] = prefix or "0"

    import sys
    old = sys.getrecursionlimit()
    # 树深上界为符号数，取声明上限的若干倍留余量；纯语言运行时参数，非方言值。
    sys.setrecursionlimit(max(old, _TREE["max_symbols"] * 8))  # dialect-literal-ok
    try:
        walk(root, "")
    finally:
        sys.setrecursionlimit(old)
    return codes, preorder


def huffman_encode(data: bytes) -> bytes:
    """压缩为该方言的位流（不含前置长度字段）。"""
    codes, preorder = _canonical_tree(data)
    bw = _BitWriter()
    vbits = _TREE["leaf_value_bits"]
    for marker, value in preorder:
        bw.bit(marker)
        if value is not None:
            bw.bits(value, vbits)
    for byte in data:
        for ch in codes[byte]:
            bw.bit(1 if ch == "1" else 0)
    return bw.finish()


# --------------------------------------------------------------------------
# 容器（AOSv2）
# --------------------------------------------------------------------------
_V2 = D.CONTAINER["v2"]
_FMT_U32 = "<I" if D.CONTAINER["endianness"] == "little" else ">I"
_FMT_I32 = "<i" if D.CONTAINER["endianness"] == "little" else ">i"


@dataclass
class ArcEntry:
    index: int
    name: str
    name_raw: bytes
    rel_offset: int
    offset: int
    size: int
    index_offset: int  # 该条目索引项在文件中的起始偏移
    is_packed: bool
    raw_sha256: str
    unpacked_size: int | None = None


@dataclass
class Archive:
    path: Path
    data: bytes
    base_offset: int
    index_size: int
    entries: list[ArcEntry]
    src_sha256: str

    @property
    def index_offset(self) -> int:
        return _V2["index"]["offset"]


def _read_u32(d: bytes, off: int) -> int:
    return struct.unpack_from(_FMT_U32, d, off)[0]


def parse_archive(path: Path) -> Archive:
    data = Path(path).read_bytes()
    sig = _V2["signature"]
    if struct.unpack_from(_FMT_I32, data, sig["offset"])[0] != sig["equals"]:
        raise ParseError(f"{path.name} 不是 AOSv2（签名字段不为声明值）")

    hdr = {f["name"]: f for f in _V2["header"]["fields"]}
    base = _read_u32(data, hdr["base_offset"]["offset"])
    index_size = struct.unpack_from(_FMT_I32, data, hdr["index_size"]["offset"])[0]
    idx_off = _V2["index"]["offset"]
    stride = _V2["index"]["stride"]

    if index_size <= 0 or idx_off + index_size > len(data):
        raise ParseError("索引大小越界")
    if base < idx_off + index_size or base > len(data):
        raise ParseError("base_offset 与索引区冲突")
    if index_size % stride:
        raise ParseError("索引大小不是条目步长的整数倍")

    ef = _V2["entry"]
    nf, of, sf = ef["name"], ef["offset"], ef["size"]
    term = bytes.fromhex(nf["terminator"])
    packed_ext = _HUF["applies_to_extension"]

    entries: list[ArcEntry] = []
    for i in range(index_size // stride):
        io = idx_off + i * stride
        raw = data[io + nf["offset"]: io + nf["offset"] + nf["width"]]
        z = raw.find(term)
        name_raw = raw if z < 0 else raw[:z]
        if not name_raw:
            raise ParseError(f"索引项 {i} 名字为空")
        name = name_raw.decode(D.SCRIPT["source_encoding"])
        rel = _read_u32(data, io + of["offset"])
        size = _read_u32(data, io + sf["offset"])
        start = base + rel
        if start + size > len(data):
            raise ParseError(f"条目 {name} 越界")
        entries.append(ArcEntry(
            index=i, name=name, name_raw=name_raw, rel_offset=rel,
            offset=start, size=size, index_offset=io,
            is_packed=name.lower().endswith(packed_ext),
            raw_sha256=sha256(data[start:start + size]),
        ))
    return Archive(path=Path(path), data=data, base_offset=base,
                   index_size=index_size, entries=entries, src_sha256=sha256(data))


def entry_bytes(arc: Archive, e: ArcEntry) -> bytes:
    """返回条目的解封装内容；.scr 走 Huffman 逆变换。"""
    stored = arc.data[e.offset:e.offset + e.size]
    if not e.is_packed:
        return stored
    po = _HP["payload_offset"]
    usz = _read_u32(stored, _HP["unpacked_size"]["offset"])
    e.unpacked_size = usz
    out = huffman_decode(stored[po:], usz)
    if len(out) != usz:
        raise ParseError(f"{e.name} 解压长度不符：{len(out)} != {usz}")
    return out


def pack_entry(e: ArcEntry, content: bytes) -> bytes:
    """把内容重新封装成存档中的字节形态。"""
    if not e.is_packed:
        return content
    body = huffman_encode(content)
    return struct.pack(_FMT_U32, len(content)) + body


# --------------------------------------------------------------------------
# 行形态派发（§7.1.3）
# --------------------------------------------------------------------------
_SHAPES = [(s["id"], re.compile(s["match"]), s) for s in D.LINE_SHAPES]
_ARG_RULES = {(r["cmd"], r["ordinal"]): r for r in D.CALLEE_STRING_ARGS}
_STR_LIT = re.compile(r'"([^"]*)"')


_SIG_BUCKET = 20   # dialect-literal-ok: 报告用长度分桶粒度，不参与解析判定
_SIG_CAP = 80      # dialect-literal-ok: 同上，仅影响签名字符串的可读性


def line_signature(line: str) -> str:
    """形态签名：首字符类别 + 长度桶。用于报告未命中形态（§7.1.3）。"""
    if not line:
        return "empty"
    c = line[0]
    kind = ("ascii-alpha" if c.isascii() and c.isalpha()
            else "ascii-punct" if c.isascii() and not c.isspace()
            else "ascii-space" if c.isascii()
            else "wide")
    return f"{kind}/len{min(len(line), _SIG_CAP) // _SIG_BUCKET * _SIG_BUCKET}"


@dataclass
class TextSlot:
    """一处可翻译文本，即改写站点（§3：JoinSite 同时是发现依据与改写单位）。"""
    idx: int
    lineno: int
    shape_id: str
    slot_name: str
    tag: str
    tag_subtype: str
    tag_source: str
    translate_policy: str
    source: str
    col_start: int  # 在该行中的字符起止，改写按此定位，不按值
    col_end: int
    speaker: str | None = None
    pair_idx: int | None = None


@dataclass
class ScriptIR:
    src_id: str
    name: str
    src_sha256: str          # 解封装后内容的哈希
    stored_sha256: str       # 存档中原始存储字节的哈希
    lines: list[str]
    shapes: list[str]
    slots: list[TextSlot]
    trailing_terminator: bool
    unmatched_signatures: dict[str, int] = field(default_factory=dict)


def _policy_for(tag: str, tag_source: str) -> str:
    if tag_source == "unresolved":
        return "review-required"
    return D.POLICY_MAP[tag]


def parse_script(src_id: str, name: str, content: bytes,
                 stored_sha: str) -> ScriptIR:
    """把 .scr 内容解析成内存 IR。文本发现只走行形态声明，不做正则扫描全文。"""
    enc = D.SCRIPT["source_encoding"]
    term = D.SCRIPT["line_terminator"]
    text = content.decode(enc)  # 不设 errors 兜底（§4.4）
    parts = text.split(term)
    trailing = parts[-1] == ""
    lines = parts[:-1] if trailing else parts

    shapes: list[str] = []
    slots: list[TextSlot] = []
    counter = 0

    for lineno, line in enumerate(lines):
        for shape_id, rx, decl in _SHAPES:
            m = rx.match(line)
            if not m:
                continue
            shapes.append(shape_id)
            group_slots: dict[str, TextSlot] = {}
            for slot_name, tag in decl["text_slots"].items():
                value = m.group(slot_name)
                if value is None or not value:
                    continue
                counter += 1
                subtype = {
                    ("dialogue", "msg"): "dialogue-body",
                    ("dialogue", "speaker"): "speaker-name",
                    ("narration", "msg"): "narration-body",
                    ("choice", "choice"): "choice-option",
                }[(shape_id, slot_name)]
                ts = TextSlot(
                    idx=counter, lineno=lineno, shape_id=shape_id,
                    slot_name=slot_name, tag=tag, tag_subtype=subtype,
                    tag_source="structural", translate_policy=_policy_for(tag, "structural"),
                    source=value, col_start=m.start(slot_name), col_end=m.end(slot_name),
                )
                group_slots[slot_name] = ts
                slots.append(ts)
            # 人名绑定：同一行的两个槽位，method=slot-ordinal（§4.7）
            binding = decl.get("binding")
            if binding and binding["name_slot"] in group_slots and binding["msg_slot"] in group_slots:
                nm = group_slots[binding["name_slot"]]
                ms = group_slots[binding["msg_slot"]]
                ms.speaker = nm.source
                ms.pair_idx = nm.idx
                nm.pair_idx = ms.idx
            # call 形态的字符串参数
            if decl.get("arg_text_rule"):
                cmd = m.group("cmd")
                args = m.group("args")
                base = m.start("args")
                for ordinal, lit in enumerate(_STR_LIT.finditer(args)):
                    if not lit.group(1):
                        continue
                    rule = _ARG_RULES.get((cmd, ordinal))
                    counter += 1
                    if rule:
                        tag, subtype, policy = rule["tag"], rule["tag_subtype"], None
                    else:
                        tag, subtype, policy = "misc", D.FROZEN_STRING_ARG_SUBTYPE, "frozen"
                    slots.append(TextSlot(
                        idx=counter, lineno=lineno, shape_id=shape_id,
                        slot_name=f"arg{ordinal}", tag=tag, tag_subtype=subtype,
                        tag_source="structural",
                        translate_policy=policy or _policy_for(tag, "structural"),
                        source=lit.group(1),
                        col_start=base + lit.start(1), col_end=base + lit.end(1),
                    ))
            break
        else:
            raise UnknownLineShape(name, lineno, line_signature(line))

    return ScriptIR(src_id=src_id, name=name, src_sha256=sha256(content),
                    stored_sha256=stored_sha, lines=lines, shapes=shapes,
                    slots=slots, trailing_terminator=trailing)


def render_script(ir: ScriptIR, overrides: dict[int, str] | None = None) -> bytes:
    """从 IR 重建 .scr 内容。overrides 为 idx -> 新文本；空则逐字节还原。

    改写按 (lineno, col_start, col_end) 定位，同一行多槽位从右向左套用，
    使前面的列偏移不受影响（§6.3 按站点不按值）。
    """
    ov = overrides or {}
    by_line: dict[int, list[TextSlot]] = {}
    for s in ir.slots:
        if s.idx in ov and ov[s.idx] != s.source:
            by_line.setdefault(s.lineno, []).append(s)

    out_lines = list(ir.lines)
    for lineno, group in by_line.items():
        line = out_lines[lineno]
        for s in sorted(group, key=lambda x: x.col_start, reverse=True):
            if line[s.col_start:s.col_end] != s.source:
                raise ParseError(
                    f"{ir.name}:{lineno} idx={s.idx} 站点内容与 IR 不符，拒绝改写")
            line = line[:s.col_start] + ov[s.idx] + line[s.col_end:]
        out_lines[lineno] = line

    term = D.SCRIPT["line_terminator"]
    text = term.join(out_lines) + (term if ir.trailing_terminator else "")
    return text.encode(D.SCRIPT["target_encoding"])


def iter_scripts(arc: Archive) -> Iterator[tuple[ArcEntry, bytes]]:
    for e in arc.entries:
        yield e, entry_bytes(arc, e)
