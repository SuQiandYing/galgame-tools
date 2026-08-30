"""结构逻辑：容器解析、密钥求解、语句切分、引用连接、文本发现、重建。

本模块不含任何引擎特定字面量 —— 密钥、偏移、记录宽度、语句形态、文本规则全部
从 opcodelist.DIALECT 读取（由 scripts/check_no_literals.py 机械校验）。

术语对照（SKILL.md §2.1）：
    Region      idx 表 / idx 尾部 / 各条目的标签表、填充、正文、种子
    CellStream  idx 记录流（T1：定长记录切分）
    AnchorHit   一条语句（T2：形态已识别、参数槽已定位）
    JoinSite    idx 记录中的 offset 字段（键 = 条目在 pak 中的起始偏移）
    TextEntry   一条可编辑文本（正文消息 / 说话者名 / 章节标题 / 选项 …）
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import opcodelist as _dialect_module

DIALECT: dict[str, Any] = _dialect_module.DIALECT
TOOL_VERSION = "eagls-ulru/1.0.0"
IR_VERSION = "1.0.0"


class ParseError(Exception):
    """解析失败。铁律 4：不静默兜底，失败即抛出并带定位信息。"""

    def __init__(self, code: str, detail: str, **ctx: Any) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.ctx = ctx


class UnknownStatementShape(ParseError):
    """无形态命中。§7.5.3：必须失败，不得返回空结果。"""


# ---------------------------------------------------------------------------
# PRNG（方言参数驱动）
# ---------------------------------------------------------------------------
class DialectRand:
    __slots__ = ("_seed", "_mul", "_inc", "_mask", "_shift")

    def __init__(self, spec: dict[str, Any], seed: int = 0) -> None:
        self._mul = spec["multiplier"]
        self._inc = spec["increment"]
        self._mask = spec["mask"]
        self._shift = spec["shift"]
        self._seed = seed

    @property
    def seed(self) -> int:
        return self._seed

    @seed.setter
    def seed(self, value: int) -> None:
        self._seed = value

    def rand(self) -> int:
        self._seed = (self._mul * self._seed + self._inc) & self._mask
        return self._seed >> self._shift


def _to_signed_byte(value: int) -> int:
    return struct.unpack("<b", struct.pack("<B", value))[0]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def window(name: str) -> dict[str, Any]:
    for spec in DIALECT["windows"]:
        if spec["name"] == name:
            return spec
    raise ParseError("WINDOW_UNDECLARED", f"窗口常量 {name} 未在方言中声明（§1.6）")


_WINDOW_HITS: dict[str, int] = {}


def _note_window(name: str) -> None:
    _WINDOW_HITS[name] = _WINDOW_HITS.get(name, 0) + 1


def window_hits() -> dict[str, int]:
    return dict(_WINDOW_HITS)


# ---------------------------------------------------------------------------
# 归档层：idx 加解密
# ---------------------------------------------------------------------------
def _idx_seed(data: bytes, cipher: dict[str, Any]) -> int:
    width = cipher["seed_field_width"]
    if len(data) < width:
        raise ParseError("IDX_TOO_SHORT", f"idx 仅 {len(data)} 字节，不足以容纳种子")
    return struct.unpack_from("<I", data, len(data) - width)[0]


def xor_idx(data: bytearray, key: bytes) -> bytearray:
    """对合变换：加密与解密是同一个函数。种子区（末 4 字节）不参与。"""
    cipher = DIALECT["archive"]["idx_cipher"]
    rnd = DialectRand(DIALECT["prng"], _idx_seed(data, cipher))
    klen = len(key)
    for i in range(len(data) - cipher["seed_field_width"]):
        data[i] ^= key[rnd.rand() % klen]
    return data


def solve_idx_key(data: bytes) -> tuple[str, str]:
    """求 idx 密钥。返回 (key, 证据来源)。

    先试方言声明的候选密钥并做结构校验；不成立时才从尾部零填充区反解。
    候选优先不是抄近路：命中即为 observed 级证据，且省掉 1024 次全扫描。
    """
    cipher = DIALECT["archive"]["idx_cipher"]
    for candidate in cipher["key_candidates"]:
        probe = xor_idx(bytearray(data), candidate.encode())
        if _idx_table_wellformed(bytes(probe)):
            return candidate, "declared-candidate"

    span = window("idx_key_probe_span")
    max_len = window("idx_key_max_len")
    seed = _idx_seed(data, cipher)
    start = len(data) - cipher["seed_field_width"] - span["value"]
    if start < 0:
        _note_window(span["name"])
        raise ParseError("IDX_PROBE_SPAN",
                         f"idx 长度 {len(data)} 小于探测窗口 {span['value']}"
                         f"（on_exceed={span['on_exceed']}）")
    for klen in range(1, max_len["value"] + 1):
        rnd = DialectRand(DIALECT["prng"], seed)
        for _ in range(start):
            rnd.rand()
        known = bytearray(klen)
        key = bytearray(klen)
        ok = True
        for i in range(start, len(data) - cipher["seed_field_width"]):
            slot = rnd.rand() % klen
            byte = data[i]
            if not known[slot]:
                known[slot], key[slot] = 1, byte
            elif key[slot] != byte:
                ok = False
                break
        if ok and all(known):
            return key.decode("latin1"), "derived-from-zero-tail"
    _note_window(max_len["name"])
    raise ParseError("IDX_KEY_UNRESOLVED",
                     f"在 1..{max_len['value']} 内未求出 idx 密钥"
                     f"（on_exceed={max_len['on_exceed']}）")


def _idx_table_wellformed(plain: bytes) -> bool:
    """结构校验：记录能走到终止符，偏移单调紧密，长度总和等于 pak 尺寸的前提。"""
    try:
        records, table_end = read_idx_records(plain)
    except ParseError:
        return False
    if not records:
        return False
    if any(b for b in plain[table_end:len(plain) - 4]):
        return False
    cursor = records[0].offset
    for rec in records:
        if rec.offset != cursor or rec.length <= 0:
            return False
        cursor += rec.length
    return True


# ---------------------------------------------------------------------------
# 归档层：记录流（T1 cell-stream）
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class IdxRecord:
    ordinal: int
    name: str
    name_bytes: bytes
    offset: int
    length: int
    record_start: int      # 记录在 idx 明文中的起始偏移
    offset_site: int       # offset 字段的偏移 —— 这就是 JoinSite（§3）
    length_site: int


def record_layout(idx_size: int) -> dict[str, Any]:
    spec = DIALECT["archive"]
    probe = spec["long_offset_probe"]
    variant = "long" if idx_size / probe["divisor"] >= probe["threshold"] else "short"
    return dict(spec["record"][variant], variant=variant)


def read_idx_records(plain: bytes) -> tuple[list[IdxRecord], int]:
    """切分 idx 明文为定长记录，返回 (记录列表, 表结束偏移)。

    §1.2：不整除即解析失败，不得截断或补齐。终止符为首字节为 0 的名字字段。
    """
    layout = record_layout(len(plain))
    name_size = layout["name_size"]
    width = layout["field_width"]
    stride = name_size + 2 * width
    fmt = struct.Struct("<q" if width == 8 else "<I")

    records: list[IdxRecord] = []
    pos = 0
    while pos + stride <= len(plain):
        name_bytes = plain[pos:pos + name_size]
        if not name_bytes[0]:
            return records, pos
        raw_name, _, pad = name_bytes.partition(b"\x00")
        if pad.count(0) != len(pad):
            raise ParseError("IDX_NAME_PAD",
                             f"记录 {len(records)} 名字填充区非零", offset=pos)
        offset_site = pos + name_size
        length_site = offset_site + width
        records.append(IdxRecord(
            ordinal=len(records),
            name=raw_name.decode("latin1"),
            name_bytes=name_bytes,
            offset=fmt.unpack_from(plain, offset_site)[0],
            length=fmt.unpack_from(plain, length_site)[0],
            record_start=pos,
            offset_site=offset_site,
            length_site=length_site,
        ))
        pos += stride
    raise ParseError("IDX_UNTERMINATED", "记录表未遇终止符即到达文件末尾")


# ---------------------------------------------------------------------------
# 条目层：标签表 + 正文起点推导
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class LabelRecord:
    ordinal: int
    name: bytes
    offset: int            # 相对正文起点的字节偏移
    record_start: int      # 记录在条目内的偏移
    offset_site: int       # offset 字段偏移 —— 条目内的 JoinSite


def read_label_table(entry: bytes, alis: bool = False) -> tuple[list[LabelRecord], int]:
    """读标签表，返回 (记录列表, 表结束偏移含终止记录)。"""
    spec = DIALECT["entry"]["label_record"]
    size = spec["alis_size"] if alis else spec["size"]
    width = spec["offset_field_width"]
    name_size = size - width
    fmt = struct.Struct("<I")

    labels: list[LabelRecord] = []
    pos = 0
    while pos + size <= len(entry):
        name_bytes = entry[pos:pos + name_size]
        if not name_bytes[0]:
            return labels, pos + size
        offset_site = pos + name_size
        labels.append(LabelRecord(
            ordinal=len(labels),
            name=name_bytes.split(b"\x00", 1)[0],
            offset=fmt.unpack_from(entry, offset_site)[0],
            record_start=pos,
            offset_site=offset_site,
        ))
        pos += size
    raise ParseError("LABEL_UNTERMINATED", "标签表未遇终止记录")


def derive_text_offset(entry: bytes, table_end: int, alis: bool = False) -> int:
    """由结构推导正文起点：表尾之后首个非零字节，向上取整到 granularity。

    §7.5.2：不按文件名或固定常量选择。声明中的 expected 只作交叉校验。
    """
    spec = DIALECT["entry"]["text_offset"]
    if alis:
        return spec["alis_fixed"]
    limit = window("text_offset_scan_limit")
    granularity = spec["granularity"]
    end = min(len(entry), limit["value"])
    probe = table_end - DIALECT["entry"]["label_record"]["size"]
    for pos in range(max(0, probe), end):
        if entry[pos]:
            return -(-pos // granularity) * granularity
    _note_window(limit["name"])
    raise ParseError("TEXT_OFFSET_UNRESOLVED",
                     f"表尾之后 {limit['value']} 字节内无非零字节"
                     f"（on_exceed={limit['on_exceed']}）")


# ---------------------------------------------------------------------------
# 条目层：正文加解密（对合，v1/v2 由方言声明）
# ---------------------------------------------------------------------------
def xor_entry(entry: bytearray, text_offset: int, key: bytes, version: int) -> bytearray:
    spec = DIALECT["entry"]["pak_cipher"]["versions"].get(version)
    if spec is None:
        raise ParseError("CIPHER_VERSION", f"未声明的正文加密版本 {version}")
    stride = spec["stride"]
    reserved = spec["tail_reserved"]
    klen = len(key)
    stop = len(entry) - reserved
    if spec["index_source"] == "prng":
        seed_pos = len(entry) - 1
        rnd = DialectRand(DIALECT["prng"], _to_signed_byte(entry[seed_pos]))
        for i in range(text_offset, stop, stride):
            entry[i] ^= key[rnd.rand() % klen]
    else:
        for i in range(text_offset, stop, stride):
            entry[i] ^= key[(i - text_offset) % klen]
    return entry


def solve_pak_key(entries: dict[str, bytearray],
                  labels: dict[str, list[LabelRecord]],
                  text_offset: int) -> tuple[str, int, str]:
    """求正文密钥与加密版本。

    已知明文来自标签表：正文中每个标签处必然是 `$` + 标签名（605 处实测成立）。
    先试方言候选（对每个版本验证全部已知明文），失败才逐长度反解。
    """
    spec = DIALECT["entry"]["pak_cipher"]
    versions = sorted(spec["versions"])
    for candidate in spec["key_candidates"]:
        for version in versions:
            if _pak_key_holds(candidate.encode(), version, entries, labels, text_offset):
                return candidate, version, "declared-candidate"
    max_len = window("pak_key_max_len")
    for version in versions:
        key = _solve_pak_key_length(version, entries, labels, text_offset, max_len["value"])
        if key is not None:
            return key.decode("latin1"), version, "derived-from-label-plaintext"
    _note_window(max_len["name"])
    raise ParseError("PAK_KEY_UNRESOLVED",
                     f"在 1..{max_len['value']} 内未求出正文密钥"
                     f"（on_exceed={max_len['on_exceed']}）")


def _pak_key_holds(key: bytes, version: int, entries: dict[str, bytearray],
                   labels: dict[str, list[LabelRecord]], text_offset: int) -> bool:
    for name, data in entries.items():
        plain = xor_entry(bytearray(data), text_offset, key, version)
        body = plain[text_offset:len(plain) - 1]
        for label in labels.get(name, ()):
            if not body.startswith(b"$" + label.name, label.offset):
                return False
    return True


def _solve_pak_key_length(version: int, entries: dict[str, bytearray],
                          labels: dict[str, list[LabelRecord]],
                          text_offset: int, max_len: int) -> bytearray | None:
    """按已知明文反解密钥。每个长度独立尝试，矛盾即否决该长度。"""
    spec = DIALECT["entry"]["pak_cipher"]["versions"][version]
    stride = spec["stride"]
    from_prng = spec["index_source"] == "prng"
    for klen in range(1, max_len + 1):
        key = bytearray(klen)
        known = bytearray(klen)
        rnd = DialectRand(DIALECT["prng"])
        consistent = True
        for name, data in entries.items():
            if not data:
                continue
            if from_prng:
                rnd.seed = _to_signed_byte(data[-1])
                cursor = 0
            for label in labels.get(name, ()):
                plain = b"$" + label.name
                if from_prng:
                    while cursor < label.offset:
                        rnd.rand()
                        cursor += stride
                    skew = label.offset % stride
                    base = label.offset + (stride - skew if skew else 0)
                    lead = stride - skew if skew else 0
                else:
                    base, lead = label.offset, 0
                for step in range(0, len(plain) - lead, stride):
                    target = text_offset + base + step
                    if target >= len(data) - spec["tail_reserved"]:
                        if from_prng:
                            rnd.rand()
                            cursor += stride
                        continue
                    slot = rnd.rand() % klen if from_prng else (base + step) % klen
                    if from_prng:
                        cursor += stride
                    value = plain[lead + step] ^ data[target]
                    if not known[slot]:
                        known[slot], key[slot] = 1, value
                    elif key[slot] != value:
                        consistent = False
                        break
                if not consistent:
                    break
            if not consistent:
                break
        if consistent and all(known):
            return key
    return None


# ---------------------------------------------------------------------------
# 语句切分（T2 anchor-resolved）：形态派发，无形态命中即失败
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Statement:
    shape: str
    kind: str
    start: int             # 相对正文起点的字符偏移
    end: int
    groups: tuple[str | None, ...] = ()


class _CompiledShape:
    """形态的编译产物。判定是纯谓词，与提取分离（§7.5.3）。"""

    __slots__ = ("spec", "id", "kind", "span", "first_chars", "first_digit",
                 "pattern", "run_chars", "until", "until_any", "include_until",
                 "absorb")

    def __init__(self, spec: dict[str, Any], patterns: dict[str, re.Pattern[str]]) -> None:
        self.spec = spec
        self.id = spec["id"]
        self.kind = spec["kind"]
        self.span = spec["span"]
        match = spec["match"]
        self.first_chars = set(match.get("first_char_in", ""))
        self.first_digit = bool(match.get("first_char_digit"))
        pattern_id = match.get("pattern_id")
        self.pattern = patterns[pattern_id] if pattern_id else None
        self.run_chars = set(spec.get("run_chars", ""))
        self.until = spec.get("until_char")
        self.until_any = set(spec.get("until_any", ""))
        self.include_until = bool(spec.get("include_until"))
        self.absorb = spec.get("absorb_trailing")

    def matches(self, text: str, pos: int) -> re.Match[str] | bool:
        char = text[pos]
        if self.first_digit:
            if not char.isdigit() or not char.isascii():
                return False
        elif char not in self.first_chars:
            return False
        if self.pattern is not None:
            return self.pattern.match(text, pos) or False
        return True


class StatementLexer:
    """把正文切成语句。整个作业只编译一次（§12.1）。"""

    def __init__(self, dialect: dict[str, Any] = DIALECT) -> None:
        self._patterns = {k: re.compile(v) for k, v in dialect["patterns"].items()}
        self._shapes = [_CompiledShape(s, self._patterns)
                        for s in dialect["statement_shapes"]]
        self._stmt_start = self._patterns["statement_start"]
        self._rpn = dialect["rpn_scan"]
        self._paren = dialect["paren_scan"]

    @property
    def patterns(self) -> dict[str, re.Pattern[str]]:
        return self._patterns

    def lex(self, text: str) -> list[Statement]:
        out: list[Statement] = []
        pos = 0
        size = len(text)
        while pos < size:
            for shape in self._shapes:
                hit = shape.matches(text, pos)
                if hit is False:
                    continue
                end, groups = self._span(shape, text, pos, hit)
                if end < 0:
                    continue
                out.append(Statement(shape.id, shape.kind, pos, end, groups))
                pos = end
                break
            else:
                raise UnknownStatementShape(
                    "UNKNOWN_STATEMENT_SHAPE",
                    f"字符偏移 {pos} 处无形态命中：{text[pos:pos + 40]!r}",
                    offset=pos, signature=self.signature(text, pos))
        return out

    def signature(self, text: str, pos: int) -> str:
        """形态签名，用于报告未命中的结构（§0.2）。"""
        head = text[pos:pos + 8]
        return "".join("D" if c.isdigit() and c.isascii()
                       else "A" if c.isascii() and c.isalpha()
                       else "W" if c in " \t\r\n"
                       else c if c.isascii() else "N" for c in head)

    # -- span 求解：每种 span 一个分支，不共享可变状态 ----------------------
    def _span(self, shape: _CompiledShape, text: str, pos: int,
              hit: re.Match[str] | bool) -> tuple[int, tuple[str | None, ...]]:
        size = len(text)
        kind = shape.span
        if kind == "single_char":
            return pos + 1, ()
        if kind == "run_of_chars":
            end = pos
            while end < size and text[end] in shape.run_chars:
                end += 1
            return end, ()
        if kind == "until_char":
            found = text.find(shape.until, pos)
            if found < 0:
                return -1, ()
            return (found + 1 if shape.include_until else found), ()
        if kind == "until_any_char":
            end = pos + 1
            while end < size and text[end] not in shape.until_any:
                end += 1
            return end, ()
        if kind == "pattern":
            assert isinstance(hit, re.Match)
            return hit.end(), tuple(hit.groups())
        if kind == "balanced_parens":
            assert isinstance(hit, re.Match)
            end = self._scan_parens(text, hit.end() - 1)
            if end < 0:
                return -1, ()
            if shape.absorb and end < size and text[end] == shape.absorb:
                end += 1
            return end, tuple(hit.groups())
        if kind == "rpn_until_statement_boundary":
            assert isinstance(hit, re.Match)
            end = self._scan_rpn(text, hit.end())
            if end < 0:
                return -1, ()
            return end, tuple(hit.groups())
        raise ParseError("SPAN_KIND", f"未声明的 span 类型 {kind}")

    def _scan_parens(self, text: str, pos: int) -> int:
        spec = self._paren
        depth = 0
        quoted = False
        size = len(text)
        while pos < size:
            char = text[pos]
            if quoted:
                if char == spec["quote_char"]:
                    quoted = False
            elif char == spec["quote_char"]:
                quoted = True
            elif char == spec["open_char"]:
                depth += 1
            elif char == spec["close_char"]:
                depth -= 1
                if depth == 0:
                    return pos + 1
            pos += 1
        return -1

    def _scan_rpn(self, text: str, pos: int) -> int:
        """RPN 参数序列：深度 0 的逗号后若已是下一条语句，则语句在此结束。

        这条判据是必要的：赋值右侧是逗号分隔的逆波兰序列（`_A=1,2,+,`），
        用「逗号即结束」会把一条语句切成碎片，用「行尾即结束」会漏掉跨行的序列。
        """
        spec = self._rpn
        depth = 0
        quoted = False
        size = len(text)
        while pos < size:
            char = text[pos]
            if quoted:
                if char == spec["quote_char"]:
                    quoted = False
                pos += 1
                continue
            if char == spec["quote_char"]:
                quoted = True
            elif char in spec["open_chars"]:
                depth += 1
            elif char in spec["close_chars"]:
                depth -= 1
            elif char in spec["abort_chars"]:
                return -1
            elif char == spec["separator"] and depth == 0:
                probe = pos + 1
                while probe < size and text[probe] in " \t\r\n":
                    probe += 1
                if probe >= size or self._stmt_start.match(text, probe):
                    return pos + 1
            pos += 1
        return -1


# ---------------------------------------------------------------------------
# 占位符（§4.5）：不可安全显示的字节以 {{XX}} 呈现，其余字符原样保留
# ---------------------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}")


def to_placeholders(text: str, encoding: str) -> str:
    """把控制字符转成占位符。斜杠、全角空格等可显示字符不得转义。"""
    out: list[str] = []
    for char in text:
        if char < " " or char == "\x7f":
            out.append("{{%s}}" % ":".join(
                f"{b:02X}" for b in char.encode(encoding, "strict")))
        else:
            out.append(char)
    return "".join(out)


def from_placeholders(text: str, encoding: str) -> bytes:
    """占位符直接解析为原始字节，忽略编码边界（§4.5）。"""
    out = bytearray()
    pos = 0
    for match in _PLACEHOLDER_RE.finditer(text):
        out += text[pos:match.start()].encode(encoding, "strict")
        out += bytes(int(b, 16) for b in match.group(1).split(":"))
        pos = match.end()
    out += text[pos:].encode(encoding, "strict")
    return bytes(out)


def encoded_length(text: str, encoding: str, terminator: int = 0) -> int:
    """§6.0.2 的唯一长度口径：按目标编码算，占位符按展开字节算，含终止符。"""
    return len(from_placeholders(text, encoding)) + terminator


# ---------------------------------------------------------------------------
# 文本发现：只从已切分的语句与已声明的调用组取，绝不扫描原始字节（铁律 2）
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class TextEntry:
    idx: int
    src_id: int
    src_name: str
    stmt_index: int
    shape: str
    tag: str
    tag_subtype: str
    tag_source: str
    translate_policy: str
    confidence: str
    source: str                 # 已占位符化的原文，双行文件与 IR 的唯一真值
    char_start: int             # 可编辑片段在正文中的字符区间
    char_end: int
    raw_len: int                # 原文按 source_encoding 的字节数
    slot_capacity: int | None   # 变长回封时为 None（容量不受限）
    speaker: str | None = None
    voice: str | None = None
    speaker_kind: str | None = None      # literal | virtual（§4.7）
    speaker_ref: str | None = None       # 虚拟名的来源变量
    speaker_entry_idx: int | None = None  # literal 时指向那条 name 条目
    speaker_candidates: list[str] = field(default_factory=list)
    message_id: str | None = None
    opcode: str | None = None
    slot_ordinal: int | None = None
    matched_rule_id: str | None = None
    aliases: list[int] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        data = {
            "idx": self.idx, "src_id": self.src_id, "src": self.src_name,
            "stmt": self.stmt_index, "shape": self.shape, "tag": self.tag,
            "tag_subtype": self.tag_subtype, "tag_source": self.tag_source,
            "translate_policy": self.translate_policy,
            "confidence": self.confidence, "source": self.source,
            "char_start": self.char_start, "char_end": self.char_end,
            "raw_len": self.raw_len, "slot_capacity": self.slot_capacity,
        }
        for key in ("speaker", "voice", "speaker_kind", "speaker_ref",
                    "speaker_entry_idx", "message_id", "opcode", "slot_ordinal",
                    "matched_rule_id"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        if self.speaker_candidates:
            data["speaker_candidates"] = list(self.speaker_candidates)
        return data

    def plain_source(self, encoding: str) -> str:
        """占位符还原为字符，用于与正文原区间逐字符比对。"""
        raw = from_placeholders(self.source, encoding)
        return raw.decode(encoding)


@dataclass(frozen=True, slots=True)
class SpeakerRef:
    """一次 `#…` 命中解析出的说话者。

    literal —— 名字字面写在 `#` 之后，同时作为可编辑的 name 条目存在。
    virtual —— `#:NameSuffix` 之类，名字存在同名变量里；此处只记引用，
               **不**伪造成可编辑条目（§4.7）。它的编辑入口是那条变量赋值。
    """

    kind: str
    display: str
    voice: str | None
    ref: str | None
    entry_idx: int | None
    candidates: tuple[str, ...] = ()


class _RuleEngine:

    def __init__(self, dialect: dict[str, Any] = DIALECT) -> None:
        self._rules = dialect["text_rules"]
        self._ranges = {name: tuple(tuple(r) for r in spans)
                        for name, spans in dialect["script_ranges"].items()}
        self.hits: dict[str, int] = {rule["id"]: 0 for rule in self._rules}
        self.misses = 0

    def _in_script(self, text: str, name: str) -> bool:
        spans = self._ranges[name]
        for char in text:
            code = ord(char)
            for low, high in spans:
                if low <= code <= high:
                    return True
        return False

    def _predicate(self, spec: dict[str, Any], text: str, ctx: dict[str, Any]) -> bool:
        kind = spec["kind"]
        if kind == "contains_script":
            return self._in_script(text, spec["value"])
        if kind == "min_length":
            return len(text) >= spec["value"]
        if kind == "max_length":
            return len(text) <= spec["value"]
        if kind == "any_char_in":
            return any(c in spec["value"] for c in text)
        if kind == "all_chars_in":
            return bool(text) and all(c in spec["value"] for c in text)
        if kind == "starts_with":
            return text.startswith(spec["value"])
        if kind == "ends_with":
            return text.endswith(spec["value"])
        if kind == "has_digit":
            return any(c.isdigit() for c in text)
        if kind == "ascii_ratio_gte":
            if not text:
                return False
            return sum(c.isascii() for c in text) / len(text) >= spec["value"]
        if kind == "requires_name_slot_prefix":
            name = ctx.get("name_slot_value")
            return bool(name) and name.startswith(spec["value"])
        if kind == "requires_callee_group":
            return ctx.get("callee_group") == spec["value"]
        if kind == "requires_anchor_kind":
            return ctx.get("anchor_kind") == spec["value"]
        raise ParseError("PREDICATE_UNKNOWN", f"未实现的谓词 {kind}（§7 谓词为闭集）")

    def classify(self, text: str, ctx: dict[str, Any]) -> dict[str, Any] | None:
        """按声明顺序求值，首个命中即返回。没有兜底规则（§4.3）。"""
        for rule in self._rules:
            required = rule.get("requires_callee_group")
            if required is not None and ctx.get("callee_group") != required:
                continue
            if all(self._predicate(p, text, ctx) for p in rule["predicates"]):
                self.hits[rule["id"]] += 1
                return rule
        self.misses += 1
        return None


_DEFAULT_POLICY = {
    "name": "translatable", "msg": "translatable", "choice": "translatable",
    "ui": "translatable", "system": "translatable", "ruby": "translatable",
    "label": "frozen", "misc": "review-required",
}


def _policy_for(tag: str, tag_source: str, override: str | None) -> str:
    if tag_source == "unresolved":
        return "review-required"
    if override is not None:
        return override
    return _DEFAULT_POLICY[tag]


class TextExtractor:
    """从语句流投影文本条目。发现依据只有两处：语句形态与已声明的调用组。"""

    def __init__(self, lexer: StatementLexer, dialect: dict[str, Any] = DIALECT) -> None:
        self._lexer = lexer
        self._rules = _RuleEngine(dialect)
        self._binding = dialect["name_binding"]
        self._voice_re = lexer.patterns[self._binding["voice_pattern_id"]]
        self._quoted_re = lexer.patterns["quoted_arg"]
        self._groups: dict[str, list[dict[str, Any]]] = {}
        for group in dialect["callee_groups"]:
            for opcode in group["opcodes"]:
                self._groups.setdefault(opcode, []).append(group)
        self._shape_kinds = {s["id"]: s for s in dialect["statement_shapes"]}
        self.shape_signatures: dict[str, int] = {}
        # 跨源收集的变量字面赋值，供虚拟名解析。必须在 extract 之前填好（见 scan_variables）。
        # 值为**去重后的候选列表**：同一变量在不同源里可能被赋不同值，那属于歧义，
        # 不能任选一个（§4.7）。
        self.variable_values: dict[str, list[str]] = {}

    def scan_variables(self, statements: dict[str, list[Statement]],
                       texts: dict[str, str]) -> None:
        """扫全部源，收集虚拟名所引用变量的**字面**赋值。

        必须先扫完再提取：赋值可能在另一个脚本文件里（本作在 IniScriptPri.dat 与
        00Name.dat），按文件顺序边扫边提取会让前面的文件解析不出人名。这与「不得跨
        文件正则扫描原始字节」不冲突 —— 读的是已切分语句里已声明的调用组槽位（§3）。

        只接受带引号的字面量。`52(":NameSuffix",_Name)` 的第二槽是另一个变量的引用
        而非人名，把它当值会让说话者显示成 `_Name`。
        """
        wanted = {spec["variable"]
                  for spec in self._binding["virtual_names"].values()}
        if not wanted:
            return
        found: dict[str, list[str]] = {}
        for name, stmts in statements.items():
            text = texts[name]
            for stmt in stmts:
                if stmt.shape != "call" or not stmt.groups:
                    continue
                for group in self._groups.get(stmt.groups[0], ()):
                    slot = group.get("name_slot")
                    if slot is None or group["slot_form"] != "quoted":
                        continue
                    body = text[stmt.start:stmt.end]
                    args = body[body.index("(") + 1:body.rindex(")")]
                    slots = _split_slots(args, 0)
                    if slot >= len(slots):
                        continue
                    key = _quoted_literal(slots[slot][0])
                    if key is None or key not in wanted:
                        continue
                    for ordinal in group["text_slots"]:
                        if ordinal >= len(slots):
                            continue
                        value = _quoted_literal(slots[ordinal][0])
                        if value:
                            bucket = found.setdefault(key, [])
                            if value not in bucket:
                                bucket.append(value)
        self.variable_values = found

    @property
    def rule_hits(self) -> dict[str, int]:
        return dict(self._rules.hits)

    @property
    def rule_misses(self) -> int:
        return self._rules.misses

    def extract(self, text: str, statements: list[Statement], src_id: int,
                src_name: str, encoding: str, next_idx: int) -> list[TextEntry]:
        entries: list[TextEntry] = []
        pending: SpeakerRef | None = None
        for position, stmt in enumerate(statements):
            self.shape_signatures[stmt.shape] = self.shape_signatures.get(stmt.shape, 0) + 1
            if stmt.shape == "message":
                entry = self._message(text, stmt, position, src_id, src_name,
                                      encoding, next_idx)
                # 绑定在 `#` 与紧随的 message 之间成立（method=slot-ordinal）。
                # 虚拟名同样绑定：它是「说话者已声明但名字存在变量里」，
                # 与「旁白，无说话者」是两种不同状态，合并会让译者无法区分。
                if pending is not None:
                    entry.speaker = pending.display
                    entry.voice = pending.voice
                    entry.speaker_kind = pending.kind
                    entry.speaker_ref = pending.ref
                    entry.speaker_entry_idx = pending.entry_idx
                    entry.speaker_candidates = list(pending.candidates)
                    pending = None
                entries.append(entry)
                next_idx += 1
            elif stmt.shape == "speaker":
                entry, pending = self._speaker(text, stmt, position, src_id,
                                               src_name, encoding, next_idx)
                if entry is not None:
                    entries.append(entry)
                    next_idx += 1
            elif stmt.shape == "label":
                entries.append(self._label(text, stmt, position, src_id, src_name,
                                           encoding, next_idx))
                next_idx += 1
            elif stmt.shape == "call":
                for entry in self._call(text, stmt, position, src_id, src_name,
                                        encoding, next_idx):
                    entries.append(entry)
                    next_idx += 1
            elif stmt.shape not in self._shape_kinds:
                raise UnknownStatementShape(
                    "UNKNOWN_STATEMENT_SHAPE",
                    f"{src_name} 语句 {position} 形态 {stmt.shape} 未声明")
        return entries

    # -- 各形态的提取（判定与提取分离；每个分支自带槽位定位） ---------------
    def _make(self, *, idx: int, src_id: int, src_name: str, position: int,
              shape: str, tag: str, subtype: str, tag_source: str,
              confidence: str, raw: str, start: int, end: int, encoding: str,
              capacity: int | None, policy_override: str | None = None,
              **extra: Any) -> TextEntry:
        return TextEntry(
            idx=idx, src_id=src_id, src_name=src_name, stmt_index=position,
            shape=shape, tag=tag, tag_subtype=subtype, tag_source=tag_source,
            translate_policy=_policy_for(tag, tag_source, policy_override),
            confidence=confidence, source=to_placeholders(raw, encoding),
            char_start=start, char_end=end,
            raw_len=len(raw.encode(encoding, "strict")),
            slot_capacity=capacity, **extra)

    def _message(self, text: str, stmt: Statement, position: int, src_id: int,
                 src_name: str, encoding: str, idx: int) -> TextEntry:
        """`&<id>"<正文>"` —— 锚点直接证明是消息调用的文本参数，tag_source=anchor。"""
        body = text[stmt.start:stmt.end]
        match = self._lexer.patterns["message"].match(body)
        if match is None:
            raise ParseError("MESSAGE_MALFORMED", f"{src_name} 语句 {position} 无法复解")
        start = stmt.start + match.start(2)
        return self._make(
            idx=idx, src_id=src_id, src_name=src_name, position=position,
            shape=stmt.shape, tag="msg", subtype="dialogue", tag_source="anchor",
            confidence="derived", raw=match.group(2), start=start,
            end=start + len(match.group(2)), encoding=encoding, capacity=None,
            message_id=match.group(1))

    def _speaker(self, text: str, stmt: Statement, position: int, src_id: int,
                 src_name: str, encoding: str, idx: int
                 ) -> tuple[TextEntry | None, SpeakerRef | None]:
        """`#<名字>=<语音ID>`、`#<名字>` 或 `#:NameSuffix`。

        返回 (可编辑条目, 说话者引用)。虚拟名照常产出一条 name 条目让译者在 name 栏
        看到说话者，但锁定 frozen —— `#` 之后是变量名而非人名，可编辑的位置在那条
        变量赋值上（§4.7 不得伪造成可编辑条目）。
        """
        body = text[stmt.start + 1:stmt.end]
        virtual = self._binding["virtual_names"].get(body)
        if virtual is not None:
            display, candidates = self._virtual_display(virtual)
            entry: TextEntry | None = None
            if virtual.get("emit_entry"):
                start = stmt.start + 1
                entry = self._make(
                    idx=idx, src_id=src_id, src_name=src_name, position=position,
                    shape=stmt.shape, tag="name",
                    subtype=virtual.get("subtype", "virtual-speaker-ref"),
                    tag_source="structural", confidence="observed", raw=body,
                    start=start, end=start + len(body), encoding=encoding,
                    capacity=len(body.encode(encoding, "strict")),
                    policy_override=virtual.get("translate_policy"),
                    speaker_kind="virtual", speaker_ref=virtual["variable"])
                entry.speaker_candidates = list(candidates)
            return entry, SpeakerRef(
                kind="virtual", display=display, voice=None,
                ref=virtual["variable"], entry_idx=entry.idx if entry else None,
                candidates=candidates)
        if not body:
            return None, None
        match = self._voice_re.match(body)
        name = match.group("name") if match else body
        voice = match.group("voice") if match else None
        if not name:
            return None, None
        start = stmt.start + 1
        entry = self._make(
            idx=idx, src_id=src_id, src_name=src_name, position=position,
            shape=stmt.shape, tag="name", subtype="speaker",
            tag_source="binding", confidence="derived", raw=name, start=start,
            end=start + len(name), encoding=encoding, capacity=None, voice=voice,
            speaker_kind="literal")
        return entry, SpeakerRef(kind="literal", display=entry.source,
                                 voice=voice, ref=None, entry_idx=idx,
                                 candidates=())

    def _virtual_display(self, spec: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
        """虚拟名的显示值：用同名变量的实测字面赋值，多个候选时不任选。

        赋值可能出现在别的源里，故查的是 scan_variables 收集的跨源表。查不到就用
        声明的兜底标签；有多个互不相同的候选则全部列出并标 AMBIGUOUS（§4.7），
        不猜一个具体人名。
        """
        candidates = tuple(self.variable_values.get(spec["variable"], ()))
        variable = spec["variable"]
        if len(candidates) == 1:
            return f"{candidates[0]}（{variable}）", candidates
        if len(candidates) > 1:
            return f"AMBIGUOUS（{variable}：{'/'.join(candidates)}）", candidates
        return f"{spec['fallback_label']}（{variable}）", candidates

    def _label(self, text: str, stmt: Statement, position: int, src_id: int,
               src_name: str, encoding: str, idx: int) -> TextEntry:
        """`$<标签名>\\n` —— 标签表的 offset 字段指向它，是引用目标，必须 frozen。"""
        body = text[stmt.start + 1:stmt.end].rstrip("\r\n")
        start = stmt.start + 1
        return self._make(
            idx=idx, src_id=src_id, src_name=src_name, position=position,
            shape=stmt.shape, tag="label", subtype="internal-anchor",
            tag_source="structural", confidence="observed", raw=body,
            start=start, end=start + len(body), encoding=encoding,
            capacity=len(body.encode(encoding, "strict")))

    def _call(self, text: str, stmt: Statement, position: int, src_id: int,
              src_name: str, encoding: str, idx: int) -> Iterator[TextEntry]:
        groups = self._groups.get(stmt.groups[0] if stmt.groups else None)
        if not groups:
            return
        body = text[stmt.start:stmt.end]
        head = self._lexer.patterns["call_head"].match(body)
        if head is None:
            raise ParseError("CALL_MALFORMED", f"{src_name} 语句 {position} 无法复解")
        arg_start = head.end()
        arg_end = body.rindex(")")
        slots = _split_slots(body[arg_start:arg_end], arg_start + stmt.start)
        for group in groups:
            quoted = group["slot_form"] == "quoted"
            name_value = None
            name_slot = group.get("name_slot")
            if name_slot is not None and name_slot < len(slots):
                name_value = _unquote(slots[name_slot][0])
            for ordinal in group["text_slots"]:
                if ordinal >= len(slots):
                    continue
                raw, offset = slots[ordinal]
                if quoted:
                    if not (raw.startswith('"') and raw.endswith('"') and len(raw) >= 2):
                        continue
                    value, offset = raw[1:-1], offset + 1
                else:
                    if '"' in raw:
                        continue
                    value = raw
                if not value:
                    continue
                ctx = {"callee_group": group["id"], "name_slot_value": name_value,
                       "anchor_kind": self._shape_kinds[stmt.shape]["kind"]}
                rule = self._rules.classify(value, ctx)
                if rule is None:
                    continue
                yield self._make(
                    idx=idx, src_id=src_id, src_name=src_name, position=position,
                    shape=stmt.shape, tag=rule["tag"],
                    subtype=rule.get("subtype", group.get("subtype", "")),
                    tag_source=rule["tag_source"], confidence=rule["confidence"],
                    raw=value, start=offset, end=offset + len(value),
                    encoding=encoding, capacity=None,
                    policy_override=rule.get("translate_policy"),
                    opcode=stmt.groups[0], slot_ordinal=ordinal,
                    matched_rule_id=rule["id"])
                idx += 1


def _split_slots(args: str, base: int) -> list[tuple[str, int]]:
    """按顶层逗号切分参数，返回 (原文, 绝对字符偏移)。引号与括号内的逗号不切。"""
    slots: list[tuple[str, int]] = []
    depth = 0
    quoted = False
    start = 0
    for pos, char in enumerate(args):
        if quoted:
            if char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            slots.append((args[start:pos], base + start))
            start = pos + 1
    slots.append((args[start:], base + start))
    return slots


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return raw


def _quoted_literal(raw: str) -> str | None:
    """带引号的字面量才返回内容；裸标识符（变量引用）返回 None。"""
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return None


# ---------------------------------------------------------------------------
# 归档文档：整个 idx+pak 的 IR。唯一真值，asm / 文本 / 重建全部只从它投影。
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class EntryDoc:
    src_id: int
    name: str
    record: IdxRecord
    raw: bytes                  # 加密态原始条目字节
    label_table_end: int
    text_offset: int
    labels: list[LabelRecord]
    body: str                   # 解密并解码后的正文（不含尾部 NUL 与种子）
    body_raw: bytes
    seed_tail: bytes            # 正文之后保留的字节（v1/v2 的 tail_reserved）
    statements: list[Statement]
    entries: list[TextEntry] = field(default_factory=list)


@dataclass(slots=True)
class ArchiveDoc:
    idx_path: Path
    pak_path: Path
    idx_raw: bytes
    pak_raw: bytes
    idx_plain: bytes
    idx_key: str
    idx_key_source: str
    pak_key: str
    pak_key_source: str
    cipher_version: int
    layout: dict[str, Any]
    table_end: int
    base_offset: int
    records: list[IdxRecord]
    entries: list[EntryDoc]
    encoding: str
    alis: bool
    rule_hits: dict[str, int] = field(default_factory=dict)
    rule_misses: int = 0
    shape_signatures: dict[str, int] = field(default_factory=dict)

    @property
    def text_entries(self) -> list[TextEntry]:
        return [e for doc in self.entries for e in doc.entries]

    def capability_tier(self) -> str:
        """决定允许申报哪些回封能力的 tier（§1.3）。

        取**参与文本改写的**区域的最低 tier，而不是整个文件的最低 tier。
        正文与标签表是 T2（形态与参数槽已证明），对齐填充与 PRNG 种子是 T1
        但它们逐字节原样复制、不被重新解释，因此不构成能力上限。
        用整文件 min_tier 会得到 T1，从而把 pointer-rewrite 误判为 TIER_TOO_LOW
        —— 那是"参与操作的区域"被算错，不是能力真的不足。
        """
        participating = {"script-statements", "label-table"}
        tiers = [region["decode_tier"] for region in self.regions("pak")
                 if region["kind"] in participating]
        return min(tiers, default="T0")

    def join_sites(self) -> list[dict[str, Any]]:
        """§3：idx 记录的 offset 字段，其值等于条目在 pak 层的起始偏移。

        键为 entry_offset（合法键，§3.1）。四条验证（§3.2）全部成立：
        对齐（记录步长整除）、范围（指向条目 start 而非内部）、锚点上下文
        （字段位于已识别的定长记录内）、密度（站点数 == 条目数，比例 1:1）。
        """
        width = self.layout["field_width"]
        sites: list[dict[str, Any]] = []
        for rec in self.records:
            sites.append({
                "join_id": f"J{rec.ordinal:05d}",
                "src_id": rec.ordinal,
                "source_layer": "L_IDX_PLAIN",
                "source_artifact_hash": sha256_bytes(self.idx_plain),
                "site_offset": rec.offset_site,
                "site_width": width,
                "site_endianness": "little",
                "site_tier": "T1",
                "key_kind": "entry_offset",
                "key_value": rec.offset,
                "target_layer": "L_PAK",
                "target_object_id": rec.name,
                "anchor_ref": f"IDX_RECORD[{rec.ordinal}]",
                "confidence": "derived",
                "collision_class": "unique",
                "rewrite_policy": "rewrite",
                "evidence_refs": ["EV_IDX_JOIN", "EV_IDX_CONTIGUOUS"],
            })
            sites.append({
                "join_id": f"L{rec.ordinal:05d}",
                "src_id": rec.ordinal,
                "source_layer": "L_IDX_PLAIN",
                "source_artifact_hash": sha256_bytes(self.idx_plain),
                "site_offset": rec.length_site,
                "site_width": width,
                "site_endianness": "little",
                "site_tier": "T1",
                "key_kind": "entry_length",
                "key_value": rec.length,
                "target_layer": "L_PAK",
                "target_object_id": rec.name,
                "anchor_ref": f"IDX_RECORD[{rec.ordinal}]",
                "confidence": "derived",
                "collision_class": "unique",
                "rewrite_policy": "rewrite",
                "evidence_refs": ["EV_IDX_JOIN"],
            })
        return sites

    def regions(self, target: str) -> list[dict[str, Any]]:
        """区间必须恰好覆盖 [0, size)，每字节唯一归属（§8）。"""
        if target == "idx":
            data = self.idx_raw
            width = self.layout["field_width"]
            stride = self.layout["name_size"] + 2 * width
            out = [_region("R_IDX_TABLE", 0, self.table_end + stride, "decoded",
                           "idx-record-stream", data, "T1",
                           ["EV_IDX_KEY", "EV_IDX_TERM"],
                           cell_size=stride, cell_count=len(self.records) + 1)]
            seed = len(data) - DIALECT["archive"]["idx_cipher"]["seed_field_width"]
            table_end = self.table_end + stride
            if seed > table_end:
                out.append(_region("R_IDX_PAD", table_end, seed, "padding",
                                   "zero-pad", data, "T1", ["EV_IDX_TAIL"]))
            out.append(_region("R_IDX_SEED", seed, len(data), "decoded",
                               "prng-seed", data, "T1", ["EV_IDX_KEY"]))
            return out

        out = []
        for doc in self.entries:
            start = doc.record.offset - self.base_offset
            spec = DIALECT["entry"]["label_record"]
            size = spec["alis_size"] if self.alis else spec["size"]
            prefix = f"R_{doc.src_id:04d}"
            table_end = start + doc.label_table_end
            out.append(_region(f"{prefix}_LABELS", start, table_end, "decoded",
                               "label-table", self.pak_raw, "T2",
                               ["EV_LABEL_TABLE", "EV_LABEL_DOLLAR"],
                               anchor_hit_count=len(doc.labels),
                               join_site_count=len(doc.labels)))
            text_start = start + doc.text_offset
            if text_start > table_end:
                out.append(_region(f"{prefix}_PAD", table_end, text_start, "padding",
                                   "zero-pad", self.pak_raw, "T1", ["EV_TEXT_OFFSET"]))
            body_end = text_start + len(doc.body_raw)
            out.append(_region(f"{prefix}_BODY", text_start, body_end, "decoded",
                               "script-statements", self.pak_raw, "T2",
                               ["EV_PAK_KEY", "EV_CALL_NUMERIC"],
                               anchor_hit_count=len(doc.statements),
                               join_site_count=len(doc.entries)))
            tail_end = start + doc.record.length
            out.append(_region(f"{prefix}_SEED", body_end, tail_end, "decoded",
                               "prng-seed", self.pak_raw, "T1", ["EV_ENTRY_SEED"]))
        return out


def _region(rid: str, start: int, end: int, status: str, kind: str, data: bytes,
            tier: str, evidence: list[str], **extra: Any) -> dict[str, Any]:
    return dict({
        "id": rid, "layer_id": "L000", "start": start, "end": end,
        "status": status, "kind": kind,
        "raw_sha256": sha256_bytes(data[start:end]),
        "owner": "profile_scpack", "decode_tier": tier,
        "tier_evidence_refs": evidence, "tier_blocked_at": None,
        "confidence": "derived", "evidence_refs": evidence,
        "rewrite_policy": "rewrite" if status == "decoded" else "preserve",
    }, **extra)


# ---------------------------------------------------------------------------
# 解析入口
# ---------------------------------------------------------------------------
def parse_archive(script_dir: Path, encoding: str | None = None,
                  alis: bool = False) -> ArchiveDoc:
    spec = DIALECT["archive"]
    idx_path = script_dir / spec["idx_name"]
    pak_path = script_dir / spec["pak_name"]
    for path in (idx_path, pak_path):
        if not path.is_file():
            raise ParseError("ARCHIVE_MISSING", f"找不到 {path}")

    idx_raw = idx_path.read_bytes()
    pak_raw = pak_path.read_bytes()
    encoding = encoding or DIALECT["entry"]["encoding"]["source"]

    idx_key, idx_key_source = solve_idx_key(idx_raw)
    idx_plain = bytes(xor_idx(bytearray(idx_raw), idx_key.encode()))
    layout = record_layout(len(idx_raw))
    records, table_end = read_idx_records(idx_plain)
    if not records:
        raise ParseError("IDX_EMPTY", "idx 中没有任何记录")

    base = records[0].offset
    cursor = base
    for rec in records:
        if rec.offset != cursor:
            raise ParseError("PAK_NONCONTIGUOUS",
                             f"条目 {rec.name} 偏移 {rec.offset} 与预期 {cursor} 不符",
                             entry=rec.name)
        cursor += rec.length
    if cursor - base != len(pak_raw):
        raise ParseError("PAK_SIZE_MISMATCH",
                         f"条目长度之和 {cursor - base} != pak 尺寸 {len(pak_raw)}")

    raw_entries = {rec.name: bytearray(pak_raw[rec.offset - base:
                                               rec.offset - base + rec.length])
                   for rec in records}
    label_map: dict[str, list[LabelRecord]] = {}
    table_ends: dict[str, int] = {}
    offsets: dict[str, int] = {}
    for rec in records:
        labels, end = read_label_table(raw_entries[rec.name], alis)
        label_map[rec.name] = labels
        table_ends[rec.name] = end
        offsets[rec.name] = derive_text_offset(raw_entries[rec.name], end, alis)

    text_offset = _consensus_text_offset(offsets)
    pak_key, version, pak_key_source = solve_pak_key(raw_entries, label_map, text_offset)

    lexer = StatementLexer()
    extractor = TextExtractor(lexer)
    reserved = DIALECT["entry"]["pak_cipher"]["versions"][version]["tail_reserved"]

    # 第一遍：解密、解码、切分语句。全部源都切完再提取文本，
    # 这样虚拟名引用的变量赋值（可能在任意源里）已经收集齐。
    plains: dict[str, bytes] = {}
    bodies: dict[str, str] = {}
    body_raws: dict[str, bytes] = {}
    stmt_map: dict[str, list[Statement]] = {}
    for rec in records:
        plain = bytes(xor_entry(bytearray(raw_entries[rec.name]), text_offset,
                                pak_key.encode(), version))
        body_raw = plain[text_offset:len(plain) - reserved]
        try:
            body = body_raw.decode(encoding)
        except UnicodeDecodeError as exc:
            raise ParseError("BODY_UNDECODABLE",
                             f"{rec.name} 正文无法以 {encoding} 解码：{exc}",
                             entry=rec.name) from exc
        if body.encode(encoding) != body_raw:
            raise ParseError("BODY_ROUNDTRIP",
                             f"{rec.name} 正文 {encoding} 往返不一致", entry=rec.name)
        plains[rec.name] = plain
        bodies[rec.name] = body
        body_raws[rec.name] = body_raw
        stmt_map[rec.name] = lexer.lex(body)

    extractor.scan_variables(stmt_map, bodies)

    # 第二遍：提取文本条目。idx 按源顺序连续分配，与第一遍的顺序无关。
    docs: list[EntryDoc] = []
    next_idx = 1
    for rec in records:
        plain = plains[rec.name]
        doc = EntryDoc(
            src_id=rec.ordinal, name=rec.name, record=rec,
            raw=bytes(raw_entries[rec.name]),
            label_table_end=table_ends[rec.name], text_offset=text_offset,
            labels=label_map[rec.name], body=bodies[rec.name],
            body_raw=body_raws[rec.name],
            seed_tail=plain[len(plain) - reserved:], statements=stmt_map[rec.name])
        doc.entries = extractor.extract(doc.body, doc.statements, rec.ordinal,
                                        rec.name, encoding, next_idx)
        next_idx += len(doc.entries)
        docs.append(doc)

    return ArchiveDoc(
        idx_path=idx_path, pak_path=pak_path, idx_raw=idx_raw, pak_raw=pak_raw,
        idx_plain=idx_plain, idx_key=idx_key, idx_key_source=idx_key_source,
        pak_key=pak_key, pak_key_source=pak_key_source, cipher_version=version,
        layout=layout, table_end=table_end, base_offset=base, records=records,
        entries=docs, encoding=encoding, alis=alis,
        rule_hits=extractor.rule_hits, rule_misses=extractor.rule_misses,
        shape_signatures=dict(extractor.shape_signatures))


def _consensus_text_offset(offsets: dict[str, int]) -> int:
    """全部条目必须给出同一个正文起点。分歧即解析失败，不取多数（铁律 4）。"""
    distinct = set(offsets.values())
    if len(distinct) != 1:
        sample = {k: v for k, v in list(offsets.items())[:5]}
        raise ParseError("TEXT_OFFSET_DISAGREEMENT",
                         f"条目间正文起点不一致：{sorted(distinct)[:5]}；样本 {sample}")
    value = distinct.pop()
    expected = DIALECT["entry"]["text_offset"]["expected"]
    if value != expected:
        sys.stderr.write(f"[note] 推导出的正文起点 {value} 与方言 expected {expected} "
                         f"不同；以推导值为准（§7.5.2）\n")
    return value


# ---------------------------------------------------------------------------
# 重建：正文 → 条目 → pak/idx。支持变长（§6.0.1 变长是主要用例）
# ---------------------------------------------------------------------------
def apply_edits(doc: EntryDoc, edits: dict[int, str], encoding: str) -> str:
    """把译文写回正文。按**字符区间**替换，从后往前，避免偏移串位。

    这是「按站点不按值」在文本层的对应（§6.3）：每处改写都锚定到一个 TextEntry
    的 char 区间，绝不做 `body.replace(旧文本, 新文本)` —— 那会命中所有恰好相同
    的其他文本（重复台词、同名说话者）并静默改掉。
    """
    if not edits:
        return doc.body
    body = doc.body
    targets = [e for e in doc.entries if e.idx in edits]
    for entry in sorted(targets, key=lambda e: e.char_start, reverse=True):
        current = body[entry.char_start:entry.char_end]
        if current != entry.plain_source(encoding):
            raise ParseError("EDIT_ANCHOR_DESYNC",
                             f"idx={entry.idx} 的原文区间与 IR 不一致，拒绝写入",
                             idx=entry.idx)
        replacement = from_placeholders(edits[entry.idx], encoding).decode(encoding)
        _reject_structural_chars(entry, replacement)
        body = body[:entry.char_start] + replacement + body[entry.char_end:]
    return body


# 各形态的可编辑片段有各自的结束条件；译文含这些字符会改变语句边界。
_FORBIDDEN_IN_SLOT = {
    "message": '"',
    "speaker": "\r\n",
    "label": "\r\n$",
    "call": '"()',
}


def _reject_structural_chars(entry: TextEntry, text: str) -> None:
    forbidden = _FORBIDDEN_IN_SLOT.get(entry.shape, "")
    hit = [c for c in forbidden if c in text]
    if hit:
        raise ParseError("EDIT_BREAKS_STRUCTURE",
                         f"idx={entry.idx} 译文含结构字符 {hit!r}，会破坏语句边界；"
                         f"如需该字符请用占位符 {{{{XX}}}}",
                         idx=entry.idx)


def build_entry(doc: EntryDoc, body_raw: bytes, pak_key: str, version: int,
                alis: bool) -> tuple[bytes, list[dict[str, Any]]]:
    """正文字节 → 加密态条目。长度随正文变化，不假设等长。

    顺序固定为「组装明文 → 按站点回填标签偏移 → 一次性加密」（§6.0.3 第 2-6 步）。
    先加密再回填会把明文偏移写进密文位置，产出可加载但错位的条目。
    """
    plain = bytearray(doc.raw[:doc.text_offset]) + body_raw + doc.seed_tail
    log: list[dict[str, Any]] = []
    if body_raw != doc.body_raw:
        plain, log = fix_label_offsets(plain, doc, body_raw, alis)
    return bytes(xor_entry(bytearray(plain), doc.text_offset,
                           pak_key.encode(), version)), log


def _encode_body(body: str, encoding: str) -> bytes:
    """占位符展开为原始字节，其余按目标编码（§6.0.2 的唯一长度口径）。"""
    return from_placeholders(body, encoding)


def fix_label_offsets(entry: bytearray, doc: EntryDoc, body_raw: bytes,
                      alis: bool) -> tuple[bytearray, list[dict[str, Any]]]:
    """按站点回填标签表的 offset 字段（§6.3）。

    改写单位是 LabelRecord.offset_site —— 一个已定位的字段偏移，不是「值等于旧
    偏移的任意 4 字节」。正文变长后标签在正文里的新位置由 `$名字` 顺序查找确定。
    """
    spec = DIALECT["entry"]["label_record"]
    width = spec["offset_field_width"]
    fmt = struct.Struct("<I")
    out = bytearray(entry)
    log: list[dict[str, Any]] = []
    cursor = 0
    for label in doc.labels:
        needle = b"$" + label.name
        found = body_raw.find(needle, cursor)
        if found < 0:
            raise ParseError("LABEL_LOST",
                             f"{doc.name} 标签 {label.name!r} 在新正文中找不到"
                             f"（原偏移 {label.offset}）；标签不得删除或改名",
                             entry=doc.name, label=label.name.decode("latin1", "replace"))
        cursor = found + 1
        if found != label.offset:
            fmt.pack_into(out, label.offset_site, found)
            log.append({"kind": "label_offset", "entry": doc.name,
                        "offset": label.offset_site, "length": width,
                        "old_value": label.offset, "new_value": found,
                        "reason": "text length changed"})
    return out, log


def rebuild_archive(doc: ArchiveDoc, bodies: dict[int, str] | None = None
                    ) -> tuple[bytes, bytes, list[dict[str, Any]], dict[str, Any]]:
    """重建 (idx_raw, pak_raw, 重定位日志, 站点映射)。

    零编辑时输出与原件逐字节相同；有编辑时长度可变，全部引用按站点回填。
    """
    bodies = bodies or {}
    width = doc.layout["field_width"]
    fmt = struct.Struct("<q" if width == 8 else "<I")
    pak = io.BytesIO()
    plain = bytearray(doc.idx_plain)
    reloc: list[dict[str, Any]] = []
    mapping: dict[int, int] = {}
    cursor = doc.base_offset

    for entry_doc in doc.entries:
        body = bodies.get(entry_doc.src_id)
        body_raw = (entry_doc.body_raw if body is None
                    else _encode_body(body, doc.encoding))
        blob, entry_log = build_entry(entry_doc, body_raw, doc.pak_key,
                                      doc.cipher_version, doc.alis)
        reloc.extend(entry_log)
        rec = entry_doc.record
        if cursor != rec.offset:
            mapping[rec.offset] = cursor
        fmt.pack_into(plain, rec.offset_site, cursor)
        fmt.pack_into(plain, rec.length_site, len(blob))
        if cursor != rec.offset or len(blob) != rec.length:
            reloc.append({"kind": "idx_record", "entry": rec.name,
                          "offset": rec.offset_site, "length": 2 * width,
                          "old_value": rec.offset, "new_value": cursor,
                          "old_length": rec.length, "new_length": len(blob),
                          "reason": "entry size changed"})
        pak.write(blob)
        cursor += len(blob)

    idx_raw = bytes(xor_idx(plain, doc.idx_key.encode()))
    return idx_raw, pak.getvalue(), reloc, mapping
