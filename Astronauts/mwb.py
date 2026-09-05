# -*- coding: utf-8 -*-
"""mwb.py — ZMOA/moacode.mwb 容器与字节码 token 流的内存 IR。

内存 IR 是解析真值；asm.txt 与 texts/*.txt 是它的两个平级投影。
IR 默认不落盘（源二进制本身即最紧凑的 IR，解析确定）。

层次：

    mwb 文件
      └ Layer L000  ZMOA 头（0x1C 字节，原样保留）
          └ Layer L001  zlib（可重放）
              └ Region R_CODE  token 流（tier T2）

token 语法（大端）：

    STR   0x1A + u32 len + len 字节 + 0x00
    REF   0x00 + u24
    REFE  0xFF + u24                    （值恒 0xFFFFFF）
    INT   0x05 + i32
    P15   0x15 + i32
    P06   0x06 + i32
    END   0x07 + i32
    MARK  0x21                          （1 字节）
    BLK   0x20 + i32
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from opcodelist import DIALECT

ZMOA_MAGIC = b"ZMOA"
ZMOA_HEADER_SIZE = 0x1C

TAG_STR = 0x1A
TAG_REF = 0x00
TAG_REFE = 0xFF
TAG_INT = 0x05
TAG_P15 = 0x15
TAG_P06 = 0x06
TAG_END = 0x07
TAG_MARK = 0x21
TAG_BLK = 0x20

_FIXED5 = (TAG_INT, TAG_P15, TAG_P06, TAG_END, TAG_BLK)
_U24 = (TAG_REF, TAG_REFE)

TOKEN_NAMES = {
    TAG_STR: "STR", TAG_REF: "REF", TAG_REFE: "REFE", TAG_INT: "INT",
    TAG_P15: "P15", TAG_P06: "P06", TAG_END: "END", TAG_MARK: "MARK",
    TAG_BLK: "BLK",
}


class MwbError(Exception):
    pass


@dataclass(slots=True)
class Token:
    """一个 token。offset/size 使字节归属唯一可判定。"""
    tag: int
    offset: int
    size: int
    arg: int = 0                  # 定长参数 / u24 / 字符串字节长度
    text: bytes | None = None     # 仅 STR

    @property
    def kind(self) -> str:
        return TOKEN_NAMES.get(self.tag, "T%02X" % self.tag)


@dataclass(slots=True)
class TextEntry:
    """一条可编辑文本，绑定到唯一 token 站点。

    msg 条目按语句合并：同一 text 语句的多个页块本质是一句话被消息窗按行拆开，
    合并为一条导出，source 内以 "\\n" 分页（双行文件中呈现为 {{BR}}）。
    pages 记录各页原始 STR token 下标；page_span 为整个页块区间（含 MARK/BLK 等
    结构 token），回封时按该区间整体重写，允许页数变化。
    """
    idx: int
    tok_index: int                # 主站点（msg 为首页 STR）
    offset: int                   # 主站点 STR token 在载荷内的偏移
    tag: str                      # msg / name / choice / label / ui / misc
    policy: str                   # translatable / frozen / review-required
    source: str                   # 原文（多页以 \n 连接）
    speaker: str | None = None    # msg 的说话人（若有）
    voice: str | None = None      # msg 的 voice id（若有）
    stmt_fn: str | None = None    # 所属语句的函数名
    tag_source: str = "structural"
    pages: tuple[int, ...] = ()   # 各页 STR token 下标（非 msg 时为单元素）
    page_span: tuple[int, int] | None = None   # (载荷起始偏移, 载荷结束偏移)
    chapter: int = -1             # 所属剧情段序号（-1 = 分界之前）


@dataclass(slots=True)
class Statement:
    """一条语句（T2 锚点）。"""
    index: int                    # 语句序号
    tok_start: int
    tok_end: int                  # 闭区间末端（END token 或其后的 label STR）
    ref_id: int
    fn_name: str | None
    offset: int


@dataclass(slots=True)
class Chapter:
    """一段剧情。边界由 `go <章节名>` 语句给出，对应一个原始脚本文件。"""
    index: int
    name: str                     # 章节标签名，如 共通＿01
    src_file: str                 # 头部标签表映射到的源文件名，如 共通＿01.txt
    stmt_start: int               # 起始语句序号（含）
    stmt_end: int                 # 结束语句序号（不含）
    offset: int                   # 起始语句的载荷偏移


@dataclass
class MwbDocument:
    path: Path
    raw: bytes                        # 原始 .mwb（含 ZMOA 头）
    header: bytes                     # ZMOA 头 0x1C 字节
    version: int
    payload: bytes                    # 解压后的 token 流
    tokens: list[Token]
    statements: list[Statement] = field(default_factory=list)
    fn_table: dict[int, str] = field(default_factory=dict)
    texts: list[TextEntry] = field(default_factory=list)
    src_sha256: str = ""
    payload_sha256: str = ""
    shape_hits: dict[str, int] = field(default_factory=dict)
    label_table: dict[str, tuple[str, int]] = field(default_factory=dict)
    chapters: list[Chapter] = field(default_factory=list)

    # ---------------- 覆盖率 ----------------
    def byte_coverage(self) -> tuple[int, int]:
        covered = sum(t.size for t in self.tokens)
        return covered, len(self.payload)


# ----------------------------------------------------------------------
# 解析
# ----------------------------------------------------------------------

def _tokenize(payload: bytes) -> list[Token]:
    """全量切分 token。任何未知字节即抛错（禁止静默跳过）。"""
    toks: list[Token] = []
    append = toks.append
    o = 0
    n = len(payload)
    u32be = struct.Struct(">I")
    i32be = struct.Struct(">i")
    while o < n:
        tag = payload[o]
        if tag == TAG_STR:
            if o + 5 > n:
                raise MwbError(f"STR 头越界 @{o:#x}")
            ln = u32be.unpack_from(payload, o + 1)[0]
            end = o + 5 + ln
            if end >= n or payload[end] != 0:
                raise MwbError(f"STR 终止符缺失 @{o:#x} len={ln}")
            append(Token(TAG_STR, o, 5 + ln + 1, ln, payload[o + 5:end]))
            o = end + 1
        elif tag == TAG_MARK:
            append(Token(TAG_MARK, o, 1))
            o += 1
        elif tag in _U24:
            if o + 4 > n:
                raise MwbError(f"u24 参数越界 @{o:#x}")
            arg = (payload[o + 1] << 16) | (payload[o + 2] << 8) | payload[o + 3]
            append(Token(tag, o, 4, arg))
            o += 4
        elif tag in _FIXED5:
            if o + 5 > n:
                raise MwbError(f"i32 参数越界 @{o:#x}")
            append(Token(tag, o, 5, i32be.unpack_from(payload, o + 1)[0]))
            o += 5
        else:
            raise MwbError(f"未定义 token 标签 {tag:#02x} @{o:#x}")
    return toks


def _build_fn_table(toks: list[Token]) -> dict[int, str]:
    """内建函数表：INT(id) INT(-1) INT(1) STR(name)。另收录代码区 REF(id) STR(name)。"""
    table: dict[int, str] = {}
    n = len(toks)
    # 表项布局：STR(name) INT(id) INT(-1) INT(1)  —— 名字在 id 之前
    for i in range(n - 3):
        if (toks[i].tag == TAG_STR and toks[i + 1].tag == TAG_INT
                and toks[i + 2].tag == TAG_INT and toks[i + 2].arg == -1
                and toks[i + 3].tag == TAG_INT and toks[i + 3].arg == 1):
            table.setdefault(toks[i + 1].arg,
                             toks[i].text.decode("utf-8", "replace"))
    for i in range(n - 1):
        if toks[i].tag == TAG_REF and toks[i + 1].tag == TAG_STR:
            table.setdefault(toks[i].arg,
                             toks[i + 1].text.decode("utf-8", "replace"))
    return table


def _build_label_table(toks: list[Token], first_code_tok: int) -> dict[str, tuple[str, int]]:
    """头部标签表：STR(label) INT(line) INT(0) STR(file) INT(kind) → {label: (file, line)}。

    证据：103 条表项，其中 67 条被代码区的 `go <name>` 引用，全部映射到 .txt 源文件，
    与 modlist.dat 的编译源清单一致（EV_LABEL_TABLE）。
    """
    table: dict[str, tuple[str, int]] = {}
    i = 0
    limit = max(0, first_code_tok - 4)
    while i < limit:
        if (toks[i].tag == TAG_STR and toks[i + 1].tag == TAG_INT
                and toks[i + 2].tag == TAG_INT and toks[i + 3].tag == TAG_STR
                and toks[i + 4].tag == TAG_INT):
            label = toks[i].text.decode("utf-8", "replace")
            src = toks[i + 3].text.decode("utf-8", "replace")
            table.setdefault(label, (src, toks[i + 1].arg))
            i += 5
            continue
        i += 1
    return table


def _build_chapters(doc: MwbDocument) -> list[Chapter]:
    """剧情分段：以 `go <章节名>` 为边界，每段对应一个原始脚本文件。

    判据（EV_CHAPTER_BOUNDARY）：`go` 的跳转目标出现在头部标签表中、且映射到
    `.txt` 源文件、且名字不以 `@` 开头（`@` 前缀为文件内的局部标签，如 @SKIP2）。
    实测 67 个边界，语句序号严格递增，24,015 条可翻译条目全部归属，零遗漏。
    """
    toks = doc.tokens
    n = len(toks)
    bounds: list[tuple[int, str, str]] = []
    for s in doc.statements:
        if s.fn_name != "go":
            continue
        for k in range(s.tok_start, min(s.tok_end + 1, n)):
            if toks[k].tag == TAG_STR and k > 0 and toks[k - 1].tag == TAG_REFE:
                name = toks[k].text.decode("utf-8", "replace")
                if name.startswith("@"):
                    continue
                info = doc.label_table.get(name)
                if info and info[0].endswith(".txt"):
                    bounds.append((s.index, name, info[0]))
                break

    chapters: list[Chapter] = []
    for j, (stmt_i, name, src) in enumerate(bounds):
        end = bounds[j + 1][0] if j + 1 < len(bounds) else len(doc.statements)
        chapters.append(Chapter(index=j, name=name, src_file=src,
                                stmt_start=stmt_i, stmt_end=end,
                                offset=doc.statements[stmt_i].offset))
    return chapters


def _assign_chapters(doc: MwbDocument) -> None:
    """把每条文本归入所在剧情段（按语句序号二分）。"""
    if not doc.chapters:
        return
    import bisect
    starts = [c.stmt_start for c in doc.chapters]
    n = len(doc.tokens)
    owner = [-1] * n
    for s in doc.statements:
        for k in range(s.tok_start, min(s.tok_end + 1, n)):
            owner[k] = s.index
    for e in doc.texts:
        si = owner[e.tok_index]
        if si < 0:
            e.chapter = -1
            continue
        e.chapter = bisect.bisect_right(starts, si) - 1


def _build_statements(toks: list[Token], fn_table: dict[int, str]) -> list[Statement]:
    """语句 = REF(id) [STR(name)] ... END [REFE STR(label)]。"""
    stmts: list[Statement] = []
    n = len(toks)
    i = 0
    idx = 0
    while i < n:
        if toks[i].tag != TAG_REF:
            i += 1
            continue
        start = i
        ref_id = toks[i].arg
        fn = None
        j = i + 1
        if j < n and toks[j].tag == TAG_STR:
            fn = toks[j].text.decode("utf-8", "replace")
            j += 1
        else:
            fn = fn_table.get(ref_id)
        # 终止符是 END(0)。END(-1) 不是终止符——它引导 REFE + STR(label)（标签引用），
        # 语句在其后继续，直到 END(0)。实测：END(0) 47251 条 == REF 语句头数量；
        # END(-1) 252 条全部紧跟 REFE+STR。
        while j < n:
            t = toks[j]
            if t.tag == TAG_END:
                if t.arg == 0:
                    break
                if (t.arg == -1 and j + 2 < n
                        and toks[j + 1].tag == TAG_REFE and toks[j + 2].tag == TAG_STR):
                    j += 3
                    continue
                break
            if t.tag == TAG_REF:            # 下一条语句已开始（缺 END，防御性）
                break
            j += 1
        end = min(j, n - 1)
        stmts.append(Statement(index=idx, tok_start=start, tok_end=end,
                               ref_id=ref_id, fn_name=fn, offset=toks[start].offset))
        idx += 1
        i = end + 1
    return stmts


# ----------------------------------------------------------------------
# 文本发现（T2 锚点，仅走已证明的结构连接；无正则、无旁路扫描）
# ----------------------------------------------------------------------

# attr 编号（40=arg0 / 35=argN / 14=objref）在 opcodelist.DIALECT["param_ids"] 中声明，
# 此处只用位置序号，不需要 attr 字面量——参数角色由 (函数, 位置) 决定，见 ARG_TAGS。
_PARAM_STRVAL = 5
_PARAM_MSG = 8
_PARAM_OBJ = 2
_PARAM_CHOICE_TARGET = 65543
_PARAM_GOIF_TARGET = 65545
_PARAM_MACRO = 327687

# 每个函数的位置参数语义：ARG_TAGS[fn][i] = 第 i 个 p5 位置参数的角色。
# 证据：131 个字符串槽位类的全量清点与取值抽样，见 vm_analysis.md §5。
# 角色 → tag/policy 映射见 _ROLE_TAG。未列出的函数：全部位置参数按 res 处理。
ARG_TAGS: dict[str, tuple[str, ...]] = {
    "text":             ("name", "voice"),
    # sel 有两个形态，见 SEL_SHAPES；此处为“无跳转目标”形态（舞台用法）
    "sel":              ("res", "effect"),
    "setgamedatatitle": ("ui",),
    "stand":            ("res", "effect"),
    "bg":               ("res", "effect"),
    "ev":               ("res", "effect"),
    "bgm":              ("res", "effect"),
    "se":               ("res", "effect"),
    "se_0":             ("res", "effect"),
    "se_1":             ("res", "effect"),
    "se_2":             ("res", "effect"),
    "se_3":             ("res", "effect"),
    "vo":               ("res", "effect"),
    "go":               ("label",),
    "goif":             ("label",),
    "gosub":            ("label",),
    "rp.set":           ("label",),
    "rp.end":           ("label",),
    "sel.go":           ("label",),
}

# 角色 → (tag, policy)。tag 取自 §4.2 的八元闭集。
_ROLE_TAG = {
    "name":   ("name", "translatable"),
    "choice": ("choice", "translatable"),
    "ui":     ("ui", "translatable"),
    "voice":  ("misc", "frozen"),
    "res":    ("misc", "frozen"),
    "effect": ("misc", "frozen"),
    "label":  ("label", "frozen"),
}

# sel(2000) 的两个形态（§7.1.3 形态派发：并列判定，无命中即显式失败）。
# 判定条件为纯谓词，与提取分离，报告可给出命中了哪个形态。
#
#   menu   —— 语句内存在跳转目标参数（P06 65543）：真实选项菜单，p5 串 = 选项文本
#   stage  —— 无跳转目标：舞台用法（转场/资源），p5 串不可翻译
#
# 证据：336 条 sel 语句中 2 条为 menu 形态（含 @YES_KUR/@EXIT00 目标），
# 其中 1 条带 3 个选项文本（'今は決められない'/'契りを交わす'/'何も答えずに黙っている'）；
# 其余 334 条无跳转目标，p5 取值为 'staff_01_2'、'T' 等资源与效果名。
SEL_SHAPES = (
    ("sel.menu",  ("choice",) * 8),
    ("sel.stage", ("res", "effect")),
)


def _scan_args(toks: list[Token], s: Statement, n: int):
    """还原一条语句的参数序列。

    返回 [(tok_index, role_slot, param_id, attr)]，其中 role_slot 为该串在
    p5 位置参数中的序号（非 p5 参数为 None）。
    """
    args = []
    pos = 0
    k = s.tok_start
    end = min(s.tok_end, n - 1)
    while k <= end - 1:
        t = toks[k]
        if t.tag == TAG_P15 and toks[k + 1].tag == TAG_P06:
            attr = t.arg if t.arg == 0 else None
            pid_holder = toks[k + 1].arg
            # (P15 0)(P06 attr)(P15 4)(P06 pid)[STR] —— 带值参数
            if (t.arg == 0 and k + 4 <= end
                    and toks[k + 2].tag == TAG_P15 and toks[k + 2].arg == 4
                    and toks[k + 3].tag == TAG_P06 and toks[k + 4].tag == TAG_STR):
                pid = toks[k + 3].arg
                slot = None
                if pid == _PARAM_STRVAL:
                    slot = pos
                    pos += 1
                args.append((k + 4, slot, pid, pid_holder))
                k += 5
                continue
            # (P15 4)(P06 pid)[STR] —— 无 attr 前缀的带值参数
            if (t.arg == 4 and k + 2 <= end and toks[k + 2].tag == TAG_STR):
                pid = pid_holder
                slot = None
                if pid == _PARAM_STRVAL:
                    slot = pos
                    pos += 1
                args.append((k + 2, slot, pid, None))
                k += 3
                continue
            k += 2
            continue
        k += 1
    return args


def _match_sel_shape(args) -> tuple[str, tuple[str, ...]]:
    """sel 形态判定（纯谓词，不产生副作用）。无命中即抛错，不静默回落。"""
    has_target = any(pid == _PARAM_CHOICE_TARGET for _i, _s, pid, _a in args)
    for name, tags in SEL_SHAPES:
        if name == "sel.menu" and has_target:
            return name, tags
        if name == "sel.stage" and not has_target:
            return name, tags
    raise MwbError("sel 语句形态未命中任何已声明形态")


def _extract_texts(doc: MwbDocument) -> list[TextEntry]:
    toks = doc.tokens
    n = len(toks)
    owner: list[int] = [-1] * n
    for s in doc.statements:
        for k in range(s.tok_start, min(s.tok_end + 1, n)):
            owner[k] = s.index

    # 先按语句还原参数序列 → 每个 STR token 的角色
    role_of: dict[int, tuple[str, str]] = {}     # tok_index → (tag, policy)
    msg_ctx: dict[int, tuple[str | None, str | None]] = {}
    shape_hits: dict[str, int] = {}
    for s in doc.statements:
        fn = s.fn_name or ("cmd_%d" % s.ref_id)
        args = _scan_args(toks, s, n)
        arg_tags = ARG_TAGS.get(s.fn_name or "", ())
        if s.ref_id == 2000:                       # sel：形态派发
            shape, arg_tags = _match_sel_shape(args)
            shape_hits[shape] = shape_hits.get(shape, 0) + 1
        speaker = voice = None
        for tok_i, slot, pid, _attr in args:
            val = toks[tok_i].text.decode("utf-8", "replace")
            if pid == _PARAM_MSG:
                role_of[tok_i] = ("msg", "translatable")
                continue
            if pid in (_PARAM_CHOICE_TARGET, _PARAM_GOIF_TARGET, _PARAM_MACRO):
                role_of[tok_i] = ("label", "frozen")
                continue
            if pid == _PARAM_OBJ:
                role_of[tok_i] = ("misc", "frozen")      # 对象引用（'栞.COLOR'）
                continue
            if slot is None:
                role_of[tok_i] = ("misc", "frozen")
                continue
            role = arg_tags[slot] if slot < len(arg_tags) else (
                arg_tags[-1] if arg_tags else "res")
            role_of[tok_i] = _ROLE_TAG.get(role, ("misc", "frozen"))
            if role == "name":
                speaker = val
            elif role == "voice":
                voice = val
        if s.fn_name == "text":
            for tok_i, slot, pid, _a in args:
                if pid == _PARAM_MSG:
                    msg_ctx[tok_i] = (speaker, voice)

    # msg 页块合并：同一语句的连续页块本质是一句话，按语句聚合成一条
    msg_groups = _group_msg_pages(doc, toks, role_of, n)
    merged_into: dict[int, int] = {}          # 被合并的从属页 → 首页 tok_index
    for head, pages in msg_groups.items():
        for p in pages[1:]:
            merged_into[p] = head

    texts: list[TextEntry] = []
    idx = 0
    for i in range(n):
        t = toks[i]
        if t.tag != TAG_STR:
            continue
        if i in merged_into:                  # 已并入首页，不单独成条
            continue
        sidx = owner[i]
        stmt = doc.statements[sidx] if sidx >= 0 else None
        fn = stmt.fn_name if stmt else None
        prev1 = toks[i - 1] if i >= 1 else None

        if i in role_of:
            tag, policy = role_of[i]
            tag_source = "structural"
        elif prev1 is not None and prev1.tag == TAG_REFE:
            tag, policy, tag_source = "label", "frozen", "structural"
        elif prev1 is not None and prev1.tag == TAG_REF:
            tag, policy, tag_source = "misc", "frozen", "structural"   # 函数名绑定
        elif prev1 is not None and prev1.tag == TAG_INT:
            tag, policy, tag_source = "misc", "frozen", "structural"   # 表项名
        else:
            tag, policy, tag_source = "misc", "frozen", "structural"

        speaker, voice = msg_ctx.get(i, (None, None))
        idx += 1
        pages = msg_groups.get(i, (i,))
        source = "\n".join(toks[p].text.decode("utf-8", "replace") for p in pages)
        span = None
        if len(pages) > 1 or tag == "msg":
            # 页块区间：从首页的 MARK 起，到末页 STR 结束
            span = (toks[pages[0] - 4].offset,
                    toks[pages[-1]].offset + toks[pages[-1]].size)
        texts.append(TextEntry(
            idx=idx, tok_index=i, offset=t.offset, tag=tag, policy=policy,
            source=source, speaker=speaker, voice=voice, stmt_fn=fn,
            tag_source=tag_source, pages=tuple(pages), page_span=span))
    doc.shape_hits = shape_hits
    return texts


def _group_msg_pages(doc: MwbDocument, toks: list[Token],
                     role_of: dict[int, tuple[str, str]], n: int) -> dict[int, tuple[int, ...]]:
    """把同一 text 语句内的连续 msg 页块聚合。

    页块布局（实测 15568 条语句全部符合，零例外）：
        MARK BLK(1) P15(4) P06(8) STR   —— 相邻页 STR 下标间距恒为 5
    因此可安全按 stride 5 判定连续性；不连续即各自独立成条（防御性）。
    """
    groups: dict[int, tuple[int, ...]] = {}
    for s in doc.statements:
        if s.fn_name != "text":
            continue
        pages = [k for k in range(s.tok_start, min(s.tok_end + 1, n))
                 if toks[k].tag == TAG_STR and role_of.get(k, ("", ""))[0] == "msg"]
        if not pages:
            continue
        run = [pages[0]]
        for prev, cur in zip(pages, pages[1:]):
            if cur - prev == 5:
                run.append(cur)
            else:
                groups[run[0]] = tuple(run)
                run = [cur]
        groups[run[0]] = tuple(run)
    return groups


# ----------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------

def parse(path: str | Path, raw: bytes | None = None) -> MwbDocument:
    """源二进制 → 内存 IR。确定性：同一输入必得同一 IR。"""
    path = Path(path)
    if raw is None:
        raw = path.read_bytes()
    if raw[:4] != ZMOA_MAGIC:
        raise MwbError(f"不是 ZMOA 文件：{path}")
    # ZMOA 头为小端；只有 zlib 载荷内的 token 参数是大端（实测，见 EV_ENDIAN）
    version, uncomp_size, comp_size = struct.unpack_from("<III", raw, 0x10)
    if comp_size != len(raw) - ZMOA_HEADER_SIZE:
        raise MwbError(f"comp_size 不符：{comp_size} vs {len(raw) - ZMOA_HEADER_SIZE}")
    payload = zlib.decompress(raw[ZMOA_HEADER_SIZE:])
    if len(payload) != uncomp_size:
        raise MwbError(f"uncomp_size 不符：{uncomp_size} vs {len(payload)}")

    tokens = _tokenize(payload)
    doc = MwbDocument(
        path=path, raw=raw, header=raw[:ZMOA_HEADER_SIZE], version=version,
        payload=payload, tokens=tokens,
        src_sha256=hashlib.sha256(raw).hexdigest(),
        payload_sha256=hashlib.sha256(payload).hexdigest())
    doc.fn_table = _build_fn_table(tokens)
    doc.statements = _build_statements(tokens, doc.fn_table)
    first_code = doc.statements[0].tok_start if doc.statements else 0
    doc.label_table = _build_label_table(tokens, first_code)
    doc.texts = _extract_texts(doc)
    doc.chapters = _build_chapters(doc)
    _assign_chapters(doc)

    covered, total = doc.byte_coverage()
    if covered != total:
        raise MwbError(f"字节覆盖不完整：{covered}/{total}")
    return doc


def _encode_str(s: str) -> bytes:
    body = s.encode("utf-8")
    return bytes([TAG_STR]) + struct.pack(">I", len(body)) + body + b"\x00"


def _encode_page_block(s: str) -> bytes:
    """一个 msg 页块：MARK BLK(1) P15(4) P06(8) STR。"""
    return (bytes([TAG_MARK])
            + bytes([TAG_BLK]) + struct.pack(">i", 1)
            + bytes([TAG_P15]) + struct.pack(">i", 4)
            + bytes([TAG_P06]) + struct.pack(">i", _PARAM_MSG)
            + _encode_str(s))


def rebuild_payload(doc: MwbDocument, new_texts: dict[int, str] | None = None) -> bytes:
    """重建 token 流。new_texts: {TextEntry.tok_index: 新文本}。

    - 单页条目：仅重写该 STR token（长度字段内联，无需重定位）。
    - 多页 msg 条目：按 page_span 整体重写整个页块序列，译文中的 "\\n" 决定页数，
      因此页数可增可减。安全性依据：流内不存在字节偏移引用
      （INT 参数最大 40013，全部为源码行号；BLK 参数最大 3708），
      见 vm_analysis.md §6。
    """
    new_texts = new_texts or {}
    if not new_texts:
        return doc.payload

    # 收集重写片段：(起始偏移, 结束偏移, 新字节)
    patches: list[tuple[int, int, bytes]] = []
    by_tok = {e.tok_index: e for e in doc.texts}
    for tok_i, val in new_texts.items():
        e = by_tok.get(tok_i)
        if e is not None and e.tag == "msg" and e.page_span is not None:
            pages = val.split("\n")
            if not any(p for p in pages):
                raise MwbError(f"idx={e.idx} 译文分页后全为空")
            blob = b"".join(_encode_page_block(p) for p in pages)
            patches.append((e.page_span[0], e.page_span[1], blob))
        else:
            t = doc.tokens[tok_i]
            if t.tag != TAG_STR:
                raise MwbError(f"tok_index={tok_i} 不是字符串 token")
            patches.append((t.offset, t.offset + t.size, _encode_str(val)))

    patches.sort()
    for (a0, a1, _), (b0, _b1, _b) in zip(patches, patches[1:]):
        if b0 < a1:
            raise MwbError(f"重写区间重叠：[{a0:#x},{a1:#x}) 与 [{b0:#x},…)")

    out = bytearray()
    cursor = 0
    for start, end, blob in patches:
        out += doc.payload[cursor:start]
        out += blob
        cursor = end
    out += doc.payload[cursor:]
    return bytes(out)


def serialize(doc: MwbDocument, new_texts: dict[int, str] | None = None,
              compress_level: int = 6) -> bytes:
    """IR → .mwb 字节（含 ZMOA 头与 zlib 压缩）。"""
    new_payload = rebuild_payload(doc, new_texts)
    # 压缩参数必须与原件一致，否则零编辑重建不能逐字节相同。
    # 实测：level=6 / Z_DEFAULT_STRATEGY / memLevel=8 / wbits=15（zlib 默认）
    # 复现原始 683161 字节流，逐字节一致。见 vm_analysis.md §3。
    co = zlib.compressobj(compress_level, zlib.DEFLATED, 15, 8,
                          zlib.Z_DEFAULT_STRATEGY)
    comp = co.compress(new_payload) + co.flush()
    header = bytearray(doc.header)
    struct.pack_into("<II", header, 0x14, len(new_payload), len(comp))
    return bytes(header) + comp
