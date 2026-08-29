"""DSAT：面向译者的三行文本格式。

每个单元由一行元数据、一行原文和一行译文组成::

    # idx=12 file=aki003.txt.scn off=0x3C10 inst=0x0A44 tag=msg
    ○12○msg○原文
    ●12●msg●译文

三行的 `idx` 与 `tag` 必须一致。只有译文行可以修改；元数据被改动是硬错误，
不是警告。

多个剧本文件合并到一个 DSAT 时，用 `### file=... sha256=...` 分节。每节的
sha256 单独校验，因此改动任一源文件都只会让对应那一节失效，而不是整份作废。
`idx` 只在节内唯一。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from ..core.errors import TextImportError

SRC_MARK = "○"   # ○
DST_MARK = "●"   # ●
# `file=` 与 `path=` 现在不再写出，但仍接受：已经翻到一半的旧文件不能因为格式收窄
# 而作废。
HEADER_RE = re.compile(
    r"^#\s*idx=(?P<idx>\d+)(?:\s+file=(?P<file>\S+))?"
    r"\s+off=(?P<off>0x[0-9A-Fa-f]+)"
    r"\s+inst=(?P<inst>0x[0-9A-Fa-f]+)\s+tag=(?P<tag>\w+)"
    r"(?:\s+path=(?P<path>\S+))?(?:\s+speaker=(?P<speaker>.*))?$")
SECTION_RE = re.compile(
    r"^###\s+file=(?P<file>\S+)\s+sha256=(?P<sha256>[0-9a-f]{64})"
    r"(?:\s+source_encoding=(?P<source_encoding>\S+))?"
    r"(?:\s+units=(?P<units>\d+))?\s*$")
NEWLINE_TOKEN = "\\n"


def escape_line(text: str) -> str:
    """折叠内嵌换行，使一个单元保持在单个物理行内。"""
    return (text.replace("\\", "\\\\").replace("\r\n", NEWLINE_TOKEN)
            .replace("\r", "\\r").replace("\n", NEWLINE_TOKEN))


def unescape_line(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n"); i += 2; continue
            if nxt == "r":
                out.append("\r"); i += 2; continue
            if nxt == "\\":
                out.append("\\"); i += 2; continue
        out.append(ch)
        i += 1
    return "".join(out)


@dataclass(slots=True)
class DsatUnit:
    idx: int
    file: str
    off: int
    inst: int
    tag: str
    source: str
    target: str
    path: str = ""
    speaker: str | None = None


@dataclass(slots=True)
class DsatSection:
    """合并 DSAT 中属于一个源文件的一节。"""

    file: str
    sha256: str
    units: list[DsatUnit]
    source_encoding: str = "utf-8"


def _render_units(entries: Iterable[dict]) -> list[str]:
    """渲染条目块：一行元数据 + 原文行 + 译文行。

    元数据行只写导入时真正会校验的字段：`idx`/`off`/`inst` 用于检出错位，`tag` 用于校验
    一致性，`speaker` 供译者判断语气。其余一律不写——`file` 在文件头已有一份，`path` 是
    内部结构路径（报错信息里的 path 取自 IR），共享条目的别名数量译者既不需要知道也无法
    据此做任何操作。译文文件是编辑工作面，不是 IR 的第二份副本。
    """
    lines: list[str] = []
    for row in entries:
        idx, tag = row["idx"], row["tag"]
        head = (f"# idx={idx} off=0x{row['off']:X} inst=0x{row['inst']:X} "
                f"tag={tag}")
        if row.get("speaker"):
            head += f" speaker={escape_line(str(row['speaker']))}"
        lines.append(head)
        lines.append(f"{SRC_MARK}{idx}{SRC_MARK}{tag}{SRC_MARK}"
                     f"{escape_line(row['source'])}")
        lines.append(f"{DST_MARK}{idx}{DST_MARK}{tag}{DST_MARK}"
                     f"{escape_line(row['target'])}")
        lines.append("")
    return lines


def _banner(target_encoding: str, ir_version: str) -> list[str]:
    return [
        f"# dsat_version=1.1.0 tool=psbscn ir_version={ir_version}",
        f"# target_encoding={target_encoding} dsat_encoding=utf-8",
        "# 只能修改 ● 行。请勿改动 #、### 与 ○ 行。",
        "# 控制字节以 {{XX}} 占位符形式出现，必须原样、按顺序完整保留。",
        "",
    ]


def render_dsat(entries: Iterable[dict], *, sample: str, source_sha256: str,
                source_encoding: str, target_encoding: str,
                ir_version: str) -> str:
    """单文件译文。

    文件头只留导入时会用到的字段：`sample` 与 `source_sha256` 是防止用旧译文覆盖新
    dump 的依据，两个编码字段决定长度校验。`dsat_encoding` 恒为 utf-8，无需写出。
    """
    lines = [
        f"# psbscn v{ir_version} sample={sample}",
        f"# source_sha256={source_sha256}",
        f"# source_encoding={source_encoding} target_encoding={target_encoding}",
        "# 只改 ● 行；# 行与 ○ 行是校验依据，改了会导入失败。",
        "# {{XX}} 是控制字节，必须原样、按顺序保留。",
        "",
    ]
    lines += _render_units(entries)
    return "\n".join(lines)


def render_merged_dsat(sections: Iterable[tuple[str, str, str, list[dict]]], *,
                       target_encoding: str, ir_version: str) -> str:
    """把多个源文件的文本条目渲染成一份带分节的 DSAT。

    `sections` 的每项是 `(文件名, sha256, 源编码, 条目行)`。
    """
    lines = _banner(target_encoding, ir_version)
    for name, sha256, source_encoding, rows in sections:
        rows = list(rows)
        lines.append(f"### file={name} sha256={sha256} "
                     f"source_encoding={source_encoding} units={len(rows)}")
        lines.append("")
        lines += _render_units(rows)
    return "\n".join(lines)


def _split_marked(line: str, mark: str, lineno: int) -> tuple[int, str, str]:
    if not line.startswith(mark):
        raise TextImportError(
            f"第 {lineno} 行：应以 {mark!r} 开头，实际为 {line[:40]!r}")
    parts = line.split(mark, 3)
    if len(parts) != 4:
        raise TextImportError(
            f"第 {lineno} 行：应有 3 个 {mark!r} 分隔符，实际找到 {len(parts) - 1} 个")
    _, idx_raw, tag, body = parts
    if not idx_raw.isdigit():
        raise TextImportError(f"第 {lineno} 行：idx {idx_raw!r} 不是整数")
    return int(idx_raw), tag, body


def parse_dsat(text: str) -> tuple[dict[str, str], list[DsatUnit]]:
    """把 DSAT 文档解析为元数据 banner 与单元列表（忽略分节）。"""
    meta, sections, flat = _parse(text)
    return meta, flat


def parse_merged_dsat(text: str) -> tuple[dict[str, str], list[DsatSection]]:
    """解析带 `### file=...` 分节的合并 DSAT。

    没有任何分节头时，整份内容作为单节返回，`sha256` 取 banner 里的
    `source_sha256`（若有），从而兼容旧的单文件 DSAT。
    """
    meta, sections, flat = _parse(text)
    if sections:
        return meta, sections
    if not flat:
        return meta, []
    return meta, [DsatSection(
        file=meta.get("sample", flat[0].file),
        sha256=meta.get("source_sha256", ""),
        units=flat,
        source_encoding=meta.get("source_encoding", "utf-8"))]


def _parse(text: str) -> tuple[dict[str, str], list[DsatSection], list[DsatUnit]]:
    meta: dict[str, str] = {}
    sections: list[DsatSection] = []
    flat: list[DsatUnit] = []
    current: DsatSection | None = None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("###"):
            section = SECTION_RE.match(line.strip())
            if section is None:
                raise TextImportError(
                    f"第 {i + 1} 行：分节头格式错误，应为 "
                    "'### file=... sha256=...'，实际为 " + repr(line[:70]))
            current = DsatSection(
                file=section["file"], sha256=section["sha256"], units=[],
                source_encoding=section["source_encoding"] or "utf-8")
            sections.append(current)
            i += 1
            continue
        if line.startswith("#"):
            match = HEADER_RE.match(line.strip())
            if match is None:
                for token in line[1:].strip().split():
                    if "=" in token:
                        key, _, value = token.partition("=")
                        meta.setdefault(key, value)
                i += 1
                continue
            if i + 2 >= n:
                raise TextImportError(
                    f"第 {i + 1} 行：单元 idx={match['idx']} 缺少原文/译文行")
            src_idx, src_tag, src_body = _split_marked(lines[i + 1], SRC_MARK, i + 2)
            dst_idx, dst_tag, dst_body = _split_marked(lines[i + 2], DST_MARK, i + 3)
            head_idx, head_tag = int(match["idx"]), match["tag"]
            if not (head_idx == src_idx == dst_idx):
                raise TextImportError(
                    f"第 {i + 1} 行：三行的 idx 不一致"
                    f"（元数据={head_idx} 原文={src_idx} 译文={dst_idx}）")
            if not (head_tag == src_tag == dst_tag):
                raise TextImportError(
                    f"第 {i + 1} 行：三行的 tag 不一致"
                    f"（元数据={head_tag} 原文={src_tag} 译文={dst_tag}）")
            # 新格式不再逐条写 file=：单文件译文里它必然等于文件头的 sample，逐条重复
            # 只是噪声。缺省时按所在分节/文件头补齐，保持后续的一致性校验不变。
            unit_file = match["file"] or (current.file if current is not None
                                          else meta.get("sample", ""))
            unit = DsatUnit(
                idx=head_idx, file=unit_file, off=int(match["off"], 16),
                inst=int(match["inst"], 16), tag=head_tag,
                source=unescape_line(src_body), target=unescape_line(dst_body),
                path=match["path"] or "",
                speaker=unescape_line(match["speaker"]) if match["speaker"] else None,
            )
            flat.append(unit)
            if current is not None:
                if unit.file != current.file:
                    raise TextImportError(
                        f"第 {i + 1} 行：条目的 file={unit.file!r} 与所在分节 "
                        f"{current.file!r} 不一致")
                current.units.append(unit)
            i += 3
            continue
        raise TextImportError(
            f"第 {i + 1} 行：单元之外出现了意外内容：{line[:60]!r}")
    return meta, sections, flat

