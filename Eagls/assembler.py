"""双行文本 → IR → 重建 SCPACK.idx / SCPACK.pak。

用法：
    python assembler.py <output 目录>                    拖 texts/ 或 output/ 亦可
    python assembler.py <output> --script-dir <Script 目录> --strategy auto

策略由 probe 协商（§6.2），不是用户偏好：零编辑选 identity，等长选 in_place，
变长选 pointer-rewrite。probe 通过而 run 失败时**不自动降级**，写 checkpoint 后停止。
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import profile_scpack as P

DIALECT = P.DIALECT
_SPEC = DIALECT["dsat"]
_ORIG = _SPEC["orig_mark"]
_TRAN = _SPEC["tran_mark"]
_PAT = _SPEC["patterns"]
_ORIG_RE = re.compile(rf"^{_ORIG}(?P<idx>\d+){_ORIG}(?P<tag>[a-z_]+){_ORIG}(?P<text>.*)$")
_TRAN_RE = re.compile(rf"^{_TRAN}(?P<idx>\d+){_TRAN}(?P<tag>[a-z_]+){_TRAN}(?P<text>.*)$")
_META_RE = re.compile(_PAT["meta_field"])
_HEADER_RE = re.compile(_PAT["header_line1"])
_SHARD_RE = re.compile(_PAT["shard"])
_PH_RE = re.compile(_PAT["placeholder"])
_PH_LOOSE_RE = re.compile(_PAT["placeholder_loose"])
_PREVIEW = _SPEC["diagnostic_preview_chars"]


class ImportReject(Exception):
    def __init__(self, code: str, detail: str, **ctx: Any) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.ctx = ctx


# ---------------------------------------------------------------------------
# 导入校验（§4.9 的 13 条，按序全过才生成 Patched IR）
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ImportResult:
    edits: dict[int, str] = field(default_factory=dict)
    seen: set[int] = field(default_factory=set)
    changed: int = 0
    files: int = 0
    overflow: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[Any] = field(default_factory=list)


def _parse_header(lines: list[str], path: Path) -> dict[str, Any]:
    if len(lines) < 4:
        raise ImportReject("HEADER_SHORT", f"{path.name} 不足 4 行文件头")
    match = _HEADER_RE.match(lines[0])
    if not match:
        raise ImportReject("HEADER_LINE1", f"{path.name} 第 1 行不是 '# TEXT/N …'")
    header: dict[str, Any] = dict(_META_RE.findall(match.group("rest")))
    for required in ("ir", "tool", "src_sha256"):
        if required not in header:
            raise ImportReject("HEADER_FIELD", f"{path.name} 文件头缺 {required}=")
    if not lines[1].startswith("# encoding"):
        raise ImportReject("HEADER_LINE2", f"{path.name} 第 2 行必须是 '# encoding …'")
    header["encoding"] = dict(_META_RE.findall(lines[1]))
    for required in ("source", "target", "file"):
        if required not in header["encoding"]:
            raise ImportReject("HEADER_FIELD", f"{path.name} encoding 行缺 {required}=")
    if not lines[2].startswith("# scope"):
        raise ImportReject("HEADER_LINE3", f"{path.name} 第 3 行必须是 '# scope …'")
    scope = dict(_META_RE.findall(lines[2]))
    part = _SHARD_RE.fullmatch(scope.get("part", ""))
    if not part:
        raise ImportReject("SCOPE_PART", f"{path.name} part 需为 K/N")
    scope["part_index"], scope["part_total"] = int(part.group(1)), int(part.group(2))
    header["scope"] = scope
    if not lines[3].startswith("# tags"):
        raise ImportReject("HEADER_LINE4", f"{path.name} 第 4 行必须是 '# tags …'")
    header["entry"] = {}
    for line in lines[4:6]:
        if line.startswith("# entry"):
            header["entry"] = dict(_META_RE.findall(line))
    return header


def import_texts(doc: P.ArchiveDoc, texts_dir: Path, idx_sha: str,
                 target_encoding: str | None = None) -> ImportResult:
    by_idx = {text.idx: text for text in doc.text_entries}
    by_name = {entry.name: entry for entry in doc.entries}
    result = ImportResult()
    files = sorted(texts_dir.rglob("*.txt"))
    if not files:
        raise ImportReject("NO_TEXTS", f"{texts_dir} 下没有 .txt")

    shards: dict[int, set[int]] = {}
    for path in files:
        header = _parse_header(
            path.read_text(encoding="utf-8-sig").splitlines(), path)
        # 1 归档哈希匹配
        if header["src_sha256"].lower() != idx_sha.lower():
            raise ImportReject("SRC_HASH_MISMATCH",
                               f"{path.name} 文件头 src_sha256 与当前 IR 不符；"
                               f"这份文件可能对应旧的 dump", file=path.name)
        # 2 版本兼容
        if header["ir"] != P.IR_VERSION:
            raise ImportReject("IR_VERSION",
                               f"{path.name} IR 版本 {header['ir']} != {P.IR_VERSION}",
                               file=path.name)
        entry_meta = header["entry"]
        name = entry_meta.get("name")
        if name is None or name not in by_name:
            raise ImportReject("ENTRY_UNKNOWN",
                               f"{path.name} 文件头未声明有效的 entry name=",
                               file=path.name)
        expected = P.sha256_bytes(by_name[name].raw)
        if entry_meta.get("sha256", "").lower() != expected.lower():
            raise ImportReject("ENTRY_HASH_MISMATCH",
                               f"{path.name} 声明的条目 {name} 哈希与当前 IR 不符",
                               file=path.name)
        codec = target_encoding or header["encoding"]["target"]
        _check_file(path, doc, by_idx, codec, result)
        scope = header["scope"]
        shards.setdefault(scope["part_total"], set()).add(scope["part_index"])
        result.files += 1

    # 3 分片完整
    for total, got in shards.items():
        if total > 1 and len(got) != total:
            raise ImportReject("SHARD_INCOMPLETE",
                               f"分片不完整：共 {total} 片，缺 "
                               f"{sorted(set(range(1, total + 1)) - got)}")
    missing = set(by_idx) - result.seen
    if missing:
        raise ImportReject("INCOMPLETE",
                           f"缺少 {len(missing)} 条；第一条缺失 idx={min(missing)}")
    return result


def _check_file(path: Path, doc: P.ArchiveDoc, by_idx: dict[int, P.TextEntry],
                codec: str, result: ImportResult) -> None:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    pending: dict[str, str] = {}
    pending_line = 0
    position = 4
    while position < len(lines):
        line = lines[position]
        if not line.strip():
            position += 1
            continue
        if line.startswith("#"):
            pending = dict(_META_RE.findall(line))
            pending_line = position + 1
            position += 1
            continue
        orig = _ORIG_RE.match(line)
        if not orig:
            # 6 分隔符未混用
            if _TRAN_RE.match(line):
                raise ImportReject("ORPHAN_TRANSLATION",
                                   f"{path.name}:{position + 1} 是译文行但缺配对原文行")
            raise ImportReject("LINE_FORMAT",
                               f"{path.name}:{position + 1} 格式不合法：{line[:60]!r}")
        if position + 1 >= len(lines):
            raise ImportReject("MISSING_TRANSLATION",
                               f"{path.name} idx={orig.group('idx')} 缺译文行")
        tran = _TRAN_RE.match(lines[position + 1])
        if not tran:
            if _ORIG_RE.match(lines[position + 1]):
                raise ImportReject("SEPARATOR_MIXED",
                                   f"{path.name}:{position + 2} 本该是译文行却用了原文标记")
            raise ImportReject("LINE_FORMAT",
                               f"{path.name}:{position + 2} 不是合法译文行")
        # 5 三行 idx/tag 一致
        if orig.group("idx") != tran.group("idx"):
            raise ImportReject("IDX_MISMATCH",
                               f"{path.name}:{position + 1}-{position + 2} 编号不一致")
        if len(orig.group("idx")) != len(tran.group("idx")):
            raise ImportReject("IDX_WIDTH", f"{path.name} idx 宽度不一致（须定宽）")
        if orig.group("tag") != tran.group("tag"):
            raise ImportReject("TAG_MISMATCH",
                               f"{path.name} idx={orig.group('idx')} 标签不一致")
        idx = int(orig.group("idx"))
        # 4 idx 唯一且存在
        if idx in result.seen:
            raise ImportReject("IDX_DUPLICATE", f"idx={idx} 重复出现", idx=idx)
        entry = by_idx.get(idx)
        if entry is None:
            raise ImportReject("IDX_UNKNOWN", f"idx={idx} 不存在于 IR", idx=idx)
        if orig.group("tag") not in _SPEC["tags"]:
            raise ImportReject("TAG_UNKNOWN", f"idx={idx} tag 不在闭集", idx=idx)
        result.seen.add(idx)

        # 12 注释与条目同步（捕获整块交换）
        if pending:
            meta_idx = pending.get("idx")
            if meta_idx is not None and int(meta_idx) != idx:
                raise ImportReject("META_DESYNC",
                                   f"{path.name}:{pending_line} 注释声明 idx={int(meta_idx)}，"
                                   f"紧随条目是 idx={idx}；疑似整块交换", idx=idx)
            meta_tag = pending.get("tag")
            if meta_tag is not None and meta_tag != orig.group("tag"):
                raise ImportReject("META_DESYNC", f"idx={idx} 注释 tag 与行内不一致",
                                   idx=idx)
        pending = {}

        # 7 原文行是校验锚，逐字符比对
        if orig.group("text") != entry.source:
            raise ImportReject(
                "SOURCE_ANCHOR",
                f"{path.name} idx={idx} 原文行与 IR 不一致（{_diagnose(entry.source, orig.group('text'))}）\n"
                f"    IR  : {entry.source[:_PREVIEW]!r}\n"
                f"    文件: {orig.group('text')[:_PREVIEW]!r}", idx=idx)

        target = tran.group("text")
        # 游标必须在此处推进：后面每个分支都可能 continue，
        # 把 += 2 放在循环末尾会让「未翻译条目」原地打转。
        position += 2
        # 13 译文行非空（预填原文后，空 = 误删）
        if not target:
            raise ImportReject("EMPTY_TRANSLATION",
                               f"{path.name} idx={idx} 译文行为空；预填原文后空行只能是误删，"
                               f"不是「未翻译」（§4.6）", idx=idx)
        if target == entry.source:
            continue
        # 8 frozen 未被改动
        if entry.translate_policy == "frozen":
            raise ImportReject("FROZEN_MODIFIED",
                               f"{path.name} idx={idx} 标记 frozen 但译文被改动"
                               f"（{entry.tag}/{entry.tag_subtype}）；"
                               f"原样保留，或改 IR 中的策略", idx=idx)
        # 11 占位符集合完整
        _check_placeholders(idx, entry.source, target)
        # 9 目标编码可表示 + 10 长度符合回封模式
        try:
            nbytes = P.encoded_length(target, codec)
        except UnicodeEncodeError as exc:
            bad = exc.object[exc.start]
            candidates = [c for c in ("utf-8", "gbk", "big5", "cp932", "cp949")
                          if c != codec and _can_encode(bad, c)]
            raise ImportReject("ENCODING_UNREPRESENTABLE",
                               f"{path.name} idx={idx} 译文编码 {codec} 无法表示 {bad!r}"
                               + (f"，换 {', '.join(candidates)} 试试" if candidates else ""),
                               idx=idx) from exc
        if entry.translate_policy == "length-locked" and nbytes != entry.raw_len:
            raise ImportReject("LENGTH_LOCKED",
                               f"{path.name} idx={idx} 要求等长：原 {entry.raw_len} 字节，"
                               f"译文 {nbytes} 字节", idx=idx)
        # 超长不是错误，只是 in_place 不适用的信号（§6.0.1）。记下来交给 probe，
        # 不在此处拒绝 —— 要求译者压缩文本是错的。
        if entry.slot_capacity is not None and nbytes > entry.slot_capacity:
            result.overflow.append({"idx": idx, "capacity": entry.slot_capacity,
                                    "needed": nbytes, "tag": entry.tag})
        result.edits[idx] = target
        result.changed += 1
    return None


def _can_encode(char: str, codec: str) -> bool:
    try:
        char.encode(codec)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _diagnose(expected: str, actual: str) -> str:
    import unicodedata
    if unicodedata.normalize("NFKC", expected) == unicodedata.normalize("NFKC", actual):
        return "疑似编辑器做了全角/半角替换"
    if expected.rstrip() == actual.rstrip():
        return "疑似行尾空白被剥离"
    if expected.replace(" ", "") == actual.replace(" ", ""):
        return "疑似空格增删"
    return "内容不同，可能是错位或误改原文"


def _check_placeholders(idx: int, source: str, target: str) -> None:
    loose, strict = _PH_LOOSE_RE, _PH_RE
    for match in loose.finditer(target):
        if not strict.fullmatch(match.group(0)):
            raise ImportReject("PLACEHOLDER_BROKEN",
                               f"idx={idx} 占位符格式非法：{match.group(0)!r}"
                               f"（须为大写 {{{{XX}}}}）", idx=idx)
    before = [m.group(0) for m in strict.finditer(source)]
    after = [m.group(0) for m in strict.finditer(target)]
    if sorted(before) != sorted(after):
        raise ImportReject("PLACEHOLDER_BROKEN",
                           f"idx={idx} 占位符集合不一致：原文 {before}，译文 {after}",
                           idx=idx)


# ---------------------------------------------------------------------------
# 回封策略：probe / run 协议（§6.1）。probe 只读、无副作用。
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ProbeVerdict:
    strategy_id: str
    applicable: bool
    reason_code: str
    reason_detail: str = ""
    blocking_refs: tuple[str, ...] = ()
    estimated_deltas: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        data = {"strategy_id": self.strategy_id, "applicable": self.applicable,
                "reason_code": self.reason_code}
        if self.reason_detail:
            data["reason_detail"] = self.reason_detail
        if self.blocking_refs:
            data["blocking_refs"] = list(self.blocking_refs)
        if self.estimated_deltas:
            data["estimated_deltas"] = self.estimated_deltas
        return data


# 能力从小到大。auto 选**能力最小**的可用策略（§6.2）：能不改引用就不改。
_ORDER = ("identity", "in_place", "pointer-rewrite", "full-layout")
_REQUIRED_TIER = {"identity": "T1", "in_place": "T2",
                  "pointer-rewrite": "T2", "full-layout": "T3"}


def probe_all(doc: P.ArchiveDoc, imported: ImportResult, declared_tier: str
              ) -> list[ProbeVerdict]:
    """对全部策略求裁决。此阶段不执行任何 run（§6.2 第 1 条）。"""
    verdicts: list[ProbeVerdict] = []
    tier_rank = {"T0": 0, "T1": 1, "T2": 2, "T3": 3, "T4": 4}
    have = tier_rank[declared_tier]
    changed = imported.changed
    delta = _estimate_delta(doc, imported)

    for strategy in _ORDER:
        need = _REQUIRED_TIER[strategy]
        if have < tier_rank[need]:
            verdicts.append(ProbeVerdict(
                strategy, False, "TIER_TOO_LOW",
                f"{strategy} 需要 {need}，当前申报 {declared_tier}",
                blocking_refs=("R_SCRIPT_BODY",)))
            continue
        if strategy == "identity":
            verdicts.append(ProbeVerdict(
                strategy, changed == 0,
                "OK" if changed == 0 else "LENGTH_OVERFLOW",
                "" if changed == 0 else f"有 {changed} 条译文与原文不同，identity 不适用",
                blocking_refs=tuple(f"idx={i}" for i in
                                    sorted(imported.edits)[:5])))
        elif strategy == "in_place":
            # 本方言的可编辑槽位没有独立长度字段，容量只能由「下一条目起始偏移」
            # 推断，而正文里条目之间并非紧密排列（有 \r\n 分隔与括号结构），
            # 因此容量不可证明 → CAPACITY_UNKNOWN（§6.0.2 第三种来源不可用）。
            unknown = [e for e in doc.text_entries
                       if e.idx in imported.edits and e.slot_capacity is None]
            if unknown:
                verdicts.append(ProbeVerdict(
                    strategy, False, "CAPACITY_UNKNOWN",
                    f"{len(unknown)} 条被编辑条目的槽容量无法从结构证明"
                    f"（无长度字段，且条目非紧密排列）；不得用相邻偏移相减推断",
                    blocking_refs=tuple(f"idx={e.idx}" for e in unknown[:5])))
            elif imported.overflow:
                verdicts.append(ProbeVerdict(
                    strategy, False, "LENGTH_OVERFLOW",
                    f"{len(imported.overflow)} 条译文超出原槽容量",
                    blocking_refs=tuple(f"idx={o['idx']}" for o in
                                        imported.overflow[:5])))
            else:
                verdicts.append(ProbeVerdict(strategy, changed > 0, "OK"))
        elif strategy == "pointer-rewrite":
            missing = _unresolved_sites(doc)
            if missing:
                verdicts.append(ProbeVerdict(
                    strategy, False, "UNRESOLVED_JOIN_SITE",
                    f"{len(missing)} 个引用站点未解析，无法安全改变文本长度",
                    blocking_refs=tuple(missing[:5])))
            else:
                verdicts.append(ProbeVerdict(strategy, True, "OK",
                                             estimated_deltas=delta))
        else:  # full-layout
            verdicts.append(ProbeVerdict(
                strategy, False, "TIER_TOO_LOW",
                "条目增删与结构重排需要 T3（指令流已证明）；本方言申报 T2",
                blocking_refs=("R_SCRIPT_BODY",)))
    return verdicts


def _estimate_delta(doc: P.ArchiveDoc, imported: ImportResult) -> dict[str, Any]:
    by_idx = {e.idx: e for e in doc.text_entries}
    ranges = 0
    total = 0
    for idx, target in imported.edits.items():
        entry = by_idx[idx]
        ranges += 1
        total += (P.encoded_length(target, doc.encoding)
                  - P.encoded_length(entry.source, doc.encoding))
    return {"ranges": ranges, "bytes": total}


def _unresolved_sites(doc: P.ArchiveDoc) -> list[str]:
    """站点集合完整性：每个条目必须有 idx 记录站点，每个标签必须有表内站点。"""
    missing: list[str] = []
    sited = {site["target_object_id"] for site in doc.join_sites()
             if site["key_kind"] == "entry_offset"}
    for entry in doc.entries:
        if entry.name not in sited:
            missing.append(f"entry={entry.name}")
        for label in entry.labels:
            if label.offset_site <= 0:
                missing.append(f"label={label.name!r}@{entry.name}")
    return missing


def select_strategy(verdicts: list[ProbeVerdict], explicit: str | None
                    ) -> ProbeVerdict:
    """auto = 能力协商，不是「试到不报错」。显式指定不适用的策略是错误，不是覆盖。"""
    by_id = {v.strategy_id: v for v in verdicts}
    if explicit and explicit != "auto":
        chosen = by_id.get(explicit)
        if chosen is None:
            raise ImportReject("STRATEGY_UNKNOWN", f"未知策略 {explicit}")
        if not chosen.applicable:
            raise ImportReject("STRATEGY_NOT_APPLICABLE",
                               f"显式指定的 {explicit} 不适用："
                               f"{chosen.reason_code} {chosen.reason_detail}")
        return chosen
    for strategy in _ORDER:
        verdict = by_id.get(strategy)
        if verdict is not None and verdict.applicable:
            return verdict
    raise ImportReject("NO_APPLICABLE_STRATEGY",
                       "没有可用策略；全部裁决见 repack_verdicts.json")


# ---------------------------------------------------------------------------
# run：写 tmp → 重新解析验证 → 原子改名到 rebuilt/（§6.5）
# ---------------------------------------------------------------------------
def run_repack(doc: P.ArchiveDoc, imported: ImportResult, verdict: ProbeVerdict,
               out_dir: Path, progress: Any = None) -> dict[str, Any]:
    report = lambda frac, note: progress(frac, note) if progress else None
    tmp = out_dir / "tmp"
    rebuilt = out_dir / "rebuilt"
    reports = out_dir / "reports"
    for path in (tmp, tmp / "failed", rebuilt, reports):
        path.mkdir(parents=True, exist_ok=True)

    report(0.1, "把译文写回正文")
    bodies: dict[int, str] = {}
    for entry in doc.entries:
        edits = {text.idx: imported.edits[text.idx] for text in entry.entries
                 if text.idx in imported.edits}
        if edits:
            bodies[entry.src_id] = P.apply_edits(entry, edits, doc.encoding)

    report(0.35, "重建归档并按站点回填引用")
    idx_new, pak_new, reloc, mapping = P.rebuild_archive(doc, bodies)

    report(0.6, "写入临时文件")
    idx_tmp = tmp / doc.idx_path.name
    pak_tmp = tmp / doc.pak_path.name
    _write_durable(idx_tmp, idx_new)
    _write_durable(pak_tmp, pak_new)
    # 明文 idx 与加密 idx 并存分开命名（§6.5）。站点门禁只能在明文层比对：
    # idx 的 XOR 密钥流由 rand() 驱动，同一个偏移值加密后字节不同，
    # 在密文上比对会把「值未改」误判成 SITE_VALUE_DESYNC。
    plain = out_dir / "plain"
    plain.mkdir(parents=True, exist_ok=True)
    idx_plain_new = bytes(P.xor_idx(bytearray(idx_new), doc.idx_key.encode()))
    _write_durable(plain / f"{doc.idx_path.name}.plain", idx_plain_new)

    report(0.7, "重新解析输出并验证")
    checks = verify_output(doc, imported, idx_tmp.parent, idx_new, pak_new, bodies)
    sites = _site_records(doc, mapping)
    _jsonl(reports / "relocation_log.jsonl", reloc)
    _json(reports / "repack_verdicts.json", {
        "selected_strategy": verdict.strategy_id,
        "selection_rule": "minimum-capability-among-applicable",
        "changed_entries": imported.changed,
        "verdicts": [v.to_json() for v in imported.verdicts],
    })
    _jsonl(reports / "new_join_sites.jsonl", sites)

    if not checks["ok"]:
        # 验证失败的产物留在 tmp/failed/ 供诊断，不进 rebuilt/（§6.5）。
        for src in (idx_tmp, pak_tmp):
            src.replace(tmp / "failed" / src.name)
        _json(reports / "verify_repack.json", checks)
        raise ImportReject("REPACK_VERIFY_FAILED",
                           "回封后验证未通过；产物留在 tmp/failed/，"
                           f"失败项：{[c for c, ok in checks['checks'].items() if not ok]}")

    report(0.9, "原子改名到 rebuilt/")
    idx_tmp.replace(rebuilt / doc.idx_path.name)
    pak_tmp.replace(rebuilt / doc.pak_path.name)
    checks["output"] = {"idx": str(rebuilt / doc.idx_path.name),
                       "pak": str(rebuilt / doc.pak_path.name)}
    _json(reports / "verify_repack.json", checks)
    report(1.0, "完成")
    return checks


def _write_durable(path: Path, data: bytes) -> None:
    """写 → flush → fsync，确保后续重新解析读到的是完整数据（§6.5）。"""
    import os
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _site_records(doc: P.ArchiveDoc, mapping: dict[int, int]) -> list[dict[str, Any]]:
    """给 check_sites.py 用的站点记录，带 new_key_value 声明映射。"""
    rows = []
    for site in doc.join_sites():
        row = dict(site)
        if site["key_kind"] == "entry_offset":
            new = mapping.get(site["key_value"])
            if new is not None:
                row["new_key_value"] = new
        rows.append(row)
    return rows


def verify_output(doc: P.ArchiveDoc, imported: ImportResult, tmp_dir: Path,
                  idx_new: bytes, pak_new: bytes,
                  bodies: dict[int, str]) -> dict[str, Any]:
    """变长回封后必须重新验证的性质（§6.0.3）。

    判定方向与零编辑相反：有编辑时哈希**必须**改变 —— 未变即表示编辑没生效。
    """
    checks: dict[str, bool] = {}
    details: dict[str, Any] = {}
    edited = imported.changed > 0

    # 1 输出可被自身完整重新解析（不止检查魔数）
    try:
        reparsed = P.parse_archive(tmp_dir, doc.encoding, doc.alis)
        checks["reparsable"] = True
    except P.ParseError as exc:
        checks["reparsable"] = False
        details["reparse_error"] = f"{exc.code}: {exc.detail}"
        return {"ok": False, "checks": checks, "details": details}

    # 2 重新解析后覆盖仍为 1.0，无缺口无重叠
    checks["coverage_intact"] = all(
        _covers(reparsed, target) for target in ("idx", "pak"))

    # 3 哈希语义：有编辑必须变，零编辑必须不变（§6.0）
    idx_same = idx_new == doc.idx_raw
    pak_same = pak_new == doc.pak_raw
    checks["hash_semantics"] = (not (idx_same and pak_same)) if edited else \
        (idx_same and pak_same)
    details["hash"] = {"idx_identical": idx_same, "pak_identical": pak_same,
                       "edited_entries": imported.changed}

    # 4 站点集合同构：数量相同，site_offset 一一对应，key_kind 相同
    old_sites = doc.join_sites()
    new_sites = reparsed.join_sites()
    checks["sites_isomorphic"] = (
        len(old_sites) == len(new_sites)
        and [s["site_offset"] for s in old_sites] == [s["site_offset"] for s in new_sites]
        and [s["key_kind"] for s in old_sites] == [s["key_kind"] for s in new_sites])
    details["sites"] = {"old": len(old_sites), "new": len(new_sites)}

    # 5 每处已编辑条目的新内容确实出现在输出中
    #   「文件可解析」不能证明「译文已写入」，必须反查（§6.0.3 倒数第三项）
    by_src = {entry.src_id: entry for entry in reparsed.entries}
    missing: list[int] = []
    for entry in doc.entries:
        for text in entry.entries:
            target = imported.edits.get(text.idx)
            if target is None or target == text.source:
                continue
            plain = P.from_placeholders(target, doc.encoding).decode(doc.encoding)
            if plain not in by_src[entry.src_id].body:
                missing.append(text.idx)
    checks["edits_present"] = not missing
    details["missing_edits"] = missing[:20]

    # 6 未编辑条目的字节内容逐条不变
    untouched: list[str] = []
    for entry in doc.entries:
        if entry.src_id in bodies:
            continue
        if by_src[entry.src_id].body_raw != entry.body_raw:
            untouched.append(entry.name)
    checks["untouched_entries_identical"] = not untouched
    details["changed_untouched"] = untouched[:20]

    # 7 总长度差值等于各条目变化量之和（差值可解释，无意外增减）
    expected = sum(len(P.from_placeholders(bodies[e.src_id], doc.encoding))
                   - len(e.body_raw) for e in doc.entries if e.src_id in bodies)
    actual = len(pak_new) - len(doc.pak_raw)
    checks["length_delta_explained"] = expected == actual
    details["length_delta"] = {"expected": expected, "actual": actual}

    # 8 标签偏移自洽：每个标签的 offset 字段确实指向正文里的 `$名字`
    broken: list[str] = []
    for entry in reparsed.entries:
        for label in entry.labels:
            if not entry.body_raw.startswith(b"$" + label.name, label.offset):
                broken.append(f"{entry.name}:{label.name!r}")
    checks["label_offsets_valid"] = not broken
    details["broken_labels"] = broken[:20]

    return {"ok": all(checks.values()), "checks": checks, "details": details,
            "changed_entries": imported.changed,
            "edited_files": sorted(by_src[i].name for i in bodies)}


def _covers(doc: P.ArchiveDoc, target: str) -> bool:
    source = doc.idx_raw if target == "idx" else doc.pak_raw
    cursor = 0
    for region in doc.regions(target):
        if region["start"] != cursor:
            return False
        cursor = region["end"]
    return cursor == len(source)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n"
                for r in rows), encoding="utf-8")


def _json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def _locate(target: Path) -> tuple[Path, Path]:
    """从拖入的路径推出 (output 目录, texts 目录)。拖 texts/ 或 output/ 都行。

    先 resolve：相对路径的 `.parent.parent` 会停在 `.`，让上层的目录推导失效。
    """
    target = target.resolve()
    if target.name == "texts" and target.is_dir():
        return target.parent, target
    if (target / "texts").is_dir():
        return target, target / "texts"
    if target.is_file() and target.parent.name == "texts":
        return target.parent.parent, target.parent
    raise ImportReject("LAYOUT_UNKNOWN",
                       f"在 {target} 下找不到 texts/；请拖入 output 目录或其中的 texts 目录")


def repack(out_dir: Path, script_dir: Path | None = None, *,
           strategy: str = "auto", target_encoding: str | None = None,
           progress: Any = None) -> dict[str, Any]:
    started = time.perf_counter()
    report = lambda frac, note: progress(frac, note) if progress else None
    texts_dir = out_dir / "texts"
    manifest = out_dir / "ir" / "manifest.jsonl"
    if not manifest.exists():
        raise ImportReject("IR_MISSING",
                           f"找不到 {manifest}；请先运行 disassembler.py")
    head = json.loads(manifest.read_text(encoding="utf-8").splitlines()[0])
    if script_dir is None:
        script_dir = _script_dir_from(out_dir, head)

    report(0.05, "重新解析原始归档")
    doc = P.parse_archive(script_dir, head.get("source_encoding"),
                          bool(head.get("alis")))
    # IR 是唯一真值：源必须与生成这份 IR 时逐字节相同，否则 idx 编号可能已错位。
    if P.sha256_bytes(doc.idx_raw) != head["sha256"]:
        raise ImportReject("SOURCE_CHANGED",
                           f"{doc.idx_path.name} 与生成 IR 时不一致；请重新反汇编")
    if P.sha256_bytes(doc.pak_raw) != head["pak_sha256"]:
        raise ImportReject("SOURCE_CHANGED",
                           f"{doc.pak_path.name} 与生成 IR 时不一致；请重新反汇编")

    report(0.2, "导入并校验双行文本")
    codec = target_encoding or head.get("target_encoding")
    imported = import_texts(doc, texts_dir, head["sha256"], codec)

    report(0.45, "协商回封策略")
    # tier 取参与文本改写的区域，不是整文件最低值（见 capability_tier 的说明）。
    imported.verdicts = probe_all(doc, imported, doc.capability_tier())
    _json(out_dir / "reports" / "repack_verdicts.json", {
        "selected_strategy": None,
        "selection_rule": "minimum-capability-among-applicable",
        "verdicts": [v.to_json() for v in imported.verdicts]})
    verdict = select_strategy(imported.verdicts, strategy)

    checks = run_repack(doc, imported, verdict, out_dir, progress)
    summary = {
        "ok": checks["ok"],
        "strategy": verdict.strategy_id,
        "changed_entries": imported.changed,
        "files_read": imported.files,
        "overflow_entries": len(imported.overflow),
        "length_delta": checks["details"].get("length_delta"),
        "edited_files": checks.get("edited_files", []),
        "output": checks.get("output"),
        "checks": checks["checks"],
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }
    _json(out_dir / "reports" / "import_check.json", summary)
    return summary


def _script_dir_from(out_dir: Path, head: dict[str, Any]) -> Path:
    """原始 Script 目录：先试 output 的父目录，再试同级 Script/。"""
    for candidate in (out_dir.parent, out_dir.parent / "Script",
                      out_dir.parent.parent / "Script"):
        if (candidate / head["name"]).is_file():
            return candidate
    raise ImportReject("SCRIPT_DIR_UNKNOWN",
                       f"找不到含 {head['name']} 的原始目录；请用 --script-dir 指定")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", type=Path, help="output 目录，或其中的 texts 目录")
    parser.add_argument("--script-dir", type=Path, default=None,
                        help="原始 Script 目录，缺省自动推导")
    parser.add_argument("--strategy", default="auto",
                        choices=("auto", *_ORDER),
                        help="回封策略，缺省 auto（能力协商，选能力最小的可用者）")
    parser.add_argument("--target-encoding", default=None, help="译文编码，缺省取 IR 声明")
    args = parser.parse_args(argv)

    def show(frac: float, note: str) -> None:
        sys.stderr.write(f"\r[{frac * 100:5.1f}%] {note:<40}")
        if frac >= 1.0:
            sys.stderr.write("\n")

    try:
        out_dir, _ = _locate(args.target)
        summary = repack(out_dir, args.script_dir, strategy=args.strategy,
                         target_encoding=args.target_encoding, progress=show)
    except ImportReject as exc:
        sys.stderr.write(f"\n导入被拒绝 {exc.code}: {exc.detail}\n")
        if exc.ctx:
            sys.stderr.write(f"  上下文: {exc.ctx}\n")
        return 1
    except P.ParseError as exc:
        sys.stderr.write(f"\n解析失败 {exc.code}: {exc.detail}\n")
        return 1

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
