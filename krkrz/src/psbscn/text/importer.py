"""DSAT 严格导入校验。

生成 ChangeSet 之前必须通过全部门禁：源哈希一致、idx 唯一、tag 一致、原文行未被
修改、译文可用目标编码表示，以及占位符集合与顺序完全一致。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.errors import PlaceholderError, TextImportError
from ..core.types import ChangeSet
from . import placeholders
from .dsat import DsatUnit, parse_dsat

@dataclass(slots=True)
class ImportCheck:
    """针对 IR 校验一个 DSAT 文件的结果。"""

    sample: str
    accepted: int = 0
    changed: int = 0
    unchanged: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_json(self) -> dict[str, Any]:
        return {
            "sample": self.sample, "ok": self.ok,
            "accepted": self.accepted, "changed": self.changed,
            "unchanged": self.unchanged,
            "errors": self.errors, "warnings": self.warnings,
        }

    def fail(self, idx: int | None, message: str, **extra: Any) -> None:
        self.errors.append({"idx": idx, "error": message, **extra})


def validate_dsat(dsat_text: str, ir_rows: list[dict[str, Any]], *,
                  source_sha256: str, sample: str,
                  target_encoding: str = "utf-8",
                  strict: bool = True) -> tuple[ImportCheck, ChangeSet]:
    """针对 IR 条目校验单文件 DSAT 文档，并构造 ChangeSet。"""
    check = ImportCheck(sample=sample)
    meta, units = parse_dsat(dsat_text)

    declared = meta.get("source_sha256")
    if declared and declared != source_sha256:
        check.fail(None, "DSAT 中的 source_sha256 与 IR 不一致",
                   expected=source_sha256, actual=declared)
        return check, ChangeSet(source_sha256=source_sha256)
    declared_sample = meta.get("sample")
    if declared_sample and declared_sample != sample:
        check.fail(None, "DSAT 中的样本名与 IR 不一致",
                   expected=sample, actual=declared_sample)

    return validate_units(units, ir_rows, check=check,
                          source_sha256=source_sha256,
                          target_encoding=target_encoding, strict=strict)


def validate_units(units: list[DsatUnit], ir_rows: list[dict[str, Any]], *,
                   check: ImportCheck, source_sha256: str,
                   target_encoding: str = "utf-8",
                   strict: bool = True) -> tuple[ImportCheck, ChangeSet]:
    """校验一组已解析的 DSAT 单元。合并 DSAT 的每一节走这里。"""
    by_idx = {row["idx"]: row for row in ir_rows}
    seen: set[int] = set()
    edits: list[dict[str, Any]] = []

    for unit in units:
        if unit.idx in seen:
            check.fail(unit.idx, "DSAT 中 idx 重复")
            continue
        seen.add(unit.idx)
        row = by_idx.get(unit.idx)
        if row is None:
            check.fail(unit.idx, "该 idx 在 IR 中不存在")
            continue
        if unit.tag != row["tag"]:
            check.fail(unit.idx, "tag 与 IR 不一致",
                       expected=row["tag"], actual=unit.tag)
            continue
        if unit.file != row["file"]:
            check.fail(unit.idx, "file 与 IR 不一致",
                       expected=row["file"], actual=unit.file)
            continue
        if unit.inst != row["inst"] or unit.off != row["off"]:
            check.fail(unit.idx, "off/inst 元数据被改动",
                       expected=f"off=0x{row['off']:X} inst=0x{row['inst']:X}",
                       actual=f"off=0x{unit.off:X} inst=0x{unit.inst:X}")
            continue
        if unit.source != row["source"]:
            check.fail(unit.idx, "原文行被修改；该行是只读的",
                       expected=row["source"], actual=unit.source)
            continue

        try:
            _check_placeholders(unit, row)
        except PlaceholderError as exc:
            check.fail(unit.idx, str(exc), path=row["path"])
            continue

        try:
            encoded = placeholders.decode(unit.target, target_encoding)
        except PlaceholderError as exc:
            check.fail(unit.idx, str(exc), path=row["path"])
            continue
        except UnicodeEncodeError as exc:
            check.fail(unit.idx,
                       f"译文无法用 {target_encoding} 表示："
                       f"{exc.reason}，位置 {exc.start}",
                       path=row["path"])
            continue
        if b"\x00" in encoded:
            check.fail(unit.idx, "译文含 NUL 字节，会使字符串提前终止",
                       path=row["path"])
            continue

        check.accepted += 1
        if unit.target == row["source"]:
            check.unchanged += 1
            continue
        check.changed += 1
        edits.append({
            "idx": unit.idx, "path": row["path"], "tag": unit.tag,
            "node_offset": row["node_offset"], "string_id": row["string_id"],
            "source": row["source"], "target": unit.target,
            "encoded_bytes": encoded.hex(),
            "encoded_length": len(encoded),
            "original_length": len(
                placeholders.decode(row["source"], row["encoding"])),
        })

    missing = sorted(set(by_idx) - seen)
    if missing:
        message = f"有 {len(missing)} 个 IR 文本条目未出现在 DSAT 中"
        if strict:
            check.fail(None, message, first_missing=missing[:12])
        else:
            check.warnings.append({"warning": message,
                                   "first_missing": missing[:12]})

    if not check.ok:
        return check, ChangeSet(source_sha256=source_sha256)
    return check, ChangeSet(source_sha256=source_sha256, edits=edits)


def _check_placeholders(unit: DsatUnit, row: dict[str, Any]) -> None:
    src_tokens = placeholders.extract(unit.source)
    dst_tokens = placeholders.extract(unit.target)
    if src_tokens != dst_tokens:
        raise PlaceholderError(
            "占位符序列被改动：应按顺序保留 "
            f"{src_tokens or '[]'}，实际为 {dst_tokens or '[]'}")
    count, byte_count, digest = placeholders.signature(unit.target)
    if (count, byte_count, digest) != (row["ph_count"], row["ph_bytes"],
                                       row["ph_hash"]):
        raise PlaceholderError(
            "占位符签名不匹配：应为 "
            f"数量={row['ph_count']} 字节={row['ph_bytes']}，实际为 "
            f"数量={count} 字节={byte_count}")
