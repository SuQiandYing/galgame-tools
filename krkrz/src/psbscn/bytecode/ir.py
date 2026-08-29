"""CanonicalIR：其他所有阶段唯一读取的机器真值。

`ir_compact.json` 是小体积索引，大数据流写入 JSONL。写好之后，后续阶段无需再从
源字节推导语义——但源字节始终可用于哈希复核。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from ..core.hashing import atomic_write_text, canonical_hash
from ..core.types import CaseDecision, SourceArtifact, TextEntry
from ..formats import psb_spec as S
from ..text import placeholders

IR_VERSION = "1.0.0"
TOOL_ID = "psbscn"


@dataclass(slots=True)
class ScnIR:
    """单个剧本文档的内存 IR。"""

    artifact: SourceArtifact
    decision: CaseDecision
    source_encoding: str
    target_encoding: str
    header: dict[str, Any]
    sections: list[dict[str, Any]]
    names: list[str]
    strings: list[str]
    text_entries: list[TextEntry]
    node_count: int
    shared_node_count: int
    string_refs: dict[int, list[int]] = field(default_factory=dict)
    tool_version: str = IR_VERSION
    notes: list[str] = field(default_factory=list)

    @property
    def sample_name(self) -> str:
        return Path(self.artifact.path).name

    def compact(self) -> dict[str, Any]:
        return {
            "schema_version": IR_VERSION,
            "tool": TOOL_ID,
            "sample": self.sample_name,
            "source": {
                "path": self.artifact.path,
                "byte_size": self.artifact.byte_size,
                "sha256": self.artifact.sha256,
                "md5": self.artifact.md5,
                "crc32": f"0x{self.artifact.crc32:08X}",
            },
            "encoding": {
                "source_encoding": self.source_encoding,
                "target_encoding": self.target_encoding,
                "asm_encoding": "utf-8",
                "dsat_encoding": "utf-8",
            },
            "decision": self.decision.to_json(),
            "header": self.header,
            "sections": self.sections,
            "counts": {
                "names": len(self.names),
                "strings": len(self.strings),
                "value_nodes": self.node_count,
                "shared_node_refs": self.shared_node_count,
                "text_entries": len(self.text_entries),
            },
            "semantic_identity": canonical_hash({
                "names": self.names,
                "strings": self.strings,
                "text_paths": [e.path for e in self.text_entries],
            }),
        }

    def text_entry_rows(self) -> Iterator[dict[str, Any]]:
        for e in self.text_entries:
            yield {
                "idx": e.idx, "file": e.file, "off": e.off, "inst": e.inst,
                "tag": e.tag, "source": e.source, "target": e.target,
                "encoding": e.encoding, "policy": e.policy,
                "node_offset": e.node_offset, "string_id": e.string_id,
                "path": e.path, "speaker": e.speaker,
                "speaker_confidence": e.speaker_confidence,
                "ph_count": e.ph_count, "ph_bytes": e.ph_bytes,
                "ph_hash": e.ph_hash, "ph_policy": e.ph_policy,
                **({"aliases": list(e.aliases)} if e.aliases else {}),
            }


def build_ir(doc, artifact: SourceArtifact, decision: CaseDecision, *,
             target_encoding: str = "utf-8") -> ScnIR:
    """把解析好的文档投影为规范化 IR。"""
    from .scenario import collect_text_sites

    sites = collect_text_sites(doc)
    sample = Path(artifact.path).name
    entries: list[TextEntry] = []
    # 值图会把相同子树去重，因此 texts[][7] 与 texts[][8] 这类位点常常指向**同一个**
    # 字符串节点。它们共享同一份存储，不可能被赋予不同译文，所以每个物理节点只出
    # 一条可编辑条目，其余路径记为别名。抽查 60 个文件有 117 处这种情况；若按位点
    # 逐条导出，用户改了两处不同译文时只有一处能生效，另一处会被静默丢弃。
    by_node: dict[int, TextEntry] = {}
    for site in sites:
        existing = by_node.get(site.node_offset)
        if existing is not None:
            existing.aliases = (*existing.aliases, site.path)
            continue
        raw = doc.strings.raw[site.string_id]
        source = placeholders.encode(raw, doc.strings.encoding)
        count, byte_count, digest = placeholders.signature(source)
        entry = TextEntry(
            idx=len(entries), file=sample,
            off=doc.strings.data_start + doc.strings.offsets.values[site.string_id],
            inst=site.node_offset, tag=site.tag, source=source, target=source,
            encoding=doc.strings.encoding, policy="strict-preserve",
            node_offset=site.node_offset, string_id=site.string_id,
            path=site.path, speaker=site.speaker,
            speaker_confidence=site.speaker_confidence,
            ph_count=count, ph_bytes=byte_count, ph_hash=digest,
        )
        by_node[site.node_offset] = entry
        entries.append(entry)

    string_refs: dict[int, list[int]] = {}
    for node in doc.graph.iter_nodes():
        if S.T_STRING_BASE <= node.type <= S.T_STRING_MAX:
            string_refs.setdefault(node.string_id(), []).append(node.offset)

    h = doc.header
    return ScnIR(
        artifact=artifact, decision=decision,
        source_encoding=doc.strings.encoding, target_encoding=target_encoding,
        header={
            "version": h.version, "header_encrypt": h.header_encrypt,
            "checksum": f"0x{h.checksum:08X}",
            "checksum_algorithm": "adler32(header[0x08:0x28])",
            "offsets": {k: f"0x{v:X}" for k, v in h.offsets().items()},
        },
        sections=[{"name": n, "start": s, "end": e, "size": e - s}
                  for n, s, e in doc.section_map()],
        names=[doc.names.text(i) for i in range(len(doc.names))],
        strings=[doc.strings.text(i) for i in range(len(doc.strings))],
        text_entries=entries,
        node_count=len(doc.graph),
        shared_node_count=doc.graph.shared_hits,
        string_refs=string_refs,
    )


def write_ir(ir: ScnIR, out_dir: str | Path) -> dict[str, str]:
    """持久化 IR：紧凑索引 + JSONL 流。返回已写入的路径。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    def dump_json(name: str, obj: Any) -> None:
        path = out / name
        atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
        written[name] = str(path)

    def dump_jsonl(name: str, rows: Any) -> None:
        path = out / name
        body = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        atomic_write_text(path, body)
        written[name] = str(path)

    dump_json("ir_compact.json", ir.compact())
    dump_json("source_manifest.json", {
        "sample": ir.sample_name,
        "path": ir.artifact.path,
        "byte_size": ir.artifact.byte_size,
        "sha256": ir.artifact.sha256,
        "md5": ir.artifact.md5,
        "crc32": f"0x{ir.artifact.crc32:08X}",
        "source_encoding": ir.source_encoding,
        "target_encoding": ir.target_encoding,
    })
    dump_jsonl("text_entries.jsonl", ir.text_entry_rows())
    dump_jsonl("name_map.jsonl", ({"key_id": i, "name": n}
                                  for i, n in enumerate(ir.names)))
    dump_jsonl("string_map.jsonl", (
        {"string_id": i, "value": v, "referenced_by": ir.string_refs.get(i, [])}
        for i, v in enumerate(ir.strings)))
    dump_jsonl("placeholder_map.jsonl", (
        {"idx": e.idx, "ph_count": e.ph_count, "ph_bytes": e.ph_bytes,
         "ph_hash": e.ph_hash, "ph_policy": e.ph_policy}
        for e in ir.text_entries if e.ph_count))
    return written


def read_ir_compact(ir_dir: str | Path) -> dict[str, Any]:
    path = Path(ir_dir) / "ir_compact.json"
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_entries(ir_dir: str | Path) -> list[dict[str, Any]]:
    path = Path(ir_dir) / "text_entries.jsonl"
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows
