"""布局规划与重序列化。

本格式中一次文本编辑的影响闭包::

    TextEntry -> 目标编码字节 + NUL 终止符
      -> 字符串数据区偏移
      -> 字符串偏移表元素宽度
      -> offset_strings_data / offset_chunk_* / offset_chunk_data
      -> 文件头校验和（偏移块的 adler32）

字符串的*同一性*同样重要：字符串节点存的是索引，而同一个字符串可能被多个节点
引用。编辑其中一处不能静默地把它的孪生位点一起改掉，因此当原 ID 还被未做同样
编辑的位点共享时，被编辑的位点会分配新的字符串 ID。

由于加长字符串只会让数据块变长（偏移是重算的，绝不原地打补丁），值图本身不会
被触及——除非加宽后的字符串 ID 已放不进该节点原有的索引宽度。这种情况通过加宽
节点并重新规划偏移来处理，这也是规划循环要迭代到布局稳定的原因。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.errors import InPlaceOverflowError, RepackError
from ..core.types import ChangeSet, LayoutPlan, RepackMode
from ..formats import psb_spec as S
from ..formats.psb_codec import write_packed_table
from ..formats.psb_graph import (emit_value_graph, node_encoded_size,
                                 plan_node_offsets)
from ..formats.psb_header import PsbHeader
from ..formats.psb_strings import plan_string_section
from ..text import placeholders


@dataclass(slots=True)
class RepackReport:
    """回封实际做了什么，用于审计追踪。"""

    mode: RepackMode
    output_size: int
    edits_applied: int = 0
    strings_added: int = 0
    strings_reused: int = 0
    nodes_widened: int = 0
    string_table_width_changed: bool = False
    relocation_log: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode, "output_size": self.output_size,
            "edits_applied": self.edits_applied,
            "strings_added": self.strings_added,
            "strings_reused": self.strings_reused,
            "nodes_widened": self.nodes_widened,
            "string_table_width_changed": self.string_table_width_changed,
            "notes": self.notes,
        }


def _string_node_width(node) -> int:
    return node.type - S.T_STRING_BASE + 1


def _needed_width(string_id: int) -> int:
    return max(1, S.min_uint_width(string_id))


def plan_and_repack(doc, changes: ChangeSet, *,
                    mode: RepackMode = "lossless-relocatable",
                    target_encoding: str = "utf-8",
                    ) -> tuple[bytes, LayoutPlan, RepackReport]:
    """应用 ChangeSet 并重序列化；零编辑时逐字节重现输入。"""
    report = RepackReport(mode=mode, output_size=0)
    plan = LayoutPlan(mode=mode)

    raw_strings = list(doc.strings.raw)
    # 每个字符串 ID 被哪些节点引用，以及其中哪些被编辑过。
    refs: dict[int, list[int]] = {}
    for node in doc.graph.iter_nodes():
        if S.T_STRING_BASE <= node.type <= S.T_STRING_MAX:
            refs.setdefault(node.string_id(), []).append(node.offset)

    node_string_override: dict[int, int] = {}
    edits_by_string: dict[int, dict[bytes, int]] = {}

    for edit in changes.edits:
        encoded = bytes.fromhex(edit["encoded_bytes"])
        old_id = edit["string_id"]
        node_offset = edit["node_offset"]
        original = raw_strings[old_id]

        if mode == "in_place" and len(encoded) > len(original):
            raise InPlaceOverflowError(
                f"idx={edit['idx']} path={edit['path']}：译文需要 "
                f"{len(encoded)} 字节，但原槽位只有 "
                f"{len(original)} 字节（{target_encoding}）；请改用 "
                "lossless-relocatable 以允许文件增长")

        if encoded == original:
            report.strings_reused += 1
            continue

        # 当完全相同的字节已存在，且该 ID 不被必须保留旧文本的未编辑位点占用时，
        # 复用现有 ID。
        pool = edits_by_string.setdefault(old_id, {})
        if encoded in pool:
            new_id = pool[encoded]
            report.strings_reused += 1
        else:
            sole_owner = len(refs.get(old_id, ())) == 1
            if sole_owner:
                raw_strings[old_id] = encoded
                new_id = old_id
                report.strings_reused += 1
            else:
                raw_strings.append(encoded)
                new_id = len(raw_strings) - 1
                report.strings_added += 1
            pool[encoded] = new_id

        if new_id != old_id:
            node_string_override[node_offset] = new_id
        report.relocation_log.append({
            "idx": edit["idx"], "path": edit["path"],
            "node_offset": node_offset,
            "old_string_id": old_id, "new_string_id": new_id,
            "old_length": len(original), "new_length": len(encoded),
            "delta": len(encoded) - len(original),
        })
        report.edits_applied += 1

    # 因索引加宽而需要覆盖节点载荷与尺寸。
    overrides: dict[int, bytes] = {}
    size_of: dict[int, int] = {}
    for node_offset, new_id in node_string_override.items():
        node = doc.graph.nodes[node_offset]
        width = max(_string_node_width(node), _needed_width(new_id))
        if width > 4:
            raise RepackError(
                f"字符串 ID {new_id} 需要 {width} 字节；PSB v3 的字符串节点"
                "最多只能容纳 4 字节")
        if width != _string_node_width(node):
            report.nodes_widened += 1
            plan.widened_nodes.append({
                "node_offset": node_offset,
                "old_width": _string_node_width(node), "new_width": width,
                "string_id": new_id,
            })
        overrides[node_offset] = (bytes([S.T_STRING_BASE + width - 1])
                                  + new_id.to_bytes(width, "little"))
        size_of[node_offset] = 1 + width

    order, offsets, entries_end = plan_node_offsets(
        doc.graph, doc.header.offset_entries, size_of=size_of)
    plan.node_order = order
    plan.node_offsets = offsets

    string_offsets, string_blob = plan_string_section(raw_strings)
    element_width = S.table_width(string_offsets)
    count_width = doc.strings.offsets.count_width
    if S.min_uint_width(len(string_offsets)) > count_width:
        count_width = S.min_uint_width(len(string_offsets))
    if element_width != doc.strings.offsets.element_width:
        report.string_table_width_changed = True
    if not changes.edits:
        # 零编辑路径必须原样重放原始表。
        element_width = doc.strings.offsets.element_width
        count_width = doc.strings.offsets.count_width
        string_offsets = list(doc.strings.offsets.values)
        string_blob = doc.strings.data_bytes()
        report.string_table_width_changed = False

    string_table = write_packed_table(string_offsets, count_width, element_width)
    entries_blob = emit_value_graph(doc.graph, order, offsets, overrides)
    names_blob = doc.names.to_bytes()
    chunk_off = write_packed_table(doc.chunk_offsets.values,
                                   doc.chunk_offsets.count_width,
                                   doc.chunk_offsets.element_width)
    chunk_len = write_packed_table(doc.chunk_lengths.values,
                                   doc.chunk_lengths.count_width,
                                   doc.chunk_lengths.element_width)

    off_names = S.HEADER_LENGTH_V3
    off_entries = off_names + len(names_blob)
    off_strings = off_entries + len(entries_blob)
    off_strings_data = off_strings + len(string_table)
    off_chunk_offsets = off_strings_data + len(string_blob)
    off_chunk_lengths = off_chunk_offsets + len(chunk_off)
    off_chunk_data = off_chunk_lengths + len(chunk_len)

    if off_entries != doc.header.offset_entries:
        raise RepackError(
            f"名称区尺寸发生变化（{off_entries:#x} != "
            f"{doc.header.offset_entries:#x}）")
    if off_strings != entries_end:
        raise RepackError("entries 布局与尺寸计算结果不一致")

    header = PsbHeader(
        version=doc.header.version, header_encrypt=doc.header.header_encrypt,
        header_length=S.HEADER_LENGTH_V3, offset_names=off_names,
        offset_strings=off_strings, offset_strings_data=off_strings_data,
        offset_chunk_offsets=off_chunk_offsets,
        offset_chunk_lengths=off_chunk_lengths,
        offset_chunk_data=off_chunk_data, offset_entries=off_entries,
        checksum=0)
    header.checksum = header.computed_checksum()

    out = b"".join([header.to_bytes(), names_blob, entries_blob, string_table,
                    string_blob, chunk_off, chunk_len])
    if len(out) != off_chunk_data:
        raise RepackError(
            f"组装长度 {len(out)} != 计划长度 {off_chunk_data}")

    plan.string_order = list(range(len(raw_strings)))
    plan.string_offsets = dict(enumerate(string_offsets))
    plan.section_offsets = {
        "names": off_names, "entries": off_entries, "strings": off_strings,
        "strings_data": off_strings_data,
        "chunk_offsets": off_chunk_offsets,
        "chunk_lengths": off_chunk_lengths, "chunk_data": off_chunk_data,
    }
    plan.total_size = len(out)
    report.output_size = len(out)
    if changes.edits:
        report.notes.append(
            f"文件长度 {doc.size} -> {len(out)} "
            f"（{len(out) - doc.size:+d} 字节）")
    return out, plan, report
