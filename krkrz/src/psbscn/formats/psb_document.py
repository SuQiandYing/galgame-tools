"""PsbDocument：整个文件的解析模型，以及逐字节精确的重序列化。

磁盘上的分区顺序（由偏移推导，绝不假设）：
header -> names -> entries -> strings -> strings_data -> chunk_offsets ->
chunk_lengths -> chunk_data(EOF)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.coverage import RegionLedger
from ..core.errors import ParseError, RepackError
from . import psb_spec as S
from .psb_codec import PackedTable, read_packed_table, write_packed_table
from .psb_graph import (ValueGraph, emit_value_graph, materialize,
                       node_encoded_size, parse_value_graph, plan_node_offsets)
from .psb_header import PsbHeader, read_header
from .psb_names import NameTable, read_name_table
from .psb_strings import StringTable, read_string_table


@dataclass(slots=True)
class PsbDocument:
    """重建文件所需的全部信息，以及原始源字节。"""

    header: PsbHeader
    names: NameTable
    strings: StringTable
    graph: ValueGraph
    chunk_offsets: PackedTable
    chunk_lengths: PackedTable
    data: bytes = field(repr=False, default=b"")
    source_name: str = ""

    @property
    def size(self) -> int:
        return len(self.data)

    def key_text(self, key_id: int) -> str:
        return self.names.text(key_id)

    def string_text(self, string_id: int) -> str:
        return self.strings.text(string_id)

    def to_python(self) -> Any:
        """把根值投影为普通 Python 容器。"""
        return materialize(self.graph, self.strings, self.names)

    def section_map(self) -> list[tuple[str, int, int]]:
        h = self.header
        return [
            ("header", 0, h.header_length),
            ("names", h.offset_names, h.offset_entries),
            ("entries", h.offset_entries, h.offset_strings),
            ("strings", h.offset_strings, h.offset_strings_data),
            ("strings_data", h.offset_strings_data, h.offset_chunk_offsets),
            ("chunk_offsets", h.offset_chunk_offsets, h.offset_chunk_lengths),
            ("chunk_lengths", h.offset_chunk_lengths, h.offset_chunk_data),
        ]

    def build_ledger(self, layer_id: str = "L000",
                     *, detailed: bool = True) -> RegionLedger:
        """覆盖整个文件、字节归属精确的 Region 账本。

        某个节点的容器字节（类型字节 + 键表/偏移表）归该节点所有；子节点的载荷
        字节归子节点所有。共享节点只记录一次，这就是尽管结构是 DAG、覆盖仍然
        精确的原因。

        `detailed=False` 时不为每个值节点构造 `checks` 字典。那些字段只有覆盖证书会读，
        且内容（类型、子节点数）在 ASM 与 IR 里都已存在；批量流程不出证书，十万级的
        字典分配纯属浪费。缺口/重叠/哈希校验完全不受影响。
        """
        ledger = RegionLedger(layer_id=layer_id, source_size=self.size)
        h = self.header
        d = self.data
        ledger.add_span(0, h.header_length, kind="psb_header",
                        owner="PsbHeader", data=d,
                        evidence_refs=("CLAIM_PSB_V3",),
                        checks={"checksum": f"0x{h.checksum:08X}",
                                "checksum_algorithm": "adler32(header[8:40])"})
        n = self.names
        for label, table in (("names_charset", n.charset),
                             ("names_tree", n.tree),
                             ("names_index", n.index)):
            ledger.add_span(table.start, table.end, kind=label,
                            owner="NameTable", data=d,
                            checks={"count": len(table.values),
                                    "count_width": table.count_width,
                                    "element_width": table.element_width})
        add_span = ledger.add_span
        if detailed:
            for node in self.graph.iter_nodes():
                add_span(node.offset, node.offset + node.size,
                         kind=f"value_{node.kind}", owner="ValueGraph", data=d,
                         checks={"type": node.type,
                                 "children": len(node.children)})
        else:
            for node in self.graph.iter_nodes():
                add_span(node.offset, node.offset + node.size,
                         kind=f"value_{node.kind}", owner="ValueGraph", data=d)
        st = self.strings
        ledger.add_span(st.offsets.start, st.offsets.end,
                        kind="string_offsets", owner="StringTable", data=d,
                        checks={"count": len(st.raw),
                                "element_width": st.offsets.element_width})
        for i, (rel, raw) in enumerate(zip(st.offsets.values, st.raw)):
            begin = st.data_start + rel
            ledger.add_span(begin, begin + len(raw) + 1,
                            kind="string_data", owner=f"string[{i}]", data=d,
                            checks={"string_id": i, "encoding": st.encoding,
                                    "terminator": "NUL"})
        for label, table in (("chunk_offsets", self.chunk_offsets),
                             ("chunk_lengths", self.chunk_lengths)):
            ledger.add_span(table.start, table.end, kind=label,
                            owner="ChunkTable", data=d,
                            status="decoded",
                            checks={"count": len(table.values)})
        return ledger

    def to_bytes(self) -> bytes:
        """从解析模型逐字节重建文件。"""
        h = self.header
        order, offsets, entries_end = plan_node_offsets(
            self.graph, h.offset_entries)
        if entries_end != h.offset_strings:
            raise RepackError(
                f"entries 区尺寸发生变化：0x{entries_end:X} != "
                f"0x{h.offset_strings:X}")
        parts = [
            h.to_bytes(),
            self.names.to_bytes(),
            emit_value_graph(self.graph, order, offsets),
            self.strings.table_bytes(),
            self.strings.data_bytes(),
            write_packed_table(self.chunk_offsets.values,
                               self.chunk_offsets.count_width,
                               self.chunk_offsets.element_width),
            write_packed_table(self.chunk_lengths.values,
                               self.chunk_lengths.count_width,
                               self.chunk_lengths.element_width),
        ]
        out = b"".join(parts)
        if len(out) != self.size:
            raise RepackError(
                f"重建长度 {len(out)} != 源文件长度 {self.size}")
        return out


def parse_document(data: bytes, *, source_name: str = "",
                   encoding: str = "utf-8",
                   strict: bool = True) -> PsbDocument:
    """把一个 PSB v3 剧本文件解析为 PsbDocument。"""
    header = read_header(data, strict=strict)
    names = read_name_table(data, header.offset_names)
    if names.end != header.offset_entries:
        raise ParseError("名称区未与 entries 区相邻",
                         offset=names.end,
                         expected=hex(header.offset_entries),
                         actual=hex(names.end))
    graph = parse_value_graph(data, header.offset_entries,
                              header.offset_strings)
    reached_end = max((n.offset + n.size for n in graph.nodes.values()),
                      default=header.offset_entries)
    if reached_end != header.offset_strings:
        raise ParseError("值图未填满 entries 区",
                         offset=reached_end,
                         expected=hex(header.offset_strings),
                         actual=hex(reached_end))
    strings = read_string_table(data, header.offset_strings,
                                header.offset_strings_data,
                                header.offset_chunk_offsets, encoding)
    chunk_offsets = read_packed_table(data, header.offset_chunk_offsets)
    if chunk_offsets.end != header.offset_chunk_lengths:
        raise ParseError("chunk 偏移表位置错位",
                         offset=chunk_offsets.end,
                         expected=hex(header.offset_chunk_lengths),
                         actual=hex(chunk_offsets.end))
    chunk_lengths = read_packed_table(data, header.offset_chunk_lengths)
    if chunk_lengths.end != header.offset_chunk_data:
        raise ParseError("chunk 长度表位置错位",
                         offset=chunk_lengths.end,
                         expected=hex(header.offset_chunk_data),
                         actual=hex(chunk_lengths.end))
    if chunk_offsets.values or chunk_lengths.values:
        raise ParseError(
            "文件含内嵌 chunk 数据；本构建只对无 chunk 的剧本文件出具证书",
            offset=header.offset_chunk_offsets,
            expected=0, actual=len(chunk_offsets.values))
    return PsbDocument(header, names, strings, graph, chunk_offsets,
                       chunk_lengths, data, source_name)
