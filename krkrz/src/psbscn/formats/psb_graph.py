"""PSB 值图：节点定义、DAG 解析与逐字节精确的重序列化。

entries 区**不是**树。全语料实测有 449,445 个子指针指向了已被另一个父节点占用
的节点，也就是说相同子树只存一份、被多处引用。因此解析按绝对偏移做记忆化并产出
一个 DAG；字节归属仍然精确（该区每个字节恰属一个节点），而朴素的树遍历会把这些
共享区间误报为重叠。

重序列化按 DFS 前序、首次出现优先的顺序发射节点，可对全部 264 个语料文件逐字节
重现原始布局。子指针以父节点偏移表结束处为基准存储相对值，且所存整数宽度原样
重放。
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Iterator

from ..core.errors import UnknownOpcodeError
from . import psb_spec as S
from .psb_codec import PackedTable, read_packed_table, write_packed_table


def _kind_of_type(t: int) -> str:
    if S.T_INT_BASE <= t <= S.T_INT_MAX:
        return "int"
    if S.T_ARRAY_BASE <= t <= S.T_ARRAY_MAX:
        return "int_array"
    if S.T_STRING_BASE <= t <= S.T_STRING_MAX:
        return "string"
    if S.T_RESOURCE_BASE <= t <= S.T_RESOURCE_MAX:
        return "resource"
    return S.TYPE_NAMES.get(t, f"type{t}")


#: 类型字节 -> kind 名。全部 256 项预先展开，取值变成一次列表索引。
#: 字符串用 intern，让后续比较退化成指针比较。
_KIND_BY_TYPE: list[str] = [sys.intern(_kind_of_type(_i)) for _i in range(256)]


@dataclass(slots=True)
class Node:
    """一个 PSB 值，连带它确切的存储编码。"""

    offset: int
    type: int
    size: int
    payload: bytes = b""
    children: tuple[int, ...] = ()
    keys: tuple[int, ...] = ()
    key_table: PackedTable | None = None
    offset_table: PackedTable | None = None
    inline_table: PackedTable | None = None

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def kind(self) -> str:
        # 只由类型字节决定，因此按类型预先算好；账本会对十万级节点逐个取这个值，
        # 每次重跑一串范围比较纯属浪费。
        return _KIND_BY_TYPE[self.type]

    @property
    def is_container(self) -> bool:
        return self.type in (S.T_COLLECTION, S.T_OBJECT)

    def int_value(self) -> int:
        return int.from_bytes(self.payload, "little")

    def string_id(self) -> int:
        return int.from_bytes(self.payload, "little")


@dataclass(slots=True)
class ValueGraph:
    """一个 entries 区的全部节点，按原始绝对偏移索引。"""

    root: int
    nodes: dict[int, Node] = field(default_factory=dict)
    start: int = 0
    end: int = 0
    shared_hits: int = 0

    def __len__(self) -> int:
        return len(self.nodes)

    def __getitem__(self, offset: int) -> Node:
        return self.nodes[offset]

    def preorder(self) -> list[int]:
        """DFS 前序、首次出现优先——即发射顺序。"""
        order: list[int] = []
        seen: set[int] = set()
        stack = [self.root]
        while stack:
            off = stack.pop()
            if off in seen:
                continue
            seen.add(off)
            order.append(off)
            kids = self.nodes[off].children
            for child in reversed(kids):
                if child not in seen:
                    stack.append(child)
        return order

    def iter_nodes(self) -> Iterator[Node]:
        for off in sorted(self.nodes):
            yield self.nodes[off]

    def parent_map(self) -> dict[int, list[int]]:
        parents: dict[int, list[int]] = {}
        for node in self.nodes.values():
            for child in node.children:
                parents.setdefault(child, []).append(node.offset)
        return parents


def parse_value_graph(data: bytes, root: int, section_end: int) -> ValueGraph:
    """把 entries 区解析为按偏移记忆化的节点 DAG。"""
    graph = ValueGraph(root=root, start=root, end=section_end)
    nodes = graph.nodes
    pending = [root]
    while pending:
        pos = pending.pop()
        if pos in nodes:
            graph.shared_hits += 1
            continue
        node = _read_node(data, pos)
        nodes[pos] = node
        for child in node.children:
            if child in nodes:
                graph.shared_hits += 1
            else:
                pending.append(child)
    return graph


# --- 类型分派表 --------------------------------------------------------
# `_read_node` 是最热的函数（每个文件调用十万级）。原先用一串范围比较分派，命中
# 靠后的类型要先失败好几次；实测最常见的类型 0x16（占 35.5%）排在第 4 个判断。
# 这里把「类型字节 -> 处理类别 + 该类别的宽度」预先展开成 256 项定长表，分派变成
# 一次列表索引，与类型频率无关。
_K_ATOM = 0      # 单字节：none/null/true/false/float0
_K_FIXED = 1     # 1 字节标签 + 定宽 payload：int/string/resource/float32/float64
_K_TABLE = 2     # 内联打包表
_K_COLL = 3      # 集合：一张偏移表
_K_OBJ = 4       # 对象：键表 + 偏移表
_K_BAD = 5       # 未定义

_DISPATCH: list[tuple[int, int]] = [(_K_BAD, 0)] * 256
for _t in (S.T_NONE, S.T_NULL, S.T_TRUE, S.T_FALSE, S.T_FLOAT0):
    _DISPATCH[_t] = (_K_ATOM, 0)
for _t in range(S.T_INT_BASE, S.T_INT_MAX + 1):
    _DISPATCH[_t] = (_K_FIXED, _t - S.T_INT_BASE)
for _t in range(S.T_ARRAY_BASE, S.T_ARRAY_MAX + 1):
    _DISPATCH[_t] = (_K_TABLE, 0)
for _t in range(S.T_STRING_BASE, S.T_STRING_MAX + 1):
    _DISPATCH[_t] = (_K_FIXED, _t - S.T_STRING_BASE + 1)
for _t in range(S.T_RESOURCE_BASE, S.T_RESOURCE_MAX + 1):
    _DISPATCH[_t] = (_K_FIXED, _t - S.T_RESOURCE_BASE + 1)
_DISPATCH[S.T_FLOAT32] = (_K_FIXED, 4)
_DISPATCH[S.T_FLOAT64] = (_K_FIXED, 8)
_DISPATCH[S.T_COLLECTION] = (_K_COLL, 0)
_DISPATCH[S.T_OBJECT] = (_K_OBJ, 0)
del _t


def _read_node(data: bytes, pos: int) -> Node:
    t = data[pos]
    kind, width = _DISPATCH[t]
    if kind == _K_ATOM:
        return Node(pos, t, 1)
    if kind == _K_FIXED:
        body = pos + 1
        return Node(pos, t, 1 + width, data[body:body + width])
    if kind == _K_TABLE:
        table = read_packed_table(data, pos)
        return Node(pos, t, table.end - pos, inline_table=table)
    if kind == _K_COLL:
        offsets = read_packed_table(data, pos + 1)
        base = offsets.end
        return Node(pos, t, base - pos,
                    children=tuple(base + rel for rel in offsets.values),
                    offset_table=offsets)
    if kind == _K_OBJ:
        keys = read_packed_table(data, pos + 1)
        offsets = read_packed_table(data, keys.end)
        base = offsets.end
        return Node(pos, t, base - pos,
                    children=tuple(base + rel for rel in offsets.values),
                    keys=keys.values, key_table=keys, offset_table=offsets)
    raise UnknownOpcodeError(f"未定义的 PSB 值类型 0x{t:02X}", offset=pos,
                             expected="0x00-0x21", actual=f"0x{t:02X}")


def node_encoded_size(node: Node) -> int:
    """按所存宽度重新发射该节点时占用的字节数。"""
    if node.type == S.T_COLLECTION:
        table = node.offset_table
        assert table is not None
        return 1 + _table_size(len(node.children), table)
    if node.type == S.T_OBJECT:
        keys, offs = node.key_table, node.offset_table
        assert keys is not None and offs is not None
        return (1 + _table_size(len(node.keys), keys)
                + _table_size(len(node.children), offs))
    if node.inline_table is not None:
        t = node.inline_table
        return _table_size(len(t.values), t)
    return node.size


def _table_size(count: int, table: PackedTable) -> int:
    return 1 + table.count_width + 1 + count * table.element_width


def plan_node_offsets(graph: ValueGraph, base: int,
                      order: list[int] | None = None,
                      size_of: dict[int, int] | None = None,
                      ) -> tuple[list[int], dict[int, int], int]:
    """按发射顺序分配新的绝对偏移。

    返回 `(order, offsets, end)`。当某个节点的载荷因编辑而加宽时，可用 `size_of`
    覆盖它的尺寸。
    """
    order = order if order is not None else graph.preorder()
    offsets: dict[int, int] = {}
    cursor = base
    nodes = graph.nodes
    # `size_of` 在循环外定型：写成 `(size_of or {})` 会为十万级节点各建一个空字典。
    sizes = size_of if size_of else None
    for off in order:
        offsets[off] = cursor
        override = sizes.get(off) if sizes is not None else None
        cursor += override or node_encoded_size(nodes[off])
    return order, offsets, cursor


def emit_value_graph(graph: ValueGraph, order: list[int],
                     offsets: dict[int, int],
                     overrides: dict[int, bytes] | None = None) -> bytes:
    """按 `order` 序列化节点，并用 `offsets` 解析子指针。"""
    out = bytearray()
    nodes = graph.nodes
    extend = out.extend
    if overrides:
        for off in order:
            patch = overrides.get(off)
            extend(patch if patch is not None else _emit_node(nodes[off], offsets))
    else:
        # 零编辑往返走这条：没有覆盖项时省掉每个节点一次字典查找。
        for off in order:
            extend(_emit_node(nodes[off], offsets))
    return bytes(out)


def _emit_node(node: Node, offsets: dict[int, int]) -> bytes:
    t = node.type
    if t == S.T_COLLECTION:
        table = node.offset_table
        assert table is not None
        base = (offsets[node.offset] + 1
                + _table_size(len(node.children), table))
        rel = [offsets[c] - base for c in node.children]
        return bytes([t]) + write_packed_table(
            rel, table.count_width, table.element_width)
    if t == S.T_OBJECT:
        keys, offs = node.key_table, node.offset_table
        assert keys is not None and offs is not None
        key_bytes = write_packed_table(node.keys, keys.count_width,
                                       keys.element_width)
        base = (offsets[node.offset] + 1 + len(key_bytes)
                + _table_size(len(node.children), offs))
        rel = [offsets[c] - base for c in node.children]
        return (bytes([t]) + key_bytes
                + write_packed_table(rel, offs.count_width, offs.element_width))
    if node.inline_table is not None:
        tbl = node.inline_table
        return write_packed_table(tbl.values, tbl.count_width,
                                  tbl.element_width)
    return bytes([t]) + node.payload


def materialize(graph: ValueGraph, strings: Any, names: Any,
                offset: int | None = None) -> Any:
    """把某个节点（默认根节点）投影为普通 Python 值。"""
    memo: dict[int, Any] = {}

    def build(off: int) -> Any:
        if off in memo:
            return memo[off]
        node = graph.nodes[off]
        t = node.type
        if t == S.T_NULL or t == S.T_NONE:
            value: Any = None
        elif t == S.T_TRUE:
            value = True
        elif t == S.T_FALSE:
            value = False
        elif S.T_INT_BASE <= t <= S.T_INT_MAX:
            value = node.int_value()
        elif node.inline_table is not None:
            value = list(node.inline_table.values)
        elif S.T_STRING_BASE <= t <= S.T_STRING_MAX:
            value = strings.text(node.string_id())
        elif S.T_RESOURCE_BASE <= t <= S.T_RESOURCE_MAX:
            value = {"$resource": node.string_id()}
        elif t == S.T_FLOAT0:
            value = 0.0
        elif t == S.T_FLOAT32:
            import struct
            value = struct.unpack("<f", node.payload)[0]
        elif t == S.T_FLOAT64:
            import struct
            value = struct.unpack("<d", node.payload)[0]
        elif t == S.T_COLLECTION:
            value = [build(c) for c in node.children]
        else:
            value = {names.text(k): build(c)
                     for k, c in zip(node.keys, node.children)}
        memo[off] = value
        return value

    return build(graph.root if offset is None else offset)
