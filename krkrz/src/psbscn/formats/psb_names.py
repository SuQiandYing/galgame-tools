"""PSB 名称表：由三个数组构成的 trie，从叶向根反向解码。

三个数组分别是 `charset`（每个节点的偏移基准）、`tree`（每个节点的父指针）与
`index`（每个键一个终止节点，按键顺序排列）。

从终止节点 `i` 解码一个键::

    while i:
        parent = tree[i]
        emit(i - charset[parent])
        i = parent

发射出的字节需要反转，并去掉末尾的 NUL 终止符。

语料观测性质（覆盖全部 264 个文件）：原始 trie 中存在任何键路径都到不了的节点
——例如某文件占用 453 个节点，而紧凑 trie 只需 362 个。因此重新生成的最小 trie
**不会**与原始表逐字节一致，所以 `parse` 原样保留三个数组，`repack` 原样重放。
只有键集合发生变化时才重新生成，并作为名称区的 `semantic-rebuild` 上报。
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.errors import ParseError
from .psb_codec import PackedTable, read_packed_table, write_packed_table


@dataclass(slots=True)
class NameTable:
    """解码出的键，以及它们来源的确切 trie 数组。"""

    names: list[bytes]
    charset: PackedTable
    tree: PackedTable
    index: PackedTable
    start: int
    end: int

    def __len__(self) -> int:
        return len(self.names)

    def text(self, key_id: int, encoding: str = "utf-8") -> str:
        return self.names[key_id].decode(encoding, "surrogateescape")

    @property
    def unreachable_node_count(self) -> int:
        reached: set[int] = set()
        tree = self.tree.values
        for terminal in self.index.values:
            node = terminal
            while node:
                if node in reached:
                    break
                reached.add(node)
                node = tree[node]
        return len(self.charset.values) - 1 - len(reached)

    def encoded_size(self) -> int:
        return (self.charset.encoded_size + self.tree.encoded_size
                + self.index.encoded_size)

    def to_bytes(self) -> bytes:
        """逐字节重放原始数组。"""
        return b"".join(
            write_packed_table(t.values, t.count_width, t.element_width)
            for t in (self.charset, self.tree, self.index)
        )


def read_name_table(data: bytes, pos: int) -> NameTable:
    """解码三个 trie 数组以及它们编码的每一个键。"""
    start = pos
    charset = read_packed_table(data, pos)
    tree = read_packed_table(data, charset.end)
    index = read_packed_table(data, tree.end)
    node_count = len(charset.values)
    names: list[bytes] = []
    for terminal in index.values:
        if terminal >= node_count:
            raise ParseError("名称终止节点越界",
                             offset=start, expected=f"<{node_count}",
                             actual=terminal)
        out = bytearray()
        node = terminal
        guard = 0
        while node:
            parent = tree.values[node]
            if parent >= node_count:
                raise ParseError("名称父节点越界",
                                 offset=start, actual=parent)
            out.append((node - charset.values[parent]) & 0xFF)
            node = parent
            guard += 1
            if guard > node_count:
                raise ParseError("名称 trie 中存在环", offset=start,
                                 actual=terminal)
        out.reverse()
        names.append(bytes(out).rstrip(b"\x00"))
    return NameTable(names, charset, tree, index, start, index.end)


def build_name_table(names: list[bytes]) -> tuple[list[int], list[int], list[int]]:
    """为一组键构造合法的 trie（仅用于 semantic-rebuild）。

    槽位分配遵循解码器的规则：字节按 `child_slot - charset[parent_slot]` 还原，
    因此同一父节点的所有子节点必须位于同一个 `base` 加上各自字节的位置。基准值
    采用贪心分配；任何键路径都到不了的槽位保留为填充项，`charset=tree=0`——
    这与原始表中观测到的现象一致。

    返回 `(charset, tree, index)`；键必须唯一。
    """
    if len(set(names)) != len(names):
        raise ValueError("名称键重复")

    # 先构造逻辑 trie：每个节点保存 子字节 -> 逻辑子节点 ID。
    kids: list[dict[int, int]] = [{}]
    terminal_of: dict[int, int] = {}
    for key_id, name in enumerate(names):
        node = 0
        for ch in name + b"\x00":
            if ch not in kids[node]:
                kids.append({})
                kids[node][ch] = len(kids) - 1
            node = kids[node][ch]
        terminal_of[node] = key_id

    # 分配物理槽位，使 child_slot == base(parent) + byte 成立。
    slot_of: dict[int, int] = {0: 0}
    occupied: set[int] = {0}
    base_of: dict[int, int] = {}
    queue = [0]
    while queue:
        logical = queue.pop(0)
        edges = kids[logical]
        if not edges:
            base_of[slot_of[logical]] = 0
            continue
        base = 1
        while any((base + ch) in occupied for ch in edges):
            base += 1
        base_of[slot_of[logical]] = base
        for ch, child in edges.items():
            slot = base + ch
            occupied.add(slot)
            slot_of[child] = slot
            queue.append(child)

    total = max(occupied) + 1
    charset = [0] * total
    tree = [0] * total
    for logical, slot in slot_of.items():
        charset[slot] = base_of.get(slot, 0)
    for logical, edges in enumerate(kids):
        parent_slot = slot_of[logical]
        for ch, child in edges.items():
            tree[slot_of[child]] = parent_slot
    index = [slot_of[node] for node in
             sorted(terminal_of, key=lambda n: terminal_of[n])]
    return charset, tree, index
