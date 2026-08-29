"""PSB 字符串表：一个偏移表加上以 NUL 结尾的 UTF-8 数据块。

语料实测性质（264 个文件全部满足）：偏移严格递增、取值唯一且按字节序排序、
数据块紧密排布无填充，且每个字符串至少被一个值节点引用。非 ASCII 内容能按
UTF-8 解码、不能只按 CP932 解码，因此 `utf-8` 是实测结论而非假设。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.errors import ParseError
from .psb_codec import PackedTable, read_packed_table, write_packed_table


@dataclass(slots=True)
class StringTable:
    """原始字符串字节，以及偏移表原本使用的宽度。"""

    raw: list[bytes]
    offsets: PackedTable
    data_start: int
    data_end: int
    encoding: str = "utf-8"
    _index: dict[bytes, int] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not self._index:
            for i, value in enumerate(self.raw):
                self._index.setdefault(value, i)

    def __len__(self) -> int:
        return len(self.raw)

    def text(self, string_id: int) -> str:
        return self.raw[string_id].decode(self.encoding, "surrogateescape")

    def id_of(self, value: bytes) -> int | None:
        return self._index.get(value)

    @property
    def strictly_increasing(self) -> bool:
        v = self.offsets.values
        return all(v[i] < v[i + 1] for i in range(len(v) - 1))

    @property
    def tightly_packed(self) -> bool:
        v = self.offsets.values
        return all(v[i] + len(self.raw[i]) + 1 == v[i + 1]
                   for i in range(len(self.raw) - 1))

    def table_bytes(self) -> bytes:
        return write_packed_table(self.offsets.values,
                                  self.offsets.count_width,
                                  self.offsets.element_width)

    def data_bytes(self) -> bytes:
        """按原始（可能稀疏的）偏移重建数据块。"""
        size = self.data_end - self.data_start
        buf = bytearray(size)
        for offset, value in zip(self.offsets.values, self.raw):
            buf[offset:offset + len(value) + 1] = value + b"\x00"
        return bytes(buf)


def read_string_table(data: bytes, table_pos: int, data_pos: int,
                      data_end: int, encoding: str = "utf-8") -> StringTable:
    """解码 table_pos 处的偏移表与 data_pos 处的数据块。"""
    offsets = read_packed_table(data, table_pos)
    if offsets.end != data_pos:
        raise ParseError("字符串偏移表未与字符串数据区相邻",
                         offset=offsets.end, expected=hex(data_pos),
                         actual=hex(offsets.end))
    raw: list[bytes] = []
    for i, rel in enumerate(offsets.values):
        begin = data_pos + rel
        if not data_pos <= begin < data_end:
            raise ParseError(f"字符串[{i}] 的偏移落在数据区之外",
                             offset=begin,
                             expected=f"[{data_pos:#x},{data_end:#x})",
                             actual=hex(begin))
        stop = data.find(b"\x00", begin, data_end)
        if stop < 0:
            raise ParseError(f"字符串[{i}] 没有终止符", offset=begin)
        raw.append(data[begin:stop])
    reach = max((rel + len(v) + 1 for rel, v in zip(offsets.values, raw)),
                default=0)
    if data_pos + reach != data_end:
        raise ParseError("字符串数据区存在尾部残余字节",
                         offset=data_pos + reach, expected=hex(data_end),
                         actual=hex(data_pos + reach))
    return StringTable(raw, offsets, data_pos, data_end, encoding)


def plan_string_section(raw: list[bytes]) -> tuple[list[int], bytes]:
    """按给定顺序紧密排布一个全新的字符串区。"""
    offsets: list[int] = []
    blob = bytearray()
    for value in raw:
        offsets.append(len(blob))
        blob += value + b"\x00"
    return offsets, bytes(blob)
