"""PSB v3（M2 Packaged-Struct-Binary）类型系统。

结论来自对 264 个 kirikiri/M2 `*.txt.scn` 剧本文件的全量观测：全部带有签名
`PSB\\0`、版本 3、header_encrypt 0、header_length 0x2C，且 chunk 表为空。

文件头布局（小端，0x2C 字节）::

    0x00  char[4] signature = "PSB\\0"
    0x04  u16     version = 3
    0x06  u16     header_encrypt = 0
    0x08  u32     header_length        （等于 offset_names，0x2C）
    0x0C  u32     offset_names
    0x10  u32     offset_strings
    0x14  u32     offset_strings_data
    0x18  u32     offset_chunk_offsets
    0x1C  u32     offset_chunk_lengths
    0x20  u32     offset_chunk_data
    0x24  u32     offset_entries
    0x28  u32     checksum = adler32(header[0x08:0x28])

磁盘上的分区顺序是 names -> entries -> strings -> strings_data ->
chunk_offsets -> chunk_lengths -> chunk_data(EOF)，与文件头字段顺序**不同**；
工具一律按偏移值推导顺序，绝不假设。
"""
from __future__ import annotations

SIGNATURE = b"PSB\x00"
SUPPORTED_VERSIONS = (3,)
HEADER_LENGTH_V3 = 0x2C
CHECKSUM_SPAN = (0x08, 0x28)

# --- 值类型字节 --------------------------------------------------------
T_NONE = 0
T_NULL = 1
T_TRUE = 2
T_FALSE = 3
# 4..12：无符号整数，字节宽度 = t - 4（宽度 0 表示字面量 0）
T_INT_BASE = 4
T_INT_MAX = 12
# 13..20：打包整数表，计数宽度 = t - 12，随后是元素宽度标签字节
T_ARRAY_BASE = 13
T_ARRAY_MAX = 20
# 21..24：字符串，字符串表索引宽度 = t - 20
T_STRING_BASE = 21
T_STRING_MAX = 24
# 25..28：资源/chunk 索引，宽度 = t - 24
T_RESOURCE_BASE = 25
T_RESOURCE_MAX = 28
T_FLOAT0 = 29
T_FLOAT32 = 30
T_FLOAT64 = 31
T_COLLECTION = 32
T_OBJECT = 33

TYPE_NAMES = {
    T_NONE: "none", T_NULL: "null", T_TRUE: "true", T_FALSE: "false",
    T_FLOAT0: "float0", T_FLOAT32: "float32", T_FLOAT64: "float64",
    T_COLLECTION: "collection", T_OBJECT: "object",
}


def min_uint_width(value: int) -> int:
    """能无符号容纳 value 的最小字节数（0 返回 0）。"""
    if value < 0:
        raise ValueError(f"数值为负：{value}")
    width = 0
    while value >> (8 * width):
        width += 1
    return width


def table_width(values: list[int] | tuple[int, ...]) -> int:
    """打包表的元素宽度：至少 1 字节。"""
    return max(1, min_uint_width(max(values) if values else 0))
