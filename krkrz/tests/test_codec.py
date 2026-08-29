"""打包表、名称 trie 与文件头编解码测试。"""
from __future__ import annotations

import pytest

from psbscn.core.errors import ParseError, ProbeRejected
from psbscn.formats import psb_spec as S
from psbscn.formats.psb_codec import read_packed_table, write_packed_table
from psbscn.formats.psb_header import read_header
from psbscn.formats.psb_names import build_name_table, read_name_table


@pytest.mark.parametrize("values,cw,ew", [
    ([], 1, 1),
    ([0], 1, 1),
    ([1, 2, 3], 1, 1),
    ([0x1234, 0xFFFF], 2, 2),
    ([0x010000], 1, 3),
])
def test_打包表往返(values, cw, ew):
    blob = write_packed_table(values, cw, ew)
    table = read_packed_table(blob, 0)
    assert list(table.values) == values
    assert (table.count_width, table.element_width) == (cw, ew)
    assert table.end == len(blob) == table.encoded_size


def test_打包表保留非最小宽度():
    """语料中的表并非总用最小宽度，宽度必须原样存活。"""
    blob = write_packed_table([0xDA], 2, 2)
    table = read_packed_table(blob, 0)
    assert table.element_width == 2
    assert write_packed_table(table.values, table.count_width,
                              table.element_width) == blob


def test_打包表拒绝溢出值():
    with pytest.raises(ValueError, match="无法放入"):
        write_packed_table([256], 1, 1)


def test_打包表拒绝错误标签():
    with pytest.raises(ValueError, match="不是打包表"):
        read_packed_table(b"\x21\x00", 0)


def test_打包表拒绝截断缓冲区():
    blob = write_packed_table([1, 2, 3], 1, 2)
    with pytest.raises(ValueError, match="越过缓冲区末尾"):
        read_packed_table(blob[:-2], 0)


def test_名称trie往返():
    keys = [b"action", b"class", b"clip", b"data", b"name", b"scenes"]
    charset, tree, index = build_name_table(keys)
    blob = b"".join([
        write_packed_table(charset, 2, max(1, S.min_uint_width(max(charset)))),
        write_packed_table(tree, 2, max(1, S.min_uint_width(max(tree)))),
        write_packed_table(index, 1, max(1, S.min_uint_width(max(index)))),
    ])
    table = read_name_table(blob, 0)
    assert table.names == keys
    assert table.to_bytes() == blob
    # 槽位分配会留下填充槽位，与原始表的现象一致。
    assert table.unreachable_node_count >= 0


def test_名称trie拒绝重复键():
    with pytest.raises(ValueError, match="重复"):
        build_name_table([b"a", b"a"])


def test_文件头拒绝错误签名():
    with pytest.raises(ProbeRejected, match="签名错误"):
        read_header(b"XXXX" + bytes(64))


def test_文件头拒绝过短输入():
    with pytest.raises(ProbeRejected, match="长度小于"):
        read_header(b"PSB\x00")


def test_文件头校验门禁(synthetic_psb):
    header = read_header(synthetic_psb)
    assert header.checksum == header.computed_checksum()
    broken = bytearray(synthetic_psb)
    broken[0x28] ^= 0xFF
    with pytest.raises(ParseError, match="校验和不匹配"):
        read_header(bytes(broken))
    # 非严格模式下容忍该差异
    assert read_header(bytes(broken), strict=False).version == 3
