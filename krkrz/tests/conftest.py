"""共享 fixture。有语料时使用真实文件，同时用工具自身的写入器构造一个合成 PSB，
使测试套件在没有语料时也能独立运行。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

CORPUS_DIR = ROOT.parent / "scn"


def corpus_files(limit: int | None = None) -> list[Path]:
    if not CORPUS_DIR.is_dir():
        return []
    files = sorted(CORPUS_DIR.glob("*.scn"))
    return files[:limit] if limit else files


@pytest.fixture(scope="session")
def corpus() -> list[Path]:
    files = corpus_files()
    if not files:
        pytest.skip(f"{CORPUS_DIR} 下没有语料文件")
    return files


@pytest.fixture(scope="session")
def sample(corpus: list[Path]) -> Path:
    """一个较小的真实文件，用于快速的单测往返。"""
    return min(corpus, key=lambda p: p.stat().st_size)


@pytest.fixture(scope="session")
def text_sample(corpus: list[Path]) -> Path:
    """真正含有可编辑消息文本的最小文件。

    部分剧本文件（例如 `scenemode.ks.scn` 这类菜单定义）只有空标题字符串，
    因此编辑路径的测试必须按证据挑选样本，而不是按体积。
    """
    from psbscn.bytecode.scenario import collect_text_sites
    from psbscn.formats.psb_document import parse_document

    for path in sorted(corpus, key=lambda p: p.stat().st_size):
        doc = parse_document(path.read_bytes(), source_name=path.name)
        sites = collect_text_sites(doc)
        editable = sum(1 for s in sites
                       if doc.strings.raw[s.string_id].strip())
        if editable >= 12:
            return path
    pytest.skip("没有找到至少含 12 个可编辑文本位点的语料文件")


@pytest.fixture(scope="session")
def synthetic_psb() -> bytes:
    """用工具自身的编码器构造的最小合法 PSB v3 文档。"""
    from psbscn.formats import psb_spec as S
    from psbscn.formats.psb_codec import write_packed_table
    from psbscn.formats.psb_names import build_name_table
    from psbscn.formats.psb_header import PsbHeader
    from psbscn.formats.psb_strings import plan_string_section

    keys = [b"msg", b"name", b"scenes"]
    charset, tree, index = build_name_table(keys)
    names_blob = b"".join([
        write_packed_table(charset, 2, max(1, S.min_uint_width(max(charset)))),
        write_packed_table(tree, 2, max(1, S.min_uint_width(max(tree)))),
        write_packed_table(index, 1, max(1, S.min_uint_width(max(index)))),
    ])
    raw_strings = [b"hello", b"world"]
    str_offsets, str_blob = plan_string_section(raw_strings)

    # 根对象 {msg: "hello", name: "world"}，键 ID 分别为 0 和 1
    child_msg = bytes([S.T_STRING_BASE]) + b"\x00"
    child_name = bytes([S.T_STRING_BASE]) + b"\x01"
    key_tbl = write_packed_table([0, 1], 1, 1)
    off_tbl = write_packed_table([0, len(child_msg)], 1, 1)
    entries_blob = bytes([S.T_OBJECT]) + key_tbl + off_tbl + child_msg + child_name

    str_tbl = write_packed_table(str_offsets, 1,
                                 max(1, S.min_uint_width(max(str_offsets))))
    chunk = write_packed_table([], 1, 1)

    off_names = S.HEADER_LENGTH_V3
    off_entries = off_names + len(names_blob)
    off_strings = off_entries + len(entries_blob)
    off_strings_data = off_strings + len(str_tbl)
    off_chunk_offsets = off_strings_data + len(str_blob)
    off_chunk_lengths = off_chunk_offsets + len(chunk)
    off_chunk_data = off_chunk_lengths + len(chunk)
    header = PsbHeader(3, 0, S.HEADER_LENGTH_V3, off_names, off_strings,
                       off_strings_data, off_chunk_offsets, off_chunk_lengths,
                       off_chunk_data, off_entries, 0)
    header.checksum = header.computed_checksum()
    return (header.to_bytes() + names_blob + entries_blob + str_tbl + str_blob
            + chunk + chunk)


@pytest.fixture(scope="session")
def nested_language_psb() -> bytes:
    """含多语言嵌套 texts 的最小 PSB。

    形态取自 `*.ks.scn`：正文不在平铺槽位，而在 `texts[i][1][0]` 这个语言项里，
    结构为 `[显示名, 正文, 消息ID, 回想行, 检索行]`。回想行与检索行指向同一个
    字符串节点，用来验证去重与别名。
    """
    from psbscn.formats import psb_spec as S
    from psbscn.formats.psb_codec import write_packed_table
    from psbscn.formats.psb_names import build_name_table
    from psbscn.formats.psb_header import PsbHeader
    from psbscn.formats.psb_strings import plan_string_section

    keys = [b"scenes", b"texts", b"title"]
    charset, tree, index = build_name_table(keys)
    names_blob = b"".join([
        write_packed_table(charset, 2, max(1, S.min_uint_width(max(charset)))),
        write_packed_table(tree, 2, max(1, S.min_uint_width(max(tree)))),
        write_packed_table(index, 1, max(1, S.min_uint_width(max(index)))),
    ])
    # 0=场景标题 1=说话人 2=正文(带控制码) 3=回想行
    raw_strings = [b"prologue", b"\xe9\x9b\xaa", b"%n;hello", b"hello"]
    str_offsets, str_blob = plan_string_section(raw_strings)
    key_id = {name: i for i, name in enumerate(
        sorted(k.decode() for k in keys))}

    def s(i: int) -> bytes:
        return bytes([S.T_STRING_BASE]) + bytes([i])

    def coll(children: list[bytes]) -> bytes:
        offs, cur = [], 0
        for c in children:
            offs.append(cur)
            cur += len(c)
        tbl = write_packed_table(offs, 1, max(1, S.min_uint_width(max(offs, default=0))))
        return bytes([S.T_COLLECTION]) + tbl + b"".join(children)

    def obj(pairs: list[tuple[int, bytes]]) -> bytes:
        pairs = sorted(pairs)
        offs, cur = [], 0
        for _, v in pairs:
            offs.append(cur)
            cur += len(v)
        ktbl = write_packed_table([k for k, _ in pairs], 1, 1)
        otbl = write_packed_table(offs, 1, max(1, S.min_uint_width(max(offs, default=0))))
        return (bytes([S.T_OBJECT]) + ktbl + otbl
                + b"".join(v for _, v in pairs))

    null = bytes([S.T_NULL])
    lang_item = coll([null, s(2), bytes([S.T_INT_BASE]), s(3), s(3)])
    entry = coll([s(1), coll([lang_item]), null, bytes([S.T_INT_BASE]), null])
    scene = obj([(key_id["title"], s(0)),
                 (key_id["texts"], coll([entry]))])
    entries_blob = obj([(key_id["scenes"], coll([scene]))])

    str_tbl = write_packed_table(str_offsets, 1,
                                 max(1, S.min_uint_width(max(str_offsets))))
    chunk = write_packed_table([], 1, 1)
    off_names = S.HEADER_LENGTH_V3
    off_entries = off_names + len(names_blob)
    off_strings = off_entries + len(entries_blob)
    off_strings_data = off_strings + len(str_tbl)
    off_chunk_offsets = off_strings_data + len(str_blob)
    off_chunk_lengths = off_chunk_offsets + len(chunk)
    off_chunk_data = off_chunk_lengths + len(chunk)
    header = PsbHeader(3, 0, S.HEADER_LENGTH_V3, off_names, off_strings,
                       off_strings_data, off_chunk_offsets, off_chunk_lengths,
                       off_chunk_data, off_entries, 0)
    header.checksum = header.computed_checksum()
    return (header.to_bytes() + names_blob + entries_blob + str_tbl + str_blob
            + chunk + chunk)
