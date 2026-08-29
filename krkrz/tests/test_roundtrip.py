"""零编辑往返同一性与覆盖测试，覆盖真实语料。"""
from __future__ import annotations

import pytest

from psbscn.core.errors import ParseError, UnknownOpcodeError
from psbscn.core.types import ChangeSet
from psbscn.bytecode.repack import plan_and_repack
from psbscn.formats.psb_document import parse_document

from .conftest import corpus_files

CORPUS = corpus_files()
SUBSET = CORPUS[:24]


def test_合成样本往返(synthetic_psb):
    doc = parse_document(synthetic_psb, source_name="synthetic.scn")
    assert doc.to_bytes() == synthetic_psb
    assert doc.to_python() == {"msg": "hello", "name": "world"}


def test_合成样本覆盖精确(synthetic_psb):
    doc = parse_document(synthetic_psb)
    ledger = doc.build_ledger()
    info = ledger.analyze()
    assert info["gaps"] == []
    assert info["overlaps"] == []
    assert ledger.byte_coverage() == 1.0


@pytest.mark.parametrize("path", SUBSET, ids=lambda p: p.name)
def test_语料往返同一性(path):
    data = path.read_bytes()
    doc = parse_document(data, source_name=path.name)
    assert doc.to_bytes() == data


@pytest.mark.parametrize("path", SUBSET, ids=lambda p: p.name)
def test_语料零编辑回封(path):
    data = path.read_bytes()
    doc = parse_document(data, source_name=path.name)
    rebuilt, plan, report = plan_and_repack(doc, ChangeSet("x"))
    assert rebuilt == data
    assert report.edits_applied == 0
    assert plan.total_size == len(data)


@pytest.mark.parametrize("path", SUBSET, ids=lambda p: p.name)
def test_语料覆盖精确(path):
    data = path.read_bytes()
    doc = parse_document(data, source_name=path.name)
    ledger = doc.build_ledger()
    info = ledger.analyze()
    assert info["gaps"] == [], f"{path.name} 存在缺口"
    assert info["overlaps"] == [], f"{path.name} 存在重叠"
    assert ledger.byte_coverage() == 1.0
    assert all(r.raw_sha256 for r in ledger.regions)


@pytest.mark.parametrize("path", SUBSET[:8], ids=lambda p: p.name)
def test_值图是DAG(path):
    """共享子树是预期现象，但绝不能造成字节被双重归属。"""
    doc = parse_document(path.read_bytes(), source_name=path.name)
    parents = doc.graph.parent_map()
    shared = [off for off, ps in parents.items() if len(ps) > 1]
    owned: dict[int, int] = {}
    for node in doc.graph.iter_nodes():
        for i in range(node.offset, node.offset + node.size):
            assert i not in owned, f"{path.name} 中字节 0x{i:X} 被双重归属"
            owned[i] = node.offset
    if shared:
        assert doc.graph.shared_hits > 0


def test_未知类型字节报告偏移(synthetic_psb):
    data = bytearray(synthetic_psb)
    header = parse_document(bytes(data)).header
    data[header.offset_entries] = 0x7E
    with pytest.raises(UnknownOpcodeError) as exc:
        parse_document(bytes(data), strict=False)
    assert f"0x{header.offset_entries:X}" in str(exc.value)


def test_截断文件被拒绝(sample):
    data = sample.read_bytes()
    with pytest.raises((ParseError, IndexError, ValueError)):
        parse_document(data[:len(data) // 2], strict=False)
