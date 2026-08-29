"""占位符、DSAT 与严格导入测试。"""
from __future__ import annotations

import pytest

from psbscn.core.errors import PlaceholderError, TextImportError
from psbscn.text import placeholders
from psbscn.text.dsat import parse_dsat, render_dsat
from psbscn.text.importer import validate_dsat


@pytest.mark.parametrize("raw", [
    b"plain",
    b"",
    "日本語テキスト".encode("utf-8"),
    b"with\x01control",
    b"\x01\x02\x03run",
    b"trailing\x1f",
])
def test_占位符往返逐字节精确(raw):
    text = placeholders.encode(raw)
    assert placeholders.decode(text) == raw


def test_连续控制字节合并为一个占位符():
    assert placeholders.encode(b"\x01\x02x") == "{{01:02}}x"
    assert placeholders.decode("{{01:02}}x") == b"\x01\x02x"


def test_占位符拒绝小写():
    with pytest.raises(PlaceholderError, match="格式错误"):
        placeholders.decode("{{0a}}")


def test_占位符拒绝非十六进制():
    with pytest.raises(PlaceholderError, match="格式错误"):
        placeholders.decode("{{XY}}")


def test_占位符签名对顺序敏感():
    a = placeholders.signature("{{01}}x{{02}}")
    b = placeholders.signature("{{02}}x{{01}}")
    assert a[0] == b[0] and a[1] == b[1]
    assert a[2] != b[2]


def _rows():
    return [{
        "idx": 0, "file": "s.scn", "off": 0x100, "inst": 0x200, "tag": "msg",
        "source": "hello", "target": "hello", "encoding": "utf-8",
        "policy": "strict-preserve", "node_offset": 0x200, "string_id": 3,
        "path": "scenes[0].texts[0][2]", "speaker": "A",
        "speaker_confidence": "observed",
        "ph_count": 0, "ph_bytes": 0,
        "ph_hash": placeholders.signature("hello")[2],
        "ph_policy": "strict-preserve",
    }]


def _dsat(rows, sha="abc"):
    return render_dsat(rows, sample="s.scn", source_sha256=sha,
                       source_encoding="utf-8", target_encoding="utf-8",
                       ir_version="1.0.0")


def test_DSAT_生成与解析往返():
    rows = _rows()
    meta, units = parse_dsat(_dsat(rows))
    assert meta["source_sha256"] == "abc"
    assert len(units) == 1
    assert units[0].source == "hello" and units[0].tag == "msg"


def test_DSAT_保留内嵌换行():
    rows = _rows()
    rows[0]["source"] = rows[0]["target"] = "line1\nline2"
    text = _dsat(rows)
    assert "\\n" in text
    _, units = parse_dsat(text)
    assert units[0].source == "line1\nline2"


def test_导入接受未编辑内容():
    rows = _rows()
    check, changes = validate_dsat(_dsat(rows), rows, source_sha256="abc",
                                  sample="s.scn")
    assert check.ok and check.changed == 0 and check.unchanged == 1
    assert changes.is_empty()


def test_导入识别改动():
    rows = _rows()
    text = _dsat(rows).replace("●0●msg●hello", "●0●msg●bonjour")
    check, changes = validate_dsat(text, rows, source_sha256="abc",
                                   sample="s.scn")
    assert check.ok and check.changed == 1
    assert changes.edits[0]["target"] == "bonjour"


def test_导入拒绝错误的源哈希():
    rows = _rows()
    check, _ = validate_dsat(_dsat(rows, sha="deadbeef"), rows,
                             source_sha256="abc", sample="s.scn")
    assert not check.ok
    assert "source_sha256" in check.errors[0]["error"]


def test_导入拒绝被修改的原文行():
    rows = _rows()
    text = _dsat(rows).replace("○0○msg○hello", "○0○msg○tampered")
    check, _ = validate_dsat(text, rows, source_sha256="abc", sample="s.scn")
    assert not check.ok
    assert "只读" in check.errors[0]["error"]


def test_导入拒绝idx不一致():
    rows = _rows()
    text = _dsat(rows).replace("●0●msg●", "●1●msg●")
    with pytest.raises(TextImportError, match="idx 不一致"):
        validate_dsat(text, rows, source_sha256="abc", sample="s.scn")


def test_导入拒绝tag不一致():
    rows = _rows()
    text = _dsat(rows).replace("●0●msg●", "●0●name●")
    with pytest.raises(TextImportError, match="tag 不一致"):
        validate_dsat(text, rows, source_sha256="abc", sample="s.scn")


def test_导入拒绝被改动的元数据():
    rows = _rows()
    text = _dsat(rows).replace("inst=0x200", "inst=0x999")
    check, _ = validate_dsat(text, rows, source_sha256="abc", sample="s.scn")
    assert not check.ok
    assert "被改动" in check.errors[0]["error"]


def test_导入拒绝丢失的占位符():
    rows = _rows()
    rows[0]["source"] = rows[0]["target"] = "a{{01}}b"
    count, byte_count, digest = placeholders.signature("a{{01}}b")
    rows[0].update(ph_count=count, ph_bytes=byte_count, ph_hash=digest)
    text = _dsat(rows).replace("●0●msg●a{{01}}b", "●0●msg●ab")
    check, _ = validate_dsat(text, rows, source_sha256="abc", sample="s.scn")
    assert not check.ok
    assert "占位符" in check.errors[0]["error"]


def test_严格模式拒绝缺失条目():
    rows = _rows() + [dict(_rows()[0], idx=1)]
    text = _dsat(rows[:1])
    check, _ = validate_dsat(text, rows, source_sha256="abc", sample="s.scn")
    assert not check.ok
    strict_off, _ = validate_dsat(text, rows, source_sha256="abc",
                                  sample="s.scn", strict=False)
    assert strict_off.ok and strict_off.warnings


def test_导入拒绝无法编码的译文():
    rows = _rows()
    text = _dsat(rows).replace("●0●msg●hello", "●0●msg●日本語")
    check, _ = validate_dsat(text, rows, source_sha256="abc", sample="s.scn",
                             target_encoding="ascii")
    assert not check.ok
    assert "无法用 ascii 表示" in check.errors[0]["error"]


def test_多语言嵌套结构能取出正文(nested_language_psb):
    """正文放在 texts[i][1][0][1] 时也必须被取到。

    这是 `*.ks.scn` 的形态：平铺槽位 2 是 null，真正的台词在语言项里。漏掉这条分支
    会导致只抽出人名、一条正文都没有——而且不会报错。
    """
    from psbscn.bytecode.scenario import collect_text_sites
    from psbscn.formats.psb_document import parse_document

    doc = parse_document(nested_language_psb, source_name="nested.ks.scn")
    sites = collect_text_sites(doc)
    by_tag = {}
    for s in sites:
        by_tag.setdefault(s.tag, []).append(s)

    msgs = by_tag.get("msg", [])
    assert msgs, "多语言嵌套结构里的正文没有被取出"
    texts = {doc.string_text(s.string_id) for s in msgs}
    assert "%n;hello" in texts          # 语言项槽位 1：带控制码的显示文本
    assert "hello" in texts             # 语言项槽位 3：回想/检索行

    paths = {s.path for s in msgs}
    assert any("[1][0][1]" in p for p in paths), paths
    # 场景标题仍按 ui 取出，说明没有把平铺路径顶掉
    assert any(s.tag == "ui" for s in sites)


def test_嵌套结构每个节点只出一条条目(nested_language_psb):
    """一个物理字符串节点只能有一条可编辑条目，其余路径记为别名。

    真实文件里语言项的槽位 3 与 4 常指向同一节点（偏移表复用）；若按位点逐条导出，
    用户给两处填了不同译文时只有一处生效，另一处被静默丢弃。这里的合成夹具复现不了
    偏移表复用，因此只断言「无重复节点」这一半，共享去重由语料测试覆盖。
    """
    from psbscn.bytecode.ir import build_ir
    from psbscn.core.types import SourceArtifact
    from psbscn.formats.psb_document import parse_document
    from psbscn.services.decision import decide, probe

    doc = parse_document(nested_language_psb, source_name="nested.ks.scn")
    art = SourceArtifact("nested.ks.scn", len(nested_language_psb),
                         "0" * 64, "0" * 32, 0)
    ir = build_ir(doc, art, decide(probe(nested_language_psb,
                                        name="nested.ks.scn")))
    offsets = [e.node_offset for e in ir.text_entries]
    assert len(offsets) == len(set(offsets)), "同一节点出了多条可编辑条目"
    # 嵌套形态下显示文本与回想行是两个不同节点，因此两条都应可编辑
    assert sum(1 for e in ir.text_entries if e.tag == "msg") >= 2
