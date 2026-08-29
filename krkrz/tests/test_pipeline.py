"""阶段服务、重定位与证书测试，针对真实语料文件。"""
from __future__ import annotations

import json

import pytest

from psbscn.core.errors import InPlaceOverflowError, VerifyError
from psbscn.formats.psb_document import parse_document
from psbscn.services.stages import StageService

from .conftest import corpus_files

CORPUS = corpus_files()


@pytest.fixture()
def svc() -> StageService:
    return StageService()


def test_探测与决策(svc, sample):
    result = svc.probe(sample)
    assert result.ok
    assert result.data["claim"]["score"] == 1.0
    decision = result.data["decision"]
    assert decision["disasm_required"] is True
    assert decision["unpack_mode"] == "not-required"


def test_探测拒绝非PSB文件(svc, tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"NOTPSB" + bytes(128))
    result = svc.probe(junk)
    assert not result.ok
    assert "signature-mismatch" in result.data["claim"]["conflicts"]


def test_解析写出模型与区间表(svc, sample, tmp_path):
    result = svc.parse(sample, tmp_path)
    assert result.ok
    assert result.data["coverage"]["byte_coverage"] == 1.0
    model = json.loads((tmp_path / "psb_model.json").read_text("utf-8"))
    assert model["header"]["checksum_ok"] is True
    assert (tmp_path / "region_map.jsonl").stat().st_size > 0


def test_反汇编后导出再导入(svc, sample, tmp_path):
    ir = tmp_path / "ir"
    svc.disasm(sample, ir)
    entries = (ir / "text_entries.jsonl").read_text("utf-8").strip().split("\n")
    assert entries and entries[0]
    texts = svc.export_text(ir, tmp_path / "texts")
    dsat = texts.artifacts["dsat"]
    check = svc.import_text(ir, dsat, tmp_path / "patched")
    assert check.ok
    assert check.data["changed"] == 0
    assert check.data["accepted"] == texts.data["units"]


def test_零编辑往返门禁(svc, sample, tmp_path):
    result = svc.smoke_roundtrip(sample, tmp_path)
    assert result.ok
    for key in ("zero_edit_identical", "sha256_match", "md5_match",
                "crc32_match", "parse_repack_parse_stable",
                "canonical_ir_stable"):
        assert result.data[key] is True


def test_往返门禁能捕获损坏(svc, sample, tmp_path):
    """值区中翻转一个字节必须被捕获，不能被掩盖。"""
    data = bytearray(sample.read_bytes())
    header = parse_document(bytes(data)).header
    data[header.offset_entries + 1] ^= 0xFF
    broken = tmp_path / "broken.scn"
    broken.write_bytes(bytes(data))
    with pytest.raises(Exception):
        svc.smoke_roundtrip(broken, tmp_path)


def test_证书严格通过(svc, sample, tmp_path):
    result = svc.certificate(sample, tmp_path)
    assert result.ok
    cert = json.loads((tmp_path / "coverage_certificate.json").read_text("utf-8"))
    assert cert["byte_coverage"] == 1.0
    assert cert["instruction_coverage"] == 1.0
    assert cert["gaps"] == [] and cert["overlaps"] == []
    assert cert["strict_success"] is True
    assert cert["roundtrip"]["zero_edit_identical"] is True
    assert cert["value_graph"]["topology"] == "dag-with-shared-subtrees"
    assert cert["intervals"][0]["start"] == 0
    assert cert["intervals"][-1]["end"] == cert["source_size"]


def test_证书区间连续无缺口(svc, sample, tmp_path):
    svc.certificate(sample, tmp_path)
    cert = json.loads((tmp_path / "coverage_certificate.json").read_text("utf-8"))
    cursor = 0
    for interval in cert["intervals"]:
        assert interval["start"] == cursor, "证书中存在缺口或重叠"
        cursor = interval["end"]
    assert cursor == cert["source_size"]


def test_零编辑回封与验证(svc, sample, tmp_path):
    out = tmp_path / "rebuilt.scn"
    svc.repack(sample, out)
    result = svc.verify(sample, out, tmp_path)
    assert result.ok
    assert result.data["sha256_match"] and result.data["md5_match"]
    assert result.data["crc32_match"]


def _grow_dsat(text: str, prefix: str, limit: int) -> str:
    lines = text.split("\n")
    done = 0
    for i, line in enumerate(lines):
        if line.startswith("●") and done < limit:
            _, idx, tag, body = line.split("●", 3)
            if body.strip():
                lines[i] = f"●{idx}●{tag}●{prefix}{body}"
                done += 1
    assert done, "未找到可编辑的译文行"
    return "\n".join(lines)


def test_变长重定位(svc, text_sample, tmp_path):
    """译文长度超过原文两倍时必须能干净地重定位。"""
    sample = text_sample
    ir = tmp_path / "ir"
    svc.disasm(sample, ir)
    dsat = svc.export_text(ir, tmp_path / "texts").artifacts["dsat"]
    original = open(dsat, encoding="utf-8").read()
    edited = tmp_path / "edited.dsat.txt"
    edited.write_text(_grow_dsat(original, "X" * 120, 12), encoding="utf-8")

    imported = svc.import_text(ir, edited, tmp_path / "patched")
    assert imported.ok, imported.messages
    assert imported.data["changed"] == 12
    changeset = imported.artifacts["changeset.json"]

    out = tmp_path / "grown.scn"
    repacked = svc.repack(sample, out, changeset=changeset,
                          log_dir=tmp_path / "logs")
    assert repacked.data["output_size"] > repacked.data["source_size"]

    # 变长后的文件必须仍是合法 PSB，且覆盖依旧精确。
    doc = parse_document(out.read_bytes(), source_name=out.name)
    ledger = doc.build_ledger()
    info = ledger.analyze()
    assert info["gaps"] == [] and info["overlaps"] == []
    assert doc.header.checksum == doc.header.computed_checksum()
    assert doc.to_bytes() == out.read_bytes()
    values = [doc.strings.text(i) for i in range(len(doc.strings))]
    assert sum(1 for v in values if v.startswith("X" * 120)) == 12


def test_原地模式拒绝超长(svc, text_sample, tmp_path):
    sample = text_sample
    ir = tmp_path / "ir"
    svc.disasm(sample, ir)
    dsat = svc.export_text(ir, tmp_path / "texts").artifacts["dsat"]
    edited = tmp_path / "edited.dsat.txt"
    edited.write_text(
        _grow_dsat(open(dsat, encoding="utf-8").read(), "Y" * 200, 1),
        encoding="utf-8")
    changeset = svc.import_text(ir, edited, tmp_path / "p").artifacts["changeset.json"]
    with pytest.raises(InPlaceOverflowError, match="原槽位"):
        svc.repack(sample, tmp_path / "x.scn", changeset=changeset,
                   mode="in_place")


def test_变更集绑定源哈希(svc, text_sample, tmp_path, corpus):
    sample = text_sample
    other = next(p for p in corpus if p != sample)
    ir = tmp_path / "ir"
    svc.disasm(sample, ir)
    dsat = svc.export_text(ir, tmp_path / "texts").artifacts["dsat"]
    edited = tmp_path / "e.dsat.txt"
    edited.write_text(_grow_dsat(open(dsat, encoding="utf-8").read(), "Z", 1),
                      encoding="utf-8")
    changeset = svc.import_text(ir, edited, tmp_path / "p").artifacts["changeset.json"]
    with pytest.raises(VerifyError, match="构建的"):
        svc.repack(other, tmp_path / "y.scn", changeset=changeset)


def test_批处理汇总(svc, corpus, tmp_path):
    result = svc.batch_disasm([str(p) for p in corpus[:6]], tmp_path,
                              export_asm=False, export_text=False)
    assert result.ok
    assert result.data["ok"] == 6
    assert result.data["all_zero_edit_identical"] is True
    assert result.data["all_strict_success"] is True


def test_批处理取消保持干净(svc, corpus, tmp_path):
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    result = svc.batch_disasm([str(p) for p in corpus[:6]], tmp_path,
                              export_asm=False, export_text=False,
                              certificate=False, cancel=cancel)
    assert result.data["samples"] == 6
    assert result.data["ok"] < 6


def test_重复运行确定性(svc, sample, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    svc.certificate(sample, a)
    svc.certificate(sample, b)
    ca = json.loads((a / "coverage_certificate.json").read_text("utf-8"))
    cb = json.loads((b / "coverage_certificate.json").read_text("utf-8"))
    for cert in (ca, cb):
        cert.pop("toolchain", None)
    assert ca == cb
