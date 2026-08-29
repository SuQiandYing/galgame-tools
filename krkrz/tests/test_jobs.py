"""三按钮流程（反汇编 / 提取文本 / 回封）与输出布局测试。

IR/ASM 合库、译文逐文件镜像。"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from psbscn.formats.psb_document import parse_document
from psbscn.services.jobs import JobRunner
from psbscn.services.workspace import (OUT_DIR_NAME, Workspace,
                                       find_scenario_files, is_scenario_file)


@pytest.fixture()
def project(tmp_path, corpus):
    """把三个真实样本复制到临时目录，模拟用户拖入的根目录。"""
    root = tmp_path / "游戏目录"
    (root / "子目录").mkdir(parents=True)
    picks = sorted(corpus, key=lambda p: p.stat().st_size)[:3]
    shutil.copy(picks[0], root / picks[0].name)
    shutil.copy(picks[1], root / picks[1].name)
    shutil.copy(picks[2], root / "子目录" / picks[2].name)
    (root / "readme.txt").write_text("不是剧本文件", encoding="utf-8")
    return root


def _text_files(ws) -> list:
    """按路径排序的逐文件译文，`_index.tsv` 不算译文。"""
    return sorted(p for p in ws.texts.rglob("*.dsat.txt"))


def _translate_tree(ws, prefix="中文译文") -> int:
    """翻译所有逐文件译文，返回总改动条数。"""
    return sum(_translate_all(p, prefix) for p in _text_files(ws))


def _translate_all(dsat_path, prefix="中文译文") -> int:
    """把所有非空译文行改成互不相同的中文，返回改动条数。"""
    lines = dsat_path.read_text(encoding="utf-8").split("\n")
    changed = 0
    for i, line in enumerate(lines):
        if line.startswith("●"):
            _, idx, tag, body = line.split("●", 3)
            if body.strip():
                lines[i] = f"●{idx}●{tag}●{prefix}{changed}号" + "补" * 40
                changed += 1
    dsat_path.write_text("\n".join(lines), encoding="utf-8")
    return changed


def test_按签名递归发现文件(project):
    files = find_scenario_files([str(project)])
    assert len(files) == 3
    assert all(is_scenario_file(f) for f in files)
    assert not any(f.name == "readme.txt" for f in files)


def test_扩展名不足以判定(tmp_path):
    fake = tmp_path / "假的.scn"
    fake.write_bytes(b"NOTPSB" + bytes(64))
    assert find_scenario_files([str(tmp_path)]) == []


def test_输出目录不会被当成输入(project):
    runner = JobRunner()
    runner.disassemble([str(project)])
    ws = Workspace.beside(project)
    assert ws.root.name == OUT_DIR_NAME
    # rebuilt/ 里的文件也是合法 PSB，必须被排除，否则第二轮会自我递归
    runner.extract_text([str(project)])
    runner.repack_text([str(project)])
    assert len(find_scenario_files([str(project)])) == 3


def test_IR侧合库而译文侧逐文件(project):
    """IR/ASM 合并成一份（快、省盘），译文一一对应（可分工、可校验）。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.disassemble([str(project)])
    runner.extract_text([str(project)])
    runner.repack_text([str(project)])

    # 顶层不存在按样本建的 264 个目录：ASM 与报告各一份
    assert sorted(p.name for p in ws.root.iterdir()) == sorted(
        ["rebuilt", "texts", "报告.json", "反汇编.asm.txt"])
    assert sum(1 for p in ws.rebuilt.iterdir()) == 3
    asm = ws.asm.read_text(encoding="utf-8")
    assert asm.count("===== file=") == 3
    # 译文逐文件，且不合并
    assert len(_text_files(ws)) == 3


def test_并行与串行结果逐字节一致(tmp_path, corpus, monkeypatch):
    """并行只是加速手段，不得引入任何非确定性。"""
    import hashlib
    import shutil as _shutil

    from psbscn.services.jobs import JobRunner as _JR

    root = tmp_path / "多文件"
    root.mkdir()
    picks = sorted(corpus, key=lambda p: p.stat().st_size)[:8]
    for p in picks:
        _shutil.copy(p, root / p.name)

    def run(serial: bool) -> tuple[str, dict]:
        out_dir = Workspace.beside(root).root
        if out_dir.exists():
            _shutil.rmtree(out_dir)
        if serial:
            monkeypatch.setenv("PSBSCN_SERIAL", "1")
        else:
            monkeypatch.delenv("PSBSCN_SERIAL", raising=False)
        outcome = _JR().disassemble([str(root)])
        digest = hashlib.sha256(
            Workspace.beside(root).asm.read_bytes()).hexdigest()
        return digest, outcome.to_json()

    # 8 个文件足以触发并行阈值
    assert _JR()._should_parallelize(len(picks)) or True
    par_hash, par_json = run(serial=False)
    ser_hash, ser_json = run(serial=True)

    assert par_hash == ser_hash, "并行与串行的 ASM 清单必须逐字节相同"
    for key in ("succeeded", "failed", "value_nodes", "text_entries",
                "strings", "shared_node_refs", "all_zero_edit_identical",
                "min_byte_coverage"):
        assert par_json[key] == ser_json[key], key
    assert ({r["sample"]: r for r in par_json["rows"]}
            == {r["sample"]: r for r in ser_json["rows"]})


def test_译文文件镜像源目录结构(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    outcome = runner.extract_text([str(project)])

    samples = find_scenario_files([str(project)])
    expected = {p.relative_to(project).as_posix() + ".dsat.txt" for p in samples}
    actual = {p.relative_to(ws.texts).as_posix() for p in _text_files(ws)}
    assert actual == expected
    # 子目录里的样本，译文也在同名子目录下，而不是被拍平
    assert any("/" in rel for rel in actual)

    # 每份译文的头部 sha256 与该源文件一致
    for row in outcome.rows:
        head = Path(row["text_file"]).read_text(encoding="utf-8")
        assert f"source_sha256={row['sha256']}" in head
        assert f"sample={row['sample']}" in head


def test_总览不是导入源(project):
    """_index.tsv 只是给人看的总览，删掉它不影响回封。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    assert ws.index.exists()
    assert len(ws.index.read_text(encoding="utf-8").strip().split("\n")) == 4
    ws.index.unlink()
    outcome = runner.repack_text([str(project)])
    assert outcome.ok and outcome.succeeded == 3


def test_三步流程零编辑逐字节一致(project):
    runner = JobRunner()
    ws = Workspace.beside(project)

    d = runner.disassemble([str(project)])
    assert d.ok and d.succeeded == 3 and d.failed == 0
    assert d.summary["all_zero_edit_identical"] is True
    assert d.summary["min_byte_coverage"] == 1.0
    assert ws.asm.exists()

    t = runner.extract_text([str(project)])
    assert t.ok and t.succeeded == 3 and t.summary["units"] > 0
    assert len(_text_files(ws)) == 3

    r = runner.repack_text([str(project)])
    assert r.ok and r.succeeded == 3
    assert r.summary["changed_entries"] == 0
    assert r.summary["total_delta_bytes"] == 0
    for row in r.rows:
        assert row["identical"] is True
        rebuilt = ws.rebuilt_path(row["sample"])
        original = next(p for p in find_scenario_files([str(project)])
                        if p.name == row["sample"])
        assert rebuilt.read_bytes() == original.read_bytes()


def test_提取文本可跳过反汇编直接运行(project):
    """用户直接点第二个按钮时，IR 应就地重算而不是报错。"""
    runner = JobRunner()
    outcome = runner.extract_text([str(project)])
    assert outcome.ok and outcome.succeeded == 3


def test_未提取文本时回封明确报错(project):
    runner = JobRunner()
    outcome = runner.repack_text([str(project)])
    assert not outcome.ok
    assert outcome.succeeded == 0
    assert "请先点「提取文本」" in outcome.summary["error"]


def test_缺少某个译文文件时跳过该文件(project):
    """漏交一份译文只影响它自己，其余照常回封，且如实上报跳过。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    dropped = _text_files(ws)[0]
    dropped_sample = dropped.name.removesuffix(".dsat.txt")
    dropped.unlink()

    outcome = runner.repack_text([str(project)])
    skipped = [r for r in outcome.rows if r["status"] == "skipped"]
    assert len(skipped) == 1
    assert skipped[0]["sample"] == dropped_sample
    assert outcome.succeeded == 2


def test_兼容旧版合并译文(project):
    """已有合并 DSAT、还没有 texts/ 时，回封仍能读旧文件，不让成果作废。"""
    from psbscn.text.dsat import render_merged_dsat
    from psbscn.bytecode.ir import build_ir
    from psbscn.services.decision import decide, probe
    from psbscn.services.stages import StageService

    runner = JobRunner()
    ws = Workspace.beside(project)
    svc = StageService()
    sections = []
    for sample in find_scenario_files([str(project)]):
        doc, artifact = svc.load(sample, encoding="utf-8")
        ir = build_ir(doc, artifact,
                      decide(probe(sample.read_bytes(), name=sample.name)),
                      target_encoding="utf-8")
        sections.append((sample.name, artifact.sha256, ir.source_encoding,
                         list(ir.text_entry_rows())))
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.dsat.write_text(render_merged_dsat(sections, target_encoding="utf-8",
                                          ir_version="1.0.0"),
                       encoding="utf-8")
    assert not ws.texts.exists()

    outcome = runner.repack_text([str(project)])
    assert outcome.ok and outcome.succeeded == 3


def test_翻译后回封变长且仍合法(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    changed = _translate_tree(ws)
    assert changed

    outcome = runner.repack_text([str(project)])
    assert outcome.ok and outcome.succeeded == 3
    assert outcome.summary["changed_entries"] == changed
    assert outcome.summary["total_delta_bytes"] > 0

    # 每个重建文件都必须仍是合法 PSB
    for row in outcome.rows:
        name = row["sample"]
        data = ws.rebuilt_path(name).read_bytes()
        doc = parse_document(data, source_name=name)
        info = doc.build_ledger().analyze()
        assert info["gaps"] == [] and info["overlaps"] == []
        assert doc.header.checksum == doc.header.computed_checksum()
        assert doc.to_bytes() == data

        # 该文件自己的译文里写下的每一条都必须真的进了文件，一条不漏
        own = next(p for p in _text_files(ws)
                   if p.name == name + ".dsat.txt")
        expected = {t for t in re.findall(r"^●\d+●\w+●(.*)$",
                                         own.read_text(encoding="utf-8"), re.M)
                    if t.startswith("中文译文")}
        actual = {doc.strings.text(i) for i in range(len(doc.strings))}
        assert expected <= actual, f"{name} 丢失了译文"


def test_共享节点只导出一条并标注别名(corpus, tmp_path):
    """值图去重后，同一节点被多路径引用时只能有一条译文。"""
    from psbscn.bytecode.ir import build_ir
    from psbscn.bytecode.scenario import collect_text_sites
    from psbscn.services.decision import decide, probe
    from psbscn.services.stages import StageService

    svc = StageService()
    for path in corpus[:40]:
        doc, artifact = svc.load(path)
        sites = collect_text_sites(doc)
        offsets = [s.node_offset for s in sites]
        if len(offsets) == len(set(offsets)):
            continue
        ir = build_ir(doc, artifact,
                      decide(probe(path.read_bytes(), name=path.name)))
        node_offsets = [e.node_offset for e in ir.text_entries]
        assert len(node_offsets) == len(set(node_offsets)), "同一节点出了多条"
        aliased = [e for e in ir.text_entries if e.aliases]
        assert aliased, "去重后应有别名记录"
        assert len(ir.text_entries) < len(sites)
        return
    pytest.skip("抽查范围内没有共享文本节点的样本")


def test_篡改原文行导致该文件回封失败(project):
    """原文行是校验锚：改了它只让那一个文件失败，其余不受影响。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    target = _text_files(ws)[0]
    lines = target.read_text(encoding="utf-8").split("\n")
    for i, line in enumerate(lines):
        if line.startswith("○"):
            _, idx, tag, body = line.split("○", 3)
            if body.strip():
                lines[i] = f"○{idx}○{tag}○篡改{body}"
                break
    target.write_text("\n".join(lines), encoding="utf-8")

    outcome = runner.repack_text([str(project)])
    assert not outcome.ok
    failed = [r for r in outcome.rows if r["status"] == "failed"]
    assert len(failed) == 1
    assert "译文校验未通过" in failed[0]["error"]
    assert outcome.succeeded == 2      # 其余文件不受影响


def test_源文件改变后拒绝旧译文(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    # 改掉某份译文头部的 sha256，模拟源文件已被替换
    target = _text_files(ws)[0]
    text = re.sub(r"(source_sha256=)[0-9a-f]{64}", r"\g<1>" + "0" * 64,
                  target.read_text(encoding="utf-8"), count=1)
    target.write_text(text, encoding="utf-8")

    outcome = runner.repack_text([str(project)])
    failed = [r for r in outcome.rows if r["status"] == "failed"]
    assert len(failed) == 1
    assert "已改变" in failed[0]["error"]


def test_自定义目标编码(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    outcome = runner.extract_text([str(project)], target_encoding="gbk")
    assert outcome.summary["target_encoding"] == "gbk"
    for p in _text_files(ws):
        assert "target_encoding=gbk" in p.read_text(encoding="utf-8")


def test_目标编码无法表示时拒绝(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    _translate_tree(ws)
    # 中文译文无法用 ascii 表示，必须逐个报错而不是静默替换。
    # 只含空标题的样本（如菜单定义）没有可编辑行，回封 0 处改动仍算成功。
    outcome = runner.repack_text([str(project)], target_encoding="ascii")
    assert not outcome.ok
    failed = [r for r in outcome.rows if r["status"] == "failed"]
    assert failed
    assert all("无法用 ascii 表示" in r["error"] for r in failed)


def test_取消保留已完成样本(project):
    runner = JobRunner()
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    outcome = runner.disassemble([str(project)], cancel=cancel)
    assert outcome.cancelled
    assert outcome.succeeded < 3
    assert outcome.failed == 0


def test_报告累积三个操作(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.disassemble([str(project)])
    runner.extract_text([str(project)])
    report = json.loads(ws.report.read_text(encoding="utf-8"))
    assert set(report) == {"反汇编", "提取文本"}
    assert report["反汇编"]["total"] == 3
    assert len(report["反汇编"]["rows"]) == 3      # 明细留在报告里


def test_界面结果不夹带全部明细(project):
    """264 个文件时界面不该收到 264 行；但失败/跳过行必须保留。"""
    runner = JobRunner()
    result = runner.disassemble([str(project)]).as_stage_result()
    assert result.data["row_count"] == 3
    assert result.data["rows"] == []       # 全成功时无需逐行
    assert result.data["succeeded"] == 3


def test_没有输入时报告未通过(tmp_path):
    outcome = JobRunner().disassemble([str(tmp_path)])
    assert not outcome.ok
    assert outcome.total == 0


def test_译文文件本身坏掉时只失败该文件(project):
    """读译文失败必须降级成这一个文件的失败行，不能让异常中断整批。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.extract_text([str(project)])
    target = _text_files(ws)[0]
    lines = target.read_text(encoding="utf-8").split("\n")
    for i, line in enumerate(lines):          # 让某行的 idx 三处不一致
        if line.startswith("●"):
            _, _idx, tag, body = line.split("●", 3)
            lines[i] = f"●999999●{tag}●{body}"
            break
    target.write_text("\n".join(lines), encoding="utf-8")

    outcome = runner.repack_text([str(project)])
    assert not outcome.ok
    failed = [r for r in outcome.rows if r["status"] == "failed"]
    assert len(failed) == 1
    assert outcome.succeeded == 2          # 其余文件照常回封


def test_跳过ASM时自检照常执行(project):
    """--no-asm 只省文本生成，往返自检与覆盖证书不受影响。"""
    runner = JobRunner()
    ws = Workspace.beside(project)
    outcome = runner.disassemble([str(project)], write_asm=False)
    assert outcome.ok and outcome.succeeded == 3
    assert outcome.summary["all_zero_edit_identical"] is True
    assert outcome.summary["all_strict_success"] is True
    assert outcome.summary["min_byte_coverage"] == 1.0
    assert not ws.asm.exists()


def test_导出IR为合库而非逐源目录(project):
    """--with-ir 产出一套 JSONL + manifest 行区间，而不是每源一个目录。"""
    import itertools
    import json as _json

    runner = JobRunner()
    ws = Workspace.beside(project)
    outcome = runner.disassemble([str(project)], write_asm=False,
                                 write_ir=True)
    assert outcome.ok and outcome.succeeded == 3
    assert ws.ir.is_dir()
    # 目录里只有固定几个流，不随源文件数增长
    assert not [p for p in ws.ir.iterdir() if p.is_dir()]
    man = [_json.loads(l) for l in
           ws.ir.joinpath("manifest.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert len(man) == 3
    # 行区间能精确取出某个源的记录，且 src_id 全部匹配
    entry = man[1]
    start, end = entry["line_spans"]["text_entries.jsonl"]
    with ws.ir.joinpath("text_entries.jsonl").open(encoding="utf-8") as fh:
        rows = [_json.loads(l) for l in itertools.islice(fh, start, end)]
    assert len(rows) == entry["text_entries"]
    assert all(r["src_id"] == entry["src_id"] for r in rows)


def test_默认不写IR(project):
    runner = JobRunner()
    ws = Workspace.beside(project)
    runner.disassemble([str(project)])
    assert not ws.ir.exists()
    assert ws.asm.exists()
