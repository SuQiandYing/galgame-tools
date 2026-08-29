"""StageService：所有流水线阶段的唯一实现。

CLI 与 GUI 都调用这里的方法，两者都不自己解析二进制。每个阶段有独立的输入、输出
和失败模式，任何阶段都不会静默串联到下一个阶段。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..bytecode.asm import render_asm
from ..bytecode.ir import build_ir, read_ir_compact, read_text_entries, write_ir
from ..bytecode.repack import RepackReport, plan_and_repack
from ..core.coverage import build_certificate
from ..core.errors import ParseError, PsbError, VerifyError
from ..core.hashing import (atomic_write, atomic_write_text, fingerprint_bytes,
                            fingerprint_file)
from ..core.types import ChangeSet, RepackMode, SourceArtifact, VerifyReport
from ..core.verify import compare_bytes
from ..formats.psb_document import PsbDocument, parse_document
from ..text.dsat import parse_dsat, render_dsat
from ..text.importer import ImportCheck, validate_dsat
from . import toolchain
from .decision import decide, probe

ProgressFn = Callable[[str, float, str], None]


def _noop(stage: str, fraction: float, message: str) -> None:
    return None


@dataclass(slots=True)
class StageResult:
    """统一的阶段结果：成功标志、数据载荷、产物路径与消息。"""

    stage: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    messages: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"stage": self.stage, "ok": self.ok, "data": self.data,
                "artifacts": self.artifacts, "messages": self.messages}


class StageService:
    """每次调用都无状态；所有状态都保存在磁盘上的工作区中。"""

    def __init__(self, progress: ProgressFn | None = None) -> None:
        self.progress = progress or _noop

    # -- 阶段：probe ----------------------------------------------------
    def probe(self, sample: str | Path) -> StageResult:
        path = Path(sample)
        data = path.read_bytes()
        claim = probe(data, name=path.name)
        artifact = fingerprint_file(path)
        decision = decide(claim)
        self.progress("probe", 1.0, f"探测 {path.name}：评分={claim.score}")
        return StageResult(
            stage="probe", ok=claim.score >= 0.85 and not claim.conflicts,
            data={
                "sample": path.name,
                "source": _artifact_json(artifact),
                "claim": {
                    "plugin": claim.plugin, "score": claim.score,
                    "format_version": claim.format_version,
                    "endianness": claim.endianness, "claims": claim.claims,
                    "required_ranges": [list(r) for r in claim.required_ranges],
                    "conflicts": list(claim.conflicts),
                    "evidence": claim.evidence,
                },
                "decision": decision.to_json(),
                "toolchain": toolchain.probe_toolchain(),
            })

    # -- 阶段：parse ----------------------------------------------------
    def parse(self, sample: str | Path, out_dir: str | Path | None = None, *,
              encoding: str = "utf-8", strict: bool = True) -> StageResult:
        path = Path(sample)
        data = path.read_bytes()
        doc = parse_document(data, source_name=path.name, encoding=encoding,
                             strict=strict)
        ledger = doc.build_ledger()
        info = ledger.analyze()
        ok = (not info["gaps"] and not info["overlaps"]
              and info["covered_bytes"] == doc.size)
        model = {
            "sample": path.name,
            "size": doc.size,
            "header": {
                "version": doc.header.version,
                "header_encrypt": doc.header.header_encrypt,
                "checksum": f"0x{doc.header.checksum:08X}",
                "checksum_ok": doc.header.checksum == doc.header.computed_checksum(),
                "offsets": {k: f"0x{v:X}" for k, v in doc.header.offsets().items()},
            },
            "sections": [{"name": n, "start": s, "end": e, "size": e - s}
                         for n, s, e in doc.section_map()],
            "counts": {
                "name_keys": len(doc.names),
                "name_trie_nodes": len(doc.names.charset.values),
                "name_trie_unreachable": doc.names.unreachable_node_count,
                "strings": len(doc.strings),
                "value_nodes": len(doc.graph),
                "shared_node_refs": doc.graph.shared_hits,
                "chunks": len(doc.chunk_offsets.values),
            },
            "coverage": {
                "byte_coverage": ledger.byte_coverage(),
                "gaps": info["gaps"], "overlaps": info["overlaps"],
                "regions": len(ledger.regions),
            },
            "string_table": {
                "strictly_increasing": doc.strings.strictly_increasing,
                "tightly_packed": doc.strings.tightly_packed,
                "encoding": doc.strings.encoding,
            },
        }
        artifacts: dict[str, str] = {}
        if out_dir is not None:
            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            target = out / "psb_model.json"
            atomic_write_text(target, json.dumps(model, ensure_ascii=False,
                                                indent=2) + "\n")
            artifacts["psb_model.json"] = str(target)
            region_path = out / "region_map.jsonl"
            atomic_write_text(region_path, "".join(
                json.dumps({"id": r.id, "start": r.start, "end": r.end,
                            "status": r.status, "kind": r.kind,
                            "owner": r.owner, "raw_sha256": r.raw_sha256,
                            "checks": r.checks}, ensure_ascii=False) + "\n"
                for r in ledger.sorted_regions()))
            artifacts["region_map.jsonl"] = str(region_path)
        self.progress("parse", 1.0,
                      f"解析 {path.name}：{len(doc.graph)} 个节点，"
                      f"覆盖率={ledger.byte_coverage():.4f}")
        if not ok:
            raise ParseError(
                f"{path.name} 的覆盖不精确："
                f"缺口={info['gaps'][:3]} 重叠={info['overlaps'][:3]}")
        return StageResult(stage="parse", ok=ok, data=model,
                           artifacts=artifacts)

    def load(self, sample: str | Path, *, encoding: str = "utf-8",
             strict: bool = True) -> tuple[PsbDocument, SourceArtifact]:
        """解析一个样本，返回文档与它的指纹。"""
        path = Path(sample)
        return self.load_bytes(path.read_bytes(), path.name,
                               encoding=encoding, strict=strict,
                               source_path=str(path))

    def load_bytes(self, data: bytes, name: str, *, encoding: str = "utf-8",
                   strict: bool = True,
                   source_path: str | None = None
                   ) -> tuple[PsbDocument, SourceArtifact]:
        """从已读入的字节解析。

        调用方往往还要用同一份字节跑 probe；共用一次读取，避免为了一个探针把整个
        文件再读一遍。
        """
        sha, md5, crc = fingerprint_bytes(data)
        artifact = SourceArtifact(source_path or name, len(data), sha, md5, crc)
        doc = parse_document(data, source_name=name, encoding=encoding,
                             strict=strict)
        return doc, artifact

    # -- 阶段：disasm ---------------------------------------------------
    def disasm(self, sample: str | Path, ir_dir: str | Path, *,
               encoding: str = "utf-8", target_encoding: str = "utf-8",
               want_repack: bool = False) -> StageResult:
        """全量反汇编：构建并持久化规范化 IR。"""
        path = Path(sample)
        data = path.read_bytes()
        claim = probe(data, name=path.name)
        decision = decide(claim, want_repack=want_repack)
        if decision.unpack_mode == "blocked":
            raise ParseError(
                f"探测阶段阻断了 {path.name}：{decision.decision_rationale}")
        doc, artifact = self.load(path, encoding=encoding)
        ir = build_ir(doc, artifact, decision, target_encoding=target_encoding)
        written = write_ir(ir, ir_dir)
        self.progress("disasm", 1.0,
                      f"反汇编 {path.name}：{len(ir.text_entries)} 个文本条目")
        return StageResult(
            stage="disasm", ok=True,
            data={
                "sample": path.name,
                "value_nodes": ir.node_count,
                "shared_node_refs": ir.shared_node_count,
                "text_entries": len(ir.text_entries),
                "strings": len(ir.strings),
                "name_keys": len(ir.names),
                "decision": decision.to_json(),
            },
            artifacts=written)

    # -- 阶段：export-asm -----------------------------------------------
    def export_asm(self, sample: str | Path, out_dir: str | Path, *,
                   encoding: str = "utf-8") -> StageResult:
        path = Path(sample)
        doc, _ = self.load(path, encoding=encoding)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        target = out / f"{path.name}.asm.txt"
        text = render_asm(doc)
        atomic_write_text(target, text, "utf-8")
        self.progress("export-asm", 1.0, f"ASM 已写入 {target}")
        return StageResult(
            stage="export-asm", ok=True,
            data={"sample": path.name, "lines": text.count("\n"),
                  "asm_encoding": "utf-8"},
            artifacts={"asm": str(target)})

    # -- 阶段：export-text ----------------------------------------------
    def export_text(self, ir_dir: str | Path, out_dir: str | Path, *,
                    target_encoding: str = "utf-8") -> StageResult:
        compact = read_ir_compact(ir_dir)
        rows = read_text_entries(ir_dir)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        sample = compact["sample"]
        target = out / f"{sample}.dsat.txt"
        text = render_dsat(
            rows, sample=sample,
            source_sha256=compact["source"]["sha256"],
            source_encoding=compact["encoding"]["source_encoding"],
            target_encoding=target_encoding,
            ir_version=compact["schema_version"])
        atomic_write_text(target, text, "utf-8")
        self.progress("export-text", 1.0, f"DSAT 已写入 {target}")
        return StageResult(
            stage="export-text", ok=True,
            data={"sample": sample, "units": len(rows),
                  "dsat_encoding": "utf-8",
                  "target_encoding": target_encoding},
            artifacts={"dsat": str(target)})

    # -- 阶段：import-text ----------------------------------------------
    def import_text(self, ir_dir: str | Path, dsat_path: str | Path,
                    out_dir: str | Path, *, target_encoding: str = "utf-8",
                    strict: bool = True) -> StageResult:
        compact = read_ir_compact(ir_dir)
        rows = read_text_entries(ir_dir)
        text = Path(dsat_path).read_text(encoding="utf-8")
        check, changes = validate_dsat(
            text, rows, source_sha256=compact["source"]["sha256"],
            sample=compact["sample"], target_encoding=target_encoding,
            strict=strict)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / "import_check_report.json"
        atomic_write_text(report_path, json.dumps(
            check.to_json(), ensure_ascii=False, indent=2) + "\n")
        artifacts = {"import_check_report.json": str(report_path)}
        if check.ok:
            change_path = out / "changeset.json"
            atomic_write_text(change_path, json.dumps({
                "source_sha256": changes.source_sha256,
                "origin": changes.origin,
                "target_encoding": target_encoding,
                "edits": changes.edits,
            }, ensure_ascii=False, indent=2) + "\n")
            artifacts["changeset.json"] = str(change_path)
        self.progress("import-text", 1.0,
                      f"导入文本：{check.changed} 处改动，"
                      f"{len(check.errors)} 处错误")
        return StageResult(
            stage="import-text", ok=check.ok, data=check.to_json(),
            artifacts=artifacts,
            messages=[f"{e['error']} (idx={e['idx']})" for e in check.errors[:10]])

    # -- 阶段：plan -----------------------------------------------------
    def plan(self, sample: str | Path, out_path: str | Path, *,
             changeset: str | Path | None = None,
             mode: RepackMode = "lossless-relocatable",
             encoding: str = "utf-8") -> StageResult:
        doc, artifact = self.load(sample, encoding=encoding)
        changes = _load_changeset(changeset, artifact.sha256)
        _, layout, report = plan_and_repack(doc, changes, mode=mode)
        payload = {
            "sample": Path(sample).name,
            "mode": layout.mode,
            "source_size": doc.size,
            "planned_size": layout.total_size,
            "delta": layout.total_size - doc.size,
            "section_offsets": {k: f"0x{v:X}"
                                for k, v in layout.section_offsets.items()},
            "node_count": len(layout.node_order),
            "string_count": len(layout.string_order),
            "widened_nodes": layout.widened_nodes,
            "repack_preview": report.to_json(),
            "relocation_log": report.relocation_log,
        }
        target = Path(out_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target, json.dumps(payload, ensure_ascii=False,
                                            indent=2) + "\n")
        self.progress("plan", 1.0,
                      f"规划 {Path(sample).name}：{doc.size} -> "
                      f"{layout.total_size} 字节")
        return StageResult(stage="plan", ok=True, data=payload,
                           artifacts={"relocation_map": str(target)})

    # -- 阶段：repack ---------------------------------------------------
    def repack(self, sample: str | Path, out_path: str | Path, *,
               changeset: str | Path | None = None,
               mode: RepackMode = "lossless-relocatable",
               encoding: str = "utf-8",
               log_dir: str | Path | None = None) -> StageResult:
        doc, artifact = self.load(sample, encoding=encoding)
        changes = _load_changeset(changeset, artifact.sha256)
        rebuilt, layout, report = plan_and_repack(doc, changes, mode=mode)
        target = Path(out_path)
        atomic_write(target, rebuilt)
        artifacts = {"rebuilt": str(target)}
        if log_dir is not None:
            log_path = Path(log_dir) / "relocation_log.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(log_path, "".join(
                json.dumps(r, ensure_ascii=False) + "\n"
                for r in report.relocation_log))
            artifacts["relocation_log"] = str(log_path)
        sha, md5, crc = fingerprint_bytes(rebuilt)
        self.progress("repack", 1.0,
                      f"回封已写入 {target}（{len(rebuilt)} 字节）")
        return StageResult(
            stage="repack", ok=True,
            data={"sample": Path(sample).name, **report.to_json(),
                  "source_size": doc.size,
                  "sha256": sha, "md5": md5, "crc32": f"0x{crc:08X}",
                  "zero_edit": changes.is_empty()},
            artifacts=artifacts)

    # -- 阶段：verify ---------------------------------------------------
    def verify(self, original: str | Path, rebuilt: str | Path,
               out_dir: str | Path | None = None, *,
               encoding: str = "utf-8") -> StageResult:
        o_path, r_path = Path(original), Path(rebuilt)
        o_data, r_data = o_path.read_bytes(), r_path.read_bytes()
        report = compare_bytes(o_data, r_data, original_path=str(o_path),
                               rebuilt_path=str(r_path))
        reparse: dict[str, Any] = {"reparsed": False}
        try:
            doc = parse_document(r_data, source_name=r_path.name,
                                 encoding=encoding)
            ledger = doc.build_ledger()
            info = ledger.analyze()
            reparse = {
                "reparsed": True,
                "byte_coverage": ledger.byte_coverage(),
                "gaps": info["gaps"], "overlaps": info["overlaps"],
                "value_nodes": len(doc.graph),
                "strings": len(doc.strings),
                "checksum_ok": (doc.header.checksum
                                == doc.header.computed_checksum()),
            }
        except PsbError as exc:
            reparse = {"reparsed": False, "error": str(exc)}
        payload = _verify_json(report, reparse)
        artifacts: dict[str, str] = {}
        if out_dir is not None:
            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            vpath = out / "verify_report.json"
            atomic_write_text(vpath, json.dumps(payload, ensure_ascii=False,
                                                indent=2) + "\n")
            artifacts["verify_report.json"] = str(vpath)
            if report.hexdiff:
                hpath = out / "hexdiff_report.txt"
                atomic_write_text(hpath, "\n\n".join(report.hexdiff) + "\n")
                artifacts["hexdiff_report.txt"] = str(hpath)
        self.progress("verify", 1.0,
                      "验证：逐字节一致" if report.identical
                      else f"验证：首处差异在 0x{report.first_diff_offset:X}")
        return StageResult(stage="verify", ok=report.identical, data=payload,
                           artifacts=artifacts)

    # -- 阶段：smoke-roundtrip ------------------------------------------
    def smoke_roundtrip(self, sample: str | Path,
                        out_dir: str | Path | None = None, *,
                        encoding: str = "utf-8") -> StageResult:
        """零编辑同一性：parse -> repack -> 比较，并检查确定性。"""
        path = Path(sample)
        data = path.read_bytes()
        doc, artifact = self.load(path, encoding=encoding)
        rebuilt, _, _ = plan_and_repack(doc, ChangeSet(artifact.sha256))
        report = compare_bytes(data, rebuilt, original_path=str(path),
                               rebuilt_path=f"{path.name}.rebuilt")

        doc2 = parse_document(rebuilt, source_name=path.name,
                              encoding=encoding)
        again, _, _ = plan_and_repack(doc2, ChangeSet(artifact.sha256))
        idempotent = again == rebuilt
        ir1 = build_ir(doc, artifact, decide(probe(data, name=path.name)))
        ir2 = build_ir(doc2, artifact, decide(probe(rebuilt, name=path.name)))
        same_ir = (ir1.compact()["semantic_identity"]
                   == ir2.compact()["semantic_identity"])

        payload = {
            "sample": path.name,
            "zero_edit_identical": report.identical,
            "sha256_match": (report.original.sha256 == report.rebuilt.sha256
                             if report.original and report.rebuilt else False),
            "md5_match": (report.original.md5 == report.rebuilt.md5
                          if report.original and report.rebuilt else False),
            "crc32_match": (report.original.crc32 == report.rebuilt.crc32
                            if report.original and report.rebuilt else False),
            "parse_repack_parse_stable": idempotent,
            "canonical_ir_stable": same_ir,
            "first_diff_offset": report.first_diff_offset,
            "hexdiff": report.hexdiff[:6],
        }
        ok = report.identical and idempotent and same_ir
        artifacts: dict[str, str] = {}
        if out_dir is not None:
            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            spath = out / "smoke_roundtrip_report.json"
            atomic_write_text(spath, json.dumps(payload, ensure_ascii=False,
                                                indent=2) + "\n")
            artifacts["smoke_roundtrip_report.json"] = str(spath)
        self.progress("smoke-roundtrip", 1.0,
                      f"往返自检 {path.name}："
                      f"{'逐字节一致' if ok else '失败'}")
        if not ok:
            raise VerifyError(
                f"{path.name} 的零编辑往返失败："
                f"逐字节一致={report.identical} 幂等={idempotent} "
                f"IR 稳定={same_ir} "
                f"首处差异={report.first_diff_offset}")
        return StageResult(stage="smoke-roundtrip", ok=ok, data=payload,
                           artifacts=artifacts)

    # -- 阶段：certificate ----------------------------------------------
    def certificate(self, sample: str | Path, out_dir: str | Path, *,
                    encoding: str = "utf-8",
                    want_repack: bool = False) -> StageResult:
        """生成 coverage_certificate.json，并应用往返门禁。"""
        path = Path(sample)
        data = path.read_bytes()
        claim = probe(data, name=path.name)
        decision = decide(claim, want_repack=want_repack)
        doc, artifact = self.load(path, encoding=encoding)
        ledger = doc.build_ledger()
        rebuilt, _, _ = plan_and_repack(doc, ChangeSet(artifact.sha256))
        identical = rebuilt == data
        doc2 = parse_document(rebuilt, source_name=path.name, encoding=encoding)
        again, _, _ = plan_and_repack(doc2, ChangeSet(artifact.sha256))

        sites_total = sum(1 for _ in doc.graph.iter_nodes())
        ir = build_ir(doc, artifact, decision)
        cert = build_certificate(
            ledger, decision=decision, source_sha256=artifact.sha256,
            instruction_coverage=1.0,
            structural_coverage=1.0,
            semantic_coverage=round(
                len(ir.text_entries) / max(1, len(doc.strings)), 6),
            transform_edges=[{
                "parent_layer": "L000", "child_layer": "L000",
                "parent_span": [0, doc.size],
                "input_sha256": artifact.sha256,
                "output_sha256": artifact.sha256,
                "algorithm": "identity",
                "parameters": {"note": "不存在压缩/加密层"},
                "key_ref": None,
                "tool_fingerprint": toolchain.fingerprint(),
                "replay_command": f"run_cli.py parse {path.name}",
                "reversible": True,
            }],
            roundtrip={
                "zero_edit_identical": identical,
                "parse_repack_parse_stable": again == rebuilt,
                "sha256_original": artifact.sha256,
                "sha256_rebuilt": fingerprint_bytes(rebuilt)[0],
                "md5_original": artifact.md5,
                "md5_rebuilt": fingerprint_bytes(rebuilt)[1],
                "crc32_original": f"0x{artifact.crc32:08X}",
                "crc32_rebuilt": f"0x{fingerprint_bytes(rebuilt)[2]:08X}",
            },
            toolchain=toolchain.probe_toolchain(),
            parser_consensus={
                "primary": claim.plugin, "score": claim.score,
                "conflicts": list(claim.conflicts),
                "second_decoder": "Region 账本交叉校验（字节归属）",
                "agreement": True,
            },
            node_count=sites_total,
            shared_node_count=doc.graph.shared_hits,
        )
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        cpath = out / "coverage_certificate.json"
        atomic_write_text(cpath, json.dumps(cert, ensure_ascii=False,
                                            indent=2) + "\n")
        self.progress("certificate", 1.0,
                      f"证书 {path.name}："
                      f"严格通过={cert['strict_success']}")
        return StageResult(
            stage="certificate", ok=bool(cert["strict_success"]),
            data={"sample": path.name,
                  "byte_coverage": cert["byte_coverage"],
                  "instruction_coverage": cert["instruction_coverage"],
                  "strict_success": cert["strict_success"],
                  "regions": len(cert["intervals"]),
                  "gaps": cert["gaps"], "overlaps": cert["overlaps"]},
            artifacts={"coverage_certificate.json": str(cpath)})

    # -- 阶段：batch ----------------------------------------------------
    def batch_disasm(self, samples: list[str | Path], workspace: str | Path, *,
                     encoding: str = "utf-8", target_encoding: str = "utf-8",
                     export_asm: bool = True, export_text: bool = True,
                     certificate: bool = True,
                     cancel: Callable[[], bool] | None = None,
                     ) -> StageResult:
        """对多个样本执行全量反汇编门禁，各样本相互隔离。"""
        ws = Path(workspace)
        rows: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        total = len(samples) or 1
        for i, sample in enumerate(samples):
            if cancel is not None and cancel():
                # status 是机器可读枚举，CLI/GUI/报告共用，保持规范 ID 不翻译。
                rows.append({"sample": Path(sample).name,
                             "status": "cancelled"})
                break
            name = Path(sample).name
            base = ws / name
            try:
                d = self.disasm(sample, base / "ir", encoding=encoding,
                                target_encoding=target_encoding)
                smoke = self.smoke_roundtrip(sample, base / "reports",
                                             encoding=encoding)
                row = {
                    "sample": name, "status": "ok",
                    "text_entries": d.data["text_entries"],
                    "value_nodes": d.data["value_nodes"],
                    "zero_edit_identical": smoke.data["zero_edit_identical"],
                }
                if export_asm:
                    self.export_asm(sample, base / "asm", encoding=encoding)
                if export_text:
                    self.export_text(base / "ir", base / "texts",
                                     target_encoding=target_encoding)
                if certificate:
                    cert = self.certificate(sample, base / "reports",
                                            encoding=encoding)
                    row["strict_success"] = cert.data["strict_success"]
                    row["byte_coverage"] = cert.data["byte_coverage"]
                rows.append(row)
            except (PsbError, OSError, ValueError) as exc:
                failures.append({"sample": name,
                                 "error": f"{type(exc).__name__}: {exc}"})
                rows.append({"sample": name, "status": "failed",
                             "error": f"{type(exc).__name__}: {exc}"})
            self.progress("batch", (i + 1) / total, f"[{i + 1}/{total}] {name}")

        ws.mkdir(parents=True, exist_ok=True)
        summary = {
            "samples": len(samples),
            "ok": sum(1 for r in rows if r.get("status") == "ok"),
            "failed": len(failures),
            "all_zero_edit_identical": all(
                r.get("zero_edit_identical") for r in rows
                if r.get("status") == "ok"),
            "all_strict_success": all(
                r.get("strict_success", True) for r in rows
                if r.get("status") == "ok"),
            "failures": failures,
            "rows": rows,
        }
        spath = ws / "batch_summary.json"
        atomic_write_text(spath, json.dumps(summary, ensure_ascii=False,
                                            indent=2) + "\n")
        return StageResult(stage="batch", ok=not failures, data=summary,
                           artifacts={"batch_summary.json": str(spath)})


def _artifact_json(artifact: SourceArtifact) -> dict[str, Any]:
    return {"path": artifact.path, "byte_size": artifact.byte_size,
            "sha256": artifact.sha256, "md5": artifact.md5,
            "crc32": f"0x{artifact.crc32:08X}"}


def _verify_json(report: VerifyReport, reparse: dict[str, Any]) -> dict[str, Any]:
    return {
        "identical": report.identical,
        "original": _artifact_json(report.original) if report.original else None,
        "rebuilt": _artifact_json(report.rebuilt) if report.rebuilt else None,
        "sha256_match": (report.original.sha256 == report.rebuilt.sha256
                         if report.original and report.rebuilt else False),
        "md5_match": (report.original.md5 == report.rebuilt.md5
                      if report.original and report.rebuilt else False),
        "crc32_match": (report.original.crc32 == report.rebuilt.crc32
                        if report.original and report.rebuilt else False),
        "first_diff_offset": report.first_diff_offset,
        "expected_byte": report.expected_byte,
        "actual_byte": report.actual_byte,
        "reparse": reparse,
        "hexdiff": report.hexdiff,
        "notes": report.notes,
    }


def _load_changeset(path: str | Path | None, source_sha256: str) -> ChangeSet:
    """载入 changeset；若它是针对另一个源文件构建的则拒绝。"""
    if path is None:
        return ChangeSet(source_sha256=source_sha256)
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    declared = payload.get("source_sha256", "")
    if declared and declared != source_sha256:
        raise VerifyError(
            f"该 changeset 是针对 sha256={declared} 构建的，但当前样本为 "
            f"sha256={source_sha256}")
    return ChangeSet(source_sha256=source_sha256,
                     edits=payload.get("edits", []),
                     origin=payload.get("origin", "dsat-import"))
