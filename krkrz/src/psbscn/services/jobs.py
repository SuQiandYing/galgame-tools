"""三个懒人操作：反汇编、提取文本、回封。

产物是**合并**的：一份 ASM 清单、一份 DSAT 翻译文件、一份 JSON 报告。只有回封
结果按文件写出，因为那是要装回游戏的。

不落盘逐文件中间 IR。解析是确定性的：给定同一份源字节和同一个源编码，`build_ir`
必然产出同一份 IR，所以回封时重算一次即用户可省下 264 个目录和数百 MB 磁盘。
"""
from __future__ import annotations

import json
import os
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from ..bytecode.asm import iter_asm_lines
from ..bytecode.ir import ScnIR, build_ir
from ..bytecode.repack import plan_and_repack
from ..core.errors import PsbError
from ..core.hashing import atomic_write, atomic_write_text
from ..core.types import ChangeSet
from ..core.verify import compare_bytes
from ..formats.psb_document import parse_document
from ..text.dsat import (DsatSection, parse_dsat, parse_merged_dsat,
                         render_dsat)
from ..text.importer import ImportCheck, validate_units
from .decision import decide, probe
from .stages import StageResult, StageService
from .workspace import Workspace, find_scenario_files, relative_key

CancelFn = Callable[[], bool]

#: 反汇编汇总的累加项，串行与并行共用同一套键。
_DISASM_TOTALS = {"value_nodes": 0, "text_entries": 0, "strings": 0,
                  "shared_node_refs": 0}


def _extract_worker(task: tuple[str, str, str, str]) -> dict[str, Any]:
    """子进程入口：导出一个文件的译文。译文经磁盘写出，只回传统计。"""
    sample_path, target_path, encoding, target_encoding = task
    sample = Path(sample_path)
    svc = StageService()
    data = sample.read_bytes()
    doc, artifact = svc.load_bytes(data, sample.name, encoding=encoding)
    ir = build_ir(doc, artifact, decide(probe(data, name=sample.name)),
                  target_encoding=target_encoding)
    rows = list(ir.text_entry_rows())
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, render_dsat(
        rows, sample=sample.name, source_sha256=artifact.sha256,
        source_encoding=ir.source_encoding,
        target_encoding=target_encoding, ir_version="1.0.0"))
    return {"units": len(rows), "sha256": artifact.sha256}


def _repack_worker(task: tuple[str, str, str, str, str]) -> dict[str, Any]:
    """子进程入口：按某个源文件的译文回封它自己。

    译文缺失返回 `{"skipped": ...}`，让主进程如实上报而不是当成成功。
    """
    sample_path, text_path, out_path, encoding, target_encoding = task
    sample, text = Path(sample_path), Path(text_path)
    if not text.exists():
        return {"skipped": f"没有对应的译文文件 {text.name}"}
    runner = JobRunner()
    meta, units = parse_dsat(text.read_text(encoding="utf-8"))
    section = DsatSection(file=meta.get("sample", sample.name),
                          sha256=meta.get("source_sha256", ""), units=units,
                          source_encoding=meta.get("source_encoding", "utf-8"))
    ws = Workspace(Path(out_path).parent.parent)
    return runner._repack_one(sample, section, ws, encoding, target_encoding)


def _disasm_worker(task: tuple[str, str, str, str, str]) -> dict[str, Any]:
    """子进程入口：反汇编一个文件，ASM/IR 写到自己的临时文件。

    必须是模块级函数才能被 pickle。只接收路径与选项这些小对象，不传 reader、
    句柄或大 buffer；ASM 与 IR 都经磁盘而非 IPC 传回。
    """
    sample_path, part_path, encoding, target_encoding, ir_part = task
    runner = JobRunner()
    with _AsmWriter(Path(part_path) if part_path else None,
                    banner=False, enabled=bool(part_path)) as asm:
        return runner._disasm_one(Path(sample_path), encoding,
                                  target_encoding, asm,
                                  ir_part=Path(ir_part) if ir_part else None)


@dataclass(slots=True)
class JobOutcome:
    """一次批量操作的结果：逐样本行 + 汇总。"""

    job: str
    ok: bool
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    cancelled: bool = False
    rows: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "job": self.job, "ok": self.ok, "total": self.total,
            "succeeded": self.succeeded, "failed": self.failed,
            "cancelled": self.cancelled, **self.summary,
            "rows": self.rows, "artifacts": self.artifacts,
        }

    def as_stage_result(self) -> StageResult:
        data = self.to_json()
        # 264 行成功明细留在报告文件里；界面只需要汇总，以及需要用户处理的
        # 失败/跳过行——把它们藏起来才是真正的信息丢失。
        data["rows"] = [r for r in self.rows
                        if r.get("status") in ("failed", "skipped")][:40]
        data["row_count"] = len(self.rows)
        return StageResult(stage=self.job, ok=self.ok, data=data,
                           artifacts=self.artifacts)


class JobRunner:
    """三个懒人操作。每个操作只解析一遍每个文件。"""

    def __init__(self, service: StageService | None = None) -> None:
        self.svc = service or StageService()

    def _progress(self, job: str, i: int, total: int, name: str) -> None:
        self.svc.progress(job, (i + 1) / max(1, total),
                          f"[{i + 1}/{total}] {name}")

    # -- 操作一：反汇编 -------------------------------------------------
    def disassemble(self, inputs: list[str] | list[Path], *,
                    encoding: str = "utf-8", target_encoding: str = "utf-8",
                    write_asm: bool = True, write_ir: bool = False,
                    cancel: CancelFn | None = None) -> JobOutcome:
        """全量反汇编：ASM 清单 + 覆盖证书 + 零编辑往返自检。

        往返自检不是可选项：一个文件若无法被逐字节重建，它的反汇编结果就不值得
        信任，此时报告失败而不是照常输出 ASM。

        `write_asm=False` 跳过 ASM 文本生成（本作语料 571 MB，约占单文件耗时 21%），
        自检与覆盖证书照常执行。`write_ir=True` 额外落盘一份合库 IR。
        """
        samples = find_scenario_files(list(inputs))
        ws = self._workspace(inputs)
        out = JobOutcome(job="反汇编", ok=True, total=len(samples))
        ws.root.mkdir(parents=True, exist_ok=True)

        if self._should_parallelize(len(samples)):
            totals = self._disassemble_parallel(samples, ws, out, encoding,
                                               target_encoding, cancel,
                                               write_asm, write_ir)
        else:
            totals = self._disassemble_serial(samples, ws, out, encoding,
                                              target_encoding, cancel,
                                              write_asm, write_ir)

        done = [r for r in out.rows if r["status"] == "ok"]
        out.summary = {
            **totals,
            "all_zero_edit_identical": all(r["zero_edit_identical"]
                                           for r in done),
            "all_strict_success": all(r["strict_success"] for r in done),
            "min_byte_coverage": min((r["byte_coverage"] for r in done),
                                     default=0.0),
        }
        out.artifacts["反汇编清单"] = str(ws.asm)
        return self._finish(out, ws)

    # -- 反汇编的两种执行方式 -------------------------------------------
    #: 文件数少于这个值就不并行：进程启动与 IPC 成本会盖过收益。
    PARALLEL_MIN_FILES = 8

    @staticmethod
    def _worker_count(n: int) -> int:
        return max(1, min(os.cpu_count() or 1, n))

    def _should_parallelize(self, n: int) -> bool:
        if os.environ.get("PSBSCN_SERIAL") == "1":
            return False
        return n >= self.PARALLEL_MIN_FILES and (os.cpu_count() or 1) > 1

    def _accumulate(self, out: JobOutcome, totals: dict[str, int],
                    sample_name: str, row: dict[str, Any]) -> None:
        for key in totals:
            totals[key] += row.get(key, 0)
        out.succeeded += 1
        out.rows.append({"sample": sample_name, "status": "ok", **row})

    def _disassemble_serial(self, samples: list[Path], ws: Workspace,
                           out: JobOutcome, encoding: str,
                           target_encoding: str,
                           cancel: CancelFn | None,
                           write_asm: bool = True,
                           write_ir: bool = False) -> dict[str, int]:
        totals = dict(_DISASM_TOTALS)
        ir_sink = _IrLibraryWriter(ws.ir) if write_ir else None
        with _AsmWriter(ws.asm, enabled=write_asm) as asm:
            for i, sample in enumerate(samples):
                if cancel is not None and cancel():
                    out.cancelled = True
                    break
                try:
                    row = self._disasm_one(sample, encoding, target_encoding,
                                           asm, ir_sink=ir_sink)
                    self._accumulate(out, totals, sample.name, row)
                except (PsbError, OSError, ValueError) as exc:
                    self._record_failure(out, sample.name, exc)
                self._progress(out.job, i, len(samples), sample.name)
        if ir_sink is not None:
            ir_sink.close()
            out.artifacts["IR 库"] = str(ws.ir)
        return totals

    def _map_parallel(self, worker: Callable[[Any], dict[str, Any]],
                      tasks: list[Any], samples: list[Path],
                      out: JobOutcome,
                      cancel: CancelFn | None) -> dict[int, dict[str, Any]]:
        """把任务分发到多进程，返回 索引 -> 结果。

        失败的任务返回 `{"error": ...}` 而不是抛出，让调用方按输入顺序统一记账，
        因此产物顺序与串行执行一致。
        """
        results: dict[int, dict[str, Any]] = {}
        with ProcessPoolExecutor(
                max_workers=self._worker_count(len(tasks))) as pool:
            futures = {pool.submit(worker, t): i for i, t in enumerate(tasks)}
            for done_count, fut in enumerate(as_completed(futures)):
                idx = futures[fut]
                if cancel is not None and cancel():
                    out.cancelled = True
                    for f in futures:
                        f.cancel()
                    break
                try:
                    results[idx] = fut.result()
                except Exception as exc:
                    results[idx] = {"error": str(exc)}
                self._progress(out.job, done_count, len(tasks),
                               samples[idx].name)
        return results

    def _disassemble_parallel(self, samples: list[Path], ws: Workspace,
                             out: JobOutcome, encoding: str,
                             target_encoding: str,
                             cancel: CancelFn | None,
                             write_asm: bool = True,
                             write_ir: bool = False) -> dict[str, int]:
        """按源文件切分到多进程。解析是纯 CPU 计算，受 GIL 限制，多线程无效。

        每个 worker 把自己那一份 ASM 写到独立临时文件，只把统计行回传主进程——
        避免把几百 MB 文本塞进 IPC。主进程按**输入顺序**拼接，因此产物与串行执行
        逐字节相同，不引入任何非确定性。
        """
        totals = dict(_DISASM_TOTALS)
        parts_dir = ws.root / ".asm_parts"
        if parts_dir.exists():
            shutil.rmtree(parts_dir, ignore_errors=True)
        parts_dir.mkdir(parents=True, exist_ok=True)
        tasks = [(str(s),
                  str(parts_dir / f"{i:05d}.part") if write_asm else "",
                  encoding, target_encoding,
                  str(parts_dir / f"{i:05d}.ir") if write_ir else "")
                 for i, s in enumerate(samples)]
        try:
            results = self._map_parallel(_disasm_worker, tasks, samples, out,
                                        cancel)
            # 按输入顺序合并：产物顺序与串行一致
            ir_sink = _IrLibraryWriter(ws.ir) if write_ir else None
            with _AsmWriter(ws.asm, enabled=write_asm) as asm:
                for idx, sample in enumerate(samples):
                    res = results.get(idx)
                    if res is None:
                        continue
                    if "error" in res:
                        self._record_failure(out, sample.name,
                                             PsbError(res["error"]))
                        continue
                    if write_asm:
                        asm.write_part(Path(tasks[idx][1]))
                    if ir_sink is not None:
                        ir_sink.merge_part(Path(tasks[idx][4]))
                    self._accumulate(out, totals, sample.name, res)
            if ir_sink is not None:
                ir_sink.close()
                out.artifacts["IR 库"] = str(ws.ir)
        finally:
            shutil.rmtree(parts_dir, ignore_errors=True)
        return totals

    def _disasm_one(self, sample: Path, encoding: str, target_encoding: str,
                    asm: _AsmWriter, *,
                    ir_sink: _IrLibraryWriter | None = None,
                    ir_part: Path | None = None) -> dict[str, Any]:
        data = sample.read_bytes()
        claim = probe(data, name=sample.name)
        decision = decide(claim)
        if decision.unpack_mode == "blocked":
            raise PsbError(f"探测阶段阻断：{decision.decision_rationale}")

        # 复用刚读进来的字节，不再让 load() 重读一遍同一个文件
        doc, artifact = self.svc.load_bytes(data, sample.name,
                                            encoding=encoding,
                                            source_path=str(sample))
        # 批量流程不出覆盖证书，逐节点的 checks 字典没人读，跳过它。
        ledger = doc.build_ledger(detailed=False)
        info = ledger.analyze()
        if info["gaps"] or info["overlaps"]:
            raise PsbError(f"覆盖不精确：缺口={info['gaps'][:2]} "
                           f"重叠={info['overlaps'][:2]}")
        # byte_coverage() 内部会再跑一遍 analyze()；这里直接用已算好的结果。
        coverage = (info["covered_bytes"] / doc.size) if doc.size else 1.0

        rebuilt, _, _ = plan_and_repack(doc, ChangeSet(artifact.sha256))
        identical = rebuilt == data

        # parse(repack(parse)) 稳定性：只有在 rebuilt != data 时才需要真的再跑一遍。
        # rebuilt == data 时第二轮解析的是**同一批字节**，解析又是确定性的，所以
        # again == rebuilt 必然成立——重算一次只是把 30% 的时间花在证明恒等式上。
        # 已在语料上实测确认这个等价关系。
        if identical:
            stable = True
        else:
            doc2 = parse_document(rebuilt, source_name=sample.name,
                                  encoding=encoding)
            again, _, _ = plan_and_repack(doc2, ChangeSet(artifact.sha256))
            stable = again == rebuilt

        ir = build_ir(doc, artifact, decision, target_encoding=target_encoding)
        asm.write(doc, ir)
        if ir_sink is not None:
            ir_sink.add(ir, _ir_streams(ir))
        elif ir_part is not None:
            # 子进程里先落成片段，由主进程按输入顺序并入合库
            ir_part.parent.mkdir(parents=True, exist_ok=True)
            ir_part.write_text(json.dumps(
                {"manifest": _ir_manifest_entry(ir), "streams": _ir_streams(ir)},
                ensure_ascii=False), encoding="utf-8")

        strict = (identical and stable and coverage == 1.0
                  and not info["gaps"] and not info["overlaps"]
                  and all(r.raw_sha256 for r in ledger.regions))
        if not identical:
            diff = compare_bytes(data, rebuilt)
            raise PsbError(
                "零编辑往返不一致，反汇编结果不可信；首处差异 "
                f"0x{diff.first_diff_offset:X}"
                if diff.first_diff_offset is not None
                else "零编辑往返不一致（长度不同）")

        return {
            "sha256": artifact.sha256,
            "value_nodes": len(doc.graph),
            "shared_node_refs": doc.graph.shared_hits,
            "strings": len(doc.strings),
            "text_entries": len(ir.text_entries),
            "byte_coverage": coverage,
            "zero_edit_identical": identical,
            "parse_repack_parse_stable": stable,
            "strict_success": strict,
        }

    # -- 操作二：提取文本 -----------------------------------------------
    def extract_text(self, inputs: list[str] | list[Path], *,
                     encoding: str = "utf-8", target_encoding: str = "utf-8",
                     cancel: CancelFn | None = None) -> JobOutcome:
        """**逐文件**导出 DSAT，目录结构镜像源目录。无需先跑反汇编。

        一个源文件对应一个译文文件。合并成一份会让 idx 跨文件冲突、无法按剧本
        分工送审、回封时判不出某条译文属于哪个源，也让原文行「本文件对应本源」
        这层校验失效。另外写一份只读的 `_index.tsv` 供总览，它不是导入源。
        """
        input_list = list(inputs)
        samples = find_scenario_files(input_list)
        ws = self._workspace(inputs)
        out = JobOutcome(job="提取文本", ok=True, total=len(samples))
        ws.texts.mkdir(parents=True, exist_ok=True)

        units = 0
        index_rows: list[str] = ["源文件\t译文文件\t条目数\tsha256"]
        tasks = [(str(s), str(ws.text_path(relative_key(s, input_list))),
                  encoding, target_encoding) for s in samples]

        if self._should_parallelize(len(samples)):
            done_rows = self._map_parallel(_extract_worker, tasks, samples,
                                           out, cancel)
        else:
            done_rows = {}
            for i, sample in enumerate(samples):
                if cancel is not None and cancel():
                    out.cancelled = True
                    break
                try:
                    done_rows[i] = _extract_worker(tasks[i])
                except (PsbError, OSError, ValueError) as exc:
                    done_rows[i] = {"error": str(exc)}
                self._progress(out.job, i, len(samples), sample.name)

        for i, sample in enumerate(samples):
            res = done_rows.get(i)
            if res is None:
                continue
            if "error" in res:
                self._record_failure(out, sample.name, PsbError(res["error"]))
                continue
            rel = relative_key(sample, input_list)
            target = Path(tasks[i][1])
            units += res["units"]
            index_rows.append(
                f"{rel.as_posix()}\t"
                f"{target.relative_to(ws.texts).as_posix()}\t"
                f"{res['units']}\t{res['sha256']}")
            out.succeeded += 1
            out.rows.append({"sample": sample.name, "status": "ok",
                             "units": res["units"],
                             "text_file": str(target),
                             "sha256": res["sha256"]})

        atomic_write_text(ws.index, "\n".join(index_rows) + "\n")
        out.summary = {"units": units,
                       "text_files": out.succeeded,
                       "target_encoding": target_encoding,
                       "source_encoding": encoding}
        out.artifacts["翻译目录"] = str(ws.texts)
        out.artifacts["总览"] = str(ws.index)
        return self._finish(out, ws)

    # -- 操作三：回封 ---------------------------------------------------
    def repack_text(self, inputs: list[str] | list[Path], *,
                    encoding: str = "utf-8", target_encoding: str = "utf-8",
                    cancel: CancelFn | None = None) -> JobOutcome:
        """读合并 DSAT，逐文件回封到 `rebuilt/` 并验证。

        DSAT 里没有某个文件的分节时，那个文件被跳过并如实上报，不会静默当成成功。
        每节的 sha256 单独校验，所以改动一个源文件只会让对应那节失效。
        """
        input_list = list(inputs)
        samples = find_scenario_files(input_list)
        ws = self._workspace(inputs)
        out = JobOutcome(job="回封", ok=True, total=len(samples))

        legacy: dict[str, DsatSection] = {}
        if not ws.texts.exists():
            if not ws.dsat.exists():
                out.ok = False
                out.summary = {
                    "error": f"找不到翻译文件；请先点「提取文本」（应生成 {ws.texts}）"}
                return self._finish(out, ws)
            # 兼容旧版单份合并文件，避免让翻到一半的成果作废。
            _, sections = parse_merged_dsat(ws.dsat.read_text(encoding="utf-8"))
            legacy = {s.file: s for s in sections}

        ws.rebuilt.mkdir(parents=True, exist_ok=True)

        changed_total = 0
        delta_total = 0
        # 旧版合并译文只能在主进程里读（整份文件在内存里），此时退回串行。
        parallel = not legacy and self._should_parallelize(len(samples))
        if parallel:
            tasks = [(str(s), str(ws.text_path(relative_key(s, input_list))),
                      str(ws.rebuilt_path(s.name)), encoding, target_encoding)
                     for s in samples]
            done = self._map_parallel(_repack_worker, tasks, samples, out,
                                      cancel)
            for i, sample in enumerate(samples):
                res = done.get(i)
                if res is None:
                    continue
                if "skipped" in res:
                    out.rows.append({"sample": sample.name,
                                     "status": "skipped",
                                     "skipped": res["skipped"]})
                    continue
                if "error" in res:
                    self._record_failure(out, sample.name,
                                         PsbError(res["error"]))
                    continue
                changed_total += res["changed"]
                delta_total += res["delta"]
                out.succeeded += 1
                out.rows.append({"sample": sample.name, "status": "ok", **res})
        else:
            for i, sample in enumerate(samples):
                if cancel is not None and cancel():
                    out.cancelled = True
                    break
                # 读译文本身也可能失败（格式坏、idx 不一致等）。必须和回封一样降级
                # 成这一个文件的失败行，而不是让异常穿出去中断整批。
                try:
                    section = self._load_section(ws, sample, input_list, legacy)
                except (PsbError, OSError, ValueError) as exc:
                    self._record_failure(out, sample.name, exc)
                    self._progress(out.job, i, len(samples), sample.name)
                    continue
                if section is None:
                    out.rows.append({
                        "sample": sample.name, "status": "skipped",
                        "skipped": f"没有对应的译文文件 "
                                   f"{ws.text_path(relative_key(sample, input_list)).name}"})
                    self._progress(out.job, i, len(samples), sample.name)
                    continue
                try:
                    row = self._repack_one(sample, section, ws, encoding,
                                           target_encoding)
                    changed_total += row["changed"]
                    delta_total += row["delta"]
                    out.succeeded += 1
                    out.rows.append({"sample": sample.name, "status": "ok",
                                     **row})
                except (PsbError, OSError, ValueError) as exc:
                    self._record_failure(out, sample.name, exc)
                self._progress(out.job, i, len(samples), sample.name)

        out.summary = {
            "changed_entries": changed_total,
            "total_delta_bytes": delta_total,
            "skipped": sum(1 for r in out.rows if r["status"] == "skipped"),
            "target_encoding": target_encoding,
        }
        out.artifacts["回封目录"] = str(ws.rebuilt)
        return self._finish(out, ws)

    def _load_section(self, ws: Workspace, sample: Path,
                      inputs: list[str] | list[Path],
                      legacy: dict[str, DsatSection]) -> DsatSection | None:
        """取该样本的译文。优先逐文件译文，其次旧版合并文件里的同名分节。"""
        path = ws.text_path(relative_key(sample, inputs))
        if path.exists():
            meta, units = parse_dsat(path.read_text(encoding="utf-8"))
            return DsatSection(
                file=meta.get("sample", sample.name),
                sha256=meta.get("source_sha256", ""),
                units=units,
                source_encoding=meta.get("source_encoding", "utf-8"))
        return legacy.get(sample.name)

    def _repack_one(self, sample: Path, section: DsatSection, ws: Workspace,
                    encoding: str, target_encoding: str) -> dict[str, Any]:
        doc, artifact = self.svc.load(sample, encoding=encoding)
        if section.sha256 and section.sha256 != artifact.sha256:
            raise PsbError(
                "翻译文件中该分节对应的源文件已改变"
                f"（分节 sha256={section.sha256[:12]}…，"
                f"当前 sha256={artifact.sha256[:12]}…），请重新提取文本")

        ir = build_ir(doc, artifact, decide(probe(sample.read_bytes(),
                                                 name=sample.name)),
                      target_encoding=target_encoding)
        check, changes = validate_units(
            section.units, list(ir.text_entry_rows()),
            check=ImportCheck(sample=sample.name),
            source_sha256=artifact.sha256,
            target_encoding=target_encoding)
        if not check.ok:
            raise PsbError(
                f"译文校验未通过（{len(check.errors)} 处错误）："
                + "；".join(f"idx={e['idx']} {e['error']}"
                            for e in check.errors[:3]))

        rebuilt, _, report = plan_and_repack(doc, changes,
                                            target_encoding=target_encoding)
        target = ws.rebuilt_path(sample.name)
        atomic_write(target, rebuilt)

        # 重建结果必须能重新解析并再次达到精确覆盖，否则不算回封成功。
        doc2 = parse_document(rebuilt, source_name=sample.name,
                              encoding=encoding)
        info2 = doc2.build_ledger().analyze()
        if info2["gaps"] or info2["overlaps"]:
            raise PsbError(f"重建文件覆盖不精确：缺口={info2['gaps'][:2]}")
        if doc2.header.checksum != doc2.header.computed_checksum():
            raise PsbError("重建文件的文件头校验和不正确")

        return {
            "changed": report.edits_applied,
            "source_size": doc.size,
            "output_size": len(rebuilt),
            "delta": len(rebuilt) - doc.size,
            "identical": rebuilt == doc.data,
            "strings_added": report.strings_added,
            "nodes_widened": report.nodes_widened,
        }

    # -- 公共部分 -------------------------------------------------------
    def _workspace(self, inputs: list[str] | list[Path]) -> Workspace:
        return (Workspace.beside(inputs[0]) if inputs
                else Workspace(Path("_psbscn")))

    def _record_failure(self, out: JobOutcome, name: str,
                        exc: Exception) -> None:
        out.failed += 1
        out.ok = False
        out.rows.append({"sample": name, "status": "failed",
                         "error": f"{type(exc).__name__}: {exc}"})

    def _finish(self, out: JobOutcome, ws: Workspace) -> JobOutcome:
        ws.root.mkdir(parents=True, exist_ok=True)
        report = json.loads(ws.report.read_text(encoding="utf-8")) \
            if ws.report.exists() else {}
        report[out.job] = out.to_json()
        atomic_write_text(ws.report, json.dumps(report, ensure_ascii=False,
                                                indent=2) + "\n")
        out.artifacts["报告"] = str(ws.report)
        out.artifacts["输出目录"] = str(ws.root)
        if out.total == 0:
            out.ok = False
        elif out.succeeded == 0 and not out.cancelled:
            # 全部被跳过也不算成功——用户很可能漏了前一步。
            out.ok = False
        return out


#: IR 合库里的 JSONL 流名。每条记录都会带上 src_id。
_IR_STREAMS = ("text_entries.jsonl", "name_map.jsonl", "string_map.jsonl",
               "placeholder_map.jsonl")


class _IrLibraryWriter:
    """把多个源文件的 IR 合并成**一套** JSONL，而不是几百个目录。

    每条记录带 `src_id`，同一源的记录连续写入；`manifest.jsonl` 记下每个源在各流中的
    行区间 `[start, end)`，所以取单个源仍是一次顺序区间读，不必解析整库。

    一源一目录的布局代价是三重的：每个小文件都要 open/close/fsync；每个按簇占盘，
    几百字节的流也吃一整簇；跨源查询还得遍历所有目录。
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._fh = {name: (self.root / name).open("w", encoding="utf-8",
                                                  newline="\n")
                    for name in _IR_STREAMS}
        self._lines = {name: 0 for name in _IR_STREAMS}
        self._manifest = (self.root / "manifest.jsonl").open(
            "w", encoding="utf-8", newline="\n")
        self._next_id = 0

    def add(self, ir: ScnIR, streams: dict[str, list[dict[str, Any]]]) -> None:
        """写入一个源的全部记录，并登记它的行区间。"""
        src_id = self._next_id
        self._next_id += 1
        spans: dict[str, list[int]] = {}
        for name in _IR_STREAMS:
            rows = streams.get(name, ())
            start = self._lines[name]
            if rows:
                self._fh[name].write("".join(
                    json.dumps({"src_id": src_id, **r}, ensure_ascii=False)
                    + "\n" for r in rows))
                self._lines[name] += len(rows)
            spans[name] = [start, self._lines[name]]
        self._manifest.write(json.dumps({
            "src_id": src_id,
            "sample": ir.sample_name,
            "path": ir.artifact.path,
            "byte_size": ir.artifact.byte_size,
            "sha256": ir.artifact.sha256,
            "md5": ir.artifact.md5,
            "crc32": f"0x{ir.artifact.crc32:08X}",
            "source_encoding": ir.source_encoding,
            "target_encoding": ir.target_encoding,
            "value_nodes": ir.node_count,
            "text_entries": len(ir.text_entries),
            "line_spans": spans,
        }, ensure_ascii=False) + "\n")

    def merge_part(self, part: Path) -> None:
        """并入某个 worker 预先序列化好的 IR 片段。"""
        if not part.exists():
            return
        payload = json.loads(part.read_text(encoding="utf-8"))
        src_id = self._next_id
        self._next_id += 1
        spans: dict[str, list[int]] = {}
        for name in _IR_STREAMS:
            rows = payload["streams"].get(name, [])
            start = self._lines[name]
            if rows:
                self._fh[name].write("".join(
                    json.dumps({"src_id": src_id, **r}, ensure_ascii=False)
                    + "\n" for r in rows))
                self._lines[name] += len(rows)
            spans[name] = [start, self._lines[name]]
        entry = dict(payload["manifest"])
        entry["src_id"] = src_id
        entry["line_spans"] = spans
        self._manifest.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def close(self) -> None:
        for fh in self._fh.values():
            fh.flush()
            os.fsync(fh.fileno())
            fh.close()
        self._manifest.flush()
        os.fsync(self._manifest.fileno())
        self._manifest.close()


def _ir_streams(ir: ScnIR) -> dict[str, list[dict[str, Any]]]:
    """把一个 IR 拆成待写入合库的各条流。"""
    return {
        "text_entries.jsonl": list(ir.text_entry_rows()),
        "name_map.jsonl": [{"key_id": i, "name": n}
                           for i, n in enumerate(ir.names)],
        "string_map.jsonl": [
            {"string_id": i, "value": v,
             "referenced_by": ir.string_refs.get(i, [])}
            for i, v in enumerate(ir.strings)],
        "placeholder_map.jsonl": [
            {"idx": e.idx, "ph_count": e.ph_count, "ph_bytes": e.ph_bytes,
             "ph_hash": e.ph_hash, "ph_policy": e.ph_policy}
            for e in ir.text_entries if e.ph_count],
    }


def _ir_manifest_entry(ir: ScnIR) -> dict[str, Any]:
    return {
        "sample": ir.sample_name,
        "path": ir.artifact.path,
        "byte_size": ir.artifact.byte_size,
        "sha256": ir.artifact.sha256,
        "md5": ir.artifact.md5,
        "crc32": f"0x{ir.artifact.crc32:08X}",
        "source_encoding": ir.source_encoding,
        "target_encoding": ir.target_encoding,
        "value_nodes": ir.node_count,
        "text_entries": len(ir.text_entries),
    }


class _AsmWriter:
    """把多个文档的 ASM 流式追加进一个文件，不在内存里拼字符串。"""

    def __init__(self, path: Path | None, *, banner: bool = True,
                 enabled: bool = True) -> None:
        self.enabled = enabled and path is not None
        self.path = path
        # 禁用时不碰路径：调用方可能根本没有可用路径传进来。
        self.tmp = (path.with_suffix(path.suffix + ".tmp")
                    if self.enabled and path is not None else None)
        self.banner = banner
        self._fh = None

    def __enter__(self) -> _AsmWriter:
        if not self.enabled or self.path is None or self.tmp is None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.tmp.open("w", encoding="utf-8", newline="\n")
        if self.banner:
            self._fh.write("; PSB/SCN 合并反汇编清单\n"
                           "; 每个源文件以一行 5 个等号的分节头开始\n\n")
        return self

    def write_part(self, part: Path) -> None:
        """把某个 worker 写好的 ASM 片段原样并入清单。"""
        if self._fh is None:
            return
        with part.open("r", encoding="utf-8", newline="") as src:
            while True:
                block = src.read(1 << 20)
                if not block:
                    break
                self._fh.write(block)

    #: 每积累这么多行拼一次字符串再落盘。逐行 write 要为每行付一次调用开销，
    #: 实测 20 万行慢 3.2 倍；一次拼完整个文件又会占用几十 MB 内存，所以分块。
    CHUNK_LINES = 8192

    def write(self, doc, ir: ScnIR) -> None:
        if self._fh is None:
            return
        write = self._fh.write
        write(f"===== file={ir.sample_name} "
              f"sha256={ir.artifact.sha256} =====\n")
        chunk: list[str] = []
        append = chunk.append
        for line in iter_asm_lines(doc):
            append(line)
            if len(chunk) >= self.CHUNK_LINES:
                write("\n".join(chunk) + "\n")
                chunk.clear()
        if chunk:
            write("\n".join(chunk) + "\n")
        write("\n")

    def __exit__(self, *exc_info) -> None:
        if self._fh is None:
            return
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        if exc_info[0] is None and self.tmp is not None and self.path is not None:
            os.replace(self.tmp, self.path)
        else:
            self.tmp.unlink(missing_ok=True)
