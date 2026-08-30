"""二进制 → IR → asm.txt + 双行文本 + 覆盖证书。

用法：
    python disassembler.py <Script 目录或 SCPACK.idx>            拖放亦可
    python disassembler.py <输入> -o <输出目录> --source-encoding cp932
    python disassembler.py <输入> --no-asm                       跳过 asm 视图

产物统一落在**输入的共同父目录**下的 output/（§交付物）。原始文件永不写入。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import opcodelist
import profile_scpack as P

DIALECT = P.DIALECT


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """一次拼接一次写（§12.4），不逐行 write。"""
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n"
                for r in rows), encoding="utf-8")


def _json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def resolve_output(inputs: list[Path], explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    parents = {p if p.is_dir() else p.parent for p in inputs}
    if len(parents) == 1:
        return next(iter(parents)) / "output"
    common = Path(*Path(sorted(str(p) for p in parents)[0]).parts)
    return common / "output"


def layout_dirs(out: Path) -> dict[str, Path]:
    dirs = {name: out / name for name in
            ("ir", "asm", "texts", "rebuilt", "reports", "logs", "tmp", "checkpoints")}
    dirs["blobs"] = dirs["ir"] / "blobs"
    # 明文产物与加密产物必须共存且分开命名（§6.5）：加密结果覆盖同名明文会让
    # 「重新解析验证」失去对照物。站点偏移属于明文层，门禁也只能在这一层比对。
    dirs["plain"] = out / "plain"
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    (dirs["tmp"] / "failed").mkdir(exist_ok=True)
    return dirs


# ---------------------------------------------------------------------------
# ASM 视图（§5）：从 IR 投影的语义化文本，绝不出现原始十六进制转储
# ---------------------------------------------------------------------------
def render_asm(doc: P.ArchiveDoc, entry: P.EntryDoc) -> str:
    out: list[str] = [
        "; EAGLS 脚本条目",
        f'.dialect  "{DIALECT["dialect_id"]}" version "{DIALECT["schema_version"]}"',
        f'.encoding "{doc.encoding}"',
        '.tier     "T2"',
        f'.entry    "{entry.name}"',
        f".text_offset {entry.text_offset}",
        "",
        "; --- 标签表（offset 字段是条目内的引用站点） ---",
    ]
    for label in entry.labels:
        name = label.name.decode(doc.encoding, "replace")
        out.append(f'.label "{name}" -> loc_{label.offset:08X}'
                   f"   ; 站点 +{label.offset_site}")
    out.append("")
    out.append("; --- 语句流 ---")

    label_at = {lab.offset: lab.name.decode(doc.encoding, "replace")
                for lab in entry.labels}
    by_stmt: dict[int, list[P.TextEntry]] = {}
    for text in entry.entries:
        by_stmt.setdefault(text.stmt_index, []).append(text)

    for position, stmt in enumerate(entry.statements):
        if stmt.shape == "whitespace":
            continue
        if stmt.start in label_at:
            out.append("")
            out.append(f"loc_{stmt.start:08X}:   ; ${label_at[stmt.start]}")
        refs = by_stmt.get(position, ())
        note = ("   ; " + " ".join(f"idx={t.idx:08d}({t.tag})" for t in refs)) if refs else ""
        out.append("    " + _render_statement(doc, entry, stmt) + note)
    out.append("")
    return "\n".join(out)


def _render_statement(doc: P.ArchiveDoc, entry: P.EntryDoc, stmt: P.Statement) -> str:
    text = entry.body[stmt.start:stmt.end]
    if stmt.shape == "label":
        return f'.label_def "{text[1:].rstrip(chr(13) + chr(10))}"'
    if stmt.shape == "message":
        ident, body = stmt.groups[0], stmt.groups[1] or ""
        return f'MESSAGE  #{ident}, .string "{P.to_placeholders(body, doc.encoding)}"'
    if stmt.shape == "speaker":
        return f'SPEAKER  .string "{P.to_placeholders(text[1:], doc.encoding)}"'
    if stmt.shape == "call":
        opcode = stmt.groups[0]
        sub = stmt.groups[1]
        mnemonic = f"CALL.{opcode}" + (f".{sub}" if sub else "")
        args = text[text.index("(") + 1:text.rindex(")")]
        tail = "  {" if text.endswith("{") else ""
        return f"{mnemonic}  ({P.to_placeholders(args, doc.encoding)}){tail}"
    if stmt.shape == "block-open-numbered":
        return f"BLOCK.OPEN  {stmt.groups[0]},{stmt.groups[1]} {{"
    if stmt.shape == "block-close":
        return f"BLOCK.CLOSE {stmt.groups[0]}"
    if stmt.shape == "block-open-bare":
        return "BLOCK.OPEN  {"
    if stmt.shape == "assign":
        target = stmt.groups[0]
        index = stmt.groups[1] or ""
        rhs = text[text.index("=") + 1:]
        return f"SET      {target}{index} = {P.to_placeholders(rhs, doc.encoding)}"
    if stmt.shape == "nul":
        return ".byte 0        ; 正文终止符"
    raise P.ParseError("ASM_SHAPE", f"未实现 asm 渲染的形态 {stmt.shape}")


# ---------------------------------------------------------------------------
# 双行文本（§4.6）。只有一个渲染器，且只从 IR 投影 —— 两个渲染器必然随时间分叉，
# 而「双行文本能只从 ir/ 渲染出来」正是 IR 完备性的实作检验（铁律 2）。
# ---------------------------------------------------------------------------
def _dsat_from_ir(head: dict[str, Any], row: dict[str, Any],
                  entries: list[dict[str, Any]]) -> str:
    """从 IR 记录渲染一个源的双行文本，不碰原始归档。

    若这里缺字段，说明固化 IR 时漏存了东西，应补 _write_ir，
    而不是"再解一遍归档补上"。
    """
    spec = DIALECT["dsat"]
    orig, tran = spec["orig_mark"], spec["tran_mark"]
    width = spec["idx_width"]
    out = [
        f'# TEXT/{spec["format_version"]} ir={P.IR_VERSION} tool={P.TOOL_VERSION}'
        f' src_sha256={head["sha256"]}',
        f'# encoding source={head["source_encoding"]}'
        f' target={head["target_encoding"]} file=utf-8',
        f'# scope kind=partition range={row["name"]} part=1/1',
        "# tags " + " ".join(spec["tags"]),
        f'# entry name={row["name"]} sha256={row["sha256"]}',
        "",
    ]
    for text in entries:
        ident = f'{text["idx"]:0{width}d}'
        meta = [f"# idx={ident}", f'off={text["char_start"]}', f'tag={text["tag"]}']
        policy = text.get("translate_policy", "translatable")
        if policy != "translatable":
            meta.append(f"policy={policy}")
        if text["tag"] == "name" and text.get("speaker_kind") == "virtual":
            candidates = text.get("speaker_candidates", [])
            meta.append("resolved=" + (
                candidates[0] if len(candidates) == 1
                else "AMBIGUOUS:" + "/".join(candidates) if candidates
                else "UNRESOLVED"))
        if text.get("speaker"):
            meta.append(f'speaker={text["speaker"]}')
        out.append(" ".join(meta))
        out.append(f'{orig}{ident}{orig}{text["tag"]}{orig}{text["source"]}')
        out.append(f'{tran}{ident}{tran}{text["tag"]}{tran}{text["source"]}')
        out.append("")
    return "\n".join(out)


def export_texts(out_dir: Path, progress: Any = None) -> dict[str, Any]:
    """第 ② 步：从固化的 IR 投影出 texts/*.txt。

    与 ① 分离是有意的：① 的产物是 IR 与证书（机器读），② 的产物是给人编辑的
    工作面。分离让「往返自检没通过」时不会产出一份翻了才发现装不回去的译文，
    也让译者能在不重跑解析的情况下重新导出一份干净的译文（§11.3）。
    """
    report = lambda frac, note: progress(frac, note) if progress else None
    ir = out_dir / "ir"
    manifest_path = ir / "manifest.jsonl"
    if not manifest_path.exists():
        raise P.ParseError("IR_MISSING", f"找不到 {manifest_path}；请先执行反汇编")

    report(0.05, "读取 IR")
    rows = [json.loads(line) for line in
            manifest_path.read_text(encoding="utf-8").splitlines()]
    head, sources = rows[0], rows[1:]
    texts = [json.loads(line) for line in
             (ir / "text_entries.jsonl").read_text(encoding="utf-8").splitlines()]

    texts_dir = out_dir / "texts"
    texts_dir.mkdir(parents=True, exist_ok=True)
    for stale in texts_dir.glob("*.txt"):
        stale.unlink()

    total = 0
    for index, row in enumerate(sources):
        # manifest 记了每源在 text_entries.jsonl 中的行区间，按区间切片即可，
        # 不必按 src_id 过滤整库（§2.3 合库布局的用法）。
        start, end = row["text_lines"]
        chunk = texts[start:end]
        (texts_dir / f'{row["name"]}.txt').write_text(
            _dsat_from_ir(head, row, chunk),
            encoding=DIALECT["dsat"]["file_encoding"])
        total += len(chunk)
        if index % 32 == 0:
            report(0.05 + 0.9 * index / max(1, len(sources)),
                   f'导出 {row["name"]}')

    translatable = sum(1 for t in texts
                       if t.get("translate_policy", "translatable") == "translatable")
    summary = {
        "ok": total == len(texts),
        "files": len(sources),
        "text_entries": total,
        "translatable": translatable,
        "locked": total - translatable,
        "texts_dir": str(texts_dir),
        "target_encoding": head["target_encoding"],
    }
    _json(out_dir / "reports" / "export.json", summary)
    report(1.0, "完成")
    return summary


# ---------------------------------------------------------------------------
# 覆盖证书（§8）
# ---------------------------------------------------------------------------
def build_certificate(doc: P.ArchiveDoc, target: str, roundtrip: dict[str, Any]
                      ) -> dict[str, Any]:
    source = doc.idx_raw if target == "idx" else doc.pak_raw
    intervals = doc.regions(target)
    counts: dict[str, int] = {}
    tiers: dict[str, int] = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    for iv in intervals:
        span = iv["end"] - iv["start"]
        counts[iv["status"]] = counts.get(iv["status"], 0) + span
        tiers[iv["decode_tier"]] += span
    covered = sum(iv["end"] - iv["start"] for iv in intervals)
    min_tier = min((iv["decode_tier"] for iv in intervals), default="T0")
    text_entries = doc.text_entries
    sources: dict[str, int] = {k: 0 for k in
                               ("structural", "anchor", "binding", "heuristic",
                                "user", "unresolved")}
    for text in text_entries:
        sources[text.tag_source] += 1
    return {
        "schema_version": "1.1.0",
        "layer_id": "L000",
        "source": (doc.idx_path if target == "idx" else doc.pak_path).name,
        "source_size": len(source),
        "intervals": intervals,
        "gaps": [],
        "overlaps": [],
        "status_counts": counts,
        "byte_coverage": covered / len(source) if source else 1.0,
        "structural_coverage": 1.0,
        "tier_coverage": tiers,
        "min_tier": min_tier,
        "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
        "tier_blocked": [],
        "instruction_coverage": "not_applicable",
        "analysis_mode": "bytecode-disasm",
        "unpack_mode": "targeted",
        "text_source": "embedded",
        "declared_tier": min_tier,
        "decision_evidence_refs": ["EV_PAK_KEY", "EV_TEXT_OFFSET", "EV_CALL_NUMERIC"],
        "tag_source_counts": sources,
        "transform_edges": [
            {"id": "L_IDX_CIPHER", "algorithm":
             DIALECT["archive"]["idx_cipher"]["algorithm"],
             "input_hash": P.sha256_bytes(doc.idx_raw),
             "output_hash": P.sha256_bytes(doc.idx_plain),
             "reversible": True, "order": 0},
            {"id": "L_PAK_CIPHER", "algorithm":
             DIALECT["entry"]["pak_cipher"]["algorithm"],
             "version": doc.cipher_version,
             "input_hash": P.sha256_bytes(doc.pak_raw),
             "output_hash": P.sha256_bytes(
                 b"".join(e.body_raw for e in doc.entries)),
             "reversible": True, "order": 1},
        ],
        "roundtrip": roundtrip,
        "toolchain": {"tool": P.TOOL_VERSION, "ir": P.IR_VERSION,
                      "dialect": DIALECT["dialect_id"],
                      "dialect_schema": DIALECT["schema_version"],
                      "python": sys.version.split()[0]},
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def disassemble(script_dir: Path, out_dir: Path, *, source_encoding: str | None = None,
                target_encoding: str | None = None, alis: bool = False,
                write_asm: bool = True, progress: Any = None) -> dict[str, Any]:
    started = time.perf_counter()
    dirs = layout_dirs(out_dir)
    report = lambda frac, note: progress(frac, note) if progress else None

    report(0.02, "读取归档并求解密钥")
    doc = P.parse_archive(script_dir, source_encoding, alis)
    target_encoding = target_encoding or DIALECT["entry"]["encoding"]["target"]

    # ---- 零编辑往返自检（§9）。不通过则不产出可编辑产物。
    report(0.35, "零编辑往返自检")
    idx_rebuilt, pak_rebuilt, _, _ = P.rebuild_archive(doc)
    identical = idx_rebuilt == doc.idx_raw and pak_rebuilt == doc.pak_raw
    roundtrip = {
        "zero_edit_identical": identical,
        "idx_source_sha256": P.sha256_bytes(doc.idx_raw),
        "idx_rebuilt_sha256": P.sha256_bytes(idx_rebuilt),
        "pak_source_sha256": P.sha256_bytes(doc.pak_raw),
        "pak_rebuilt_sha256": P.sha256_bytes(pak_rebuilt),
    }
    if not identical:
        # 只有在自检失败时第二轮才提供信息（§12.8）：定位首个不一致偏移。
        roundtrip["first_diff"] = _first_diff(doc, idx_rebuilt, pak_rebuilt)
        (dirs["tmp"] / "failed" / "SCPACK.idx").write_bytes(idx_rebuilt)
        (dirs["tmp"] / "failed" / "SCPACK.pak").write_bytes(pak_rebuilt)

    report(0.5, "固化 IR")
    idx_sha = P.sha256_bytes(doc.idx_raw)
    pak_sha = P.sha256_bytes(doc.pak_raw)
    manifest = _write_ir(doc, dirs, idx_sha, pak_sha, target_encoding)
    # 明文 idx 单独落盘：站点偏移是明文层的坐标，check_sites.py 必须在明文上比对，
    # 在密文上比对会把「同一个值加密后不同」误判为改写（§6.5 两者并存分开命名）。
    (dirs["plain"] / f"{doc.idx_path.name}.plain").write_bytes(doc.idx_plain)

    report(0.7, "写 asm 视图" if write_asm else "跳过 asm 视图")
    if write_asm:
        for entry in doc.entries:
            (dirs["asm"] / f"{entry.name}.asm.txt").write_text(
                render_asm(doc, entry), encoding="utf-8")

    report(0.9, "写覆盖证书")
    certs = {}
    for target in ("idx", "pak"):
        cert = build_certificate(doc, target, roundtrip)
        certs[target] = cert
        _json(dirs["reports"] / f"coverage_certificate_{target}.json", cert)
    _json(dirs["reports"] / "coverage_certificate.json", certs["pak"])
    _json(dirs["reports"] / "rule_hits.json",
          {"hits": doc.rule_hits, "candidates_rejected": doc.rule_misses,
           "note": "misses 为未命中任何规则的候选串（未提取），非错误；"
                   "命中 0 次的规则需复查是否形同虚设"})
    _json(dirs["reports"] / "window_hits.json", P.window_hits())
    _json(dirs["reports"] / "shape_signatures.json", doc.shape_signatures)
    _json(out_dir / "decision.json", _decision(doc, certs["pak"]))
    _json(out_dir / "case.json", _case(doc, idx_sha, pak_sha))

    summary = {
        "ok": identical,
        "output": str(out_dir),
        "entries": len(doc.entries),
        "text_entries": len(doc.text_entries),
        "statements": sum(len(e.statements) for e in doc.entries),
        "zero_edit_identical": identical,
        "byte_coverage": {t: certs[t]["byte_coverage"] for t in certs},
        "min_tier": certs["pak"]["min_tier"],
        "tag_counts": _count(doc, "tag"),
        "policy_counts": _count(doc, "translate_policy"),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "manifest_rows": len(manifest),
    }
    # 产出合理性门禁必须在此处执行，不能只放在 CLI 的 main() 里：
    # GUI 直接调用本函数，两个入口必须产出相同的 summary（§11.8）。
    # 门禁是硬要求，字节门禁全过仍可能一条正文都没提取到（§0.1）。
    summary["sanity_problems"] = sanity_gate(summary)
    summary["ok"] = identical and not summary["sanity_problems"]
    _json(dirs["reports"] / "verify.json", summary)
    report(1.0, "完成" if summary["ok"] else "自检未通过")
    return summary


def _count(doc: P.ArchiveDoc, field_name: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for text in doc.text_entries:
        key = getattr(text, field_name)
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def _first_diff(doc: P.ArchiveDoc, idx_rebuilt: bytes, pak_rebuilt: bytes
                ) -> dict[str, Any]:
    for name, original, rebuilt in (("idx", doc.idx_raw, idx_rebuilt),
                                    ("pak", doc.pak_raw, pak_rebuilt)):
        if original == rebuilt:
            continue
        limit = min(len(original), len(rebuilt))
        for pos in range(limit):
            if original[pos] != rebuilt[pos]:
                return {"target": name, "offset": pos,
                        "source_byte": original[pos], "rebuilt_byte": rebuilt[pos]}
        return {"target": name, "offset": limit, "reason": "length differs",
                "source_size": len(original), "rebuilt_size": len(rebuilt)}
    return {}


def _write_ir(doc: P.ArchiveDoc, dirs: dict[str, Path], idx_sha: str, pak_sha: str,
              target_encoding: str) -> list[dict[str, Any]]:
    """IR 合库：整个作业共用一套 JSONL，每条带 src_id，按 src_id 连续写（§2.3）。"""
    ir = dirs["ir"]
    manifest: list[dict[str, Any]] = []
    regions: list[dict[str, Any]] = []
    cells: list[dict[str, Any]] = []
    anchors: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    texts: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    for region in doc.regions("idx"):
        regions.append(dict(region, src_id=-1, target="idx"))
    idx_regions = len(regions)

    binding_spec = DIALECT["name_binding"]
    for shape in DIALECT["statement_shapes"]:
        anchors.append({
            "anchor_id": shape["id"], "kind": shape["kind"],
            "pattern": DIALECT["patterns"].get(
                shape["match"].get("pattern_id", ""), ""),
            "mask": None,
            "operand_slots": [k for k in ("text_slot", "name_slot", "id_group",
                                          "text_group") if k in shape],
            "evidence_refs": shape.get("evidence_refs", []),
            "confidence": shape.get("confidence", "derived"),
        })

    pak_regions = doc.regions("pak")
    per_src: dict[int, list[dict[str, Any]]] = {}
    for region in pak_regions:
        src_id = int(region["id"].split("_")[1]) if region["id"].startswith("R_0") else -1
        per_src.setdefault(src_id, []).append(region)

    binding_id = 0
    for entry in doc.entries:
        text_start = len(texts)
        region_start = len(regions)
        for region in per_src.get(entry.src_id, ()):
            regions.append(dict(region, src_id=entry.src_id, target="pak"))
        for label in entry.labels:
            labels.append({"src_id": entry.src_id, "ordinal": label.ordinal,
                           "name": label.name.decode(doc.encoding, "replace"),
                           "offset": label.offset, "site": label.offset_site})
        cells.append({"src_id": entry.src_id, "region_id": f"R_{entry.src_id:04d}_LABELS",
                      "cell_size": DIALECT["entry"]["label_record"]["size"],
                      "cell_count": len(entry.labels) + 1, "endianness": "little",
                      "evidence_refs": ["EV_LABEL_TABLE"]})
        for position, stmt in enumerate(entry.statements):
            if stmt.shape == "whitespace":
                continue
            hits.append({"src_id": entry.src_id, "anchor_id": stmt.shape,
                         "hit_offset": stmt.start, "end_offset": stmt.end,
                         "kind": stmt.kind,
                         "resolved_operands": [g for g in stmt.groups if g is not None],
                         "stmt_index": position})
        for text in entry.entries:
            texts.append(text.to_json())
            if text.tag == "msg" and text.speaker:
                binding_id += 1
                # 虚拟名（名字存在变量里）与字面名各自如实记录；歧义时保留全部候选，
                # 不输出确定值（§4.7）。
                ambiguous = len(text.speaker_candidates) > 1
                bindings.append({
                    "binding_id": f"B{binding_id:06d}", "src_id": entry.src_id,
                    "msg_entry_idx": text.idx,
                    "name_entry_idx": text.speaker_entry_idx,
                    "name_kind": text.speaker_kind or "unresolved",
                    "name_ref": text.speaker_ref,
                    "method": ("explicit-id" if text.speaker_kind == "virtual"
                               else binding_spec["method"]),
                    "extractor_ids": ["speaker-adjacent-message"],
                    "agreed_by": ["speaker-adjacent-message"],
                    "confidence": ("ambiguous" if ambiguous
                                   else binding_spec["confidence"]),
                    "candidates": list(text.speaker_candidates),
                    "evidence_refs": binding_spec["evidence_refs"]})
        manifest.append({
            "src_id": entry.src_id, "name": entry.name,
            "sha256": P.sha256_bytes(entry.raw), "size": len(entry.raw),
            "offset_in_pak": entry.record.offset - doc.base_offset,
            "tier": "T2", "text_offset": entry.text_offset,
            "labels": len(entry.labels), "statements": len(entry.statements),
            "text_entries": len(entry.entries),
            "region_lines": [region_start, len(regions)],
            "text_lines": [text_start, len(texts)],
        })

    manifest.insert(0, {
        "src_id": -1, "name": doc.idx_path.name, "sha256": idx_sha,
        "size": len(doc.idx_raw), "tier": "T1",
        "pak_sha256": pak_sha, "pak_size": len(doc.pak_raw),
        "idx_key_source": doc.idx_key_source, "pak_key_source": doc.pak_key_source,
        "cipher_version": doc.cipher_version,
        "source_encoding": doc.encoding, "target_encoding": target_encoding,
        "region_lines": [0, idx_regions],
    })

    _jsonl(ir / "manifest.jsonl", manifest)
    _jsonl(ir / "regions.jsonl", regions)
    _jsonl(ir / "cells.jsonl", cells)
    _jsonl(ir / "anchors.jsonl", anchors)
    _jsonl(ir / "anchor_hits.jsonl", hits)
    _jsonl(ir / "join_sites.jsonl", doc.join_sites())
    _jsonl(ir / "text_entries.jsonl", texts)
    _jsonl(ir / "name_bindings.jsonl", bindings)
    _jsonl(ir / "labels.jsonl", labels)
    _jsonl(ir / "instructions.jsonl", [])       # T2：无指令对象（§1.4）

    # blobs/ 内容寻址，重复内容只存一份（§2.3）
    for entry in doc.entries:
        digest = P.sha256_bytes(entry.raw)
        shard = dirs["blobs"] / digest[:2]
        shard.mkdir(parents=True, exist_ok=True)
        blob = shard / digest
        if not blob.exists():
            blob.write_bytes(entry.raw)
    return manifest


def _decision(doc: P.ArchiveDoc, cert: dict[str, Any]) -> dict[str, Any]:
    return {
        "analysis_mode": "bytecode-disasm",
        "declared_tier": cert["min_tier"],
        "unpack_mode": "targeted",
        "text_source": "embedded",
        "repack_strategy": "pointer-rewrite",
        "dialect_id": DIALECT["dialect_id"],
        "decision_evidence_refs": ["EV_IDX_KEY", "EV_PAK_KEY", "EV_TEXT_OFFSET",
                                   "EV_CALL_NUMERIC", "EV_SPEAKER_BINDING"],
        "decision_rationale":
            "文本封在 SCPACK.pak 的加密条目内，必须解密到正文才能定位；正文是 CP932"
            "文本 DSL，语句边界在字符层，故申报 T2（形态与参数槽已证明，未申报指令语义）。"
            "标签表 offset 字段与 idx 记录 offset/length 字段构成完整引用站点集合，"
            "因此变长回封可用 pointer-rewrite。",
        "user_override": None,
    }


def _case(doc: P.ArchiveDoc, idx_sha: str, pak_sha: str) -> dict[str, Any]:
    return {
        "profile_id": "profile_scpack",
        "dialect_id": DIALECT["dialect_id"],
        "engine_id": DIALECT["engine_id"],
        "sources": [
            {"name": doc.idx_path.name, "sha256": idx_sha, "size": len(doc.idx_raw)},
            {"name": doc.pak_path.name, "sha256": pak_sha, "size": len(doc.pak_raw)},
        ],
        "dialect_selection": {
            "method": "structural-probe",
            "evidence": [
                f"idx_key={doc.idx_key_source}",
                f"pak_key={doc.pak_key_source}",
                f"record_variant={doc.layout['variant']}",
                f"cipher_version={doc.cipher_version}",
                f"text_offset={doc.entries[0].text_offset}",
                f"records={len(doc.records)}",
            ],
            "candidates_rejected": [
                {"dialect_id": "EAGLS_ALIS",
                 "reason": "ALIS 变体标签记录 136 字节、正文起点固定 136000；"
                           "本样本标签表在 36 字节步长下终止且正文起点推导为 3600"},
                {"dialect_id": "EAGLS_CIPHER_V1",
                 "reason": "v1 连续 XOR 无法满足 605 处标签已知明文，v2 隔字节 XOR 满足"},
            ],
        },
        "shape_signatures": doc.shape_signatures,
        "rule_hits": doc.rule_hits,
        "cross_sample_validation": {
            "performed": False,
            "note": "仅在本作品（HENSIN-PKPDL，307 条目）上验证；"
                    "未进行跨样本验证，列为已知风险（§0.3）",
        },
    }


# ---------------------------------------------------------------------------
# 产出合理性门禁（§0.1）：内容层检查，与字节门禁正交
# ---------------------------------------------------------------------------
def sanity_gate(summary: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    tags = summary["tag_counts"]
    total = summary["text_entries"]
    if not total:
        problems.append("提取到 0 条文本；剧本类样本不可能为 0（§0.1）")
        return problems
    if not tags.get("msg"):
        problems.append("正文（msg）0 条；含对话的作品不可能为 0（§0.1）")
    for tag, count in tags.items():
        if count / total > 0.95 and len(tags) > 1:
            problems.append(f"产出高度倾斜：{tag} 占 {count / total:.1%}（§0.1）")
    if summary["statements"] and total / summary["statements"] < 0.01:
        problems.append(f"文本条数 {total} 与语句数 {summary['statements']} "
                        f"数量级不符（§0.1）")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", type=Path, nargs="+",
                        help="Script 目录，或其中的 SCPACK.idx / SCPACK.pak")
    parser.add_argument("-o", "--output", type=Path, help="输出目录，缺省为输入父目录下 output/")
    parser.add_argument("--source-encoding", default=None, help="原文编码，缺省取方言声明")
    parser.add_argument("--target-encoding", default=None, help="译文编码，缺省同原文")
    parser.add_argument("--alis", action="store_true", help="ALIS 变体（136 字节标签记录）")
    parser.add_argument("--no-asm", action="store_true", help="跳过 asm 视图，只出 IR 与文本")
    parser.add_argument("--export-texts", action="store_true",
                        help="只做第 ② 步：从已有 IR 导出双行文本，不重新解析")
    args = parser.parse_args(argv)

    dirs = {p if p.is_dir() else p.parent for p in args.inputs}
    if len(dirs) != 1:
        sys.stderr.write("错误：请一次只处理一个 Script 目录\n")
        return 2
    script_dir = next(iter(dirs))
    out_dir = resolve_output(args.inputs, args.output)

    def show(frac: float, note: str) -> None:
        sys.stderr.write(f"\r[{frac * 100:5.1f}%] {note:<40}")
        if frac >= 1.0:
            sys.stderr.write("\n")

    try:
        if args.export_texts:
            summary = export_texts(out_dir, progress=show)
        else:
            summary = disassemble(script_dir, out_dir,
                                  source_encoding=args.source_encoding,
                                  target_encoding=args.target_encoding,
                                  alis=args.alis, write_asm=not args.no_asm,
                                  progress=show)
    except P.ParseError as exc:
        sys.stderr.write(f"\n解析失败 {exc.code}: {exc.detail}\n")
        if exc.ctx:
            sys.stderr.write(f"  上下文: {exc.ctx}\n")
        return 1

    text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    print(text)
    for item in summary.get("sanity_problems", ()):
        sys.stderr.write(f"产出合理性门禁未通过：{item}\n")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
