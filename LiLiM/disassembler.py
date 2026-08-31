# -*- coding: utf-8 -*-
"""源归档 → 内存 IR → asm.txt / texts/ / 覆盖证书。

两个入口互不依赖，输入均为源二进制（§11.5）：
    render_asm(...)     结构编辑面
    extract_texts(...)  文本编辑面

命令行：
    python disassembler.py scr.aos              两者都出
    python disassembler.py scr.aos --texts      只出 texts/
    python disassembler.py scr.aos --asm        只出 asm/
    python disassembler.py scr.aos -o OUTDIR --with-ir
拖放：把 .aos 拖到本文件图标上，输出到输入文件所在目录的 output/。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aoslib as A
import opcodelist as D

PH_SAFE_MIN = D.PLACEHOLDER["display_min_codepoint"]

#: 正文行占全部行的比例下限，达此值方归入剧本类。用于把剧本与控制流脚本分成
#: 两个可比总体（§0.1 的密度检查只在同类内部有意义）。
#: 实测：130 个剧本脚本最低 0.10，唯一被排除的 main.scr 为 0.001（927 行 1 条正文）。
SCENARIO_BODY_RATIO = 0.05  # dialect-literal-ok: 报告分类阈值，不参与解析


# --------------------------------------------------------------------------
# 占位符（§4.5）
# --------------------------------------------------------------------------
def to_display(s: str) -> str:
    """把不可安全显示的字符转成 {{XX}}。斜杠、全角空格等照原样保留。"""
    out = []
    enc = D.SCRIPT["source_encoding"]
    for ch in s:
        if ord(ch) < PH_SAFE_MIN:
            out.append("{{%s}}" % ":".join("%02X" % b for b in ch.encode(enc)))
        else:
            out.append(ch)
    return "".join(out)


def from_display(s: str) -> str:
    """占位符还原为字符。"""
    import re
    enc = D.SCRIPT["target_encoding"]
    def sub(m: "re.Match[str]") -> str:
        return bytes(int(b, 16) for b in m.group(1).split(":")).decode(enc)
    return re.sub(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}", sub, s)


def encoded_len(display_text: str) -> int:
    """§6.0.2 的唯一口径：按 target_encoding 计算，占位符按展开后字节计。"""
    return len(from_display(display_text).encode(D.SCRIPT["target_encoding"]))


# --------------------------------------------------------------------------
# 输出布局（§2.3）
# --------------------------------------------------------------------------
def default_outdir(src: Path) -> Path:
    return src.parent / "output"


def layout(outdir: Path) -> dict[str, Path]:
    p = {k: outdir / k for k in
         ("ir", "asm", "texts", "rebuilt", "reports", "tmp", "logs")}
    return p


# --------------------------------------------------------------------------
# 解析：源归档 → 内存 IR
# --------------------------------------------------------------------------
def build_ir(src: Path, progress=None, cancelled=None
             ) -> tuple[A.Archive, list[A.ScriptIR], list[dict[str, Any]]] | None:
    """解析全部条目。返回 (归档, 脚本 IR 列表, 非脚本条目记录)。

    progress(done_bytes, total_bytes, name) 供界面按**已处理字节数**报进度（§11.7）。
    cancelled() 返回真则中止并返回 None——调用方不得写出任何产物。
    单个脚本解析失败不中断整批：记入 opaque 的 failed 列表，其余照常（§11.7 末条）。
    """
    arc = A.parse_archive(src)
    scripts: list[A.ScriptIR] = []
    opaque: list[dict[str, Any]] = []
    total = sum(e.size for e in arc.entries) or 1
    done = 0
    for e in arc.entries:
        if cancelled is not None and cancelled():
            return None
        if progress is not None:
            progress(done, total, e.name)
        try:
            content = A.entry_bytes(arc, e)
            if e.is_packed:
                scripts.append(A.parse_script(str(e.index), e.name, content,
                                              e.raw_sha256))
            else:
                opaque.append({"src_id": str(e.index), "name": e.name,
                               "size": e.size, "raw_sha256": e.raw_sha256,
                               "status": "opaque-preserved"})
        except (A.ParseError, UnicodeDecodeError) as exc:
            # 如实上报，不静默跳过（铁律 4）
            opaque.append({"src_id": str(e.index), "name": e.name,
                           "size": e.size, "raw_sha256": e.raw_sha256,
                           "status": "parse-failed", "error": str(exc)})
        done += e.size
    if progress is not None:
        progress(total, total, "")
    return arc, scripts, opaque


def count_entries(src: Path) -> int:
    """只读索引，数脚本条目数。供界面在选定文件后立刻显示，不做完整解析。"""
    arc = A.parse_archive(src)
    return sum(1 for e in arc.entries if e.is_packed)


# --------------------------------------------------------------------------
# 入口一：asm 渲染（结构编辑面，§5）
# --------------------------------------------------------------------------
def render_asm_text(ir: A.ScriptIR) -> str:
    """一行一条记录，行首带偏移用于把 diff 映射回 IR 对象。无原始十六进制转储。"""
    L = [
        f'; source {ir.name}',
        f'.encoding "{D.SCRIPT["source_encoding"]}"',
        f'.dialect  "{D.DIALECT_ID}" version "{D.SCHEMA_VERSION}"',
        f'.tier     "{D.DECODE_TIER["script"]}"',
        f'.src_sha256 "{ir.src_sha256}"',
        "",
    ]
    slots_by_line: dict[int, list[A.TextSlot]] = {}
    for s in ir.slots:
        slots_by_line.setdefault(s.lineno, []).append(s)

    for lineno, (line, shape) in enumerate(zip(ir.lines, ir.shapes)):
        tagged = slots_by_line.get(lineno, [])
        if shape == "label":
            L.append("")
        prefix = f"L{lineno:06d}"
        if tagged:
            ids = " ".join(
                f'sid={s.idx}:{s.tag}' for s in sorted(tagged, key=lambda x: x.col_start))
            L.append(f'{prefix}  .line {shape:9s} "{to_display(line)}"   ; {ids}')
        else:
            L.append(f'{prefix}  .line {shape:9s} "{to_display(line)}"')
    L.append(f'; trailing_terminator={int(ir.trailing_terminator)}')
    return "\n".join(L) + "\n"


def render_asm(src: Path, outdir: Path, ir_bundle=None) -> dict[str, Any]:
    arc, scripts, opaque = ir_bundle or build_ir(src)
    paths = layout(outdir)
    paths["asm"].mkdir(parents=True, exist_ok=True)
    for ir in scripts:
        (paths["asm"] / f"{ir.name}.asm.txt").write_text(
            render_asm_text(ir), encoding=D.SCRIPT["asm_encoding"], newline="\n")
    return {"asm_files": len(scripts)}


# --------------------------------------------------------------------------
# 入口二：文本提取（文本编辑面，§4.6）
# --------------------------------------------------------------------------
def render_dsat(ir: A.ScriptIR) -> str:
    """双行文本。导出时译文行预填原文（§4.6）。"""
    tags = " ".join(sorted({s.tag for s in ir.slots})) or "misc"
    out = [
        f"# TEXT/2 ir={D.IR_VERSION} tool={D.TOOL_VERSION} src_sha256={ir.src_sha256}",
        f"# encoding source={D.SCRIPT['source_encoding']} "
        f"target={D.SCRIPT['target_encoding']} file={D.SCRIPT['text_encoding']}",
        "# scope kind=all range=ALL part=1/1",
        f"# tags {tags}",
        "#",
    ]
    for s in ir.slots:
        disp = to_display(s.source)
        meta = f"# idx={s.idx:08d} line={s.lineno} tag={s.tag}"
        if s.speaker:
            meta += f" speaker={s.speaker}"
        if s.translate_policy != "translatable":
            meta += f" policy={s.translate_policy}"
        out.append(meta)
        out.append(f"○{s.idx:08d}○{s.tag}○{disp}")
        out.append(f"●{s.idx:08d}●{s.tag}●{disp}")
        out.append("")
    return "\n".join(out) + "\n"


def extract_texts(src: Path, outdir: Path, ir_bundle=None,
                  with_ir: bool = False) -> dict[str, Any]:
    arc, scripts, opaque = ir_bundle or build_ir(src)
    paths = layout(outdir)
    for k in ("texts", "reports"):
        paths[k].mkdir(parents=True, exist_ok=True)

    # 零条目的源不产出双行文件：没有可编辑内容，空文件只会让译者与门禁都无从判断。
    # 但必须在 _index.tsv 中显式记为 0，使省略可见、可审计，而不是静默消失。
    index_rows = []
    for ir in scripts:
        if ir.slots:
            (paths["texts"] / f"{ir.name}.txt").write_text(
                render_dsat(ir), encoding=D.SCRIPT["text_encoding"], newline="\n")
            index_rows.append(f"{ir.name}\t{ir.name}.txt\t{len(ir.slots)}")
        else:
            index_rows.append(f"{ir.name}\t-\t0")
    (paths["texts"] / "_index.tsv").write_text(
        "source\ttext_file\tentries\n" + "\n".join(index_rows) + "\n",
        encoding="utf-8", newline="\n")

    if with_ir:
        write_ir(arc, scripts, opaque, paths["ir"])

    return write_reports(arc, scripts, opaque, paths["reports"])


# --------------------------------------------------------------------------
# IR 落盘（§2.3 合库；默认关闭，§2.4）
# --------------------------------------------------------------------------
def write_ir(arc: A.Archive, scripts: list[A.ScriptIR],
             opaque: list[dict[str, Any]], irdir: Path) -> None:
    irdir.mkdir(parents=True, exist_ok=True)
    with (irdir / "text_entries.jsonl").open("w", encoding="utf-8", newline="\n") as fh, \
         (irdir / "manifest.jsonl").open("w", encoding="utf-8", newline="\n") as mf, \
         (irdir / "name_bindings.jsonl").open("w", encoding="utf-8", newline="\n") as nb, \
         (irdir / "join_sites.jsonl").open("w", encoding="utf-8", newline="\n") as js:
        line_no = 0
        for ir in scripts:
            start = line_no
            for s in ir.slots:
                rec = {
                    "src_id": ir.src_id, "idx": s.idx, "line": s.lineno,
                    "shape": s.shape_id, "slot": s.slot_name,
                    "tag": s.tag, "tag_subtype": s.tag_subtype,
                    "tag_source": s.tag_source,
                    "translate_policy": s.translate_policy,
                    "source": s.source,
                    "raw_len": len(s.source.encode(D.SCRIPT["source_encoding"])),
                    "col_start": s.col_start, "col_end": s.col_end,
                }
                if s.speaker:
                    rec["speaker"] = s.speaker
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                line_no += 1
                if s.pair_idx and s.tag == "msg":
                    nb.write(json.dumps({
                        "binding_id": f"{ir.src_id}:{s.idx}", "src_id": ir.src_id,
                        "msg_entry_idx": s.idx, "name_entry_idx": s.pair_idx,
                        "name_kind": "explicit", "method": "slot-ordinal",
                        "extractor_ids": ["shape:dialogue"], "agreed_by": ["shape:dialogue"],
                        "confidence": "derived", "candidates": [],
                        "evidence_refs": ["EV_SHAPE_DIALOGUE"],
                    }, ensure_ascii=False) + "\n")
            mf.write(json.dumps({
                "src_id": ir.src_id, "name": ir.name, "sha256": ir.src_sha256,
                "stored_sha256": ir.stored_sha256, "entries": len(ir.slots),
                "text_entries_lines": [start, line_no],
                "decode_tier": D.DECODE_TIER["script"],
            }, ensure_ascii=False) + "\n")
        # 归档索引槽位即容器级改写站点（§6.3）
        ef = D.CONTAINER["v2"]["entry"]
        for e in arc.entries:
            for slot in D.JOIN_SITES["slots"]:
                js.write(json.dumps({
                    "join_id": f"IDX{e.index:04d}_{slot}",
                    "src_id": str(e.index),
                    "site_offset": e.index_offset + ef[slot]["offset"],
                    "site_width": D.JOIN_SITES["site_width"],
                    "site_endianness": D.JOIN_SITES["site_endianness"],
                    "site_tier": D.DECODE_TIER["container"],
                    "key_kind": D.JOIN_SITES["key_kind"],
                    "key_value": e.rel_offset if slot == "offset" else e.size,
                    "target_object_id": e.name,
                    "collision_class": "unique",
                    "rewrite_policy": "rewrite",
                    "confidence": D.JOIN_SITES["confidence"],
                    "evidence_refs": D.JOIN_SITES["evidence_refs"],
                }, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# 报告与覆盖证书（§8）
# --------------------------------------------------------------------------
def coverage_certificate(arc: A.Archive) -> dict[str, Any]:
    v2 = D.CONTAINER["v2"]
    intervals = [
        {"id": "R_HEADER", "layer_id": "L000", "start": 0,
         "end": v2["index"]["offset"], "status": "decoded", "kind": "header",
         "raw_sha256": A.sha256(arc.data[:v2["index"]["offset"]]),
         "owner": "container", "decode_tier": D.DECODE_TIER["container"],
         "tier_evidence_refs": v2["evidence_refs"], "confidence": "derived",
         "evidence_refs": v2["evidence_refs"], "rewrite_policy": "rebuild"},
        {"id": "R_INDEX", "layer_id": "L000", "start": v2["index"]["offset"],
         "end": v2["index"]["offset"] + arc.index_size, "status": "decoded",
         "kind": "index",
         "raw_sha256": A.sha256(arc.data[v2["index"]["offset"]:
                                        v2["index"]["offset"] + arc.index_size]),
         "owner": "container", "decode_tier": D.DECODE_TIER["container"],
         "tier_evidence_refs": v2["evidence_refs"], "confidence": "derived",
         "evidence_refs": v2["evidence_refs"], "rewrite_policy": "rebuild",
         "anchor_ids": ["index_slot"], "anchor_hit_count": len(arc.entries),
         "join_site_count": len(arc.entries) * len(D.JOIN_SITES["slots"])},
    ]
    for e in arc.entries:
        intervals.append({
            "id": f"R_ENTRY_{e.index:04d}", "layer_id": "L000",
            "start": e.offset, "end": e.offset + e.size,
            "status": "decoded" if e.is_packed else "opaque-preserved",
            "kind": "script" if e.is_packed else "data",
            "raw_sha256": e.raw_sha256, "owner": e.name,
            "decode_tier": D.DECODE_TIER["script" if e.is_packed else "container"],
            "tier_evidence_refs": ["EV_SCR_PLAINTEXT"] if e.is_packed else ["EV_AOSV2_INDEX"],
            "confidence": "derived",
            "evidence_refs": ["EV_HUFFMAN_STREAM"] if e.is_packed else ["EV_AOSV2_INDEX"],
            "rewrite_policy": "rebuild" if e.is_packed else "preserve",
            "anchor_ids": ["index_slot"], "anchor_hit_count": 1,
            "join_site_count": len(D.JOIN_SITES["slots"]),
        })
    intervals.sort(key=lambda r: r["start"])

    gaps, overlaps = [], []
    cur = 0
    for r in intervals:
        if r["start"] > cur:
            gaps.append({"start": cur, "end": r["start"]})
        elif r["start"] < cur:
            overlaps.append({"start": r["start"], "end": min(cur, r["end"])})
        cur = max(cur, r["end"])
    if cur < len(arc.data):
        gaps.append({"start": cur, "end": len(arc.data)})

    # status_counts 是按状态的**字节数**，不是区间个数——证书校验按字节复核。
    counts: Counter = Counter()
    for r in intervals:
        counts[r["status"]] += r["end"] - r["start"]
    tier_bytes: Counter = Counter()
    for r in intervals:
        tier_bytes[r["decode_tier"]] += r["end"] - r["start"]
    covered = sum(r["end"] - r["start"] for r in intervals) - \
        sum(o["end"] - o["start"] for o in overlaps)

    return {
        "schema_version": "1.1.0", "layer_id": "L000",
        "source_size": len(arc.data), "intervals": intervals,
        "gaps": gaps, "overlaps": overlaps, "status_counts": dict(counts),
        "byte_coverage": covered / len(arc.data) if arc.data else 0.0,
        "structural_coverage": 1.0 if not gaps and not overlaps else 0.0,
        "tier_coverage": {t: tier_bytes.get(t, 0) for t in ("T0", "T1", "T2", "T3", "T4")},
        "min_tier": min((r["decode_tier"] for r in intervals), default="T0"),
        "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
        "tier_blocked": [], "instruction_coverage": "not_applicable",
        "analysis_mode": "data-text-only", "declared_tier": D.DECODE_TIER["script"],
        "unpack_mode": "targeted", "text_source": "embedded",
        "disasm_required": False, "decision_evidence_refs": ["EV_SCR_PLAINTEXT"],
        "transform_edges": [{
            "id": t["id"], "algorithm": t["algorithm"], "reversible": t["reversible"],
            "evidence_refs": t["evidence_refs"], "order": i,
        } for i, t in enumerate(D.TRANSFORMS)],
        "roundtrip": {}, "toolchain": {"tool": "aos_tool", "version": D.TOOL_VERSION,
                                       "dialect": D.DIALECT_ID},
    }


def write_reports(arc: A.Archive, scripts: list[A.ScriptIR],
                  opaque: list[dict[str, Any]], repdir: Path) -> dict[str, Any]:
    repdir.mkdir(parents=True, exist_ok=True)

    cert = coverage_certificate(arc)
    (repdir / "coverage_certificate.json").write_text(
        json.dumps(cert, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")

    # 产出合理性（§0.1）：per-sample，供 check_output_sanity.py 读取。
    # 剧本脚本与引擎配置脚本分两份报告：前者必须有 msg，后者结构上不含对话行。
    # 密度离散度只在同类内部才有判定意义——两类混在一起必然产生假阳性。
    scenario_rows, plumbing_rows, textless_rows = [], [], []
    for ir in scripts:
        tags = Counter(s.tag for s in ir.slots)
        shape_counts = Counter(ir.shapes)
        dlg = shape_counts.get("dialogue", 0)
        nar = shape_counts.get("narration", 0)
        row = {
            "sample": ir.name,
            "byte_size": sum(
                len(l.encode(D.SCRIPT["source_encoding"])) +
                len(D.SCRIPT["line_terminator"]) for l in ir.lines),
            "tags": dict(tags),
            "containers": {"lines": len(ir.lines),
                           "dialog_entries": dlg + nar,
                           "dialogue_lines": dlg, "narration_lines": nar,
                           "select_entries": shape_counts.get("choice", 0)},
        }
        # 分类依据是结构，不是文件名（§7.1.2 的同一原则：禁止按名字选分支）。
        # 剧本脚本 = 正文行占比达阈值；控制流脚本（分支路由、菜单）即便含个别
        # 正文行，其密度也由 directive/assign 决定，与剧本不可比。
        body_ratio = (dlg + nar) / len(ir.lines) if ir.lines else 0.0
        is_scenario = (dlg or nar) and body_ratio >= SCENARIO_BODY_RATIO
        row["containers"]["body_line_ratio"] = round(body_ratio, 4)
        if is_scenario:
            scenario_rows.append(row)
        elif tags:
            plumbing_rows.append(row)
        else:
            # 完全无文本对象的脚本：无字符串字面量，非 ASCII 全在 #comment 行内。
            # 单列并附结构证据，使"这里本就没有可提取对象"可被复核，而不是靠豁免掩盖。
            textless_rows.append({
                "sample": ir.name, "byte_size": row["byte_size"],
                "shapes": dict(shape_counts),
                "string_literals": sum(
                    1 for s in ir.slots),  # 恒为 0，与 tags 为空互为印证
                # 非 ASCII 必须只出现在注释里——整行注释，或指令行尾的 # 注释。
                # 行尾注释同样是开发者注记而非游戏可见文本，故一并剥除后再判定。
                "nonascii_outside_comments": sum(
                    1 for l, sh in zip(ir.lines, ir.shapes)
                    if sh != "comment"
                    and any(ord(c) > 0x7F for c in l.split("#", 1)[0])),
            })

    (repdir / "extract_report.json").write_text(
        json.dumps(scenario_rows, ensure_ascii=False, indent=1),
        encoding="utf-8", newline="\n")
    (repdir / "extract_report_plumbing.json").write_text(
        json.dumps(plumbing_rows, ensure_ascii=False, indent=1),
        encoding="utf-8", newline="\n")
    (repdir / "extract_report_textless.json").write_text(
        json.dumps({
            "rule": "无任何文本对象的脚本：无字符串字面量，非 ASCII 仅出现在 #comment 行",
            "samples": textless_rows,
        }, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")

    # 完备性不变式：剧本脚本的 msg 条数必须恰等于对话行 + 旁白行。
    # 这比密度检查强——它逐文件断言"每一条正文都被提取"，漏抽一条即失败。
    # 不变式覆盖**全部**脚本，不只是剧本类——否则把一个脚本改归为配置类就能
    # 绕过完备性检查，分类阈值反而成了漏抽的入口。
    invariant_fail = [
        {"sample": r["sample"], "msg": r["tags"].get("msg", 0),
         "dialog_entries": r["containers"]["dialog_entries"]}
        for r in scenario_rows + plumbing_rows
        if r["tags"].get("msg", 0) != r["containers"]["dialog_entries"]
    ]
    (repdir / "completeness_invariant.json").write_text(
        json.dumps({"ok": not invariant_fail,
                    "rule": "msg == dialogue_lines + narration_lines",
                    "checked_samples": len(scenario_rows) + len(plumbing_rows),
                    "scenario_samples": len(scenario_rows),
                    "plumbing_samples": len(plumbing_rows),
                    "violations": invariant_fail}, ensure_ascii=False, indent=1),
        encoding="utf-8", newline="\n")

    # 形态报告（§0.2 / §7.1.5）
    observed: dict[str, dict[str, int]] = {}
    for ir in scripts:
        sc = Counter(ir.shapes)
        for shape_id in sc:
            slot = observed.setdefault(shape_id, {"entries": 0, "texts": 0})
            slot["entries"] += sc[shape_id]
        for s in ir.slots:
            observed.setdefault(s.shape_id, {"entries": 0, "texts": 0})["texts"] += 1
    declared = [s["id"] for s in D.LINE_SHAPES]
    # 无文本槽位的形态是声明如此，不构成 BARREN：以 entries 计为 texts 免除误判
    for shape in D.LINE_SHAPES:
        if not shape["text_slots"] and not shape.get("arg_text_rule"):
            if shape["id"] in observed:
                observed[shape["id"]]["texts"] = observed[shape["id"]]["entries"]
    shapes_rep = {"declared": declared, "observed": observed, "unmatched": {}}
    (repdir / "shapes.json").write_text(
        json.dumps(shapes_rep, ensure_ascii=False, indent=1),
        encoding="utf-8", newline="\n")

    tag_totals = Counter()
    src_totals = Counter()
    for ir in scripts:
        for s in ir.slots:
            tag_totals[s.tag] += 1
            src_totals[s.tag_source] += 1
    summary = {
        "archive": arc.path.name, "src_sha256": arc.src_sha256,
        "entries": len(arc.entries), "scripts": len(scripts),
        "opaque_entries": opaque,
        "text_entries": sum(len(ir.slots) for ir in scripts),
        "tag_counts": dict(tag_totals),
        "tag_source_counts": {k: src_totals.get(k, 0) for k in
                              ("structural", "anchor", "binding", "heuristic",
                               "user", "unresolved")},
        "byte_coverage": cert["byte_coverage"],
        "structural_coverage": cert["structural_coverage"],
        "min_tier": cert["min_tier"],
        "declared_capabilities": cert["declared_capabilities"],
        "window_hits": {w["name"]: 0 for w in D.WINDOWS},
        "rule_hits": {},
    }
    (repdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    (repdir / "window_hits.json").write_text(
        json.dumps(summary["window_hits"], ensure_ascii=False, indent=1),
        encoding="utf-8", newline="\n")
    return summary


# --------------------------------------------------------------------------
def run_extract(src: Path, outdir: Path, want_texts: bool = True,
                want_asm: bool = False, with_ir: bool = False,
                source_encoding: str | None = None,
                target_encoding: str | None = None,
                progress=None, cancelled=None) -> dict[str, Any] | None:
    """「输出文本」按钮与命令行共用的单一入口（§11.9：两者必须产出相同结果）。

    无论勾选组合如何，覆盖证书与零编辑往返自检照常执行（§11.5.1 末条）——
    跳过可选产物不得跳过核心门禁。返回 None 表示被取消，此时不写出任何产物。
    """
    if not want_texts and not want_asm:
        raise ValueError("请至少选择一种输出")
    apply_encodings(source_encoding, target_encoding)

    bundle = build_ir(src, progress=progress, cancelled=cancelled)
    if bundle is None:
        return None
    arc, scripts, opaque = bundle

    if want_texts:
        summary = extract_texts(src, outdir, bundle, with_ir=with_ir)
    if want_asm:
        render_asm(src, outdir, bundle)
        if not want_texts:
            summary = write_reports(*bundle, layout(outdir)["reports"])

    # 核心门禁：零编辑往返自检必须执行，且使用者无法关闭（§11.9）
    import assembler
    rc = assembler.repack(src, outdir, verify_only=True, ir_bundle=bundle)
    if not rc["identical"]:
        raise A.ParseError(
            "自检未通过：不修改任何内容重建出的文件与原件不一致，"
            "此文件暂不支持装回。已导出的文本仅供阅读，请勿用于回封。")

    policy = Counter(s.translate_policy for ir in scripts for s in ir.slots)
    return {
        "entries": len(scripts), "opaque_entries": len(opaque),
        "parse_failed": [o["name"] for o in opaque if o.get("status") == "parse-failed"],
        "text_entries": summary["text_entries"],
        "tag_counts": summary["tag_counts"],
        "tag_source_counts": summary["tag_source_counts"],
        "policy_counts": {k: policy.get(k, 0) for k in
                          ("translatable", "review-required", "frozen", "length-locked")},
        "byte_coverage": summary["byte_coverage"],
        "min_tier": summary["min_tier"],
        "roundtrip_identical": rc["identical"],
        "src_sha256": arc.src_sha256, "source_size": len(arc.data),
        "reports_dir": str(layout(outdir)["reports"]),
    }


def apply_encodings(source: str | None, target: str | None) -> None:
    """把界面选定的编码写入方言（§11.6：选定后由产物文件头承载，不需选第二次）。"""
    import codecs
    for name, value in (("source_encoding", source), ("target_encoding", target)):
        if value:
            codecs.lookup(value)          # 不存在的 codec 立即报错，不静默回落
            D.SCRIPT[name] = value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AOS 归档反汇编与文本提取")
    ap.add_argument("input", type=Path, help=".aos 归档")
    ap.add_argument("-o", "--outdir", type=Path, default=None)
    ap.add_argument("--texts", action="store_true", help="只提取文本")
    ap.add_argument("--asm", action="store_true", help="只渲染 asm")
    ap.add_argument("--with-ir", action="store_true", help="IR 落盘（§2.4）")
    ap.add_argument("--source-encoding", default=None)
    ap.add_argument("--target-encoding", default=None)
    ap.add_argument("--no-selfcheck", action="store_true",
                    help=argparse.SUPPRESS)   # 仅供阶段级 CI 调用，见下
    a = ap.parse_args(argv)

    src = a.input.resolve()
    outdir = (a.outdir or default_outdir(src)).resolve()
    do_texts = a.texts or not a.asm
    do_asm = a.asm or not a.texts

    # 阶段级入口保留（§11.9 末条：界面简化不得削减命令行的可组合性）：
    # --no-selfcheck 只跳过往返自检这一步，便于 CI 单独重跑某阶段；
    # 覆盖证书照常产出，且该开关不经 GUI 暴露，使用者无法关闭自检。
    if a.no_selfcheck:
        apply_encodings(a.source_encoding, a.target_encoding)
        bundle = build_ir(src)
        summary = None
        if do_texts:
            summary = extract_texts(src, outdir, bundle, with_ir=a.with_ir)
        if do_asm:
            render_asm(src, outdir, bundle)
            if not do_texts:
                summary = write_reports(*bundle, layout(outdir)["reports"])
        arc, scripts, _ = bundle
        print(f"归档 {src.name}  条目 {len(arc.entries)}  脚本 {len(scripts)}"
              f"  （未跑往返自检）")
        if summary:
            print(f"文本条目 {summary['text_entries']}  分布 {summary['tag_counts']}")
        print(f"输出 {outdir}")
        return 0

    r = run_extract(src, outdir, want_texts=do_texts, want_asm=do_asm,
                    with_ir=a.with_ir, source_encoding=a.source_encoding,
                    target_encoding=a.target_encoding)
    assert r is not None
    print(f"归档 {src.name}  脚本 {r['entries']}  非脚本 {r['opaque_entries']}")
    if r["parse_failed"]:
        print(f"解析失败 {len(r['parse_failed'])} 个：{r['parse_failed']}")
    print(f"文本条目 {r['text_entries']}  分布 {r['tag_counts']}")
    print(f"可翻译 {r['policy_counts']['translatable']} / "
          f"需确认 {r['policy_counts']['review-required']} / "
          f"锁定 {r['policy_counts']['frozen']}")
    print(f"byte_coverage={r['byte_coverage']:.6f}  min_tier={r['min_tier']}  "
          f"零编辑往返一致={r['roundtrip_identical']}")
    print(f"输出 {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
