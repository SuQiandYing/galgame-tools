#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dynamic-relocation SCR text importer/compiler for the supplied scr.dat project.

This tool consumes the Compact IR and DSAT text files produced by scr_text_ir_tool.py,
but changes the compilation strategy from fixed in-place patching to whole-line
re-serialization:

- tag=msg entries are rebuilt as script text lines and may grow/shrink freely. Legacy tag=text is still accepted.
- <br> in a target text becomes multiple physical script lines; part counts may differ.
- tag=name / tag=choice entries replace the editable suffix of their command line.
- Existing labels/goto/change/select commands are symbol/name based in this script corpus,
  so no byte-offset jump table is rewritten inside .scr files.
- The outer scr.dat archive still must be repacked with scr_dat_tool.py so DAT FAT offsets
  and file sizes are relocated.

Zero-edit invariant: if DSAT target lines equal source lines, the emitted .scr files are
byte-identical to the original IR bytes.
"""
from __future__ import annotations

import argparse
import json
import hashlib
import os
import re
import shutil
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VALID_TAGS = {"name", "msg", "text", "choice", "label", "ui", "system", "ruby"}
DEFAULT_ENCODING = "cp932"
SCHEMA = "local.scr_text_ir.dynamic_reloc/1.0"
SRC_MARK = "\u25cb"
DST_MARK = "\u25cf"
SOURCE_LINE_RE = re.compile(rf"^{SRC_MARK}([^{SRC_MARK}{DST_MARK}]+){SRC_MARK}([^{SRC_MARK}{DST_MARK}]+){SRC_MARK}(.*)$")
TARGET_LINE_RE = re.compile(rf"^{DST_MARK}([^{SRC_MARK}{DST_MARK}]+){DST_MARK}([^{SRC_MARK}{DST_MARK}]+){DST_MARK}(.*)$")
BR_RE = re.compile(r"(?i)<br>")
ASCII_COMMAND_RE = re.compile(r"^[A-Za-z_@][A-Za-z0-9_@]*$")
SCRIPT_ASSIGNMENT_RE = re.compile(r"^[^\s;{}\[\]\"'「『（【]+\s*=\s*[^\s{}]+(?:\s+[^\s;{}\[\]\"'「『（【]+\s*=\s*[^\s{}]+)*\s*$")
CHOICE_PAYLOAD_RE = re.compile(r'^(?P<label>.*?)(?P<suffix>\s+"[^"]+"\s+\d+\s+\d+\s+NULL\s*)$')
FULLWIDTH_TRANS = str.maketrans({
    " ": "\u3000",
    **{chr(c): chr(c + 0xFEE0) for c in range(0x21, 0x7F)},
})


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def json_dump(obj: Any, path: Path) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crc32_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xffffffff:08X}"


def jsonl_read(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def dsat_unescape_text(text: str) -> str:
    return text.replace("\\r", "\r").replace("\\n", "\n")


def parse_dsat_header(header: Optional[str]) -> Dict[str, str]:
    if not header or not header.startswith("# "):
        raise ValueError("Missing DSAT metadata header")
    meta: Dict[str, str] = {}
    for token in header[2:].split():
        if "=" in token:
            k, v = token.split("=", 1)
            meta[k] = v.replace("%20", " ")
    if "idx" not in meta or "tag" not in meta:
        raise ValueError(f"Malformed DSAT header: {header}")
    return meta


def parse_dsat_file(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    pending_header: Optional[str] = None
    pending_src: Optional[Tuple[str, str, str]] = None
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("# idx="):
                pending_header = line
                pending_src = None
            elif line.startswith("○"):
                try:
                    idx, tag, src = line[1:].split("○", 2)
                except ValueError:
                    raise ValueError(f"Malformed source line {path}:{lineno}")
                pending_src = (idx, tag, dsat_unescape_text(src))
            elif line.startswith("●"):
                try:
                    idx, tag, tgt = line[1:].split("●", 2)
                except ValueError:
                    raise ValueError(f"Malformed target line {path}:{lineno}")
                if pending_src is None:
                    raise ValueError(f"Target without source {path}:{lineno}")
                src_idx, src_tag, src = pending_src
                if idx != src_idx or tag != src_tag:
                    raise ValueError(f"DSAT idx/tag mismatch {path}:{lineno}")
                if tag not in VALID_TAGS:
                    raise ValueError(f"Invalid tag {tag} at {path}:{lineno}")
                rows.append({
                    "idx": idx,
                    "tag": tag,
                    "source": src,
                    "target": dsat_unescape_text(tgt),
                    "header": pending_header,
                    "line": lineno,
                    "dsat": path.name,
                })
                pending_header = None
                pending_src = None
    return rows


def parse_dsat_file(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    pending_header: Optional[str] = None
    pending_src: Optional[Tuple[str, str, str]] = None
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("# idx="):
                pending_header = line
                pending_src = None
            elif line.startswith(SRC_MARK):
                match = SOURCE_LINE_RE.match(line)
                if match is None:
                    raise ValueError(f"Malformed source line {path}:{lineno}")
                idx, tag, src = match.groups()
                pending_src = (idx, tag, dsat_unescape_text(src))
            elif line.startswith(DST_MARK):
                match = TARGET_LINE_RE.match(line)
                if match is None:
                    raise ValueError(f"Malformed target line {path}:{lineno}")
                idx, tag, tgt = match.groups()
                if pending_src is None:
                    raise ValueError(f"Target without source {path}:{lineno}")
                src_idx, src_tag, src = pending_src
                if idx != src_idx or tag != src_tag:
                    raise ValueError(f"DSAT idx/tag mismatch {path}:{lineno}")
                if tag not in VALID_TAGS:
                    raise ValueError(f"Invalid tag {tag} at {path}:{lineno}")
                rows.append({
                    "idx": idx,
                    "tag": tag,
                    "source": src,
                    "target": dsat_unescape_text(tgt),
                    "header": pending_header,
                    "line": lineno,
                    "dsat": path.name,
                })
                pending_header = None
                pending_src = None
    return rows


def load_project_manifest(ir_root: Path) -> Dict[str, Any]:
    return json.loads((ir_root / "project_manifest.json").read_text(encoding="utf-8"))


def split_eol(raw: bytes) -> Tuple[bytes, bytes]:
    if raw.endswith(b"\r\n"):
        return raw[:-2], b"\r\n"
    if raw.endswith(b"\n") or raw.endswith(b"\r"):
        return raw[:-1], raw[-1:]
    return raw, b""


def split_ascii_command(line: str) -> Tuple[str, str, str]:
    n = len(line)
    i = 0
    while i < n and line[i] in " \t":
        i += 1
    j = i
    while j < n and line[j] not in " \t":
        j += 1
    cmd = line[i:j]
    k = j
    while k < n and line[k] in " \t":
        k += 1
    return line[:i], cmd, line[k:]


def is_probable_script_command(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return False
    if stripped[0] in "[]{}":
        return True
    if SCRIPT_ASSIGNMENT_RE.fullmatch(stripped) is not None:
        return True
    _, cmd, _ = split_ascii_command(line)
    return bool(cmd) and ASCII_COMMAND_RE.fullmatch(cmd) is not None


@dataclass
class Line:
    line_no: int
    old_offset: int
    raw: bytes
    body: bytes
    eol: bytes
    text: str


def load_lines_from_ir(ir_root: Path, src: Dict[str, Any]) -> List[Line]:
    rows = sorted(jsonl_read(ir_root / src["ir_dir"] / "instructions.jsonl"), key=lambda r: int(r["line_no"]))
    lines: List[Line] = []
    for r in rows:
        raw = bytes.fromhex(r["raw_bytes"])
        body, eol = split_eol(raw)
        off = int(str(r["offset"]), 16)
        lines.append(Line(line_no=int(r["line_no"]), old_offset=off, raw=raw, body=body, eol=eol, text=r.get("text", "")))
    return lines


def load_text_entries_from_ir(ir_root: Path, src: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(jsonl_read(ir_root / src["ir_dir"] / "text_entries.jsonl"))


def build_message_group_map(src: Dict[str, Any], entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    file_id = src["ir_dir"]
    for entry in entries:
        if entry.get("kind") != "message":
            continue
        prefix = "dlg" if entry.get("speaker") is not None else "nar"
        group = f"{prefix}_{file_id}_{int(entry['vo_line_no']):06d}"
        groups[group] = entry
    return groups


def encode_text(s: str, enc: str, row: Dict[str, Any]) -> bytes:
    try:
        return s.encode(enc)
    except UnicodeEncodeError as e:
        raise ValueError(
            f"Encoding failure for idx={row.get('idx')} using {enc}: {e}. "
            "Use --target-encoding only if the game/runtime font and decoder support that encoding."
        )


def normalize_target_text(s: str) -> str:
    placeholders: List[str] = []

    def protect_br(match: re.Match[str]) -> str:
        placeholders.append("<br>")
        return chr(0xE000 + len(placeholders) - 1)

    protected = BR_RE.sub(protect_br, s)
    normalized = protected.translate(FULLWIDTH_TRANS)
    for index, marker in enumerate(placeholders):
        normalized = normalized.replace(chr(0xE000 + index), marker)
    return normalized


def normalize_choice_target(s: str, row: Dict[str, Any]) -> str:
    meta = row.get("meta") or {}
    suffix = meta.get("suffix")
    if suffix:
        target_match = CHOICE_PAYLOAD_RE.match(s)
        if target_match is not None and target_match.group("suffix") == suffix:
            label = target_match.group("label").rstrip()
        else:
            label = s.rstrip()
        return normalize_target_text(label)

    source = row.get("source", "")
    source_match = CHOICE_PAYLOAD_RE.match(source)
    target_match = CHOICE_PAYLOAD_RE.match(s)
    if source_match is None:
        if target_match is not None:
            return normalize_target_text(target_match.group("label").rstrip())
        return normalize_target_text(s)
    if target_match is None:
        raise ValueError(
            f"choice entry idx={row.get('idx')} must keep the original suffix format: "
            '"image_id" X Y NULL'
        )
    return normalize_target_text(target_match.group("label").rstrip())


def strip_legacy_command_parts(source_text: str, target_text: str, idxs: List[int], lines: List[Line]) -> Tuple[List[str], List[str], List[int]]:
    command_positions = [pos for pos, idx in enumerate(idxs) if is_probable_script_command(lines[idx].text)]
    source_parts = BR_RE.split(source_text)
    target_parts = BR_RE.split(target_text)
    if not command_positions:
        return source_parts, target_parts, idxs

    keep_positions = [pos for pos in range(len(idxs)) if pos not in command_positions]
    command_texts = {lines[idxs[pos]].text.strip() for pos in command_positions}
    kept_idxs = [idxs[pos] for pos in keep_positions]
    if not kept_idxs:
        raise ValueError("text entry resolved only to script command lines")

    if len(source_parts) == len(idxs):
        source_parts = [source_parts[pos] for pos in keep_positions]
    else:
        source_parts = [part for part in source_parts if part.strip() not in command_texts]
    if len(target_parts) == len(idxs):
        target_parts = [target_parts[pos] for pos in keep_positions]
    else:
        target_parts = [part for part in target_parts if part.strip() not in command_texts]
    return source_parts, target_parts, kept_idxs


def copy_texts_as_relocate(src_text_root: Path, dst_text_root: Path) -> Dict[str, Any]:
    if dst_text_root.exists():
        shutil.rmtree(dst_text_root)
    ensure_dir(dst_text_root)
    copied = 0
    for src in sorted(src_text_root.glob("*.dsat.txt"), key=lambda p: p.name.lower()):
        text = src.read_text(encoding="utf-8")
        text = text.replace("policy=in_place", "policy=relocate")
        # Normalize old DSAT tags to the current translator-facing tag names.
        text = re.sub(r"(^# idx=\S+ tag=)(text|ui)(\b)", r"\1msg\3", text, flags=re.MULTILINE)
        text = re.sub(r"^([○●][^○●]+[○●])(text|ui)([○●])", r"\1msg\3", text, flags=re.MULTILINE)
        text = text.replace("schema=local.scr_text_ir/1.0", f"schema={SCHEMA}")
        text = text.replace("# Edit only target lines beginning with ●. Do not change idx/tag/header metadata.",
                            "# Dynamic relocation mode: edit only target lines beginning with ●. Text may be longer; use <br> for extra physical lines.")
        (dst_text_root / src.name).write_text(text, encoding="utf-8", newline="\n")
        copied += 1
    report = {"source_text_root": str(src_text_root), "output_text_root": str(dst_text_root), "files": copied, "policy": "relocate"}
    json_dump(report, dst_text_root / "dynamic_dsat_export_report.json")
    return report


@dataclass
class BodyReplacement:
    line_index: int
    new_body: bytes
    idx: str
    tag: str


@dataclass
class RangeReplacement:
    start_index: int
    end_index: int
    new_parts: List[bytes]
    idx: str
    tag: str
    old_part_count: int
    new_part_count: int


def compile_dynamic(ir_root: Path, text_root: Path, output_scripts: Path, *, target_encoding: Optional[str] = None,
                    strict: bool = True) -> Dict[str, Any]:
    manifest = load_project_manifest(ir_root)
    source_encoding = manifest.get("encoding", DEFAULT_ENCODING)
    target_encoding = target_encoding or source_encoding
    sources_by_file = {src["file"]: src for src in manifest["sources"]}

    if output_scripts.exists():
        shutil.rmtree(output_scripts)
    ensure_dir(output_scripts)

    # Gather DSAT rows by source file.
    rows_by_file: Dict[str, List[Dict[str, Any]]] = {rel: [] for rel in sources_by_file}
    errors: List[Dict[str, Any]] = []
    dsat_files = sorted(text_root.glob("*.dsat.txt"), key=lambda p: p.name.lower())
    for dsat_path in dsat_files:
        try:
            for row in parse_dsat_file(dsat_path):
                meta = parse_dsat_header(row.get("header"))
                if meta.get("idx") != row["idx"] or meta.get("tag") != row["tag"]:
                    raise ValueError("Header idx/tag does not match DSAT body")
                rel = meta.get("file")
                if rel not in sources_by_file:
                    raise ValueError(f"Unknown source file in DSAT: {rel}")
                row["meta"] = meta
                rows_by_file[rel].append(row)
        except Exception as e:
            errors.append({"dsat": dsat_path.name, "error": str(e)})
            if strict:
                report = {"ok": False, "errors": errors}
                json_dump(report, output_scripts / "dynamic_import_report.json")
                raise RuntimeError("DSAT parse failed; see dynamic_import_report.json")

    source_reports: List[Dict[str, Any]] = []
    total_changed_entries = 0
    total_delta = 0
    total_inserted_lines = 0
    total_removed_lines = 0

    for rel, src in sources_by_file.items():
        lines = load_lines_from_ir(ir_root, src)
        text_entries = load_text_entries_from_ir(ir_root, src)
        message_groups = build_message_group_map(src, text_entries)
        offset_to_index = {ln.old_offset: i for i, ln in enumerate(lines)}
        body_repl: Dict[int, BodyReplacement] = {}
        ranges: List[RangeReplacement] = []
        changed_entries = 0
        validation_errors: List[Dict[str, Any]] = []

        for row in rows_by_file.get(rel, []):
            try:
                if row["target"] == row["source"]:
                    continue
                meta = row["meta"]
                tag = row["tag"]
                if tag == "choice":
                    normalized_target = normalize_choice_target(row["target"], row)
                else:
                    normalized_target = normalize_target_text(row["target"])
                if tag in {"msg", "text"} and "src" in meta:
                    offsets = [int(x, 16) for x in meta["src"].split(",") if x]
                    if not offsets:
                        raise ValueError("msg/text entry has empty src list")
                    if any(off not in offset_to_index for off in offsets):
                        entry = message_groups.get(meta.get("dialogue_group", ""))
                        if entry and entry.get("text_offsets"):
                            offsets = [int(x) for x in entry["text_offsets"]]
                    idxs = []
                    for off in offsets:
                        if off not in offset_to_index:
                            raise ValueError(f"text src offset not found in IR line map: 0x{off:08X}")
                        idxs.append(offset_to_index[off])
                    source_parts, target_parts, idxs = strip_legacy_command_parts(
                        row["source"], normalized_target, idxs, lines
                    )
                    if sorted(idxs) != list(range(min(idxs), max(idxs) + 1)):
                        raise ValueError("text src lines are not contiguous; refusing variable-line replacement")
                    new_parts = [encode_text(part, target_encoding, row) for part in target_parts]
                    ranges.append(RangeReplacement(
                        start_index=min(idxs),
                        end_index=max(idxs),
                        new_parts=new_parts,
                        idx=row["idx"],
                        tag=tag,
                        old_part_count=len(idxs),
                        new_part_count=len(new_parts),
                    ))
                    changed_entries += 1
                else:
                    off_s = meta.get("off")
                    if off_s is None:
                        raise ValueError("line entry missing off metadata")
                    off = int(off_s, 16)
                    if tag == "name" and meta.get("dialogue_group"):
                        body_end_matches = [
                            i for i, ln in enumerate(lines)
                            if ln.old_offset <= off <= (ln.old_offset + len(ln.body))
                        ]
                        if not body_end_matches:
                            entry = message_groups.get(meta["dialogue_group"])
                            if entry and entry.get("msg2_offset") is not None:
                                off = int(entry["msg2_offset"])
                    # Locate the line by offset range, because name/choice offsets point into a command body.
                    line_index = None
                    rel_off = None
                    for i, ln in enumerate(lines):
                        body_end = ln.old_offset + len(ln.body)
                        if ln.old_offset <= off <= body_end:
                            line_index = i
                            rel_off = off - ln.old_offset
                            break
                    if line_index is None or rel_off is None:
                        raise ValueError(f"offset not found in line body map: 0x{off:08X}")
                    if line_index in body_repl:
                        raise ValueError(f"multiple replacements target same command line: line={lines[line_index].line_no}")
                    prefix = lines[line_index].body[:rel_off]
                    if meta.get("len") is not None:
                        editable_len = int(meta["len"])
                        suffix = lines[line_index].body[rel_off + editable_len:]
                        new_body = prefix + encode_text(normalized_target, target_encoding, row) + suffix
                    else:
                        new_body = prefix + encode_text(normalized_target, target_encoding, row)
                    body_repl[line_index] = BodyReplacement(line_index, new_body, row["idx"], tag)
                    changed_entries += 1
            except Exception as e:
                validation_errors.append({"idx": row.get("idx"), "dsat": row.get("dsat"), "line": row.get("line"), "error": str(e)})
                if strict:
                    break
        if validation_errors and strict:
            errors.extend({"file": rel, **e} for e in validation_errors)
            break

        # Overlap checks for text ranges and command body replacements.
        ranges.sort(key=lambda r: (r.start_index, r.end_index))
        occupied = set()
        overlap_error = None
        for rr in ranges:
            for i in range(rr.start_index, rr.end_index + 1):
                if i in occupied:
                    overlap_error = f"overlapping text replacement at original line {lines[i].line_no}"
                    break
                occupied.add(i)
            if overlap_error:
                break
        if overlap_error:
            errors.append({"file": rel, "error": overlap_error})
            if strict:
                break
        # It is legal to modify msg2/choice command lines separately from text payload lines.

        original_bytes = b"".join(ln.raw for ln in lines)
        out = bytearray()
        relocation_rows: List[Dict[str, Any]] = []
        range_by_start = {r.start_index: r for r in ranges}
        range_inside = {i: r for r in ranges for i in range(r.start_index, r.end_index + 1)}
        i = 0
        while i < len(lines):
            if i in range_by_start:
                rr = range_by_start[i]
                old_start_off = lines[rr.start_index].old_offset
                new_start_off = len(out)
                old_bytes = b"".join(lines[j].raw for j in range(rr.start_index, rr.end_index + 1))
                # Preserve final EOL from the last original text line; use CRLF for inserted intermediate lines.
                final_eol = lines[rr.end_index].eol or b"\r\n"
                for part_i, body in enumerate(rr.new_parts):
                    eol = final_eol if part_i == len(rr.new_parts) - 1 else b"\r\n"
                    out.extend(body + eol)
                new_size = len(out) - new_start_off
                old_line_span = f"{lines[rr.start_index].line_no}-{lines[rr.end_index].line_no}"
                relocation_rows.append({
                    "kind": "text_range",
                    "idx": rr.idx,
                    "old_line_span": old_line_span,
                    "old_offset": old_start_off,
                    "new_offset": new_start_off,
                    "old_size": len(old_bytes),
                    "new_size": new_size,
                    "delta": new_size - len(old_bytes),
                    "old_part_count": rr.old_part_count,
                    "new_part_count": rr.new_part_count,
                })
                i = rr.end_index + 1
                continue
            if i in range_inside:
                i += 1
                continue
            ln = lines[i]
            new_body = body_repl[i].new_body if i in body_repl else ln.body
            new_raw = new_body + ln.eol
            relocation_rows.append({
                "kind": "line",
                "line_no": ln.line_no,
                "old_offset": ln.old_offset,
                "new_offset": len(out),
                "old_size": len(ln.raw),
                "new_size": len(new_raw),
                "delta": len(new_raw) - len(ln.raw),
                "changed": i in body_repl,
                "idx": body_repl[i].idx if i in body_repl else None,
                "tag": body_repl[i].tag if i in body_repl else None,
            })
            out.extend(new_raw)
            i += 1

        new_bytes = bytes(out)
        out_path = output_scripts / rel
        ensure_dir(out_path.parent)
        out_path.write_bytes(new_bytes)

        delta = len(new_bytes) - len(original_bytes)
        total_delta += delta
        total_changed_entries += changed_entries
        inserted = sum(max(0, r.new_part_count - r.old_part_count) for r in ranges)
        removed = sum(max(0, r.old_part_count - r.new_part_count) for r in ranges)
        total_inserted_lines += inserted
        total_removed_lines += removed
        source_report = {
            "file": rel,
            "original_size": len(original_bytes),
            "new_size": len(new_bytes),
            "delta": delta,
            "changed_entries": changed_entries,
            "range_replacements": len(ranges),
            "line_suffix_replacements": len(body_repl),
            "inserted_text_lines": inserted,
            "removed_text_lines": removed,
            "original_sha256": sha256_bytes(original_bytes),
            "new_sha256": sha256_bytes(new_bytes),
            "byte_exact": original_bytes == new_bytes,
        }
        source_reports.append(source_report)
        # Per-file relocation map can be large; write only for changed files or if zero-edit with compact summary.
        if changed_entries:
            map_path = output_scripts / (rel + ".relocation_map.json")
            json_dump({"file": rel, "rows": relocation_rows}, map_path)

    ok = not errors
    report = {
        "$schema": SCHEMA + "/dynamic_import_report",
        "created_utc": int(time.time()),
        "ok": ok,
        "strict": strict,
        "source_encoding": source_encoding,
        "target_encoding": target_encoding,
        "input_ir_root": str(ir_root),
        "input_text_root": str(text_root),
        "output_scripts": str(output_scripts),
        "errors": errors,
        "totals": {
            "files": len(source_reports),
            "changed_entries": total_changed_entries,
            "byte_delta": total_delta,
            "inserted_text_lines": total_inserted_lines,
            "removed_text_lines": total_removed_lines,
            "byte_exact_all": all(s["byte_exact"] for s in source_reports) and ok,
        },
        "sources": source_reports,
        "strategy": {
            "relocation_allowed": True,
            "script_internal_relocation": "line_rebuild_symbolic_control_flow",
            "outer_archive_relocation_required": True,
            "line_break_join_token": "<br>",
            "length_limit": "unbounded_by_original_slot",
        },
    }
    json_dump(report, output_scripts / "dynamic_import_report.json")
    if errors and strict:
        raise RuntimeError("Dynamic import failed; see dynamic_import_report.json")
    return report


def discover_scr(root: Path) -> List[Path]:
    return sorted([p for p in root.rglob("*.scr") if p.is_file()], key=lambda p: p.relative_to(root).as_posix().lower())


def verify_dirs(original_dir: Path, rebuilt_dir: Path, output: Optional[Path] = None) -> Dict[str, Any]:
    mismatches = []
    checked = 0
    for p in discover_scr(original_dir):
        rel = p.relative_to(original_dir)
        q = rebuilt_dir / rel
        checked += 1
        if not q.exists():
            mismatches.append({"file": rel.as_posix(), "reason": "missing"})
            continue
        a = p.read_bytes(); b = q.read_bytes()
        if a != b:
            first = None
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    first = i; break
            if first is None and len(a) != len(b):
                first = min(len(a), len(b))
            mismatches.append({
                "file": rel.as_posix(),
                "reason": "bytes differ",
                "original_size": len(a),
                "rebuilt_size": len(b),
                "first_conflict_offset": first,
                "original_sha256": sha256_bytes(a),
                "rebuilt_sha256": sha256_bytes(b),
            })
    extra = [p.relative_to(rebuilt_dir).as_posix() for p in discover_scr(rebuilt_dir) if not (original_dir / p.relative_to(rebuilt_dir)).exists()]
    report = {"checked": checked, "extra": extra, "mismatches": mismatches, "byte_exact": not mismatches and not extra}
    if output:
        json_dump(report, output)
    return report


def analyze_control_flow(script_dir: Path, output: Path, encoding: str = DEFAULT_ENCODING) -> Dict[str, Any]:
    label_def_re = re.compile(r"^@([A-Za-z0-9_\-]+)\s*$")
    goto_re = re.compile(r"^goto\s+([^\s]+)")
    change_re = re.compile(r"^change\s+\"?([^\"\s]+)\"?")
    numeric_offset_re = re.compile(r"(?:0x[0-9A-Fa-f]{4,}|\b[0-9]{5,}\b)")
    report: Dict[str, Any] = {
        "$schema": SCHEMA + "/control_flow_analysis",
        "script_dir": str(script_dir),
        "encoding": encoding,
        "files": 0,
        "labels": 0,
        "gotos": 0,
        "changes": 0,
        "select2": 0,
        "def_sel": 0,
        "def_sel2": 0,
        "numeric_offset_like_operands": [],
        "unresolved_gotos": [],
        "conclusion": "",
    }
    all_labels: Dict[str, List[str]] = {}
    goto_refs: List[Tuple[str, int, str]] = []
    for p in discover_scr(script_dir):
        report["files"] += 1
        rel = p.relative_to(script_dir).as_posix()
        for line_no, line in enumerate(p.read_text(encoding=encoding, errors="replace").splitlines(), 1):
            s = line.strip()
            m = label_def_re.match(s)
            if m:
                lab = m.group(1)
                all_labels.setdefault(lab, []).append(f"{rel}:{line_no}")
                report["labels"] += 1
            m = goto_re.match(s)
            if m:
                lab = m.group(1).strip('"')
                goto_refs.append((rel, line_no, lab))
                report["gotos"] += 1
            if change_re.match(s):
                report["changes"] += 1
            if s.startswith("select2"):
                report["select2"] += 1
            if s.startswith("def_sel2"):
                report["def_sel2"] += 1
            elif s.startswith("def_sel"):
                report["def_sel"] += 1
            if numeric_offset_re.search(s) and not s.startswith(("wait", "timer_wait", "alpha", "zoom_set", "move_xyset", "set_rgb", "def_sp", "F", "S", "T")):
                # Keep this as heuristic evidence, not a fatal rule. Most numbers in this corpus are visual coordinates/timers.
                report["numeric_offset_like_operands"].append({"file": rel, "line": line_no, "text": s[:200]})
    for rel, line_no, lab in goto_refs:
        if lab not in all_labels:
            report["unresolved_gotos"].append({"file": rel, "line": line_no, "label": lab})
    report["label_names"] = {k: v[:5] for k, v in sorted(all_labels.items())}
    if not report["numeric_offset_like_operands"] and not report["unresolved_gotos"]:
        report["conclusion"] = "No byte-address jump table was detected; observed control-flow references are symbolic labels/files. Whole-line dynamic text growth is structurally safe for scripts, while the outer DAT packer relocates file offsets."
    else:
        report["conclusion"] = "Symbolic control flow dominates. Review numeric_offset_like_operands/unresolved_gotos before runtime deployment."
    json_dump(report, output)
    return report


def make_extract_dir_for_dat(base_extract_dir: Path, scripts_dir: Path, output_extract_dir: Path) -> Dict[str, Any]:
    if output_extract_dir.exists():
        shutil.rmtree(output_extract_dir)
    shutil.copytree(base_extract_dir, output_extract_dir)
    copied = 0
    for src in discover_scr(scripts_dir):
        rel = src.relative_to(scripts_dir)
        dst = output_extract_dir / "files" / rel
        ensure_dir(dst.parent)
        shutil.copy2(src, dst)
        copied += 1
    report = {"base_extract_dir": str(base_extract_dir), "scripts_dir": str(scripts_dir), "output_extract_dir": str(output_extract_dir), "files_replaced": copied}
    json_dump(report, output_extract_dir / "dynamic_dat_input_report.json")
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Dynamic relocation compiler for SCR DSAT text")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("export-relocate-text", help="copy DSAT files and mark them policy=relocate")
    sp.add_argument("source_texts")
    sp.add_argument("-o", "--output", required=True)

    sp = sub.add_parser("import-text", help="compile DSAT into variable-length .scr files")
    sp.add_argument("ir_dir")
    sp.add_argument("texts_dir")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("--target-encoding", default=None)
    sp.add_argument("--no-strict", action="store_true")

    sp = sub.add_parser("verify")
    sp.add_argument("original_dir")
    sp.add_argument("rebuilt_dir")
    sp.add_argument("-o", "--output")

    sp = sub.add_parser("analyze-flow")
    sp.add_argument("script_dir")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("--encoding", default=DEFAULT_ENCODING)

    sp = sub.add_parser("make-dat-input", help="copy an unpacked DAT dir and replace its files/ scripts")
    sp.add_argument("base_extract_dir")
    sp.add_argument("scripts_dir")
    sp.add_argument("-o", "--output", required=True)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "export-relocate-text":
        report = copy_texts_as_relocate(Path(args.source_texts), Path(args.output))
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.cmd == "import-text":
        report = compile_dynamic(Path(args.ir_dir), Path(args.texts_dir), Path(args.output), target_encoding=args.target_encoding, strict=not args.no_strict)
        print(json.dumps({"ok": report["ok"], **report["totals"]}, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 2
    elif args.cmd == "verify":
        report = verify_dirs(Path(args.original_dir), Path(args.rebuilt_dir), Path(args.output) if args.output else None)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["byte_exact"] else 2
    elif args.cmd == "analyze-flow":
        report = analyze_control_flow(Path(args.script_dir), Path(args.output), args.encoding)
        print(json.dumps({k: report[k] for k in ["files", "labels", "gotos", "changes", "select2", "def_sel", "def_sel2", "unresolved_gotos", "conclusion"]}, ensure_ascii=False, indent=2))
    elif args.cmd == "make-dat-input":
        report = make_extract_dir_for_dat(Path(args.base_extract_dir), Path(args.scripts_dir), Path(args.output))
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
