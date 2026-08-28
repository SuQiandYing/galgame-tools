#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_ENCODING = "cp932"
EXPORT_SCHEMA = "local.scr_text_export/1.0"
RELOCATE_SCHEMA = "local.scr_text_ir.dynamic_reloc/1.0"
SRC_MARK = "\u25cb"
DST_MARK = "\u25cf"
ASCII_COMMAND_RE = re.compile(r"^[A-Za-z_@][A-Za-z0-9_@]*$")
SCRIPT_ASSIGNMENT_RE = re.compile(r"^[^\s;{}\[\]\"'「『（【]+\s*=\s*[^\s{}]+(?:\s+[^\s;{}\[\]\"'「『（【]+\s*=\s*[^\s{}]+)*\s*$")
CHOICE_PAYLOAD_RE = re.compile(r'^(?P<label>.*?)(?P<suffix>\s+"[^"]+"\s+\d+\s+\d+\s+NULL\s*)$')
INLINE_CHOICE_CMD_RE = re.compile(r'(?P<cmd>def_sel2|def_sel)\b')


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def json_dump(obj: Any, path: Path) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def jsonl_write(rows: Iterable[Dict[str, Any]], path: Path) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def jsonl_read(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crc32_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xffffffff:08X}"


def split_line_segment(seg: bytes, encoding: str) -> Tuple[bytes, bytes, str]:
    if seg.endswith(b"\r\n"):
        body, eol = seg[:-2], b"\r\n"
    elif seg.endswith(b"\n") or seg.endswith(b"\r"):
        body, eol = seg[:-1], seg[-1:]
    else:
        body, eol = seg, b""
    return body, eol, body.decode(encoding)


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


def split_choice_payload(value: str, cmd: str) -> Tuple[str, str]:
    if cmd == "def_sel":
        return value, ""
    match = CHOICE_PAYLOAD_RE.match(value)
    if match is None:
        raise ValueError(f"Unsupported {cmd} payload format: {value}")
    return match.group("label").rstrip(), match.group("suffix")


def split_quoted_payload(value: str, cmd: str) -> str:
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        raise ValueError(f"Unsupported {cmd} payload format: {value}")
    return value[1:-1]


def dsat_escape_text(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")


def meta_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return str(v).replace(" ", "%20")


@dataclass
class LineRecord:
    line_no: int
    offset: int
    size: int
    body_hex: str
    eol_hex: str
    text: str

    @property
    def raw_hex(self) -> str:
        return self.body_hex + self.eol_hex


@dataclass
class MessageBlock:
    block_id: str
    file: str
    vo_line_no: int
    ret_line_no: int
    inst_offset: int
    voice_id: str
    msg2_line_no: Optional[int]
    msg2_offset: Optional[int]
    msg2_len: Optional[int]
    speaker: Optional[str]
    msg3_code: Optional[str]
    text_line_nos: List[int]
    text_offsets: List[int]
    text_lens: List[int]
    text: str


def discover_script_files(input_dir: Path) -> List[Path]:
    files = []
    for p in input_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() == ".scr":
            files.append(p)
    return sorted(files, key=lambda x: x.as_posix().lower())


def build_line_records(data: bytes, encoding: str) -> List[LineRecord]:
    records: List[LineRecord] = []
    off = 0
    for idx, seg in enumerate(data.splitlines(keepends=True), 1):
        body, eol, text = split_line_segment(seg, encoding)
        records.append(LineRecord(idx, off, len(seg), body.hex().upper(), eol.hex().upper(), text))
        off += len(seg)
    if not records and data:
        body, eol, text = split_line_segment(data, encoding)
        records.append(LineRecord(1, 0, len(data), body.hex().upper(), eol.hex().upper(), text))
    return records


def extract_quoted_or_raw(arg: str) -> str:
    s = arg.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def parse_messages(rel: str, records: List[LineRecord], encoding: str) -> List[MessageBlock]:
    blocks: List[MessageBlock] = []
    i = 0
    while i < len(records):
        rec = records[i]
        stripped0 = rec.text.strip()
        _, cmd, rest = split_ascii_command(rec.text)
        if cmd == "vo":
            voice_id = extract_quoted_or_raw(rest)
            j = i + 1
        elif not stripped0 or stripped0.startswith(";") or is_probable_script_command(rec.text):
            i += 1
            continue
        else:
            voice_id = ""
            j = i
        msg2_line_no: Optional[int] = None
        msg2_offset: Optional[int] = None
        msg2_len: Optional[int] = None
        speaker: Optional[str] = None
        msg3_code: Optional[str] = None
        text_line_nos: List[int] = []
        text_offsets: List[int] = []
        text_lens: List[int] = []
        text_parts: List[str] = []
        ret_line_no = rec.line_no

        while j < len(records):
            cur = records[j]
            stripped = cur.text.strip()
            leading, cmd2, rest2 = split_ascii_command(cur.text)
            if cmd2 == "ret":
                ret_line_no = cur.line_no
                break
            if not stripped or stripped.startswith(";"):
                j += 1
                continue
            if cmd2 == "msg2":
                msg2_line_no = cur.line_no
                speaker = rest2.strip()
                body = bytes.fromhex(cur.body_hex)
                k = len((leading + cmd2).encode(encoding))
                while k < len(body) and body[k] in (0x20, 0x09):
                    k += 1
                msg2_offset = cur.offset + k
                msg2_len = len(body) - k
            elif cmd2 == "msg3":
                msg3_code = extract_quoted_or_raw(rest2)
            elif is_probable_script_command(cur.text):
                j += 1
                continue
            else:
                body_len = len(bytes.fromhex(cur.body_hex))
                text_line_nos.append(cur.line_no)
                text_offsets.append(cur.offset)
                text_lens.append(body_len)
                text_parts.append(cur.text)
            j += 1

        if text_parts:
            block_id = f"{Path(rel).stem}:{rec.line_no:06d}"
            blocks.append(MessageBlock(
                block_id=block_id,
                file=rel,
                vo_line_no=rec.line_no,
                ret_line_no=ret_line_no,
                inst_offset=rec.offset,
                voice_id=voice_id,
                msg2_line_no=msg2_line_no,
                msg2_offset=msg2_offset,
                msg2_len=msg2_len,
                speaker=speaker,
                msg3_code=msg3_code,
                text_line_nos=text_line_nos,
                text_offsets=text_offsets,
                text_lens=text_lens,
                text="<br>".join(text_parts),
            ))
        i = max(i + 1, j + 1 if j < len(records) else len(records))
    return blocks


def parse_choices(rel: str, records: List[LineRecord], encoding: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rec in records:
        body = bytes.fromhex(rec.body_hex)
        for match in INLINE_CHOICE_CMD_RE.finditer(rec.text):
            cmd = match.group("cmd")
            value_start = match.end()
            while value_start < len(rec.text) and rec.text[value_start] in " \t":
                value_start += 1
            value_end = rec.text.find("}", value_start)
            if value_end == -1:
                value_end = len(rec.text)
            value = rec.text[value_start:value_end].strip()
            if not value or value == "NULL":
                continue
            label, suffix = split_choice_payload(value, cmd)
            k = len(rec.text[:value_start].encode(encoding))
            rows.append({
                "file": rel,
                "line_no": rec.line_no,
                "offset": rec.offset + k,
                "inst_offset": rec.offset,
                "cmd": cmd,
                "len": len(label.encode(encoding)),
                "text": label,
                "suffix": suffix,
                "policy": "relocate",
                "encoding": encoding,
            })
    return rows


def parse_ui_strings(rel: str, records: List[LineRecord], encoding: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rec in records:
        leading, cmd, rest = split_ascii_command(rec.text)
        if cmd != "def_selmes":
            continue
        value = rest.strip()
        if not value or value == '""':
            continue
        text = split_quoted_payload(value, cmd)
        body = bytes.fromhex(rec.body_hex)
        k = len((leading + cmd).encode(encoding))
        while k < len(body) and body[k] in (0x20, 0x09):
            k += 1
        if k >= len(body) or body[k] != 0x22:
            raise ValueError(f"Unsupported {cmd} byte layout at {rel}:{rec.line_no}")
        rows.append({
            "file": rel,
            "line_no": rec.line_no,
            "offset": rec.offset + k + 1,
            "inst_offset": rec.offset,
            "cmd": cmd,
            "len": len(text.encode(encoding)),
            "text": text,
            "policy": "relocate",
            "encoding": encoding,
        })
    return rows


def write_ir_for_file(src_file: Path, rel: str, ir_root: Path, encoding: str) -> Dict[str, Any]:
    raw = src_file.read_bytes()
    raw.decode(encoding)
    records = build_line_records(raw, encoding)
    messages = parse_messages(rel, records, encoding)
    choices = parse_choices(rel, records, encoding)
    ui_rows = parse_ui_strings(rel, records, encoding)

    file_id = rel.replace("/", "__").replace("\\", "__")
    out_dir = ir_root / file_id
    ensure_dir(out_dir)

    instructions = [{
        "line_no": rec.line_no,
        "offset": f"0x{rec.offset:08X}",
        "size": rec.size,
        "raw_bytes": rec.raw_hex,
        "text": rec.text,
    } for rec in records]

    text_entries: List[Dict[str, Any]] = []
    for entry in messages:
        text_entries.append({
            "kind": "message",
            "file": entry.file,
            "block_id": entry.block_id,
            "vo_line_no": entry.vo_line_no,
            "ret_line_no": entry.ret_line_no,
            "inst_offset": entry.inst_offset,
            "voice_id": entry.voice_id,
            "msg2_line_no": entry.msg2_line_no,
            "msg2_offset": entry.msg2_offset,
            "msg2_len": entry.msg2_len,
            "speaker": entry.speaker,
            "msg3_code": entry.msg3_code,
            "text_line_nos": entry.text_line_nos,
            "text_offsets": entry.text_offsets,
            "text_lens": entry.text_lens,
            "text": entry.text,
        })
    text_entries.extend({"kind": "choice", **choice} for choice in choices)
    text_entries.extend({"kind": "ui", **row} for row in ui_rows)
    text_entries.sort(key=entry_order_key)

    jsonl_write(instructions, out_dir / "instructions.jsonl")
    jsonl_write(text_entries, out_dir / "text_entries.jsonl")
    (out_dir / "coverage_report.txt").write_text(
        f"file={rel}\nbytes={len(raw)}\nlines={len(records)}\nmessages={len(messages)}\nchoices={len(choices)}\nui={len(ui_rows)}\n",
        encoding="utf-8",
    )

    return {
        "file": rel,
        "ir_dir": file_id,
        "byte_size": len(raw),
        "line_count": len(records),
        "message_blocks": len(messages),
        "speaker_bound_messages": sum(1 for x in messages if x.speaker is not None),
        "narrator_messages": sum(1 for x in messages if x.speaker is None),
        "choices": len(choices),
        "ui": len(ui_rows),
        "sha256": sha256_bytes(raw),
        "crc32": crc32_hex(raw),
    }


def disasm(input_dir: Path, ir_root: Path, encoding: str = DEFAULT_ENCODING) -> Dict[str, Any]:
    ensure_dir(ir_root)
    files = discover_script_files(input_dir)
    if not files:
        raise FileNotFoundError(f"No .scr files found under {input_dir}")
    sources = []
    for src in files:
        rel = src.relative_to(input_dir).as_posix()
        sources.append(write_ir_for_file(src, rel, ir_root, encoding))
    manifest = {
        "$schema": EXPORT_SCHEMA + "/project_manifest",
        "created_utc": int(time.time()),
        "input_dir": str(input_dir),
        "encoding": encoding,
        "sources": sources,
        "totals": {
            "files": len(sources),
            "bytes": sum(x["byte_size"] for x in sources),
            "lines": sum(x["line_count"] for x in sources),
            "message_blocks": sum(x["message_blocks"] for x in sources),
            "speaker_bound_messages": sum(x["speaker_bound_messages"] for x in sources),
            "narrator_messages": sum(x["narrator_messages"] for x in sources),
            "choices": sum(x["choices"] for x in sources),
            "coverage_percent": 100.0,
        },
    }
    json_dump(manifest, ir_root / "project_manifest.json")
    return manifest


def load_project_manifest(ir_root: Path) -> Dict[str, Any]:
    return json.loads((ir_root / "project_manifest.json").read_text(encoding="utf-8"))


def entry_order_key(entry: Dict[str, Any]) -> Tuple[int, int, int]:
    """Return a physical-script-order key for DSAT/IR entries.

    Earlier versions appended all message blocks first, then all choices, then UI strings.
    That was safe for recompilation because every row carries offsets, but inconvenient for
    translators: choices near a dialogue block appeared at the bottom of the file.  We sort
    by the original command/text offset so the exported .dsat.txt follows the .scr layout.
    """
    kind = entry.get("kind")
    if kind == "message":
        off = int(entry.get("inst_offset") or (entry.get("text_offsets") or [0])[0])
        # A speaker name and its text are emitted together, so keep the whole dialogue block
        # anchored at its original vo/text command position.
        return off, 0, int(entry.get("vo_line_no") or 0)
    if kind == "choice":
        return int(entry.get("inst_offset", entry.get("offset", 0))), 1, int(entry.get("line_no") or 0)
    if kind == "ui":
        return int(entry.get("inst_offset", entry.get("offset", 0))), 2, int(entry.get("line_no") or 0)
    return int(entry.get("inst_offset", entry.get("offset", 0))), 9, int(entry.get("line_no") or 0)


def dsat_block(idx: str, tag: str, source_text: str, target_text: str, meta: Dict[str, Any]) -> str:
    meta_text = " ".join([f"{k}={meta_value(v)}" for k, v in meta.items() if v is not None])
    return f"# idx={idx} tag={tag} {meta_text}\n○{idx}●{tag}○{dsat_escape_text(source_text)}\n●{idx}●{tag}●{dsat_escape_text(target_text)}\n"


def dsat_block(idx: str, tag: str, source_text: str, target_text: str, meta: Dict[str, Any]) -> str:
    meta_text = " ".join([f"{k}={meta_value(v)}" for k, v in meta.items() if v is not None])
    return (
        f"# idx={idx} tag={tag} {meta_text}\n"
        f"{SRC_MARK}{idx}{SRC_MARK}{tag}{SRC_MARK}{dsat_escape_text(source_text)}\n"
        f"{DST_MARK}{idx}{DST_MARK}{tag}{DST_MARK}{dsat_escape_text(target_text)}\n"
    )


def export_text(ir_root: Path, text_root: Path, *, relocate: bool = True) -> Dict[str, Any]:
    manifest = load_project_manifest(ir_root)
    ensure_dir(text_root)
    next_idx = 1
    totals = {"name": 0, "msg": 0, "choice": 0, "files": 0}
    index_rows = []
    policy = "relocate" if relocate else "in_place"
    schema = RELOCATE_SCHEMA if relocate else EXPORT_SCHEMA
    note = (
        "# Dynamic relocation mode: edit only target lines beginning with ●. Text may be longer; use <br> for extra physical lines.\n\n"
        if relocate
        else "# Edit only target lines beginning with ●. Do not change idx/tag/header metadata.\n\n"
    )

    for src in manifest["sources"]:
        rel = src["file"]
        file_id = src["ir_dir"]
        entries_path = ir_root / file_id / "text_entries.jsonl"
        out_file = text_root / (rel.replace("/", "__") + ".dsat.txt")
        ensure_dir(out_file.parent)
        chunks = [
            f"# DSAT file={rel} encoding={manifest['encoding']} schema={schema} policy={policy}\n",
            note,
        ]
        file_counts = {"name": 0, "msg": 0, "choice": 0}
        entries = sorted(jsonl_read(entries_path), key=entry_order_key)
        for entry in entries:
            if entry["kind"] == "message":
                if entry.get("speaker") is not None:
                    name_idx = f"{next_idx:06d}"
                    next_idx += 1
                    text_idx = f"{next_idx:06d}"
                    next_idx += 1
                    group = f"dlg_{file_id}_{entry['vo_line_no']:06d}"
                    name_meta = {
                        "file": rel,
                        "off": f"0x{entry['msg2_offset']:08X}",
                        "inst": f"0x{entry['inst_offset']:08X}",
                        "source": "msg2",
                        "len": entry["msg2_len"],
                        "enc": manifest["encoding"],
                        "pair": text_idx,
                        "dialogue_group": group,
                        "policy": policy,
                    }
                    if entry.get("msg3_code"):
                        name_meta["msg3"] = entry["msg3_code"]
                    chunks.append(dsat_block(name_idx, "name", entry["speaker"], entry["speaker"], name_meta) + "\n")
                    file_counts["name"] += 1
                    totals["name"] += 1

                    text_meta = {
                        "file": rel,
                        "off": f"0x{entry['text_offsets'][0]:08X}",
                        "inst": f"0x{entry['inst_offset']:08X}",
                        "speaker_idx": name_idx,
                        "name": entry["speaker"],
                        "name_source": "msg2",
                        "pair": name_idx,
                        "dialogue_group": group,
                        "voice": entry.get("voice_id", ""),
                        "parts": len(entry["text_offsets"]),
                        "src": ",".join(f"0x{x:08X}" for x in entry["text_offsets"]),
                        "rec": ",".join(str(x) for x in entry["text_lens"]),
                        "len": sum(entry["text_lens"]),
                        "enc": manifest["encoding"],
                        "policy": policy,
                    }
                    chunks.append(dsat_block(text_idx, "msg", entry["text"], entry["text"], text_meta) + "\n")
                    file_counts["msg"] += 1
                    totals["msg"] += 1
                else:
                    text_idx = f"{next_idx:06d}"
                    next_idx += 1
                    group = f"nar_{file_id}_{entry['vo_line_no']:06d}"
                    text_meta = {
                        "file": rel,
                        "off": f"0x{entry['text_offsets'][0]:08X}",
                        "inst": f"0x{entry['inst_offset']:08X}",
                        "role": "narrator",
                        "dialogue_group": group,
                        "voice": entry.get("voice_id", ""),
                        "parts": len(entry["text_offsets"]),
                        "src": ",".join(f"0x{x:08X}" for x in entry["text_offsets"]),
                        "rec": ",".join(str(x) for x in entry["text_lens"]),
                        "len": sum(entry["text_lens"]),
                        "enc": manifest["encoding"],
                        "policy": policy,
                    }
                    chunks.append(dsat_block(text_idx, "msg", entry["text"], entry["text"], text_meta) + "\n")
                    file_counts["msg"] += 1
                    totals["msg"] += 1
            elif entry["kind"] == "choice":
                choice_idx = f"{next_idx:06d}"
                next_idx += 1
                choice_meta = {
                    "file": rel,
                    "off": f"0x{entry['offset']:08X}",
                    "inst": f"0x{entry['inst_offset']:08X}",
                    "source": entry["cmd"],
                    "len": entry["len"],
                    "enc": manifest["encoding"],
                    "policy": policy,
                }
                if entry.get("suffix"):
                    choice_meta["suffix"] = entry["suffix"]
                chunks.append(dsat_block(choice_idx, "choice", entry["text"], entry["text"], choice_meta) + "\n")
                file_counts["choice"] += 1
                totals["choice"] += 1
            elif entry["kind"] == "ui":
                ui_idx = f"{next_idx:06d}"
                next_idx += 1
                ui_meta = {
                    "file": rel,
                    "off": f"0x{entry['offset']:08X}",
                    "inst": f"0x{entry['inst_offset']:08X}",
                    "source": entry["cmd"],
                    "len": entry["len"],
                    "enc": manifest["encoding"],
                    "policy": policy,
                }
                chunks.append(dsat_block(ui_idx, "msg", entry["text"], entry["text"], ui_meta) + "\n")
                file_counts["msg"] += 1
                totals["msg"] += 1

        out_file.write_text("".join(chunks), encoding="utf-8", newline="\n")
        totals["files"] += 1
        index_rows.append({"file": rel, "dsat": out_file.relative_to(text_root).as_posix(), **file_counts})

    report = {"text_root": str(text_root), "totals": totals, "files": index_rows, "policy": policy}
    json_dump(report, text_root / "dsat_export_report.json")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SCR text export helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("disasm")
    sp.add_argument("input_dir")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("--encoding", default=DEFAULT_ENCODING)

    sp = sub.add_parser("export-text")
    sp.add_argument("ir_dir")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("--in-place", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "disasm":
        report = disasm(Path(args.input_dir), Path(args.output), args.encoding)
        print(json.dumps(report["totals"], ensure_ascii=False, indent=2))
    elif args.cmd == "export-text":
        report = export_text(Path(args.ir_dir), Path(args.output), relocate=not args.in_place)
        print(json.dumps(report["totals"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
