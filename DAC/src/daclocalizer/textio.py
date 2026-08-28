# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, Optional

from .placeholder import decode_dsat_text, dsat_text_to_plain_string, validate_placeholder_preserve, extract_placeholder_hex, extract_placeholder_display, visible_escape_from_bytes, PlaceholderError
from .utils import checksums

QUOTE_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
# DAC source often prefixes dialogue with a face/voice cue, e.g. ５Ｂ「...」, １２Ｂ「...」, ５大Ａ「...」.
# It is script control metadata, not translatable message text.
DIALOGUE_CUE_RE = re.compile(r"^(?P<cue>[0-9０-９]{1,3}(?:大)?[A-ZＡ-Ｚ])(?P<text>[「『（(【〈《].*)$")
# DAC runtime interpolation macro, e.g. {$.M}. Simple scalar macros can be
# resolved to the displayed name in DSAT, then restored on rebuild.
SIMPLE_RUNTIME_MACRO_RE = re.compile(r"\{\$\.(?P<name>[A-Za-z_]\w*)\}")
ANY_RUNTIME_MACRO_RE = re.compile(r"\{\$\.[^}]+\}")
SCALAR_ASSIGN_RE = re.compile(r'^\s*\$\.(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<val>(?:[^"\\]|\\.)*)"')
SCALAR_DEFAULT_RE = re.compile(r'\?\s*\$\.(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<val>(?:[^"\\]|\\.)*)"')
DSAT_META_RE = re.compile(r"#\s+(.*)$")
DSAT_SRC_RE = re.compile(r"^○(?P<idx>\d+)○(?P<tag>[^○]+)○(?P<text>.*)$")
DSAT_DST_RE = re.compile(r"^●(?P<idx>\d+)●(?P<tag>[^●]+)●(?P<text>.*)$")


def unquote_script_string(s: str) -> str:
    return s.replace('\\"', '"').replace('\\\\', '\\')


def quote_script_string(s: str) -> str:
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def parse_meta(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for token in s.split():
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        out[k] = v
    return out


@dataclass
class TextEntry:
    idx: str
    file: str
    decoded_file: str
    source_encrypted: str
    line: int
    off: str
    tag: str
    text: str
    kind: str
    speaker: str = ""
    pair: str = ""
    dialogue_group: str = ""
    arg_index: int = -1
    prefix: str = ""
    cue_prefix: str = ""
    policy: str = "relocate"
    encoding: str = "cp932"
    ph_bytes: str = ""
    ph_hash: str = ""
    ph_display: str = ""
    macro_refs: str = ""
    macro_values: str = ""
    macro_tokens: str = ""
    macro_policy: str = ""


def line_offsets(raw: bytes) -> list[tuple[int, bytes, bytes]]:
    out = []
    off = 0
    for line in raw.splitlines(keepends=True):
        # split content and line ending exactly
        if line.endswith(b"\r\n"):
            body, eol = line[:-2], b"\r\n"
        elif line.endswith(b"\n"):
            body, eol = line[:-1], b"\n"
        elif line.endswith(b"\r"):
            body, eol = line[:-1], b"\r"
        else:
            body, eol = line, b""
        out.append((off, body, eol))
        off += len(line)
    if not raw:
        out.append((0, b"", b""))
    return out


def compute_placeholder_info(text: str) -> tuple[str, str, str]:
    xs = extract_placeholder_hex(text)
    displays = extract_placeholder_display(text)
    ph_bytes = ",".join(xs)
    ph_display = ",".join(displays)
    h = hashlib.sha256(("|".join(xs)).encode("ascii")).hexdigest() if xs else ""
    return ph_bytes, h, ph_display


def build_runtime_macro_map(decoded_dir: Path, encoding: str = "cp932") -> dict[str, str]:
    """Collect simple scalar runtime variables such as $.M = "浅木"."""
    values: dict[str, str] = {}
    for fp in sorted(decoded_dir.glob("*")):
        if not fp.is_file():
            continue
        try:
            text = fp.read_bytes().decode(encoding)
        except UnicodeDecodeError:
            continue
        for line in text.splitlines():
            for rx in (SCALAR_ASSIGN_RE, SCALAR_DEFAULT_RE):
                m = rx.search(line)
                if not m:
                    continue
                key = "$." + m.group("name")
                val = unquote_script_string(m.group("val"))
                if not val:
                    continue
                # Prefer the first stable scalar value. If a later assignment differs,
                # leave the original mapping rather than flipping mid-export.
                values.setdefault(key, val)
    return values


def resolve_runtime_macros_for_display(text: str, runtime_macros: dict[str, str] | None = None) -> tuple[str, str, str, str]:
    """Replace simple runtime macros with their visible value for DSAT.

    Example: 「なあ{$.M}」 -> 「なあ浅木」 with metadata refs=$.M.
    Indexed/runtime expressions remain untouched and can be filtered separately.
    """
    runtime_macros = runtime_macros or {}
    refs: list[str] = []
    vals: list[str] = []
    toks: list[str] = []

    def repl(m: re.Match[str]) -> str:
        key = "$." + m.group("name")
        if key not in runtime_macros:
            return m.group(0)
        refs.append(key)
        vals.append(runtime_macros[key])
        toks.append(m.group(0))
        return runtime_macros[key]

    display = SIMPLE_RUNTIME_MACRO_RE.sub(repl, text)
    return display, ",".join(refs), ",".join(vals), ",".join(toks)


def restore_runtime_macros_for_script(text: str, entry: "TextEntry") -> str:
    """Restore displayed simple macro values to original script macros.

    Zero-edit rebuilds become byte-identical, while intentional edits that remove
    the original display value are kept as literals.
    """
    if not entry.macro_tokens or not entry.macro_values:
        return text
    tokens = entry.macro_tokens.split(",")
    values = entry.macro_values.split(",")
    out = text
    for token, value in zip(tokens, values):
        if value:
            out = out.replace(value, token, 1)
    return out


def has_unresolved_runtime_macro(text: str) -> bool:
    return ANY_RUNTIME_MACRO_RE.search(text) is not None


def is_dynamic_only_runtime_text(text: str) -> bool:
    """True for runtime-only UI/expression lines that should not be translated."""
    stripped = ANY_RUNTIME_MACRO_RE.sub("", text)
    noise = set(" \t\r\n　《》「」『』【】[]（）()〈〉<>、。・…!！?？:：;；,.，/\\\"\'`")
    stripped = "".join(ch for ch in stripped if ch not in noise)
    return stripped == ""


def build_script_ir(decoded_path: Path, source_encrypted: str, out_dir: Path, encoding: str = "cp932") -> dict:
    raw = decoded_path.read_bytes()
    out_dir.mkdir(parents=True, exist_ok=True)
    region_map = [{
        "region_type": "instruction_stream_text",
        "start": "0x00000000",
        "end": f"0x{len(raw):08X}",
        "size": len(raw),
        "coverage_policy": "full_decoded_script_stream",
    }]
    instructions_path = out_dir / (decoded_path.name + ".instructions.jsonl")
    with instructions_path.open("w", encoding="utf-8") as f:
        for line_no, (off, body, eol) in enumerate(line_offsets(raw), 1):
            try:
                text = body.decode(encoding)
                ok = True
            except UnicodeDecodeError:
                text = body.decode(encoding, errors="replace")
                ok = False
            s = text.strip()
            opcode = "BLANK"
            if s.startswith(".call 台詞"):
                opcode = "CALL.SPEAKER"
            elif s.startswith(".call 選択肢"):
                opcode = "CALL.CHOICE"
            elif s.startswith(".call set_subtitle"):
                opcode = "CALL.SUBTITLE"
            elif s.startswith("."):
                opcode = "COMMAND"
            elif s.startswith("$"):
                opcode = "EXPRESSION"
            elif s.endswith(":") and not s.startswith("//"):
                opcode = "LABEL"
            elif s.startswith("//"):
                opcode = "COMMENT"
            elif s:
                opcode = "TEXT.MSG"
            rec = {
                "offset": f"0x{off:08X}",
                "line": line_no,
                "size": len(body) + len(eol),
                "raw_bytes_sha256": hashlib.sha256(body + eol).hexdigest(),
                "opcode": opcode,
                "label": f"loc_{off:08X}",
                "decode_ok": ok,
                "text_semantic": "msg" if opcode == "TEXT.MSG" else None,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    ir = {
        "schema_version": "1.0.0",
        "binary_metadata": {
            "filename": decoded_path.name,
            "source_encrypted": source_encrypted,
            "encoding": encoding,
            "checksum": checksums(raw),
            "layers": [{"algorithm": "DACZ_LCG_STREAM", "order": 1}],
        },
        "subresources": {
            "region_map": decoded_path.name + ".region_map.json",
            "instructions": instructions_path.name,
            "text_entries": decoded_path.name + ".text_entries.jsonl",
        },
        "compilation_strategy": {
            "relocation_allowed": True,
            "string_padding_mode": "whole_text_script_rebuild",
            "label_resolution": False,
            "alignment_requirement": 1,
        },
    }
    (out_dir / (decoded_path.name + ".region_map.json")).write_text(json.dumps(region_map, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / (decoded_path.name + ".ir_compact.json")).write_text(json.dumps(ir, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / (decoded_path.name + ".coverage_report.txt")).write_text("address_space_coverage = 100.00%\n[OK] no gap\n[OK] no overlap\n", encoding="utf-8")
    # human-readable asm view, source-level because this VM stores DAC source text after decoding.
    asm_lines = [
        "; daclocalizer asm/source view v1",
        f"; source: {decoded_path.name}",
        f"; source_encrypted: {source_encrypted}",
        f"; encoding: {encoding}",
        f"; sha256: {checksums(raw)['sha256']}",
        "",
    ]
    for line_no, (off, body, eol) in enumerate(line_offsets(raw), 1):
        text = visible_escape_from_bytes(body, encoding)
        asm_lines.append(f"loc_{off:08X}:")
        asm_lines.append(f"    .source_line {line_no} {quote_script_string(text)}")
        asm_lines.append("")
    (out_dir / (decoded_path.name + ".asm.txt")).write_text("\n".join(asm_lines), encoding="utf-8")
    return ir


def extract_entries_from_decoded(decoded_path: Path, source_encrypted: str, start_idx: int, encoding: str = "cp932", runtime_macros: dict[str, str] | None = None) -> tuple[list[TextEntry], int]:
    raw = decoded_path.read_bytes()
    runtime_macros = runtime_macros or {}
    entries: list[TextEntry] = []
    idx = start_idx
    current_name_idx = ""
    current_speaker = ""
    pending_name_entry: Optional[TextEntry] = None
    group_no = 0

    def add(line_no: int, off: int, tag: str, text: str, kind: str, speaker: str = "", arg_index: int = -1, prefix: str = "", cue_prefix: str = "") -> TextEntry:
        nonlocal idx
        display_text, macro_refs, macro_values, macro_tokens = resolve_runtime_macros_for_display(text.strip(), runtime_macros)
        ph_bytes, ph_hash, ph_display = compute_placeholder_info(display_text)
        e = TextEntry(
            idx=f"{idx:06d}",
            file=decoded_path.name,
            decoded_file=decoded_path.name,
            source_encrypted=source_encrypted,
            line=line_no,
            off=f"0x{off:08X}",
            tag=tag,
            text=display_text,
            kind=kind,
            speaker=speaker,
            arg_index=arg_index,
            prefix=prefix,
            cue_prefix=cue_prefix,
            ph_bytes=ph_bytes,
            ph_hash=ph_hash,
            ph_display=ph_display,
            macro_refs=macro_refs,
            macro_values=macro_values,
            macro_tokens=macro_tokens,
            macro_policy=("display_resolve_restore" if macro_refs else ""),
        )
        entries.append(e)
        idx += 1
        return e

    for line_no, (off, body, eol) in enumerate(line_offsets(raw), 1):
        try:
            line = body.decode(encoding)
        except UnicodeDecodeError:
            continue
        s = line.strip()
        if not s or s.startswith("//"):
            continue

        if s.startswith(".call 台詞"):
            # speaker command, physical and writable; pair with next msg if any.
            speaker = s[len(".call 台詞"):].strip().strip('"')
            current_speaker = speaker
            name_entry = add(line_no, off, "name", speaker, "speaker_call", speaker="")
            current_name_idx = name_entry.idx
            pending_name_entry = name_entry
            continue

        if s.startswith(".call set_subtitle"):
            rest = s[len(".call set_subtitle"):].strip()
            if rest:
                add(line_no, off, "label", rest, "subtitle", speaker="", prefix=line[:line.find(rest)] if rest in line else ".call set_subtitle ")
            continue

        if s.startswith(".call 選択肢"):
            for n, m in enumerate(QUOTE_RE.finditer(line)):
                val = unquote_script_string(m.group(1))
                if val.strip():
                    add(line_no, off, "choice", val, "choice_arg", speaker="", arg_index=n)
            continue

        # selected variable / ini quoted strings that are likely visible. Keep conservative.
        if s.startswith("caption ") or s.startswith("dialog_title ") or s.startswith("help\t") or s.startswith("help "):
            for n, m in enumerate(QUOTE_RE.finditer(line)):
                val = unquote_script_string(m.group(1))
                if val.strip():
                    add(line_no, off, "ui", val, "quoted_arg", speaker="", arg_index=n)
            continue

        # Names stored in variables in main.dac, e.g. $.N = "政紀".
        if re.match(r"^\$\.[A-Za-z_][\w]*\s*=\s*\"", s):
            for n, m in enumerate(QUOTE_RE.finditer(line)):
                val = unquote_script_string(m.group(1))
                if val.strip():
                    add(line_no, off, "name", val, "quoted_assignment", speaker="", arg_index=n)
            continue

        if s.startswith(".") or s.startswith("$") or s.endswith(":"):
            continue

        # Plain script line. Strip DAC dialogue cue prefixes such as
        # ５Ｂ / ７Ｂ / １２Ａ / ５大Ａ from the translatable text.
        # They are control metadata used by the engine for expression/voice style,
        # and must be preserved separately and reinserted on rebuild.
        text = s
        cue_prefix = ""
        cue_m = DIALOGUE_CUE_RE.match(text)
        if cue_m:
            cue_prefix = cue_m.group("cue")
            text = cue_m.group("text")
        if text:
            display_text, _, _, _ = resolve_runtime_macros_for_display(text, runtime_macros)
            if has_unresolved_runtime_macro(display_text) and is_dynamic_only_runtime_text(display_text):
                continue
            e = add(line_no, off, "msg", text, "plain_line", speaker=current_speaker, cue_prefix=cue_prefix)
            if pending_name_entry is not None:
                group = f"dlg_{group_no:06d}"
                group_no += 1
                pending_name_entry.pair = e.idx
                pending_name_entry.dialogue_group = group
                e.pair = pending_name_entry.idx
                e.dialogue_group = group
                e.speaker = current_speaker
                pending_name_entry = None
            elif current_name_idx:
                e.pair = current_name_idx
                e.speaker = current_speaker

    return entries, idx



def dsat_filename_for_source(source_encrypted: str) -> str:
    """Human-editable DSAT filename that preserves the original DPK entry name."""
    return source_encrypted.replace("/", "__").replace("\\", "__") + ".dsat.txt"


def _write_dsat_file(path: Path, entries: list[TextEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        for e in entries:
            meta = [
                f"idx={e.idx}", f"file={e.file}", f"decoded={e.decoded_file}", f"src={e.source_encrypted}",
                f"off={e.off}", f"line={e.line}", f"tag={e.tag}", f"kind={e.kind}", f"enc={e.encoding}", f"policy={e.policy}",
            ]
            if e.speaker:
                meta.append(f"name={e.speaker}")
            if e.pair:
                meta.append(f"pair={e.pair}")
            if e.dialogue_group:
                meta.append(f"dialogue_group={e.dialogue_group}")
            if e.arg_index >= 0:
                meta.append(f"arg={e.arg_index}")
            if e.cue_prefix:
                meta.append(f"cue={e.cue_prefix}")
            if e.macro_refs:
                meta += [f"macro_count={len(e.macro_refs.split(','))}", f"macro_refs={e.macro_refs}", f"macro_values={e.macro_values}", f"macro_policy={e.macro_policy}"]
            if e.ph_bytes:
                meta += [f"ph_count={len(e.ph_bytes.split(','))}", f"ph_bytes={e.ph_bytes}", f"ph_display={e.ph_display}", "ph_policy=preserve", f"ph_hash={e.ph_hash}"]
            f.write("# " + " ".join(meta) + "\n")
            f.write(f"○{e.idx}○{e.tag}○{e.text}\n")
            f.write(f"●{e.idx}●{e.tag}●{e.text}\n\n")


def write_entries(entries: list[TextEntry], out_dir: Path) -> None:
    """Write DSAT primarily as one file per original script entry.

    Main editing path:
      texts/by_source/<original_dpk_entry>.dsat.txt

    A combined all_text file is still emitted under texts/_all/ for search/review
    and backward compatibility, but the workspace README and GUI use by_source by default.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    by_file_dir = out_dir / "by_source"
    all_dir = out_dir / "_all"
    by_file_dir.mkdir(parents=True, exist_ok=True)
    all_dir.mkdir(parents=True, exist_ok=True)

    grouped: dict[str, list[TextEntry]] = {}
    for e in entries:
        grouped.setdefault(e.source_encrypted, []).append(e)

    index = []
    for source_name, file_entries in sorted(grouped.items(), key=lambda kv: kv[0].lower()):
        fname = dsat_filename_for_source(source_name)
        path = by_file_dir / fname
        _write_dsat_file(path, file_entries)
        index.append({
            "source_encrypted": source_name,
            "decoded_file": file_entries[0].decoded_file if file_entries else "",
            "dsat": str(Path("by_source") / fname),
            "entries": len(file_entries),
        })

    (out_dir / "dsat_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")

    # Optional combined reference files, not the main editing target.
    _write_dsat_file(all_dir / "all_text.dsat.txt", entries)
    with (all_dir / "all_text.tsv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(entries[0]).keys()) if entries else ["idx", "file", "tag", "text"], delimiter="\t")
        w.writeheader()
        for e in entries:
            w.writerow(asdict(e))
    with (all_dir / "all_text.jsonl").open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")


def iter_dsat_files(path: Path) -> list[Path]:
    """Return DSAT files from a single file, texts, texts/by_source, or legacy by_file directory."""
    if path.is_file():
        return [path]
    if not path.exists():
        raise FileNotFoundError(f"DSAT path not found: {path}")
    # If user selects texts, prefer its by_source directory. Fall back to old by_file for compatibility.
    candidate = path / "by_source"
    if candidate.is_dir():
        path = candidate
    elif (path / "by_file").is_dir():
        path = path / "by_file"
    files = sorted(p for p in path.glob("*.dsat.txt") if p.is_file())
    # Fallback for older workspaces that only have all_text at the root.
    if not files:
        old = path / "all_text.dsat.txt"
        if old.exists():
            files = [old]
    if not files:
        raise FileNotFoundError(f"no *.dsat.txt files under: {path}")
    return files


def parse_dsat_inputs(path: Path) -> tuple[dict[str, dict], list[str]]:
    merged: dict[str, dict] = {}
    sources: list[str] = []
    for fp in iter_dsat_files(path):
        parsed = parse_dsat(fp)
        for idx, rec in parsed.items():
            if idx in merged:
                raise ValueError(f"duplicate DSAT idx={idx} in {fp}")
            merged[idx] = rec
        sources.append(str(fp))
    return merged, sources

def parse_dsat(path: Path) -> dict[str, dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    out: dict[str, dict] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if not line.startswith("#"):
            raise ValueError(f"DSAT parse error at line {i+1}: expected # metadata")
        meta = parse_meta(line[1:].strip())
        if meta.get("no_text") == "true":
            i += 1
            continue
        if i + 2 >= len(lines):
            raise ValueError(f"DSAT parse error at line {i+1}: incomplete block")
        src_m = DSAT_SRC_RE.match(lines[i+1])
        dst_m = DSAT_DST_RE.match(lines[i+2])
        if not src_m or not dst_m:
            raise ValueError(f"DSAT parse error at line {i+1}: expected ○ and ● lines")
        idx = meta.get("idx") or src_m.group("idx")
        if src_m.group("idx") != idx or dst_m.group("idx") != idx:
            raise ValueError(f"DSAT idx mismatch near line {i+1}")
        tag = meta.get("tag") or src_m.group("tag")
        if dst_m.group("tag") != tag or src_m.group("tag") != tag:
            raise ValueError(f"DSAT tag mismatch near idx={idx}")
        src_text = src_m.group("text")
        dst_text = dst_m.group("text")
        validate_placeholder_preserve(src_text, dst_text, strict_order=True)
        out[idx] = {"meta": meta, "source": src_text, "target": dst_text, "line_no": i+1}
        i += 3
    return out


def load_jsonl_entries(path: Path) -> list[TextEntry]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(TextEntry(**json.loads(line)))
    return entries


def apply_text_to_decoded(decoded_dir: Path, text_dir: Path, output_decoded_dir: Path, dsat_path: Path, encoding: str = "cp932", allow_lengthen: bool = True) -> dict:
    dsat, dsat_sources = parse_dsat_inputs(dsat_path)
    entries: list[TextEntry] = []
    manifest_path = text_dir / "text_entries.jsonl"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing text_entries.jsonl in {text_dir}")
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(TextEntry(**json.loads(line)))
    by_file: dict[str, list[TextEntry]] = {}
    for e in entries:
        by_file.setdefault(e.decoded_file, []).append(e)
    output_decoded_dir.mkdir(parents=True, exist_ok=True)
    report = {"patched_files": [], "entries_total": len(entries), "entries_changed": 0, "allow_lengthen": allow_lengthen, "dsat_sources": dsat_sources}
    for src_path in decoded_dir.iterdir():
        if src_path.is_file():
            data = src_path.read_bytes()
            out_path = output_decoded_dir / src_path.name
            out_path.write_bytes(data)
    for fname, file_entries in by_file.items():
        src_path = decoded_dir / fname
        if not src_path.exists():
            raise FileNotFoundError(f"decoded source missing: {src_path}")
        raw = src_path.read_bytes()
        split = line_offsets(raw)
        lines = []
        for off, body, eol in split:
            try:
                text = body.decode(encoding)
            except UnicodeDecodeError:
                text = body.decode(encoding, errors="replace")
            lines.append([text, eol])
        changed = 0
        per_line: dict[int, list[TextEntry]] = {}
        for e in file_entries:
            per_line.setdefault(e.line, []).append(e)
        for line_no, ents in sorted(per_line.items()):
            if line_no < 1 or line_no > len(lines):
                raise ValueError(f"entry line out of range: file={fname} line={line_no}")
            original_line = lines[line_no-1][0]
            new_line = original_line
            # Apply multiple entries on same line carefully. Choices/quoted args by index first.
            for e in ents:
                patch = dsat.get(e.idx)
                if patch is None:
                    raise ValueError(f"DSAT missing idx={e.idx}")
                target = patch["target"]
                if target == patch["source"]:
                    continue
                # Validate target encodes and placeholders are restorable before touching file.
                target_plain = dsat_text_to_plain_string(target, encoding)
                target_plain_for_script = restore_runtime_macros_for_script(target_plain, e)
                if not allow_lengthen:
                    old_len = len(restore_runtime_macros_for_script(patch["source"], e).encode(encoding, errors="strict"))
                    new_len = len(target_plain_for_script.encode(encoding, errors="strict"))
                    if new_len > old_len:
                        raise ValueError(f"in_place length overflow idx={e.idx}: {new_len}>{old_len}")
                if e.kind == "speaker_call":
                    prefix = new_line[:new_line.find(new_line.strip())] if new_line.strip() else ""
                    new_line = prefix + ".call 台詞 " + target_plain_for_script
                elif e.kind == "subtitle":
                    prefix = e.prefix or ".call set_subtitle "
                    leading = new_line[:len(new_line) - len(new_line.lstrip())]
                    new_line = leading + prefix.strip() + " " + target_plain_for_script
                elif e.kind in {"choice_arg", "quoted_arg", "quoted_assignment"}:
                    matches = list(QUOTE_RE.finditer(new_line))
                    if e.arg_index < 0 or e.arg_index >= len(matches):
                        raise ValueError(f"quoted arg index not found idx={e.idx} file={fname} line={line_no}")
                    m = matches[e.arg_index]
                    q = quote_script_string(target_plain_for_script)
                    new_line = new_line[:m.start()] + q + new_line[m.end():]
                elif e.kind == "plain_line":
                    leading = new_line[:len(new_line) - len(new_line.lstrip())]
                    cue = e.cue_prefix or ""
                    new_line = leading + cue + target_plain_for_script
                else:
                    raise ValueError(f"unsupported entry kind idx={e.idx}: {e.kind}")
                changed += 1
            lines[line_no-1][0] = new_line
        out = bytearray()
        for text, eol in lines:
            out.extend(text.encode(encoding))
            out.extend(eol)
        out_path = output_decoded_dir / fname
        out_path.write_bytes(bytes(out))
        if changed:
            report["entries_changed"] += changed
            report["patched_files"].append({"file": fname, "changed_entries": changed, "old_size": len(raw), "new_size": len(out), "delta": len(out)-len(raw)})
    return report
