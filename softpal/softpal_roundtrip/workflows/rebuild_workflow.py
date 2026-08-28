from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..binary.primitives import encode_with_codec, sha256_hex
from ..core.models import TextEntry
from ..crypto.softpal import softpal_encrypt_bytes
from ..engine.text_dat_parser import load_text_dat_auto
from ..io.json_io import json_dump, load_jsonl
from ..profiles import load_profile


PAC_COMPATIBLE_ENCODINGS = {"932", "cp932", "ms932", "ms_kanji", "shift_jis", "shiftjis", "sjis"}


@dataclass(frozen=True, slots=True)
class RebuildStrategy:
    name: str
    probe: Callable[..., tuple[bool, str]]
    run: Callable[..., dict]


def rebuild_text_dat_from_rows(
    manifest: dict,
    text_rows: list[dict],
    *,
    inplace_mode: bool,
    strict_original: bool,
    edited_encoding: str = "cp932",
) -> bytes:
    parts = [bytes.fromhex(manifest["text_header_hex"])]
    for row in text_rows:
        idx = int(row["idx"])
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        original_raw = bytes.fromhex(row["raw_text_hex"])
        if strict_original and current_text != original_text:
            raise ValueError(f"idx={idx} 的 text 字段已被修改，rebuild-lossless 只允许从未改动的 dump 原样回编")
        if inplace_mode and current_text != original_text:
            encoded = encode_with_codec(current_text, edited_encoding)
            if len(encoded) != len(original_raw):
                raise ValueError(
                    f"idx={idx} 原文长度 {len(original_raw)}，新文长度 {len(encoded)}，原地回编要求字节长度完全一致"
                )
            raw_text = encoded
        elif current_text != original_text:
            raw_text = encode_with_codec(current_text, edited_encoding)
        else:
            raw_text = original_raw
        parts.extend([struct.pack("<I", idx), raw_text, b"\x00"])
    parts.append(bytes.fromhex(manifest["text_trailer_hex"]))
    return b"".join(parts)


def rebuild_text_dat_with_relocations(
    manifest: dict,
    text_rows: list[dict],
    *,
    edited_encoding: str,
) -> tuple[bytes, dict[int, int], int]:
    header = bytes.fromhex(manifest["text_header_hex"])
    trailer = bytes.fromhex(manifest["text_trailer_hex"])
    parts = [header]
    old_to_new: dict[int, int] = {}
    changed_rows = 0
    cursor = len(header)
    for row in text_rows:
        idx = int(row["idx"])
        old_offset = int(row["entry_offset"])
        old_to_new[old_offset] = cursor
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        original_raw = bytes.fromhex(row["raw_text_hex"])
        raw_text = encode_with_codec(current_text, edited_encoding) if current_text != original_text else original_raw
        if current_text != original_text:
            changed_rows += 1
        parts.extend([struct.pack("<I", idx), raw_text, b"\x00"])
        cursor += 4 + len(raw_text) + 1
    parts.append(trailer)
    return b"".join(parts), old_to_new, changed_rows


def rebuild_script_from_rows(script_rows: list[dict]) -> bytes:
    blob = bytearray()
    expected_offset = 0
    for row in script_rows:
        offset = int(row["offset"])
        value = int(row["u32"])
        if offset != expected_offset:
            raise ValueError(f"script_words.jsonl 偏移不连续：期望 0x{expected_offset:08X}，实际 0x{offset:08X}")
        blob.extend(struct.pack("<I", value))
        expected_offset += 4
    return bytes(blob)


def rebuild_script_from_rows_with_relocations(
    script_rows: list[dict],
    old_to_new: dict[int, int],
) -> tuple[bytes, int]:
    blob = bytearray()
    expected_offset = 0
    changed_words = 0
    for row in script_rows:
        offset = int(row["offset"])
        value = int(row["u32"])
        if offset != expected_offset:
            raise ValueError(f"script_words.jsonl 偏移不连续：期望 0x{expected_offset:08X}，实际 0x{offset:08X}")
        if "text_idx" in row and value in old_to_new:
            new_value = old_to_new[value]
            if new_value != value:
                value = new_value
                changed_words += 1
        blob.extend(struct.pack("<I", value))
        expected_offset += 4
    return bytes(blob), changed_words


def write_encrypted_variants(
    out_dir: Path,
    manifest: dict,
    script_data: bytes,
    text_data: bytes,
    *,
    replace_plain_outputs: bool = False,
) -> dict[str, str | bool]:
    encrypted_paths: dict[str, str | bool] = {}
    text_encrypted = softpal_encrypt_bytes(text_data)
    text_name = manifest["text_name"] if replace_plain_outputs else manifest["text_name"] + ".en"
    (out_dir / text_name).write_bytes(text_encrypted)
    encrypted_paths["text_encrypted"] = text_name
    script_encrypted = softpal_encrypt_bytes(script_data)
    script_name = manifest["script_name"] if replace_plain_outputs else manifest["script_name"] + ".en"
    (out_dir / script_name).write_bytes(script_encrypted)
    encrypted_paths["script_encrypted"] = script_name
    encrypted_paths["encrypted_replaces_plain"] = replace_plain_outputs
    return encrypted_paths


def rebuild_lossless_command(dump_dir: Path, out_dir: Path, *, encrypt_output: bool = False, replace_plain_with_encrypted: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    script_rows = load_jsonl(dump_dir / "script_words.jsonl")
    text_data = rebuild_text_dat_from_rows(manifest, text_rows, inplace_mode=False, strict_original=True)
    script_data = rebuild_script_from_rows(script_rows)
    if not replace_plain_with_encrypted:
        (out_dir / manifest["text_name"]).write_bytes(text_data)
        (out_dir / manifest["script_name"]).write_bytes(script_data)
    report = {
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(text_data),
        "script_matches_original": sha256_hex(script_data) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(text_data) == manifest["text_sha256"],
    }
    if encrypt_output:
        report.update(write_encrypted_variants(out_dir, manifest, script_data, text_data, replace_plain_outputs=replace_plain_with_encrypted))
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def rebuild_inplace_command(dump_dir: Path, out_dir: Path, *, edited_encoding: str = "cp932", encrypt_output: bool = False, replace_plain_with_encrypted: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    script_rows = load_jsonl(dump_dir / "script_words.jsonl")
    text_data = rebuild_text_dat_from_rows(manifest, text_rows, inplace_mode=True, strict_original=False, edited_encoding=edited_encoding)
    script_data = rebuild_script_from_rows(script_rows)
    if not replace_plain_with_encrypted:
        (out_dir / manifest["text_name"]).write_bytes(text_data)
        (out_dir / manifest["script_name"]).write_bytes(script_data)
    report = {
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(text_data),
        "script_matches_original": sha256_hex(script_data) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(text_data) == manifest["text_sha256"],
        "edited_encoding": edited_encoding,
        "note": "如果你改了 text_entries.jsonl 里的 text 字段，TEXT.DAT 的哈希理应变化；完全不改时应与原文件完全一致。",
    }
    if encrypt_output:
        report.update(write_encrypted_variants(out_dir, manifest, script_data, text_data, replace_plain_outputs=replace_plain_with_encrypted))
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def rebuild_relocate_command(dump_dir: Path, out_dir: Path, *, edited_encoding: str, encrypt_output: bool = False, replace_plain_with_encrypted: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    script_rows = load_jsonl(dump_dir / "script_words.jsonl")
    text_data, old_to_new, changed_rows = rebuild_text_dat_with_relocations(manifest, text_rows, edited_encoding=edited_encoding)
    script_data, changed_words = rebuild_script_from_rows_with_relocations(script_rows, old_to_new)
    if not replace_plain_with_encrypted:
        (out_dir / manifest["text_name"]).write_bytes(text_data)
        (out_dir / manifest["script_name"]).write_bytes(script_data)
    report = {
        "edited_encoding": edited_encoding,
        "changed_rows": changed_rows,
        "relocated_offsets": sum(1 for old, new in old_to_new.items() if old != new),
        "rewritten_script_words": changed_words,
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(text_data),
        "script_matches_original": sha256_hex(script_data) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(text_data) == manifest["text_sha256"],
        "note": "这个模式允许文本变长，并会同步改写 SCRIPT.SRC 里的文本偏移引用。",
    }
    if encrypt_output:
        report.update(write_encrypted_variants(out_dir, manifest, script_data, text_data, replace_plain_outputs=replace_plain_with_encrypted))
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def normalize_codec_name(codec: str) -> str:
    return codec.strip().lower().replace("-", "_")


def is_pointer_table_compatible_codec(codec: str) -> bool:
    return normalize_codec_name(codec) in PAC_COMPATIBLE_ENCODINGS


def find_pointer_table_start(text_data: bytes, script_data: bytes, start_idx: int = 0) -> tuple[int, int]:
    pos1 = text_data.find(b"\x00\x00\x00\x00\x00\x00")
    if pos1 < 2:
        raise ValueError("未找到 TEXT.DAT 指针表计数区域")
    text_count_offset = pos1 - 2
    
    anchor_idx, script_hit_pos = auto_find_anchor_idx(text_data, script_data, start_idx=start_idx)
    return text_count_offset, script_hit_pos - 8


def auto_find_anchor_idx(text_data: bytes, script_data: bytes, start_idx: int = 0, limit: int = 10000) -> tuple[int, int]:
    """
    在脚本中搜索一个唯一的文本地址引用，作为定位指针表的锚点。
    """
    curr_idx = start_idx
    count = 0
    while count < limit:
        target_bytes = b"\x00" + struct.pack("<I", curr_idx)
        pos_in_text = text_data.find(target_bytes)
        
        if pos_in_text >= 0:
            p_val = pos_in_text + 1
            needle = struct.pack("<I", p_val)
            
            hits = []
            search_pos = 0
            while True:
                hit = script_data.find(needle, search_pos)
                if hit < 0:
                    break
                hits.append(hit)
                search_pos = hit + 1
            
            if len(hits) == 1:
                return curr_idx, hits[0]
        
        curr_idx += 1
        count += 1
        
    raise ValueError(f"无法定位唯一的脚本指针锚点（已尝试 {limit} 个索引）。")


def build_pointer_table_map(script_data: bytes, entries: list[TextEntry], *, start_idx: int = 0, script_scan_start: int) -> dict[int, int]:
    entry_by_idx = {entry.idx: entry for entry in entries}
    mapping: dict[int, int] = {}
    pos = script_scan_start
    for idx in range(len(entries)):
        if idx < start_idx:
            continue
        entry = entry_by_idx.get(idx)
        if entry is None:
            continue
        target = struct.pack("<I", entry.entry_offset)
        while True:
            if pos + 4 > len(script_data):
                raise ValueError(f"在 SCRIPT.SRC 中查找 idx={idx} 指针失败")
            if script_data[pos : pos + 4] == target:
                mapping[idx] = pos
                pos += 4
                break
            pos += 4
    return mapping


def rebuild_with_pointer_table_command(
    dump_dir: Path,
    script_path: Path,
    text_path: Path,
    out_dir: Path,
    *,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
    start_idx: int = 0,
    script_scan_start: int | None = None,
) -> dict:
    if not is_pointer_table_compatible_codec(edited_encoding):
        raise ValueError("pointer-table backend 仅支持 cp932/932/Shift-JIS 系编码")
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    changed_rows = sum(1 for row in text_rows if row.get("text", row["original_text"]) != row["original_text"])
    profile = load_profile(manifest.get("profile", "classic-softpal"))
    archive = load_text_dat_auto(text_path, profile, text_codec=manifest.get("text_codec", "cp932"))
    entries = list(archive.entries)
    raw_script = script_path.read_bytes()

    if script_scan_start is None:
        _text_count_offset, script_scan_start = find_pointer_table_start(archive.normalized_data, raw_script, start_idx=start_idx)
    
    pointer_map = build_pointer_table_map(raw_script, entries, start_idx=start_idx, script_scan_start=script_scan_start)
    script_out = bytearray(raw_script)
    text_parts = [archive.header]
    cursor = len(archive.header)
    for row in text_rows:
        idx = int(row["idx"])
        current_text = row.get("text", row["original_text"])
        if idx >= start_idx:
            script_off = pointer_map.get(idx)
            if script_off is not None:
                script_out[script_off : script_off + 4] = struct.pack("<I", cursor)
        raw_line = encode_with_codec(current_text, edited_encoding) if current_text != row["original_text"] else bytes.fromhex(row["raw_text_hex"])
        text_parts.extend([struct.pack("<I", idx), raw_line, b"\x00"])
        cursor += 4 + len(raw_line) + 1
    text_parts.append(archive.trailer)
    plain_script_data = bytes(script_out)
    plain_text_data = b"".join(text_parts)
    encrypted_script_data = softpal_encrypt_bytes(plain_script_data)
    encrypted_text_data = softpal_encrypt_bytes(plain_text_data)
    output_map: dict[str, str] = {}
    if replace_plain_with_encrypted:
        delivered_script = encrypted_script_data if encrypt_output else plain_script_data
        delivered_text = encrypted_text_data if encrypt_output else plain_text_data
        (out_dir / manifest["script_name"]).write_bytes(delivered_script)
        (out_dir / manifest["text_name"]).write_bytes(delivered_text)
        if encrypt_output:
            output_map["script_encrypted_path"] = manifest["script_name"]
            output_map["text_encrypted_path"] = manifest["text_name"]
    else:
        delivered_script = plain_script_data
        delivered_text = plain_text_data
        (out_dir / manifest["script_name"]).write_bytes(plain_script_data)
        (out_dir / manifest["text_name"]).write_bytes(plain_text_data)
        if encrypt_output:
            script_en = manifest["script_name"] + ".en"
            text_en = manifest["text_name"] + ".en"
            (out_dir / script_en).write_bytes(encrypted_script_data)
            (out_dir / text_en).write_bytes(encrypted_text_data)
            output_map["script_encrypted_path"] = script_en
            output_map["text_encrypted_path"] = text_en
    report = {
        "backend": "pointer_table_rebuild",
        "edited_encoding": edited_encoding,
        "changed_rows": changed_rows,
        "pointer_table_entries": len(pointer_map),
        "pointer_table_start": f"0x{script_scan_start:08X}",
        "script_sha256": sha256_hex(delivered_script),
        "text_sha256": sha256_hex(delivered_text),
        "script_matches_original": sha256_hex(delivered_script) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(delivered_text) == manifest["text_sha256"],
    }
    report.update(output_map)
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def _probe_inplace(
    dump_dir: Path,
    *,
    edited_encoding: str,
    **_: object,
) -> tuple[bool, str]:
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    changed_rows = 0
    for row in text_rows:
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        if current_text == original_text:
            continue
        changed_rows += 1
        original_raw = bytes.fromhex(row["raw_text_hex"])
        encoded = encode_with_codec(current_text, edited_encoding)
        if len(encoded) != len(original_raw):
            return False, f"inplace length mismatch at idx={row['idx']}"
    if changed_rows == 0:
        return True, "no edited rows; inplace is safe"
    return True, f"{changed_rows} changed rows with matching byte lengths"


def _probe_relocate(
    dump_dir: Path,
    *,
    edited_encoding: str,
    **_: object,
) -> tuple[bool, str]:
    del dump_dir, edited_encoding
    return True, "relocate backend is generally applicable for variable-length text"


def _probe_pointer_table(
    dump_dir: Path,
    *,
    edited_encoding: str,
    script_path: Path,
    text_path: Path,
    **_: object,
) -> tuple[bool, str]:
    if not is_pointer_table_compatible_codec(edited_encoding):
        return False, "pointer-table backend only supports Shift-JIS compatible encodings"
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    profile = load_profile(manifest.get("profile", "classic-softpal"))
    archive = load_text_dat_auto(text_path, profile, text_codec=manifest.get("text_codec", "cp932"))
    raw_script = script_path.read_bytes()
    try:
        _text_count_offset, script_scan_start = find_pointer_table_start(archive.normalized_data, raw_script, start_idx=1111)
    except Exception as exc:
        return False, str(exc)
    return True, f"pointer table detected near script offset 0x{script_scan_start:08X}"


def get_rebuild_strategies() -> list[RebuildStrategy]:
    return [
        RebuildStrategy(
            name="inplace",
            probe=_probe_inplace,
            run=lambda **kwargs: rebuild_inplace_command(**kwargs),
        ),
        RebuildStrategy(
            name="relocate",
            probe=_probe_relocate,
            run=lambda **kwargs: rebuild_relocate_command(**kwargs),
        ),
        RebuildStrategy(
            name="pointer-table",
            probe=_probe_pointer_table,
            run=lambda **kwargs: rebuild_with_pointer_table_command(**kwargs),
        ),
    ]


def rebuild_auto_command(
    dump_dir: Path,
    out_dir: Path,
    *,
    script_path: Path,
    text_path: Path,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
) -> dict:
    attempts: list[dict[str, object]] = []
    for strategy in get_rebuild_strategies():
        if strategy.name == "inplace":
            probe_ok, reason = strategy.probe(
                dump_dir,
                edited_encoding=edited_encoding,
                script_path=script_path,
                text_path=text_path,
                encrypt_output=encrypt_output,
                replace_plain_with_encrypted=replace_plain_with_encrypted,
            )
            attempts.append({"strategy": strategy.name, "probe_ok": probe_ok, "reason": reason})
            if not probe_ok:
                continue
            try:
                result = strategy.run(
                    dump_dir=dump_dir,
                    out_dir=out_dir,
                    edited_encoding=edited_encoding,
                    encrypt_output=encrypt_output,
                    replace_plain_with_encrypted=replace_plain_with_encrypted,
                )
                result["selected_strategy"] = strategy.name
                result["auto_attempts"] = attempts
                return result
            except Exception as exc:
                attempts[-1]["run_error"] = str(exc)
                continue
        if strategy.name == "relocate":
            probe_ok, reason = strategy.probe(
                dump_dir,
                edited_encoding=edited_encoding,
                script_path=script_path,
                text_path=text_path,
                encrypt_output=encrypt_output,
                replace_plain_with_encrypted=replace_plain_with_encrypted,
            )
            attempts.append({"strategy": strategy.name, "probe_ok": probe_ok, "reason": reason})
            if not probe_ok:
                continue
            try:
                result = strategy.run(
                    dump_dir=dump_dir,
                    out_dir=out_dir,
                    edited_encoding=edited_encoding,
                    encrypt_output=encrypt_output,
                    replace_plain_with_encrypted=replace_plain_with_encrypted,
                )
                result["selected_strategy"] = strategy.name
                result["auto_attempts"] = attempts
                return result
            except Exception as exc:
                attempts[-1]["run_error"] = str(exc)
                continue
        probe_ok, reason = strategy.probe(
            dump_dir,
            edited_encoding=edited_encoding,
            script_path=script_path,
            text_path=text_path,
            encrypt_output=encrypt_output,
            replace_plain_with_encrypted=replace_plain_with_encrypted,
        )
        attempts.append({"strategy": strategy.name, "probe_ok": probe_ok, "reason": reason})
        if not probe_ok:
            continue
        try:
            result = strategy.run(
                dump_dir=dump_dir,
                script_path=script_path,
                text_path=text_path,
                out_dir=out_dir,
                edited_encoding=edited_encoding,
                encrypt_output=encrypt_output,
                replace_plain_with_encrypted=replace_plain_with_encrypted,
            )
            result["selected_strategy"] = strategy.name
            result["auto_attempts"] = attempts
            return result
        except Exception as exc:
            attempts[-1]["run_error"] = str(exc)
            continue
    raise ValueError(f"auto rebuild could not find a usable strategy: {attempts}")
