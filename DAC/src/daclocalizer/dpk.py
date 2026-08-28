# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple

from .utils import safe_relpath, copy_stream, checksums


@dataclass
class DpkEntry:
    index: int
    virtual_path: str
    local_relative_path: str
    data_offset: int
    size: int
    unknown_flags: int
    index_entry_relative_offset: int


def decode_index(data: bytes) -> tuple[bytearray, int, int, int]:
    if len(data) < 0x18 or data[:4] != b"DPK\x00":
        raise ValueError("Not a supported DPK file: missing DPK\\0 magic.")
    header = bytearray(data[:0x18])
    prev_cipher = 0
    for i in range(8, 16):
        c = header[i]
        header[i] = c ^ ((i - 16) & 0xFF)
        prev_cipher = c
    index_size = struct.unpack_from("<I", header, 8)[0]
    archive_size = struct.unpack_from("<I", header, 12)[0]
    if archive_size != len(data):
        raise ValueError(f"Archive size mismatch: header={archive_size}, actual={len(data)}")
    if not (0x18 <= index_size <= len(data)):
        raise ValueError(f"Invalid index size: {index_size}")
    index = bytearray(data[:index_size])
    index[:0x18] = header
    seed = prev_cipher
    for i in range(0x10, index_size):
        c = index[i]
        index[i] = c ^ ((i + seed) & 0xFF)
        seed = c
    file_count = struct.unpack_from("<I", index, 16)[0]
    return index, index_size, archive_size, file_count


def encode_index(decoded_index: bytes | bytearray) -> bytes:
    idx = bytearray(decoded_index)
    if len(idx) < 0x18 or idx[:4] != b"DPK\x00":
        raise ValueError("decoded index must start with DPK\\0")
    out = bytearray(idx)
    # Header bytes 8..15 are encoded independently. Bytes 0..7 stay as is.
    for i in range(8, 16):
        out[i] = idx[i] ^ ((i - 16) & 0xFF)
    seed = out[15]
    # The game's index stream starts at byte 0x10 and uses previous cipher byte.
    for i in range(0x10, len(idx)):
        out[i] = idx[i] ^ ((i + seed) & 0xFF)
        seed = out[i]
    return bytes(out)


def parse_entries(index: bytes | bytearray) -> list[DpkEntry]:
    file_count = struct.unpack_from("<I", index, 16)[0]
    entry_base = 0x14 + 4 * file_count
    entries: list[DpkEntry] = []
    for i in range(file_count):
        rel = struct.unpack_from("<I", index, 0x14 + 4 * i)[0]
        pos = entry_base + rel
        data_off, file_size, unk = struct.unpack_from("<III", index, pos)
        name_end = index.find(b"\x00", pos + 12)
        if name_end < 0:
            raise ValueError(f"Entry {i}: unterminated CP932 name.")
        raw_name = bytes(index[pos+12:name_end])
        name = raw_name.decode("cp932", errors="replace")
        local = safe_relpath(name, f"entry_{i:04d}.bin")
        entries.append(DpkEntry(i, name, local, data_off, file_size, unk, rel))
    return entries


def unpack_dpk(input_path: Path, output_dir: Path) -> dict:
    data = input_path.read_bytes()
    index, index_size, archive_size, file_count = decode_index(data)
    entries = parse_entries(index)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_entries = []
    for e in entries:
        abs_off = index_size + e.data_offset
        abs_end = abs_off + e.size
        if abs_end > len(data):
            raise ValueError(f"Entry {e.index}: data range exceeds archive size")
        payload = data[abs_off:abs_end]
        out_path = output_dir / e.local_relative_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(payload)
        manifest_entries.append({
            "index": e.index,
            "virtual_path": e.virtual_path,
            "local_relative_path": e.local_relative_path,
            "original_metadata": {
                "index_entry_relative_offset": e.index_entry_relative_offset,
                "data_offset": e.data_offset,
                "absolute_data_offset": abs_off,
                "size": e.size,
                "unknown_flags": e.unknown_flags,
                "crc32": f"{zlib.crc32(payload) & 0xFFFFFFFF:08X}",
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
        })
    manifest = {
        "$schema": "local.dac_dpk.vfs_manifest.v2",
        "engine_plugin": "dac_dpk_integrated",
        "archive_metadata": {
            "filename": input_path.name,
            "byte_size": archive_size,
            "magic": "DPK\\0",
            "decoded_index_size": index_size,
            "file_count": file_count,
            "index_encryption": "rolling_xor",
            "payload_order": "index_order_contiguous_after_index",
        },
        "files": manifest_entries,
    }
    (output_dir / "vfs_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "_decoded_index.bin").write_bytes(index)
    return manifest


def physical_order_entries(entries: list[dict]) -> list[dict]:
    """Return entries in original payload physical order, not index-table order.

    This DPK variant stores several entries out of index order. Preserving the
    original physical order is required for byte-exact zero-edit round-trip.
    When files grow, later files in this physical stream are relocated.
    """
    return sorted(entries, key=lambda e: (int(e.get("original_metadata", {}).get("data_offset", 0)), int(e["index"])))


def patch_decoded_index(decoded_index: bytes | bytearray, entries: list[dict], base_dir: Path) -> tuple[bytes, list[dict], int]:
    idx = bytearray(decoded_index)
    file_count = struct.unpack_from("<I", idx, 16)[0]
    if file_count != len(entries):
        raise ValueError(f"index file count {file_count} != manifest entries {len(entries)}")
    entry_base = 0x14 + 4 * file_count
    current = 0
    reloc = []
    for e in physical_order_entries(entries):
        i = int(e["index"])
        rel = struct.unpack_from("<I", idx, 0x14 + 4 * i)[0]
        pos = entry_base + rel
        local = base_dir / e["local_relative_path"]
        if not local.exists():
            raise FileNotFoundError(f"missing payload for DPK repack: {local}")
        new_size = local.stat().st_size
        old = e.get("original_metadata", {})
        old_off = int(old.get("data_offset", 0))
        old_size = int(old.get("size", new_size))
        struct.pack_into("<II", idx, pos, current, new_size)
        reloc.append({
            "index": i,
            "path": e["local_relative_path"],
            "old_offset": old_off,
            "new_offset": current,
            "old_size": old_size,
            "new_size": new_size,
            "delta_size": new_size - old_size,
        })
        current += new_size
    archive_size = len(idx) + current
    struct.pack_into("<I", idx, 12, archive_size)
    return bytes(idx), reloc, archive_size


def repack_dpk(extract_dir: Path, output_path: Path) -> dict:
    manifest_path = extract_dir / "vfs_manifest.json"
    index_path = extract_dir / "_decoded_index.bin"
    if not manifest_path.exists() or not index_path.exists():
        raise FileNotFoundError("extract_dir must contain vfs_manifest.json and _decoded_index.bin")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    decoded_index = index_path.read_bytes()
    patched_index, reloc, archive_size = patch_decoded_index(decoded_index, manifest["files"], extract_dir)
    encoded_index = encode_index(patched_index)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as out:
        out.write(encoded_index)
        for e in physical_order_entries(manifest["files"]):
            copy_stream(extract_dir / e["local_relative_path"], out)
    report = {
        "output": str(output_path),
        "archive_size": archive_size,
        "file_count": len(manifest["files"]),
        "checksums": checksums(output_path.read_bytes()),
        "relocation_log": reloc,
    }
    output_path.with_suffix(output_path.suffix + ".repack_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    output_path.with_suffix(output_path.suffix + ".relocation_log.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in reloc) + "\n", encoding="utf-8")
    return report
