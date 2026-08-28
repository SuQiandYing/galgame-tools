#!/usr/bin/env python3
"""scr.dat unpack/repack tool.

Detected format for the supplied scr.dat:
- 16-byte clear header: uint32_le file_count + 12 reserved bytes.
- FAT: file_count * 32 bytes, XOR 0x81 encrypted.
  Decoded record = uint32_le offset + uint32_le size + 24-byte NUL-padded ASCII name.
- Payload: each file payload starts with a plaintext 0x58 marker; remaining bytes are XOR 0x81 encrypted; file starts are aligned to 16 bytes.
- Bytes between (offset + size) and next aligned offset are opaque padding and are recorded.

This tool extracts decrypted payloads plus vfs_manifest.json and can rebuild byte-identical
archives when files are unmodified. If files are edited, offsets and sizes are recomputed
and padding is adjusted to 16-byte alignment.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

XOR_KEY_DEFAULT = 0x81
HEADER_SIZE = 16
ENTRY_SIZE = 32
NAME_SIZE = 24
ALIGNMENT_DEFAULT = 16
BUF_SIZE = 1024 * 1024


@dataclass
class Entry:
    index: int
    name: str
    offset: int
    size: int
    name_raw: bytes
    padding_after: bytes
    encrypted_sha256: str
    decoded_sha256: str


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(BUF_SIZE), b''):
            h.update(chunk)
    return h.hexdigest()


def hash_region(path: Path, offset: int, size: int, key: int | None = None, payload_mode: bool = False) -> str:
    h = hashlib.sha256()
    remaining = size
    first = True
    with path.open('rb') as f:
        f.seek(offset)
        while remaining:
            chunk = f.read(min(BUF_SIZE, remaining))
            if not chunk:
                raise EOFError(f'Unexpected EOF while hashing region at 0x{offset:x}')
            remaining -= len(chunk)
            if key is not None:
                if payload_mode and first:
                    # Payloads use a plaintext leading marker byte (0x58, ASCII 'X') and XOR for the rest.
                    chunk = chunk[:1] + xor_bytes(chunk[1:], key)
                    first = False
                else:
                    chunk = xor_bytes(chunk, key)
            h.update(chunk)
    return h.hexdigest()


def stream_payload_decode(src: BinaryIO, dst: BinaryIO, size: int, key: int) -> None:
    if size <= 0:
        return
    first = src.read(1)
    if len(first) != 1:
        raise EOFError('Unexpected EOF during payload decode')
    dst.write(first)
    remaining = size - 1
    while remaining:
        chunk = src.read(min(BUF_SIZE, remaining))
        if not chunk:
            raise EOFError('Unexpected EOF during payload decode')
        remaining -= len(chunk)
        dst.write(xor_bytes(chunk, key))


def stream_payload_encode(src: BinaryIO, dst: BinaryIO, size: int, key: int) -> None:
    if size <= 0:
        return
    first = src.read(1)
    if len(first) != 1:
        raise EOFError('Unexpected EOF during payload encode')
    dst.write(first)
    remaining = size - 1
    while remaining:
        chunk = src.read(min(BUF_SIZE, remaining))
        if not chunk:
            raise EOFError('Unexpected EOF during payload encode')
        remaining -= len(chunk)
        dst.write(xor_bytes(chunk, key))


def parse_archive(path: Path, key: int = XOR_KEY_DEFAULT) -> tuple[bytes, list[Entry]]:
    file_size = path.stat().st_size
    with path.open('rb') as f:
        header = f.read(HEADER_SIZE)
        if len(header) != HEADER_SIZE:
            raise ValueError('Archive is too small to contain the 16-byte header')
        count = struct.unpack_from('<I', header, 0)[0]
        table_end = HEADER_SIZE + count * ENTRY_SIZE
        if count <= 0:
            raise ValueError(f'Invalid file count: {count}')
        if table_end > file_size:
            raise ValueError(f'FAT exceeds archive size: table_end={table_end}, file_size={file_size}')
        decoded_records: list[tuple[int, int, bytes, str]] = []
        f.seek(HEADER_SIZE)
        for i in range(count):
            enc = f.read(ENTRY_SIZE)
            if len(enc) != ENTRY_SIZE:
                raise EOFError('Unexpected EOF while reading FAT')
            rec = xor_bytes(enc, key)
            off, size = struct.unpack_from('<II', rec, 0)
            name_raw = rec[8:8 + NAME_SIZE]
            name_bytes = name_raw.split(b'\x00', 1)[0]
            try:
                name = name_bytes.decode('ascii')
            except UnicodeDecodeError:
                name = name_bytes.decode('shift_jis', errors='replace')
            if not name:
                raise ValueError(f'Empty filename in FAT entry {i}')
            decoded_records.append((off, size, name_raw, name))

    # Basic structural validation and padding capture.
    entries: list[Entry] = []
    for i, (off, size, name_raw, name) in enumerate(decoded_records):
        if off < table_end:
            raise ValueError(f'Entry {i} ({name}) starts inside FAT: offset={off}, table_end={table_end}')
        if off + size > file_size:
            raise ValueError(f'Entry {i} ({name}) exceeds archive size: offset={off}, size={size}')
        next_off = decoded_records[i + 1][0] if i + 1 < len(decoded_records) else file_size
        if next_off < off + size:
            raise ValueError(f'Entry {i} ({name}) overlaps next entry')
        with path.open('rb') as f:
            f.seek(off + size)
            padding = f.read(next_off - (off + size))
        entries.append(Entry(
            index=i,
            name=name,
            offset=off,
            size=size,
            name_raw=name_raw,
            padding_after=padding,
            encrypted_sha256=hash_region(path, off, size, None),
            decoded_sha256=hash_region(path, off, size, key, payload_mode=True),
        ))
    return header, entries


def safe_output_path(root: Path, relative_name: str) -> Path:
    # The supplied archive uses flat ASCII names. This also prevents path traversal if reused.
    candidate = (root / relative_name).resolve()
    root_resolved = root.resolve()
    if root_resolved not in candidate.parents and candidate != root_resolved:
        raise ValueError(f'Unsafe path in archive: {relative_name!r}')
    return candidate


def unpack_archive(input_archive: Path, output_dir: Path, key: int = XOR_KEY_DEFAULT) -> dict:
    header, entries = parse_archive(input_archive, key)
    assets_dir = output_dir / 'files'
    if output_dir.exists():
        shutil.rmtree(output_dir)
    assets_dir.mkdir(parents=True, exist_ok=True)

    with input_archive.open('rb') as src:
        for entry in entries:
            out_path = safe_output_path(assets_dir, entry.name)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            src.seek(entry.offset)
            with out_path.open('wb') as dst:
                stream_payload_decode(src, dst, entry.size, key)

    manifest = {
        '$schema': 'local/scr_dat_manifest.schema.json',
        'engine_plugin': 'scr_dat_xor81_fixed_fat_payload_marker_plain',
        'archive_metadata': {
            'filename': input_archive.name,
            'byte_size': input_archive.stat().st_size,
            'sha256': sha256_file(input_archive),
            'header_size': HEADER_SIZE,
            'entry_size': ENTRY_SIZE,
            'name_field_size': NAME_SIZE,
            'file_count': len(entries),
            'xor_key': key,
            'sector_alignment': ALIGNMENT_DEFAULT,
            'header_raw_b64': base64.b64encode(header).decode('ascii'),
            'table_size': len(entries) * ENTRY_SIZE,
            'payload_base_offset': HEADER_SIZE + len(entries) * ENTRY_SIZE,
            'payload_transform': 'first_byte_plain_then_xor81',
        },
        'files': []
    }
    for entry in entries:
        manifest['files'].append({
            'index': entry.index,
            'virtual_path': entry.name,
            'local_relative_path': f'files/{entry.name}',
            'original_metadata': {
                'offset': entry.offset,
                'raw_size': entry.size,
                'compressed_size': entry.size,
                'is_compressed': False,
                'compression_method': 'none',
                'encryption_flag': 1,
                'encryption_method': 'first_byte_plain_then_xor',
                'xor_key': key,
                'filename_field_raw_b64': base64.b64encode(entry.name_raw).decode('ascii'),
                'padding_after_b64': base64.b64encode(entry.padding_after).decode('ascii'),
                'padding_after_size': len(entry.padding_after),
                'encrypted_sha256': entry.encrypted_sha256,
                'decoded_sha256': entry.decoded_sha256,
            },
            'repack_rules': {
                'alignment': ALIGNMENT_DEFAULT,
                'preserve_original_padding_when_possible': True,
            }
        })

    manifest_path = output_dir / 'vfs_manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


def load_manifest(extract_dir: Path) -> dict:
    manifest_path = extract_dir / 'vfs_manifest.json'
    if not manifest_path.exists():
        raise FileNotFoundError(f'Missing manifest: {manifest_path}')
    return json.loads(manifest_path.read_text(encoding='utf-8'))


def build_entry_record(offset: int, size: int, name_raw: bytes, key: int) -> bytes:
    if len(name_raw) != NAME_SIZE:
        raise ValueError(f'name_raw must be exactly {NAME_SIZE} bytes')
    rec = struct.pack('<II', offset, size) + name_raw
    if len(rec) != ENTRY_SIZE:
        raise AssertionError('Internal record-size mismatch')
    return xor_bytes(rec, key)


def repack_archive(extract_dir: Path, output_archive: Path, alignment: int | None = None,
                   key: int | None = None, preserve_padding: bool = True) -> dict:
    manifest = load_manifest(extract_dir)
    meta = manifest['archive_metadata']
    key = int(meta.get('xor_key', XOR_KEY_DEFAULT) if key is None else key)
    alignment = int(meta.get('sector_alignment', ALIGNMENT_DEFAULT) if alignment is None else alignment)
    files = sorted(manifest['files'], key=lambda x: int(x['index']))
    count = len(files)
    header = base64.b64decode(meta['header_raw_b64'])
    if len(header) != HEADER_SIZE:
        raise ValueError('Manifest header_raw_b64 is not 16 bytes')
    # Keep reserved bytes, but make the count authoritative.
    header = struct.pack('<I', count) + header[4:]

    output_archive.parent.mkdir(parents=True, exist_ok=True)
    offsets: list[int] = []
    sizes: list[int] = []
    name_fields: list[bytes] = []
    padding_written: list[int] = []
    table_end = HEADER_SIZE + count * ENTRY_SIZE
    current = align_up(table_end, alignment)
    if current != table_end:
        raise ValueError('This format expects table end to already satisfy the detected alignment')

    with output_archive.open('wb+') as out:
        out.write(header)
        out.write(b'\x00' * (count * ENTRY_SIZE))  # FAT placeholder; filled after payload layout is known.

        for idx, item in enumerate(files):
            local_path = extract_dir / item['local_relative_path']
            if not local_path.exists():
                raise FileNotFoundError(f'Missing extracted asset: {local_path}')
            name_raw = base64.b64decode(item['original_metadata']['filename_field_raw_b64'])
            if len(name_raw) != NAME_SIZE:
                # Fallback to encoding virtual_path if a human-edited manifest damaged the raw field.
                name_bytes = item['virtual_path'].encode('ascii')
                if len(name_bytes) > NAME_SIZE:
                    raise ValueError(f'Filename too long for 24-byte field: {item["virtual_path"]}')
                name_raw = name_bytes + b'\x00' * (NAME_SIZE - len(name_bytes))
            out.seek(current)
            offsets.append(current)
            size = local_path.stat().st_size
            sizes.append(size)
            name_fields.append(name_raw)
            with local_path.open('rb') as src:
                stream_payload_encode(src, out, size, key)
            current += size
            next_aligned = align_up(current, alignment)
            pad_len = next_aligned - current
            orig_pad = base64.b64decode(item['original_metadata'].get('padding_after_b64', ''))
            if preserve_padding and len(orig_pad) == pad_len:
                pad = orig_pad
            else:
                # Payload is XOR-encrypted, so plaintext zero padding is stored as key bytes.
                pad = bytes([key]) * pad_len
            out.write(pad)
            padding_written.append(len(pad))
            current = next_aligned

        # Write FAT after payload offsets and sizes are known.
        out.seek(HEADER_SIZE)
        for off, size, name_raw in zip(offsets, sizes, name_fields):
            out.write(build_entry_record(off, size, name_raw, key))

    report = {
        'output_archive': str(output_archive),
        'byte_size': output_archive.stat().st_size,
        'sha256': sha256_file(output_archive),
        'file_count': count,
        'alignment': alignment,
        'xor_key': key,
        'entries': [
            {
                'index': int(files[i]['index']),
                'virtual_path': files[i]['virtual_path'],
                'new_offset': offsets[i],
                'new_size': sizes[i],
                'padding_after_size': padding_written[i],
            }
            for i in range(count)
        ],
    }
    return report


def verify_archive(original: Path, rebuilt: Path) -> dict:
    orig_hash = sha256_file(original)
    rebuilt_hash = sha256_file(rebuilt)
    same = orig_hash == rebuilt_hash and original.stat().st_size == rebuilt.stat().st_size
    return {
        'original': str(original),
        'rebuilt': str(rebuilt),
        'original_size': original.stat().st_size,
        'rebuilt_size': rebuilt.stat().st_size,
        'original_sha256': orig_hash,
        'rebuilt_sha256': rebuilt_hash,
        'byte_exact': same,
    }


def cmd_unpack(args: argparse.Namespace) -> None:
    manifest = unpack_archive(Path(args.input), Path(args.output), key=args.key)
    print(json.dumps({
        'status': 'ok',
        'operation': 'unpack',
        'output_dir': args.output,
        'file_count': manifest['archive_metadata']['file_count'],
        'archive_sha256': manifest['archive_metadata']['sha256'],
    }, ensure_ascii=False, indent=2))


def cmd_repack(args: argparse.Namespace) -> None:
    report = repack_archive(Path(args.extract_dir), Path(args.output), alignment=args.align,
                            key=args.key, preserve_padding=not args.no_preserve_padding)
    print(json.dumps({'status': 'ok', 'operation': 'repack', **report}, ensure_ascii=False, indent=2))


def cmd_verify(args: argparse.Namespace) -> None:
    print(json.dumps(verify_archive(Path(args.original), Path(args.rebuilt)), ensure_ascii=False, indent=2))


def cmd_smoke(args: argparse.Namespace) -> None:
    temp_dir = Path(args.temp_dir)
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = temp_dir / 'unpacked'
    rebuilt = temp_dir / 'rebuilt.dat'
    unpack_archive(Path(args.input), extract_dir, key=args.key)
    repack_archive(extract_dir, rebuilt, alignment=args.align, key=args.key, preserve_padding=True)
    report = verify_archive(Path(args.input), rebuilt)
    (temp_dir / 'smoke_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'status': 'ok', 'operation': 'smoke-test', **report}, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Unpack/repack the detected scr.dat XOR archive format')
    sub = p.add_subparsers(required=True)

    up = sub.add_parser('unpack', help='extract decrypted files and vfs_manifest.json')
    up.add_argument('input')
    up.add_argument('-o', '--output', required=True)
    up.add_argument('--key', type=lambda x: int(x, 0), default=XOR_KEY_DEFAULT)
    up.set_defaults(func=cmd_unpack)

    rp = sub.add_parser('repack', help='rebuild archive from extracted directory')
    rp.add_argument('extract_dir')
    rp.add_argument('-o', '--output', required=True)
    rp.add_argument('--align', type=int, default=None)
    rp.add_argument('--key', type=lambda x: int(x, 0), default=None)
    rp.add_argument('--no-preserve-padding', action='store_true')
    rp.set_defaults(func=cmd_repack)

    vf = sub.add_parser('verify-archive', help='compare two archives by size and SHA256')
    vf.add_argument('original')
    vf.add_argument('rebuilt')
    vf.set_defaults(func=cmd_verify)

    sm = sub.add_parser('smoke-test', help='unpack then repack and verify byte-exact identity')
    sm.add_argument('input')
    sm.add_argument('-o', '--temp-dir', required=True)
    sm.add_argument('--align', type=int, default=None)
    sm.add_argument('--key', type=lambda x: int(x, 0), default=XOR_KEY_DEFAULT)
    sm.set_defaults(func=cmd_smoke)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
