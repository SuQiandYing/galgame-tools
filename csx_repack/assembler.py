"""Cotopha CSX repacker with variable-length text support.

Localisation normally changes text length, so growing and shrinking a string is
the primary use case, not an error (SKILL.md §6.0.1).  This is safe for this
container because image reference sites hold conststr *indices*, not byte
offsets: rewriting the string table never invalidates a reference.  Only three
container fields depend on the section size and are recomputed here.

    identity   no entry changed        -> byte-for-byte copy of the source
    in_place   changed, same length    -> total size unchanged
    rewrite    changed, new length     -> conststr rebuilt, size fields updated

Every write is traced back to a sid and its JoinSites, and the rebuilt file is
re-parsed and re-verified before it is accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from disassembler import (CsxError, TEXT_ENCODING, escape_line,
                          parse_const_strings, parse_sections, parse_source)
from opcodelist import DIALECT, SIZE_FIELDS

TEXT_SOURCE = re.compile(r"^○(?P<idx>\d{8})○(?P<tag>[a-z_]+)○(?P<text>.*)$")
TEXT_TARGET = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$")
PLACEHOLDER = re.compile(r"\{\{(?P<bytes>[0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}")

U32 = struct.Struct("<I")
U64 = struct.Struct("<Q")


class TextImportError(CsxError):
    pass


class ConflictError(CsxError):
    pass


def unescape_text(value: str) -> str:
    """Decode the strict upper-case byte placeholders used by TEXT/2."""
    pieces: list[bytes] = []
    pos = 0
    for match in PLACEHOLDER.finditer(value):
        pieces.append(value[pos:match.start()].encode(TEXT_ENCODING))
        pieces.append(bytes.fromhex(match.group("bytes").replace(":", " ")))
        pos = match.end()
    pieces.append(value[pos:].encode(TEXT_ENCODING))
    raw = b"".join(pieces)
    try:
        return raw.decode(TEXT_ENCODING)
    except UnicodeDecodeError as exc:
        raise TextImportError(f"invalid UTF-16LE placeholder sequence: {exc}") from exc


def parse_text_file(path: Path, image) -> dict[int, str]:
    """Run the §4.9 import checks and return {sid: new_text} for real changes.

    Entries that share one storage must agree: they are one set of bytes, so two
    different translations for the same sid cannot both be honoured.
    """
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    if len(lines) < 4 or not lines[0].startswith("# TEXT/2 "):
        raise TextImportError("not a TEXT/2 file")
    marker = "src_sha256="
    if marker not in lines[0]:
        raise TextImportError("TEXT/2 header has no source hash")
    if lines[0].split(marker, 1)[1].split()[0] != image.sha256:
        raise TextImportError("TEXT/2 source hash does not match the current CSX")
    if "part=1/1" not in lines[2]:
        raise TextImportError("only a complete, unsharded TEXT/2 file can be imported")

    by_idx = {entry.idx: entry for entry in image.texts}
    changes: dict[int, str] = {}
    origin: dict[int, int] = {}
    seen: set[int] = set()
    index = 5
    while index < len(lines):
        if not lines[index]:
            index += 1
            continue
        if not lines[index].startswith("# idx="):
            raise TextImportError(f"expected an entry comment at line {index + 1}")
        if index + 2 >= len(lines):
            raise TextImportError(f"truncated entry at line {index + 1}")
        original = TEXT_SOURCE.fullmatch(lines[index + 1])
        target = TEXT_TARGET.fullmatch(lines[index + 2])
        if original is None or target is None:
            raise TextImportError(f"malformed ○/● pair at line {index + 2}")
        idx = int(original.group("idx"))
        if idx != int(target.group("idx")):
            raise TextImportError(f"idx differs between the ○ and ● lines of entry {idx:08d}")
        if original.group("tag") != target.group("tag"):
            raise TextImportError(f"tag differs between the two lines of entry {idx:08d}")
        entry = by_idx.get(idx)
        if entry is None:
            raise TextImportError(f"entry {idx:08d} does not exist in this source")
        if idx in seen:
            raise TextImportError(f"entry {idx:08d} appears twice")
        seen.add(idx)
        if original.group("tag") != entry.tag:
            raise TextImportError(f"entry {idx:08d} tag was changed")
        if original.group("text") != escape_line(entry.text):
            raise TextImportError(
                f"the ○ line of entry {idx:08d} no longer matches the source text")
        translated = unescape_text(target.group("text"))
        if not translated:
            raise TextImportError(f"entry {idx:08d} has an empty ● line (deleted content)")
        if translated == entry.text:
            index += 3
            continue
        if entry.translate_policy == "frozen":
            raise TextImportError(f"entry {idx:08d} is locked and must not be changed")
        previous = changes.get(entry.sid)
        if previous is not None and previous != translated:
            raise ConflictError(
                f"entries {origin[entry.sid]:08d} and {idx:08d} share one stored string "
                f"but were given different translations: {previous!r} vs {translated!r}")
        changes[entry.sid] = translated
        origin[entry.sid] = idx
        index += 3

    if seen != set(by_idx):
        missing = sorted(set(by_idx) - seen)
        raise TextImportError(
            f"the file omits {len(missing)} entries; the first is {missing[0]:08d}")
    return changes


def encoded_length(text: str) -> int:
    """Bytes this text occupies in the container, terminator excluded.

    conststr is length-prefixed rather than NUL-terminated, so no terminator is
    counted; the u32 code-unit count is part of the record header.
    """
    return len(text.encode(TEXT_ENCODING))


def rebuild_const_string_section(image, changes: dict[int, str]) -> bytes:
    """Re-serialise conststr with the new text, preserving every other field."""
    out = bytearray()
    out += U32.pack(len(image.strings))
    for entry in image.strings:
        text = changes.get(entry.sid, entry.text)
        raw = text.encode(TEXT_ENCODING)
        if len(raw) % 2:
            raise CsxError(f"sid={entry.sid} does not encode to whole UTF-16 code units")
        out += U32.pack(len(raw) // 2)
        out += raw
        out += U32.pack(len(entry.sites))
        for site in entry.sites:
            out += U32.pack(site)
    return bytes(out)


def serialise(image, changes: dict[int, str]) -> tuple[bytes, list[dict], str]:
    """Apply the changes and return (bytes, relocation log, strategy)."""
    data = image.data
    section = next(s for s in image.sections if s.name == "const_string")
    body = rebuild_const_string_section(image, changes)
    delta = len(body) - section.size
    strategy = "identity" if not changes else ("in_place" if delta == 0 else "rewrite")

    out = bytearray()
    out += data[:section.header_offset]
    out += data[section.header_offset:section.header_offset + DIALECT["container"]["record_tag_width"]]
    out += U64.pack(len(body))                       # section length field
    out += body
    out += data[section.end:]

    if delta:
        # header total: sections_end minus the fixed header size
        field = SIZE_FIELDS["header_total"]
        previous = U64.unpack_from(out, field["offset"])[0]
        U64.pack_into(out, field["offset"], previous + delta)
        # Trailer self-pointer, when a trailer is present.  A csx stored inside a
        # NOA archive has no trailer at all, so its absence is normal and only
        # the header total needs updating.
        old_end = _sections_end(image)
        pointer_at = _trailer_pointer_offset(data, old_end)
        if pointer_at is not None:
            U32.pack_into(out, pointer_at + delta, old_end + delta)

    log: list[dict] = []
    for sid, text in sorted(changes.items()):
        entry = image.strings[sid]
        log.append({
            "sid": sid, "join_sites": list(entry.sites),
            "old_code_units": len(entry.text), "new_code_units": len(text),
            "old_bytes": encoded_length(entry.text), "new_bytes": encoded_length(text),
            "rewrite_policy": "conststr-record-rebuild",
        })
    return bytes(out), log, strategy


def _sections_end(image) -> int:
    return max(section.end for section in image.sections)


def _trailer_pointer_offset(data: bytes, sections_end: int) -> int | None:
    """Offset of the trailer word holding the absolute end of the sections.

    Returns None when the file has no trailer, which is the case for a csx
    stored inside a NOA archive.  More than one candidate is ambiguous and is
    reported rather than guessed at.
    """
    hits = [offset for offset in range(sections_end, len(data) - 3)
            if U32.unpack_from(data, offset)[0] == sections_end]
    if not hits:
        return None
    if len(hits) > 1:
        raise CsxError(f"trailer has {len(hits)} self-pointer candidates")
    return hits[0]


def verify(image, rebuilt: bytes, changes: dict[int, str], strategy: str) -> dict:
    """§6.0.3: re-parse the output and prove the edit landed and nothing moved.

    Only the container and the string table are re-read.  Re-running the full
    instruction decode would re-prove a property that cannot have changed: the
    image bytes are copied verbatim, and site isomorphism is checked directly.
    """
    if strategy == "identity":
        # Nothing was written, so the byte comparison below is the whole proof.
        identical = rebuilt == image.data
        return {
            "ok": identical, "issues": [] if identical else ["output differs from source"],
            "strategy": strategy, "reparsed": False, "sites_isomorphic": True,
            "unchanged_entries_verified": len(image.strings), "size_delta": 0,
        }

    sections, _ = parse_sections(rebuilt)
    by_name = {section.name: section for section in sections}
    again_strings, again_sites = parse_const_strings(rebuilt, by_name["const_string"])

    issues: list[str] = []
    if len(again_strings) != len(image.strings):
        issues.append("the string count changed")
    if again_sites != image.site_to_sid:
        issues.append("the reference site set is not isomorphic")

    image_section = by_name["image"]
    original = next(s for s in image.sections if s.name == "image")
    if rebuilt[image_section.start:image_section.end] != \
            image.data[original.start:original.end]:
        issues.append("the image section was modified")

    for sid, text in changes.items():
        if again_strings[sid].text != text:
            issues.append(f"sid={sid} does not hold the new text in the output")
    unchanged_checked = 0
    for entry in image.strings:
        if entry.sid in changes:
            continue
        if again_strings[entry.sid].text != entry.text:
            issues.append(f"sid={entry.sid} changed but was not edited")
        unchanged_checked += 1

    expected = len(image.data) + sum(
        encoded_length(text) - encoded_length(image.strings[sid].text)
        for sid, text in changes.items())
    if len(rebuilt) != expected:
        issues.append(f"size is {len(rebuilt)} but the edits account for {expected}")

    identical = rebuilt == image.data
    if changes and identical:
        issues.append("entries were changed but the output equals the source")
    if not changes and not identical:
        issues.append("nothing was changed but the output differs from the source")

    return {
        "ok": not issues, "issues": issues, "strategy": strategy,
        "reparsed": True, "sites_isomorphic": again_sites == image.site_to_sid,
        "unchanged_entries_verified": unchanged_checked,
        "size_delta": len(rebuilt) - len(image.data),
    }


def rebuild(source: Path, texts: Path | None, output: Path) -> dict:
    # An identity rebuild needs no text entries, so it can skip the instruction
    # decode entirely; importing a TEXT/2 file needs them to validate each idx.
    image = parse_source(source, decode=texts is not None)
    changes = parse_text_file(texts, image) if texts is not None else {}
    rebuilt, log, strategy = serialise(image, changes)
    report = verify(image, rebuilt, changes, strategy)
    if not report["ok"]:
        failed = output.parent / "failed" / output.name
        failed.parent.mkdir(parents=True, exist_ok=True)
        failed.write_bytes(rebuilt)
        raise CsxError("verification failed: " + "; ".join(report["issues"])
                       + f" (kept for diagnosis at {failed})")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(rebuilt)
    temporary.replace(output)

    result = {
        "source": str(source), "output": str(output),
        "source_sha256": image.sha256, "output_sha256": hashlib.sha256(rebuilt).hexdigest(),
        "source_md5": image.md5, "output_md5": hashlib.md5(rebuilt).hexdigest(),
        "source_size": len(image.data), "output_size": len(rebuilt),
        "changed_entries": len(changes), "strategy": strategy,
        "identity": rebuilt == image.data, "verification": report,
        "relocation_log": log,
    }
    destination = output.parent.parent / "reports" / "repack_report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n",
                           encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cotopha CSX repacker")
    parser.add_argument("source", type=Path)
    parser.add_argument("-t", "--texts", type=Path,
                        help="TEXT/2 file; omit for an identity rebuild")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = rebuild(args.source, args.texts, args.output)
    summary = {k: v for k, v in result.items() if k != "relocation_log"}
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
