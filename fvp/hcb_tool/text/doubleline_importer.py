from __future__ import annotations

import re
from pathlib import Path
from .doubleline_exporter import unescape_line

META_RE = re.compile(r"(\w+)=([^\s]*)")
SRC_RE = re.compile(r"^○(?P<idx>\d+)●(?P<tag>[^○●]+)○(?P<text>.*)$")
EDIT_RE = re.compile(r"^●(?P<idx>\d+)●(?P<tag>[^○●]+)●(?P<text>.*)$")


def parse_meta(line: str) -> dict:
    if not line.startswith("#"):
        raise ValueError("metadata line must start with #")
    return {m.group(1): m.group(2) for m in META_RE.finditer(line[1:].strip())}


def parse_doubleline_text(text: str) -> list[dict]:
    lines = text.splitlines()
    entries: list[dict] = []
    i = 0
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        if not lines[i].startswith("#"):
            raise ValueError(f"expected metadata line at physical line {i + 1}")
        meta = parse_meta(lines[i])
        if i + 2 >= len(lines):
            raise ValueError(f"incomplete entry after line {i + 1}")
        src_m = SRC_RE.match(lines[i + 1])
        edit_m = EDIT_RE.match(lines[i + 2])
        if not src_m or not edit_m:
            raise ValueError(f"bad source/edit line near physical line {i + 1}")
        if src_m.group("idx") != edit_m.group("idx") or src_m.group("tag") != edit_m.group("tag"):
            raise ValueError(f"idx/tag mismatch near physical line {i + 1}")
        if meta.get("idx") != src_m.group("idx") or meta.get("tag") != src_m.group("tag"):
            raise ValueError(f"metadata idx/tag mismatch near physical line {i + 1}")
        entry = dict(meta)
        entry["original"] = unescape_line(src_m.group("text"))
        entry["edited"] = unescape_line(edit_m.group("text"))
        entries.append(entry)
        i += 3
    seen: set[str] = set()
    for e in entries:
        idx = e.get("idx")
        if idx in seen:
            raise ValueError(f"duplicate idx {idx}")
        seen.add(idx)
    return entries


def parse_doubleline_file(path: str | Path) -> list[dict]:
    return parse_doubleline_text(Path(path).read_text(encoding="utf-8"))


def parse_doubleline_path(path: str | Path) -> list[dict]:
    p = Path(path)
    if p.is_dir():
        entries: list[dict] = []
        for txt in sorted(p.glob("*.txt")):
            if txt.name.startswith("_"):
                continue
            entries.extend(parse_doubleline_file(txt))
        seen: set[str] = set()
        for e in entries:
            idx = e.get("idx")
            if idx in seen:
                raise ValueError(f"duplicate idx {idx} across chapter files")
            seen.add(idx)
        return entries
    return parse_doubleline_file(p)
