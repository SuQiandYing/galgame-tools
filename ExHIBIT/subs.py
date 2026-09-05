"""Simplified-Chinese <-> cp932 glyph substitution, driven by subs_cn_jp.json.

The engine writes cp932 and its font hook maps those code points onto Chinese
glyphs. So a translation is authored in normal simplified Chinese and then each
character is swapped for a cp932-representable stand-in before it is packed.
This module is that swap, plus the reverse direction so exported text can be
shown to the translator as real Chinese rather than the stand-in glyphs.

The table is data, not code: it is the same subs_cn_jp.json the existing patch
was built with, so output stays glyph-compatible with it.
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_NAMES = ("subs_cn_jp.json", "subs_cn_jp_v1.json")


class SubsTable:
    """A loaded substitution table. Empty table = identity, never an error."""

    def __init__(self, mapping: dict | None = None, source: Path | None = None):
        self.forward = dict(mapping or {})          # simplified -> cp932 glyph
        self.source = source
        # Reverse is only well-defined because the shipped table is injective;
        # verify rather than assume, and drop any colliding pair so a bad table
        # cannot silently corrupt round-tripping.
        seen = {}
        collisions = set()
        for k, v in self.forward.items():
            if v in seen and seen[v] != k:
                collisions.add(v)
            seen[v] = k
        self.collisions = collisions
        self.reverse = {v: k for k, v in self.forward.items()
                        if v not in collisions}

    def __bool__(self):
        return bool(self.forward)

    def __len__(self):
        return len(self.forward)

    def to_cp932(self, text: str) -> str:
        """Simplified Chinese -> stand-in glyphs the engine can store."""
        if not self.forward:
            return text
        f = self.forward
        return "".join(f.get(ch, ch) for ch in text)

    def to_chinese(self, text: str) -> str:
        """Stand-in glyphs -> the Chinese the player actually sees."""
        if not self.reverse:
            return text
        r = self.reverse
        return "".join(r.get(ch, ch) for ch in text)

    def unmappable(self, text: str, encoding: str = "cp932"):
        """Characters still not representable after substitution."""
        bad = []
        for ch in self.to_cp932(text):
            try:
                ch.encode(encoding)
            except UnicodeEncodeError:
                bad.append(ch)
        return bad


def find_table(start: Path | None = None) -> Path | None:
    """Look for the table beside the tool, then in parent directories."""
    here = Path(start or __file__).resolve()
    roots = [here if here.is_dir() else here.parent]
    roots += list(roots[0].parents)[:3]
    for root in roots:
        for name in DEFAULT_NAMES:
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def load(path=None) -> SubsTable:
    """Load a table. Missing file yields an identity table, not a failure."""
    if path is None:
        path = find_table()
    if path is None:
        return SubsTable()
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return SubsTable()
    if not isinstance(data, dict):
        return SubsTable()
    mapping = {k: v for k, v in data.items()
               if isinstance(k, str) and isinstance(v, str)
               and len(k) == 1 and len(v) == 1 and k != v}
    return SubsTable(mapping, source=path)
