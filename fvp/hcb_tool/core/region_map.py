from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass
class Region:
    start: int
    end: int
    type: str
    confidence: str = "high"
    note: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict:
        d = asdict(self)
        d["start_hex"] = f"0x{self.start:08X}"
        d["end_hex"] = f"0x{self.end:08X}"
        d["size"] = self.size
        d["interval"] = "[start,end)"
        return d


def normalize_regions(regions: Iterable[Region], file_size: int) -> list[Region]:
    items = sorted(list(regions), key=lambda r: (r.start, r.end))
    out: list[Region] = []
    pos = 0
    for r in items:
        if r.end <= r.start:
            continue
        if r.start > pos:
            out.append(Region(pos, r.start, "unknown_gap", "low", "auto-filled gap"))
        if r.start < pos:
            # keep non-overlap by trimming; record the fact in note.
            if r.end <= pos:
                continue
            r = Region(pos, r.end, r.type, r.confidence, (r.note + "; trimmed overlap").strip("; "))
        out.append(r)
        pos = r.end
    if pos < file_size:
        out.append(Region(pos, file_size, "unknown_tail", "low", "auto-filled tail"))
    return out


def coverage_report(regions: list[Region], file_size: int) -> dict:
    covered = 0
    unknown = 0
    prev = 0
    gaps: list[dict] = []
    overlaps: list[dict] = []
    for r in sorted(regions, key=lambda x: (x.start, x.end)):
        if r.start > prev:
            gaps.append({"start": prev, "end": r.start})
        if r.start < prev:
            overlaps.append({"start": r.start, "end": r.end, "prev_end": prev})
        covered += max(0, r.end - max(r.start, 0))
        if "unknown" in r.type or "padding" in r.type or "opaque" in r.type:
            unknown += r.size
        prev = max(prev, r.end)
    if prev < file_size:
        gaps.append({"start": prev, "end": file_size})
    coverage = min(covered, file_size) / file_size if file_size else 1.0
    return {
        "file_size": file_size,
        "covered_bytes": min(covered, file_size),
        "coverage_ratio": coverage,
        "coverage_percent": round(coverage * 100, 6),
        "unknown_bytes": unknown,
        "unknown_percent": round((unknown / file_size * 100) if file_size else 0, 6),
        "region_count": len(regions),
        "gaps": gaps,
        "overlaps": overlaps,
        "is_100_percent": coverage == 1.0 and not gaps and not overlaps,
    }


def write_coverage_text(report: dict, regions: list[Region]) -> str:
    lines = [
        "[COVERAGE]",
        f"file_size = {report['file_size']}",
        f"covered_bytes = {report['covered_bytes']}",
        f"coverage_percent = {report['coverage_percent']}",
        f"unknown_bytes = {report['unknown_bytes']}",
        f"unknown_percent = {report['unknown_percent']}",
        f"region_count = {report['region_count']}",
        f"status = {'PASS' if report['is_100_percent'] else 'FAIL'}",
        "",
        "[REGIONS]",
    ]
    for r in regions:
        lines.append(f"0x{r.start:08X}..0x{r.end:08X} size={r.size} type={r.type} confidence={r.confidence} note={r.note}")
    if report["gaps"]:
        lines.append("")
        lines.append("[GAPS]")
        for g in report["gaps"]:
            lines.append(f"0x{g['start']:08X}..0x{g['end']:08X}")
    if report["overlaps"]:
        lines.append("")
        lines.append("[OVERLAPS]")
        for o in report["overlaps"]:
            lines.append(f"0x{o['start']:08X}..0x{o['end']:08X} prev_end=0x{o['prev_end']:08X}")
    return "\n".join(lines) + "\n"
