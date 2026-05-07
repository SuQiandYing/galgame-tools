from __future__ import annotations

import re
from pathlib import Path


TRANSLATE_MARK = "●"
TRANSLATE_TAG_RE = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$")
TRANSLATE_RANGE_RE = re.compile(
    r"^#\s*提取范围：idx\s+(?P<start>-inf|\d+)\s+\.\.\s+(?P<end>\+inf|\d+)\s*$"
)


def read_text_auto(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    for encoding in ("utf-8-sig", "utf-8", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"无法识别 {path} 的文本编码")


def preview_text_for_error(text: str, limit: int = 80) -> str:
    preview = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(preview) > limit:
        preview = preview[:limit] + "..."
    return preview


def normalize_idx_range(
    idx_start: int | None,
    idx_end: int | None,
) -> tuple[int | None, int | None]:
    if idx_start is not None and idx_start < 0:
        raise ValueError(f"idx_start 不能小于 0: {idx_start}")
    if idx_end is not None and idx_end < 0:
        raise ValueError(f"idx_end 不能小于 0: {idx_end}")
    if idx_start is not None and idx_end is not None and idx_start > idx_end:
        raise ValueError(f"idx_start 不能大于 idx_end: {idx_start} > {idx_end}")
    return idx_start, idx_end


def row_in_idx_range(row: dict, idx_start: int | None, idx_end: int | None) -> bool:
    idx = int(row["idx"])
    if idx_start is not None and idx < idx_start:
        return False
    if idx_end is not None and idx > idx_end:
        return False
    return True


def filter_text_rows_by_idx(
    text_rows: list[dict],
    idx_start: int | None,
    idx_end: int | None,
) -> list[dict]:
    idx_start, idx_end = normalize_idx_range(idx_start, idx_end)
    return [row for row in text_rows if row_in_idx_range(row, idx_start, idx_end)]


def detect_idx_range_from_lines(lines: list[str]) -> tuple[int | None, int | None]:
    for line in lines:
        if line.strip() == "# 提取范围：ALL":
            return None, None
        match = TRANSLATE_RANGE_RE.match(line.strip())
        if match is None:
            continue
        start_text = match.group("start")
        end_text = match.group("end")
        idx_start = None if start_text == "-inf" else int(start_text)
        idx_end = None if end_text == "+inf" else int(end_text)
        return normalize_idx_range(idx_start, idx_end)
    return None, None
