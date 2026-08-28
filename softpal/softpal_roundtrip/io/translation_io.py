from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TranslationFormat:
    translate_mark: str = "●"
    original_mark: str = "○"
    tag_regex: re.Pattern[str] = field(
        default_factory=lambda: re.compile(
            r"^[○●](?P<idx>\d{8})[○●](?P<tag>[a-z_]+)[○●](?P<text>.*)$"
        )
    )


def build_translation_header(
    idx_start: int | None,
    idx_end: int | None,
) -> list[str]:
    scope = (
        "# range: ALL"
        if idx_start is None and idx_end is None
        else f"# range: idx {idx_start if idx_start is not None else '-inf'} .. {idx_end if idx_end is not None else '+inf'}"
    )
    return [
        "# SOFTPAL_TRANSLATE_V2",
        "# Edit only the second line in each double-line pair.",
        "# Keep the leading marker, numeric index, and tag intact.",
        scope,
        "#",
        "",
    ]


def build_translation_blocks(
    text_rows: list[dict[str, object]],
    *,
    fmt: TranslationFormat | None = None,
) -> list[str]:
    fmt = fmt or TranslationFormat()
    blocks: list[str] = []
    for row in text_rows:
        idx = int(row["idx"])
        tag = "msg" if str(row["export_tag"]) == "text" else str(row["export_tag"])
        original = str(row["original_text"])
        original_line = f"{fmt.original_mark}{idx:08d}{fmt.original_mark}{tag}{fmt.original_mark}{original}"
        translated_line = f"{fmt.translate_mark}{idx:08d}{fmt.translate_mark}{tag}{fmt.translate_mark}{original}"
        blocks.append("\n".join([original_line, translated_line, ""]))
    return blocks
