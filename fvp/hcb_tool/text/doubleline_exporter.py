from __future__ import annotations

from pathlib import Path

META_KEYS = [
    "format_version", "idx", "file", "off", "tag", "kind", "parts", "src", "rec", "len", "join", "func",
    "raw_sha1", "text_sha1", "source", "patchable", "pair", "event", "speaker", "speaker_real",
    "speaker_display", "speaker_call", "speaker_func", "speaker_key", "text_call", "name_kind",
    "name_real", "name_display", "speaker_resolver_function_offset_hex", "speaker_condition_key",
    "choice_group", "choice_index", "choice_call", "choice_target", "choice_commit",
    "choice_commit_target", "jump", "chapter", "chapter_title", "chapter_start", "detect_rule"
]


def escape_line(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def unescape_line(text: str) -> str:
    return text.replace("<br>", "\n")


def format_entries(entries: list[dict]) -> str:
    lines: list[str] = []
    for e in entries:
        meta = " ".join(f"{k}={e.get(k, '')}" for k in META_KEYS if k in e)
        lines.append("# " + meta)
        lines.append(f"○{e['idx']}●{e['tag']}○{escape_line(e.get('original', ''))}")
        lines.append(f"●{e['idx']}●{e['tag']}●{escape_line(e.get('edited', e.get('original', '')))}")
        lines.append("")
    return "\n".join(lines) + "\n"


def export_doubleline(entries: list[dict], output_path: str | Path) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(format_entries(entries), encoding="utf-8")
